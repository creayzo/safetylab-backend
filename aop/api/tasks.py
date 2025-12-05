"""
Celery Tasks for Async Event Processing

Worker Pipeline:
1. Consume events from WAL (Redis stream or DB polling)
2. Persist TraceEvent to Postgres
3. Upload large payloads to S3 (if >100KB)
4. Forward to Evaluation Engine (webhook/queue)
5. Push to WebSocket for live dashboard
6. Mark WAL entry as completed
7. Handle retries on failure

Workers run independently and can be scaled horizontally.
"""

import json
import logging
import uuid
from datetime import timedelta
from typing import Dict, Any, Optional

from celery import shared_task, group
from django.utils import timezone
from django.db import transaction
from django.conf import settings
import requests
import boto3
from botocore.exceptions import BotoCoreError, ClientError

from api.models import TraceEvent, Run, Agent, TraceRecord, EnvironmentSnapshot
from api.wal_models import EventWAL, RedisWALStream
from api.auth_models import OrganizationSaltKey, SignatureVerifier

logger = logging.getLogger(__name__)

# Initialize S3 client for large payload storage
s3_client = None
if hasattr(settings, 'AWS_ACCESS_KEY_ID') and settings.AWS_ACCESS_KEY_ID:
    s3_client = boto3.client(
        's3',
        aws_access_key_id=settings.AWS_ACCESS_KEY_ID,
        aws_secret_access_key=settings.AWS_SECRET_ACCESS_KEY,
        region_name=getattr(settings, 'AWS_REGION', 'us-east-1')
    )

# Thresholds
LARGE_PAYLOAD_THRESHOLD_KB = 100
S3_BUCKET = getattr(settings, 'AOP_S3_BUCKET', 'aop-trace-events')


# ============================================================================
# Core Processing Tasks
# ============================================================================

@shared_task(bind=True, max_retries=3, default_retry_delay=60)
def process_wal_entry(self, wal_id: str):
    """
    Main task: Process a single WAL entry.
    
    Steps:
    1. Load WAL entry and mark as processing
    2. Verify signature (if not already verified)
    3. Persist TraceEvent to Postgres
    4. Upload large payloads to S3
    5. Forward to evaluation engine
    6. Push to live WebSocket
    7. Mark WAL as completed
    
    Args:
        wal_id: UUID of EventWAL entry
        
    Raises:
        Retry on transient failures
    """
    try:
        wal_entry = EventWAL.objects.get(id=uuid.UUID(wal_id))
    except EventWAL.DoesNotExist:
        logger.error(f"WAL entry {wal_id} not found")
        return {'status': 'error', 'message': 'WAL entry not found'}
    
    # Mark as processing
    wal_entry.mark_processing()
    
    try:
        # Step 1: Verify signature if not already verified
        if not wal_entry.signature_verified:
            agent = Agent.objects.select_related('organization').get(id=wal_entry.agent_id)
            org_salt_key = agent.organization.get_active_salt_key()
            org_salt = org_salt_key.decrypt_salt()
            
            payload_json = json.dumps(wal_entry.payload, sort_keys=True, separators=(',', ':'))
            is_valid = SignatureVerifier.verify_signature(
                org_salt=org_salt,
                run_id=str(wal_entry.run_id),
                seq_no=wal_entry.seq_no,
                payload=payload_json,
                provided_signature=wal_entry.signature
            )
            
            if not is_valid:
                wal_entry.mark_failed("Signature verification failed")
                logger.error(f"Signature verification failed for WAL {wal_id}")
                return {'status': 'failed', 'reason': 'invalid_signature'}
        
        # Step 2: Check if payload is large and needs S3 storage
        payload_size_kb = len(json.dumps(wal_entry.payload).encode('utf-8')) / 1024
        s3_key = None
        
        if payload_size_kb > LARGE_PAYLOAD_THRESHOLD_KB and s3_client:
            # Upload to S3
            s3_key = f"payloads/{wal_entry.run_id}/{wal_entry.seq_no}.json"
            try:
                s3_client.put_object(
                    Bucket=S3_BUCKET,
                    Key=s3_key,
                    Body=json.dumps(wal_entry.payload).encode('utf-8'),
                    ContentType='application/json',
                    Metadata={
                        'run_id': str(wal_entry.run_id),
                        'seq_no': str(wal_entry.seq_no),
                        'agent_id': str(wal_entry.agent_id)
                    }
                )
                logger.info(f"Uploaded large payload to S3: {s3_key}")
                
                # Replace payload with S3 reference
                payload_to_store = {
                    '_s3_reference': s3_key,
                    '_payload_size_kb': payload_size_kb,
                    '_summary': str(wal_entry.payload)[:500]  # Keep small summary
                }
            except (BotoCoreError, ClientError) as e:
                logger.warning(f"S3 upload failed, storing in DB: {e}")
                payload_to_store = wal_entry.payload
                s3_key = None
        else:
            payload_to_store = wal_entry.payload
        
        # Step 3: Persist TraceEvent to Postgres
        with transaction.atomic():
            run = Run.objects.get(run_id=wal_entry.run_id)
            
            trace_event = TraceEvent.objects.create(
                run=run,
                seq_no=wal_entry.seq_no,
                event_type=wal_entry.event_type,
                timestamp=wal_entry.timestamp,
                payload=payload_to_store,
                actor=wal_entry.metadata.get('actor', 'agent'),
                signature=wal_entry.signature,
                idempotency_key=wal_entry.idempotency_key,
                s3_key=s3_key,
                metadata=wal_entry.metadata
            )
            
            logger.info(f"Persisted TraceEvent {trace_event.event_id} from WAL {wal_id}")
        
        # Step 4: Forward to evaluation engine
        forward_to_evaluation_engine.delay(str(trace_event.event_id))
        
        # Step 5: Push to live WebSocket (if simulation is active)
        push_to_websocket.delay(str(trace_event.event_id))
        
        # Step 6: Mark WAL as completed
        wal_entry.mark_completed(trace_event_id=trace_event.event_id)
        
        return {
            'status': 'success',
            'trace_event_id': str(trace_event.event_id),
            'wal_id': wal_id,
            's3_key': s3_key
        }
    
    except Exception as e:
        logger.error(f"Error processing WAL {wal_id}: {e}", exc_info=True)
        
        # Retry logic
        if wal_entry.can_retry():
            wal_entry.increment_retry()
            # Exponential backoff: 60s, 120s, 240s
            retry_delay = 60 * (2 ** wal_entry.retry_count)
            raise self.retry(exc=e, countdown=retry_delay)
        else:
            wal_entry.mark_failed(str(e))
            return {'status': 'failed', 'error': str(e)}


@shared_task
def forward_to_evaluation_engine(trace_event_id: str):
    """
    Forward TraceEvent to Evaluation Engine for analysis.
    
    The evaluation engine processes events for:
    - Safety violations detection
    - Performance metrics
    - Behavioral analysis
    - Red-teaming results
    
    Args:
        trace_event_id: UUID of TraceEvent
    """
    try:
        trace_event = TraceEvent.objects.select_related('run', 'run__agent').get(
            event_id=uuid.UUID(trace_event_id)
        )
    except TraceEvent.DoesNotExist:
        logger.error(f"TraceEvent {trace_event_id} not found for forwarding")
        return
    
    # Get evaluation engine webhook URL
    eval_webhook = getattr(settings, 'EVALUATION_ENGINE_WEBHOOK', None)
    if not eval_webhook:
        logger.debug("Evaluation engine webhook not configured, skipping")
        return
    
    # Prepare payload for evaluation engine
    payload = {
        'event_id': str(trace_event.event_id),
        'run_id': str(trace_event.run.run_id),
        'agent_id': trace_event.run.agent.id,
        'seq_no': trace_event.seq_no,
        'event_type': trace_event.event_type,
        'timestamp': trace_event.timestamp.isoformat(),
        'actor': trace_event.actor,
        'payload': trace_event.payload,
        'metadata': trace_event.metadata
    }
    
    try:
        response = requests.post(
            eval_webhook,
            json=payload,
            timeout=5,
            headers={'Content-Type': 'application/json'}
        )
        response.raise_for_status()
        logger.info(f"Forwarded event {trace_event_id} to evaluation engine")
    except requests.RequestException as e:
        logger.warning(f"Failed to forward to evaluation engine: {e}")
        # Don't fail the task - evaluation is optional


@shared_task
def push_to_websocket(trace_event_id: str):
    """
    Push TraceEvent to WebSocket for live dashboard updates.
    
    If a simulation/run is being actively monitored, push events
    in real-time to the orchestrator dashboard.
    
    Args:
        trace_event_id: UUID of TraceEvent
    """
    try:
        from channels.layers import get_channel_layer
        from asgiref.sync import async_to_sync
        
        trace_event = TraceEvent.objects.select_related('run').get(
            event_id=uuid.UUID(trace_event_id)
        )
        
        run_id = str(trace_event.run.run_id)
        
        # Check if run has active WebSocket connections
        channel_layer = get_channel_layer()
        if not channel_layer:
            return
        
        # Send to run-specific group
        group_name = f"run_{run_id}"
        
        message = {
            'type': 'trace_event',
            'event': {
                'event_id': str(trace_event.event_id),
                'run_id': run_id,
                'seq_no': trace_event.seq_no,
                'event_type': trace_event.event_type,
                'timestamp': trace_event.timestamp.isoformat(),
                'actor': trace_event.actor,
                'payload': trace_event.payload,
            }
        }
        
        async_to_sync(channel_layer.group_send)(group_name, message)
        logger.debug(f"Pushed event {trace_event_id} to WebSocket group {group_name}")
        
    except TraceEvent.DoesNotExist:
        logger.error(f"TraceEvent {trace_event_id} not found for WebSocket push")
    except ImportError:
        logger.debug("Channels not available, skipping WebSocket push")
    except Exception as e:
        logger.warning(f"WebSocket push failed: {e}")


# ============================================================================
# WAL Consumer Tasks
# ============================================================================

@shared_task
def consume_redis_wal():
    """
    Consume events from Redis WAL stream.
    
    This task runs continuously in a dedicated worker.
    It reads events from Redis stream and dispatches them
    for processing.
    """
    redis_wal = RedisWALStream()
    
    if not redis_wal.available:
        logger.warning("Redis WAL not available, skipping")
        return
    
    consumer_name = f"worker_{uuid.uuid4().hex[:8]}"
    
    # Read batch of events
    messages = redis_wal.read_events(consumer_name, count=10, block=5000)
    
    if not messages:
        return {'status': 'no_messages'}
    
    processed_count = 0
    
    for message_id, event_data in messages:
        wal_id = event_data.get('wal_id')
        
        if not wal_id:
            logger.error(f"Message {message_id} missing wal_id")
            redis_wal.acknowledge(message_id)
            continue
        
        # Dispatch processing task
        process_wal_entry.delay(wal_id)
        
        # Acknowledge message
        redis_wal.acknowledge(message_id)
        processed_count += 1
    
    logger.info(f"Consumed {processed_count} events from Redis WAL")
    return {'status': 'success', 'processed': processed_count}


@shared_task
def consume_db_wal():
    """
    Consume pending events from DB WAL.
    
    Fallback when Redis is unavailable. Polls database for
    pending WAL entries and dispatches them for processing.
    """
    pending_entries = EventWAL.get_pending_entries(limit=50)
    
    if not pending_entries:
        return {'status': 'no_entries'}
    
    # Dispatch processing tasks
    jobs = group(process_wal_entry.s(str(entry.id)) for entry in pending_entries)
    result = jobs.apply_async()
    
    logger.info(f"Dispatched {len(pending_entries)} pending WAL entries")
    return {'status': 'success', 'dispatched': len(pending_entries)}


@shared_task
def retry_failed_wal_entries():
    """
    Retry failed WAL entries.
    
    Periodically checks for failed entries that can be retried
    and re-dispatches them for processing.
    """
    retry_entries = EventWAL.get_retry_entries(max_age_minutes=5)
    
    if not retry_entries:
        return {'status': 'no_retries'}
    
    retried_count = 0
    
    for entry in retry_entries:
        if entry.can_retry():
            process_wal_entry.delay(str(entry.id))
            retried_count += 1
    
    logger.info(f"Retrying {retried_count} failed WAL entries")
    return {'status': 'success', 'retried': retried_count}


# ============================================================================
# Finalization Tasks
# ============================================================================

@shared_task
def generate_trace_record(run_id: str):
    """
    Generate TraceRecord summary when run is finalized.
    
    Aggregates all TraceEvents into a single exportable record
    with statistics and metadata.
    
    Args:
        run_id: UUID of completed run
    """
    try:
        run = Run.objects.get(run_id=uuid.UUID(run_id))
    except Run.DoesNotExist:
        logger.error(f"Run {run_id} not found")
        return
    
    # Get all trace events for this run
    events = TraceEvent.objects.filter(run=run).order_by('seq_no')
    
    if not events.exists():
        logger.warning(f"No events found for run {run_id}")
        return
    
    # Calculate statistics
    event_counts = {}
    for event in events:
        event_counts[event.event_type] = event_counts.get(event.event_type, 0) + 1
    
    # Build trace data
    trace_data = {
        'run_id': str(run.run_id),
        'agent_id': run.agent.id,
        'scenario_id': run.scenario_id,
        'seed': run.seed,
        'status': run.status,
        'start_ts': run.start_ts.isoformat(),
        'finalized_at': run.finalized_at.isoformat() if run.finalized_at else None,
        'event_count': events.count(),
        'event_types': event_counts,
        'events': [
            {
                'event_id': str(e.event_id),
                'seq_no': e.seq_no,
                'event_type': e.event_type,
                'timestamp': e.timestamp.isoformat(),
                'actor': e.actor,
                'payload': e.payload,
                's3_key': e.s3_key
            }
            for e in events
        ]
    }
    
    # Create TraceRecord
    with transaction.atomic():
        trace_record = TraceRecord.objects.create(
            run=run,
            format_version='toon-1.0',
            trace_data=trace_data,
            compressed=False  # Could add compression here
        )
        
        logger.info(f"Generated TraceRecord {trace_record.record_id} for run {run_id}")
    
    return {'status': 'success', 'record_id': str(trace_record.record_id)}


@shared_task
def capture_environment_snapshot(run_id: str):
    """
    Capture environment snapshot when run is finalized.
    
    Stores runtime environment details for reproducibility.
    
    Args:
        run_id: UUID of completed run
    """
    try:
        run = Run.objects.get(run_id=uuid.UUID(run_id))
    except Run.DoesNotExist:
        logger.error(f"Run {run_id} not found")
        return
    
    # Build environment snapshot
    snapshot_data = {
        'python_version': '3.12.6',  # Could get from actual runtime
        'framework_versions': {
            'django': '5.2.3',
            'celery': '5.3.0',
            # Add other relevant versions
        },
        'system_info': {
            'platform': 'linux',  # Could get from platform module
            'timestamp': timezone.now().isoformat()
        }
    }
    
    with transaction.atomic():
        snapshot = EnvironmentSnapshot.objects.create(
            run=run,
            snapshot_data=snapshot_data
        )
        
        logger.info(f"Captured environment snapshot {snapshot.snapshot_id} for run {run_id}")
    
    return {'status': 'success', 'snapshot_id': str(snapshot.snapshot_id)}


# ============================================================================
# Maintenance Tasks
# ============================================================================

@shared_task
def cleanup_old_wal_entries():
    """
    Cleanup old completed WAL entries to save space.
    
    Runs daily to remove WAL entries older than 7 days.
    """
    deleted_count = EventWAL.cleanup_old_entries(days=7)
    logger.info(f"Cleaned up {deleted_count} old WAL entries")
    return {'status': 'success', 'deleted': deleted_count}


@shared_task
def health_check_wal():
    """
    Health check for WAL system.
    
    Monitors queue depths and processing latency.
    Sends alerts if thresholds are exceeded.
    """
    redis_wal = RedisWALStream()
    
    # Check queue depths
    pending_db = EventWAL.objects.filter(status='pending').count()
    processing_db = EventWAL.objects.filter(status='processing').count()
    failed_db = EventWAL.objects.filter(status='failed').count()
    
    redis_health = redis_wal.health_check()
    
    health_data = {
        'timestamp': timezone.now().isoformat(),
        'db': {
            'pending': pending_db,
            'processing': processing_db,
            'failed': failed_db
        },
        'redis': redis_health,
        'status': 'healthy'
    }
    
    # Alert thresholds
    if pending_db > 1000:
        health_data['status'] = 'degraded'
        health_data['alerts'] = ['High pending queue depth']
        logger.warning(f"High pending WAL entries: {pending_db}")
    
    if failed_db > 100:
        health_data['status'] = 'degraded'
        health_data['alerts'] = health_data.get('alerts', []) + ['High failure rate']
        logger.warning(f"High failed WAL entries: {failed_db}")
    
    return health_data


# ============================================================================
# Evaluation and Validation Tasks
# ============================================================================

@shared_task
def evaluate_run(run_id: str):
    """
    Post-run comprehensive evaluation using registered validators.
    
    Runs all POST_RUN phase validators on the complete trace:
    - Timelag detection
    - Missing step detection
    - Sequence consistency
    - Event frequency analysis
    
    Stores results in run metadata or separate ValidationReport model.
    
    Args:
        run_id: UUID of the run to evaluate
        
    Returns:
        Dict with evaluation results
    """
    try:
        run = Run.objects.get(run_id=uuid.UUID(run_id))
    except Run.DoesNotExist:
        logger.error(f"Run {run_id} not found for evaluation")
        return {'status': 'error', 'message': 'Run not found'}
    
    try:
        # Import validators
        from api.validators import validator_registry, ValidationPhase
        
        # Get all events for this run
        events = TraceEvent.objects.filter(
            run_id=run.run_id
        ).order_by('seq_no').values(
            'seq_no', 'timestamp', 'event_type', 'actor', 'payload', 'metadata'
        )
        
        # Convert to list of dicts
        events_list = list(events)
        
        # Add formatted timestamp strings for validators
        for event in events_list:
            event['timestamp'] = event['timestamp'].isoformat()
        
        logger.info(f"Evaluating run {run_id} with {len(events_list)} events")
        
        # Run post-run validators
        violations = validator_registry.evaluate_run(
            run_id=str(run.run_id),
            events=events_list,
            phase=ValidationPhase.POST_RUN
        )
        
        # Aggregate results
        violation_summary = {
            'total': len(violations),
            'by_severity': {},
            'by_type': {},
            'by_validator': {}
        }
        
        for violation in violations:
            # By severity
            severity = violation.severity.value
            violation_summary['by_severity'][severity] = violation_summary['by_severity'].get(severity, 0) + 1
            
            # By type
            vtype = violation.violation_type
            violation_summary['by_type'][vtype] = violation_summary['by_type'].get(vtype, 0) + 1
            
            # By validator
            vname = violation.validator_name
            violation_summary['by_validator'][vname] = violation_summary['by_validator'].get(vname, 0) + 1
        
        # Store results in run metadata
        if not hasattr(run, 'metadata') or run.metadata is None:
            run.metadata = {}
        
        run.metadata['evaluation'] = {
            'timestamp': timezone.now().isoformat(),
            'summary': violation_summary,
            'violations': [
                {
                    'validator': v.validator_name,
                    'severity': v.severity.value,
                    'type': v.violation_type,
                    'message': v.message,
                    'seq_no': v.seq_no,
                    'details': v.details,
                    'remediation': v.remediation,
                    'timestamp': v.timestamp.isoformat() if v.timestamp else None
                }
                for v in violations
            ]
        }
        run.save()
        
        logger.info(
            f"Evaluation complete for run {run_id}: "
            f"{violation_summary['total']} violations found"
        )
        
        # Send to WebSocket clients
        try:
            from channels.layers import get_channel_layer
            from asgiref.sync import async_to_sync
            
            channel_layer = get_channel_layer()
            if channel_layer:
                group_name = f"run_{run_id}"
                async_to_sync(channel_layer.group_send)(
                    group_name,
                    {
                        'type': 'evaluation_complete',
                        'run_id': run_id,
                        'summary': violation_summary,
                        'violations': run.metadata['evaluation']['violations'][:10]  # First 10
                    }
                )
        except Exception as e:
            logger.warning(f"Failed to send evaluation results to WebSocket: {e}")
        
        return {
            'status': 'success',
            'run_id': run_id,
            'evaluation_summary': violation_summary
        }
        
    except Exception as e:
        logger.error(f"Error evaluating run {run_id}: {e}", exc_info=True)
        return {
            'status': 'error',
            'run_id': run_id,
            'message': str(e)
        }
