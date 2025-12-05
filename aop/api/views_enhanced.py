"""
Enhanced API Views with Ingestion Pipeline

Pipeline Flow:
1. API receives event → Immediate validation (Toon parse, schema, HMAC, rate limits)
2. If validation fails → Return error immediately with code
3. Write to WAL (Redis stream + DB backup) for durability
4. Return success to client (fast response)
5. Async worker consumes WAL → Persist to Postgres/S3 → Forward to evaluation engine
6. Real-time forward to WebSocket if simulation is live

Idempotency: Events can be retried safely using seq + idempotency_key
"""

from rest_framework import status
from rest_framework.decorators import api_view
from rest_framework.response import Response
from django.utils import timezone
from django.db import transaction
from django.core.cache import cache
from django_ratelimit.decorators import ratelimit
import json
import uuid
import logging

from api.models import Agent, Run
from api.auth_models import OrganizationSaltKey, AgentAPIKey, SignatureVerifier
from api.wal_models import EventWAL, RedisWALStream, IdempotencyCache
from api.toon_spec import ToonValidator
from api.serializers import CreateRunSerializer, RunSerializer
from api.validators import validator_registry, ValidationPhase, ViolationSeverity

logger = logging.getLogger(__name__)

# Initialize WAL components
redis_wal = RedisWALStream()
idempotency_cache = IdempotencyCache()
toon_validator = ToonValidator()


# ============================================================================
# Validation Helpers
# ============================================================================

def validate_toon_event(event_data: dict, agent: Agent = None) -> tuple[bool, dict, list]:
    """
    Lightweight validation of Toon event structure + ingestion-time validators.
    
    Checks:
    - Required fields present (seq, t, actor, type, payload, meta)
    - Event type valid
    - Payload structure matches type
    - Timestamp format valid
    - Runs ingestion-phase validators (policy, PII, injection, action misuse)
    
    Returns:
        (is_valid, errors_dict, validation_warnings)
    """
    errors = {}
    validation_warnings = []
    
    # Check required top-level fields
    required_fields = ['seq', 't', 'actor', 'type', 'payload', 'meta']
    for field in required_fields:
        if field not in event_data:
            errors[field] = f"Required field '{field}' missing"
    
    if errors:
        return False, errors, validation_warnings
    
    # Validate event type
    valid_types = ['reasoning', 'action_request', 'action_response', 'final_output', 'error']
    if event_data['type'] not in valid_types:
        errors['type'] = f"Invalid event type. Must be one of: {valid_types}"
    
    # Validate actor
    valid_actors = ['agent', 'tool', 'user', 'system', 'redteam']
    if event_data['actor'] not in valid_actors:
        errors['actor'] = f"Invalid actor. Must be one of: {valid_actors}"
    
    # Validate payload structure against event type
    event_type = event_data.get('type')
    payload = event_data.get('payload', {})
    
    if event_type:
        is_valid, payload_errors = toon_validator.validate_payload(event_type, payload)
        if not is_valid:
            errors['payload'] = payload_errors
    
    # Validate meta structure
    meta = event_data.get('meta', {})
    required_meta = ['run_id', 'agent_id', 'signature']
    for field in required_meta:
        if field not in meta:
            if 'meta' not in errors:
                errors['meta'] = {}
            errors['meta'][field] = f"Required meta field '{field}' missing"
    
    # If basic validation failed, return early
    if errors:
        return False, errors, validation_warnings
    
    # ========== Run Ingestion-Time Validators ==========
    # These are fast checks that run synchronously during ingestion
    # (policy rules, PII detection, prompt injection, action misuse)
    
    try:
        from api.validators import ValidationContext
        from datetime import datetime
        
        # Build validation context
        context = ValidationContext(
            event=event_data,
            run_id=meta['run_id'],
            seq_no=event_data['seq'],
            timestamp=datetime.fromisoformat(event_data['t'].replace('Z', '+00:00')),
            agent_metadata={
                'agent_id': meta['agent_id'],
                'role': agent.metadata.get('role', 'agent') if agent and hasattr(agent, 'metadata') else 'agent',
                'permissions': agent.metadata.get('permissions', []) if agent and hasattr(agent, 'metadata') else []
            } if agent else None
        )
        
        # Run validators that are registered for INGESTION phase
        violations = validator_registry.validate_event(context, phase=ValidationPhase.INGESTION)
        
        # Separate by severity
        critical_violations = [v for v in violations if v.severity == ViolationSeverity.CRITICAL]
        error_violations = [v for v in violations if v.severity == ViolationSeverity.ERROR]
        warning_violations = [v for v in violations if v.severity in [ViolationSeverity.WARNING, ViolationSeverity.INFO]]
        
        # CRITICAL violations -> reject event
        if critical_violations:
            errors['validation'] = {
                'critical_violations': [
                    {
                        'type': v.violation_type,
                        'message': v.message,
                        'validator': v.validator_name,
                        'remediation': v.remediation
                    }
                    for v in critical_violations
                ]
            }
        
        # ERROR violations -> reject event
        if error_violations:
            if 'validation' not in errors:
                errors['validation'] = {}
            errors['validation']['error_violations'] = [
                {
                    'type': v.violation_type,
                    'message': v.message,
                    'validator': v.validator_name,
                    'remediation': v.remediation
                }
                for v in error_violations
            ]
        
        # WARNING violations -> accept but warn
        if warning_violations:
            validation_warnings = [
                {
                    'severity': v.severity.value,
                    'type': v.violation_type,
                    'message': v.message,
                    'validator': v.validator_name
                }
                for v in warning_violations
            ]
    
    except Exception as e:
        logger.error(f"Validator execution error: {e}", exc_info=True)
        # Don't block ingestion on validator errors
        validation_warnings.append({
            'severity': 'WARNING',
            'type': 'VALIDATOR_ERROR',
            'message': f'Validator execution failed: {str(e)}',
            'validator': 'system'
        })
    
    return len(errors) == 0, errors, validation_warnings


def verify_signature(event_data: dict, org_salt: str) -> bool:
    """
    Verify HMAC signature on event.
    
    Args:
        event_data: Full event dict with meta.signature
        org_salt: Organization's decrypted salt key
        
    Returns:
        True if signature is valid
    """
    try:
        meta = event_data.get('meta', {})
        provided_signature = meta.get('signature', '')
        run_id = meta.get('run_id', '')
        seq_no = event_data.get('seq', 0)
        
        # Canonical payload (without meta for signature calculation)
        payload_for_sig = {k: v for k, v in event_data.items() if k != 'meta'}
        payload_json = json.dumps(payload_for_sig, sort_keys=True, separators=(',', ':'))
        
        is_valid = SignatureVerifier.verify_signature(
            org_salt=org_salt,
            run_id=run_id,
            seq_no=seq_no,
            payload=payload_json,
            provided_signature=provided_signature
        )
        
        return is_valid
        
    except Exception as e:
        logger.error(f"Signature verification error: {e}")
        return False


def check_sequence_ordering(run_id: uuid.UUID, seq_no: int) -> tuple[bool, str]:
    """
    Check if sequence number is valid for the run.
    
    Events must be in order: seq 1, 2, 3, ...
    Allows retries of same seq, but not skipping.
    
    Returns:
        (is_valid, error_message)
    """
    try:
        # Get last seq for this run from WAL
        last_entry = EventWAL.objects.filter(
            run_id=run_id,
            status__in=['completed', 'processing']
        ).order_by('-seq_no').first()
        
        if last_entry is None:
            # First event, must be seq=1
            if seq_no != 1:
                return False, f"First event must have seq=1, got seq={seq_no}"
            return True, ""
        
        # Must be last_seq or last_seq+1
        if seq_no == last_entry.seq_no:
            # Retry of same event (allowed for idempotency)
            return True, ""
        elif seq_no == last_entry.seq_no + 1:
            # Next event in sequence
            return True, ""
        else:
            return False, f"Invalid sequence: last={last_entry.seq_no}, got={seq_no}"
            
    except Exception as e:
        logger.error(f"Sequence check error: {e}")
        return False, f"Sequence validation error: {str(e)}"


def check_rate_limit(agent_id: int, run_id: uuid.UUID) -> tuple[bool, str]:
    """
    Check rate limits for agent.
    
    Limits:
    - 1000 events per run per minute
    - 10000 events per agent per minute
    
    Returns:
        (is_allowed, error_message)
    """
    minute_key = timezone.now().strftime('%Y%m%d%H%M')
    
    # Check per-run limit
    run_key = f"ratelimit:run:{run_id}:{minute_key}"
    run_count = cache.get(run_key, 0)
    if run_count >= 1000:
        return False, "Rate limit exceeded: 1000 events/minute per run"
    
    # Check per-agent limit
    agent_key = f"ratelimit:agent:{agent_id}:{minute_key}"
    agent_count = cache.get(agent_key, 0)
    if agent_count >= 10000:
        return False, "Rate limit exceeded: 10000 events/minute per agent"
    
    # Increment counters
    cache.set(run_key, run_count + 1, timeout=60)
    cache.set(agent_key, agent_count + 1, timeout=60)
    
    return True, ""


# ============================================================================
# Enhanced API Endpoints with Pipeline
# ============================================================================

@api_view(['POST'])
def create_run(request):
    """
    POST /api/runs/ - Create a new run
    
    Returns run_id and seed for the new run.
    """
    serializer = CreateRunSerializer(data=request.data, context={'request': request})
    
    if not serializer.is_valid():
        return Response({
            'error': 'VALIDATION_ERROR',
            'details': serializer.errors
        }, status=status.HTTP_400_BAD_REQUEST)
    
    validated_data = serializer.validated_data
    
    try:
        agent = Agent.objects.get(id=validated_data['agent_id'])
        
        # Generate seed if not provided
        seed = validated_data.get('seed')
        if seed is None:
            import random
            seed = random.randint(0, 2**31 - 1)
        
        # Create run
        run = Run.objects.create(
            agent=agent,
            scenario_id=validated_data.get('scenario_id'),
            seed=seed,
            status='running'
        )
        
        logger.info(f"Created run {run.run_id} for agent {agent.id}")
        
        response_serializer = RunSerializer(run)
        return Response(response_serializer.data, status=status.HTTP_201_CREATED)
    
    except Agent.DoesNotExist:
        return Response({
            'error': 'AGENT_NOT_FOUND',
            'message': 'Agent not found'
        }, status=status.HTTP_404_NOT_FOUND)
    except Exception as e:
        logger.error(f"Error creating run: {e}")
        return Response({
            'error': 'INTERNAL_ERROR',
            'message': 'Internal server error'
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@api_view(['POST'])
def append_trace_event(request, run_id):
    """
    POST /api/runs/{run_id}/events/ - Append a single TraceEvent
    
    Ingestion Pipeline:
    1. Immediate validation (Toon parse, schema, HMAC, rate limits)
    2. Write to WAL (Redis + DB)
    3. Return success immediately
    4. Async worker processes from WAL
    
    Request body (Toon format):
    {
      "seq": 1,
      "t": "2025-12-05T10:00:00Z",
      "actor": "agent",
      "type": "reasoning",
      "payload": {...},
      "meta": {
        "run_id": "uuid",
        "agent_id": 123,
        "signature": "hmac_signature",
        "idempotency_key": "unique_key"
      }
    }
    
    Response (success):
    {
      "status": "accepted",
      "wal_id": "uuid",
      "message": "Event queued for processing"
    }
    
    Response (error):
    {
      "error": "ERROR_CODE",
      "details": {...},
      "message": "Human readable error"
    }
    """
    event_data = request.data
    
    # ========== STEP 1: Immediate Lightweight Validation ==========
    
    # Extract metadata early for agent lookup
    meta = event_data.get('meta', {})
    agent_id = meta.get('agent_id')
    
    # Get agent for validator context
    agent = None
    try:
        if agent_id:
            agent = Agent.objects.select_related('organization').get(id=agent_id)
    except Agent.DoesNotExist:
        pass  # Will be caught later
    
    # Validate Toon structure + run ingestion validators
    is_valid, errors, validation_warnings = validate_toon_event(event_data, agent)
    if not is_valid:
        logger.warning(f"Toon validation failed for run {run_id}: {errors}")
        return Response({
            'error': 'TOON_VALIDATION_ERROR',
            'details': errors,
            'message': 'Event does not conform to Toon specification'
        }, status=status.HTTP_400_BAD_REQUEST)
    
    # Extract remaining metadata
    seq_no = event_data.get('seq')
    idempotency_key = meta.get('idempotency_key')
    
    # Validate idempotency key presence
    if not idempotency_key:
        return Response({
            'error': 'MISSING_IDEMPOTENCY_KEY',
            'message': 'meta.idempotency_key is required'
        }, status=status.HTTP_400_BAD_REQUEST)
    
    # Check idempotency (fast Redis check)
    if not idempotency_cache.check_and_set(idempotency_key, str(uuid.uuid4())):
        # Duplicate request - return existing WAL entry
        existing_wal_id = idempotency_cache.get(idempotency_key)
        logger.info(f"Duplicate event detected: {idempotency_key}")
        return Response({
            'status': 'duplicate',
            'wal_id': existing_wal_id,
            'message': 'Event already received (idempotent)'
        }, status=status.HTTP_200_OK)
    
    # Check sequence ordering
    is_valid_seq, seq_error = check_sequence_ordering(uuid.UUID(run_id), seq_no)
    if not is_valid_seq:
        logger.warning(f"Sequence error for run {run_id}: {seq_error}")
        return Response({
            'error': 'SEQUENCE_ERROR',
            'message': seq_error
        }, status=status.HTTP_400_BAD_REQUEST)
    
    # Check rate limits
    is_allowed, rate_error = check_rate_limit(agent_id, uuid.UUID(run_id))
    if not is_allowed:
        logger.warning(f"Rate limit exceeded for agent {agent_id}: {rate_error}")
        return Response({
            'error': 'RATE_LIMIT_EXCEEDED',
            'message': rate_error
        }, status=status.HTTP_429_TOO_MANY_REQUESTS)
    
    # Verify HMAC signature
    try:
        agent = Agent.objects.select_related('organization').get(id=agent_id)
        org_salt_key = agent.organization.get_active_salt_key()
        org_salt = org_salt_key.decrypt_salt()
        
        if not verify_signature(event_data, org_salt):
            logger.warning(f"Signature verification failed for run {run_id}, seq {seq_no}")
            return Response({
                'error': 'SIGNATURE_INVALID',
                'message': 'HMAC signature verification failed'
            }, status=status.HTTP_401_UNAUTHORIZED)
    
    except Agent.DoesNotExist:
        return Response({
            'error': 'AGENT_NOT_FOUND',
            'message': f'Agent {agent_id} not found'
        }, status=status.HTTP_404_NOT_FOUND)
    except Exception as e:
        logger.error(f"Signature verification error: {e}")
        return Response({
            'error': 'SIGNATURE_VERIFICATION_ERROR',
            'message': str(e)
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
    
    # ========== STEP 2: Write to WAL for Durability ==========
    
    try:
        with transaction.atomic():
            # Create WAL entry
            wal_metadata = {
                'actor': event_data['actor'],
                'client_timestamp': event_data['t'],
                'meta': meta
            }
            
            # Store validation warnings in metadata for post-processing
            if validation_warnings:
                wal_metadata['validation_warnings'] = validation_warnings
            
            wal_entry = EventWAL.objects.create(
                run_id=uuid.UUID(run_id),
                agent_id=agent_id,
                seq_no=seq_no,
                idempotency_key=idempotency_key,
                event_type=event_data['type'],
                timestamp=timezone.now(),  # Use server time for consistency
                payload=event_data['payload'],
                metadata=wal_metadata,
                signature=meta['signature'],
                signature_verified=True,  # We just verified it
                status='pending'
            )
            
            # Update idempotency cache with actual WAL ID
            idempotency_cache.check_and_set(idempotency_key, str(wal_entry.id))
            
            # Append to Redis stream (best effort)
            redis_appended = redis_wal.append_event(wal_entry)
            
            if redis_appended:
                logger.info(f"Event written to WAL: {wal_entry.id} (Redis + DB)")
            else:
                logger.warning(f"Event written to WAL: {wal_entry.id} (DB only, Redis unavailable)")
            
            # ========== STEP 3: Return Success Immediately ==========
            response_data = {
                'status': 'accepted',
                'wal_id': str(wal_entry.id),
                'message': 'Event queued for processing',
                'wal_backend': 'redis_db' if redis_appended else 'db_only'
            }
            
            # Include validation warnings if any
            if validation_warnings:
                response_data['validation_warnings'] = validation_warnings
            
            return Response(response_data, status=status.HTTP_202_ACCEPTED)
    
    except Exception as e:
        logger.error(f"WAL write error: {e}", exc_info=True)
        # Cleanup idempotency cache on failure
        idempotency_cache.delete(idempotency_key)
        return Response({
            'error': 'WAL_WRITE_ERROR',
            'message': 'Failed to queue event for processing',
            'details': str(e)
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@api_view(['POST'])
def batch_trace_events(request):
    """
    POST /api/trace-events/batch/ - Batch event submission
    
    Accepts multiple events in a single request for better throughput.
    Each event goes through the same validation + WAL pipeline.
    
    Request body:
    {
      "agent_id": 123,
      "events": [
        {
          "run_id": "uuid",
          "seq": 1,
          "t": "2025-12-05T10:00:00Z",
          "actor": "agent",
          "type": "reasoning",
          "payload": {...},
          "meta": {...}
        },
        ...
      ]
    }
    
    Response:
    {
      "accepted": 10,
      "failed": 0,
      "results": [
        {"index": 0, "status": "accepted", "wal_id": "uuid"},
        {"index": 1, "status": "failed", "error": "SEQUENCE_ERROR", "message": "..."},
        ...
      ]
    }
    """
    agent_id = request.data.get('agent_id')
    events = request.data.get('events', [])
    
    if not agent_id:
        return Response({
            'error': 'MISSING_AGENT_ID',
            'message': 'agent_id is required'
        }, status=status.HTTP_400_BAD_REQUEST)
    
    if not events or not isinstance(events, list):
        return Response({
            'error': 'INVALID_EVENTS',
            'message': 'events must be a non-empty array'
        }, status=status.HTTP_400_BAD_REQUEST)
    
    if len(events) > 100:
        return Response({
            'error': 'BATCH_TOO_LARGE',
            'message': 'Maximum 100 events per batch'
        }, status=status.HTTP_400_BAD_REQUEST)
    
    # Process each event
    results = []
    accepted_count = 0
    failed_count = 0
    
    for idx, event_data in enumerate(events):
        # Add agent_id to meta if not present
        if 'meta' not in event_data:
            event_data['meta'] = {}
        event_data['meta']['agent_id'] = agent_id
        
        # Generate idempotency key if missing
        if 'idempotency_key' not in event_data['meta']:
            event_data['meta']['idempotency_key'] = f"{event_data.get('run_id')}:{event_data.get('seq')}"
        
        # Process through same pipeline (inline to avoid request overhead)
        try:
            # Validate
            is_valid, errors = validate_toon_event(event_data)
            if not is_valid:
                results.append({
                    'index': idx,
                    'status': 'failed',
                    'error': 'TOON_VALIDATION_ERROR',
                    'details': errors
                })
                failed_count += 1
                continue
            
            # Check idempotency
            idempotency_key = event_data['meta']['idempotency_key']
            if not idempotency_cache.check_and_set(idempotency_key, str(uuid.uuid4())):
                results.append({
                    'index': idx,
                    'status': 'duplicate',
                    'wal_id': idempotency_cache.get(idempotency_key)
                })
                accepted_count += 1  # Count as accepted (idempotent)
                continue
            
            # Write to WAL
            wal_entry = EventWAL.objects.create(
                run_id=uuid.UUID(event_data['meta']['run_id']),
                agent_id=agent_id,
                seq_no=event_data['seq'],
                idempotency_key=idempotency_key,
                event_type=event_data['type'],
                timestamp=timezone.now(),
                payload=event_data['payload'],
                metadata={'actor': event_data['actor'], 'client_timestamp': event_data['t']},
                signature=event_data['meta'].get('signature', ''),
                signature_verified=False,  # Batch mode: verify async
                status='pending'
            )
            
            redis_wal.append_event(wal_entry)
            
            results.append({
                'index': idx,
                'status': 'accepted',
                'wal_id': str(wal_entry.id)
            })
            accepted_count += 1
            
        except Exception as e:
            logger.error(f"Batch event {idx} error: {e}")
            results.append({
                'index': idx,
                'status': 'failed',
                'error': 'PROCESSING_ERROR',
                'message': str(e)
            })
            failed_count += 1
    
    return Response({
        'accepted': accepted_count,
        'failed': failed_count,
        'total': len(events),
        'results': results
    }, status=status.HTTP_207_MULTI_STATUS)


@api_view(['POST'])
def finalize_run(request, run_id):
    """
    POST /api/runs/{run_id}/finalize/ - Mark run as complete
    
    Triggers:
    - Run status update to 'completed' or 'failed'
    - TraceRecord summary generation
    - EnvironmentSnapshot capture
    - Final audit log entry
    
    Request body:
    {
      "status": "completed",  // or "failed"
      "error": null,          // or error message if failed
      "final_output": {...}   // optional final output payload
    }
    """
    try:
        run = Run.objects.get(run_id=uuid.UUID(run_id))
    except Run.DoesNotExist:
        return Response({
            'error': 'RUN_NOT_FOUND',
            'message': f'Run {run_id} not found'
        }, status=status.HTTP_404_NOT_FOUND)
    
    final_status = request.data.get('status', 'completed')
    error_message = request.data.get('error')
    
    if final_status not in ['completed', 'failed']:
        return Response({
            'error': 'INVALID_STATUS',
            'message': 'Status must be "completed" or "failed"'
        }, status=status.HTTP_400_BAD_REQUEST)
    
    try:
        with transaction.atomic():
            # Update run status
            run.status = final_status
            run.finalized_at = timezone.now()
            if error_message:
                run.error = error_message
            run.save()
            
            logger.info(f"Finalized run {run_id} with status {final_status}")
        
        # Trigger async tasks for finalization
        from api.tasks import generate_trace_record, capture_environment_snapshot, evaluate_run
        
        # Generate TraceRecord summary (async)
        generate_trace_record.delay(str(run.run_id))
        
        # Capture environment snapshot (async)
        capture_environment_snapshot.delay(str(run.run_id))
        
        # Run post-run evaluation (async)
        evaluate_run.delay(str(run.run_id))
        
        # Notify WebSocket clients
        try:
            from channels.layers import get_channel_layer
            from asgiref.sync import async_to_sync
            
            channel_layer = get_channel_layer()
            if channel_layer:
                group_name = f"run_{run_id}"
                async_to_sync(channel_layer.group_send)(
                    group_name,
                    {
                        'type': 'run_finalized',
                        'run_id': run_id,
                        'status': final_status,
                        'timestamp': run.finalized_at.isoformat()
                    }
                )
        except Exception as e:
            logger.warning(f"WebSocket notification failed: {e}")
        
        return Response({
            'status': 'finalized',
            'run_id': str(run.run_id),
            'final_status': final_status,
            'finalized_at': run.finalized_at.isoformat(),
            'trace_record_generation': 'queued',
            'environment_snapshot': 'queued'
        }, status=status.HTTP_200_OK)
    
    except Exception as e:
        logger.error(f"Finalize error: {e}")
        return Response({
            'error': 'FINALIZE_ERROR',
            'message': str(e)
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@api_view(['GET'])
def wal_status(request):
    """
    GET /api/wal/status - Check WAL health and stats
    
    Returns:
    {
      "redis": {"status": "healthy", "pending": 10, "stream_length": 100},
      "db": {"pending": 5, "processing": 2, "failed": 1},
      "cache": {"available": true}
    }
    """
    redis_health = redis_wal.health_check()
    
    db_stats = {
        'pending': EventWAL.objects.filter(status='pending').count(),
        'processing': EventWAL.objects.filter(status='processing').count(),
        'failed': EventWAL.objects.filter(status='failed').count(),
        'completed_last_hour': EventWAL.objects.filter(
            status='completed',
            processed_at__gte=timezone.now() - timezone.timedelta(hours=1)
        ).count()
    }
    
    cache_available = idempotency_cache.available
    
    return Response({
        'redis': redis_health,
        'db': db_stats,
        'cache': {
            'available': cache_available,
            'backend': 'redis' if cache_available else 'db_fallback'
        },
        'timestamp': timezone.now().isoformat()
    }, status=status.HTTP_200_OK)
