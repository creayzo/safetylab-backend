"""
Retention and Privacy Celery Tasks

Handles:
- Scheduled data cleanup
- PII redaction pipeline
- Deletion request execution
- Consent expiration handling
"""

import logging
from datetime import timedelta
from typing import Dict, Any
from celery import shared_task
from django.utils import timezone
from django.db import transaction
from django.db.models import Q

logger = logging.getLogger(__name__)


@shared_task
def cleanup_expired_data():
    """
    Scheduled task to clean up expired data based on retention policies.
    
    Runs daily to check and delete:
    - Expired trace events
    - Old snapshots
    - Cached responses
    - Completed WAL entries
    """
    from api.models import Organization, TraceEvent, EnvironmentSnapshot
    from api.retention_models import RetentionPolicy, PrivacyAuditLog
    from api.wal_models import EventWAL
    from api.replay_models import CachedLLMResponse, CachedToolResponse
    
    results = {
        'organizations_processed': 0,
        'traces_deleted': 0,
        'snapshots_deleted': 0,
        'cached_responses_deleted': 0,
        'wal_entries_deleted': 0
    }
    
    for org in Organization.objects.filter(is_active=True):
        try:
            # Get or create retention policy
            policy, _ = RetentionPolicy.objects.get_or_create(
                organization=org,
                defaults={'tier': 'free'}
            )
            
            if not policy.auto_cleanup_enabled:
                continue
            
            # Cleanup trace events
            trace_cutoff = timezone.now() - timedelta(days=policy.trace_retention_days)
            deleted_traces = TraceEvent.objects.filter(
                run__agent__organization=org,
                timestamp__lt=trace_cutoff
            ).delete()[0]
            results['traces_deleted'] += deleted_traces
            
            # Cleanup snapshots
            snapshot_cutoff = timezone.now() - timedelta(days=policy.snapshot_retention_days)
            deleted_snapshots = EnvironmentSnapshot.objects.filter(
                run__agent__organization=org,
                captured_at__lt=snapshot_cutoff
            ).delete()[0]
            results['snapshots_deleted'] += deleted_snapshots
            
            # Cleanup cached responses
            cache_cutoff = timezone.now() - timedelta(days=policy.cached_response_retention_days)
            deleted_llm_cache = CachedLLMResponse.objects.filter(
                snapshot__run__agent__organization=org,
                timestamp__lt=cache_cutoff
            ).delete()[0]
            deleted_tool_cache = CachedToolResponse.objects.filter(
                snapshot__run__agent__organization=org,
                timestamp__lt=cache_cutoff
            ).delete()[0]
            results['cached_responses_deleted'] += deleted_llm_cache + deleted_tool_cache
            
            # Cleanup WAL entries
            wal_cutoff = timezone.now() - timedelta(days=policy.wal_retention_days)
            deleted_wal = EventWAL.objects.filter(
                agent__organization=org,
                status='completed',
                timestamp__lt=wal_cutoff
            ).delete()[0]
            results['wal_entries_deleted'] += deleted_wal
            
            # Update last cleanup time
            policy.last_cleanup_at = timezone.now()
            policy.save()
            
            # Log audit
            PrivacyAuditLog.objects.create(
                organization=org,
                action_type='data_deletion',
                performed_by='system',
                details={
                    'traces_deleted': deleted_traces,
                    'snapshots_deleted': deleted_snapshots,
                    'cached_responses_deleted': deleted_llm_cache + deleted_tool_cache,
                    'wal_entries_deleted': deleted_wal,
                    'retention_policy': {
                        'trace_days': policy.trace_retention_days,
                        'snapshot_days': policy.snapshot_retention_days
                    }
                },
                success=True
            )
            
            results['organizations_processed'] += 1
            logger.info(f"Cleaned up data for org {org.id}: {deleted_traces} traces, {deleted_snapshots} snapshots")
            
        except Exception as e:
            logger.error(f"Error cleaning up org {org.id}: {e}", exc_info=True)
            
            PrivacyAuditLog.objects.create(
                organization=org,
                action_type='data_deletion',
                performed_by='system',
                details={'error': str(e)},
                success=False,
                error_message=str(e)
            )
    
    logger.info(f"Cleanup complete: {results}")
    return results


@shared_task
def redact_pii_pipeline():
    """
    Scheduled task to redact PII from stored traces.
    
    Runs hourly to check for:
    - Traces that need redaction (based on policy)
    - Recently stored traces that haven't been redacted yet
    - Consent revocations requiring immediate redaction
    """
    from api.models import TraceEvent, Organization
    from api.retention_models import RetentionPolicy, RedactionLog, PrivacyAuditLog
    from api.validators.pii_detector import pii_detector
    
    results = {
        'organizations_processed': 0,
        'events_scanned': 0,
        'events_redacted': 0,
        'pii_instances_found': 0
    }
    
    for org in Organization.objects.filter(is_active=True):
        try:
            policy = RetentionPolicy.objects.filter(organization=org).first()
            if not policy or not policy.auto_redact_pii:
                continue
            
            # Find unredacted events from last 24 hours
            cutoff = timezone.now() - timedelta(hours=24)
            events = TraceEvent.objects.filter(
                run__agent__organization=org,
                timestamp__gte=cutoff
            ).exclude(
                metadata__contains={'pii_redacted': True}
            )[:1000]  # Process in batches
            
            for event in events:
                try:
                    # Scan for PII
                    pii_matches = pii_detector.scan_dict(event.payload)
                    
                    if pii_matches:
                        # Redact based on policy mode
                        if policy.pii_redaction_mode == 'mask':
                            redacted_payload = pii_detector.redact_dict(event.payload)
                        elif policy.pii_redaction_mode == 'hash':
                            redacted_payload = pii_detector.hash_pii_dict(event.payload)
                        elif policy.pii_redaction_mode == 'remove':
                            redacted_payload = pii_detector.remove_pii_dict(event.payload)
                        else:
                            continue  # No redaction
                        
                        # Update event
                        event.payload = redacted_payload
                        if not event.metadata:
                            event.metadata = {}
                        event.metadata['pii_redacted'] = True
                        event.metadata['pii_redacted_at'] = timezone.now().isoformat()
                        event.save()
                        
                        # Log redaction
                        RedactionLog.objects.create(
                            run=event.run,
                            trace_event=event,
                            redaction_type=f'pii_{policy.pii_redaction_mode}',
                            fields_redacted=[match.field_path for match in pii_matches],
                            pii_types_found=list(set(match.pattern for match in pii_matches)),
                            redacted_by='system',
                            reason=f'Automatic PII redaction per retention policy ({policy.pii_redaction_mode})'
                        )
                        
                        results['events_redacted'] += 1
                        results['pii_instances_found'] += len(pii_matches)
                    
                    results['events_scanned'] += 1
                    
                except Exception as e:
                    logger.error(f"Error redacting event {event.id}: {e}", exc_info=True)
            
            results['organizations_processed'] += 1
            
        except Exception as e:
            logger.error(f"Error processing org {org.id} for PII redaction: {e}", exc_info=True)
    
    logger.info(f"PII redaction complete: {results}")
    return results


@shared_task
def process_consent_expirations():
    """
    Check for expired consents and trigger appropriate actions.
    
    When consent expires:
    - Redact associated data
    - Delete cached responses
    - Update audit logs
    """
    from api.retention_models import DataConsentRecord, PrivacyAuditLog
    
    results = {
        'consents_checked': 0,
        'consents_expired': 0,
        'actions_taken': 0
    }
    
    # Find expired consents
    expired_consents = DataConsentRecord.objects.filter(
        is_granted=True,
        expires_at__lt=timezone.now()
    )
    
    for consent in expired_consents:
        try:
            # Mark as expired
            consent.is_granted = False
            consent.save()
            
            # Take action based on consent type
            if consent.consent_type == 'raw_trace_storage':
                # Redact traces
                for run in consent.applies_to_runs.all():
                    redact_run_pii.delay(str(run.run_id), reason='Consent expired')
                    results['actions_taken'] += 1
            
            elif consent.consent_type == 'llm_response_caching':
                # Delete cached responses
                from api.replay_models import CachedLLMResponse
                deleted = CachedLLMResponse.objects.filter(
                    snapshot__run__in=consent.applies_to_runs.all()
                ).delete()[0]
                results['actions_taken'] += deleted
            
            # Log audit
            PrivacyAuditLog.objects.create(
                organization=consent.organization,
                action_type='consent_revoked',
                performed_by='system',
                details={
                    'consent_id': str(consent.consent_id),
                    'consent_type': consent.consent_type,
                    'reason': 'Consent expired',
                    'expired_at': consent.expires_at.isoformat()
                },
                success=True
            )
            
            results['consents_expired'] += 1
            
        except Exception as e:
            logger.error(f"Error processing expired consent {consent.consent_id}: {e}", exc_info=True)
        
        results['consents_checked'] += 1
    
    logger.info(f"Consent expiration check complete: {results}")
    return results


@shared_task
def execute_deletion_request(request_id: str):
    """
    Execute a data deletion request.
    
    Args:
        request_id: UUID of DataDeletionRequest
    """
    from api.retention_models import DataDeletionRequest, PrivacyAuditLog
    from api.models import TraceEvent, Run
    from api.wal_models import EventWAL
    from api.replay_models import ReplaySnapshot
    
    try:
        request = DataDeletionRequest.objects.get(request_id=request_id)
    except DataDeletionRequest.DoesNotExist:
        logger.error(f"Deletion request {request_id} not found")
        return {'status': 'error', 'message': 'Request not found'}
    
    # Update status
    request.status = 'in_progress'
    request.started_at = timezone.now()
    request.save()
    
    items_deleted = {
        'runs': 0,
        'trace_events': 0,
        'wal_entries': 0,
        'snapshots': 0
    }
    
    try:
        with transaction.atomic():
            # Determine scope
            if request.request_type == 'full_org':
                runs_to_delete = Run.objects.filter(
                    agent__organization=request.organization
                )
            elif request.request_type == 'specific_runs':
                runs_to_delete = request.runs_to_delete.all()
            elif request.request_type == 'time_range':
                runs_to_delete = Run.objects.filter(
                    agent__organization=request.organization,
                    created_at__gte=request.delete_after_date,
                    created_at__lte=request.delete_before_date
                )
            elif request.request_type == 'pii_only':
                # Just redact PII, don't delete
                for run in request.runs_to_delete.all():
                    redact_run_pii.delay(str(run.run_id), reason='Deletion request (PII only)')
                
                request.status = 'completed'
                request.completed_at = timezone.now()
                request.items_deleted = {'pii_redacted': request.runs_to_delete.count()}
                request.save()
                
                return {'status': 'completed', 'items_deleted': request.items_deleted}
            else:
                raise ValueError(f"Unknown request type: {request.request_type}")
            
            # Delete data
            for run in runs_to_delete:
                # Delete trace events
                items_deleted['trace_events'] += TraceEvent.objects.filter(run=run).delete()[0]
                
                # Delete WAL entries
                items_deleted['wal_entries'] += EventWAL.objects.filter(run_id=run.run_id).delete()[0]
                
                # Delete snapshots
                items_deleted['snapshots'] += ReplaySnapshot.objects.filter(run=run).delete()[0]
                
                # Delete run
                run.delete()
                items_deleted['runs'] += 1
            
            # Update request
            request.status = 'completed'
            request.completed_at = timezone.now()
            request.items_deleted = items_deleted
            
            # Generate deletion certificate (proof of deletion)
            import hashlib
            import json
            
            certificate_data = {
                'request_id': str(request_id),
                'organization_id': request.organization.id,
                'deleted_at': timezone.now().isoformat(),
                'items_deleted': items_deleted,
                'legal_basis': request.legal_basis
            }
            certificate_json = json.dumps(certificate_data, sort_keys=True)
            certificate_hash = hashlib.sha256(certificate_json.encode()).hexdigest()
            
            request.deletion_certificate = {
                'hash': certificate_hash,
                'timestamp': timezone.now().isoformat(),
                'items': items_deleted
            }
            request.save()
            
            # Log audit
            PrivacyAuditLog.objects.create(
                organization=request.organization,
                action_type='data_deletion',
                performed_by=request.requested_by,
                details={
                    'request_id': str(request_id),
                    'request_type': request.request_type,
                    'items_deleted': items_deleted,
                    'legal_basis': request.legal_basis
                },
                success=True,
                is_gdpr_related='gdpr' in request.legal_basis.lower(),
                is_ccpa_related='ccpa' in request.legal_basis.lower()
            )
            
            logger.info(f"Deletion request {request_id} completed: {items_deleted}")
            
            return {'status': 'completed', 'items_deleted': items_deleted}
            
    except Exception as e:
        logger.error(f"Error executing deletion request {request_id}: {e}", exc_info=True)
        
        request.status = 'failed'
        request.completed_at = timezone.now()
        request.notes += f"\nError: {str(e)}"
        request.save()
        
        # Log audit
        PrivacyAuditLog.objects.create(
            organization=request.organization,
            action_type='data_deletion',
            performed_by=request.requested_by,
            details={
                'request_id': str(request_id),
                'error': str(e)
            },
            success=False,
            error_message=str(e)
        )
        
        return {'status': 'failed', 'error': str(e)}


@shared_task
def redact_run_pii(run_id: str, reason: str = "Manual redaction"):
    """
    Redact PII from all events in a run.
    
    Args:
        run_id: UUID of the run
        reason: Reason for redaction
    """
    from api.models import Run, TraceEvent
    from api.retention_models import RedactionLog
    from api.validators.pii_detector import pii_detector
    
    try:
        run = Run.objects.get(run_id=run_id)
    except Run.DoesNotExist:
        logger.error(f"Run {run_id} not found")
        return {'status': 'error', 'message': 'Run not found'}
    
    events_redacted = 0
    pii_instances = 0
    
    for event in TraceEvent.objects.filter(run=run):
        try:
            # Scan for PII
            pii_matches = pii_detector.scan_dict(event.payload)
            
            if pii_matches:
                # Redact
                redacted_payload = pii_detector.redact_dict(event.payload)
                event.payload = redacted_payload
                
                if not event.metadata:
                    event.metadata = {}
                event.metadata['pii_redacted'] = True
                event.metadata['pii_redacted_at'] = timezone.now().isoformat()
                event.metadata['redaction_reason'] = reason
                event.save()
                
                # Log
                RedactionLog.objects.create(
                    run=run,
                    trace_event=event,
                    redaction_type='pii_mask',
                    fields_redacted=[match.field_path for match in pii_matches],
                    pii_types_found=list(set(match.pattern for match in pii_matches)),
                    redacted_by='system',
                    reason=reason
                )
                
                events_redacted += 1
                pii_instances += len(pii_matches)
        
        except Exception as e:
            logger.error(f"Error redacting event {event.id}: {e}", exc_info=True)
    
    logger.info(f"Redacted {events_redacted} events in run {run_id}, found {pii_instances} PII instances")
    
    return {
        'status': 'completed',
        'run_id': run_id,
        'events_redacted': events_redacted,
        'pii_instances': pii_instances
    }
