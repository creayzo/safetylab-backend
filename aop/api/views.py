"""
API Views for AOP Platform

Endpoints for trace event submission, run management, and admin operations.
All endpoints require authentication and enforce TLS in production.
"""

from rest_framework import status, viewsets
from rest_framework.decorators import api_view, action, permission_classes
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated, IsAdminUser
from rest_framework.views import APIView
from django.http import StreamingHttpResponse, HttpResponse, JsonResponse
from django.utils import timezone
from django.db import transaction
from django.core.exceptions import ValidationError
import json
import uuid
import zipfile
import io
import logging
import requests

from api.models import (
    Organization,
    Agent,
    Run,
    TraceEvent,
    TraceRecord,
    EnvironmentSnapshot,
    AuditLog
)
from api.auth_models import (
    OrganizationSaltKey,
    AgentAPIKey,
    SignatureVerifier,
    MTLSCertificate
)
from api.serializers import (
    TraceEventSerializer,
    CreateRunSerializer,
    RunSerializer,
    BatchTraceEventsSerializer,
    FinalizeRunSerializer,
    TraceDownloadSerializer,
    AgentValidateCallbackSerializer,
    OrganizationSerializer,
    AgentSerializer,
    CreateAPIKeySerializer,
    AgentAPIKeySerializer,
    RotateSaltKeySerializer,
    UpdateRetentionPolicySerializer,
    AuditLogSerializer
)
from api.middleware import APIKeyAuthentication

logger = logging.getLogger(__name__)


# ============================================================================
# Run Management Endpoints
# ============================================================================

@api_view(['POST'])
def create_run(request):
    """
    POST /api/runs/ - Create a new run
    
    Returns run_id and seed for the new run.
    
    Request body:
    {
      "agent_id": 123,
      "scenario_id": "optional-scenario-id",
      "seed": 42  // optional
    }
    
    Response:
    {
      "run_id": "uuid",
      "agent_id": 123,
      "scenario_id": "...",
      "seed": 42,
      "status": "running",
      "start_ts": "2025-12-05T10:00:00Z"
    }
    """
    serializer = CreateRunSerializer(data=request.data, context={'request': request})
    
    if not serializer.is_valid():
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
    validated_data = serializer.validated_data
    
    try:
        # Get agent
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
        
        # Return run details
        response_serializer = RunSerializer(run)
        return Response(response_serializer.data, status=status.HTTP_201_CREATED)
    
    except Agent.DoesNotExist:
        return Response(
            {'error': 'Agent not found'},
            status=status.HTTP_404_NOT_FOUND
        )
    except Exception as e:
        logger.error(f"Error creating run: {e}")
        return Response(
            {'error': 'Internal server error'},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )


@api_view(['POST'])
def append_trace_event(request, run_id):
    """
    POST /api/runs/{run_id}/events/ - Append a single TraceEvent
    
    Accepts Toon-formatted event with signature verification.
    Supports streaming via chunked upload.
    
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
        "signature": "hmac_signature"
      }
    }
    """
    try:
        # Validate run exists
        run = Run.objects.select_related('agent', 'agent__owner').get(run_id=run_id)
    except Run.DoesNotExist:
        return Response(
            {'error': 'Run not found'},
            status=status.HTTP_404_NOT_FOUND
        )
    
    # Validate event
    serializer = TraceEventSerializer(data=request.data)
    if not serializer.is_valid():
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
    validated_data = serializer.validated_data
    
    # Verify signature if org has salt key
    org_salt_key = run.agent.owner.get_active_salt_key()
    if org_salt_key:
        signature = validated_data['meta'].get('signature', '')
        payload_str = validated_data['payload']
        
        is_valid = SignatureVerifier.verify_signature(
            org_salt_key.decrypt_salt(),
            str(run_id),
            validated_data['seq'],
            payload_str,
            signature
        )
        
        if not is_valid:
            logger.warning(f"Invalid signature for run {run_id}, seq {validated_data['seq']}")
            return Response(
                {'error': 'Invalid signature'},
                status=status.HTTP_401_UNAUTHORIZED
            )
    
    # Create trace event
    try:
        trace_event = TraceEvent.objects.create(
            run=run,
            seq_no=validated_data['seq'],
            timestamp=validated_data['timestamp'],
            actor=validated_data['actor'],
            type=validated_data['type'],
            payload=validated_data['payload'],
            signature=validated_data['meta'].get('signature', ''),
            meta=validated_data['meta']
        )
        
        logger.debug(f"Created trace event {run_id}:{validated_data['seq']}")
        
        return Response(
            {'status': 'created', 'seq': trace_event.seq_no},
            status=status.HTTP_201_CREATED
        )
    
    except Exception as e:
        logger.error(f"Error creating trace event: {e}")
        return Response(
            {'error': str(e)},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )


@api_view(['POST'])
def batch_trace_events(request):
    """
    POST /api/trace-events/batch/ - Batch event submission
    
    Accepts multiple events in a single request with idempotency.
    
    Request body:
    {
      "run_id": "uuid",
      "agent_id": 123,
      "events": [...],
      "idempotency_token": "uuid"  // optional
    }
    """
    serializer = BatchTraceEventsSerializer(data=request.data)
    
    if not serializer.is_valid():
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
    validated_data = serializer.validated_data
    run_id = validated_data['run_id']
    events = validated_data['events']
    
    try:
        run = Run.objects.select_related('agent', 'agent__owner').get(run_id=run_id)
    except Run.DoesNotExist:
        return Response(
            {'error': 'Run not found'},
            status=status.HTTP_404_NOT_FOUND
        )
    
    # Get org salt key for verification
    org_salt_key = run.agent.owner.get_active_salt_key()
    
    created_count = 0
    skipped_count = 0
    errors = []
    
    with transaction.atomic():
        for event_data in events:
            try:
                # Verify signature
                if org_salt_key:
                    signature = event_data['meta'].get('signature', '')
                    is_valid = SignatureVerifier.verify_signature(
                        org_salt_key.decrypt_salt(),
                        str(run_id),
                        event_data['seq'],
                        event_data['payload'],
                        signature
                    )
                    
                    if not is_valid:
                        errors.append(f"Invalid signature for seq {event_data['seq']}")
                        continue
                
                # Check if event already exists (idempotency)
                if TraceEvent.objects.filter(run=run, seq_no=event_data['seq']).exists():
                    skipped_count += 1
                    continue
                
                # Create event
                TraceEvent.objects.create(
                    run=run,
                    seq_no=event_data['seq'],
                    timestamp=event_data['timestamp'],
                    actor=event_data['actor'],
                    type=event_data['type'],
                    payload=event_data['payload'],
                    signature=event_data['meta'].get('signature', ''),
                    meta=event_data['meta']
                )
                
                created_count += 1
            
            except Exception as e:
                errors.append(f"seq {event_data['seq']}: {str(e)}")
    
    logger.info(f"Batch upload: {created_count} created, {skipped_count} skipped, {len(errors)} errors")
    
    return Response({
        'status': 'completed',
        'created': created_count,
        'skipped': skipped_count,
        'errors': errors
    }, status=status.HTTP_200_OK if not errors else status.HTTP_207_MULTI_STATUS)


@api_view(['POST'])
def finalize_run(request, run_id):
    """
    POST /api/runs/{run_id}/finalize/ - Finalize a run
    
    Marks the run as complete, computes summary metrics, and persists trace.
    
    Request body:
    {
      "summary_metrics": {...},  // optional
      "object_store_path": "s3://..."  // optional
    }
    """
    try:
        run = Run.objects.select_related('agent').get(run_id=run_id)
    except Run.DoesNotExist:
        return Response(
            {'error': 'Run not found'},
            status=status.HTTP_404_NOT_FOUND
        )
    
    if run.status != 'running':
        return Response(
            {'error': f'Run already finalized with status: {run.status}'},
            status=status.HTTP_400_BAD_REQUEST
        )
    
    serializer = FinalizeRunSerializer(data=request.data)
    if not serializer.is_valid():
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
    validated_data = serializer.validated_data
    
    try:
        with transaction.atomic():
            # Update run status
            run.status = 'success'
            run.end_ts = timezone.now()
            run.save()
            
            # Count events
            event_count = TraceEvent.objects.filter(run=run).count()
            
            # Create or update trace record
            trace_record, created = TraceRecord.objects.update_or_create(
                run=run,
                defaults={
                    'aggregation_pointer': f"run_{run_id}",
                    'summary_metrics': validated_data.get('summary_metrics', {
                        'event_count': event_count,
                        'duration_seconds': (run.end_ts - run.start_ts).total_seconds()
                    }),
                    'object_store_path': validated_data.get('object_store_path', f"traces/{run_id}")
                }
            )
            
            logger.info(f"Finalized run {run_id} with {event_count} events")
            
            return Response({
                'status': 'finalized',
                'run_id': str(run_id),
                'event_count': event_count,
                'duration_seconds': (run.end_ts - run.start_ts).total_seconds(),
                'end_ts': run.end_ts.isoformat()
            }, status=status.HTTP_200_OK)
    
    except Exception as e:
        logger.error(f"Error finalizing run {run_id}: {e}")
        
        # Mark run as failed
        run.status = 'failed'
        run.end_ts = timezone.now()
        run.save()
        
        return Response(
            {'error': 'Failed to finalize run'},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )


@api_view(['GET'])
def download_trace(request, run_id):
    """
    GET /api/runs/{run_id}/trace - Download full trace
    
    Query parameters:
    - format: toon (default), json, or zip
    - include_metadata: true (default) or false
    - pretty: true or false (default)
    
    Returns the complete trace in requested format.
    Requires authentication.
    """
    try:
        run = Run.objects.select_related('agent', 'agent__owner').get(run_id=run_id)
    except Run.DoesNotExist:
        return Response(
            {'error': 'Run not found'},
            status=status.HTTP_404_NOT_FOUND
        )
    
    # Validate format
    format_type = request.query_params.get('format', 'toon')
    include_metadata = request.query_params.get('include_metadata', 'true').lower() == 'true'
    pretty = request.query_params.get('pretty', 'false').lower() == 'true'
    
    if format_type not in ['toon', 'json', 'zip']:
        return Response(
            {'error': 'Invalid format. Must be toon, json, or zip'},
            status=status.HTTP_400_BAD_REQUEST
        )
    
    # Get all trace events
    events = TraceEvent.objects.filter(run=run).order_by('seq_no')
    
    # Build trace data
    trace_data = {
        'run_id': str(run.run_id),
        'agent_id': run.agent.id,
        'status': run.status,
        'start_ts': run.start_ts.isoformat(),
        'end_ts': run.end_ts.isoformat() if run.end_ts else None,
        'event_count': events.count(),
        'events': []
    }
    
    if include_metadata:
        trace_data['metadata'] = {
            'seed': run.seed,
            'scenario_id': run.scenario_id,
            'organization': run.agent.owner.name,
            'agent_config': run.agent.runtime_config
        }
    
    # Add events in Toon format
    for event in events:
        trace_data['events'].append(event.get_toon_canonical_format())
    
    # Return based on format
    if format_type == 'zip':
        # Create zip file with trace and metadata
        zip_buffer = io.BytesIO()
        
        with zipfile.ZipFile(zip_buffer, 'w', zipfile.ZIP_DEFLATED) as zip_file:
            # Add trace JSON
            trace_json = json.dumps(trace_data, indent=2 if pretty else None)
            zip_file.writestr('trace.json', trace_json)
            
            # Add individual event files
            for event in events:
                event_json = json.dumps(event.get_toon_canonical_format(), indent=2 if pretty else None)
                zip_file.writestr(f'events/event_{event.seq_no:04d}.json', event_json)
            
            # Add metadata
            if include_metadata:
                metadata_json = json.dumps(trace_data['metadata'], indent=2)
                zip_file.writestr('metadata.json', metadata_json)
        
        zip_buffer.seek(0)
        
        response = HttpResponse(zip_buffer.getvalue(), content_type='application/zip')
        response['Content-Disposition'] = f'attachment; filename="trace_{run_id}.zip"'
        return response
    
    else:
        # Return JSON
        indent = 2 if pretty else None
        return Response(trace_data, status=status.HTTP_200_OK)


# ============================================================================
# Agent Management Endpoints
# ============================================================================

@api_view(['POST'])
def validate_agent_callback(request):
    """
    POST /api/agents/validate_callback - Test agent connectivity
    
    Healthcheck endpoint to validate agent callback URL is reachable.
    
    Request body:
    {
      "callback_url": "https://agent.example.com/callback",
      "timeout": 5  // optional, seconds
    }
    """
    serializer = AgentValidateCallbackSerializer(data=request.data)
    
    if not serializer.is_valid():
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
    validated_data = serializer.validated_data
    callback_url = validated_data['callback_url']
    timeout = validated_data['timeout']
    
    try:
        # Send test request
        start_time = timezone.now()
        response = requests.get(
            callback_url,
            timeout=timeout,
            headers={'User-Agent': 'AOP-HealthCheck/1.0'}
        )
        end_time = timezone.now()
        
        latency_ms = (end_time - start_time).total_seconds() * 1000
        
        return Response({
            'status': 'reachable',
            'http_status': response.status_code,
            'latency_ms': round(latency_ms, 2),
            'timestamp': end_time.isoformat()
        }, status=status.HTTP_200_OK)
    
    except requests.Timeout:
        return Response({
            'status': 'timeout',
            'error': f'Request timed out after {timeout}s',
            'timestamp': timezone.now().isoformat()
        }, status=status.HTTP_408_REQUEST_TIMEOUT)
    
    except requests.ConnectionError as e:
        return Response({
            'status': 'unreachable',
            'error': 'Connection failed',
            'timestamp': timezone.now().isoformat()
        }, status=status.HTTP_503_SERVICE_UNAVAILABLE)
    
    except Exception as e:
        return Response({
            'status': 'error',
            'error': str(e),
            'timestamp': timezone.now().isoformat()
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


# ============================================================================
# Admin Endpoints
# ============================================================================

@api_view(['POST'])
@permission_classes([IsAdminUser])
def rotate_org_salt_key(request, org_id):
    """
    POST /api/admin/organizations/{org_id}/rotate_salt_key
    
    Rotate organization's salt key. Admin only.
    
    Request body:
    {
      "expiry_days": 90  // optional, default 90
    }
    """
    try:
        org = Organization.objects.get(id=org_id)
    except Organization.DoesNotExist:
        return Response(
            {'error': 'Organization not found'},
            status=status.HTTP_404_NOT_FOUND
        )
    
    serializer = RotateSaltKeySerializer(data=request.data)
    if not serializer.is_valid():
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
    try:
        new_key = org.rotate_salt_key(
            expiry_days=serializer.validated_data['expiry_days']
        )
        
        # Create audit log
        AuditLog.objects.create(
            organization=org,
            actor='admin',
            type='config_change',
            payload=json.dumps({
                'action': 'rotate_salt_key',
                'new_version': new_key.version,
                'expiry_days': serializer.validated_data['expiry_days']
            }),
            user_id=request.user.id,
            meta={'admin_user': request.user.username}
        )
        
        logger.info(f"Rotated salt key for org {org.name} to version {new_key.version}")
        
        return Response({
            'status': 'rotated',
            'new_version': new_key.version,
            'created_at': new_key.created_at.isoformat()
        }, status=status.HTTP_200_OK)
    
    except Exception as e:
        logger.error(f"Error rotating salt key: {e}")
        return Response(
            {'error': 'Failed to rotate salt key'},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )


@api_view(['PUT'])
@permission_classes([IsAdminUser])
def update_retention_policy(request, org_id):
    """
    PUT /api/admin/organizations/{org_id}/retention_policy
    
    Update organization's retention policy. Admin only.
    
    Request body:
    {
      "trace_retention_days": 90,
      "audit_log_retention_days": 180,
      "auto_delete_expired": true
    }
    """
    try:
        org = Organization.objects.get(id=org_id)
    except Organization.DoesNotExist:
        return Response(
            {'error': 'Organization not found'},
            status=status.HTTP_404_NOT_FOUND
        )
    
    serializer = UpdateRetentionPolicySerializer(data=request.data)
    if not serializer.is_valid():
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
    validated_data = serializer.validated_data
    
    try:
        # Update retention policy
        org.retention_policy = {
            'trace_retention_days': validated_data['trace_retention_days'],
            'audit_log_retention_days': validated_data['audit_log_retention_days'],
            'auto_delete_expired': validated_data['auto_delete_expired'],
            'updated_at': timezone.now().isoformat(),
            'updated_by': request.user.username
        }
        org.save()
        
        # Create audit log
        AuditLog.objects.create(
            organization=org,
            actor='admin',
            type='policy_update',
            payload=json.dumps({
                'action': 'update_retention_policy',
                'policy': org.retention_policy
            }),
            user_id=request.user.id,
            meta={'admin_user': request.user.username}
        )
        
        logger.info(f"Updated retention policy for org {org.name}")
        
        return Response({
            'status': 'updated',
            'retention_policy': org.retention_policy
        }, status=status.HTTP_200_OK)
    
    except Exception as e:
        logger.error(f"Error updating retention policy: {e}")
        return Response(
            {'error': 'Failed to update retention policy'},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )


@api_view(['GET'])
@permission_classes([IsAdminUser])
def list_audit_logs(request, org_id):
    """
    GET /api/admin/organizations/{org_id}/audit_logs
    
    List audit logs for an organization. Admin only.
    
    Query parameters:
    - limit: max results (default 100)
    - offset: pagination offset (default 0)
    - actor: filter by actor type
    - type: filter by event type
    """
    try:
        org = Organization.objects.get(id=org_id)
    except Organization.DoesNotExist:
        return Response(
            {'error': 'Organization not found'},
            status=status.HTTP_404_NOT_FOUND
        )
    
    # Get query parameters
    limit = int(request.query_params.get('limit', 100))
    offset = int(request.query_params.get('offset', 0))
    actor_filter = request.query_params.get('actor')
    type_filter = request.query_params.get('type')
    
    # Build query
    queryset = AuditLog.objects.filter(organization=org)
    
    if actor_filter:
        queryset = queryset.filter(actor=actor_filter)
    
    if type_filter:
        queryset = queryset.filter(type=type_filter)
    
    # Paginate
    total_count = queryset.count()
    logs = queryset.order_by('-timestamp')[offset:offset + limit]
    
    # Serialize
    serializer = AuditLogSerializer(logs, many=True)
    
    return Response({
        'total_count': total_count,
        'limit': limit,
        'offset': offset,
        'results': serializer.data
    }, status=status.HTTP_200_OK)
