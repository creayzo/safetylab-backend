"""
Monitoring and Health Check API Endpoints

Provides:
- Health check endpoints
- Prometheus metrics export
- System status
"""

from rest_framework.decorators import api_view, permission_classes
from rest_framework.response import Response
from rest_framework import status
from rest_framework.permissions import AllowAny, IsAdminUser
from django.http import HttpResponse

from api.monitoring import (
    health_checker,
    performance_monitor,
    backpressure_handler,
    METRICS_ENABLED
)


@api_view(['GET'])
@permission_classes([AllowAny])
def health_check(request):
    """
    GET /api/health/ - Basic health check
    
    Returns 200 if system is operational.
    """
    result = health_checker.comprehensive_health_check()
    
    # Determine overall status
    components = result['components']
    all_healthy = all(
        comp.get('status') in ['healthy', 'not_configured']
        for comp in components.values()
    )
    
    result['overall_status'] = 'healthy' if all_healthy else 'degraded'
    
    return Response(result, status=status.HTTP_200_OK if all_healthy else status.HTTP_503_SERVICE_UNAVAILABLE)


@api_view(['GET'])
@permission_classes([IsAdminUser])
def system_status(request):
    """
    GET /api/system/status/ - Detailed system status
    
    Requires admin permissions.
    """
    from api.wal_models import EventWAL
    from api.models import Run, TraceEvent, Organization
    from django.db.models import Count, Q
    from datetime import timedelta
    from django.utils import timezone
    
    # WAL stats
    wal_stats = {
        'pending': EventWAL.objects.filter(status='pending').count(),
        'processing': EventWAL.objects.filter(status='processing').count(),
        'completed': EventWAL.objects.filter(status='completed').count(),
        'failed': EventWAL.objects.filter(status='failed').count()
    }
    
    # Recent activity (last 24 hours)
    last_24h = timezone.now() - timedelta(hours=24)
    recent_stats = {
        'runs_created': Run.objects.filter(created_at__gte=last_24h).count(),
        'events_received': TraceEvent.objects.filter(timestamp__gte=last_24h).count(),
        'active_organizations': Organization.objects.filter(
            agents__runs__created_at__gte=last_24h
        ).distinct().count()
    }
    
    # Backpressure status
    is_healthy, error_msg = backpressure_handler.check_system_load()
    
    return Response({
        'health': health_checker.comprehensive_health_check(),
        'wal': wal_stats,
        'recent_activity': recent_stats,
        'backpressure': {
            'status': 'healthy' if is_healthy else 'overloaded',
            'message': error_msg
        }
    })


@api_view(['GET'])
@permission_classes([AllowAny])
def metrics(request):
    """
    GET /api/metrics/ - Prometheus metrics export
    
    Returns metrics in Prometheus text format.
    """
    if not METRICS_ENABLED:
        return Response({
            'error': 'Metrics not enabled',
            'message': 'Install prometheus_client to enable metrics'
        }, status=status.HTTP_501_NOT_IMPLEMENTED)
    
    try:
        from prometheus_client import generate_latest, CONTENT_TYPE_LATEST
        
        # Update metrics before export
        performance_monitor.update_wal_queue_depth()
        performance_monitor.update_system_health()
        
        # Generate metrics
        metrics_output = generate_latest()
        
        return HttpResponse(
            metrics_output,
            content_type=CONTENT_TYPE_LATEST
        )
    
    except Exception as e:
        return Response({
            'error': 'Metrics generation failed',
            'message': str(e)
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@api_view(['GET'])
@permission_classes([IsAdminUser])
def retention_status(request):
    """
    GET /api/retention/status/ - Retention policy status
    
    Shows data retention status across organizations.
    """
    from api.retention_models import RetentionPolicy, DataDeletionRequest
    from api.models import Organization, TraceEvent
    from datetime import timedelta
    from django.utils import timezone
    
    org_stats = []
    
    for org in Organization.objects.filter(is_active=True):
        try:
            policy = RetentionPolicy.objects.get(organization=org)
        except RetentionPolicy.DoesNotExist:
            policy = None
        
        # Count traces
        total_traces = TraceEvent.objects.filter(
            run__agent__organization=org
        ).count()
        
        # Count expired traces
        if policy:
            cutoff = timezone.now() - timedelta(days=policy.trace_retention_days)
            expired_traces = TraceEvent.objects.filter(
                run__agent__organization=org,
                timestamp__lt=cutoff
            ).count()
        else:
            expired_traces = 0
        
        # Pending deletions
        pending_deletions = DataDeletionRequest.objects.filter(
            organization=org,
            status='pending'
        ).count()
        
        org_stats.append({
            'organization_id': org.id,
            'organization_name': org.name,
            'tier': policy.tier if policy else 'none',
            'total_traces': total_traces,
            'expired_traces': expired_traces,
            'pending_deletions': pending_deletions,
            'last_cleanup': policy.last_cleanup_at.isoformat() if policy and policy.last_cleanup_at else None
        })
    
    return Response({
        'timestamp': timezone.now().isoformat(),
        'organizations': org_stats
    })


@api_view(['POST'])
@permission_classes([IsAdminUser])
def trigger_cleanup(request):
    """
    POST /api/retention/cleanup/ - Manually trigger cleanup
    
    Requires admin permissions.
    """
    from api.retention_tasks import cleanup_expired_data
    
    # Trigger async cleanup
    task = cleanup_expired_data.delay()
    
    return Response({
        'message': 'Cleanup task triggered',
        'task_id': task.id
    }, status=status.HTTP_202_ACCEPTED)
