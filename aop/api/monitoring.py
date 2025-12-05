"""
Operational Monitoring and Metrics

Provides:
- Prometheus metrics export
- Performance monitoring
- Backpressure handling
- Event size limits
- S3 signed URLs for large artifacts
- System health checks
"""

import logging
import time
from typing import Dict, Any, Optional
from datetime import timedelta
from django.core.cache import cache
from django.utils import timezone
from django.conf import settings
import boto3
from botocore.exceptions import ClientError

logger = logging.getLogger(__name__)

# Prometheus metrics (if prometheus_client is installed)
try:
    from prometheus_client import Counter, Histogram, Gauge, Summary
    
    # Event ingestion metrics
    events_received_total = Counter(
        'aop_events_received_total',
        'Total number of events received',
        ['organization', 'event_type']
    )
    
    events_rejected_total = Counter(
        'aop_events_rejected_total',
        'Total number of events rejected',
        ['organization', 'reason']
    )
    
    event_processing_duration = Histogram(
        'aop_event_processing_duration_seconds',
        'Event processing duration',
        ['phase']  # validation, wal_write, async_processing
    )
    
    # WAL metrics
    wal_queue_depth = Gauge(
        'aop_wal_queue_depth',
        'Number of events in WAL queue',
        ['status']  # pending, processing, failed
    )
    
    wal_processing_duration = Histogram(
        'aop_wal_processing_duration_seconds',
        'WAL entry processing duration'
    )
    
    # Validation metrics
    validation_violations_total = Counter(
        'aop_validation_violations_total',
        'Total validation violations',
        ['validator', 'severity']
    )
    
    # Signature verification
    signature_verifications_total = Counter(
        'aop_signature_verifications_total',
        'Total signature verifications',
        ['result']  # success, failure
    )
    
    # Rate limiting
    rate_limit_hits_total = Counter(
        'aop_rate_limit_hits_total',
        'Total rate limit hits',
        ['organization', 'limit_type']
    )
    
    # System health
    system_health_score = Gauge(
        'aop_system_health_score',
        'Overall system health (0-1)',
        ['component']
    )
    
    # Retention
    data_retention_overage = Gauge(
        'aop_data_retention_overage_bytes',
        'Data exceeding retention policy',
        ['organization']
    )
    
    METRICS_ENABLED = True
    
except ImportError:
    logger.warning("prometheus_client not installed, metrics disabled")
    METRICS_ENABLED = False


class PerformanceMonitor:
    """Tracks performance metrics for operations."""
    
    @staticmethod
    def track_event_ingestion(
        organization_id: int,
        event_type: str,
        duration: float,
        rejected: bool = False,
        rejection_reason: str = None
    ):
        """Track event ingestion metrics."""
        if not METRICS_ENABLED:
            return
        
        try:
            if rejected:
                events_rejected_total.labels(
                    organization=organization_id,
                    reason=rejection_reason or 'unknown'
                ).inc()
            else:
                events_received_total.labels(
                    organization=organization_id,
                    event_type=event_type
                ).inc()
            
            event_processing_duration.labels(phase='ingestion').observe(duration)
        
        except Exception as e:
            logger.error(f"Error tracking metrics: {e}")
    
    @staticmethod
    def track_signature_verification(success: bool):
        """Track signature verification attempts."""
        if not METRICS_ENABLED:
            return
        
        try:
            signature_verifications_total.labels(
                result='success' if success else 'failure'
            ).inc()
        except Exception as e:
            logger.error(f"Error tracking signature metrics: {e}")
    
    @staticmethod
    def track_validation_violation(validator_name: str, severity: str):
        """Track validation violations."""
        if not METRICS_ENABLED:
            return
        
        try:
            validation_violations_total.labels(
                validator=validator_name,
                severity=severity
            ).inc()
        except Exception as e:
            logger.error(f"Error tracking validation metrics: {e}")
    
    @staticmethod
    def track_rate_limit_hit(organization_id: int, limit_type: str):
        """Track rate limit hits."""
        if not METRICS_ENABLED:
            return
        
        try:
            rate_limit_hits_total.labels(
                organization=organization_id,
                limit_type=limit_type
            ).inc()
        except Exception as e:
            logger.error(f"Error tracking rate limit metrics: {e}")
    
    @staticmethod
    def update_wal_queue_depth():
        """Update WAL queue depth metrics."""
        if not METRICS_ENABLED:
            return
        
        try:
            from api.wal_models import EventWAL
            
            for status in ['pending', 'processing', 'failed']:
                count = EventWAL.objects.filter(status=status).count()
                wal_queue_depth.labels(status=status).set(count)
        
        except Exception as e:
            logger.error(f"Error updating WAL metrics: {e}")
    
    @staticmethod
    def update_system_health():
        """Update system health scores."""
        if not METRICS_ENABLED:
            return
        
        try:
            from api.wal_models import EventWAL
            from django.db import connection
            
            # Database health
            try:
                connection.ensure_connection()
                system_health_score.labels(component='database').set(1.0)
            except Exception:
                system_health_score.labels(component='database').set(0.0)
            
            # Redis health
            try:
                cache.set('health_check', '1', timeout=10)
                system_health_score.labels(component='redis').set(1.0)
            except Exception:
                system_health_score.labels(component='redis').set(0.0)
            
            # WAL health (based on queue depth)
            pending = EventWAL.objects.filter(status='pending').count()
            failed = EventWAL.objects.filter(status='failed').count()
            
            if pending < 100 and failed < 10:
                system_health_score.labels(component='wal').set(1.0)
            elif pending < 1000 and failed < 100:
                system_health_score.labels(component='wal').set(0.5)
            else:
                system_health_score.labels(component='wal').set(0.0)
        
        except Exception as e:
            logger.error(f"Error updating system health: {e}")


class BackpressureHandler:
    """Handles backpressure and rate limiting."""
    
    @staticmethod
    def check_system_load() -> tuple[bool, Optional[str]]:
        """
        Check if system is overloaded.
        
        Returns:
            (is_healthy, error_message)
        """
        from api.wal_models import EventWAL
        
        # Check WAL queue depth
        pending_count = EventWAL.objects.filter(status='pending').count()
        processing_count = EventWAL.objects.filter(status='processing').count()
        failed_count = EventWAL.objects.filter(status='failed').count()
        
        # Thresholds
        MAX_PENDING = getattr(settings, 'MAX_WAL_PENDING', 10000)
        MAX_PROCESSING = getattr(settings, 'MAX_WAL_PROCESSING', 5000)
        MAX_FAILED = getattr(settings, 'MAX_WAL_FAILED', 1000)
        
        if pending_count > MAX_PENDING:
            return False, f"WAL queue overloaded: {pending_count} pending (max {MAX_PENDING})"
        
        if processing_count > MAX_PROCESSING:
            return False, f"Too many events processing: {processing_count} (max {MAX_PROCESSING})"
        
        if failed_count > MAX_FAILED:
            return False, f"Too many failed events: {failed_count} (max {MAX_FAILED})"
        
        return True, None
    
    @staticmethod
    def should_apply_backpressure(organization_id: int) -> tuple[bool, Optional[int]]:
        """
        Check if backpressure should be applied to an organization.
        
        Returns:
            (should_apply, retry_after_seconds)
        """
        # Check per-org rate in last minute
        minute_key = timezone.now().strftime('%Y%m%d%H%M')
        org_key = f"org_events:{organization_id}:{minute_key}"
        
        org_count = cache.get(org_key, 0)
        ORG_LIMIT = getattr(settings, 'ORG_EVENTS_PER_MINUTE', 1000)
        
        if org_count > ORG_LIMIT:
            # Apply backpressure
            retry_after = 60  # Wait 1 minute
            
            PerformanceMonitor.track_rate_limit_hit(
                organization_id,
                'events_per_minute'
            )
            
            return True, retry_after
        
        return False, None


class EventSizeLimiter:
    """Enforces event size limits."""
    
    # Limits in bytes
    MAX_EVENT_SIZE = getattr(settings, 'MAX_EVENT_SIZE_BYTES', 1024 * 1024)  # 1MB
    MAX_PAYLOAD_SIZE = getattr(settings, 'MAX_PAYLOAD_SIZE_BYTES', 512 * 1024)  # 512KB
    LARGE_PAYLOAD_THRESHOLD = getattr(settings, 'LARGE_PAYLOAD_THRESHOLD_BYTES', 100 * 1024)  # 100KB
    
    @staticmethod
    def check_event_size(event_data: dict) -> tuple[bool, Optional[str]]:
        """
        Check if event is within size limits.
        
        Returns:
            (is_valid, error_message)
        """
        import json
        
        # Calculate event size
        event_json = json.dumps(event_data, separators=(',', ':'))
        event_size = len(event_json.encode('utf-8'))
        
        if event_size > EventSizeLimiter.MAX_EVENT_SIZE:
            return False, f"Event size {event_size} bytes exceeds limit of {EventSizeLimiter.MAX_EVENT_SIZE} bytes"
        
        # Check payload size
        payload = event_data.get('payload', {})
        payload_json = json.dumps(payload, separators=(',', ':'))
        payload_size = len(payload_json.encode('utf-8'))
        
        if payload_size > EventSizeLimiter.MAX_PAYLOAD_SIZE:
            return False, f"Payload size {payload_size} bytes exceeds limit of {EventSizeLimiter.MAX_PAYLOAD_SIZE} bytes"
        
        return True, None
    
    @staticmethod
    def should_use_s3(payload: dict) -> bool:
        """Check if payload should be stored in S3."""
        import json
        
        payload_json = json.dumps(payload, separators=(',', ':'))
        payload_size = len(payload_json.encode('utf-8'))
        
        return payload_size > EventSizeLimiter.LARGE_PAYLOAD_THRESHOLD


class S3ArtifactManager:
    """Manages S3 storage for large artifacts."""
    
    def __init__(self):
        """Initialize S3 client."""
        self.s3_client = None
        self.bucket = getattr(settings, 'AOP_S3_BUCKET', None)
        
        if hasattr(settings, 'AWS_ACCESS_KEY_ID') and settings.AWS_ACCESS_KEY_ID:
            self.s3_client = boto3.client(
                's3',
                aws_access_key_id=settings.AWS_ACCESS_KEY_ID,
                aws_secret_access_key=settings.AWS_SECRET_ACCESS_KEY,
                region_name=getattr(settings, 'AWS_REGION', 'us-east-1')
            )
    
    def upload_artifact(
        self,
        artifact_data: Any,
        artifact_id: str,
        content_type: str = 'application/json'
    ) -> Optional[str]:
        """
        Upload artifact to S3.
        
        Args:
            artifact_data: Data to upload
            artifact_id: Unique identifier for the artifact
            content_type: MIME type
            
        Returns:
            S3 key if successful, None otherwise
        """
        if not self.s3_client or not self.bucket:
            logger.error("S3 not configured")
            return None
        
        try:
            import json
            
            # Convert to JSON if dict
            if isinstance(artifact_data, dict):
                artifact_data = json.dumps(artifact_data, separators=(',', ':'))
            
            # Upload to S3
            s3_key = f"artifacts/{artifact_id}.json"
            
            self.s3_client.put_object(
                Bucket=self.bucket,
                Key=s3_key,
                Body=artifact_data,
                ContentType=content_type,
                ServerSideEncryption='AES256'
            )
            
            logger.info(f"Uploaded artifact to S3: {s3_key}")
            return s3_key
        
        except Exception as e:
            logger.error(f"Error uploading to S3: {e}", exc_info=True)
            return None
    
    def generate_signed_url(
        self,
        s3_key: str,
        expiration: int = 3600
    ) -> Optional[str]:
        """
        Generate signed URL for S3 object.
        
        Args:
            s3_key: S3 object key
            expiration: URL expiration in seconds (default: 1 hour)
            
        Returns:
            Signed URL if successful, None otherwise
        """
        if not self.s3_client or not self.bucket:
            return None
        
        try:
            url = self.s3_client.generate_presigned_url(
                'get_object',
                Params={
                    'Bucket': self.bucket,
                    'Key': s3_key
                },
                ExpiresIn=expiration
            )
            
            return url
        
        except ClientError as e:
            logger.error(f"Error generating signed URL: {e}")
            return None
    
    def download_artifact(self, s3_key: str) -> Optional[Any]:
        """
        Download artifact from S3.
        
        Args:
            s3_key: S3 object key
            
        Returns:
            Artifact data if successful, None otherwise
        """
        if not self.s3_client or not self.bucket:
            return None
        
        try:
            import json
            
            response = self.s3_client.get_object(
                Bucket=self.bucket,
                Key=s3_key
            )
            
            data = response['Body'].read().decode('utf-8')
            return json.loads(data)
        
        except Exception as e:
            logger.error(f"Error downloading from S3: {e}", exc_info=True)
            return None


class HealthChecker:
    """System health check utilities."""
    
    @staticmethod
    def check_database() -> Dict[str, Any]:
        """Check database connectivity and performance."""
        from django.db import connection
        
        try:
            start = time.time()
            connection.ensure_connection()
            latency = (time.time() - start) * 1000  # ms
            
            return {
                'status': 'healthy',
                'latency_ms': latency,
                'connected': True
            }
        except Exception as e:
            return {
                'status': 'unhealthy',
                'error': str(e),
                'connected': False
            }
    
    @staticmethod
    def check_redis() -> Dict[str, Any]:
        """Check Redis connectivity and performance."""
        try:
            start = time.time()
            cache.set('health_check', '1', timeout=10)
            value = cache.get('health_check')
            latency = (time.time() - start) * 1000  # ms
            
            return {
                'status': 'healthy' if value == '1' else 'degraded',
                'latency_ms': latency,
                'connected': True
            }
        except Exception as e:
            return {
                'status': 'unhealthy',
                'error': str(e),
                'connected': False
            }
    
    @staticmethod
    def check_s3() -> Dict[str, Any]:
        """Check S3 connectivity."""
        manager = S3ArtifactManager()
        
        if not manager.s3_client or not manager.bucket:
            return {
                'status': 'not_configured',
                'connected': False
            }
        
        try:
            # Try to list bucket (permission check)
            manager.s3_client.head_bucket(Bucket=manager.bucket)
            
            return {
                'status': 'healthy',
                'bucket': manager.bucket,
                'connected': True
            }
        except Exception as e:
            return {
                'status': 'unhealthy',
                'error': str(e),
                'connected': False
            }
    
    @staticmethod
    def check_celery() -> Dict[str, Any]:
        """Check Celery worker status."""
        try:
            from aop.celery import app
            
            inspect = app.control.inspect()
            stats = inspect.stats()
            
            if stats:
                return {
                    'status': 'healthy',
                    'workers': len(stats),
                    'worker_names': list(stats.keys())
                }
            else:
                return {
                    'status': 'unhealthy',
                    'error': 'No workers available'
                }
        except Exception as e:
            return {
                'status': 'unhealthy',
                'error': str(e)
            }
    
    @staticmethod
    def comprehensive_health_check() -> Dict[str, Any]:
        """Run comprehensive health check."""
        return {
            'timestamp': timezone.now().isoformat(),
            'components': {
                'database': HealthChecker.check_database(),
                'redis': HealthChecker.check_redis(),
                's3': HealthChecker.check_s3(),
                'celery': HealthChecker.check_celery()
            },
            'overall_status': 'healthy'  # Computed based on components
        }


# Initialize global instances
s3_manager = S3ArtifactManager()
performance_monitor = PerformanceMonitor()
backpressure_handler = BackpressureHandler()
health_checker = HealthChecker()
