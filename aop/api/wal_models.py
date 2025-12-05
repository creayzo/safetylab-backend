"""
Write-Ahead Log (WAL) Models

This module implements durable event queueing before processing.
Events are first written to WAL (Redis stream + DB backup), then
asynchronously consumed by workers for persistence and forwarding.

Pipeline:
1. API receives event → validate → write to WAL
2. Return success immediately (durability guaranteed)
3. Async worker consumes WAL → persist to DB/S3 → forward to evaluation engine
4. Mark WAL entry as processed

Benefits:
- Durability: Events survive server crashes
- Performance: API returns fast, heavy work happens async
- Idempotency: Seq + idempotency_key prevent duplicates
- Ordering: Seq numbers ensure correct event sequence
"""

import json
import uuid
from datetime import timedelta
from django.db import models, transaction
from django.utils import timezone
from django.conf import settings
import redis


class EventWAL(models.Model):
    """
    Write-Ahead Log entry for incoming events.
    
    Events are written here first for durability, then processed
    asynchronously by workers. This ensures no data loss even if
    the server crashes before processing.
    """
    
    STATUS_CHOICES = [
        ('pending', 'Pending'),
        ('processing', 'Processing'),
        ('completed', 'Completed'),
        ('failed', 'Failed'),
        ('retrying', 'Retrying'),
    ]
    
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    
    # Event identification
    run_id = models.UUIDField(db_index=True)
    agent_id = models.IntegerField(db_index=True)
    seq_no = models.IntegerField()
    idempotency_key = models.CharField(max_length=255, unique=True, db_index=True)
    
    # Event data
    event_type = models.CharField(max_length=50)
    timestamp = models.DateTimeField()
    payload = models.JSONField()
    metadata = models.JSONField(default=dict, blank=True)
    
    # Processing status
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='pending', db_index=True)
    created_at = models.DateTimeField(auto_now_add=True, db_index=True)
    processed_at = models.DateTimeField(null=True, blank=True)
    
    # Error tracking
    error_message = models.TextField(blank=True)
    retry_count = models.IntegerField(default=0)
    last_retry_at = models.DateTimeField(null=True, blank=True)
    
    # Signature verification
    signature = models.CharField(max_length=64)
    signature_verified = models.BooleanField(default=False)
    
    class Meta:
        db_table = 'api_event_wal'
        ordering = ['run_id', 'seq_no']
        indexes = [
            models.Index(fields=['status', 'created_at']),
            models.Index(fields=['run_id', 'seq_no']),
            models.Index(fields=['agent_id', 'created_at']),
        ]
        unique_together = [['run_id', 'seq_no']]
    
    def __str__(self):
        return f"WAL[{self.id}] Run:{self.run_id} Seq:{self.seq_no} Status:{self.status}"
    
    def mark_processing(self):
        """Mark entry as being processed."""
        self.status = 'processing'
        self.save(update_fields=['status'])
    
    def mark_completed(self, trace_event_id=None):
        """Mark entry as successfully processed."""
        self.status = 'completed'
        self.processed_at = timezone.now()
        if trace_event_id:
            self.metadata['trace_event_id'] = str(trace_event_id)
        self.save(update_fields=['status', 'processed_at', 'metadata'])
    
    def mark_failed(self, error_message: str):
        """Mark entry as failed."""
        self.status = 'failed'
        self.error_message = error_message
        self.processed_at = timezone.now()
        self.save(update_fields=['status', 'error_message', 'processed_at'])
    
    def can_retry(self, max_retries: int = 3) -> bool:
        """Check if entry can be retried."""
        return self.retry_count < max_retries and self.status in ['failed', 'retrying']
    
    def increment_retry(self):
        """Increment retry counter and mark as retrying."""
        self.retry_count += 1
        self.last_retry_at = timezone.now()
        self.status = 'retrying'
        self.save(update_fields=['retry_count', 'last_retry_at', 'status'])
    
    @classmethod
    def get_pending_entries(cls, limit: int = 100):
        """Get pending WAL entries for processing."""
        return cls.objects.filter(
            status='pending'
        ).order_by('created_at')[:limit]
    
    @classmethod
    def get_retry_entries(cls, max_age_minutes: int = 5):
        """Get failed entries eligible for retry."""
        cutoff = timezone.now() - timedelta(minutes=max_age_minutes)
        return cls.objects.filter(
            status__in=['failed', 'retrying'],
            retry_count__lt=3,
            created_at__gte=cutoff
        ).order_by('retry_count', 'created_at')
    
    @classmethod
    def cleanup_old_entries(cls, days: int = 7):
        """Delete old completed entries to save space."""
        cutoff = timezone.now() - timedelta(days=days)
        deleted = cls.objects.filter(
            status='completed',
            processed_at__lt=cutoff
        ).delete()
        return deleted[0]


class RedisWALStream:
    """
    Redis Stream-based WAL for high-performance event queueing.
    
    This provides an in-memory, durable queue for events with automatic
    consumer groups and acknowledgment. Falls back to DB-only if Redis
    is unavailable.
    """
    
    STREAM_NAME = "aop:event_wal"
    CONSUMER_GROUP = "aop_workers"
    
    def __init__(self):
        """Initialize Redis connection."""
        try:
            self.redis_client = redis.Redis(
                host=getattr(settings, 'REDIS_HOST', 'localhost'),
                port=getattr(settings, 'REDIS_PORT', 6379),
                db=getattr(settings, 'REDIS_WAL_DB', 0),
                decode_responses=True,
                socket_connect_timeout=2,
                socket_timeout=2
            )
            self.redis_client.ping()
            self.available = True
            self._ensure_consumer_group()
        except (redis.ConnectionError, redis.TimeoutError, AttributeError):
            self.available = False
            self.redis_client = None
    
    def _ensure_consumer_group(self):
        """Create consumer group if it doesn't exist."""
        if not self.available:
            return
        
        try:
            self.redis_client.xgroup_create(
                self.STREAM_NAME,
                self.CONSUMER_GROUP,
                id='0',
                mkstream=True
            )
        except redis.ResponseError as e:
            # Group already exists
            if 'BUSYGROUP' not in str(e):
                raise
    
    def append_event(self, wal_entry: EventWAL) -> bool:
        """
        Append event to Redis stream.
        
        Args:
            wal_entry: EventWAL instance
            
        Returns:
            True if appended to Redis, False if fallback to DB only
        """
        if not self.available:
            return False
        
        try:
            event_data = {
                'wal_id': str(wal_entry.id),
                'run_id': str(wal_entry.run_id),
                'agent_id': str(wal_entry.agent_id),
                'seq_no': str(wal_entry.seq_no),
                'event_type': wal_entry.event_type,
                'idempotency_key': wal_entry.idempotency_key,
                'timestamp': wal_entry.timestamp.isoformat(),
                'payload': json.dumps(wal_entry.payload),
                'signature': wal_entry.signature,
            }
            
            self.redis_client.xadd(self.STREAM_NAME, event_data, maxlen=100000)
            return True
            
        except (redis.ConnectionError, redis.TimeoutError):
            self.available = False
            return False
    
    def read_events(self, consumer_name: str, count: int = 10, block: int = 5000):
        """
        Read events from stream as a consumer.
        
        Args:
            consumer_name: Unique consumer identifier
            count: Max events to read
            block: Block time in milliseconds
            
        Returns:
            List of (message_id, event_data) tuples
        """
        if not self.available:
            return []
        
        try:
            messages = self.redis_client.xreadgroup(
                groupname=self.CONSUMER_GROUP,
                consumername=consumer_name,
                streams={self.STREAM_NAME: '>'},
                count=count,
                block=block
            )
            
            if not messages:
                return []
            
            # Format: [(stream_name, [(message_id, data), ...])]
            return messages[0][1] if messages else []
            
        except (redis.ConnectionError, redis.TimeoutError):
            self.available = False
            return []
    
    def acknowledge(self, message_id: str) -> bool:
        """
        Acknowledge message processing.
        
        Args:
            message_id: Redis stream message ID
            
        Returns:
            True if acknowledged successfully
        """
        if not self.available:
            return False
        
        try:
            self.redis_client.xack(self.STREAM_NAME, self.CONSUMER_GROUP, message_id)
            return True
        except (redis.ConnectionError, redis.TimeoutError):
            self.available = False
            return False
    
    def get_pending_count(self) -> int:
        """Get number of pending messages in stream."""
        if not self.available:
            return 0
        
        try:
            info = self.redis_client.xpending(self.STREAM_NAME, self.CONSUMER_GROUP)
            return info['pending']
        except (redis.ConnectionError, redis.TimeoutError, KeyError):
            return 0
    
    def health_check(self) -> dict:
        """Check Redis WAL health status."""
        if not self.available:
            return {
                'status': 'unavailable',
                'message': 'Redis connection failed'
            }
        
        try:
            self.redis_client.ping()
            stream_length = self.redis_client.xlen(self.STREAM_NAME)
            pending = self.get_pending_count()
            
            return {
                'status': 'healthy',
                'stream_length': stream_length,
                'pending_messages': pending,
                'available': True
            }
        except Exception as e:
            self.available = False
            return {
                'status': 'error',
                'message': str(e)
            }


class IdempotencyCache:
    """
    Redis-based cache for fast idempotency checks.
    
    Before writing to WAL, check if idempotency_key was recently seen.
    This prevents duplicate processing of retried requests.
    """
    
    KEY_PREFIX = "aop:idempotency:"
    TTL_SECONDS = 3600  # 1 hour
    
    def __init__(self):
        """Initialize Redis connection."""
        try:
            self.redis_client = redis.Redis(
                host=getattr(settings, 'REDIS_HOST', 'localhost'),
                port=getattr(settings, 'REDIS_PORT', 6379),
                db=getattr(settings, 'REDIS_CACHE_DB', 1),
                decode_responses=True,
                socket_connect_timeout=2,
                socket_timeout=2
            )
            self.redis_client.ping()
            self.available = True
        except (redis.ConnectionError, redis.TimeoutError, AttributeError):
            self.available = False
            self.redis_client = None
    
    def check_and_set(self, idempotency_key: str, wal_id: str) -> bool:
        """
        Check if key exists and set it atomically.
        
        Args:
            idempotency_key: Unique key for the request
            wal_id: WAL entry ID to store
            
        Returns:
            True if key was new (safe to process), False if duplicate
        """
        if not self.available:
            # Fallback to DB check
            return not EventWAL.objects.filter(idempotency_key=idempotency_key).exists()
        
        try:
            cache_key = f"{self.KEY_PREFIX}{idempotency_key}"
            # SETNX: set if not exists (atomic)
            was_set = self.redis_client.set(
                cache_key,
                wal_id,
                ex=self.TTL_SECONDS,
                nx=True
            )
            return bool(was_set)
            
        except (redis.ConnectionError, redis.TimeoutError):
            self.available = False
            # Fallback to DB check
            return not EventWAL.objects.filter(idempotency_key=idempotency_key).exists()
    
    def get(self, idempotency_key: str) -> str:
        """Get WAL ID for an idempotency key."""
        if not self.available:
            try:
                wal_entry = EventWAL.objects.get(idempotency_key=idempotency_key)
                return str(wal_entry.id)
            except EventWAL.DoesNotExist:
                return None
        
        try:
            cache_key = f"{self.KEY_PREFIX}{idempotency_key}"
            return self.redis_client.get(cache_key)
        except (redis.ConnectionError, redis.TimeoutError):
            return None
    
    def delete(self, idempotency_key: str):
        """Delete idempotency key (for testing/cleanup)."""
        if not self.available:
            return
        
        try:
            cache_key = f"{self.KEY_PREFIX}{idempotency_key}"
            self.redis_client.delete(cache_key)
        except (redis.ConnectionError, redis.TimeoutError):
            pass
