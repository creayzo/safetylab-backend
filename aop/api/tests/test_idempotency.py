"""
Unit tests for idempotency and deduplication.

Tests write-ahead log, duplicate detection, replay prevention.
"""

import uuid
from datetime import timedelta
from django.test import TestCase
from django.utils import timezone

from api.models import Organization, Agent, Run, TraceEvent
from api.wal_models import EventWAL
from api.auth_models import OrganizationSaltKey


class IdempotencyTest(TestCase):
    """Test idempotency and duplicate detection."""
    
    def setUp(self):
        self.org = Organization.objects.create(name="Test Org")
        self.salt_key = OrganizationSaltKey.create_for_organization(self.org)
        self.agent = Agent.objects.create(owner=self.org)
        self.run = Run.objects.create(
            agent=self.agent,
            run_id=uuid.uuid4()
        )
    
    def test_first_event_creates_wal_entry(self):
        """Test first event creates WAL entry."""
        wal = EventWAL.objects.create(
            run_id=self.run.run_id,
            agent_id=self.agent.id,
            seq_no=1,
            event_type='reasoning',
            timestamp=timezone.now(),
            payload={"reasoning": "test"},
            signature='test_signature',
            status='pending',
            idempotency_key=f"{self.run.run_id}:1"
        )
        
        self.assertIsNotNone(wal)
        self.assertEqual(wal.status, 'pending')
    
    def test_duplicate_idempotency_key_prevented(self):
        """Test duplicate idempotency key is prevented."""
        idempotency_key = f"{self.run.run_id}:1"
        
        # Create first WAL entry
        EventWAL.objects.create(
            run_id=self.run.run_id,
            agent_id=self.agent.id,
            seq_no=1,
            event_type='reasoning',
            timestamp=timezone.now(),
            payload={},
            signature='test_signature',
            status='pending',
            idempotency_key=idempotency_key
        )
        
        # Try to create duplicate
        from django.db import IntegrityError
        with self.assertRaises(IntegrityError):
            EventWAL.objects.create(
                run_id=self.run.run_id,
                agent_id=self.agent.id,
                seq_no=1,
                event_type='reasoning',
                timestamp=timezone.now(),
                payload={},
                signature='test_signature',
                status='pending',
                idempotency_key=idempotency_key
            )
    
    def test_duplicate_detection_within_run(self):
        """Test detecting duplicate events within same run."""
        # Create event 1
        event1 = TraceEvent.objects.create(
            run=self.run,
            seq_no=1,
            timestamp=timezone.now(),
            actor='agent',
            type='reasoning',
            payload={"reasoning": "test"}
        )
        
        # Check duplicate
        is_duplicate = TraceEvent.objects.filter(
            run=self.run,
            seq_no=1
        ).exists()
        
        self.assertTrue(is_duplicate)
    
    def test_same_seq_different_runs_allowed(self):
        """Test same seq_no in different runs is allowed."""
        # Create event in run 1
        event1 = TraceEvent.objects.create(
            run=self.run,
            seq_no=1,
            timestamp=timezone.now(),
            actor='agent',
            type='reasoning',
            payload={"reasoning": "test"}
        )
        
        # Create another run
        run2 = Run.objects.create(
            agent=self.agent,
            run_id=uuid.uuid4()
        )
        
        # Create event with same seq in run 2
        event2 = TraceEvent.objects.create(
            run=run2,
            seq_no=1,
            timestamp=timezone.now(),
            actor='agent',
            type='reasoning',
            payload={"reasoning": "test"}
        )
        
        self.assertNotEqual(event1.id, event2.id)
    
    def test_wal_status_transitions(self):
        """Test WAL status transitions."""
        wal = EventWAL.objects.create(
            run_id=self.run.run_id,
            agent_id=self.agent.id,
            seq_no=1,
            event_type='reasoning',
            timestamp=timezone.now(),
            payload={},
            signature='test_signature',
            status='pending',
            idempotency_key=f"{self.run.run_id}:1"
        )
        
        # Transition to processing
        wal.mark_processing()
        self.assertEqual(wal.status, 'processing')
        
        # Transition to completed
        wal.mark_completed()
        self.assertEqual(wal.status, 'completed')
    
    def test_wal_failed_status_with_retry(self):
        """Test WAL failed status and retry logic."""
        wal = EventWAL.objects.create(
            run_id=self.run.run_id,
            agent_id=self.agent.id,
            seq_no=1,
            event_type='reasoning',
            timestamp=timezone.now(),
            payload={},
            signature='test_signature',
            status='pending',
            idempotency_key=f"{self.run.run_id}:1"
        )
        
        # Fail processing
        wal.mark_failed("Processing error")
        self.assertEqual(wal.status, 'failed')
        self.assertEqual(wal.retry_count, 0)  # mark_failed doesn't increment retry_count
        
        # Increment retry and try again
        wal.increment_retry()
        self.assertEqual(wal.retry_count, 1)
        self.assertEqual(wal.status, 'retrying')
        
        # Can retry again
        self.assertTrue(wal.can_retry(max_retries=3))
    
    def test_wal_max_retries(self):
        """Test WAL respects max retry limit."""
        wal = EventWAL.objects.create(
            run_id=self.run.run_id,
            agent_id=self.agent.id,
            seq_no=1,
            event_type='reasoning',
            timestamp=timezone.now(),
            payload={},
            signature='test_signature',
            status='pending',
            idempotency_key=f"{self.run.run_id}:1",
            retry_count=0
        )
        
        max_retries = 3
        
        # Simulate retries
        for i in range(max_retries):
            wal.retry_count += 1
            wal.status = 'failed'
            wal.save()
        
        # Check if max retries reached
        self.assertEqual(wal.retry_count, max_retries)
    
    def test_wal_ordering_by_seq_no(self):
        """Test WAL entries are ordered by seq_no."""
        # Create events out of order
        wal3 = EventWAL.objects.create(
            run_id=self.run.run_id,
            agent_id=self.agent.id,
            seq_no=3,
            event_type='reasoning',
            timestamp=timezone.now(),
            payload={},
            signature='test_signature',
            status='pending',
            idempotency_key=f"{self.run.run_id}:3"
        )
        wal1 = EventWAL.objects.create(
            run_id=self.run.run_id,
            agent_id=self.agent.id,
            seq_no=1,
            event_type='reasoning',
            timestamp=timezone.now(),
            payload={},
            signature='test_signature',
            status='pending',
            idempotency_key=f"{self.run.run_id}:1"
        )
        wal2 = EventWAL.objects.create(
            run_id=self.run.run_id,
            agent_id=self.agent.id,
            seq_no=2,
            event_type='reasoning',
            timestamp=timezone.now(),
            payload={},
            signature='test_signature',
            status='pending',
            idempotency_key=f"{self.run.run_id}:2"
        )
        
        # Query with default ordering (run_id, seq_no)
        wal_entries = EventWAL.objects.filter(run_id=self.run.run_id)
        
        # Should be ordered by seq_no (1, 2, 3) due to model's Meta.ordering
        seq_numbers = [w.seq_no for w in wal_entries]
        self.assertEqual(seq_numbers, [1, 2, 3])
    
    def test_wal_cleanup_old_entries(self):
        """Test cleanup of old completed WAL entries."""
        # Create old completed entry
        old_wal = EventWAL.objects.create(
            run_id=self.run.run_id,
            agent_id=self.agent.id,
            seq_no=1,
            event_type='reasoning',
            timestamp=timezone.now(),
            payload={},
            signature='test_signature',
            status='completed',
            idempotency_key=f"{self.run.run_id}:1"
        )
        
        # Manually set created_at to old date
        EventWAL.objects.filter(id=old_wal.id).update(
            created_at=timezone.now() - timedelta(days=8)
        )
        
        # Query for old entries (>7 days)
        cutoff_date = timezone.now() - timedelta(days=7)
        old_entries = EventWAL.objects.filter(
            status='completed',
            created_at__lt=cutoff_date
        )
        
        self.assertTrue(old_entries.exists())
        
        # Cleanup
        old_entries.delete()
        
        # Verify deletion
        self.assertFalse(EventWAL.objects.filter(id=old_wal.id).exists())


class WALProcessingTest(TestCase):
    """Test WAL processing logic."""
    
    def setUp(self):
        self.org = Organization.objects.create(name="Test Org")
        self.salt_key = OrganizationSaltKey.create_for_organization(self.org)
        self.agent = Agent.objects.create(owner=self.org)
        self.run = Run.objects.create(
            agent=self.agent,
            run_id=uuid.uuid4()
        )
    
    def test_process_pending_wal_entries(self):
        """Test processing pending WAL entries."""
        # Create pending entries
        wal1 = EventWAL.objects.create(
            run_id=self.run.run_id,
            agent_id=self.agent.id,
            seq_no=1,
            event_type='reasoning',
            timestamp=timezone.now(),
            payload={},
            signature='test_signature',
            status='pending',
            idempotency_key=f"{self.run.run_id}:1"
        )
        
        # Query pending
        pending = EventWAL.objects.filter(status='pending')
        self.assertEqual(pending.count(), 1)
        
        # Mark as processing
        wal1.status = 'processing'
        wal1.started_at = timezone.now()
        wal1.save()
        
        # Verify status change
        self.assertEqual(wal1.status, 'processing')
    
    def test_wal_concurrent_processing_prevention(self):
        """Test preventing concurrent processing of same WAL entry."""
        wal = EventWAL.objects.create(
            run_id=self.run.run_id,
            agent_id=self.agent.id,
            seq_no=1,
            event_type='reasoning',
            timestamp=timezone.now(),
            payload={},
            signature='test_signature',
            status='pending',
            idempotency_key=f"{self.run.run_id}:1"
        )
        
        # Simulate worker 1 claiming entry
        from django.db import transaction
        with transaction.atomic():
            wal_for_processing = EventWAL.objects.select_for_update().get(id=wal.id)
            if wal_for_processing.status == 'pending':
                wal_for_processing.status = 'processing'
                wal_for_processing.save()
        
        # Worker 2 should see it as processing
        wal.refresh_from_db()
        self.assertEqual(wal.status, 'processing')
    
    def test_wal_batch_processing(self):
        """Test batch processing of WAL entries."""
        # Create multiple pending entries
        for i in range(5):
            EventWAL.objects.create(
                run_id=self.run.run_id,
                agent_id=self.agent.id,
                seq_no=i + 1,
                event_type='reasoning',
                timestamp=timezone.now(),
                payload={},
                signature='test_signature',
                status='pending',
                idempotency_key=f"{self.run.run_id}:{i + 1}"
            )
        
        # Batch query
        batch = EventWAL.objects.filter(
            run_id=self.run.run_id,
            status='pending'
        )[:10]  # Batch size 10
        
        self.assertEqual(len(batch), 5)
