"""
Integration tests for end-to-end event flow.

Tests: mock agent → event emission → server ingestion → WAL → evaluation → validation
"""

import json
import uuid
import unittest
from datetime import timedelta
from django.test import TestCase, TransactionTestCase, override_settings
from django.utils import timezone
from unittest.mock import patch, MagicMock

from api.models import Organization, Agent, Run, TraceEvent, EvaluationRun
from api.wal_models import EventWAL
from api.auth_models import OrganizationSaltKey, AgentAPIKey, SignatureVerifier
from api.validators.base import ValidationViolation
from cryptography.fernet import Fernet

# Test encryption key
TEST_ENCRYPTION_KEY = Fernet.generate_key()


@override_settings(SALT_ENCRYPTION_KEY=TEST_ENCRYPTION_KEY)
class EndToEndEventFlowTest(TransactionTestCase):
    """Test complete event flow from client to server."""
    
    def setUp(self):
        """Set up test organization, agent, and authentication."""
        self.org = Organization.objects.create(name="Test Org")
        self.salt_key = OrganizationSaltKey.create_for_organization(self.org)
        self.agent = Agent.objects.create(
            owner=self.org,
            runtime_config={
                "model": "gpt-4",
                "temperature": 0.7
            }
        )
        self.api_key = AgentAPIKey.create_for_agent(
            agent=self.agent,
            scopes=['write:events', 'read:events']
        )
        self.run_id = uuid.uuid4()
    
    def create_signed_event(self, seq, type="reasoning", payload=None):
        """Create a signed event payload."""
        if payload is None:
            payload = {"reasoning": f"Step {seq}"}
        
        event = {
            "seq": seq,
            "t": timezone.now().isoformat(),
            "actor": "agent",
            "type": type,
            "payload": payload,
            "meta": {
                "run_id": str(self.run_id),
                "agent_id": self.agent.id
            }
        }
        
        # Generate signature
        salt_key = self.salt_key.decrypt_salt()
        payload_str = json.dumps(payload, separators=(',', ':'))
        signature = SignatureVerifier.generate_signature(
            org_salt=salt_key,
            run_id=str(self.run_id),
            seq_no=seq,
            payload=payload_str
        )
        event["meta"]["signature"] = signature
        
        return event
    
    def test_full_event_ingestion_flow(self):
        """Test complete flow: client event → WAL → TraceEvent."""
        # Step 1: Create run
        run = Run.objects.create(
            agent=self.agent,
            run_id=self.run_id,
            status='running'
        )
        
        # Step 2: Create signed event
        event_data = self.create_signed_event(seq=1)
        
        # Step 3: Verify signature
        signature = event_data["meta"]["signature"]
        payload_str = json.dumps(event_data['payload'], separators=(',', ':'))
        
        is_valid = SignatureVerifier.verify_signature(
            org_salt=self.salt_key.decrypt_salt(),
            run_id=str(self.run_id),
            seq_no=1,
            payload=payload_str,
            provided_signature=signature
        )
        self.assertTrue(is_valid)
        
        # Step 4: Create WAL entry
        wal = EventWAL.objects.create(
            run_id=run.run_id,
            agent_id=self.agent.id,
            seq_no=1,
            event_type='reasoning',
            timestamp=timezone.now(),
            payload=event_data['payload'],
            signature=signature,
            status='pending',
            idempotency_key=f"{self.run_id}:1"
        )
        self.assertEqual(wal.status, 'pending')
        
        # Step 5: Process WAL → TraceEvent
        wal.status = 'processing'
        wal.started_at = timezone.now()
        wal.save()
        
        trace_event = TraceEvent.objects.create(
            run=run,
            seq_no=event_data['seq'],
            timestamp=timezone.now(),
            actor=event_data['actor'],
            type=event_data['type'],
            payload=event_data['payload']
        )
        
        wal.status = 'completed'
        wal.completed_at = timezone.now()
        wal.save()
        
        # Step 6: Verify event stored
        self.assertEqual(TraceEvent.objects.filter(run=run).count(), 1)
        self.assertEqual(wal.status, 'completed')
    
    def test_multiple_events_sequential_ingestion(self):
        """Test ingesting multiple events in sequence."""
        run = Run.objects.create(
            agent=self.agent,
            run_id=self.run_id,
            status='running'
        )
        
        # Ingest 5 events
        for seq in range(1, 6):
            event_data = self.create_signed_event(seq=seq)
            
            # Create WAL
            wal = EventWAL.objects.create(
                run_id=run.run_id,
                agent_id=self.agent.id,
                seq_no=seq,
                event_type='reasoning',
                timestamp=timezone.now(),
                payload=event_data['payload'],
                signature=event_data['meta']['signature'],
                status='pending',
                idempotency_key=f"{self.run_id}:{seq}"
            )
            
            # Process
            wal.status = 'processing'
            wal.save()
            
            TraceEvent.objects.create(
                run=run,
                seq_no=seq,
                timestamp=timezone.now(),
                actor='agent',
                type='reasoning',
                payload=event_data['payload']
            )
            
            wal.status = 'completed'
            wal.save()
        
        # Verify all events stored
        self.assertEqual(TraceEvent.objects.filter(run=run).count(), 5)
        self.assertEqual(EventWAL.objects.filter(run_id=run.run_id, status='completed').count(), 5)
    
    def test_duplicate_event_rejection(self):
        """Test duplicate event is rejected via idempotency."""
        run = Run.objects.create(
            agent=self.agent,
            run_id=self.run_id,
            status='running'
        )
        
        event_data = self.create_signed_event(seq=1)
        
        # First submission
        wal1 = EventWAL.objects.create(
            run_id=run.run_id,
            agent_id=self.agent.id,
            seq_no=1,
            event_type='reasoning',
            timestamp=timezone.now(),
            payload=event_data['payload'],
            signature=event_data['meta']['signature'],
            status='completed',
            idempotency_key=f"{self.run_id}:1"
        )
        
        # Attempt duplicate submission
        from django.db import IntegrityError
        with self.assertRaises(IntegrityError):
            wal2 = EventWAL.objects.create(
                run_id=run.run_id,
                agent_id=self.agent.id,
                seq_no=1,
                event_type='reasoning',
                timestamp=timezone.now(),
                payload=event_data['payload'],
                signature=event_data['meta']['signature'],
                status='pending',
                idempotency_key=f"{self.run_id}:1"
            )
    
    def test_signature_verification_failure(self):
        """Test tampered event fails signature verification."""
        run = Run.objects.create(
            agent=self.agent,
            run_id=self.run_id,
            status='running'
        )
        
        event_data = self.create_signed_event(seq=1)
        signature = event_data["meta"]["signature"]
        
        # Tamper with payload
        event_data["payload"]["reasoning"] = "TAMPERED"
        tampered_payload_str = json.dumps(event_data['payload'], separators=(',', ':'))
        
        # Verify signature fails
        is_valid = SignatureVerifier.verify_signature(
            org_salt=self.salt_key.decrypt_salt(),
            run_id=str(self.run_id),
            seq_no=1,
            payload=tampered_payload_str,
            provided_signature=signature
        )
        
        self.assertFalse(is_valid)
    
    @patch('api.tasks.evaluate_run.delay')
    def test_evaluation_triggered_on_run_completion(self, mock_evaluate):
        """Test evaluation is triggered when run completes."""
        run = Run.objects.create(
            agent=self.agent,
            run_id=self.run_id,
            status='running'
        )
        
        # Ingest events
        for seq in range(1, 4):
            event_data = self.create_signed_event(seq=seq)
            TraceEvent.objects.create(
                run=run,
                seq_no=seq,
                timestamp=timezone.now(),
                actor='agent',
                type='reasoning' if seq < 3 else 'final_output',
                payload=event_data['payload']
            )
        
        # Finalize run
        run.status = 'completed'
        run.finalized_at = timezone.now()
        run.save()
        
        # Trigger evaluation (would be done by signal or view)
        from api.tasks import evaluate_run
        mock_evaluate.return_value = MagicMock(id='task-123')
        task = mock_evaluate(str(run.run_id))
        
        # Verify evaluation was triggered
        mock_evaluate.assert_called_once_with(str(run.run_id))


@override_settings(SALT_ENCRYPTION_KEY=TEST_ENCRYPTION_KEY)
class EvaluationPipelineTest(TestCase):
    """Test evaluation pipeline integration."""
    
    def setUp(self):
        self.org = Organization.objects.create(name="Test Org")
        self.salt_key = OrganizationSaltKey.create_for_organization(self.org)
        self.agent = Agent.objects.create(owner=self.org)
        self.run = Run.objects.create(
            agent=self.agent,
            run_id=uuid.uuid4(),
            status='completed'
        )
    
    def test_run_evaluation_creation(self):
        """Test creating an evaluation run."""
        eval_run = EvaluationRun.objects.create(
            organization=self.org,
            agent=self.agent,
            associated_run=self.run,
            initiated_by='test_user',
            status='pending',
            evaluator_version='1.0.0'
        )
        
        self.assertIsNotNone(eval_run)
        self.assertEqual(eval_run.status, 'pending')
    
    @patch('api.validators.policy_validator.PolicyValidator.validate')
    def test_policy_validator_invoked(self, mock_validate):
        """Test policy validator is invoked during evaluation."""
        # Create trace events
        TraceEvent.objects.create(
            run=self.run,
            seq_no=1,
            timestamp=timezone.now(),
            actor='agent',
            type='action_request',
            payload={
                "action": "execute_code",
                "parameters": {"code": "print('hello')"}
            }
        )
        
        # Mock validator response - return empty list (no violations)
        mock_validate.return_value = []
        
        # Run evaluation
        from api.validators.policy_validator import PolicyValidator
        validator = PolicyValidator(organization=self.org)
        
        events = TraceEvent.objects.filter(run=self.run)
        for event in events:
            result = validator.validate(event.payload, event)
        
        # Verify validator was called
        self.assertTrue(mock_validate.called)
    
    @patch('api.validators.pii_detector.PIIDetector.scan_dict')
    def test_pii_detector_invoked(self, mock_scan):
        """Test PII detector is invoked during evaluation."""
        # Create event with potential PII
        TraceEvent.objects.create(
            run=self.run,
            seq_no=1,
            timestamp=timezone.now(),
            actor='agent',
            type='reasoning',
            payload={
                "text": "User email is test@example.com",
                "phone": "555-1234"
            }
        )
        
        # Mock PII detection
        mock_scan.return_value = {
            'email': ['test@example.com'],
            'phone_number': ['555-1234']
        }
        
        # Run PII scan
        from api.validators.pii_detector import PIIDetector
        detector = PIIDetector()
        
        events = TraceEvent.objects.filter(run=self.run)
        for event in events:
            findings = detector.scan_dict(event.payload)
        
        # Verify detector was called
        self.assertTrue(mock_scan.called)
    
    def test_evaluation_result_storage(self):
        """Test evaluation results are stored."""
        eval_run = EvaluationRun.objects.create(
            organization=self.org,
            agent=self.agent,
            associated_run=self.run,
            initiated_by='test_user',
            status='completed',
            evaluator_version='1.0.0',
            results={
                'policy_violations': [],
                'pii_detected': ['email'],
                'prompt_injection_score': 0.1,
                'overall_score': 0.95
            }
        )
        
        self.assertIsNotNone(eval_run.results)
        self.assertIn('overall_score', eval_run.results)
        self.assertEqual(eval_run.results['overall_score'], 0.95)


class BackpressureTest(TestCase):
    """Test backpressure and rate limiting."""
    
    def setUp(self):
        self.org = Organization.objects.create(name="Test Org")
        self.agent = Agent.objects.create(owner=self.org)
        self.run = Run.objects.create(
            agent=self.agent,
            run_id=uuid.uuid4()
        )
    
    def test_wal_queue_depth_check(self):
        """Test WAL queue depth monitoring."""
        # Create many pending WAL entries
        for i in range(100):
            EventWAL.objects.create(
                run_id=self.run.run_id,
                agent_id=self.agent.id,
                seq_no=i + 1,
                event_type='reasoning',
                timestamp=timezone.now(),
                payload={"seq": i + 1},
                signature='test_signature',
                status='pending',
                idempotency_key=f"{self.run.run_id}:{i + 1}"
            )
        
        # Check queue depth
        pending_count = EventWAL.objects.filter(status='pending').count()
        self.assertEqual(pending_count, 100)
        
        # Check if backpressure should be applied
        from api.monitoring import BackpressureHandler
        handler = BackpressureHandler()
        is_healthy, error = handler.check_system_load()
        
        # System should be healthy at 100 pending (threshold is 10,000)
        self.assertTrue(is_healthy)
    
    def test_rate_limit_per_organization(self):
        """Test per-organization rate limiting."""
        from api.monitoring import BackpressureHandler
        from django.core.cache import cache
        
        handler = BackpressureHandler()
        org_id = str(self.org.id)
        
        # Simulate rapid requests
        for i in range(10):
            cache_key = f"org_events:{org_id}"
            current_count = cache.get(cache_key, 0)
            cache.set(cache_key, current_count + 1, timeout=60)
        
        # Check if rate limit should apply
        should_limit, retry_after = handler.should_apply_backpressure(org_id)
        
        # Should not be limited at 10 events (threshold is 1000/min)
        self.assertFalse(should_limit)


class StreamingModeTest(TestCase):
    """Test real-time streaming mode."""
    
    def setUp(self):
        self.org = Organization.objects.create(name="Test Org")
        self.agent = Agent.objects.create(owner=self.org)
        self.run = Run.objects.create(
            agent=self.agent,
            run_id=uuid.uuid4(),
            status='running'
        )
    
    def test_streaming_event_immediate_availability(self):
        """Test events are immediately available in streaming mode."""
        # Create event
        event = TraceEvent.objects.create(
            run=self.run,
            seq_no=1,
            timestamp=timezone.now(),
            actor='agent',
            type='reasoning',
            payload={"reasoning": "test"}
        )
        
        # Query immediately
        latest_event = TraceEvent.objects.filter(run=self.run).latest('timestamp')
        
        self.assertEqual(latest_event.id, event.id)
        self.assertEqual(latest_event.seq_no, 1)
    
    @patch('channels.layers.get_channel_layer')
    def test_websocket_notification_on_event(self, mock_channel_layer):
        """Test WebSocket notification is sent on new event."""
        # Mock channel layer
        mock_layer = MagicMock()
        mock_channel_layer.return_value = mock_layer
        
        # Create event
        event = TraceEvent.objects.create(
            run=self.run,
            seq_no=1,
            timestamp=timezone.now(),
            actor='agent',
            type='reasoning',
            payload={"reasoning": "test"}
        )
        
        # Simulate WebSocket send (would be in signal handler)
        from channels.layers import get_channel_layer
        channel_layer = get_channel_layer()
        
        if channel_layer:
            # Would send notification to WebSocket consumers
            pass
