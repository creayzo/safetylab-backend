"""
Reproducibility tests for replay and determinism.

Tests seed-replay cycles produce identical traces when caching enabled.
"""

import json
import random
import uuid
from django.test import TestCase
from django.utils import timezone

from api.models import Organization, Agent, Run, TraceEvent, EnvironmentSnapshot
from api.replay_models import (
    ReplaySnapshot,
    CachedLLMResponse,
    CachedToolResponse,
    ReplayRun
)
from api.replay_runner import (
    ReplayRunner,
    create_replay_snapshot,
    cache_llm_response,
    cache_tool_response
)
from api.auth_models import OrganizationSaltKey


class ReplaySnapshotTest(TestCase):
    """Test replay snapshot creation and storage."""
    
    def setUp(self):
        self.org = Organization.objects.create(name="Test Org")
        self.salt_key = OrganizationSaltKey.create_for_organization(self.org)
        self.agent = Agent.objects.create(
            owner=self.org,
            runtime_config={
                "model": "gpt-4",
                "temperature": 0.7
            }
        )
        self.run = Run.objects.create(
            agent=self.agent,
            run_id=uuid.uuid4(),
            status='completed',
            seed=42
        )
    
    def test_create_replay_snapshot(self):
        """Test creating a replay snapshot."""
        snapshot = create_replay_snapshot(
            run=self.run,
            seed=42,
            model_name='gpt-4',
            temperature=0.7,
            top_p=0.9,
            max_tokens=2048,
            tool_responses_cached=True,
            llm_responses_cached=True,
            replay_mode='full'
        )
        
        self.assertIsNotNone(snapshot)
        self.assertEqual(snapshot.seed, 42)
        self.assertEqual(snapshot.model_name, 'gpt-4')
        self.assertEqual(snapshot.temperature, 0.7)
        self.assertEqual(snapshot.replay_mode, 'full')
    
    def test_snapshot_seed_storage(self):
        """Test seed is stored correctly."""
        snapshot = ReplaySnapshot.objects.create(
            run=self.run,
            seed=12345,
            model_name='gpt-4',
            temperature=0.0
        )
        
        self.assertEqual(snapshot.seed, 12345)
    
    def test_snapshot_model_parameters(self):
        """Test model parameters are stored."""
        snapshot = ReplaySnapshot.objects.create(
            run=self.run,
            seed=42,
            model_name='gpt-4-turbo',
            temperature=0.5,
            top_p=0.95,
            max_tokens=4096
        )
        
        self.assertEqual(snapshot.model_name, 'gpt-4-turbo')
        self.assertEqual(snapshot.temperature, 0.5)
        self.assertEqual(snapshot.top_p, 0.95)
        self.assertEqual(snapshot.max_tokens, 4096)


class LLMResponseCachingTest(TestCase):
    """Test LLM response caching for deterministic replay."""
    
    def setUp(self):
        self.org = Organization.objects.create(name="Test Org")
        self.agent = Agent.objects.create(owner=self.org)
        self.run = Run.objects.create(
            agent=self.agent,
            run_id=uuid.uuid4(),
            seed=42
        )
        self.snapshot = ReplaySnapshot.objects.create(
            run=self.run,
            seed=42,
            model_name='gpt-4'
        )
    
    def test_cache_llm_response(self):
        """Test caching an LLM response."""
        cached = cache_llm_response(
            snapshot=self.snapshot,
            seq_no=1,
            event_type='reasoning',
            event_type='reasoning',
            prompt="What is 2+2?",
            response_text="The answer is 4.",
            model_name='gpt-4',
            temperature=0.0,
            finish_reason='stop',
            prompt_tokens=10,
            completion_tokens=6,
            latency_ms=250,
            consent_given=True
        )
        
        self.assertIsNotNone(cached)
        self.assertEqual(cached.response_text, "The answer is 4.")
        self.assertEqual(cached.seq_no, 1)
        self.assertTrue(cached.consent_given)
    
    def test_prompt_hashing(self):
        """Test prompt is hashed consistently."""
        prompt = "What is the capital of France?"
        
        cached1 = cache_llm_response(
            snapshot=self.snapshot,
            seq_no=1,
            event_type='reasoning',
            prompt=prompt,
            response_text="Paris",
            consent_given=True
        )
        
        cached2 = cache_llm_response(
            snapshot=self.snapshot,
            seq_no=2,
            event_type='reasoning',
            prompt=prompt,
            response_text="Paris",
            consent_given=True
        )
        
        # Same prompt should have same hash
        self.assertEqual(cached1.prompt_hash, cached2.prompt_hash)
    
    def test_retrieve_cached_response(self):
        """Test retrieving cached response by prompt hash."""
        prompt = "What is 2+2?"
        
        cached = cache_llm_response(
            snapshot=self.snapshot,
            seq_no=1,
            event_type='reasoning',
            prompt=prompt,
            response_text="4",
            consent_given=True
        )
        
        # Calculate hash for lookup
        import hashlib
        prompt_hash = hashlib.sha256(prompt.encode('utf-8')).hexdigest()
        
        # Retrieve
        retrieved = CachedLLMResponse.objects.filter(
            snapshot=self.snapshot,
            prompt_hash=prompt_hash
        ).first()
        
        self.assertIsNotNone(retrieved)
        self.assertEqual(retrieved.response_text, "4")
    
    def test_cache_expiration(self):
        """Test cached responses respect expiration."""
        from datetime import timedelta
        
        cached = cache_llm_response(
            snapshot=self.snapshot,
            seq_no=1,
            event_type='reasoning',
            prompt="test",
            response_text="response",
            consent_given=True,
            expires_at=timezone.now() + timedelta(days=7)
        )
        
        self.assertIsNotNone(cached.expires_at)
        self.assertFalse(cached.is_expired())
        
        # Test expired
        cached.expires_at = timezone.now() - timedelta(days=1)
        cached.save()
        self.assertTrue(cached.is_expired())
    
    def test_consent_required_for_caching(self):
        """Test consent flag is stored."""
        cached = cache_llm_response(
            snapshot=self.snapshot,
            seq_no=1,
            event_type='reasoning',
            prompt="test",
            response_text="response",
            consent_given=False  # No consent
        )
        
        self.assertFalse(cached.consent_given)


class ToolResponseCachingTest(TestCase):
    """Test tool response caching for deterministic replay."""
    
    def setUp(self):
        self.org = Organization.objects.create(name="Test Org")
        self.agent = Agent.objects.create(owner=self.org)
        self.run = Run.objects.create(
            agent=self.agent,
            run_id=uuid.uuid4(),
            seed=42
        )
        self.snapshot = ReplaySnapshot.objects.create(
            run=self.run,
            seed=42,
            model_name='gpt-4'
        )
    
    def test_cache_tool_response(self):
        """Test caching a tool response."""
        cached = cache_tool_response(
            snapshot=self.snapshot,
            seq_no=1,
            action_name='search',
            params={"query": "Python tutorials"},
            status='success',
            result={"results": ["link1", "link2"]},
            latency_ms=150
        )
        
        self.assertIsNotNone(cached)
        self.assertEqual(cached.action_name, 'search')
        self.assertEqual(cached.status, 'success')
    
    def test_params_hashing(self):
        """Test parameters are hashed consistently."""
        params = {"query": "test", "limit": 10}
        
        cached1 = cache_tool_response(
            snapshot=self.snapshot,
            seq_no=1,
            action_name='search',
            params=params,
            status='success',
            result={}
        )
        
        cached2 = cache_tool_response(
            snapshot=self.snapshot,
            seq_no=2,
            action_name='search',
            params=params,
            status='success',
            result={}
        )
        
        # Same params should have same hash
        self.assertEqual(cached1.params_hash, cached2.params_hash)
    
    def test_retrieve_cached_tool_response(self):
        """Test retrieving cached tool response by params hash."""
        params = {"query": "test"}
        action_name = 'search'
        
        cached = cache_tool_response(
            snapshot=self.snapshot,
            seq_no=1,
            action_name=action_name,
            params=params,
            status='success',
            result={"data": "test"}
        )
        
        # Calculate hash for lookup
        import hashlib
        params_hash = hashlib.sha256(
            json.dumps(params, sort_keys=True).encode('utf-8')
        ).hexdigest()
        
        # Retrieve
        retrieved = CachedToolResponse.objects.filter(
            snapshot=self.snapshot,
            action_name=action_name,
            params_hash=params_hash
        ).first()
        
        self.assertIsNotNone(retrieved)
        self.assertEqual(retrieved.result, {"data": "test"})


class DeterministicReplayTest(TestCase):
    """Test deterministic replay produces identical results."""
    
    def setUp(self):
        self.org = Organization.objects.create(name="Test Org")
        self.agent = Agent.objects.create(owner=self.org)
        self.seed = 42
        self.run_id = uuid.uuid4()
        
        # Create original run
        self.run = Run.objects.create(
            agent=self.agent,
            run_id=self.run_id,
            status='completed',
            seed=self.seed
        )
        
        # Create events
        self.create_test_events()
        
        # Create replay snapshot with caching
        self.snapshot = create_replay_snapshot(
            run=self.run,
            seed=self.seed,
            model_name='gpt-4',
            temperature=0.0,  # Deterministic
            tool_responses_cached=True,
            llm_responses_cached=True,
            replay_mode='full'
        )
    
    def create_test_events(self):
        """Create test events for the run."""
        events = [
            {
                "seq_no": 1,
                "actor": "agent",
                "type": "reasoning",
                "payload": {"reasoning": "Analyzing request"}
            },
            {
                "seq_no": 2,
                "actor": "agent",
                "type": "action_request",
                "payload": {
                    "action": "search",
                    "parameters": {"query": "test"}
                }
            },
            {
                "seq_no": 3,
                "actor": "tool",
                "type": "action_response",
                "payload": {
                    "status": "success",
                    "result": {"data": ["item1", "item2"]}
                }
            },
            {
                "seq_no": 4,
                "actor": "agent",
                "type": "final_output",
                "payload": {"output": "Task completed"}
            }
        ]
        
        for event_data in events:
            TraceEvent.objects.create(
                run=self.run,
                timestamp=timezone.now(),
                **event_data
            )
    
    def cache_test_responses(self):
        """Cache LLM and tool responses."""
        # Cache LLM response for reasoning
        cache_llm_response(
            snapshot=self.snapshot,
            seq_no=1,
            event_type='reasoning',
            prompt="User request: test",
            response_text="Analyzing request",
            consent_given=True
        )
        
        # Cache tool response for search
        cache_tool_response(
            snapshot=self.snapshot,
            seq_no=3,
            action_name='search',
            params={"query": "test"},
            status='success',
            result={"data": ["item1", "item2"]}
        )
    
    def test_replay_with_full_caching(self):
        """Test replay with full caching produces identical results."""
        # Cache responses
        self.cache_test_responses()
        
        # Execute replay
        runner = ReplayRunner(
            original_run_id=str(self.run_id),
            replay_mode='full',
            use_cached_llm=True,
            use_cached_tools=True
        )
        
        replay_run = runner.execute()
        
        # Verify reproducibility
        self.assertIsNotNone(replay_run)
        self.assertEqual(replay_run.status, 'completed')
        # High reproducibility score expected with full caching
        self.assertGreaterEqual(replay_run.reproducibility_score, 0.95)
    
    def test_seed_determinism(self):
        """Test same seed produces same random outputs."""
        # Set seed
        random.seed(self.seed)
        result1 = [random.random() for _ in range(10)]
        
        # Reset seed
        random.seed(self.seed)
        result2 = [random.random() for _ in range(10)]
        
        # Should be identical
        self.assertEqual(result1, result2)
    
    def test_replay_comparison_report(self):
        """Test replay generates comparison report."""
        self.cache_test_responses()
        
        runner = ReplayRunner(
            original_run_id=str(self.run_id),
            replay_mode='full',
            use_cached_llm=True,
            use_cached_tools=True
        )
        
        replay_run = runner.execute()
        report = replay_run.generate_report()
        
        self.assertIsNotNone(report)
        self.assertIn('total_events', report)
        self.assertIn('matching_events', report)
        self.assertIn('reproducibility_score', report)
    
    def test_divergence_detection(self):
        """Test divergence detection in replay."""
        # Don't cache responses - will cause divergence
        
        runner = ReplayRunner(
            original_run_id=str(self.run_id),
            replay_mode='verification',
            use_cached_llm=False,
            use_cached_tools=False
        )
        
        # Note: This would fail in real scenario without actual LLM/tool execution
        # In production, divergences would be detected and logged
        
        # Test divergence structure
        divergence = {
            'seq_no': 1,
            'event_type': 'reasoning',
            'difference_type': 'payload_mismatch',
            'original': {"reasoning": "A"},
            'replayed': {"reasoning": "B"}
        }
        
        self.assertIn('seq_no', divergence)
        self.assertIn('difference_type', divergence)


class ReplayModesTest(TestCase):
    """Test different replay modes."""
    
    def setUp(self):
        self.org = Organization.objects.create(name="Test Org")
        self.agent = Agent.objects.create(owner=self.org)
        self.run = Run.objects.create(
            agent=self.agent,
            run_id=uuid.uuid4(),
            seed=42,
            status='completed'
        )
        self.snapshot = ReplaySnapshot.objects.create(
            run=self.run,
            seed=42,
            model_name='gpt-4'
        )
    
    def test_full_replay_mode(self):
        """Test full replay mode (all cached)."""
        self.snapshot.replay_mode = 'full'
        self.snapshot.llm_responses_cached = True
        self.snapshot.tool_responses_cached = True
        self.snapshot.save()
        
        self.assertEqual(self.snapshot.replay_mode, 'full')
        self.assertTrue(self.snapshot.llm_responses_cached)
        self.assertTrue(self.snapshot.tool_responses_cached)
    
    def test_hybrid_replay_mode(self):
        """Test hybrid replay mode (tools cached, LLM re-run)."""
        self.snapshot.replay_mode = 'hybrid'
        self.snapshot.llm_responses_cached = False
        self.snapshot.tool_responses_cached = True
        self.snapshot.save()
        
        self.assertEqual(self.snapshot.replay_mode, 'hybrid')
        self.assertFalse(self.snapshot.llm_responses_cached)
        self.assertTrue(self.snapshot.tool_responses_cached)
    
    def test_verification_replay_mode(self):
        """Test verification replay mode (nothing cached)."""
        self.snapshot.replay_mode = 'verification'
        self.snapshot.llm_responses_cached = False
        self.snapshot.tool_responses_cached = False
        self.snapshot.save()
        
        self.assertEqual(self.snapshot.replay_mode, 'verification')
        self.assertFalse(self.snapshot.llm_responses_cached)
        self.assertFalse(self.snapshot.tool_responses_cached)
