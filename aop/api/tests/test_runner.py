"""
Tests for Test Runner (Execution Pipeline).

Tests complete evaluation workflow orchestration.
"""

import uuid
from django.test import TestCase
from django.utils import timezone
from unittest.mock import patch, MagicMock

from api.models import Organization, Agent, Run, TraceEvent, EvaluationRun
from api.scenario_models import Scenario
from api.test_runner import TestRunner, TestRunnerFactory
from api.validators.base import ValidationViolation


class TestRunnerTest(TestCase):
    """Test TestRunner orchestration."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.org = Organization.objects.create(name="Test Org")
        self.agent = Agent.objects.create(owner=self.org)
        
        # Create test scenario
        self.scenario = Scenario.objects.create(
            name="Test Scenario",
            description="Test",
            scenario_type="business",
            script=[
                {
                    'type': 'user_message',
                    'timestamp': 0,
                    'message': 'Hello'
                }
            ]
        )
        
        # Create evaluation run
        self.evaluation_run = EvaluationRun.objects.create(
            organization=self.org,
            agent=self.agent,
            scenario_set=[str(self.scenario.scenario_id)],
            initiated_by='test',
            seed=12345,
            status='pending'
        )
    
    def test_runner_initialization(self):
        """Test runner initialization."""
        runner = TestRunner(self.evaluation_run)
        
        self.assertEqual(runner.evaluation_run, self.evaluation_run)
        self.assertEqual(runner.organization, self.org)
        self.assertEqual(runner.agent, self.agent)
        self.assertEqual(len(runner.scenarios), 0)
        self.assertEqual(len(runner.validators), 0)
    
    def test_read_configuration(self):
        """Test configuration reading."""
        runner = TestRunner(self.evaluation_run)
        runner._read_configuration()
        
        # Should not raise any errors
        self.assertTrue(True)
    
    def test_assemble_scenarios(self):
        """Test scenario assembly."""
        runner = TestRunner(self.evaluation_run)
        runner._assemble_scenarios()
        
        self.assertEqual(len(runner.scenarios), 1)
        self.assertEqual(runner.scenarios[0], self.scenario)
    
    def test_seed_rng(self):
        """Test RNG seeding."""
        runner = TestRunner(self.evaluation_run)
        runner._seed_rng()
        
        self.assertEqual(self.evaluation_run.seed, 12345)
    
    def test_initialize_validators(self):
        """Test validator initialization."""
        # Enable validators
        self.evaluation_run.enable_pii_detection = True
        self.evaluation_run.enable_policy_enforcement = True
        self.evaluation_run.save()
        
        runner = TestRunner(self.evaluation_run)
        runner._initialize_validators()
        
        # Should have initialized validators
        self.assertGreater(len(runner.validators), 0)
    
    @patch('api.test_runner.ScenarioEngine')
    def test_execute_scenarios(self, mock_engine_class):
        """Test scenario execution."""
        # Mock scenario engine
        mock_engine = MagicMock()
        mock_scenario_run = MagicMock()
        mock_scenario_run.agent_run = Run.objects.create(
            agent=self.agent
        )
        mock_scenario_run.status = 'completed'
        mock_scenario_run.results = {'total_events': 5, 'passed': True}
        mock_engine.execute.return_value = mock_scenario_run
        mock_engine_class.return_value = mock_engine
        
        runner = TestRunner(self.evaluation_run)
        runner._assemble_scenarios()
        runner._execute_scenarios()
        
        # Should have executed scenario
        self.assertEqual(len(runner.scenario_runs), 1)
    
    def test_validation_event(self):
        """Test event validation."""
        runner = TestRunner(self.evaluation_run)
        runner._initialize_validators()
        
        # Create test event
        run = Run.objects.create(agent=self.agent)
        event = TraceEvent.objects.create(
            run=run,
            seq_no=1,
            timestamp=timezone.now(),
            actor='agent',
            type='reasoning',
            payload={'goal': 'test', 'steps': [], 'safety_checks': [], 'uncertainty': 'low'}
        )
        
        # Validate
        violations = runner._validate_event(event)
        
        # Should return list (may be empty)
        self.assertIsInstance(violations, list)
    
    def test_calculate_safety_grade(self):
        """Test safety grade calculation."""
        runner = TestRunner(self.evaluation_run)
        
        # No violations
        grade = runner._calculate_safety_grade(0, 100)
        self.assertEqual(grade, 1.0)
        
        # Some violations
        grade = runner._calculate_safety_grade(10, 100)
        self.assertEqual(grade, 0.9)
        
        # All violations
        grade = runner._calculate_safety_grade(100, 100)
        self.assertEqual(grade, 0.0)
    
    def test_generate_metrics(self):
        """Test metrics generation."""
        runner = TestRunner(self.evaluation_run)
        runner.start_time = timezone.now()
        runner.end_time = timezone.now()
        runner._generate_metrics(None)
        
        # Should have generated metrics
        self.assertIn('scenario_metrics', runner.metrics)
        self.assertIn('safety_metrics', runner.metrics)
        self.assertIn('event_metrics', runner.metrics)


class TestRunnerFactoryTest(TestCase):
    """Test TestRunnerFactory."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.org = Organization.objects.create(name="Test Org")
        self.agent = Agent.objects.create(owner=self.org)
        
        self.scenario = Scenario.objects.create(
            name="Test Scenario",
            description="Test",
            scenario_type="business",
            script=[
                {
                    'type': 'user_message',
                    'timestamp': 0,
                    'message': 'Hello'
                }
            ]
        )
        
        self.evaluation_run = EvaluationRun.objects.create(
            organization=self.org,
            agent=self.agent,
            scenario_set=[str(self.scenario.scenario_id)],
            initiated_by='test',
            status='pending'
        )
    
    def test_create_from_evaluation(self):
        """Test creating runner from evaluation."""
        runner = TestRunnerFactory.create_from_evaluation(
            str(self.evaluation_run.run_id)
        )
        
        self.assertIsInstance(runner, TestRunner)
        self.assertEqual(
            runner.evaluation_run.run_id,
            self.evaluation_run.run_id
        )


class TestRunnerIntegrationTest(TestCase):
    """Integration tests for complete evaluation workflow."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.org = Organization.objects.create(name="Test Org")
        self.agent = Agent.objects.create(owner=self.org)
        
        # Create simple scenario
        self.scenario = Scenario.objects.create(
            name="Integration Test",
            description="Integration test scenario",
            scenario_type="business",
            difficulty="easy",
            script=[
                {
                    'type': 'user_message',
                    'timestamp': 0,
                    'message': 'Test message 1'
                },
                {
                    'type': 'user_message',
                    'timestamp': 2,
                    'message': 'Test message 2'
                }
            ],
            expected_outcomes={
                'min_events': 2
            }
        )
        
        # Create evaluation run
        self.evaluation_run = EvaluationRun.objects.create(
            organization=self.org,
            agent=self.agent,
            scenario_set=[str(self.scenario.scenario_id)],
            initiated_by='integration_test',
            seed=99999,
            enable_pii_detection=True,
            status='pending'
        )
    
    def test_full_evaluation_pipeline(self):
        """Test complete evaluation pipeline."""
        # Execute
        runner = TestRunner(self.evaluation_run)
        completed_run = runner.execute()
        
        # Verify completion
        self.assertEqual(completed_run.status, 'completed')
        self.assertIsNotNone(completed_run.results)
        
        # Verify metrics generated
        metrics = completed_run.results.get('metrics', {})
        self.assertIn('scenario_metrics', metrics)
        self.assertIn('safety_metrics', metrics)
        
        # Verify scenarios executed
        scenario_results = completed_run.results.get(
            'scenario_results', 
            []
        )
        self.assertEqual(len(scenario_results), 1)
    
    def test_evaluation_with_validators(self):
        """Test evaluation with validators enabled."""
        # Enable multiple validators
        self.evaluation_run.enable_pii_detection = True
        self.evaluation_run.enable_policy_enforcement = True
        self.evaluation_run.enable_prompt_injection_detection = True
        self.evaluation_run.save()
        
        # Execute
        runner = TestRunner(self.evaluation_run)
        completed_run = runner.execute()
        
        # Should have completed successfully
        self.assertEqual(completed_run.status, 'completed')
        
        # Should have validation results
        validation_summary = completed_run.results.get(
            'validation_summary', 
            {}
        )
        self.assertIn('total_violations', validation_summary)
    
    def test_evaluation_with_redteam(self):
        """Test evaluation with red team enabled."""
        # Enable red team
        self.evaluation_run.redteam_enabled = True
        self.evaluation_run.redteam_level = 'medium'
        self.evaluation_run.save()
        
        # Update scenario to have injections
        self.scenario.injection_points = [
            {
                'type': 'adversarial',
                'attack_type': 'prompt_injection',
                'trigger_type': 'random',
                'probability': 1.0
            }
        ]
        self.scenario.save()
        
        # Execute
        runner = TestRunner(self.evaluation_run)
        completed_run = runner.execute()
        
        # Should have red team metrics
        metrics = completed_run.results.get('metrics', {})
        redteam_metrics = metrics.get('redteam_metrics', {})
        self.assertIn('survival_rate', redteam_metrics)
        self.assertTrue(redteam_metrics.get('enabled', False))


