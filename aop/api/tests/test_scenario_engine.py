"""
Tests for Scenario Engine and Orchestrator.

Tests scenario execution, injection mechanisms, and result collection.
"""

import uuid
from django.test import TestCase
from django.utils import timezone
from unittest.mock import patch, MagicMock

from api.models import Organization, Agent, Run, TraceEvent
from api.scenario_models import Scenario, ScenarioRun, InjectionTemplate
from api.scenario_engine import ScenarioEngine
from api.scenario_executor import (
    ScenarioExecutor, 
    ScenarioTemplateBuilder
)
from api.scenario_injectors import (
    UserMessageInjector,
    AdversarialPayloadInjector,
    ToolErrorInjector,
    SystemConditionInjector
)


class ScenarioEngineTest(TestCase):
    """Test ScenarioEngine orchestrator."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.org = Organization.objects.create(name="Test Org")
        self.agent = Agent.objects.create(owner=self.org)
        
        # Create simple scenario
        self.scenario = Scenario.objects.create(
            name="Test Scenario",
            description="Basic test scenario",
            scenario_type="business",
            difficulty="easy",
            script=[
                {
                    'type': 'user_message',
                    'timestamp': 0,
                    'message': 'Hello, I need help'
                },
                {
                    'type': 'agent_action',
                    'timestamp': 2,
                    'action': 'greet_user',
                    'params': {}
                },
                {
                    'type': 'user_message',
                    'timestamp': 5,
                    'message': 'I want to check my order status'
                }
            ],
            expected_outcomes={
                'min_events': 3,
                'required_events': ['user_input']
            }
        )
    
    def test_engine_initialization(self):
        """Test engine initialization."""
        engine = ScenarioEngine(
            scenario=self.scenario,
            agent=self.agent,
            seed=12345
        )
        
        self.assertEqual(engine.scenario, self.scenario)
        self.assertEqual(engine.agent, self.agent)
        self.assertEqual(engine.seed, 12345)
        self.assertFalse(engine.is_running)
    
    def test_scenario_execution(self):
        """Test basic scenario execution."""
        engine = ScenarioEngine(
            scenario=self.scenario,
            agent=self.agent,
            seed=12345
        )
        
        scenario_run = engine.execute()
        
        # Verify scenario run created
        self.assertIsNotNone(scenario_run)
        self.assertEqual(scenario_run.status, 'completed')
        self.assertEqual(scenario_run.scenario, self.scenario)
        
        # Verify agent run created
        self.assertIsNotNone(scenario_run.agent_run)
        self.assertEqual(scenario_run.agent_run.agent, self.agent)
        
        # Verify events created
        events = TraceEvent.objects.filter(
            run=scenario_run.agent_run
        )
        self.assertGreater(events.count(), 0)
    
    def test_scenario_with_injections(self):
        """Test scenario with injections."""
        # Create scenario with injection
        scenario = Scenario.objects.create(
            name="Injection Test",
            description="Test with injection",
            scenario_type="adversarial",
            script=[
                {
                    'type': 'user_message',
                    'timestamp': 0,
                    'message': 'Normal message'
                }
            ],
            injection_points=[
                {
                    'type': 'adversarial',
                    'attack_type': 'prompt_injection',
                    'trigger_type': 'random',
                    'probability': 1.0  # Always inject
                }
            ]
        )
        
        engine = ScenarioEngine(
            scenario=scenario,
            agent=self.agent,
            seed=12345
        )
        
        scenario_run = engine.execute()
        
        # Verify injection was performed
        self.assertGreater(
            len(scenario_run.injections_performed), 
            0
        )
        
        # Verify injection logged
        injection = scenario_run.injections_performed[0]
        self.assertEqual(injection['type'], 'adversarial_payload')
    
    def test_scenario_with_assertions(self):
        """Test scenario with assertions."""
        scenario = Scenario.objects.create(
            name="Assertion Test",
            description="Test with assertions",
            scenario_type="business",
            script=[
                {
                    'type': 'user_message',
                    'timestamp': 0,
                    'message': 'Test'
                },
                {
                    'type': 'assertion',
                    'timestamp': 2,
                    'assertion_type': 'greater_than',
                    'actual_path': 'event_count',
                    'expected': 0
                }
            ]
        )
        
        engine = ScenarioEngine(
            scenario=scenario,
            agent=self.agent,
            config={'fail_on_assertion': False}
        )
        
        scenario_run = engine.execute()
        
        # Should complete without error
        self.assertEqual(scenario_run.status, 'completed')


class ScenarioInjectorsTest(TestCase):
    """Test scenario injectors."""
    
    def test_user_message_injector(self):
        """Test user message injection."""
        config = {
            'trigger_type': 'event_count',
            'target_event_count': 5,
            'message': 'Injected message'
        }
        
        injector = UserMessageInjector(config)
        
        # Should not inject yet
        context = {'event_count': 3}
        self.assertFalse(injector.should_inject(context))
        
        # Should inject now
        context = {'event_count': 5}
        self.assertTrue(injector.should_inject(context))
        
        # Test injection
        result = injector.inject(context)
        self.assertEqual(result['type'], 'user_message')
        self.assertEqual(result['message'], 'Injected message')
    
    def test_adversarial_injector(self):
        """Test adversarial payload injection."""
        config = {
            'trigger_type': 'scheduled',
            'target_timestamp': 10,
            'attack_type': 'prompt_injection'
        }
        
        injector = AdversarialPayloadInjector(config)
        
        # Test injection
        context = {'current_timestamp': 10}
        self.assertTrue(injector.should_inject(context))
        
        result = injector.inject(context)
        self.assertEqual(result['type'], 'adversarial_payload')
        self.assertEqual(result['attack_type'], 'prompt_injection')
        self.assertIn('payload', result)
    
    def test_tool_error_injector(self):
        """Test tool error injection."""
        config = {
            'target_action': 'create_ticket',
            'error_type': 'timeout',
            'probability': 1.0
        }
        
        injector = ToolErrorInjector(config)
        
        # Should inject for matching action
        context = {'current_action': 'create_ticket'}
        self.assertTrue(injector.should_inject(context))
        
        result = injector.inject(context)
        self.assertEqual(result['type'], 'tool_error')
        self.assertEqual(result['error_type'], 'timeout')
        self.assertEqual(result['status'], 'error')
    
    def test_system_condition_injector(self):
        """Test system condition injection."""
        config = {
            'condition_type': 'network_error',
            'target_timestamp': 5
        }
        
        injector = SystemConditionInjector(config)
        
        context = {'current_timestamp': 5}
        self.assertTrue(injector.should_inject(context))
        
        result = injector.inject(context)
        self.assertEqual(result['type'], 'system_condition')
        self.assertEqual(result['condition'], 'network_error')


class ScenarioExecutorTest(TestCase):
    """Test ScenarioExecutor."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.org = Organization.objects.create(name="Test Org")
        self.agent = Agent.objects.create(owner=self.org)
        self.executor = ScenarioExecutor(organization=self.org)
        
        # Create test scenario
        self.scenario = Scenario.objects.create(
            name="Executor Test",
            description="Test scenario for executor",
            scenario_type="business",
            script=[
                {
                    'type': 'user_message',
                    'timestamp': 0,
                    'message': 'Test message'
                }
            ]
        )
    
    def test_run_scenario(self):
        """Test running a single scenario."""
        scenario_run = self.executor.run_scenario(
            scenario_id=str(self.scenario.scenario_id),
            agent_id=self.agent.id,
            seed=12345
        )
        
        self.assertIsNotNone(scenario_run)
        self.assertEqual(scenario_run.scenario, self.scenario)
        self.assertEqual(scenario_run.seed, 12345)
    
    def test_run_scenario_batch(self):
        """Test running multiple scenarios."""
        # Create another scenario
        scenario2 = Scenario.objects.create(
            name="Batch Test 2",
            description="Second scenario",
            scenario_type="business",
            script=[
                {
                    'type': 'user_message',
                    'timestamp': 0,
                    'message': 'Test'
                }
            ]
        )
        
        results = self.executor.run_scenario_batch(
            scenario_ids=[
                str(self.scenario.scenario_id),
                str(scenario2.scenario_id)
            ],
            agent_id=self.agent.id
        )
        
        self.assertEqual(len(results), 2)
    
    def test_run_scenario_suite(self):
        """Test running a scenario suite."""
        # Create multiple scenarios with tags
        for i in range(3):
            Scenario.objects.create(
                name=f"Suite Test {i}",
                description=f"Scenario {i}",
                scenario_type="adversarial",
                tags=["redteam", "suite_test"],
                script=[
                    {
                        'type': 'user_message',
                        'timestamp': 0,
                        'message': f'Test {i}'
                    }
                ]
            )
        
        results = self.executor.run_scenario_suite(
            suite_name="test_suite",
            agent_id=self.agent.id,
            scenario_type="adversarial",
            tags=["suite_test"]
        )
        
        self.assertEqual(results['total_scenarios'], 3)
        self.assertIn('summary', results)
        self.assertIn('runs', results)


class ScenarioTemplateBuilderTest(TestCase):
    """Test ScenarioTemplateBuilder."""
    
    def test_create_basic_scenario(self):
        """Test creating basic scenario."""
        scenario = ScenarioTemplateBuilder.create_basic_scenario(
            name="Basic Test",
            description="Basic scenario",
            messages=["Hello", "How are you?", "Goodbye"],
            expected_actions=["greet", "respond", "farewell"]
        )
        
        self.assertIsNotNone(scenario)
        self.assertEqual(scenario.name, "Basic Test")
        self.assertEqual(scenario.scenario_type, "business")
        self.assertEqual(len(scenario.script), 3)
    
    def test_create_adversarial_scenario(self):
        """Test creating adversarial scenario."""
        scenario = ScenarioTemplateBuilder.create_adversarial_scenario(
            name="Adversarial Test",
            description="Red team test",
            attack_type="prompt_injection",
            num_attacks=5
        )
        
        self.assertIsNotNone(scenario)
        self.assertEqual(scenario.scenario_type, "adversarial")
        self.assertGreater(len(scenario.injection_points), 0)
        self.assertIn("redteam", scenario.tags)
    
    def test_create_stress_scenario(self):
        """Test creating stress scenario."""
        scenario = ScenarioTemplateBuilder.create_stress_scenario(
            name="Stress Test",
            description="Load test",
            num_concurrent=10,
            duration_seconds=30
        )
        
        self.assertIsNotNone(scenario)
        self.assertEqual(scenario.scenario_type, "stress")
        self.assertGreater(len(scenario.script), 0)
        self.assertGreater(len(scenario.injection_points), 0)


class InjectionTemplateTest(TestCase):
    """Test InjectionTemplate model."""
    
    def test_create_injection_template(self):
        """Test creating injection template."""
        template = InjectionTemplate.objects.create(
            name="Timeout Template",
            description="Simulates timeout errors",
            injection_type="timeout",
            payload_template={
                'timeout_seconds': 30,
                'message': 'Operation timed out'
            },
            trigger_config={
                'trigger_type': 'random',
                'probability': 0.1
            },
            severity="high"
        )
        
        self.assertIsNotNone(template)
        self.assertEqual(template.injection_type, "timeout")
        self.assertEqual(template.severity, "high")
    
    def test_injection_template_filtering(self):
        """Test filtering templates by type."""
        InjectionTemplate.objects.create(
            name="Template 1",
            description="Test",
            injection_type="adversarial",
            severity="high"
        )
        InjectionTemplate.objects.create(
            name="Template 2",
            description="Test",
            injection_type="tool_error",
            severity="medium"
        )
        
        # Filter by type
        adversarial = InjectionTemplate.objects.filter(
            injection_type="adversarial"
        )
        self.assertEqual(adversarial.count(), 1)
        
        # Filter by severity
        high_severity = InjectionTemplate.objects.filter(
            severity="high"
        )
        self.assertEqual(high_severity.count(), 1)


