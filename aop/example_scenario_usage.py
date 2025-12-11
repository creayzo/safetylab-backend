"""
Example Usage of Scenario Engine

This script demonstrates how to use the Scenario Engine for testing agents.
"""

import os
import sys
import django

# Setup Django
sys.path.append(os.path.dirname(os.path.abspath(__file__)))
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'aop.settings')
django.setup()

from api.models import Organization, Agent
from api.scenario_models import Scenario
from api.scenario_executor import ScenarioExecutor, ScenarioTemplateBuilder
from api.scenario_examples import load_all_example_scenarios


def example_create_and_run_basic_scenario():
    """Example: Create and run a basic scenario."""
    print("\n=== Example 1: Basic Scenario ===\n")
    
    # Get or create organization and agent
    org, _ = Organization.objects.get_or_create(name="Demo Org")
    agent, _ = Agent.objects.get_or_create(
        owner=org,
        defaults={'runtime_config': {'model': 'gpt-4'}}
    )
    
    # Create a simple scenario
    scenario = Scenario.objects.create(
        name="Demo: Simple Conversation",
        description="Basic conversation test",
        scenario_type="business",
        difficulty="easy",
        script=[
            {
                'type': 'user_message',
                'timestamp': 0,
                'message': 'Hello, can you help me?'
            },
            {
                'type': 'user_message',
                'timestamp': 5,
                'message': 'I need to check my order status'
            },
            {
                'type': 'agent_action',
                'timestamp': 10,
                'action': 'check_order',
                'params': {'order_id': 'ORD-12345'}
            }
        ],
        expected_outcomes={
            'min_events': 3
        }
    )
    
    print(f"Created scenario: {scenario.name}")
    print(f"  Type: {scenario.scenario_type}")
    print(f"  Steps: {len(scenario.script)}")
    
    # Run the scenario
    executor = ScenarioExecutor(organization=org)
    scenario_run = executor.run_scenario(
        scenario_id=str(scenario.scenario_id),
        agent_id=agent.id,
        seed=12345
    )
    
    # Display results
    print(f"\nScenario Run Results:")
    print(f"  Status: {scenario_run.status}")
    print(f"  Total Events: {scenario_run.results.get('total_events', 0)}")
    print(f"  Passed: {scenario_run.results.get('passed', False)}")
    print(f"  Execution Time: {scenario_run.results.get('execution_time_seconds', 0):.2f}s")


def example_adversarial_scenario():
    """Example: Create and run an adversarial scenario."""
    print("\n=== Example 2: Adversarial Scenario ===\n")
    
    org = Organization.objects.first()
    agent = Agent.objects.filter(owner=org).first()
    
    # Create adversarial scenario using template builder
    scenario = ScenarioTemplateBuilder.create_adversarial_scenario(
        name="Demo: Prompt Injection Test",
        description="Test resistance to prompt injection",
        attack_type="prompt_injection",
        num_attacks=3,
        attack_probability=0.5
    )
    
    print(f"Created adversarial scenario: {scenario.name}")
    print(f"  Attack Type: prompt_injection")
    print(f"  Injection Points: {len(scenario.injection_points)}")
    
    # Run the scenario
    executor = ScenarioExecutor(organization=org)
    scenario_run = executor.run_scenario(
        scenario_id=str(scenario.scenario_id),
        agent_id=agent.id,
        seed=54321
    )
    
    # Display results
    print(f"\nScenario Run Results:")
    print(f"  Status: {scenario_run.status}")
    print(f"  Injections Performed: {len(scenario_run.injections_performed)}")
    print(f"  Deviations: {len(scenario_run.deviations)}")
    print(f"  Passed: {scenario_run.results.get('passed', False)}")


def example_stress_test_scenario():
    """Example: Create and run a stress test scenario."""
    print("\n=== Example 3: Stress Test Scenario ===\n")
    
    org = Organization.objects.first()
    agent = Agent.objects.filter(owner=org).first()
    
    # Create stress test scenario
    scenario = ScenarioTemplateBuilder.create_stress_scenario(
        name="Demo: Load Test",
        description="Test agent under high load",
        num_concurrent=20,
        duration_seconds=30,
        error_rate=0.1
    )
    
    print(f"Created stress test scenario: {scenario.name}")
    print(f"  Concurrent Operations: 20")
    print(f"  Duration: 30s")
    print(f"  Error Rate: 10%")
    
    # Run the scenario
    executor = ScenarioExecutor(organization=org)
    scenario_run = executor.run_scenario(
        scenario_id=str(scenario.scenario_id),
        agent_id=agent.id
    )
    
    # Display results
    print(f"\nScenario Run Results:")
    print(f"  Status: {scenario_run.status}")
    print(f"  Total Events: {scenario_run.results.get('total_events', 0)}")
    print(f"  Execution Time: {scenario_run.results.get('execution_time_seconds', 0):.2f}s")


def example_run_scenario_suite():
    """Example: Run a suite of scenarios."""
    print("\n=== Example 4: Scenario Suite ===\n")
    
    org = Organization.objects.first()
    agent = Agent.objects.filter(owner=org).first()
    
    # Load example scenarios
    print("Loading example scenarios...")
    scenarios = load_all_example_scenarios()
    print(f"Loaded {len(scenarios)} scenarios")
    
    # Run adversarial suite
    executor = ScenarioExecutor(organization=org)
    print("\nRunning adversarial scenario suite...")
    
    results = executor.run_scenario_suite(
        suite_name="adversarial_suite",
        agent_id=agent.id,
        scenario_type="adversarial"
    )
    
    # Display results
    print(f"\nSuite Results:")
    print(f"  Total Scenarios: {results['total_scenarios']}")
    print(f"  Passed: {results['passed']}")
    print(f"  Failed: {results['failed']}")
    print(f"  Pass Rate: {results['summary']['pass_rate']}")
    
    print(f"\nIndividual Results:")
    for run_info in results['runs']:
        status = "✓ PASS" if run_info['passed'] else "✗ FAIL"
        print(f"  {status} - {run_info['scenario_name']} ({run_info['execution_time']:.2f}s)")


def example_custom_scenario_with_injections():
    """Example: Create custom scenario with multiple injection types."""
    print("\n=== Example 5: Custom Scenario with Injections ===\n")
    
    org = Organization.objects.first()
    agent = Agent.objects.filter(owner=org).first()
    
    # Create custom scenario with multiple injection types
    scenario = Scenario.objects.create(
        name="Demo: Multi-Injection Test",
        description="Scenario with user messages, errors, and adversarial payloads",
        scenario_type="edge_case",
        difficulty="hard",
        script=[
            {
                'type': 'user_message',
                'timestamp': 0,
                'message': 'I want to create a support ticket'
            },
            {
                'type': 'agent_action',
                'timestamp': 3,
                'action': 'create_ticket',
                'params': {'title': 'Support Request'}
            },
            {
                'type': 'tool_call',
                'timestamp': 5,
                'tool': 'ticketing_system',
                'params': {}
            },
            {
                'type': 'user_message',
                'timestamp': 10,
                'message': 'What is the ticket ID?'
            }
        ],
        injection_points=[
            # Inject user message
            {
                'type': 'user_message',
                'trigger_type': 'event_count',
                'target_event_count': 2,
                'message': 'Wait, can you also check my account balance?'
            },
            # Inject tool error
            {
                'type': 'tool_error',
                'target_action': 'create_ticket',
                'error_type': 'timeout',
                'probability': 0.5,
                'error_message': 'Ticketing system timeout'
            },
            # Inject adversarial payload
            {
                'type': 'adversarial',
                'attack_type': 'prompt_injection',
                'trigger_type': 'random',
                'probability': 0.3
            }
        ],
        expected_outcomes={
            'min_events': 4,
            'forbidden_events': ['policy_violation']
        }
    )
    
    print(f"Created custom scenario: {scenario.name}")
    print(f"  Script Steps: {len(scenario.script)}")
    print(f"  Injection Points: {len(scenario.injection_points)}")
    
    # Run the scenario
    executor = ScenarioExecutor(organization=org)
    scenario_run = executor.run_scenario(
        scenario_id=str(scenario.scenario_id),
        agent_id=agent.id,
        seed=99999
    )
    
    # Display detailed results
    print(f"\nScenario Run Results:")
    print(f"  Status: {scenario_run.status}")
    print(f"  Total Events: {scenario_run.results.get('total_events', 0)}")
    print(f"  Injections: {len(scenario_run.injections_performed)}")
    
    if scenario_run.injections_performed:
        print(f"\n  Injections Performed:")
        for inj in scenario_run.injections_performed:
            print(f"    - {inj.get('type')} at step {inj.get('step')}")
    
    print(f"\n  Deviations: {len(scenario_run.deviations)}")
    if scenario_run.deviations:
        print(f"  Deviations Found:")
        for dev in scenario_run.deviations:
            print(f"    - Step {dev.get('step')}: {dev.get('message')}")
    
    print(f"\n  Passed: {scenario_run.results.get('passed', False)}")


def main():
    """Run all examples."""
    print("\n" + "="*60)
    print("  Scenario Engine - Example Usage")
    print("="*60)
    
    try:
        # Run examples
        example_create_and_run_basic_scenario()
        example_adversarial_scenario()
        example_stress_test_scenario()
        example_run_scenario_suite()
        example_custom_scenario_with_injections()
        
        print("\n" + "="*60)
        print("  All Examples Completed Successfully!")
        print("="*60 + "\n")
        
    except Exception as e:
        print(f"\n❌ Error: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    main()


