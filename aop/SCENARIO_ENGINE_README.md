# Scenario Engine (Orchestrator) Documentation

## Overview

The Scenario Engine is a comprehensive test orchestration system for AI agents. It enables systematic testing across multiple dimensions:

- **Business Logic Testing**: Verify correct behavior in typical use cases
- **Adversarial Testing**: Red team attacks and jailbreak attempts
- **Stress Testing**: Load, concurrency, and performance testing
- **Edge Case Testing**: Error handling and resilience
- **Compliance Testing**: Security, privacy, and policy adherence

## Architecture

The Scenario Engine consists of several key components:

### 1. **Scenario Models** (`scenario_models.py`)
   - `Scenario`: Defines test scenarios with scripts and injection points
   - `ScenarioRun`: Tracks execution of scenarios
   - `InjectionTemplate`: Reusable injection patterns

### 2. **Scenario Injectors** (`scenario_injectors.py`)
   - `UserMessageInjector`: Injects user messages at defined points
   - `AdversarialPayloadInjector`: Injects attack payloads
   - `ToolErrorInjector`: Simulates tool/API errors
   - `SystemConditionInjector`: Simulates timeouts, network errors, etc.
   - `ConcurrencyInjector`: Simulates concurrent operations
   - `FileUploadInjector`: Simulates file upload scenarios

### 3. **Scenario Engine** (`scenario_engine.py`)
   - Main orchestrator that coordinates scenario execution
   - Manages state, context, and event flow
   - Applies injections at appropriate times
   - Collects results and deviations

### 4. **Scenario Executor** (`scenario_executor.py`)
   - High-level API for running scenarios
   - Batch and suite execution
   - Result aggregation
   - Template builders for common scenarios

## Quick Start

### 1. Create a Scenario

```python
from api.scenario_models import Scenario

scenario = Scenario.objects.create(
    name="Customer Support Test",
    description="Test refund request handling",
    scenario_type="business",
    difficulty="easy",
    script=[
        {
            'type': 'user_message',
            'timestamp': 0,
            'message': 'I want a refund for order ORD-12345'
        },
        {
            'type': 'agent_action',
            'timestamp': 5,
            'action': 'create_ticket',
            'params': {'order_id': 'ORD-12345'}
        }
    ],
    expected_outcomes={
        'min_events': 2,
        'required_events': ['action_request']
    }
)
```

### 2. Run a Scenario

```python
from api.scenario_executor import ScenarioExecutor
from api.models import Organization, Agent

org = Organization.objects.get(name="My Org")
agent = Agent.objects.get(id=1)

executor = ScenarioExecutor(organization=org)
scenario_run = executor.run_scenario(
    scenario_id=str(scenario.scenario_id),
    agent_id=agent.id,
    seed=12345
)

print(f"Status: {scenario_run.status}")
print(f"Passed: {scenario_run.results.get('passed')}")
```

### 3. Run via CLI

```bash
# Run single scenario
python manage.py run_scenario --scenario <scenario_id> --agent <agent_id>

# Run scenario suite
python manage.py run_scenario --suite adversarial --agent <agent_id>

# Run with specific seed for reproducibility
python manage.py run_scenario --scenario <scenario_id> --agent <agent_id> --seed 12345
```

## Scenario Script Format

A scenario script is a list of steps executed in sequence. Each step has:

- `type`: Step type (user_message, agent_action, tool_call, etc.)
- `timestamp`: When to execute (seconds from start)
- Additional type-specific fields

### Step Types

#### User Message
```python
{
    'type': 'user_message',
    'timestamp': 0,
    'message': 'Hello, I need help'
}
```

#### Agent Action
```python
{
    'type': 'agent_action',
    'timestamp': 5,
    'action': 'create_ticket',
    'params': {'order_id': 'ORD-123'}
}
```

#### Tool Call
```python
{
    'type': 'tool_call',
    'timestamp': 10,
    'tool': 'database_query',
    'params': {'query': 'SELECT * FROM orders'},
    'expected_result': {'count': 5}
}
```

#### System Event
```python
{
    'type': 'system_event',
    'timestamp': 15,
    'event': 'rate_limit_reached',
    'data': {'limit': 100}
}
```

#### Wait
```python
{
    'type': 'wait',
    'timestamp': 20,
    'duration': 5.0
}
```

#### Assertion
```python
{
    'type': 'assertion',
    'timestamp': 25,
    'assertion_type': 'equals',
    'actual_path': 'variables.ticket_count',
    'expected': 1
}
```

## Injection Points

Injections allow you to inject adversarial content, errors, or conditions during execution.

### User Message Injection
```python
{
    'type': 'user_message',
    'trigger_type': 'event_count',
    'target_event_count': 5,
    'message': 'Injected message'
}
```

### Adversarial Payload Injection
```python
{
    'type': 'adversarial',
    'attack_type': 'prompt_injection',
    'trigger_type': 'random',
    'probability': 0.3,
    'severity': 'high'
}
```

**Attack Types:**
- `prompt_injection`
- `jailbreak`
- `context_drift`
- `pii_extraction`
- `policy_violation`

### Tool Error Injection
```python
{
    'type': 'tool_error',
    'target_action': 'create_ticket',
    'error_type': 'timeout',
    'probability': 0.2,
    'error_message': 'Database timeout',
    'recoverable': True
}
```

**Error Types:**
- `timeout`
- `not_found`
- `permission_denied`
- `rate_limit`
- `invalid_input`
- `internal_error`

### System Condition Injection
```python
{
    'type': 'timeout',
    'condition_type': 'network_error',
    'target_timestamp': 10
}
```

**Condition Types:**
- `timeout`
- `network_error`
- `rate_limit`
- `high_latency`

### Concurrency Injection
```python
{
    'type': 'concurrency',
    'num_concurrent': 50,
    'operation': 'read',
    'duration_seconds': 30
}
```

### File Upload Injection
```python
{
    'type': 'file_upload',
    'file_type': 'document',
    'file_size_mb': 10,
    'filename': 'test.pdf',
    'malformed': False,
    'contains_malware': False
}
```

## Expected Outcomes

Define what success looks like for a scenario:

```python
expected_outcomes = {
    # Minimum number of events
    'min_events': 5,
    
    # Required event types
    'required_events': ['action_request', 'action_response'],
    
    # Forbidden event types (test fails if any occur)
    'forbidden_events': ['policy_violation', 'pii_leak'],
}
```

## Pre-built Scenarios

Load example scenarios:

```python
from api.scenario_examples import load_all_example_scenarios

scenarios = load_all_example_scenarios()
```

Available examples:
- Customer Support - Basic Flow
- Red Team - Prompt Injection
- Red Team - PII Extraction
- Edge Case - Tool Error Handling
- Stress Test - High Concurrent Load
- Red Team - Context Drift Attack
- Security - Malware Upload Detection
- Red Team - Multi-Turn Jailbreak

## Creating Custom Scenarios

### Using Template Builders

```python
from api.scenario_executor import ScenarioTemplateBuilder

# Basic scenario
scenario = ScenarioTemplateBuilder.create_basic_scenario(
    name="My Test",
    description="Test description",
    messages=["Hello", "How are you?"],
    expected_actions=["greet", "respond"]
)

# Adversarial scenario
scenario = ScenarioTemplateBuilder.create_adversarial_scenario(
    name="Red Team Test",
    description="Test prompt injection",
    attack_type="prompt_injection",
    num_attacks=5,
    attack_probability=0.3
)

# Stress test scenario
scenario = ScenarioTemplateBuilder.create_stress_scenario(
    name="Load Test",
    description="High load test",
    num_concurrent=50,
    duration_seconds=60,
    error_rate=0.2
)
```

## Running Scenario Suites

Execute multiple related scenarios:

```python
from api.scenario_executor import ScenarioExecutor

executor = ScenarioExecutor(organization=org)

# Run all adversarial scenarios
results = executor.run_scenario_suite(
    suite_name="adversarial_suite",
    agent_id=agent.id,
    scenario_type="adversarial"
)

print(f"Total: {results['total_scenarios']}")
print(f"Passed: {results['passed']}")
print(f"Failed: {results['failed']}")
print(f"Pass Rate: {results['summary']['pass_rate']}")
```

## Batch Execution

Run multiple scenarios in sequence:

```python
scenario_runs = executor.run_scenario_batch(
    scenario_ids=[scenario1_id, scenario2_id, scenario3_id],
    agent_id=agent.id,
    seeds=[12345, 54321, 99999]  # Optional, for reproducibility
)
```

## Result Analysis

Scenario results include:

```python
{
    'scenario_name': 'Test Scenario',
    'scenario_type': 'adversarial',
    'seed': 12345,
    'execution_time_seconds': 15.3,
    'total_steps': 10,
    'total_events': 25,
    'injections_count': 5,
    'deviations_count': 0,
    'events_by_type': {
        'user_input': 8,
        'action_request': 5,
        'action_response': 5,
        'reasoning': 7
    },
    'events_by_actor': {
        'user': 8,
        'agent': 12,
        'tool': 5
    },
    'outcome_checks': {
        'all_passed': True,
        'checks': [...]
    },
    'passed': True
}
```

## Integration with Evaluation System

Scenarios can be linked to EvaluationRun for comprehensive testing:

```python
from api.models import EvaluationRun

eval_run = EvaluationRun.objects.create(
    organization=org,
    agent=agent,
    scenario_set=[str(scenario.scenario_id)],
    redteam_enabled=True,
    redteam_level='high',
    # ... other eval parameters
)

# Link scenario run to evaluation
scenario_run.evaluation_run = eval_run
scenario_run.save()
```

## Best Practices

1. **Use Seeds for Reproducibility**: Always specify seeds for deterministic testing
2. **Tag Scenarios**: Use tags to organize and filter scenarios
3. **Start Simple**: Begin with basic scenarios before advancing to complex adversarial tests
4. **Monitor Injections**: Review injection logs to understand test coverage
5. **Analyze Deviations**: Investigate any deviations from expected behavior
6. **Batch Testing**: Run scenario suites regularly as part of CI/CD
7. **Gradual Difficulty**: Progress from easy → medium → hard → extreme

## CI/CD Integration

Example GitHub Actions workflow:

```yaml
name: Agent Testing
on: [push, pull_request]

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      - name: Run Scenario Tests
        run: |
          python manage.py run_scenario --suite business --agent 1
          python manage.py run_scenario --suite adversarial --agent 1
          python manage.py run_scenario --suite edge_case --agent 1
```

## Troubleshooting

### Scenario Won't Run
- Check that agent exists and is active
- Verify scenario is active (`is_active=True`)
- Ensure script is valid JSON

### Injections Not Triggering
- Check trigger conditions (timestamp, event_count, etc.)
- Verify probability settings
- Review injection logs in scenario_run.injections_performed

### Results Don't Match Expected
- Review deviations in scenario_run.deviations
- Check expected_outcomes configuration
- Verify assertion conditions

## API Reference

### ScenarioEngine
- `execute()`: Run the scenario
- `stop()`: Request execution stop

### ScenarioExecutor
- `run_scenario(scenario_id, agent_id, seed, config)`
- `run_scenario_batch(scenario_ids, agent_id, seeds, config)`
- `run_scenario_suite(suite_name, agent_id, scenario_type, tags, config)`

### ScenarioTemplateBuilder
- `create_basic_scenario(name, description, messages, expected_actions)`
- `create_adversarial_scenario(name, description, attack_type, num_attacks, attack_probability)`
- `create_stress_scenario(name, description, num_concurrent, duration_seconds, error_rate)`

## Support

For issues or questions:
1. Check this documentation
2. Review example scenarios in `scenario_examples.py`
3. Run tests: `python manage.py test api.tests.test_scenario_engine`
4. Check logs for detailed execution traces


