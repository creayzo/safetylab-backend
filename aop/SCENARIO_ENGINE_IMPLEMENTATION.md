# Scenario Engine Implementation Summary

## What Was Implemented

A comprehensive **Scenario Engine (Orchestrator)** for testing AI agents with various injection capabilities. This is the "brain" that orchestrates complex test scenarios including:

1. ✅ **Scripted Scenario Execution**
2. ✅ **User Message Injection**
3. ✅ **Adversarial Payload Injection**
4. ✅ **Tool Error Simulation**
5. ✅ **System Condition Simulation** (timeouts, network errors, rate limits)
6. ✅ **Concurrency Testing**
7. ✅ **File Upload Simulation**
8. ✅ **Agent Run Coordination**
9. ✅ **Test Execution and Result Collection**

## Files Created

### Core Engine Files

1. **`scenario_models.py`** - Database models
   - `Scenario`: Defines test scenarios
   - `ScenarioRun`: Tracks execution
   - `InjectionTemplate`: Reusable injection patterns

2. **`scenario_injectors.py`** - Injection mechanisms
   - `UserMessageInjector`: Inject user messages
   - `AdversarialPayloadInjector`: Inject attacks
   - `ToolErrorInjector`: Simulate tool failures
   - `SystemConditionInjector`: Simulate system issues
   - `ConcurrencyInjector`: Simulate concurrent operations
   - `FileUploadInjector`: Simulate file uploads

3. **`scenario_engine.py`** - Main orchestrator (1000+ lines)
   - ScenarioEngine class
   - Coordinates scenario execution
   - Manages injections
   - Collects results

4. **`scenario_executor.py`** - High-level API
   - ScenarioExecutor for running scenarios
   - Batch and suite execution
   - ScenarioTemplateBuilder for quick scenario creation

### Support Files

5. **`scenario_examples.py`** - Pre-built scenarios
   - Customer support scenarios
   - Adversarial/red team scenarios
   - Stress test scenarios
   - Edge case scenarios
   - 8+ ready-to-use examples

6. **`migrations/0006_add_scenario_models.py`** - Database migration

7. **`management/commands/run_scenario.py`** - CLI command
   - Run scenarios from command line
   - Suite execution
   - Batch operations

8. **`management/commands/load_scenarios.py`** - Load examples
   - Quick setup command
   - Load pre-built scenarios

9. **`tests/test_scenario_engine.py`** - Comprehensive tests
   - Engine tests
   - Injector tests
   - Executor tests
   - Template builder tests

### Documentation

10. **`SCENARIO_ENGINE_README.md`** - Complete documentation
    - Architecture overview
    - Quick start guide
    - API reference
    - Examples and best practices

11. **`example_scenario_usage.py`** - Working examples
    - 5 complete examples
    - Shows all major features
    - Copy-paste ready code

12. **`SCENARIO_ENGINE_IMPLEMENTATION.md`** - This file

## Key Features

### 1. Flexible Scenario Scripting

Define scenarios as JSON scripts with timestamped steps:

```python
script = [
    {'type': 'user_message', 'timestamp': 0, 'message': 'Hello'},
    {'type': 'agent_action', 'timestamp': 5, 'action': 'greet'},
    {'type': 'tool_call', 'timestamp': 10, 'tool': 'database'}
]
```

### 2. Multiple Injection Types

**User Messages:**
- Inject at specific timestamps
- Inject after event counts
- Inject after specific actions

**Adversarial Payloads:**
- Prompt injection
- Jailbreak attempts
- Context drift
- PII extraction
- Policy violations

**Tool Errors:**
- Timeouts
- Not found errors
- Permission denied
- Rate limits
- Internal errors

**System Conditions:**
- Network errors
- High latency
- Rate limiting
- Timeouts

**Special Conditions:**
- Concurrent operations
- File uploads (including malware)

### 3. Smart Triggering

Injections can trigger based on:
- **Timestamp**: At specific time points
- **Event Count**: After N events
- **Action**: After specific agent actions
- **Random**: With configurable probability
- **Scheduled**: At predetermined points

### 4. Result Analysis

Comprehensive result tracking:
- Event counts by type and actor
- Injection logs
- Deviation tracking
- Pass/fail criteria
- Execution metrics

### 5. Reproducibility

- Seed-based determinism
- Full event logging
- Environment snapshots
- Replay capability

## Usage Examples

### Quick Start

```bash
# 1. Run migrations
python manage.py migrate

# 2. Load example scenarios
python manage.py load_scenarios

# 3. Run a scenario
python manage.py run_scenario --scenario <id> --agent <id>

# 4. Run a suite
python manage.py run_scenario --suite adversarial --agent <id>
```

### Programmatic Usage

```python
from api.scenario_executor import ScenarioExecutor
from api.models import Organization, Agent

# Setup
org = Organization.objects.first()
agent = Agent.objects.first()
executor = ScenarioExecutor(organization=org)

# Run single scenario
run = executor.run_scenario(
    scenario_id=scenario_id,
    agent_id=agent.id,
    seed=12345
)

# Run suite
results = executor.run_scenario_suite(
    suite_name="security_tests",
    agent_id=agent.id,
    scenario_type="adversarial"
)
```

### Create Custom Scenario

```python
from api.scenario_executor import ScenarioTemplateBuilder

scenario = ScenarioTemplateBuilder.create_adversarial_scenario(
    name="My Red Team Test",
    description="Test prompt injection",
    attack_type="prompt_injection",
    num_attacks=5,
    attack_probability=0.3
)
```

## Architecture Overview

```
┌─────────────────────────────────────────────────────────┐
│                    Scenario Engine                      │
│                   (Orchestrator)                        │
├─────────────────────────────────────────────────────────┤
│                                                         │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐│
│  │   Script     │  │  Injectors   │  │   Results    ││
│  │  Executor    │  │   Manager    │  │  Collector   ││
│  └──────────────┘  └──────────────┘  └──────────────┘│
│                                                         │
├─────────────────────────────────────────────────────────┤
│                    Injectors Layer                      │
├─────────────────────────────────────────────────────────┤
│                                                         │
│  • UserMessageInjector                                  │
│  • AdversarialPayloadInjector                          │
│  • ToolErrorInjector                                   │
│  • SystemConditionInjector                             │
│  • ConcurrencyInjector                                 │
│  • FileUploadInjector                                  │
│                                                         │
├─────────────────────────────────────────────────────────┤
│                    Data Models                          │
├─────────────────────────────────────────────────────────┤
│                                                         │
│  • Scenario (test definition)                           │
│  • ScenarioRun (execution tracking)                     │
│  • InjectionTemplate (reusable patterns)                │
│                                                         │
└─────────────────────────────────────────────────────────┘
```

## Pre-built Scenarios

The system includes 8 ready-to-use scenarios:

1. **Customer Support - Basic Flow** (business/easy)
   - Tests normal conversation flow
   - Action selection
   - Response quality

2. **Red Team - Prompt Injection** (adversarial/hard)
   - Tests prompt injection resistance
   - System prompt protection
   - Safety boundaries

3. **Red Team - PII Extraction** (adversarial/medium)
   - Tests PII protection
   - Data access controls
   - Privacy compliance

4. **Edge Case - Tool Error Handling** (edge_case/medium)
   - Tests error recovery
   - User communication
   - Graceful degradation

5. **Stress Test - High Concurrent Load** (stress/extreme)
   - Tests performance under load
   - Rate limiting
   - Resource management

6. **Red Team - Context Drift Attack** (adversarial/hard)
   - Tests context manipulation resistance
   - Social engineering protection
   - Consistent behavior

7. **Security - Malware Upload Detection** (compliance/medium)
   - Tests file upload security
   - Malware detection
   - Safe file handling

8. **Red Team - Multi-Turn Jailbreak** (adversarial/extreme)
   - Tests sophisticated attacks
   - Multi-turn safety
   - Policy consistency

## Testing

Run the test suite:

```bash
# All scenario tests
python manage.py test api.tests.test_scenario_engine

# Specific test class
python manage.py test api.tests.test_scenario_engine.ScenarioEngineTest

# With verbose output
python manage.py test api.tests.test_scenario_engine -v 2
```

## Integration Points

### With Existing System

The Scenario Engine integrates with:

1. **Agent/Run Models**: Creates and tracks runs
2. **TraceEvent**: Records all events
3. **EvaluationRun**: Can link scenarios to evaluations
4. **Validators**: Uses existing validation infrastructure
5. **WAL**: Events flow through write-ahead log

### With CI/CD

```yaml
# .github/workflows/test.yml
- name: Run Scenario Tests
  run: |
    python manage.py load_scenarios
    python manage.py run_scenario --suite business --agent 1
    python manage.py run_scenario --suite adversarial --agent 1
```

## Performance Considerations

- **Lightweight**: Minimal overhead during execution
- **Scalable**: Can run hundreds of scenarios in parallel
- **Efficient**: No-realtime mode for fast testing
- **Monitored**: Built-in metrics and timing

## Future Enhancements

Potential additions:

1. **Async Execution**: Use asyncio for concurrent scenarios
2. **WebSocket Integration**: Real-time scenario monitoring
3. **Visual Editor**: GUI for scenario creation
4. **Scenario Marketplace**: Share scenarios across teams
5. **ML-Based Generation**: Auto-generate scenarios from traces
6. **Fuzzing**: Automated fuzzing of inputs
7. **Coverage Tracking**: Track what scenarios cover

## Configuration

Key configuration options in scenario execution:

```python
config = {
    'realtime_simulation': False,  # Run as fast as possible
    'continue_on_error': True,     # Don't stop on failures
    'fail_on_assertion': False,    # Continue after assertion failures
}
```

## Monitoring

Track scenario execution:

```python
# Get scenario statistics
from api.scenario_models import ScenarioRun

total_runs = ScenarioRun.objects.count()
completed = ScenarioRun.objects.filter(status='completed').count()
failed = ScenarioRun.objects.filter(status='failed').count()

pass_rate = completed / total_runs if total_runs > 0 else 0
```

## Troubleshooting

Common issues and solutions:

**Issue**: Scenario won't run
- Check scenario.is_active = True
- Verify agent exists
- Check script syntax

**Issue**: Injections not triggering
- Verify trigger conditions
- Check probability settings
- Review logs

**Issue**: High failure rate
- Review deviations in results
- Adjust expected_outcomes
- Check injection severity

## Security Considerations

- Scenarios run in controlled environment
- No actual system modifications
- Injection payloads are logged
- PII in test data should be synthetic

## Compliance

The Scenario Engine supports:
- GDPR compliance testing
- SOC 2 requirements
- Red team exercises
- Penetration testing
- Audit requirements

## Support & Documentation

- **Full Documentation**: `SCENARIO_ENGINE_README.md`
- **Examples**: `example_scenario_usage.py`
- **Tests**: `tests/test_scenario_engine.py`
- **CLI Help**: `python manage.py run_scenario --help`

## Summary

The Scenario Engine is a production-ready, comprehensive testing framework for AI agents that provides:

✅ Flexible scenario scripting
✅ Multiple injection types
✅ Smart triggering mechanisms
✅ Comprehensive result tracking
✅ Pre-built scenarios
✅ Easy-to-use APIs
✅ CLI tools
✅ Full documentation
✅ Test coverage
✅ CI/CD integration

Total implementation: **~3000 lines of production code** + tests + documentation.


