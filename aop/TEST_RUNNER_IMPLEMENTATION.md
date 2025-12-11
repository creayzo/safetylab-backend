# Test Runner Implementation Summary

## What Was Implemented

A comprehensive **Test Runner (Execution Pipeline)** - the master orchestrator that coordinates the complete agent evaluation workflow. This sits at the top level above all other components and orchestrates:

1. ✅ **EvaluationRun Configuration Reading**
2. ✅ **Scenario Set Assembly**
3. ✅ **RNG Seeding for Reproducibility**
4. ✅ **Validator Initialization**
5. ✅ **Scenario Execution via Scenario Engine**
6. ✅ **Real-time Event Streaming & Validation**
7. ✅ **Violation Threshold Checking**
8. ✅ **Replay Runner Integration (Optional)**
9. ✅ **Comprehensive Metrics Aggregation**
10. ✅ **Result Finalization & Storage**

## Files Created

### Core Pipeline Files

1. **`test_runner.py`** (~700 lines) - Main orchestrator
   - `TestRunner` class - Master orchestrator
   - `TestRunnerFactory` - Factory pattern for creation
   - Complete pipeline implementation
   - Metrics aggregation
   - Pass/fail determination

2. **`test_runner_tasks.py`** - Celery async tasks
   - `execute_evaluation_run` - Async execution
   - `execute_evaluation_batch` - Parallel batch execution
   - `cleanup_old_evaluation_runs` - Cleanup task
   - `schedule_periodic_evaluations` - Auto-monitoring

3. **`management/commands/run_evaluation.py`** - CLI command
   - Create evaluations from command line
   - Execute synchronously or asynchronously
   - Detailed result display
   - Progress reporting

### Support Files

4. **`tests/test_runner.py`** - Comprehensive test suite
   - TestRunner unit tests
   - Factory tests
   - Integration tests
   - Full pipeline tests

5. **`TEST_RUNNER_README.md`** - Complete documentation
   - Architecture overview
   - Quick start guide
   - API reference
   - Examples and best practices
   - Troubleshooting guide

6. **`example_test_runner_usage.py`** - Working examples
   - Basic evaluation
   - Adversarial evaluation
   - Comprehensive evaluation
   - Copy-paste ready code

7. **`TEST_RUNNER_IMPLEMENTATION.md`** - This file

## Architecture

```
┌───────────────────────────────────────────────────────────┐
│                    Test Runner                            │
│              (Master Orchestrator)                        │
├───────────────────────────────────────────────────────────┤
│                                                           │
│  ┌─────────────────────────────────────────────────┐   │
│  │ 1. Read EvaluationRun Configuration              │   │
│  └─────────────────────────────────────────────────┘   │
│                        ▼                                 │
│  ┌─────────────────────────────────────────────────┐   │
│  │ 2. Assemble Scenario Set                         │   │
│  └─────────────────────────────────────────────────┘   │
│                        ▼                                 │
│  ┌─────────────────────────────────────────────────┐   │
│  │ 3. Seed RNG for Reproducibility                  │   │
│  └─────────────────────────────────────────────────┘   │
│                        ▼                                 │
│  ┌─────────────────────────────────────────────────┐   │
│  │ 4. Initialize Validators                         │   │
│  │    • PIIDetector                                 │   │
│  │    • PolicyValidator                             │   │
│  │    • PromptInjectionDetector                     │   │
│  │    • ActionMisuseDetector                        │   │
│  └─────────────────────────────────────────────────┘   │
│                        ▼                                 │
│  ┌─────────────────────────────────────────────────┐   │
│  │ 5. Execute Scenarios                             │   │
│  │    ┌────────────────────────────────────┐       │   │
│  │    │   For each scenario:               │       │   │
│  │    │   • Create ScenarioEngine          │       │   │
│  │    │   • Execute scenario script        │       │   │
│  │    │   • Apply injections               │       │   │
│  │    │   • Collect events                 │       │   │
│  │    └────────────────────────────────────┘       │   │
│  └─────────────────────────────────────────────────┘   │
│                        ▼                                 │
│  ┌─────────────────────────────────────────────────┐   │
│  │ 6. Stream Events & Validate                      │   │
│  │    • Get TraceEvents                             │   │
│  │    • Apply all validators                        │   │
│  │    • Collect violations                          │   │
│  │    • Store validation results                    │   │
│  └─────────────────────────────────────────────────┘   │
│                        ▼                                 │
│  ┌─────────────────────────────────────────────────┐   │
│  │ 7. Check Violation Thresholds                    │   │
│  │    • Compare against configured limits           │   │
│  │    • Flag critical violations                    │   │
│  └─────────────────────────────────────────────────┘   │
│                        ▼                                 │
│  ┌─────────────────────────────────────────────────┐   │
│  │ 8. Run Replay (Optional)                         │   │
│  │    • Create ReplaySnapshot                       │   │
│  │    • Execute ReplayRunner                        │   │
│  │    • Calculate reproducibility score             │   │
│  └─────────────────────────────────────────────────┘   │
│                        ▼                                 │
│  ┌─────────────────────────────────────────────────┐   │
│  │ 9. Generate Aggregated Metrics                   │   │
│  │    • Scenario metrics                            │   │
│  │    • Safety metrics                              │   │
│  │    • Red team metrics                            │   │
│  │    • Reproducibility metrics                     │   │
│  │    • Performance metrics                         │   │
│  └─────────────────────────────────────────────────┘   │
│                        ▼                                 │
│  ┌─────────────────────────────────────────────────┐   │
│  │ 10. Finalize & Store Results                     │   │
│  │    • Check pass criteria                         │   │
│  │    • Mark evaluation complete                    │   │
│  │    • Trigger notifications                       │   │
│  └─────────────────────────────────────────────────┘   │
│                                                           │
└───────────────────────────────────────────────────────────┘
```

## Key Features

### 1. Complete Pipeline Orchestration

The Test Runner orchestrates all components:
- **EvaluationRun**: Configuration and settings
- **Scenario Engine**: Test execution
- **Validators**: Safety checks
- **Replay Runner**: Reproducibility
- **WAL**: Event ingestion
- **Metrics**: Aggregation and reporting

### 2. Real-time Event Validation

As events are generated:
- Stream from TraceEvent table
- Apply all configured validators
- Collect violations immediately
- Check thresholds in real-time

### 3. Comprehensive Metrics

**Scenario Metrics:**
- Total scenarios run
- Pass/fail counts
- Pass rate

**Safety Metrics:**
- Overall safety grade (0.0-1.0)
- Violation counts by type
- Violation rate
- PII leaks, policy violations, prompt injections

**Red Team Metrics:**
- Survival rate
- Attacks survived
- Attack effectiveness

**Reproducibility Metrics:**
- Reproducibility score
- Determinism verification
- Event matching rate

**Performance Metrics:**
- Total execution time
- Per-scenario timing
- Resource utilization

### 4. Flexible Pass/Fail Criteria

Configurable thresholds for:
- Safety grade requirements
- Maximum violations allowed
- Red team survival rate
- Reproducibility score
- Output consistency

### 5. Async Execution

- Celery task integration
- Background processing
- Batch parallel execution
- Progress tracking
- Result notifications

### 6. CLI & Programmatic Access

**CLI:**
```bash
python manage.py run_evaluation --create --agent 1 --scenarios "id1,id2"
```

**Python:**
```python
completed = TestRunnerFactory.create_and_execute(eval_run_id)
```

## Integration Points

The Test Runner integrates with:

### 1. EvaluationRun Model
- Reads configuration
- Updates status
- Stores results

### 2. Scenario Engine
- Creates ScenarioEngine instances
- Executes scenarios
- Collects scenario results

### 3. Validators
- Initializes based on config
- Applies to all events
- Aggregates violations

### 4. Replay Runner
- Creates snapshots
- Runs replays
- Calculates reproducibility

### 5. TraceEvent/WAL
- Reads events
- Validates in real-time
- Tracks event flow

## Usage Examples

### Basic Evaluation

```python
from api.test_runner import TestRunnerFactory
from api.models import EvaluationRun

# Create evaluation
eval_run = EvaluationRun.objects.create(
    organization=org,
    agent=agent,
    scenario_set=scenario_ids,
    initiated_by='user',
    status='pending'
)

# Execute
completed = TestRunnerFactory.create_and_execute(
    str(eval_run.run_id)
)

# Check results
print(f"Passed: {completed.results['passed']}")
```

### Async Execution

```python
from api.test_runner_tasks import execute_evaluation_run

# Queue for execution
task = execute_evaluation_run.delay(str(eval_run.run_id))

# Check later
result = task.get(timeout=600)
```

### CLI Execution

```bash
# Create and run
python manage.py run_evaluation \
  --create \
  --agent 1 \
  --scenarios "uuid1,uuid2,uuid3" \
  --redteam \
  --redteam-level high \
  --seed 12345

# Run existing
python manage.py run_evaluation --run-id <uuid>

# Async
python manage.py run_evaluation --run-id <uuid> --async
```

## Metrics Output Example

```python
{
    'passed': True,
    'pass_criteria_violations': [],
    
    'metrics': {
        'scenario_metrics': {
            'total_scenarios': 5,
            'passed': 4,
            'failed': 1,
            'pass_rate': 0.8
        },
        'safety_metrics': {
            'safety_grade': 0.92,
            'total_violations': 3,
            'pii_violations': 0,
            'policy_violations': 1,
            'prompt_injection_attempts': 2,
            'violation_rate': 0.05
        },
        'redteam_metrics': {
            'enabled': True,
            'survival_rate': 0.90,
            'attacks_survived': 18
        },
        'reproducibility_metrics': {
            'score': 0.98,
            'is_reproducible': True
        },
        'performance_metrics': {
            'total_execution_time': 125.3,
            'avg_scenario_time': 25.1
        }
    },
    
    'scenario_results': [
        {
            'scenario_id': 'uuid1',
            'scenario_name': 'Customer Support Test',
            'status': 'completed',
            'passed': True,
            'total_events': 12,
            'injections': 2,
            'deviations': 0
        }
    ],
    
    'validation_summary': {
        'total_violations': 3,
        'violations_by_type': {
            'policy_violation': 1,
            'prompt_injection': 2
        }
    }
}
```

## Testing

Comprehensive test coverage:

```bash
# Run all tests
python manage.py test api.tests.test_runner

# Specific test class
python manage.py test api.tests.test_runner.TestRunnerTest

# Integration tests
python manage.py test api.tests.test_runner.TestRunnerIntegrationTest
```

## Performance Considerations

- **Parallel Scenarios**: Can run multiple scenarios concurrently
- **Batch Execution**: Process multiple evaluations in parallel
- **Streaming Validation**: Real-time without loading all events
- **Efficient Metrics**: Incremental aggregation
- **Optional Replay**: Can skip replay for faster execution

## Best Practices

1. **Always Set Seeds**: For reproducible testing
2. **Start Conservative**: Begin with lenient thresholds
3. **Progressive Hardening**: Gradually tighten requirements
4. **Monitor Trends**: Track metrics over time
5. **Use Async for Production**: Non-blocking execution
6. **Set Timeouts**: Prevent hung evaluations
7. **Review Failures**: Investigate failed scenarios
8. **Archive Results**: Keep evaluation history
9. **CI/CD Integration**: Automate testing
10. **Regular Monitoring**: Schedule periodic evaluations

## CI/CD Integration

```yaml
# .github/workflows/agent-testing.yml
name: Agent Testing
on: [push, pull_request]

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      
      - name: Setup
        run: |
          pip install -r requirements.txt
          python manage.py migrate
          python manage.py load_scenarios
      
      - name: Run Evaluation
        run: |
          python manage.py run_evaluation \
            --create \
            --agent 1 \
            --scenarios "$(python -c 'from api.scenario_models import Scenario; print(",".join(str(s.scenario_id) for s in Scenario.objects.all()[:5]))')" \
            --redteam \
            --seed 12345
```

## Future Enhancements

Potential additions:

1. **Distributed Execution**: Multi-worker scenario processing
2. **Live Dashboards**: Real-time monitoring UI
3. **Webhook Notifications**: Alert on completion/failure
4. **Result Comparison**: Compare across evaluation runs
5. **Auto-tuning**: ML-based threshold optimization
6. **Advanced Scheduling**: Cron-like evaluation scheduling
7. **Cost Tracking**: Token usage and compute costs
8. **Dependency Graphs**: Scenario dependency management

## Summary

The Test Runner is a **production-ready, comprehensive orchestration engine** that provides:

✅ Complete pipeline orchestration
✅ Real-time validation
✅ Comprehensive metrics
✅ Pass/fail automation
✅ Async execution
✅ CLI & API access
✅ CI/CD integration
✅ Full documentation
✅ Test coverage
✅ Example code

**Total implementation: ~1500 lines of production code** + tests + documentation.

## Files Summary

| File | Lines | Purpose |
|------|-------|---------|
| `test_runner.py` | ~700 | Main orchestrator |
| `test_runner_tasks.py` | ~150 | Celery tasks |
| `run_evaluation.py` | ~250 | CLI command |
| `test_runner.py` (tests) | ~400 | Test suite |
| `TEST_RUNNER_README.md` | ~800 | Documentation |
| `example_test_runner_usage.py` | ~400 | Examples |
| **Total** | **~2700** | **Complete implementation** |

The Test Runner completes the AOP platform by providing the top-level orchestration layer that brings all components together for comprehensive agent testing and evaluation.


