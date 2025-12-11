
# Test Runner (Execution Pipeline) Documentation

## Overview

The **Test Runner** is the master orchestrator that coordinates the entire agent evaluation workflow. It sits at the top level and orchestrates:

- **EvaluationRun** configuration
- **Scenario Engine** (test execution)
- **Trace Ingestion** (WAL)
- **Validators** (safety checks)
- **Replay Runner** (reproducibility)
- **Metrics Aggregation**

This is the "Orchestrate the whole crash test" engine.

## Architecture

```
┌─────────────────────────────────────────────────────┐
│              Test Runner Pipeline                   │
├─────────────────────────────────────────────────────┤
│                                                     │
│  1. Read EvaluationRun Config                      │
│  2. Assemble Scenario Set                          │
│  3. Seed RNG                                       │
│  4. Initialize Validators                          │
│  5. Execute Scenarios ─────┐                       │
│                            ▼                        │
│                   ┌─────────────────┐              │
│                   │ Scenario Engine │              │
│                   │   (per scenario) │              │
│                   └─────────────────┘              │
│  6. Stream Events & Validate                       │
│  7. Check Violation Thresholds                     │
│  8. Run Replay (optional)                          │
│  9. Generate Aggregated Metrics                    │
│ 10. Finalize & Store Results                       │
│                                                     │
└─────────────────────────────────────────────────────┘
```

## Quick Start

### 1. Create Evaluation Run

```python
from api.models import Organization, Agent, EvaluationRun
from api.scenario_models import Scenario

org = Organization.objects.first()
agent = Agent.objects.first()

# Get scenarios
scenarios = Scenario.objects.filter(
    scenario_type='adversarial',
    is_active=True
)[:5]

# Create evaluation run
eval_run = EvaluationRun.objects.create(
    organization=org,
    agent=agent,
    scenario_set=[str(s.scenario_id) for s in scenarios],
    initiated_by='test_user',
    seed=12345,
    
    # Enable validators
    enable_pii_detection=True,
    enable_policy_enforcement=True,
    enable_prompt_injection_detection=True,
    
    # Enable red team
    redteam_enabled=True,
    redteam_level='high',
    
    # Thresholds
    max_pii_leak_tolerance=0,
    max_policy_violation_tolerance=2,
    min_safety_grade_required=0.9,
    
    # Execution config
    max_steps=100,
    timeout_seconds=300,
    
    status='pending'
)
```

### 2. Execute Synchronously

```python
from api.test_runner import TestRunnerFactory

# Execute
completed_run = TestRunnerFactory.create_and_execute(
    str(eval_run.run_id)
)

# Check results
print(f"Status: {completed_run.status}")
print(f"Passed: {completed_run.results.get('passed')}")
print(f"Safety Grade: {completed_run.results['metrics']['safety_metrics']['safety_grade']}")
```

### 3. Execute Asynchronously (Celery)

```python
from api.test_runner_tasks import execute_evaluation_run

# Queue for execution
task = execute_evaluation_run.delay(str(eval_run.run_id))

print(f"Task ID: {task.id}")

# Check status later
result = task.get(timeout=600)  # 10 minute timeout
```

### 4. CLI Execution

```bash
# Create and execute
python manage.py run_evaluation \
  --create \
  --agent 1 \
  --scenarios "uuid1,uuid2,uuid3" \
  --redteam \
  --seed 12345

# Execute existing
python manage.py run_evaluation \
  --run-id <uuid>

# Async execution
python manage.py run_evaluation \
  --run-id <uuid> \
  --async
```

## Pipeline Steps

### Step 1: Read Configuration

The runner loads the `EvaluationRun` configuration which contains:

- **Scenario Set**: Which scenarios to run
- **Validator Config**: Which validators to enable
- **Red Team Config**: Attack types and intensity
- **Execution Limits**: Max steps, timeout
- **Thresholds**: Pass/fail criteria
- **Reproducibility Config**: Seeds, determinism

### Step 2: Assemble Scenarios

- Loads `Scenario` objects from database
- Validates they exist and are active
- Orders them for execution
- Logs scenario information

### Step 3: Seed RNG

- Sets random seed for reproducibility
- Ensures consistent behavior across runs
- Can specify both orchestrator seed and agent seed

### Step 4: Initialize Validators

Creates validator instances based on configuration:

- **PIIDetector**: Scans for PII leaks
- **PolicyValidator**: Checks policy compliance
- **PromptInjectionDetector**: Detects injection attempts
- **ActionMisuseDetector**: Validates tool usage
- And more...

### Step 5: Execute Scenarios

For each scenario:

1. Create `ScenarioEngine` instance
2. Execute scenario script
3. Apply injections
4. Collect events
5. Store scenario results

### Step 6: Stream & Validate Events

As events are generated:

1. Stream from `TraceEvent` table
2. Apply all validators
3. Collect violations
4. Check real-time thresholds

### Step 7: Check Thresholds

Compare violations against configured thresholds:

- PII leak tolerance
- Policy violation tolerance
- Safety grade requirements
- Reproducibility requirements

### Step 8: Run Replay (Optional)

If enabled and conditions met:

1. Create replay snapshot
2. Execute replay
3. Compare results
4. Calculate reproducibility score

### Step 9: Generate Metrics

Aggregate metrics across all scenarios:

**Scenario Metrics:**
- Total scenarios
- Pass/fail counts
- Pass rate

**Safety Metrics:**
- Safety grade (0.0-1.0)
- Total violations
- Violations by type
- Violation rate

**Red Team Metrics:**
- Survival rate
- Attacks survived
- Attack types

**Reproducibility Metrics:**
- Reproducibility score
- Is reproducible (boolean)

**Performance Metrics:**
- Total execution time
- Average scenario time

### Step 10: Finalize

- Store complete results
- Check pass criteria
- Update evaluation status
- Trigger notifications (if configured)

## Configuration Options

### EvaluationRun Fields

```python
{
    # Identity
    'run_id': UUID,
    'organization': Organization,
    'agent': Agent,
    'initiated_by': str,
    
    # Execution
    'scenario_set': List[str],  # Scenario UUIDs
    'run_mode': 'single_turn|multi_turn|streaming|batch',
    'max_steps': int,
    'timeout_seconds': int,
    'parallelism': int,
    
    # Determinism
    'seed': int,
    'agent_seed': int,
    'fixed_sampling': bool,
    'capture_model_outputs': bool,
    
    # Safety Config
    'enable_pii_detection': bool,
    'enable_policy_enforcement': bool,
    'enable_prompt_injection_detection': bool,
    'enable_action_boundary_check': bool,
    # ... more validators
    
    # Thresholds
    'max_pii_leak_tolerance': int,
    'max_policy_violation_tolerance': int,
    'max_hallucination_threshold': float,
    'min_safety_grade_required': float,
    
    # Red Team
    'redteam_enabled': bool,
    'redteam_level': 'low|medium|high|extreme',
    'attack_modules_enabled': List[str],
    'max_redteam_events': int,
    
    # Agent Config
    'agent_model_name': str,
    'agent_temperature': float,
    'agent_tool_permissions': List[str],
    'max_tool_calls_allowed': int,
    
    # Pass Criteria
    'min_redteam_survival_rate': float,
    'min_reproducibility_score': float,
    'min_output_consistency': float,
}
```

## Result Structure

```python
{
    'passed': bool,
    'pass_criteria_violations': List[str],
    
    'metrics': {
        'scenario_metrics': {
            'total_scenarios': int,
            'passed': int,
            'failed': int,
            'pass_rate': float
        },
        'event_metrics': {
            'total_events': int,
            'total_injections': int,
            'events_per_scenario': float
        },
        'safety_metrics': {
            'safety_grade': float,  # 0.0-1.0
            'total_violations': int,
            'pii_violations': int,
            'policy_violations': int,
            'prompt_injection_attempts': int,
            'violation_rate': float
        },
        'redteam_metrics': {
            'enabled': bool,
            'survival_rate': float,
            'attacks_survived': int
        },
        'reproducibility_metrics': {
            'score': float,
            'is_reproducible': bool
        },
        'performance_metrics': {
            'total_execution_time': float,
            'avg_scenario_time': float
        }
    },
    
    'scenario_results': [
        {
            'scenario_id': str,
            'scenario_name': str,
            'status': str,
            'passed': bool,
            'total_events': int,
            'injections': int,
            'deviations': int
        }
    ],
    
    'validation_summary': {
        'total_violations': int,
        'violations_by_type': {
            'pii_leak': int,
            'policy_violation': int,
            # ...
        }
    }
}
```

## Advanced Usage

### Custom Validator Integration

```python
from api.validators.base import BaseValidator

class CustomValidator(BaseValidator):
    def validate(self, payload, event):
        violations = []
        # Your validation logic
        return violations

# Add to evaluation
runner = TestRunner(eval_run)
runner.validators.append(CustomValidator())
runner.execute()
```

### Batch Execution

```python
from api.test_runner_tasks import execute_evaluation_batch

# Create multiple evaluation runs
eval_run_ids = [
    str(eval_run1.run_id),
    str(eval_run2.run_id),
    str(eval_run3.run_id)
]

# Execute in parallel
batch_result = execute_evaluation_batch(eval_run_ids)
```

### Periodic Auto-Monitoring

```python
from api.test_runner_tasks import schedule_periodic_evaluations

# Schedule periodic evaluations
# Runs as Celery beat task
result = schedule_periodic_evaluations()
```

### CI/CD Integration

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

## Monitoring & Debugging

### Check Evaluation Status

```python
from api.models import EvaluationRun

eval_run = EvaluationRun.objects.get(run_id=run_id)

print(f"Status: {eval_run.status}")
print(f"Started: {eval_run.started_at}")
print(f"Completed: {eval_run.completed_at}")

if eval_run.status == 'failed':
    print(f"Error: {eval_run.error_message}")
```

### View Detailed Results

```python
results = eval_run.results

# Scenario breakdown
for scenario_result in results['scenario_results']:
    print(f"{scenario_result['scenario_name']}: {scenario_result['status']}")
    print(f"  Events: {scenario_result['total_events']}")
    print(f"  Passed: {scenario_result['passed']}")

# Violation breakdown
violations = results['validation_summary']['violations_by_type']
for vtype, count in violations.items():
    print(f"{vtype}: {count}")
```

### Enable Debug Logging

```python
import logging

logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)

# Now run evaluation
runner = TestRunner(eval_run)
runner.execute()
```

## Best Practices

1. **Always Use Seeds**: For reproducible testing
2. **Start Conservative**: Begin with lenient thresholds
3. **Progressive Hardening**: Gradually tighten requirements
4. **Monitor Metrics**: Track trends over time
5. **Batch Similar Tests**: Group scenarios by type
6. **Use Async for Production**: Avoid blocking main thread
7. **Set Reasonable Timeouts**: Prevent hung evaluations
8. **Review Failures**: Investigate failed scenarios
9. **Tune Thresholds**: Based on actual performance
10. **Archive Results**: Keep evaluation history

## Troubleshooting

### Evaluation Times Out

- Increase `timeout_seconds`
- Reduce `max_steps`
- Check for infinite loops in scenarios
- Review agent response times

### High Failure Rate

- Review violation details
- Check threshold settings
- Verify scenario expectations
- Test individual scenarios

### Validators Not Running

- Check validator enable flags
- Verify validator initialization
- Review error logs
- Test validators independently

### Replay Fails

- Ensure `capture_model_outputs=True`
- Check seed configuration
- Verify deterministic mode
- Review caching settings

### Memory Issues

- Reduce parallelism
- Limit scenario set size
- Enable result streaming
- Clean up old runs

## Performance Optimization

### Parallel Execution

```python
# Set parallelism for concurrent scenarios
eval_run.parallelism = 5
eval_run.save()
```

### Disable Expensive Features

```python
# Skip replay for faster execution
eval_run.capture_model_outputs = False

# Reduce logging
eval_run.trace_level = 'minimal'

# Limit validator checks
eval_run.enable_bias_check = False
```

### Batch Processing

```python
# Process multiple evaluations together
from celery import group

jobs = group(
    execute_evaluation_run.s(run_id) 
    for run_id in eval_run_ids
)
result = jobs.apply_async()
```

## API Reference

### TestRunner

```python
class TestRunner:
    def __init__(self, evaluation_run: EvaluationRun)
    def execute(self) -> EvaluationRun
```

### TestRunnerFactory

```python
class TestRunnerFactory:
    @classmethod
    def create_from_evaluation(cls, evaluation_run_id: str) -> TestRunner
    
    @classmethod
    def create_and_execute(cls, evaluation_run_id: str) -> EvaluationRun
```

### Celery Tasks

```python
@shared_task
def execute_evaluation_run(evaluation_run_id: str) -> dict

@shared_task
def execute_evaluation_batch(evaluation_run_ids: list) -> dict

@shared_task
def cleanup_old_evaluation_runs(days: int = 90) -> dict

@shared_task
def schedule_periodic_evaluations() -> dict
```

## Support

For issues or questions:
- Review logs in detail
- Check configuration
- Test components individually
- Consult scenario engine docs
- Run test suite

## Next Steps

- Configure your first evaluation
- Load example scenarios
- Run a test evaluation
- Review metrics
- Set up CI/CD integration
- Enable auto-monitoring


