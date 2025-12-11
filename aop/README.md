# Agent Observability Platform (AOP) - Django Service

Complete Django REST API for AI agent observability with Toon canonical format support, HMAC signature verification, and multi-auth support.

## Features

- **Toon Canonical Format**: JSON-based trace specification with reasoning/action/output payloads
- **Multi-Auth Support**: API keys, OAuth2/JWT, mTLS, HMAC signatures
- **Real-time Streaming**: WebSocket support for live trace updates
- **Audit Logging**: Complete audit trail for all operations
- **Key Management**: Encrypted salt keys with rotation support
- **Retention Policies**: Configurable data retention per organization
- **Scenario Engine**: Comprehensive test orchestration with adversarial testing, error injection, and stress testing

## Quick Start

### 1. Installation

```bash
# Install dependencies
pip install -r requirements.txt

# Copy environment template
cp .env.example .env

# Generate encryption key
python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
# Add the output to SALT_ENCRYPTION_KEY in .env
```

### 2. Database Setup

```bash
# Run migrations
python manage.py migrate

# Create superuser
python manage.py createsuperuser
```

### 3. Generate Keys

```bash
# Create organization and salt key
python manage.py manage_keys create-org --name "Acme Corp"

# Generate API key for an agent
python manage.py manage_keys create-api-key --agent-id <uuid>
```

### 4. Run Server

```bash
# Development
python manage.py runserver

# Production (use gunicorn or similar)
gunicorn aop.wsgi:application --bind 0.0.0.0:8000
```

## API Endpoints

### Run Management

#### Create Run
```http
POST /api/runs/
Content-Type: application/json
X-API-Key: your-api-key
X-Signature: HMAC-SHA256-signature

{
  "agent_id": "uuid",
  "metadata": {
    "environment": "production",
    "version": "1.0.0"
  }
}
```

#### Append Trace Event
```http
POST /api/runs/{run_id}/events/
Content-Type: application/json
X-API-Key: your-api-key
X-Signature: HMAC-SHA256-signature

{
  "event_type": "reasoning",
  "timestamp": "2024-01-15T12:00:00Z",
  "payload": {
    "thought": "User wants to book a flight",
    "plan": ["Search flights", "Compare prices", "Book cheapest"],
    "confidence": 0.95
  }
}
```

#### Batch Events
```http
POST /api/trace-events/batch/
Content-Type: application/json
X-API-Key: your-api-key
X-Signature: HMAC-SHA256-signature

{
  "agent_id": "uuid",
  "events": [
    {
      "run_id": "uuid",
      "event_type": "reasoning",
      "timestamp": "2024-01-15T12:00:00Z",
      "payload": {...}
    },
    ...
  ]
}
```

#### Finalize Run
```http
POST /api/runs/{run_id}/finalize/
Content-Type: application/json
X-API-Key: your-api-key

{
  "status": "completed",
  "error": null
}
```

#### Download Trace
```http
GET /api/runs/{run_id}/trace?format=toon
X-API-Key: your-api-key

Response:
{
  "run_id": "uuid",
  "agent_id": "uuid",
  "created_at": "2024-01-15T12:00:00Z",
  "finalized_at": "2024-01-15T12:05:00Z",
  "status": "completed",
  "events": [
    {
      "event_id": "uuid",
      "event_type": "reasoning",
      "timestamp": "2024-01-15T12:00:00Z",
      "payload": {...}
    },
    ...
  ]
}
```

### Agent Management

#### Validate Agent Callback
```http
POST /api/agents/validate_callback
Content-Type: application/json
X-API-Key: your-api-key

{
  "agent_id": "uuid",
  "callback_url": "https://example.com/webhook"
}
```

### Admin Endpoints

#### Rotate Organization Salt Key
```http
POST /api/admin/organizations/{org_id}/rotate_salt_key
Content-Type: application/json
X-API-Key: admin-api-key
X-Signature: HMAC-SHA256-signature

{}

Response:
{
  "message": "Salt key rotated successfully",
  "new_key_id": "uuid"
}
```

#### Update Retention Policy
```http
PUT /api/admin/organizations/{org_id}/retention_policy
Content-Type: application/json
X-API-Key: admin-api-key

{
  "retention_days": 90
}
```

#### List Audit Logs
```http
GET /api/admin/organizations/{org_id}/audit_logs?limit=50&offset=0
X-API-Key: admin-api-key

Response:
{
  "count": 100,
  "next": "http://api/admin/organizations/{org_id}/audit_logs?limit=50&offset=50",
  "previous": null,
  "results": [
    {
      "id": "uuid",
      "action": "rotate_salt_key",
      "actor": "admin@example.com",
      "timestamp": "2024-01-15T12:00:00Z",
      "details": {...}
    },
    ...
  ]
}
```

## Authentication

### API Key Authentication

Add header:
```
X-API-Key: your-api-key-here
```

### JWT Authentication

```bash
# Get token
curl -X POST http://localhost:8000/api/token/ \
  -H "Content-Type: application/json" \
  -d '{"username": "user", "password": "pass"}'

# Use token
curl -X GET http://localhost:8000/api/runs/ \
  -H "Authorization: Bearer <token>"
```

### HMAC Signature Verification

Calculate signature:
```python
import hmac
import hashlib
import json

def generate_signature(payload: dict, salt_key: str) -> str:
    canonical = json.dumps(payload, sort_keys=True, separators=(',', ':'))
    signature = hmac.new(
        salt_key.encode('utf-8'),
        canonical.encode('utf-8'),
        hashlib.sha256
    ).hexdigest()
    return signature

# Add to headers
headers = {
    'X-Signature': generate_signature(payload, salt_key)
}
```

## Toon Canonical Format

### Event Types

1. **reasoning**: Agent's thought process
   ```json
   {
     "thought": "User wants to book a flight",
     "plan": ["Search flights", "Compare prices"],
     "confidence": 0.95,
     "reasoning_type": "chain_of_thought"
   }
   ```

2. **action_request**: Request to external system
   ```json
   {
     "tool_name": "search_flights",
     "arguments": {"from": "SFO", "to": "NYC"},
     "idempotency_key": "uuid"
   }
   ```

3. **action_response**: Response from external system
   ```json
   {
     "tool_name": "search_flights",
     "result": {"flights": [...]},
     "status": "success",
     "duration_ms": 1200
   }
   ```

4. **final_output**: Final response to user
   ```json
   {
     "content": "I found 5 flights for you.",
     "format": "text",
     "confidence": 0.98
   }
   ```

### Validation

The server validates all payloads against the Toon specification:
- Required fields presence
- Field type correctness
- Enum value validity
- Nested structure compliance

## Security Best Practices

### Production Checklist

- [ ] Set `DEBUG=False`
- [ ] Use strong `SECRET_KEY`
- [ ] Enable TLS: `SECURE_SSL_REDIRECT=True`
- [ ] Rotate salt keys regularly
- [ ] Use environment variables for secrets
- [ ] Configure CORS allowed origins
- [ ] Enable rate limiting
- [ ] Set up monitoring and alerting

### Key Management

```bash
# Rotate salt key every 90 days
python manage.py manage_keys rotate-salt --org-id <uuid>

# Revoke compromised API key
python manage.py manage_keys revoke-api-key --key-id <uuid>

# List all active keys
python manage.py manage_keys list-keys --org-id <uuid>
```

## Reporter Engine (Safety & Reliability Reports)

The AOP includes a comprehensive **Reporter Engine** that generates enterprise-ready safety and reliability reports. See `REPORTER_ENGINE_README.md` for full documentation.

### Quick Start

```bash
# Generate JSON report
python manage.py generate_report --run-id <uuid>

# Generate HTML report
python manage.py generate_report --run-id <uuid> --format html --output report.html

# Generate Markdown report
python manage.py generate_report --run-id <uuid> --format markdown --output report.md
```

### Programmatic Usage

```python
from api.models import EvaluationRun
from api.reporter_engine import ReporterEngine
from api.report_formatters import ReportFormatterFactory

# Load completed evaluation
eval_run = EvaluationRun.objects.get(run_id=run_id)

# Generate report
reporter = ReporterEngine(eval_run)
report = reporter.generate_report()

# Format as HTML
html_report = ReportFormatterFactory.format(report, 'html')

# Save to file
with open('safety_report.html', 'w') as f:
    f.write(html_report)
```

### Report Sections

- **Executive Summary**: Overall status, safety grade, key findings
- **Safety Assessment**: Safety grade (A+ to F), PII exposure, policy compliance
- **Security Assessment**: Prompt injection resistance, red team results
- **Reliability Assessment**: Reproducibility score, consistency metrics
- **Performance Assessment**: Execution time, event throughput
- **Recommendations**: Prioritized, actionable improvements
- **Severity Classification**: Risk level, deployment recommendation
- **Evidence Pack**: Links to trace data, replays, artifacts
- **Compliance Summary**: GDPR, SOC 2, HIPAA assessment

### Output Formats

- **JSON**: Machine-readable, API-friendly
- **HTML**: Professional web viewing, color-coded, print-friendly
- **Markdown**: Version control friendly, GitHub-compatible
- **PDF**: Via HTML conversion for executives

### Safety Grade System

| Grade | Score | Interpretation |
|-------|-------|----------------|
| A+ | 97-100% | Exceptional - Production ready |
| A | 93-96% | Excellent - Production ready |
| A- | 90-92% | Very Good - Production ready |
| B+/B/B- | 80-89% | Good to Fair - Acceptable |
| C+/C/C- | 70-79% | Poor - Needs improvement |
| D | 60-69% | Failing - Major issues |
| F | 0-59% | Critical failure |

## Test Runner (Execution Pipeline)

The AOP includes a master orchestrator called the **Test Runner** that coordinates complete evaluation workflows. See `TEST_RUNNER_README.md` for full documentation.

### Quick Start

```bash
# Create and execute evaluation
python manage.py run_evaluation \
  --create \
  --agent 1 \
  --scenarios "uuid1,uuid2,uuid3" \
  --redteam \
  --seed 12345

# Execute existing evaluation
python manage.py run_evaluation --run-id <uuid>

# Async execution
python manage.py run_evaluation --run-id <uuid> --async
```

### Programmatic Usage

```python
from api.models import Organization, Agent, EvaluationRun
from api.scenario_models import Scenario
from api.test_runner import TestRunnerFactory

# Setup
org = Organization.objects.first()
agent = Agent.objects.first()
scenarios = Scenario.objects.filter(is_active=True)[:5]

# Create evaluation
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
    
    # Red team
    redteam_enabled=True,
    redteam_level='high',
    
    # Thresholds
    min_safety_grade_required=0.9,
    
    status='pending'
)

# Execute
completed_run = TestRunnerFactory.create_and_execute(
    str(eval_run.run_id)
)

print(f"Passed: {completed_run.results.get('passed')}")
print(f"Safety Grade: {completed_run.results['metrics']['safety_metrics']['safety_grade']}")
```

### Pipeline Steps

1. **Read EvaluationRun Config** - Load configuration and settings
2. **Assemble Scenario Set** - Load and validate scenarios
3. **Seed RNG** - Set random seeds for reproducibility
4. **Initialize Validators** - Setup safety validators
5. **Execute Scenarios** - Run all scenarios via Scenario Engine
6. **Stream & Validate Events** - Real-time validation of agent behavior
7. **Run Replay** (optional) - Verify reproducibility
8. **Generate Metrics** - Aggregate results across all scenarios
9. **Finalize** - Store results and check pass criteria

### Key Features

- **Complete Orchestration**: Coordinates Scenario Engine, Validators, and Replay Runner
- **Real-time Validation**: Events validated as they're generated
- **Comprehensive Metrics**: Safety, red team, reproducibility, performance
- **Pass/Fail Criteria**: Configurable thresholds for automated gating
- **Async Execution**: Celery task support for background processing
- **CI/CD Ready**: Perfect for deployment pipelines

## Scenario Engine (Testing & Orchestration)

The AOP includes a powerful Scenario Engine for comprehensive agent testing. See `SCENARIO_ENGINE_README.md` for full documentation.

### Quick Start

```bash
# Load example scenarios
python manage.py load_scenarios

# Run a single scenario
python manage.py run_scenario --scenario <scenario_id> --agent <agent_id>

# Run scenario suite
python manage.py run_scenario --suite adversarial --agent <agent_id>
```

### Programmatic Usage

```python
from api.scenario_executor import ScenarioExecutor
from api.models import Organization, Agent

org = Organization.objects.first()
agent = Agent.objects.first()
executor = ScenarioExecutor(organization=org)

# Run single scenario
scenario_run = executor.run_scenario(
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

print(f"Passed: {results['passed']}/{results['total_scenarios']}")
```

### Features

- **Scripted Scenarios**: Define test scenarios with timestamped steps
- **Multiple Injection Types**: User messages, adversarial payloads, tool errors, system conditions
- **Smart Triggering**: Time-based, event-based, or probabilistic injections
- **Pre-built Scenarios**: 8+ ready-to-use scenarios (business logic, red team, stress tests)
- **Suite Execution**: Run batches of related scenarios
- **Result Analysis**: Comprehensive metrics and deviation tracking
- **Reproducibility**: Seed-based determinism for consistent testing

### Example Scenarios Included

- Customer Support - Basic Flow
- Red Team - Prompt Injection
- Red Team - PII Extraction
- Edge Case - Tool Error Handling
- Stress Test - High Concurrent Load
- Red Team - Context Drift Attack
- Security - Malware Upload Detection
- Red Team - Multi-Turn Jailbreak

See `example_scenario_usage.py` for working examples.

## Client Library Integration

See `../client-library/README.md` for Python client library usage.

Quick example:
```python
from aop_client import AOPClient, ClientConfig

config = ClientConfig(
    base_url="http://localhost:8000",
    api_key="your-api-key",
    salt_key="your-salt-key"
)
client = AOPClient(config)

# Passive mode
with client.trace_run(agent_id="uuid") as run:
    # Your agent code here
    pass
```

## Database Schema

### Core Models

- **Organization**: Multi-tenant organization
- **Agent**: AI agent instance
- **Run**: Single execution trace
- **TraceEvent**: Individual event in a run (Toon format)
- **TraceRecord**: Aggregated trace for export
- **EnvironmentSnapshot**: Runtime environment capture
- **AuditLog**: Security audit trail

### Auth Models

- **OrganizationSaltKey**: Encrypted HMAC keys
- **AgentAPIKey**: Hashed API credentials
- **MTLSCertificate**: mTLS certificate storage
- **OAuthToken**: OAuth2 token management

## Development

### Running Tests

```bash
python manage.py test api
```

### Code Quality

```bash
# Format code
black .

# Lint
flake8 .

# Type checking
mypy .
```

### Database Reset

```bash
# WARNING: Deletes all data
python manage.py flush
python manage.py migrate
```

## Troubleshooting

### "SALT_ENCRYPTION_KEY not configured"
Generate and set in `.env`:
```bash
python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
```

### "Signature verification failed"
- Check salt key matches between client and server
- Ensure canonical JSON formatting (sorted keys, no spaces)
- Verify timestamp is within acceptable skew

### "API key authentication failed"
- Confirm API key is active and not revoked
- Check agent_id matches the key
- Verify X-API-Key header is set correctly

## Performance Tips

- Use batch endpoints for high-throughput scenarios
- Enable database connection pooling
- Configure caching (Redis/Memcached)
- Use async workers for callback processing
- Monitor database query performance

## License

[Your License Here]

## Support

For issues and questions:
- GitHub Issues: [your-repo]
- Email: [your-email]
- Docs: [your-docs-url]
