# Agent Observability Platform (AOP) - Django Service

Complete Django REST API for AI agent observability with Toon canonical format support, HMAC signature verification, and multi-auth support.

## Features

- **Toon Canonical Format**: JSON-based trace specification with reasoning/action/output payloads
- **Multi-Auth Support**: API keys, OAuth2/JWT, mTLS, HMAC signatures
- **Real-time Streaming**: WebSocket support for live trace updates
- **Audit Logging**: Complete audit trail for all operations
- **Key Management**: Encrypted salt keys with rotation support
- **Retention Policies**: Configurable data retention per organization

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
