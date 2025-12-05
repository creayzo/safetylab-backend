"""
Example: README for the Examples Directory

This directory contains complete working examples demonstrating all
integration modes and features of the AOP Client Library.
"""

# AOP Client Library - Examples

This directory contains practical examples demonstrating different ways to integrate with the Agent Observability Platform (AOP).

## Examples Overview

### 1. `passive_mode.py` - Passive (Push) Integration

**Best for:** Long-running agents, background processors, conversational AI

The agent calls `emit_event()` as it reasons. Events are automatically buffered and flushed to the server in batches.

**Key Features:**
- Background auto-flushing
- Batching and backpressure handling
- Local fallback storage
- Automatic retry with exponential backoff

**Run:**
```bash
python examples/passive_mode.py
```

---

### 2. `active_mode.py` - Active (Pull) Integration

**Best for:** Serverless/FaaS, request-response APIs, stateless agents

The agent collects events locally and returns the complete trace at the end. The orchestrator then sends the trace to AOP.

**Key Features:**
- No background threads
- Suitable for serverless environments
- Return full trace with response
- Orchestrator handles upload

**Run:**
```bash
python examples/active_mode.py
```

---

### 3. `hybrid_mode.py` - Hybrid Integration

**Best for:** Complex reasoning tasks, debugging, research

Combines real-time streaming (via WebSocket) with batch upload on completion. Provides live monitoring while ensuring guaranteed delivery.

**Key Features:**
- Real-time event streaming
- Fallback to batch if streaming fails
- Local replay recording
- Best visibility for debugging

**Run:**
```bash
python examples/hybrid_mode.py
```

**Requirements:**
```bash
pip install websocket-client  # For WebSocket support
```

---

### 4. `custom_hooks.py` - PII Redaction & Hooks

**Best for:** Compliance requirements, data governance, custom processing

Demonstrates how to implement PII redaction and custom event processing using hooks.

**Key Features:**
- Automatic PII redaction (emails, phones, SSNs, credit cards)
- Pre-send hooks for validation
- Post-send hooks for metrics/logging
- Compliance-friendly

**Run:**
```bash
python examples/custom_hooks.py
```

---

## Configuration

All examples use similar configuration. Update these values before running:

```python
config = ClientConfig(
    api_key="aop_your_api_key_here",        # Your agent API key
    base_url="http://localhost:8000",        # AOP server URL
    agent_id=123,                            # Your agent ID
    org_salt_key="your_org_salt_key_here"   # For HMAC signatures
)
```

### Getting Your Credentials

1. **API Key**: Generate via Django management command
   ```bash
   python manage.py manage_keys --agent 123 --create-api-key
   ```

2. **Agent ID**: Created when registering your agent
   ```bash
   python manage.py shell
   >>> from api.models import Agent, Organization
   >>> org = Organization.objects.first()
   >>> agent = Agent.objects.create(owner=org)
   >>> print(agent.id)
   ```

3. **Salt Key**: Retrieved from your organization
   ```bash
   python manage.py manage_keys --org "YourOrg" --init-salt
   ```

---

## Environment Variables

You can also configure using environment variables:

```bash
export AOP_API_KEY="aop_your_api_key_here"
export AOP_BASE_URL="http://localhost:8000"
export AOP_AGENT_ID="123"
export AOP_ORG_SALT_KEY="your_salt_key"
export AOP_BATCH_SIZE="100"
export AOP_BATCH_INTERVAL="5.0"
export AOP_ENABLE_STREAMING="true"
export AOP_STREAMING_URL="ws://localhost:8000/ws/trace/"
```

Then in your code:
```python
config = ClientConfig.from_env()
```

---

## Common Patterns

### Context Manager Pattern

Automatically starts and stops the client:

```python
with AOPClient(config) as client:
    builder = client.trace_builder
    
    event = builder.create_reasoning(...)
    client.emit_event(event)
    
    # Automatically flushed on exit
```

### Manual Control Pattern

More control over lifecycle:

```python
client = AOPClient(config)
client.start()

try:
    # Emit events
    ...
finally:
    client.stop()  # Ensures flush
```

### Serverless Pattern

No background threads, collect and return:

```python
def handler(event, context):
    client = AOPClient(config)
    builder = client.trace_builder
    
    # Process request and emit events
    ...
    
    # Return response + trace
    return {
        'statusCode': 200,
        'body': json.dumps(response),
        'trace': client.get_trace()
    }
```

---

## Troubleshooting

### Connection Refused

Server not running or wrong URL:
```python
config = ClientConfig(
    base_url="http://localhost:8000",  # Check port
    ...
)
```

### Authentication Failed

Invalid API key:
```bash
# Generate new key
python manage.py manage_keys --agent 123 --create-api-key
```

### Events Not Sending

Check batch configuration:
```python
config = ClientConfig(
    batch_size=10,        # Lower for testing
    batch_interval=1.0,   # Shorter interval
    ...
)
```

### Streaming Connection Failed

WebSocket not available or wrong URL:
```python
config = ClientConfig(
    streaming_url="ws://localhost:8000/ws/trace/",  # Check protocol and path
    ...
)
```

---

## Next Steps

1. **Run Examples**: Try each example to understand different modes
2. **Integrate**: Choose the mode that fits your use case
3. **Customize**: Add your own hooks and processing logic
4. **Deploy**: Configure for production environment
5. **Monitor**: Use AOP dashboard to view traces

---

## Additional Resources

- **Client Library Documentation**: `../README.md`
- **Toon Specification**: `../../aop/api/TOON_SPEC.md`
- **Server Setup**: `../../aop/README.md`
- **API Reference**: https://aop-docs.example.com/api

---

## Support

Questions? Issues?

- GitHub Issues: https://github.com/yourorg/aop-client/issues
- Discord: https://discord.gg/aop
- Email: support@aop.example.com
