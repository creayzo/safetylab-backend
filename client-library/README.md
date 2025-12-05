# AOP Client Library

Python client library for the **Agent Observability Platform (AOP)**.

## Features

- **Toon Parser & Serializer**: Parse and serialize Toon-formatted trace data
- **Trace Builder**: Helper to create TraceEvent structures with automatic sequence numbering
- **HMAC Signing**: Automatic signature generation for tamper detection
- **Batching & Backpressure**: Buffer events locally, flush at intervals or on completion
- **Retry Logic**: Exponential backoff with idempotency tokens
- **Local Fallback**: Store events locally when server is unavailable
- **Streaming Support**: WebSocket or chunked HTTP for real-time event transmission
- **Local Replay**: Write full traces to local files
- **PII Redaction**: Pre-send hooks for data redaction
- **Multiple Integration Modes**: Passive (push), Active (pull), and Hybrid

## Installation

```bash
# Basic installation
pip install aop-client

# With streaming support
pip install aop-client[streaming]

# Development
pip install aop-client[dev]
```

## Quick Start

### Passive Mode (Push)

Agent calls `emit_event()` as it reasons:

```python
from aop_client import AOPClient, ClientConfig, TraceBuilder

# Configure client
config = ClientConfig(
    api_key="aop_your_api_key_here",
    base_url="http://localhost:8000",
    agent_id=123,
    org_salt_key="your_org_salt_key"  # For signing
)

# Create client and trace builder
client = AOPClient(config)
builder = client.trace_builder

# Start background flusher
client.start()

# Emit reasoning event
event = builder.create_reasoning(
    goal="Process customer refund request",
    steps=[
        {
            "step_id": "s1",
            "description": "Validate order ID",
            "decision": "proceed",
            "confidence": 0.95
        }
    ],
    safety_checks=[
        {"name": "policy_check", "result": "passed"}
    ],
    uncertainty="low"
)
client.emit_event(event)

# Emit action request
event = builder.create_action_request(
    action="create_ticket",
    params={"order_id": "ORD-123", "reason": "defect"}
)
client.emit_event(event)

# Emit final output
event = builder.create_final_output(
    text="Ticket T-999 created successfully",
    structured={"ticket_id": "T-999"}
)
client.emit_event(event)

# Stop and flush remaining events
client.stop()
```

### Active Mode (Pull)

Collect events and return full trace:

```python
from aop_client import AOPClient, ClientConfig

config = ClientConfig(
    api_key="aop_your_api_key_here",
    base_url="http://localhost:8000",
    agent_id=123
)

client = AOPClient(config)
builder = client.trace_builder

# Create events
event1 = builder.create_reasoning(goal="Analyze query", steps=[], safety_checks=[], uncertainty="low")
event2 = builder.create_final_output(text="Analysis complete")

# Get full trace
trace = client.get_trace()  # Returns list of dicts
trace_json = client.get_trace_json(pretty=True)  # Returns JSON string

# Send trace to server (manual)
# ... your HTTP post logic ...
```

### Hybrid Mode

Stream events in real-time + batch upload on completion:

```python
from aop_client import AOPClient, ClientConfig
from aop_client.streaming import HybridClient

config = ClientConfig(
    api_key="aop_your_api_key_here",
    base_url="http://localhost:8000",
    agent_id=123,
    enable_streaming=True,
    streaming_url="ws://localhost:8000/ws/trace/"
)

base_client = AOPClient(config)
hybrid = HybridClient(
    base_client,
    streaming_url=config.streaming_url,
    streaming_mode="websocket"
)

# Use as context manager
with hybrid:
    builder = base_client.trace_builder
    
    # Events are streamed AND buffered for batch upload
    event = builder.create_reasoning(...)
    hybrid.emit_event(event)
    
    # Finalize sends remaining batch
    hybrid.finalize()
```

## Configuration

### From Code

```python
from aop_client import ClientConfig

config = ClientConfig(
    api_key="aop_...",
    base_url="http://localhost:8000",
    agent_id=123,
    
    # Batching
    batch_size=100,
    batch_interval=5.0,  # seconds
    max_buffer_size=1000,
    
    # Retry
    max_retries=3,
    retry_backoff_base=1.0,
    retry_backoff_max=60.0,
    
    # Fallback
    enable_local_fallback=True,
    local_fallback_dir="./aop_fallback",
    
    # Replay
    enable_local_replay=True,
    replay_dir="./aop_replay",
    
    # Streaming
    enable_streaming=False,
    streaming_url=None,
    
    # Security
    org_salt_key="your_salt_key",
    verify_ssl=True,
)
```

### From Environment

```python
from aop_client import ClientConfig

# Set environment variables:
# AOP_API_KEY=aop_...
# AOP_BASE_URL=http://localhost:8000
# AOP_AGENT_ID=123
# AOP_BATCH_SIZE=100
# AOP_ENABLE_STREAMING=true
# AOP_STREAMING_URL=ws://localhost:8000/ws/trace/

config = ClientConfig.from_env()
```

## Advanced Features

### PII Redaction Hook

```python
def redact_pii(event: dict) -> dict:
    """Redact PII from event before sending."""
    if 'payload' in event:
        payload = event['payload']
        
        # Redact email addresses
        if 'email' in payload:
            payload['email'] = '[REDACTED]'
        
        # Redact phone numbers
        if 'phone' in payload:
            payload['phone'] = '[REDACTED]'
    
    return event

config = ClientConfig(
    api_key="...",
    redaction_hook=redact_pii
)
```

### Pre/Post Send Hooks

```python
def pre_send(event: dict):
    """Called before sending event."""
    print(f"Sending event seq={event['seq']}")

def post_send(event: dict, success: bool):
    """Called after sending event."""
    if success:
        print(f"Event seq={event['seq']} sent successfully")
    else:
        print(f"Event seq={event['seq']} failed to send")

config = ClientConfig(
    api_key="...",
    pre_send_hook=pre_send,
    post_send_hook=post_send
)
```

### Local Replay Files

Replay files are written to `replay_dir` when `enable_local_replay=True`:

```python
config = ClientConfig(
    api_key="...",
    enable_local_replay=True,
    replay_dir="./replays"
)

client = AOPClient(config)
# ... emit events ...
client.stop()  # Writes replay file

# Replay file format:
{
  "run_id": "550e8400-e29b-41d4-a716-446655440000",
  "timestamp": "2025-12-05T10:30:00.000Z",
  "event_count": 42,
  "metadata": {
    "agent_id": 123,
    "seed": 42,
    "stats": {...}
  },
  "events": [...]
}
```

### Fallback Storage

When server is unavailable, events are saved locally:

```python
config = ClientConfig(
    api_key="...",
    enable_local_fallback=True,
    local_fallback_dir="./fallback"
)

client = AOPClient(config)
# ... emit events ...
# If server fails, events saved to ./fallback/fallback_<run_id>_<timestamp>.json
```

## Toon Spec Helpers

### Create Payloads

```python
from aop_client.toon_parser import ToonBuilder

# Reasoning payload
reasoning = ToonBuilder.build_reasoning_payload(
    goal="Analyze customer request",
    steps=[
        {"step_id": "s1", "description": "Parse input", "confidence": 0.9}
    ],
    safety_checks=[
        {"name": "input_validation", "result": "passed"}
    ],
    uncertainty="low"
)

# Action request payload
action_req = ToonBuilder.build_action_request_payload(
    action="search_database",
    params={"query": "customer_id:123"},
    context={"timeout": 5000}
)

# Action response payload
action_resp = ToonBuilder.build_action_response_payload(
    status="ok",
    data={"results": [...]},
    meta={"latency_ms": 245}
)

# Final output payload
final = ToonBuilder.build_final_output_payload(
    text="Found 3 matching records",
    structured={"count": 3, "records": [...]}
)
```

### Parse and Serialize

```python
from aop_client import parse_toon, to_toon

# Parse Toon string
event = parse_toon('{"seq": 1, "t": "2025-12-05T10:00:00Z", ...}')

# Serialize to Toon string
toon_str = to_toon(event, pretty=True)
```

## Integration Examples

See the `examples/` directory for complete integration examples:

- `passive_mode.py`: Passive push integration
- `active_mode.py`: Active pull integration
- `hybrid_mode.py`: Hybrid streaming + batch
- `custom_hooks.py`: PII redaction and custom hooks
- `serverless.py`: Integration for serverless environments

## API Reference

### AOPClient

Main client for sending trace events.

**Methods:**
- `start()`: Start background flusher
- `stop(timeout=10.0)`: Stop and flush remaining events
- `emit_event(event)`: Emit a trace event
- `finalize()`: Finalize run and send all events
- `get_trace()`: Get all events as list
- `get_trace_json(pretty=False)`: Get events as JSON
- `get_stats()`: Get client statistics

### TraceBuilder

Helper for creating trace events.

**Methods:**
- `create_reasoning(...)`: Create reasoning event
- `create_action_request(...)`: Create action request
- `create_action_response(...)`: Create action response
- `create_final_output(...)`: Create final output
- `create_error(...)`: Create error event
- `create_custom(...)`: Create custom event
- `get_events()`: Get all events
- `export_trace()`: Export as list of dicts
- `export_trace_json(pretty=False)`: Export as JSON

### StreamingClient

Client for WebSocket/HTTP streaming.

**Methods:**
- `connect()`: Connect to streaming endpoint
- `disconnect()`: Disconnect
- `send_event(event)`: Send event via stream
- `is_connected()`: Check connection status

## Testing

```bash
# Run tests
pytest

# With coverage
pytest --cov=aop_client --cov-report=html

# Run specific test
pytest tests/test_client.py::test_passive_mode
```

## License

MIT License

## Support

For issues and questions:
- GitHub Issues: https://github.com/yourorg/aop-client/issues
- Documentation: https://aop-docs.example.com
- Email: support@aop.example.com
