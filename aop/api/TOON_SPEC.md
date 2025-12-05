# Toon Canonical Specification

## Overview

The Toon canonical specification defines the standardized format for trace events in the AOP (Agent Observability Platform) system. All trace events and audit logs must conform to this specification to ensure machine-parseability and consistency across the platform.

## Core Event Structure

Each TraceEvent must include these top-level fields:

```json
{
  "seq": 1,
  "t": "2025-12-05T10:30:00.000Z",
  "actor": "agent",
  "type": "reasoning",
  "payload": { ... },
  "meta": {
    "seed": 42,
    "run_id": "550e8400-e29b-41d4-a716-446655440000",
    "agent_id": 123,
    "session_id": "sess-abc123",
    "signature": "HMAC-SHA256-signature-here"
  }
}
```

### Field Definitions

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `seq` | int | Yes | Sequence number within the run |
| `t` | string | Yes | ISO 8601 timestamp |
| `actor` | enum | Yes | One of: `agent`, `tool`, `user`, `system`, `redteam` |
| `type` | enum | Yes | Event type (see Event Types section) |
| `payload` | object | Yes | Type-specific payload structure |
| `meta` | object | Yes | Metadata container (see Meta Structure) |

## Event Types

### 1. Reasoning Event

**Type:** `reasoning`

**Purpose:** Captures agent's reasoning process, decision-making steps, and safety checks.

**Payload Structure:**

```json
{
  "goal": "Process customer refund request",
  "steps": [
    {
      "step_id": "s1",
      "description": "interpret query",
      "decision": "select_tool: create_ticket",
      "confidence": 0.82
    },
    {
      "step_id": "s2",
      "description": "validate order_id",
      "decision": "proceed_with_validation",
      "confidence": 0.95
    }
  ],
  "safety_checks": [
    {
      "name": "policy_lookup",
      "result": "passed"
    },
    {
      "name": "data_validation",
      "result": "passed"
    }
  ],
  "uncertainty": "low"
}
```

**Required Fields:**
- `goal` (string): High-level objective
- `steps` (array): Ordered list of reasoning steps
  - Each step must have: `step_id`, `description`
  - Optional: `decision`, `confidence` (0.0-1.0)
- `safety_checks` (array): Security/policy validations
  - Each check must have: `name`, `result`
- `uncertainty` (enum): One of `low`, `medium`, `high`

---

### 2. Action Request Event

**Type:** `action_request`

**Purpose:** Records a request to execute an action or call a tool.

**Payload Structure:**

```json
{
  "action": "create_ticket",
  "params": {
    "title": "Refund Request - Order #12345",
    "order_id": "ORD-12345",
    "amount": 99.99,
    "reason": "Product defect"
  },
  "context": {
    "user_id": "U-789",
    "session_id": "sess-abc123",
    "timestamp": "2025-12-05T10:30:00Z"
  }
}
```

**Required Fields:**
- `action` (string): Name of the action/tool to execute
- `params` (object): Parameters for the action
- `context` (object, optional): Additional contextual information

---

### 3. Action Response Event

**Type:** `action_response`

**Purpose:** Captures the result of an action execution.

**Payload Structure (Success):**

```json
{
  "status": "ok",
  "data": {
    "ticket_id": "T-999",
    "created_at": "2025-12-05T10:30:15Z",
    "status": "open"
  },
  "meta": {
    "latency_ms": 120,
    "policy_flags": [],
    "retries": 0
  }
}
```

**Payload Structure (Error):**

```json
{
  "status": "error",
  "data": {
    "error_code": "INVALID_ORDER",
    "message": "Order ID not found",
    "details": {}
  },
  "meta": {
    "latency_ms": 85,
    "policy_flags": ["validation_failed"],
    "retries": 1
  }
}
```

**Required Fields:**
- `status` (enum): Either `ok` or `error`
- `data` (object): Result data or error information
- `meta` (object, optional): Performance metrics and flags

---

### 4. Final Output Event

**Type:** `final_output`

**Purpose:** Captures the final response returned to the user.

**Payload Structure:**

```json
{
  "text": "Your refund ticket has been created: T-999. You will receive an email confirmation shortly.",
  "structured": {
    "ticket_id": "T-999",
    "status": "created",
    "next_steps": [
      "Check email for confirmation",
      "Expect response within 24 hours"
    ],
    "reference_number": "REF-20251205-999"
  }
}
```

**Required Fields:**
- `text` (string): Human-readable output message
- `structured` (object, optional): Machine-readable structured result

---

### 5. Error Event

**Type:** `error`

**Purpose:** Records errors and exceptions during execution.

**Payload Structure:**

```json
{
  "error_type": "ValidationError",
  "message": "Invalid order ID format",
  "code": "ERR_INVALID_INPUT",
  "details": {
    "field": "order_id",
    "expected": "ORD-XXXXX",
    "received": "12345"
  },
  "recoverable": true,
  "timestamp": "2025-12-05T10:30:10Z"
}
```

**Required Fields:**
- `error_type` (string): Type/class of error
- `message` (string): Human-readable error message
- `code` (string): Error code for programmatic handling
- `details` (object): Detailed error context
- `recoverable` (boolean): Whether the error is recoverable

---

## Meta Structure

The `meta` object contains contextual information about the event:

```json
{
  "seed": 42,
  "run_id": "550e8400-e29b-41d4-a716-446655440000",
  "agent_id": 123,
  "session_id": "sess-abc123",
  "signature": "HMAC-SHA256-signature-here"
}
```

**Standard Meta Fields:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `run_id` | uuid | Yes | Unique identifier for the run |
| `agent_id` | int | Yes | ID of the agent |
| `seed` | int | No | Random seed for reproducibility |
| `session_id` | string | No | User session identifier |
| `signature` | string | Yes | HMAC signature for integrity verification |

Additional custom fields may be added to `meta` as needed.

---

## Actor Types

| Actor | Description |
|-------|-------------|
| `agent` | AI agent making decisions |
| `tool` | External tool or API being called |
| `user` | Human user interaction |
| `system` | System-level operations |
| `redteam` | Red team testing/adversarial probing |

---

## Machine Parseability

All payloads must be:
- Valid JSON format
- Parseable by the Toon library parser
- Conform to the specified structure for their event type
- Include all required fields
- Use correct data types

---

## Validation

Use the `ToonValidator` class from `api.toon_spec` module to validate payloads:

```python
from api.toon_spec import ToonValidator

# Validate a reasoning payload
is_valid, message = ToonValidator.validate_reasoning_payload(payload)

# Validate any payload by type
is_valid, message = ToonValidator.validate_payload('action_request', payload)
```

---

## Examples

See `api/toon_spec.py` for complete working examples:

```python
from api.toon_spec import ToonPayloadExamples

# Get example payloads
reasoning = ToonPayloadExamples.reasoning_payload()
action_req = ToonPayloadExamples.action_request_payload()
action_resp = ToonPayloadExamples.action_response_payload()
final = ToonPayloadExamples.final_output_payload()
error = ToonPayloadExamples.error_payload()
```

---

## Signature Generation

Event signatures use HMAC-SHA256:

1. Concatenate: `run_id + seq_no + timestamp + actor + type + payload_json`
2. Generate HMAC using organization's `salt_key`
3. Store signature in both `signature` field and `meta.signature`

Example:
```python
import hmac
import hashlib
import json

def generate_signature(org_salt_key, run_id, seq_no, timestamp, actor, type, payload):
    message = f"{run_id}{seq_no}{timestamp}{actor}{type}{json.dumps(payload, sort_keys=True)}"
    signature = hmac.new(
        org_salt_key.encode(),
        message.encode(),
        hashlib.sha256
    ).hexdigest()
    return signature
```

---

## Audit Logs

Audit logs follow the same Toon spec with additional event types:

- `config_change`: Configuration modifications
- `admin_action`: Administrative operations
- `policy_update`: Policy changes

Same structure applies with type-specific payload requirements.

---

## Best Practices

1. **Always validate** payloads before storing
2. **Include timestamps** in ISO 8601 format with timezone
3. **Sign all events** using organization's salt_key
4. **Preserve order** using sequential `seq` numbers
5. **Include context** in meta for debugging
6. **Use enums** for actor and type fields
7. **Document custom fields** added to payloads
8. **Test parseability** with Toon library before production

---

## Version

**Specification Version:** 1.0  
**Last Updated:** December 5, 2025  
**Status:** Active
