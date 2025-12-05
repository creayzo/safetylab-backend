"""
Toon Canonical Spec Helper Module

This module provides helper functions and example payloads for working with
the Toon canonical specification format used in TraceEvent and AuditLog models.

Toon Spec Overview:
-------------------
Each TraceEvent must include these fields:
- seq: <int>                  # sequence in run
- t: <ISO timestamp>
- actor: <agent|tool|user|system|redteam>
- type: <reasoning|action_request|action_response|final_output|error>
- payload: { ... }            # Toon object
- meta:
    - seed: <int>
    - run_id: <uuid>
    - agent_id: <id>
    - session_id: <id>
    - signature: <HMAC>
"""

import json
from typing import Dict, Any, List


class ToonPayloadExamples:
    """Example payloads for each TraceEvent type following Toon spec."""
    
    @staticmethod
    def reasoning_payload() -> Dict[str, Any]:
        """
        Example reasoning payload structure.
        
        Returns:
            Dict containing goal, steps, safety_checks, and uncertainty level
        """
        return {
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
    
    @staticmethod
    def action_request_payload() -> Dict[str, Any]:
        """
        Example action_request payload structure.
        
        Returns:
            Dict containing action, params, and context
        """
        return {
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
    
    @staticmethod
    def action_response_payload(success: bool = True) -> Dict[str, Any]:
        """
        Example action_response payload structure.
        
        Args:
            success: Whether the action succeeded
            
        Returns:
            Dict containing status, data, and meta
        """
        if success:
            return {
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
        else:
            return {
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
    
    @staticmethod
    def final_output_payload() -> Dict[str, Any]:
        """
        Example final_output payload structure.
        
        Returns:
            Dict containing text and optional structured result
        """
        return {
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
    
    @staticmethod
    def error_payload() -> Dict[str, Any]:
        """
        Example error payload structure.
        
        Returns:
            Dict containing error details
        """
        return {
            "error_type": "ValidationError",
            "message": "Invalid order ID format",
            "code": "ERR_INVALID_INPUT",
            "details": {
                "field": "order_id",
                "expected": "ORD-XXXXX",
                "received": "12345"
            },
            "recoverable": True,
            "timestamp": "2025-12-05T10:30:10Z"
        }


class ToonMetaBuilder:
    """Helper class to build Toon-compliant meta objects."""
    
    @staticmethod
    def build_meta(
        run_id: str,
        agent_id: int,
        seed: int = None,
        session_id: str = None,
        signature: str = "",
        **kwargs
    ) -> Dict[str, Any]:
        """
        Builds a Toon-compliant meta object.
        
        Args:
            run_id: UUID of the run
            agent_id: ID of the agent
            seed: Random seed used (optional)
            session_id: Session identifier (optional)
            signature: HMAC signature
            **kwargs: Additional metadata fields
            
        Returns:
            Dict containing meta information
        """
        meta = {
            "run_id": run_id,
            "agent_id": agent_id,
            "signature": signature
        }
        
        if seed is not None:
            meta["seed"] = seed
        
        if session_id:
            meta["session_id"] = session_id
        
        # Add any additional metadata
        meta.update(kwargs)
        
        return meta


class ToonValidator:
    """Validator for Toon canonical format compliance."""
    
    @staticmethod
    def validate_reasoning_payload(payload: Dict[str, Any]) -> tuple[bool, str]:
        """Validate reasoning payload structure."""
        required_fields = ['goal', 'steps', 'safety_checks', 'uncertainty']
        
        for field in required_fields:
            if field not in payload:
                return False, f"Missing required field: {field}"
        
        if not isinstance(payload['steps'], list):
            return False, "steps must be a list"
        
        if not isinstance(payload['safety_checks'], list):
            return False, "safety_checks must be a list"
        
        if payload['uncertainty'] not in ['low', 'medium', 'high']:
            return False, "uncertainty must be 'low', 'medium', or 'high'"
        
        # Validate step structure
        for step in payload['steps']:
            if 'step_id' not in step or 'description' not in step:
                return False, "Each step must have step_id and description"
        
        return True, "Valid"
    
    @staticmethod
    def validate_action_request_payload(payload: Dict[str, Any]) -> tuple[bool, str]:
        """Validate action_request payload structure."""
        required_fields = ['action', 'params']
        
        for field in required_fields:
            if field not in payload:
                return False, f"Missing required field: {field}"
        
        if not isinstance(payload['params'], dict):
            return False, "params must be a dictionary"
        
        return True, "Valid"
    
    @staticmethod
    def validate_action_response_payload(payload: Dict[str, Any]) -> tuple[bool, str]:
        """Validate action_response payload structure."""
        required_fields = ['status', 'data']
        
        for field in required_fields:
            if field not in payload:
                return False, f"Missing required field: {field}"
        
        if payload['status'] not in ['ok', 'error']:
            return False, "status must be 'ok' or 'error'"
        
        if not isinstance(payload['data'], dict):
            return False, "data must be a dictionary"
        
        return True, "Valid"
    
    @staticmethod
    def validate_final_output_payload(payload: Dict[str, Any]) -> tuple[bool, str]:
        """Validate final_output payload structure."""
        if 'text' not in payload:
            return False, "Missing required field: text"
        
        if not isinstance(payload['text'], str):
            return False, "text must be a string"
        
        return True, "Valid"
    
    @staticmethod
    def validate_payload(payload_type: str, payload: Dict[str, Any]) -> tuple[bool, str]:
        """
        Validate payload based on type.
        
        Args:
            payload_type: Type of payload (reasoning, action_request, etc.)
            payload: The payload dict to validate
            
        Returns:
            Tuple of (is_valid, message)
        """
        validators = {
            'reasoning': ToonValidator.validate_reasoning_payload,
            'action_request': ToonValidator.validate_action_request_payload,
            'action_response': ToonValidator.validate_action_response_payload,
            'final_output': ToonValidator.validate_final_output_payload,
        }
        
        validator = validators.get(payload_type)
        if not validator:
            return True, f"No specific validation for type: {payload_type}"
        
        return validator(payload)


def create_toon_event(
    seq: int,
    timestamp: str,
    actor: str,
    event_type: str,
    payload: Dict[str, Any],
    meta: Dict[str, Any]
) -> Dict[str, Any]:
    """
    Creates a complete Toon-formatted event.
    
    Args:
        seq: Sequence number in run
        timestamp: ISO 8601 timestamp
        actor: Actor type (agent|tool|user|system|redteam)
        event_type: Event type (reasoning|action_request|action_response|final_output|error)
        payload: Event payload
        meta: Metadata including run_id, agent_id, signature, etc.
        
    Returns:
        Complete Toon-formatted event dictionary
    """
    return {
        "seq": seq,
        "t": timestamp,
        "actor": actor,
        "type": event_type,
        "payload": payload,
        "meta": meta
    }


def serialize_toon_event(event: Dict[str, Any]) -> str:
    """
    Serializes a Toon event to JSON string.
    
    Args:
        event: Toon event dictionary
        
    Returns:
        JSON string representation
    """
    return json.dumps(event, indent=2, ensure_ascii=False)


def parse_toon_event(toon_string: str) -> Dict[str, Any]:
    """
    Parses a Toon-formatted JSON string into a dictionary.
    
    Args:
        toon_string: JSON string in Toon format
        
    Returns:
        Parsed event dictionary
        
    Raises:
        json.JSONDecodeError: If string is not valid JSON
    """
    return json.loads(toon_string)
