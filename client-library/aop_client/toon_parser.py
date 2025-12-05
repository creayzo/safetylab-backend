"""
Toon Parser & Serializer

Provides functions to parse and serialize Toon-formatted data.
Toon is a lightweight, machine-parseable format for structured data.
"""

import json
from typing import Any, Dict, List, Union
from datetime import datetime


class ToonParser:
    """
    Parser for Toon canonical format.
    
    Toon format is JSON-based with specific structure requirements
    for trace events, payloads, and metadata.
    """
    
    @staticmethod
    def validate_event_structure(event: Dict[str, Any]) -> bool:
        """
        Validate that an event conforms to Toon canonical structure.
        
        Required fields: seq, t, actor, type, payload, meta
        """
        required_fields = ['seq', 't', 'actor', 'type', 'payload', 'meta']
        return all(field in event for field in required_fields)
    
    @staticmethod
    def validate_meta(meta: Dict[str, Any]) -> bool:
        """Validate meta structure."""
        required_fields = ['run_id', 'agent_id']
        return all(field in meta for field in required_fields)
    
    @staticmethod
    def validate_payload(payload_type: str, payload: Dict[str, Any]) -> tuple[bool, str]:
        """Validate payload based on type."""
        validators = {
            'reasoning': ToonParser._validate_reasoning_payload,
            'action_request': ToonParser._validate_action_request_payload,
            'action_response': ToonParser._validate_action_response_payload,
            'final_output': ToonParser._validate_final_output_payload,
        }
        
        validator = validators.get(payload_type)
        if not validator:
            return True, "No specific validation required"
        
        return validator(payload)
    
    @staticmethod
    def _validate_reasoning_payload(payload: Dict[str, Any]) -> tuple[bool, str]:
        """Validate reasoning payload."""
        required = ['goal', 'steps', 'safety_checks', 'uncertainty']
        for field in required:
            if field not in payload:
                return False, f"Missing required field: {field}"
        
        if payload['uncertainty'] not in ['low', 'medium', 'high']:
            return False, "uncertainty must be low, medium, or high"
        
        return True, "Valid"
    
    @staticmethod
    def _validate_action_request_payload(payload: Dict[str, Any]) -> tuple[bool, str]:
        """Validate action_request payload."""
        required = ['action', 'params']
        for field in required:
            if field not in payload:
                return False, f"Missing required field: {field}"
        return True, "Valid"
    
    @staticmethod
    def _validate_action_response_payload(payload: Dict[str, Any]) -> tuple[bool, str]:
        """Validate action_response payload."""
        required = ['status', 'data']
        for field in required:
            if field not in payload:
                return False, f"Missing required field: {field}"
        
        if payload['status'] not in ['ok', 'error']:
            return False, "status must be ok or error"
        
        return True, "Valid"
    
    @staticmethod
    def _validate_final_output_payload(payload: Dict[str, Any]) -> tuple[bool, str]:
        """Validate final_output payload."""
        if 'text' not in payload:
            return False, "Missing required field: text"
        return True, "Valid"


def parse_toon(toon_string: str) -> Dict[str, Any]:
    """
    Parse a Toon-formatted JSON string into a dictionary.
    
    Args:
        toon_string: JSON string in Toon format
        
    Returns:
        Parsed dictionary
        
    Raises:
        json.JSONDecodeError: If string is not valid JSON
        ValueError: If structure doesn't conform to Toon spec
    
    Example:
        >>> event = parse_toon('{"seq": 1, "t": "2025-12-05T10:00:00Z", ...}')
        >>> print(event['seq'])
        1
    """
    try:
        data = json.loads(toon_string)
    except json.JSONDecodeError as e:
        raise ValueError(f"Invalid JSON: {e}")
    
    # Validate structure if it looks like an event
    if isinstance(data, dict) and 'seq' in data:
        if not ToonParser.validate_event_structure(data):
            raise ValueError("Data does not conform to Toon event structure")
    
    return data


def to_toon(data: Union[Dict, List, Any], pretty: bool = False) -> str:
    """
    Serialize data to Toon-formatted JSON string.
    
    Args:
        data: Data to serialize (dict, list, or primitive)
        pretty: If True, format with indentation for readability
        
    Returns:
        JSON string representation
        
    Example:
        >>> event = {"seq": 1, "t": "2025-12-05T10:00:00Z", "actor": "agent"}
        >>> toon_str = to_toon(event, pretty=True)
        >>> print(toon_str)
        {
          "seq": 1,
          ...
        }
    """
    if pretty:
        return json.dumps(data, indent=2, ensure_ascii=False, default=_json_serializer)
    return json.dumps(data, ensure_ascii=False, default=_json_serializer)


def _json_serializer(obj: Any) -> str:
    """Custom JSON serializer for non-standard types."""
    if isinstance(obj, datetime):
        return obj.isoformat()
    raise TypeError(f"Object of type {type(obj).__name__} is not JSON serializable")


class ToonBuilder:
    """Helper class to build Toon-compliant structures."""
    
    @staticmethod
    def build_reasoning_payload(
        goal: str,
        steps: List[Dict[str, Any]],
        safety_checks: List[Dict[str, str]],
        uncertainty: str = "medium"
    ) -> Dict[str, Any]:
        """Build a reasoning payload."""
        if uncertainty not in ['low', 'medium', 'high']:
            raise ValueError("uncertainty must be low, medium, or high")
        
        return {
            "goal": goal,
            "steps": steps,
            "safety_checks": safety_checks,
            "uncertainty": uncertainty
        }
    
    @staticmethod
    def build_action_request_payload(
        action: str,
        params: Dict[str, Any],
        context: Dict[str, Any] = None
    ) -> Dict[str, Any]:
        """Build an action_request payload."""
        payload = {
            "action": action,
            "params": params
        }
        if context:
            payload["context"] = context
        return payload
    
    @staticmethod
    def build_action_response_payload(
        status: str,
        data: Dict[str, Any],
        meta: Dict[str, Any] = None
    ) -> Dict[str, Any]:
        """Build an action_response payload."""
        if status not in ['ok', 'error']:
            raise ValueError("status must be ok or error")
        
        payload = {
            "status": status,
            "data": data
        }
        if meta:
            payload["meta"] = meta
        return payload
    
    @staticmethod
    def build_final_output_payload(
        text: str,
        structured: Dict[str, Any] = None
    ) -> Dict[str, Any]:
        """Build a final_output payload."""
        payload = {"text": text}
        if structured:
            payload["structured"] = structured
        return payload
    
    @staticmethod
    def build_error_payload(
        error_type: str,
        message: str,
        code: str,
        details: Dict[str, Any] = None,
        recoverable: bool = True
    ) -> Dict[str, Any]:
        """Build an error payload."""
        payload = {
            "error_type": error_type,
            "message": message,
            "code": code,
            "recoverable": recoverable,
            "timestamp": datetime.utcnow().isoformat() + 'Z'
        }
        if details:
            payload["details"] = details
        return payload
