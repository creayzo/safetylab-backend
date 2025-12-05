"""
Trace Builder - Helper to create TraceEvent structures

Manages trace event creation with automatic sequence numbering,
timestamp generation, and metadata attachment.
"""

import uuid
from typing import Any, Dict, Optional, List
from datetime import datetime, timezone
from dataclasses import dataclass, field, asdict
import json


@dataclass
class TraceEvent:
    """
    Represents a single trace event in Toon canonical format.
    
    Attributes:
        seq: Sequence number in the run
        timestamp: ISO 8601 timestamp
        actor: Actor type (agent, tool, user, system, redteam)
        type: Event type (reasoning, action_request, etc.)
        payload: Event payload (dict)
        meta: Metadata including run_id, agent_id, signature
    """
    seq: int
    timestamp: str
    actor: str
    type: str
    payload: Dict[str, Any]
    meta: Dict[str, Any]
    signature: str = ""
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "seq": self.seq,
            "t": self.timestamp,
            "actor": self.actor,
            "type": self.type,
            "payload": self.payload,
            "meta": self.meta
        }
    
    def to_json(self, pretty: bool = False) -> str:
        """Convert to JSON string."""
        if pretty:
            return json.dumps(self.to_dict(), indent=2, ensure_ascii=False)
        return json.dumps(self.to_dict(), ensure_ascii=False)


class TraceBuilder:
    """
    Builder class for creating trace events with automatic sequence management.
    
    Usage:
        builder = TraceBuilder(run_id=str(uuid.uuid4()), agent_id=123, seed=42)
        
        # Create reasoning event
        event = builder.create_reasoning(
            goal="Process refund request",
            steps=[...],
            safety_checks=[...]
        )
        
        # Create action request
        event = builder.create_action_request(
            action="create_ticket",
            params={"order_id": "123"}
        )
    """
    
    def __init__(
        self,
        run_id: str,
        agent_id: int,
        seed: Optional[int] = None,
        session_id: Optional[str] = None,
        initial_seq: int = 1
    ):
        """
        Initialize trace builder.
        
        Args:
            run_id: UUID of the run
            agent_id: ID of the agent
            seed: Random seed for reproducibility
            session_id: Session identifier
            initial_seq: Starting sequence number (default: 1)
        """
        self.run_id = run_id
        self.agent_id = agent_id
        self.seed = seed
        self.session_id = session_id
        self._current_seq = initial_seq
        self._events: List[TraceEvent] = []
    
    def _get_next_seq(self) -> int:
        """Get next sequence number and increment."""
        seq = self._current_seq
        self._current_seq += 1
        return seq
    
    def _build_meta(self, **extra) -> Dict[str, Any]:
        """Build meta object with standard fields."""
        meta = {
            "run_id": self.run_id,
            "agent_id": self.agent_id,
        }
        
        if self.seed is not None:
            meta["seed"] = self.seed
        
        if self.session_id:
            meta["session_id"] = self.session_id
        
        # Add any extra meta fields
        meta.update(extra)
        
        return meta
    
    def _create_event(
        self,
        actor: str,
        event_type: str,
        payload: Dict[str, Any],
        **meta_extra
    ) -> TraceEvent:
        """
        Create a trace event.
        
        Args:
            actor: Actor type
            event_type: Event type
            payload: Event payload
            **meta_extra: Additional metadata fields
        
        Returns:
            TraceEvent instance
        """
        event = TraceEvent(
            seq=self._get_next_seq(),
            timestamp=datetime.now(timezone.utc).isoformat(),
            actor=actor,
            type=event_type,
            payload=payload,
            meta=self._build_meta(**meta_extra)
        )
        
        self._events.append(event)
        return event
    
    def create_reasoning(
        self,
        goal: str,
        steps: List[Dict[str, Any]],
        safety_checks: List[Dict[str, str]],
        uncertainty: str = "medium",
        actor: str = "agent",
        **meta_extra
    ) -> TraceEvent:
        """
        Create a reasoning event.
        
        Args:
            goal: High-level goal or objective
            steps: List of reasoning steps
            safety_checks: List of safety/policy checks
            uncertainty: Uncertainty level (low, medium, high)
            actor: Actor performing reasoning (default: agent)
            **meta_extra: Additional metadata
        
        Returns:
            TraceEvent instance
        """
        payload = {
            "goal": goal,
            "steps": steps,
            "safety_checks": safety_checks,
            "uncertainty": uncertainty
        }
        
        return self._create_event(actor, "reasoning", payload, **meta_extra)
    
    def create_action_request(
        self,
        action: str,
        params: Dict[str, Any],
        context: Optional[Dict[str, Any]] = None,
        actor: str = "agent",
        **meta_extra
    ) -> TraceEvent:
        """
        Create an action request event.
        
        Args:
            action: Action/tool name to execute
            params: Action parameters
            context: Optional context information
            actor: Actor requesting action (default: agent)
            **meta_extra: Additional metadata
        
        Returns:
            TraceEvent instance
        """
        payload = {
            "action": action,
            "params": params
        }
        
        if context:
            payload["context"] = context
        
        return self._create_event(actor, "action_request", payload, **meta_extra)
    
    def create_action_response(
        self,
        status: str,
        data: Dict[str, Any],
        latency_ms: Optional[int] = None,
        policy_flags: Optional[List[str]] = None,
        actor: str = "tool",
        **meta_extra
    ) -> TraceEvent:
        """
        Create an action response event.
        
        Args:
            status: Response status (ok or error)
            data: Response data
            latency_ms: Response latency in milliseconds
            policy_flags: Policy flags raised during execution
            actor: Actor responding (default: tool)
            **meta_extra: Additional metadata
        
        Returns:
            TraceEvent instance
        """
        payload = {
            "status": status,
            "data": data,
            "meta": {}
        }
        
        if latency_ms is not None:
            payload["meta"]["latency_ms"] = latency_ms
        
        if policy_flags is not None:
            payload["meta"]["policy_flags"] = policy_flags
        
        return self._create_event(actor, "action_response", payload, **meta_extra)
    
    def create_final_output(
        self,
        text: str,
        structured: Optional[Dict[str, Any]] = None,
        actor: str = "agent",
        **meta_extra
    ) -> TraceEvent:
        """
        Create a final output event.
        
        Args:
            text: Human-readable output text
            structured: Optional structured result
            actor: Actor producing output (default: agent)
            **meta_extra: Additional metadata
        
        Returns:
            TraceEvent instance
        """
        payload = {"text": text}
        
        if structured:
            payload["structured"] = structured
        
        return self._create_event(actor, "final_output", payload, **meta_extra)
    
    def create_error(
        self,
        error_type: str,
        message: str,
        code: str,
        details: Optional[Dict[str, Any]] = None,
        recoverable: bool = True,
        actor: str = "system",
        **meta_extra
    ) -> TraceEvent:
        """
        Create an error event.
        
        Args:
            error_type: Error type/class
            message: Error message
            code: Error code
            details: Additional error details
            recoverable: Whether error is recoverable
            actor: Actor reporting error (default: system)
            **meta_extra: Additional metadata
        
        Returns:
            TraceEvent instance
        """
        payload = {
            "error_type": error_type,
            "message": message,
            "code": code,
            "recoverable": recoverable,
            "timestamp": datetime.now(timezone.utc).isoformat()
        }
        
        if details:
            payload["details"] = details
        
        return self._create_event(actor, "error", payload, **meta_extra)
    
    def create_custom(
        self,
        actor: str,
        event_type: str,
        payload: Dict[str, Any],
        **meta_extra
    ) -> TraceEvent:
        """
        Create a custom event with arbitrary payload.
        
        Args:
            actor: Actor type
            event_type: Event type
            payload: Event payload
            **meta_extra: Additional metadata
        
        Returns:
            TraceEvent instance
        """
        return self._create_event(actor, event_type, payload, **meta_extra)
    
    def get_events(self) -> List[TraceEvent]:
        """Get all events created by this builder."""
        return self._events.copy()
    
    def get_event_count(self) -> int:
        """Get number of events created."""
        return len(self._events)
    
    def reset(self, keep_sequence: bool = False):
        """
        Reset the builder state.
        
        Args:
            keep_sequence: If True, keep current sequence number
        """
        self._events.clear()
        if not keep_sequence:
            self._current_seq = 1
    
    def export_trace(self) -> List[Dict[str, Any]]:
        """
        Export all events as a list of dictionaries.
        
        Returns:
            List of event dictionaries
        """
        return [event.to_dict() for event in self._events]
    
    def export_trace_json(self, pretty: bool = False) -> str:
        """
        Export all events as JSON string.
        
        Args:
            pretty: If True, format with indentation
        
        Returns:
            JSON string
        """
        trace = self.export_trace()
        if pretty:
            return json.dumps(trace, indent=2, ensure_ascii=False)
        return json.dumps(trace, ensure_ascii=False)
