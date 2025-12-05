"""
Base Validator Framework

Pluggable validation system for trace events with support for:
- Ingestion-time validation (sync, fast)
- Post-run evaluation (async, comprehensive)
- Custom enterprise validators
- Violation tracking and reporting

Validators can inspect:
- Event payloads (reasoning, action_request, action_response, final_output)
- Sequences of events (temporal patterns)
- Run metadata
- Cross-event relationships

Example Usage:
    # Register validator
    validator_registry.register(MyCustomValidator())
    
    # Run at ingestion time
    violations = validator_registry.validate_event(event, context)
    
    # Run post-run analysis
    report = validator_registry.evaluate_run(run_id)
"""

import logging
from abc import ABC, abstractmethod
from typing import List, Dict, Any, Optional, Union
from dataclasses import dataclass
from datetime import datetime
from enum import Enum

logger = logging.getLogger(__name__)


class ViolationSeverity(Enum):
    """Severity levels for violations."""
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"
    CRITICAL = "critical"


class ValidationPhase(Enum):
    """When validation runs."""
    INGESTION = "ingestion"  # Real-time during event submission
    POST_RUN = "post_run"    # After run completes
    BATCH = "batch"          # Scheduled batch analysis


@dataclass
class ValidationViolation:
    """
    Represents a detected violation.
    
    Violations are stored in the database and can be queried
    for compliance reports, dashboards, and alerting.
    """
    validator_name: str
    severity: ViolationSeverity
    violation_type: str
    message: str
    event_id: Optional[str] = None
    run_id: Optional[str] = None
    seq_no: Optional[int] = None
    details: Optional[Dict[str, Any]] = None
    timestamp: Optional[datetime] = None
    remediation: Optional[str] = None  # Suggested fix
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            'validator_name': self.validator_name,
            'severity': self.severity.value,
            'violation_type': self.violation_type,
            'message': self.message,
            'event_id': self.event_id,
            'run_id': self.run_id,
            'seq_no': self.seq_no,
            'details': self.details,
            'timestamp': self.timestamp.isoformat() if self.timestamp else None,
            'remediation': self.remediation
        }


@dataclass
class ValidationContext:
    """
    Context provided to validators during validation.
    
    Contains current event, run metadata, and history.
    """
    event: Dict[str, Any]
    run_id: str
    agent_id: int
    seq_no: int
    event_type: str
    timestamp: datetime
    
    # Optional context
    previous_events: Optional[List[Dict[str, Any]]] = None
    run_metadata: Optional[Dict[str, Any]] = None
    agent_metadata: Optional[Dict[str, Any]] = None
    
    def get_payload(self) -> Dict[str, Any]:
        """Get event payload."""
        return self.event.get('payload', {})
    
    def get_actor(self) -> str:
        """Get event actor."""
        return self.event.get('actor', 'unknown')


class BaseValidator(ABC):
    """
    Abstract base class for all validators.
    
    Subclass and implement validate() to create custom validators.
    Validators can run at ingestion time (fast) or post-run (comprehensive).
    """
    
    def __init__(
        self,
        name: str,
        description: str,
        phases: List[ValidationPhase],
        enabled: bool = True
    ):
        """
        Initialize validator.
        
        Args:
            name: Unique validator name
            description: Human-readable description
            phases: When this validator runs
            enabled: Whether validator is active
        """
        self.name = name
        self.description = description
        self.phases = phases
        self.enabled = enabled
        self.violation_count = 0
    
    @abstractmethod
    def validate(self, context: ValidationContext) -> List[ValidationViolation]:
        """
        Validate an event or sequence of events.
        
        Args:
            context: Validation context with event and history
            
        Returns:
            List of violations found (empty if valid)
        """
        pass
    
    def can_run_at_phase(self, phase: ValidationPhase) -> bool:
        """Check if validator runs in given phase."""
        return phase in self.phases
    
    def is_enabled(self) -> bool:
        """Check if validator is enabled."""
        return self.enabled
    
    def enable(self):
        """Enable validator."""
        self.enabled = True
    
    def disable(self):
        """Disable validator."""
        self.enabled = False
    
    def log_violation(self, violation: ValidationViolation):
        """Log violation for debugging."""
        self.violation_count += 1
        logger.warning(
            f"[{self.name}] {violation.severity.value.upper()}: {violation.message}"
        )


class EventTypeValidator(BaseValidator):
    """
    Validator that only runs for specific event types.
    
    Useful for validators that only make sense for certain events
    (e.g., action misuse only for action_request events).
    """
    
    def __init__(
        self,
        name: str,
        description: str,
        event_types: List[str],
        phases: List[ValidationPhase],
        enabled: bool = True
    ):
        """
        Initialize event-type-specific validator.
        
        Args:
            event_types: List of event types this validator handles
                        (reasoning, action_request, action_response, final_output, error)
        """
        super().__init__(name, description, phases, enabled)
        self.event_types = event_types
    
    def should_validate(self, context: ValidationContext) -> bool:
        """Check if validator should run for this event."""
        return context.event_type in self.event_types
    
    def validate(self, context: ValidationContext) -> List[ValidationViolation]:
        """Validate only if event type matches."""
        if not self.should_validate(context):
            return []
        return self.validate_event(context)
    
    @abstractmethod
    def validate_event(self, context: ValidationContext) -> List[ValidationViolation]:
        """
        Validate event (called only for matching event types).
        
        Subclass should implement this instead of validate().
        """
        pass


class ValidatorRegistry:
    """
    Central registry for all validators.
    
    Manages validator lifecycle, execution, and results.
    Enterprise customers can register custom validators here.
    """
    
    def __init__(self):
        """Initialize empty registry."""
        self._validators: Dict[str, BaseValidator] = {}
        self._validators_by_phase: Dict[ValidationPhase, List[BaseValidator]] = {
            phase: [] for phase in ValidationPhase
        }
    
    def register(self, validator: BaseValidator):
        """
        Register a validator.
        
        Args:
            validator: Validator instance to register
            
        Raises:
            ValueError: If validator with same name already registered
        """
        if validator.name in self._validators:
            raise ValueError(f"Validator '{validator.name}' already registered")
        
        self._validators[validator.name] = validator
        
        # Index by phase
        for phase in validator.phases:
            self._validators_by_phase[phase].append(validator)
        
        logger.info(f"Registered validator: {validator.name}")
    
    def unregister(self, validator_name: str):
        """
        Unregister a validator.
        
        Args:
            validator_name: Name of validator to remove
        """
        if validator_name not in self._validators:
            logger.warning(f"Validator '{validator_name}' not found")
            return
        
        validator = self._validators[validator_name]
        
        # Remove from phase indexes
        for phase in validator.phases:
            self._validators_by_phase[phase].remove(validator)
        
        del self._validators[validator_name]
        logger.info(f"Unregistered validator: {validator_name}")
    
    def get_validator(self, name: str) -> Optional[BaseValidator]:
        """Get validator by name."""
        return self._validators.get(name)
    
    def list_validators(self, phase: Optional[ValidationPhase] = None) -> List[BaseValidator]:
        """
        List all validators, optionally filtered by phase.
        
        Args:
            phase: Optional phase to filter by
            
        Returns:
            List of validators
        """
        if phase:
            return self._validators_by_phase.get(phase, [])
        return list(self._validators.values())
    
    def validate_event(
        self,
        context: ValidationContext,
        phase: ValidationPhase = ValidationPhase.INGESTION
    ) -> List[ValidationViolation]:
        """
        Run all validators for an event at given phase.
        
        Args:
            context: Validation context
            phase: Validation phase
            
        Returns:
            List of all violations found
        """
        violations = []
        
        validators = self._validators_by_phase.get(phase, [])
        
        for validator in validators:
            if not validator.is_enabled():
                continue
            
            try:
                validator_violations = validator.validate(context)
                for violation in validator_violations:
                    validator.log_violation(violation)
                violations.extend(validator_violations)
            except Exception as e:
                logger.error(f"Validator {validator.name} failed: {e}", exc_info=True)
                # Continue with other validators
        
        return violations
    
    def evaluate_run(
        self,
        run_id: str,
        events: List[Dict[str, Any]],
        metadata: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Run post-run evaluation on completed run.
        
        Args:
            run_id: Run UUID
            events: All events in the run
            metadata: Run metadata
            
        Returns:
            Evaluation report with violations by validator
        """
        all_violations = []
        validator_results = {}
        
        validators = self._validators_by_phase.get(ValidationPhase.POST_RUN, [])
        
        for validator in validators:
            if not validator.is_enabled():
                continue
            
            violations = []
            
            try:
                # Run validator on each event
                for event in events:
                    context = ValidationContext(
                        event=event,
                        run_id=run_id,
                        agent_id=event.get('meta', {}).get('agent_id', 0),
                        seq_no=event.get('seq', 0),
                        event_type=event.get('type', ''),
                        timestamp=datetime.fromisoformat(event.get('t', '')),
                        previous_events=events[:event.get('seq', 0) - 1] if event.get('seq', 0) > 1 else None,
                        run_metadata=metadata
                    )
                    
                    validator_violations = validator.validate(context)
                    violations.extend(validator_violations)
                
                validator_results[validator.name] = {
                    'violations': [v.to_dict() for v in violations],
                    'count': len(violations),
                    'severities': self._count_severities(violations)
                }
                
                all_violations.extend(violations)
                
            except Exception as e:
                logger.error(f"Post-run validator {validator.name} failed: {e}", exc_info=True)
                validator_results[validator.name] = {
                    'error': str(e),
                    'count': 0
                }
        
        return {
            'run_id': run_id,
            'total_violations': len(all_violations),
            'severities': self._count_severities(all_violations),
            'validators': validator_results,
            'timestamp': datetime.utcnow().isoformat()
        }
    
    def _count_severities(self, violations: List[ValidationViolation]) -> Dict[str, int]:
        """Count violations by severity."""
        counts = {severity.value: 0 for severity in ViolationSeverity}
        for violation in violations:
            counts[violation.severity.value] += 1
        return counts
    
    def get_stats(self) -> Dict[str, Any]:
        """Get registry statistics."""
        return {
            'total_validators': len(self._validators),
            'enabled_validators': sum(1 for v in self._validators.values() if v.enabled),
            'disabled_validators': sum(1 for v in self._validators.values() if not v.enabled),
            'by_phase': {
                phase.value: len(validators)
                for phase, validators in self._validators_by_phase.items()
            },
            'total_violations': sum(v.violation_count for v in self._validators.values())
        }


# Global validator registry
validator_registry = ValidatorRegistry()


# Decorator for easy validator registration
def register_validator(
    name: str,
    description: str,
    phases: List[ValidationPhase],
    event_types: Optional[List[str]] = None
):
    """
    Decorator to register a validator class.
    
    Usage:
        @register_validator(
            name="my_validator",
            description="Checks my rules",
            phases=[ValidationPhase.INGESTION]
        )
        class MyValidator(BaseValidator):
            def validate(self, context):
                ...
    """
    def decorator(cls):
        if event_types:
            # Create EventTypeValidator wrapper
            class WrappedValidator(EventTypeValidator):
                def __init__(self):
                    super().__init__(name, description, event_types, phases)
                    self._impl = cls()
                
                def validate_event(self, context):
                    return self._impl.validate(context)
            
            validator_registry.register(WrappedValidator())
        else:
            validator_registry.register(cls(name, description, phases))
        
        return cls
    
    return decorator
