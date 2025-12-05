"""
Policy validator module - wrapper around PolicyChecker for compatibility.
"""

from typing import Dict, Any, List, Optional
from api.validators.policy_checker import PolicyChecker
from api.validators.base import ValidationViolation, ValidationContext


class PolicyValidator:
    """
    Policy validator wrapper for evaluating events against organizational policies.
    
    This is a wrapper around PolicyChecker to provide a simplified interface
    for use in evaluation pipelines.
    """
    
    def __init__(self, organization=None):
        """
        Initialize policy validator.
        
        Args:
            organization: Organization instance (optional)
        """
        self.organization = organization
        self.policy_checker = PolicyChecker()
    
    def validate(self, payload: Dict[str, Any], event=None, context: Optional[ValidationContext] = None) -> List[ValidationViolation]:
        """
        Validate an event payload against policies.
        
        Args:
            payload: Event payload data
            event: TraceEvent instance (optional)
            context: ValidationContext (optional)
            
        Returns:
            List of policy violations (empty if no violations)
        """
        # If context is not provided, create one
        if context is None and event is not None:
            context = ValidationContext(
                event_type=event.type if hasattr(event, 'type') else 'unknown',
                seq_no=event.seq_no if hasattr(event, 'seq_no') else 0,
                timestamp=event.timestamp if hasattr(event, 'timestamp') else None,
                payload=payload,
                metadata={}
            )
        elif context is None:
            # Create minimal context
            from django.utils import timezone
            context = ValidationContext(
                event_type='action_request',
                seq_no=0,
                timestamp=timezone.now(),
                payload=payload,
                metadata={}
            )
        
        # Use policy checker to validate
        violations = self.policy_checker.validate(context)
        return violations
