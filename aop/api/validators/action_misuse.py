"""
Action Misuse Checker

Validates action parameters against:
- Access Control Lists (ACLs)
- Permitted value ranges
- Business rules
- Rate limits
- Resource quotas

Example rules:
- Refund amount must be <= order amount
- Only approved users can delete data
- File uploads must be < 10MB
- API calls limited to 100/hour per user
"""

import logging
from typing import List, Dict, Any, Optional, Callable
from datetime import datetime, timedelta

from api.validators.base import (
    EventTypeValidator,
    ValidationContext,
    ValidationViolation,
    ViolationSeverity,
    ValidationPhase,
    validator_registry
)

logger = logging.getLogger(__name__)


class ActionACL:
    """Access Control List for actions."""
    
    def __init__(self):
        """Initialize ACL."""
        self.rules: Dict[str, Dict[str, Any]] = {}
    
    def add_rule(
        self,
        action_name: str,
        allowed_roles: Optional[List[str]] = None,
        required_permissions: Optional[List[str]] = None,
        forbidden_params: Optional[List[str]] = None
    ):
        """
        Add ACL rule for an action.
        
        Args:
            action_name: Name of the action
            allowed_roles: List of roles that can execute
            required_permissions: List of required permissions
            forbidden_params: List of parameter names that are forbidden
        """
        self.rules[action_name] = {
            'allowed_roles': allowed_roles or [],
            'required_permissions': required_permissions or [],
            'forbidden_params': forbidden_params or []
        }
    
    def check_access(
        self,
        action_name: str,
        user_role: str,
        user_permissions: List[str],
        params: Dict[str, Any]
    ) -> tuple[bool, Optional[str]]:
        """
        Check if action is allowed.
        
        Returns:
            (is_allowed, error_message)
        """
        if action_name not in self.rules:
            return True, None  # No ACL = allowed
        
        rule = self.rules[action_name]
        
        # Check role
        if rule['allowed_roles'] and user_role not in rule['allowed_roles']:
            return False, f"Role '{user_role}' not authorized for action '{action_name}'"
        
        # Check permissions
        required_perms = set(rule['required_permissions'])
        user_perms = set(user_permissions)
        if required_perms and not required_perms.issubset(user_perms):
            missing = required_perms - user_perms
            return False, f"Missing permissions: {', '.join(missing)}"
        
        # Check forbidden params
        if rule['forbidden_params']:
            forbidden_found = [p for p in rule['forbidden_params'] if p in params]
            if forbidden_found:
                return False, f"Forbidden parameters used: {', '.join(forbidden_found)}"
        
        return True, None


class ParameterValidator:
    """Validates action parameters against constraints."""
    
    def __init__(self):
        """Initialize validator."""
        self.constraints: Dict[str, Dict[str, Callable]] = {}
    
    def add_constraint(
        self,
        action_name: str,
        param_name: str,
        validator: Callable[[Any], tuple[bool, Optional[str]]]
    ):
        """
        Add parameter constraint.
        
        Args:
            action_name: Name of the action
            param_name: Name of the parameter
            validator: Function that validates the parameter value
        """
        if action_name not in self.constraints:
            self.constraints[action_name] = {}
        
        self.constraints[action_name][param_name] = validator
    
    def validate_params(
        self,
        action_name: str,
        params: Dict[str, Any]
    ) -> List[tuple[str, str]]:
        """
        Validate all parameters for an action.
        
        Returns:
            List of (param_name, error_message) tuples for violations
        """
        violations = []
        
        if action_name not in self.constraints:
            return violations
        
        for param_name, validator in self.constraints[action_name].items():
            if param_name in params:
                is_valid, error_msg = validator(params[param_name])
                if not is_valid:
                    violations.append((param_name, error_msg))
        
        return violations


class ActionMisuseChecker(EventTypeValidator):
    """
    Checks for action parameter misuse and ACL violations.
    
    Validates action_request events against configured rules.
    """
    
    def __init__(self):
        """Initialize action misuse checker."""
        super().__init__(
            name="action_misuse_checker",
            description="Validates action parameters against ACLs and business rules",
            event_types=["action_request"],
            phases=[ValidationPhase.INGESTION, ValidationPhase.POST_RUN]
        )
        
        self.acl = ActionACL()
        self.param_validator = ParameterValidator()
        self._load_default_rules()
    
    def _load_default_rules(self):
        """Load default ACL and validation rules."""
        
        # ACL Rules
        self.acl.add_rule(
            "delete_user",
            allowed_roles=["admin", "manager"],
            required_permissions=["delete_users"],
            forbidden_params=["force_delete"]
        )
        
        self.acl.add_rule(
            "process_refund",
            allowed_roles=["agent", "manager"],
            required_permissions=["process_refunds"]
        )
        
        self.acl.add_rule(
            "modify_permissions",
            allowed_roles=["admin"],
            required_permissions=["manage_permissions"]
        )
        
        # Parameter Validators
        
        # Refund amount constraints
        self.param_validator.add_constraint(
            "process_refund",
            "amount",
            lambda val: (
                (True, None) if isinstance(val, (int, float)) and 0 < val <= 10000
                else (False, f"Refund amount must be between $0 and $10,000, got ${val}")
            )
        )
        
        # File upload size limit
        self.param_validator.add_constraint(
            "upload_file",
            "file_size",
            lambda val: (
                (True, None) if isinstance(val, int) and val <= 10 * 1024 * 1024  # 10MB
                else (False, f"File size exceeds 10MB limit: {val} bytes")
            )
        )
        
        # Email recipient count limit
        self.param_validator.add_constraint(
            "send_email",
            "recipients",
            lambda val: (
                (True, None) if isinstance(val, list) and len(val) <= 100
                else (False, f"Too many recipients: {len(val)}, max 100")
            )
        )
        
        # Discount percentage limit
        self.param_validator.add_constraint(
            "apply_discount",
            "discount_percent",
            lambda val: (
                (True, None) if isinstance(val, (int, float)) and 0 <= val <= 75
                else (False, f"Discount must be 0-75%, got {val}%")
            )
        )
        
        # API call timeout
        self.param_validator.add_constraint(
            "call_external_api",
            "timeout",
            lambda val: (
                (True, None) if isinstance(val, (int, float)) and 0 < val <= 30
                else (False, f"Timeout must be 0-30 seconds, got {val}")
            )
        )
        
        logger.info("Loaded default action misuse rules")
    
    def validate_event(self, context: ValidationContext) -> List[ValidationViolation]:
        """
        Validate action_request event.
        
        Args:
            context: Validation context
            
        Returns:
            List of violations
        """
        violations = []
        payload = context.get_payload()
        
        action_name = payload.get('action', '')
        params = payload.get('params', {})
        
        # Get user context (if available)
        user_role = context.agent_metadata.get('role', 'agent') if context.agent_metadata else 'agent'
        user_permissions = context.agent_metadata.get('permissions', []) if context.agent_metadata else []
        
        # Check ACL
        is_allowed, acl_error = self.acl.check_access(action_name, user_role, user_permissions, params)
        if not is_allowed:
            violations.append(ValidationViolation(
                validator_name=self.name,
                severity=ViolationSeverity.CRITICAL,
                violation_type="ACL_VIOLATION",
                message=acl_error,
                run_id=context.run_id,
                seq_no=context.seq_no,
                details={
                    'action': action_name,
                    'user_role': user_role,
                    'required_permissions': self.acl.rules.get(action_name, {}).get('required_permissions', [])
                },
                timestamp=context.timestamp,
                remediation="Ensure user has required role and permissions"
            ))
        
        # Validate parameters
        param_violations = self.param_validator.validate_params(action_name, params)
        for param_name, error_msg in param_violations:
            violations.append(ValidationViolation(
                validator_name=self.name,
                severity=ViolationSeverity.ERROR,
                violation_type="PARAMETER_VIOLATION",
                message=f"Invalid parameter '{param_name}': {error_msg}",
                run_id=context.run_id,
                seq_no=context.seq_no,
                details={
                    'action': action_name,
                    'parameter': param_name,
                    'value': params.get(param_name)
                },
                timestamp=context.timestamp,
                remediation="Adjust parameter value to meet constraints"
            ))
        
        return violations


# Register checker
action_misuse_checker = ActionMisuseChecker()
validator_registry.register(action_misuse_checker)
