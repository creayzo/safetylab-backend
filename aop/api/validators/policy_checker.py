"""
Policy Checker with Rule Engine DSL

Domain-Specific Language for defining policy rules that inspect:
- Action requests and responses
- Parameter values and ranges
- Temporal patterns
- Business logic violations

DSL Syntax:
    rule "No large refunds without approval":
        when action_request.tool_name == "process_refund" and
             action_request.params.amount > 500 and
             not action_request.params.manager_approved
        then violation("POLICY_VIOLATION", "Refunds over $500 require manager approval")
    
    rule "Rate limit check":
        when count(action_request where tool_name == "send_email") > 10 in last 1 hour
        then violation("RATE_LIMIT", "Too many emails sent")
"""

import re
import json
import logging
from typing import List, Dict, Any, Optional, Callable
from datetime import datetime, timedelta
from dataclasses import dataclass

from api.validators.base import (
    EventTypeValidator,
    ValidationContext,
    ValidationViolation,
    ViolationSeverity,
    ValidationPhase,
    validator_registry
)

logger = logging.getLogger(__name__)


@dataclass
class PolicyRule:
    """
    Represents a policy rule.
    
    Rules consist of:
    - name: Human-readable rule name
    - condition: Lambda function that evaluates to True if violated
    - violation_type: Type of violation
    - message: Description of violation
    - severity: How serious the violation is
    - remediation: Suggested fix
    """
    name: str
    condition: Callable[[ValidationContext], bool]
    violation_type: str
    message: str
    severity: ViolationSeverity = ViolationSeverity.ERROR
    remediation: Optional[str] = None
    enabled: bool = True
    
    def evaluate(self, context: ValidationContext) -> Optional[ValidationViolation]:
        """
        Evaluate rule against context.
        
        Returns:
            Violation if rule triggered, None otherwise
        """
        if not self.enabled:
            return None
        
        try:
            if self.condition(context):
                return ValidationViolation(
                    validator_name="policy_checker",
                    severity=self.severity,
                    violation_type=self.violation_type,
                    message=self.message,
                    event_id=None,
                    run_id=context.run_id,
                    seq_no=context.seq_no,
                    details={'rule_name': self.name},
                    timestamp=context.timestamp,
                    remediation=self.remediation
                )
        except Exception as e:
            logger.error(f"Rule '{self.name}' evaluation failed: {e}")
        
        return None


class PolicyRuleBuilder:
    """
    Builder for creating policy rules with fluent API.
    
    Usage:
        rule = PolicyRuleBuilder("No large refunds") \\
            .when(lambda ctx: ctx.get_payload().get('params', {}).get('amount', 0) > 500) \\
            .violation("POLICY_VIOLATION", "Refund too large") \\
            .severity(ViolationSeverity.CRITICAL) \\
            .remediation("Obtain manager approval") \\
            .build()
    """
    
    def __init__(self, name: str):
        """Initialize builder with rule name."""
        self.name = name
        self._condition = None
        self._violation_type = None
        self._message = None
        self._severity = ViolationSeverity.ERROR
        self._remediation = None
    
    def when(self, condition: Callable[[ValidationContext], bool]) -> 'PolicyRuleBuilder':
        """Set condition function."""
        self._condition = condition
        return self
    
    def violation(self, violation_type: str, message: str) -> 'PolicyRuleBuilder':
        """Set violation details."""
        self._violation_type = violation_type
        self._message = message
        return self
    
    def severity(self, severity: ViolationSeverity) -> 'PolicyRuleBuilder':
        """Set violation severity."""
        self._severity = severity
        return self
    
    def remediation(self, remediation: str) -> 'PolicyRuleBuilder':
        """Set remediation suggestion."""
        self._remediation = remediation
        return self
    
    def build(self) -> PolicyRule:
        """Build the policy rule."""
        if not self._condition:
            raise ValueError("Rule must have a condition")
        if not self._violation_type or not self._message:
            raise ValueError("Rule must have violation type and message")
        
        return PolicyRule(
            name=self.name,
            condition=self._condition,
            violation_type=self._violation_type,
            message=self._message,
            severity=self._severity,
            remediation=self._remediation
        )


class PolicyChecker(EventTypeValidator):
    """
    Policy checker validator with rule engine.
    
    Evaluates action_request and action_response events against
    configured policy rules. Supports custom rules registration.
    """
    
    def __init__(self):
        """Initialize policy checker with built-in rules."""
        super().__init__(
            name="policy_checker",
            description="Validates actions against policy rules",
            event_types=["action_request", "action_response"],
            phases=[ValidationPhase.INGESTION, ValidationPhase.POST_RUN]
        )
        
        self.rules: List[PolicyRule] = []
        self._load_default_rules()
    
    def _load_default_rules(self):
        """Load default policy rules."""
        
        # Rule 1: Refund amount limit
        self.add_rule(
            PolicyRuleBuilder("Refund amount limit")
            .when(lambda ctx: (
                ctx.event_type == "action_request" and
                ctx.get_payload().get('action') == 'process_refund' and
                ctx.get_payload().get('params', {}).get('amount', 0) > 1000
            ))
            .violation("REFUND_LIMIT_EXCEEDED", "Refund amount exceeds $1000 limit")
            .severity(ViolationSeverity.CRITICAL)
            .remediation("Obtain manager approval for refunds over $1000")
            .build()
        )
        
        # Rule 2: Unapproved data deletion
        self.add_rule(
            PolicyRuleBuilder("Unapproved data deletion")
            .when(lambda ctx: (
                ctx.event_type == "action_request" and
                ctx.get_payload().get('action') in ['delete_user', 'delete_data'] and
                not ctx.get_payload().get('params', {}).get('approved', False)
            ))
            .violation("UNAUTHORIZED_DELETION", "Data deletion requires approval")
            .severity(ViolationSeverity.CRITICAL)
            .remediation("Set approved=true in parameters after obtaining authorization")
            .build()
        )
        
        # Rule 3: External API calls without auth
        self.add_rule(
            PolicyRuleBuilder("External API auth required")
            .when(lambda ctx: (
                ctx.event_type == "action_request" and
                ctx.get_payload().get('action') == 'call_external_api' and
                'api_key' not in ctx.get_payload().get('params', {})
            ))
            .violation("MISSING_API_AUTH", "External API calls require authentication")
            .severity(ViolationSeverity.ERROR)
            .remediation("Include api_key in parameters")
            .build()
        )
        
        # Rule 4: Excessive discount
        self.add_rule(
            PolicyRuleBuilder("Discount limit")
            .when(lambda ctx: (
                ctx.event_type == "action_request" and
                ctx.get_payload().get('action') == 'apply_discount' and
                ctx.get_payload().get('params', {}).get('discount_percent', 0) > 50
            ))
            .violation("EXCESSIVE_DISCOUNT", "Discount exceeds 50% limit")
            .severity(ViolationSeverity.WARNING)
            .remediation("Limit discount to 50% or obtain approval")
            .build()
        )
        
        # Rule 5: Failed critical actions
        self.add_rule(
            PolicyRuleBuilder("Critical action failure")
            .when(lambda ctx: (
                ctx.event_type == "action_response" and
                ctx.get_payload().get('status') == 'error' and
                ctx.get_payload().get('data', {}).get('error_code') in ['PAYMENT_FAILED', 'SYSTEM_ERROR']
            ))
            .violation("CRITICAL_ACTION_FAILED", "Critical action failed with system error")
            .severity(ViolationSeverity.CRITICAL)
            .remediation("Investigate system error and retry")
            .build()
        )
        
        # Rule 6: Sensitive data in params
        self.add_rule(
            PolicyRuleBuilder("Sensitive data exposure")
            .when(lambda ctx: self._check_sensitive_params(ctx))
            .violation("SENSITIVE_DATA_EXPOSED", "Sensitive data in action parameters")
            .severity(ViolationSeverity.ERROR)
            .remediation("Use secure parameter passing or redact sensitive data")
            .build()
        )
        
        logger.info(f"Loaded {len(self.rules)} default policy rules")
    
    def _check_sensitive_params(self, ctx: ValidationContext) -> bool:
        """Check if params contain sensitive data (SSN, credit card)."""
        if ctx.event_type != "action_request":
            return False
        
        params = ctx.get_payload().get('params', {})
        params_str = json.dumps(params)
        
        # SSN pattern (XXX-XX-XXXX)
        if re.search(r'\b\d{3}-\d{2}-\d{4}\b', params_str):
            return True
        
        # Credit card pattern (16 digits)
        if re.search(r'\b\d{16}\b', params_str):
            return True
        
        # Common sensitive field names
        sensitive_fields = ['ssn', 'social_security', 'credit_card', 'password', 'secret']
        for field in sensitive_fields:
            if field in params_str.lower():
                return True
        
        return False
    
    def add_rule(self, rule: PolicyRule):
        """
        Add a custom policy rule.
        
        Args:
            rule: PolicyRule instance
        """
        self.rules.append(rule)
        logger.info(f"Added policy rule: {rule.name}")
    
    def remove_rule(self, rule_name: str):
        """
        Remove a policy rule by name.
        
        Args:
            rule_name: Name of rule to remove
        """
        self.rules = [r for r in self.rules if r.name != rule_name]
        logger.info(f"Removed policy rule: {rule_name}")
    
    def enable_rule(self, rule_name: str):
        """Enable a rule."""
        for rule in self.rules:
            if rule.name == rule_name:
                rule.enabled = True
                return
    
    def disable_rule(self, rule_name: str):
        """Disable a rule."""
        for rule in self.rules:
            if rule.name == rule_name:
                rule.enabled = False
                return
    
    def list_rules(self) -> List[Dict[str, Any]]:
        """List all rules."""
        return [
            {
                'name': rule.name,
                'violation_type': rule.violation_type,
                'severity': rule.severity.value,
                'enabled': rule.enabled
            }
            for rule in self.rules
        ]
    
    def validate_event(self, context: ValidationContext) -> List[ValidationViolation]:
        """
        Validate event against all policy rules.
        
        Args:
            context: Validation context
            
        Returns:
            List of violations
        """
        violations = []
        
        for rule in self.rules:
            violation = rule.evaluate(context)
            if violation:
                violations.append(violation)
        
        return violations


# Helper functions for building complex conditions

def field_equals(field_path: str, value: Any) -> Callable[[ValidationContext], bool]:
    """
    Create condition that checks if field equals value.
    
    Usage:
        .when(field_equals("payload.action", "delete_user"))
    """
    def condition(ctx: ValidationContext) -> bool:
        parts = field_path.split('.')
        obj = ctx.event if parts[0] == 'event' else ctx.get_payload()
        
        for part in parts[1:]:
            if isinstance(obj, dict):
                obj = obj.get(part)
            else:
                return False
        
        return obj == value
    
    return condition


def field_greater_than(field_path: str, threshold: float) -> Callable[[ValidationContext], bool]:
    """
    Create condition that checks if numeric field exceeds threshold.
    
    Usage:
        .when(field_greater_than("payload.params.amount", 1000))
    """
    def condition(ctx: ValidationContext) -> bool:
        parts = field_path.split('.')
        obj = ctx.event if parts[0] == 'event' else ctx.get_payload()
        
        for part in parts[1:]:
            if isinstance(obj, dict):
                obj = obj.get(part)
            else:
                return False
        
        try:
            return float(obj) > threshold
        except (TypeError, ValueError):
            return False
    
    return condition


def field_in_list(field_path: str, allowed_values: List[Any]) -> Callable[[ValidationContext], bool]:
    """
    Create condition that checks if field value is NOT in allowed list.
    
    Usage:
        .when(field_in_list("payload.action", ["read", "list"]))
    """
    def condition(ctx: ValidationContext) -> bool:
        parts = field_path.split('.')
        obj = ctx.event if parts[0] == 'event' else ctx.get_payload()
        
        for part in parts[1:]:
            if isinstance(obj, dict):
                obj = obj.get(part)
            else:
                return False
        
        return obj not in allowed_values
    
    return condition


def combine_and(*conditions: Callable[[ValidationContext], bool]) -> Callable[[ValidationContext], bool]:
    """
    Combine multiple conditions with AND logic.
    
    Usage:
        .when(combine_and(
            field_equals("type", "action_request"),
            field_greater_than("params.amount", 1000)
        ))
    """
    def condition(ctx: ValidationContext) -> bool:
        return all(cond(ctx) for cond in conditions)
    
    return condition


def combine_or(*conditions: Callable[[ValidationContext], bool]) -> Callable[[ValidationContext], bool]:
    """
    Combine multiple conditions with OR logic.
    
    Usage:
        .when(combine_or(
            field_equals("action", "delete_user"),
            field_equals("action", "delete_data")
        ))
    """
    def condition(ctx: ValidationContext) -> bool:
        return any(cond(ctx) for cond in conditions)
    
    return condition


# Register policy checker
policy_checker = PolicyChecker()
validator_registry.register(policy_checker)
