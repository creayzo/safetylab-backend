"""
Prompt Injection Detector

Detects prompt injection attempts in reasoning logs and user inputs.
Uses pattern matching and heuristics to identify malicious prompts.

Injection patterns detected:
- Role confusion ("You are now...", "Ignore previous instructions")
- System prompt leakage attempts
- Jailbreak attempts
- Hidden instructions
- Command injection
- SQL injection patterns

Usage:
    detector = PromptInjectionDetector()
    violations = detector.validate(context)
"""

import re
import logging
from typing import List, Dict, Any, Pattern, Tuple

from api.validators.base import (
    EventTypeValidator,
    ValidationContext,
    ValidationViolation,
    ViolationSeverity,
    ValidationPhase,
    validator_registry
)

logger = logging.getLogger(__name__)


class InjectionPattern:
    """Represents a prompt injection pattern."""
    
    def __init__(
        self,
        name: str,
        pattern: Pattern,
        description: str,
        severity: ViolationSeverity = ViolationSeverity.ERROR
    ):
        """Initialize injection pattern."""
        self.name = name
        self.pattern = pattern
        self.description = description
        self.severity = severity
    
    def detect(self, text: str) -> List[str]:
        """Find all matches in text."""
        matches = self.pattern.findall(text, re.IGNORECASE | re.MULTILINE)
        return matches if matches else []


class PromptInjectionDetector(EventTypeValidator):
    """
    Detects prompt injection attempts in reasoning logs.
    
    Focuses on reasoning events where agent thoughts may contain
    injected instructions from user input.
    """
    
    def __init__(self):
        """Initialize detector with injection patterns."""
        super().__init__(
            name="prompt_injection_detector",
            description="Detects prompt injection attempts in reasoning logs",
            event_types=["reasoning", "final_output"],
            phases=[ValidationPhase.INGESTION, ValidationPhase.POST_RUN]
        )
        
        self.patterns: List[InjectionPattern] = []
        self._load_injection_patterns()
    
    def _load_injection_patterns(self):
        """Load prompt injection detection patterns."""
        
        # Role confusion attacks
        self.patterns.append(InjectionPattern(
            name="role_confusion",
            pattern=re.compile(
                r'\b(you are now|ignore previous|disregard|forget (all |previous )?(instructions?|rules?))\b',
                re.IGNORECASE
            ),
            description="Role confusion or instruction override attempt",
            severity=ViolationSeverity.CRITICAL
        ))
        
        # System prompt leakage
        self.patterns.append(InjectionPattern(
            name="system_prompt_leak",
            pattern=re.compile(
                r'\b(repeat (your|the) (system )?prompt|show (me )?(your|the) instructions|what (are|is) your (system )?prompt)\b',
                re.IGNORECASE
            ),
            description="System prompt leakage attempt",
            severity=ViolationSeverity.ERROR
        ))
        
        # Jailbreak attempts
        self.patterns.append(InjectionPattern(
            name="jailbreak",
            pattern=re.compile(
                r'\b(DAN mode|developer mode|god mode|admin mode|jailbreak|bypass (safety |content )?(guidelines?|filters?|restrictions?))\b',
                re.IGNORECASE
            ),
            description="Jailbreak attempt to bypass safety guidelines",
            severity=ViolationSeverity.CRITICAL
        ))
        
        # Hidden instructions (Unicode, encoding)
        self.patterns.append(InjectionPattern(
            name="hidden_instructions",
            pattern=re.compile(
                r'([\u200B-\u200F\u202A-\u202E]|<!--.*?-->|<script>|javascript:)',
                re.IGNORECASE
            ),
            description="Hidden instructions using Unicode or HTML",
            severity=ViolationSeverity.ERROR
        ))
        
        # Command injection
        self.patterns.append(InjectionPattern(
            name="command_injection",
            pattern=re.compile(
                r'(\||&&|;|\$\(|\`|>\s*/|<\s*/|rm\s+-rf|sudo\s+)',
                re.IGNORECASE
            ),
            description="Command injection attempt",
            severity=ViolationSeverity.CRITICAL
        ))
        
        # SQL injection
        self.patterns.append(InjectionPattern(
            name="sql_injection",
            pattern=re.compile(
                r"('|\"\s*)(OR|AND)\s+('1'='1'|1=1|'x'='x'|true)",
                re.IGNORECASE
            ),
            description="SQL injection attempt",
            severity=ViolationSeverity.CRITICAL
        ))
        
        # Context switching
        self.patterns.append(InjectionPattern(
            name="context_switch",
            pattern=re.compile(
                r'\b(new (context|conversation|session)|start over|reset conversation|clear (history|context))\b',
                re.IGNORECASE
            ),
            description="Context switching attempt",
            severity=ViolationSeverity.WARNING
        ))
        
        # Fake authority
        self.patterns.append(InjectionPattern(
            name="fake_authority",
            pattern=re.compile(
                r'\b(I am (the|an?) (admin|administrator|developer|engineer|owner|CEO)|(admin|developer|system) (said|told|instructed))\b',
                re.IGNORECASE
            ),
            description="Fake authority claim",
            severity=ViolationSeverity.WARNING
        ))
        
        # Instruction appending
        self.patterns.append(InjectionPattern(
            name="instruction_append",
            pattern=re.compile(
                r'\b(also|additionally|furthermore),?\s+(please\s+)?(do|execute|run|perform|say|output|print)\b',
                re.IGNORECASE
            ),
            description="Instruction appending attempt",
            severity=ViolationSeverity.WARNING
        ))
        
        # Output manipulation
        self.patterns.append(InjectionPattern(
            name="output_manipulation",
            pattern=re.compile(
                r'\b(output|print|say|respond with|return)\s+["\']?\{',
                re.IGNORECASE
            ),
            description="Output manipulation attempt",
            severity=ViolationSeverity.ERROR
        ))
        
        logger.info(f"Loaded {len(self.patterns)} prompt injection patterns")
    
    def scan_text(self, text: str) -> List[Tuple[str, str, List[str]]]:
        """
        Scan text for injection patterns.
        
        Args:
            text: Text to scan
            
        Returns:
            List of (pattern_name, description, matches) tuples
        """
        detections = []
        
        for pattern in self.patterns:
            matches = pattern.detect(text)
            if matches:
                detections.append((pattern.name, pattern.description, matches))
        
        return detections
    
    def analyze_reasoning(self, payload: Dict[str, Any]) -> List[Tuple[str, str, List[str]]]:
        """
        Analyze reasoning payload for injections.
        
        Args:
            payload: Reasoning event payload
            
        Returns:
            List of detections
        """
        detections = []
        
        # Check thought field
        if 'thought' in payload:
            thought_detections = self.scan_text(payload['thought'])
            detections.extend(thought_detections)
        
        # Check goal field
        if 'goal' in payload:
            goal_detections = self.scan_text(payload['goal'])
            detections.extend(goal_detections)
        
        # Check steps
        if 'steps' in payload:
            for step in payload.get('steps', []):
                if isinstance(step, dict):
                    step_desc = step.get('description', '')
                    step_detections = self.scan_text(step_desc)
                    detections.extend(step_detections)
                elif isinstance(step, str):
                    step_detections = self.scan_text(step)
                    detections.extend(step_detections)
        
        # Check plan field
        if 'plan' in payload:
            if isinstance(payload['plan'], list):
                for item in payload['plan']:
                    if isinstance(item, str):
                        detections.extend(self.scan_text(item))
            elif isinstance(payload['plan'], str):
                detections.extend(self.scan_text(payload['plan']))
        
        return detections
    
    def validate_event(self, context: ValidationContext) -> List[ValidationViolation]:
        """
        Validate event for prompt injections.
        
        Args:
            context: Validation context
            
        Returns:
            List of violations
        """
        violations = []
        payload = context.get_payload()
        
        if context.event_type == "reasoning":
            detections = self.analyze_reasoning(payload)
        elif context.event_type == "final_output":
            # Check final output text
            text = payload.get('text', '')
            detections = self.scan_text(text)
        else:
            return violations
        
        # Create violations
        for pattern_name, description, matches in detections:
            # Find severity from pattern
            pattern = next((p for p in self.patterns if p.name == pattern_name), None)
            severity = pattern.severity if pattern else ViolationSeverity.WARNING
            
            violation = ValidationViolation(
                validator_name=self.name,
                severity=severity,
                violation_type="PROMPT_INJECTION",
                message=f"Prompt injection detected: {description}",
                event_id=None,
                run_id=context.run_id,
                seq_no=context.seq_no,
                details={
                    'pattern': pattern_name,
                    'matches': matches[:3],  # First 3 matches
                    'match_count': len(matches)
                },
                timestamp=context.timestamp,
                remediation="Sanitize user input and validate reasoning outputs"
            )
            
            violations.append(violation)
        
        return violations


# Advanced heuristics
class PromptInjectionHeuristics:
    """
    Advanced heuristic analysis for prompt injections.
    
    Uses statistical and contextual analysis beyond pattern matching.
    """
    
    @staticmethod
    def check_excessive_instructions(text: str) -> bool:
        """Check for excessive imperative instructions."""
        imperatives = re.findall(
            r'\b(do|execute|run|perform|output|say|print|show|tell|give|provide)\b',
            text,
            re.IGNORECASE
        )
        return len(imperatives) > 5
    
    @staticmethod
    def check_suspicious_quotes(text: str) -> bool:
        """Check for suspicious quotation patterns."""
        # Multiple quote types suggest attempted escaping
        quote_types = sum([
            '"' in text,
            "'" in text,
            '`' in text,
            '"""' in text,
            "'''" in text
        ])
        return quote_types >= 3
    
    @staticmethod
    def check_encoding_attempts(text: str) -> bool:
        """Check for encoding/obfuscation attempts."""
        patterns = [
            r'\\x[0-9a-f]{2}',  # Hex encoding
            r'\\u[0-9a-f]{4}',  # Unicode encoding
            r'%[0-9a-f]{2}',    # URL encoding
            r'&#\d+;',          # HTML entity
        ]
        
        for pattern in patterns:
            if re.search(pattern, text, re.IGNORECASE):
                return True
        return False
    
    @staticmethod
    def check_recursive_instructions(text: str) -> bool:
        """Check for recursive or nested instructions."""
        return bool(re.search(
            r'\b(then|after (that|this)|next)\s+(do|execute|run|say)',
            text,
            re.IGNORECASE
        ))


# Register detector
prompt_injection_detector = PromptInjectionDetector()
validator_registry.register(prompt_injection_detector)


# Helper function
def detect_injection(text: str) -> List[str]:
    """
    Quick injection detection in text.
    
    Args:
        text: Text to check
        
    Returns:
        List of injection types detected
    """
    detections = prompt_injection_detector.scan_text(text)
    return [pattern_name for pattern_name, _, _ in detections]
