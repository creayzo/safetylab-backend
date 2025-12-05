"""
PII (Personally Identifiable Information) Detector

Multi-layer PII detection using:
1. Regex patterns for common PII formats (SSN, credit cards, phone, email)
2. Named entity recognition (NER) for names, locations
3. Configurable custom patterns
4. ML-based detection (optional, with prebuilt model)

Detects PII in:
- Reasoning payloads (thoughts, plans)
- Action requests/responses
- Final outputs
- Any text fields

Usage:
    detector = PII Detector()
    detector.add_pattern("employee_id", r"EMP-\d{6}")
    violations = detector.validate(context)
"""

import re
import json
import logging
from typing import List, Dict, Any, Optional, Pattern, Tuple
from dataclasses import dataclass

from api.validators.base import (
    BaseValidator,
    ValidationContext,
    ValidationViolation,
    ViolationSeverity,
    ValidationPhase,
    validator_registry
)

logger = logging.getLogger(__name__)


@dataclass
class PIIPattern:
    """Represents a PII detection pattern."""
    name: str
    pattern: Pattern
    description: str
    severity: ViolationSeverity = ViolationSeverity.ERROR
    redaction_char: str = '*'
    
    def detect(self, text: str) -> List[str]:
        """Find all matches in text."""
        matches = self.pattern.findall(text)
        return matches if matches else []
    
    def redact(self, text: str) -> str:
        """Redact PII from text."""
        def replace_match(match):
            # Keep first and last char, redact middle
            matched = match.group(0)
            if len(matched) <= 4:
                return self.redaction_char * len(matched)
            return matched[0] + self.redaction_char * (len(matched) - 2) + matched[-1]
        
        return self.pattern.sub(replace_match, text)


class PIIDetector(BaseValidator):
    """
    PII detector with regex and optional ML.
    
    Scans all text fields in events for personally identifiable information.
    """
    
    def __init__(self):
        """Initialize PII detector with built-in patterns."""
        super().__init__(
            name="pii_detector",
            description="Detects personally identifiable information in trace events",
            phases=[ValidationPhase.INGESTION, ValidationPhase.POST_RUN]
        )
        
        self.patterns: Dict[str, PIIPattern] = {}
        self._load_default_patterns()
        
        # ML model (optional)
        self.ml_model = None
        self._try_load_ml_model()
    
    def _load_default_patterns(self):
        """Load built-in PII patterns."""
        
        # Social Security Number (US)
        self.add_pattern(
            PIIPattern(
                name="ssn",
                pattern=re.compile(r'\b\d{3}-\d{2}-\d{4}\b'),
                description="US Social Security Number (XXX-XX-XXXX)",
                severity=ViolationSeverity.CRITICAL
            )
        )
        
        # Credit Card Numbers (13-19 digits)
        self.add_pattern(
            PIIPattern(
                name="credit_card",
                pattern=re.compile(r'\b(?:\d[ -]*?){13,19}\b'),
                description="Credit card number",
                severity=ViolationSeverity.CRITICAL
            )
        )
        
        # Email Addresses
        self.add_pattern(
            PIIPattern(
                name="email",
                pattern=re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'),
                description="Email address",
                severity=ViolationSeverity.WARNING
            )
        )
        
        # Phone Numbers (various formats)
        self.add_pattern(
            PIIPattern(
                name="phone",
                pattern=re.compile(r'\b(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b'),
                description="Phone number",
                severity=ViolationSeverity.WARNING
            )
        )
        
        # IP Addresses
        self.add_pattern(
            PIIPattern(
                name="ip_address",
                pattern=re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b'),
                description="IP address",
                severity=ViolationSeverity.INFO
            )
        )
        
        # API Keys / Tokens (generic patterns)
        self.add_pattern(
            PIIPattern(
                name="api_key",
                pattern=re.compile(r'\b(?:api[_-]?key|token|secret)["\s:=]+([a-zA-Z0-9_\-]{20,})\b', re.IGNORECASE),
                description="API key or token",
                severity=ViolationSeverity.CRITICAL
            )
        )
        
        # Passwords in JSON
        self.add_pattern(
            PIIPattern(
                name="password",
                pattern=re.compile(r'"password"\s*:\s*"([^"]+)"', re.IGNORECASE),
                description="Password in plain text",
                severity=ViolationSeverity.CRITICAL
            )
        )
        
        # US Passport Numbers
        self.add_pattern(
            PIIPattern(
                name="passport",
                pattern=re.compile(r'\b[A-Z]{1,2}\d{6,9}\b'),
                description="US Passport number",
                severity=ViolationSeverity.CRITICAL
            )
        )
        
        # Driver's License (generic)
        self.add_pattern(
            PIIPattern(
                name="drivers_license",
                pattern=re.compile(r'\b[A-Z]{1,2}\d{6,8}\b'),
                description="Driver's license number",
                severity=ViolationSeverity.ERROR
            )
        )
        
        logger.info(f"Loaded {len(self.patterns)} PII patterns")
    
    def _try_load_ml_model(self):
        """Try to load optional ML model for NER."""
        try:
            # Optional: Load spaCy or transformers model
            # import spacy
            # self.ml_model = spacy.load("en_core_web_sm")
            # logger.info("Loaded ML model for PII detection")
            pass
        except ImportError:
            logger.debug("ML model not available, using regex only")
    
    def add_pattern(self, pattern: PIIPattern):
        """
        Add a custom PII pattern.
        
        Args:
            pattern: PIIPattern instance
        """
        self.patterns[pattern.name] = pattern
        logger.debug(f"Added PII pattern: {pattern.name}")
    
    def remove_pattern(self, pattern_name: str):
        """Remove a PII pattern."""
        if pattern_name in self.patterns:
            del self.patterns[pattern_name]
            logger.debug(f"Removed PII pattern: {pattern_name}")
    
    def add_custom_pattern(
        self,
        name: str,
        regex: str,
        description: str,
        severity: ViolationSeverity = ViolationSeverity.ERROR
    ):
        """
        Add a custom pattern from regex string.
        
        Args:
            name: Pattern name
            regex: Regular expression string
            description: Human-readable description
            severity: Violation severity
        """
        pattern = PIIPattern(
            name=name,
            pattern=re.compile(regex),
            description=description,
            severity=severity
        )
        self.add_pattern(pattern)
    
    def scan_text(self, text: str) -> List[Tuple[str, List[str]]]:
        """
        Scan text for PII.
        
        Args:
            text: Text to scan
            
        Returns:
            List of (pattern_name, matches) tuples
        """
        detections = []
        
        for pattern_name, pattern in self.patterns.items():
            matches = pattern.detect(text)
            if matches:
                detections.append((pattern_name, matches))
        
        return detections
    
    def scan_dict(self, obj: Any, path: str = "") -> List[Tuple[str, str, List[str]]]:
        """
        Recursively scan dictionary/list for PII.
        
        Args:
            obj: Object to scan (dict, list, or primitive)
            path: Current path in object (for reporting)
            
        Returns:
            List of (path, pattern_name, matches) tuples
        """
        detections = []
        
        if isinstance(obj, dict):
            for key, value in obj.items():
                new_path = f"{path}.{key}" if path else key
                detections.extend(self.scan_dict(value, new_path))
        
        elif isinstance(obj, list):
            for idx, item in enumerate(obj):
                new_path = f"{path}[{idx}]"
                detections.extend(self.scan_dict(item, new_path))
        
        elif isinstance(obj, str):
            text_detections = self.scan_text(obj)
            for pattern_name, matches in text_detections:
                detections.append((path, pattern_name, matches))
        
        return detections
    
    def redact_text(self, text: str) -> str:
        """
        Redact PII from text.
        
        Args:
            text: Text to redact
            
        Returns:
            Redacted text
        """
        redacted = text
        for pattern in self.patterns.values():
            redacted = pattern.redact(redacted)
        return redacted
    
    def redact_dict(self, obj: Any) -> Any:
        """
        Recursively redact PII from dictionary/list.
        
        Args:
            obj: Object to redact
            
        Returns:
            Redacted copy of object
        """
        if isinstance(obj, dict):
            return {key: self.redact_dict(value) for key, value in obj.items()}
        
        elif isinstance(obj, list):
            return [self.redact_dict(item) for item in obj]
        
        elif isinstance(obj, str):
            return self.redact_text(obj)
        
        return obj
    
    def validate(self, context: ValidationContext) -> List[ValidationViolation]:
        """
        Validate event for PII.
        
        Args:
            context: Validation context
            
        Returns:
            List of violations
        """
        violations = []
        
        # Scan entire event
        detections = self.scan_dict(context.event)
        
        for path, pattern_name, matches in detections:
            pattern = self.patterns[pattern_name]
            
            violation = ValidationViolation(
                validator_name=self.name,
                severity=pattern.severity,
                violation_type="PII_DETECTED",
                message=f"PII detected: {pattern.description} in {path}",
                event_id=None,
                run_id=context.run_id,
                seq_no=context.seq_no,
                details={
                    'pattern_name': pattern_name,
                    'field_path': path,
                    'match_count': len(matches),
                    'sample': matches[0] if matches else None
                },
                timestamp=context.timestamp,
                remediation="Redact PII before logging or use secure field masking"
            )
            
            violations.append(violation)
        
        # ML-based detection (if available)
        if self.ml_model:
            ml_violations = self._ml_detect(context)
            violations.extend(ml_violations)
        
        return violations
    
    def _ml_detect(self, context: ValidationContext) -> List[ValidationViolation]:
        """
        ML-based PII detection using NER.
        
        Args:
            context: Validation context
            
        Returns:
            List of violations
        """
        violations = []
        
        # Extract text from event
        text = json.dumps(context.event)
        
        try:
            # Run NER model
            doc = self.ml_model(text)
            
            # Check for person names, locations, organizations
            for ent in doc.ents:
                if ent.label_ in ['PERSON', 'GPE', 'ORG', 'LOC']:
                    violation = ValidationViolation(
                        validator_name=self.name,
                        severity=ViolationSeverity.WARNING,
                        violation_type="PII_ENTITY_DETECTED",
                        message=f"Named entity detected: {ent.label_} - {ent.text}",
                        event_id=None,
                        run_id=context.run_id,
                        seq_no=context.seq_no,
                        details={
                            'entity_type': ent.label_,
                            'entity_text': ent.text
                        },
                        timestamp=context.timestamp,
                        remediation="Review if entity is PII and redact if necessary"
                    )
                    violations.append(violation)
        
        except Exception as e:
            logger.error(f"ML PII detection failed: {e}")
        
        return violations


# Prebuilt PII detector instance
pii_detector = PIIDetector()
validator_registry.register(pii_detector)


# Helper functions for external use

def detect_pii(text: str) -> List[str]:
    """
    Quick PII detection in text.
    
    Args:
        text: Text to scan
        
    Returns:
        List of PII types detected
    """
    detections = pii_detector.scan_text(text)
    return [pattern_name for pattern_name, _ in detections]


def redact_pii(text: str) -> str:
    """
    Quick PII redaction from text.
    
    Args:
        text: Text to redact
        
    Returns:
        Redacted text
    """
    return pii_detector.redact_text(text)


def redact_event_pii(event: Dict[str, Any]) -> Dict[str, Any]:
    """
    Redact PII from entire event.
    
    Args:
        event: Event dictionary
        
    Returns:
        Redacted event copy
    """
    return pii_detector.redact_dict(event)
