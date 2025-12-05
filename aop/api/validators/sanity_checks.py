"""
Sanity Check Validators

Validates trace consistency and temporal properties:
- Timelags between events (detect hanging/stuck agents)
- Missing required steps in sequences
- Sequence number anomalies (jumps, duplicates, out-of-order)
- Chronological ordering violations
- Event frequency anomalies
"""

import logging
from typing import List, Dict, Any, Optional, Set
from datetime import datetime, timedelta
from collections import defaultdict

from api.validators.base import (
    BaseValidator,
    ValidationContext,
    ValidationViolation,
    ViolationSeverity,
    ValidationPhase,
    validator_registry
)

logger = logging.getLogger(__name__)


class TimelagValidator(BaseValidator):
    """
    Detects abnormal time gaps between events.
    
    Warns if agent takes too long between steps.
    """
    
    def __init__(
        self,
        warning_threshold: timedelta = timedelta(minutes=5),
        critical_threshold: timedelta = timedelta(minutes=30)
    ):
        """
        Initialize timelag validator.
        
        Args:
            warning_threshold: Time gap to trigger warning
            critical_threshold: Time gap to trigger critical alert
        """
        super().__init__(
            name="timelag_validator",
            description="Detects abnormal time gaps between events",
            phases=[ValidationPhase.POST_RUN]
        )
        self.warning_threshold = warning_threshold
        self.critical_threshold = critical_threshold
    
    def validate_event(self, context: ValidationContext) -> List[ValidationViolation]:
        """Not used - this validator only runs on complete runs."""
        return []
    
    def evaluate_run(
        self,
        run_id: str,
        events: List[Dict[str, Any]],
        metadata: Optional[Dict[str, Any]] = None
    ) -> List[ValidationViolation]:
        """
        Check for abnormal time gaps.
        
        Args:
            run_id: Run ID
            events: All events in the run
            metadata: Optional run metadata
            
        Returns:
            List of violations
        """
        violations = []
        
        # Sort by sequence
        sorted_events = sorted(events, key=lambda e: e['seq_no'])
        
        for i in range(1, len(sorted_events)):
            prev_event = sorted_events[i-1]
            curr_event = sorted_events[i]
            
            prev_time = datetime.fromisoformat(prev_event['timestamp'].replace('Z', '+00:00'))
            curr_time = datetime.fromisoformat(curr_event['timestamp'].replace('Z', '+00:00'))
            
            gap = curr_time - prev_time
            
            if gap > self.critical_threshold:
                violations.append(ValidationViolation(
                    validator_name=self.name,
                    severity=ViolationSeverity.CRITICAL,
                    violation_type="EXCESSIVE_TIMELAG",
                    message=f"Critical time gap of {gap.total_seconds():.1f}s between events",
                    run_id=run_id,
                    seq_no=curr_event['seq_no'],
                    details={
                        'previous_seq': prev_event['seq_no'],
                        'current_seq': curr_event['seq_no'],
                        'previous_type': prev_event['event_type'],
                        'current_type': curr_event['event_type'],
                        'gap_seconds': gap.total_seconds(),
                        'threshold_seconds': self.critical_threshold.total_seconds()
                    },
                    timestamp=curr_time,
                    remediation="Check for agent hanging, network issues, or resource constraints"
                ))
            elif gap > self.warning_threshold:
                violations.append(ValidationViolation(
                    validator_name=self.name,
                    severity=ViolationSeverity.WARNING,
                    violation_type="LONG_TIMELAG",
                    message=f"Long time gap of {gap.total_seconds():.1f}s between events",
                    run_id=run_id,
                    seq_no=curr_event['seq_no'],
                    details={
                        'previous_seq': prev_event['seq_no'],
                        'current_seq': curr_event['seq_no'],
                        'gap_seconds': gap.total_seconds(),
                        'threshold_seconds': self.warning_threshold.total_seconds()
                    },
                    timestamp=curr_time,
                    remediation="Monitor agent performance and resource usage"
                ))
        
        return violations


class MissingStepValidator(BaseValidator):
    """
    Detects missing required steps in common workflows.
    
    Example: action_response without preceding action_request
    """
    
    def __init__(self):
        """Initialize missing step validator."""
        super().__init__(
            name="missing_step_validator",
            description="Detects missing required steps in workflows",
            phases=[ValidationPhase.POST_RUN]
        )
        
        # Define required sequences
        self.required_sequences = {
            'action_response': ['action_request'],  # Response needs request
            'final_output': ['reasoning']  # Output needs reasoning
        }
    
    def validate_event(self, context: ValidationContext) -> List[ValidationViolation]:
        """Not used - this validator only runs on complete runs."""
        return []
    
    def evaluate_run(
        self,
        run_id: str,
        events: List[Dict[str, Any]],
        metadata: Optional[Dict[str, Any]] = None
    ) -> List[ValidationViolation]:
        """
        Check for missing prerequisite steps.
        
        Args:
            run_id: Run ID
            events: All events in the run
            metadata: Optional run metadata
            
        Returns:
            List of violations
        """
        violations = []
        
        # Track seen event types
        seen_types: Set[str] = set()
        
        # Sort by sequence
        sorted_events = sorted(events, key=lambda e: e['seq_no'])
        
        for event in sorted_events:
            event_type = event['event_type']
            
            # Check if this type requires prerequisites
            if event_type in self.required_sequences:
                required = self.required_sequences[event_type]
                
                # Check if all prerequisites are present
                missing = [req for req in required if req not in seen_types]
                
                if missing:
                    violations.append(ValidationViolation(
                        validator_name=self.name,
                        severity=ViolationSeverity.ERROR,
                        violation_type="MISSING_PREREQUISITE",
                        message=f"Event '{event_type}' missing prerequisite steps: {', '.join(missing)}",
                        run_id=run_id,
                        seq_no=event['seq_no'],
                        details={
                            'event_type': event_type,
                            'missing_prerequisites': missing,
                            'seen_types': list(seen_types)
                        },
                        timestamp=datetime.fromisoformat(event['timestamp'].replace('Z', '+00:00')),
                        remediation="Ensure workflow follows required sequence"
                    ))
            
            # Add to seen types
            seen_types.add(event_type)
        
        return violations


class SequenceValidator(BaseValidator):
    """
    Validates sequence number consistency.
    
    Detects:
    - Sequence jumps (missing numbers)
    - Out-of-order timestamps
    - Duplicate sequences (beyond retries)
    """
    
    def __init__(self, max_allowed_gap: int = 10):
        """
        Initialize sequence validator.
        
        Args:
            max_allowed_gap: Maximum allowed gap in sequence numbers
        """
        super().__init__(
            name="sequence_validator",
            description="Validates sequence number and timestamp consistency",
            phases=[ValidationPhase.POST_RUN]
        )
        self.max_allowed_gap = max_allowed_gap
    
    def validate_event(self, context: ValidationContext) -> List[ValidationViolation]:
        """Not used - this validator only runs on complete runs."""
        return []
    
    def evaluate_run(
        self,
        run_id: str,
        events: List[Dict[str, Any]],
        metadata: Optional[Dict[str, Any]] = None
    ) -> List[ValidationViolation]:
        """
        Check sequence consistency.
        
        Args:
            run_id: Run ID
            events: All events in the run
            metadata: Optional run metadata
            
        Returns:
            List of violations
        """
        violations = []
        
        # Sort by sequence
        sorted_events = sorted(events, key=lambda e: e['seq_no'])
        
        # Check for sequence gaps
        for i in range(1, len(sorted_events)):
            prev_seq = sorted_events[i-1]['seq_no']
            curr_seq = sorted_events[i]['seq_no']
            
            gap = curr_seq - prev_seq
            
            if gap > self.max_allowed_gap:
                violations.append(ValidationViolation(
                    validator_name=self.name,
                    severity=ViolationSeverity.WARNING,
                    violation_type="SEQUENCE_GAP",
                    message=f"Large gap in sequence: {prev_seq} -> {curr_seq} (gap: {gap})",
                    run_id=run_id,
                    seq_no=curr_seq,
                    details={
                        'previous_seq': prev_seq,
                        'current_seq': curr_seq,
                        'gap_size': gap,
                        'max_allowed': self.max_allowed_gap
                    },
                    timestamp=datetime.fromisoformat(sorted_events[i]['timestamp'].replace('Z', '+00:00')),
                    remediation="Check for lost events or client-side sequence generation issues"
                ))
        
        # Check for timestamp ordering violations
        for i in range(1, len(sorted_events)):
            prev_time = datetime.fromisoformat(sorted_events[i-1]['timestamp'].replace('Z', '+00:00'))
            curr_time = datetime.fromisoformat(sorted_events[i]['timestamp'].replace('Z', '+00:00'))
            
            if curr_time < prev_time:
                violations.append(ValidationViolation(
                    validator_name=self.name,
                    severity=ViolationSeverity.ERROR,
                    violation_type="TIMESTAMP_ORDERING",
                    message=f"Event timestamp earlier than previous event",
                    run_id=run_id,
                    seq_no=sorted_events[i]['seq_no'],
                    details={
                        'previous_seq': sorted_events[i-1]['seq_no'],
                        'previous_timestamp': sorted_events[i-1]['timestamp'],
                        'current_seq': sorted_events[i]['seq_no'],
                        'current_timestamp': sorted_events[i]['timestamp']
                    },
                    timestamp=curr_time,
                    remediation="Check system clock synchronization and timestamp generation"
                ))
        
        # Check for duplicate sequences (count occurrences)
        seq_counts = defaultdict(int)
        for event in events:
            seq_counts[event['seq_no']] += 1
        
        # Allow up to 3 duplicates (retries)
        for seq_no, count in seq_counts.items():
            if count > 3:
                violations.append(ValidationViolation(
                    validator_name=self.name,
                    severity=ViolationSeverity.WARNING,
                    violation_type="EXCESSIVE_DUPLICATES",
                    message=f"Sequence {seq_no} appears {count} times (possible retry loop)",
                    run_id=run_id,
                    seq_no=seq_no,
                    details={
                        'sequence_number': seq_no,
                        'occurrence_count': count,
                        'max_retries': 3
                    },
                    timestamp=datetime.now(),
                    remediation="Check retry logic and idempotency handling"
                ))
        
        return violations


class EventFrequencyValidator(BaseValidator):
    """
    Detects abnormal event frequencies.
    
    Warns if agent generates too many events too quickly (potential loop).
    """
    
    def __init__(
        self,
        max_events_per_minute: int = 100,
        max_events_per_run: int = 1000
    ):
        """
        Initialize frequency validator.
        
        Args:
            max_events_per_minute: Max events per minute
            max_events_per_run: Max total events per run
        """
        super().__init__(
            name="event_frequency_validator",
            description="Detects abnormal event generation rates",
            phases=[ValidationPhase.POST_RUN]
        )
        self.max_events_per_minute = max_events_per_minute
        self.max_events_per_run = max_events_per_run
    
    def validate_event(self, context: ValidationContext) -> List[ValidationViolation]:
        """Not used - this validator only runs on complete runs."""
        return []
    
    def evaluate_run(
        self,
        run_id: str,
        events: List[Dict[str, Any]],
        metadata: Optional[Dict[str, Any]] = None
    ) -> List[ValidationViolation]:
        """
        Check event generation frequency.
        
        Args:
            run_id: Run ID
            events: All events in the run
            metadata: Optional run metadata
            
        Returns:
            List of violations
        """
        violations = []
        
        # Check total event count
        if len(events) > self.max_events_per_run:
            violations.append(ValidationViolation(
                validator_name=self.name,
                severity=ViolationSeverity.WARNING,
                violation_type="EXCESSIVE_EVENTS",
                message=f"Run has {len(events)} events (max: {self.max_events_per_run})",
                run_id=run_id,
                details={
                    'total_events': len(events),
                    'max_allowed': self.max_events_per_run
                },
                timestamp=datetime.now(),
                remediation="Check for infinite loops or excessive iterations"
            ))
        
        # Check events per minute
        if len(events) >= 2:
            sorted_events = sorted(events, key=lambda e: e['timestamp'])
            
            start_time = datetime.fromisoformat(sorted_events[0]['timestamp'].replace('Z', '+00:00'))
            end_time = datetime.fromisoformat(sorted_events[-1]['timestamp'].replace('Z', '+00:00'))
            
            duration_minutes = max((end_time - start_time).total_seconds() / 60, 1)
            events_per_minute = len(events) / duration_minutes
            
            if events_per_minute > self.max_events_per_minute:
                violations.append(ValidationViolation(
                    validator_name=self.name,
                    severity=ViolationSeverity.WARNING,
                    violation_type="HIGH_EVENT_RATE",
                    message=f"High event rate: {events_per_minute:.1f} events/min (max: {self.max_events_per_minute})",
                    run_id=run_id,
                    details={
                        'events_per_minute': events_per_minute,
                        'max_allowed': self.max_events_per_minute,
                        'total_events': len(events),
                        'duration_minutes': duration_minutes
                    },
                    timestamp=datetime.now(),
                    remediation="Check for rapid loops or inefficient processing"
                ))
        
        return violations


# Register validators
timelag_validator = TimelagValidator()
missing_step_validator = MissingStepValidator()
sequence_validator = SequenceValidator()
event_frequency_validator = EventFrequencyValidator()

validator_registry.register(timelag_validator)
validator_registry.register(missing_step_validator)
validator_registry.register(sequence_validator)
validator_registry.register(event_frequency_validator)
