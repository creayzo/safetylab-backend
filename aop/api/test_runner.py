"""
Test Runner (Execution Pipeline)

The master orchestrator that coordinates the entire evaluation workflow:
1. Read EvaluationRun configuration
2. Assemble scenario set
3. Seed RNG
4. Initialize run
5. Stream agent outputs
6. Call validators
7. Finalize the run
8. Initiate replay run (optional)
9. Generate aggregated metrics

This is the "Orchestrate the whole crash test" engine.
"""

import logging
import random
import time
from typing import Dict, Any, List, Optional, Tuple
from datetime import datetime, timedelta
from django.utils import timezone
from django.db import transaction

from api.models import (
    Organization, Agent, Run, TraceEvent, EvaluationRun
)
from api.scenario_models import Scenario, ScenarioRun
from api.scenario_engine import ScenarioEngine
from api.validators.base import BaseValidator, ValidationViolation
from api.validators.pii_detector import PIIDetector
from api.validators.policy_validator import PolicyValidator
from api.validators.prompt_injection import PromptInjectionDetector
from api.validators.action_misuse import ActionMisuseDetector
from api.replay_runner import ReplayRunner, create_replay_snapshot
from api.wal_models import EventWAL

logger = logging.getLogger(__name__)


class TestRunner:
    """
    Master orchestrator for evaluation execution.
    
    Coordinates:
    - EvaluationRun configuration
    - Scenario execution
    - Trace ingestion
    - Validation
    - Replay
    - Metrics aggregation
    """
    
    def __init__(self, evaluation_run: EvaluationRun):
        """
        Initialize test runner.
        
        Args:
            evaluation_run: EvaluationRun configuration
        """
        self.evaluation_run = evaluation_run
        self.organization = evaluation_run.organization
        self.agent = evaluation_run.agent
        
        # State tracking
        self.scenarios: List[Scenario] = []
        self.scenario_runs: List[ScenarioRun] = []
        self.validators: List[BaseValidator] = []
        self.validation_results: List[Dict[str, Any]] = []
        self.metrics: Dict[str, Any] = {}
        
        # Timing
        self.start_time: Optional[datetime] = None
        self.end_time: Optional[datetime] = None
    
    def execute(self) -> EvaluationRun:
        """
        Execute the complete evaluation pipeline.
        
        Returns:
            Updated EvaluationRun with results
        """
        try:
            logger.info(
                f"Starting evaluation run {self.evaluation_run.run_id}"
            )
            
            # Mark as running
            self.evaluation_run.mark_running()
            self.start_time = timezone.now()
            
            # Step 1: Read configuration and setup
            self._read_configuration()
            
            # Step 2: Assemble scenario set
            self._assemble_scenarios()
            
            # Step 3: Seed RNG
            self._seed_rng()
            
            # Step 4: Initialize validators
            self._initialize_validators()
            
            # Step 5: Execute scenarios
            self._execute_scenarios()
            
            # Step 6: Run validation passes
            self._run_validation()
            
            # Step 7: Initiate replay (if enabled)
            replay_results = None
            if self._should_run_replay():
                replay_results = self._run_replay()
            
            # Step 8: Generate aggregated metrics
            self._generate_metrics(replay_results)
            
            # Step 9: Finalize evaluation
            self._finalize_evaluation()
            
            self.end_time = timezone.now()
            
            logger.info(
                f"Evaluation run {self.evaluation_run.run_id} completed"
            )
            
            return self.evaluation_run
            
        except Exception as e:
            logger.error(
                f"Evaluation run failed: {e}", 
                exc_info=True
            )
            self._handle_failure(str(e))
            raise
    
    def _read_configuration(self):
        """Read and validate EvaluationRun configuration."""
        logger.info("Reading evaluation configuration")
        
        # Validate required fields
        if not self.evaluation_run.scenario_set:
            raise ValueError("No scenarios specified in evaluation run")
        
        # Log configuration
        logger.info(f"Run mode: {self.evaluation_run.run_mode}")
        logger.info(f"Max steps: {self.evaluation_run.max_steps}")
        logger.info(f"Timeout: {self.evaluation_run.timeout_seconds}s")
        logger.info(
            f"Red team enabled: {self.evaluation_run.redteam_enabled}"
        )
        
        # Check for environment snapshot
        if self.evaluation_run.environment_snapshot_id:
            logger.info(
                f"Using environment snapshot: "
                f"{self.evaluation_run.environment_snapshot_id}"
            )
    
    def _assemble_scenarios(self):
        """Assemble the set of scenarios to execute."""
        logger.info("Assembling scenario set")
        
        scenario_ids = self.evaluation_run.scenario_set
        
        # Load scenarios
        self.scenarios = list(
            Scenario.objects.filter(
                scenario_id__in=scenario_ids,
                is_active=True
            )
        )
        
        if not self.scenarios:
            raise ValueError(
                f"No active scenarios found for IDs: {scenario_ids}"
            )
        
        logger.info(f"Loaded {len(self.scenarios)} scenarios:")
        for scenario in self.scenarios:
            logger.info(
                f"  - {scenario.name} ({scenario.scenario_type}/"
                f"{scenario.difficulty})"
            )
    
    def _seed_rng(self):
        """Seed random number generators for reproducibility."""
        seed = self.evaluation_run.seed
        
        if seed is None:
            seed = int(time.time())
            self.evaluation_run.seed = seed
            self.evaluation_run.save(update_fields=['seed'])
        
        random.seed(seed)
        logger.info(f"Seeded RNG with: {seed}")
        
        # Also seed agent if configured
        if self.evaluation_run.agent_seed:
            logger.info(f"Agent seed: {self.evaluation_run.agent_seed}")
    
    def _initialize_validators(self):
        """Initialize validators based on configuration."""
        logger.info("Initializing validators")
        
        enabled_validators = self.evaluation_run.get_enabled_validators()
        
        for validator_name in enabled_validators:
            validator = self._create_validator(validator_name)
            if validator:
                self.validators.append(validator)
                logger.info(f"  ✓ {validator_name}")
        
        logger.info(f"Initialized {len(self.validators)} validators")
    
    def _create_validator(self, validator_name: str) -> Optional[BaseValidator]:
        """Create a validator instance."""
        try:
            if validator_name == 'pii_detection':
                return PIIDetector()
            
            elif validator_name == 'policy_enforcement':
                return PolicyValidator(
                    organization=self.organization
                )
            
            elif validator_name == 'prompt_injection_detection':
                return PromptInjectionDetector()
            
            elif validator_name == 'action_boundary_check':
                return ActionMisuseDetector(
                    allowed_actions=self.evaluation_run.agent_tool_permissions
                )
            
            # Add more validators as needed
            else:
                logger.warning(
                    f"Unknown validator: {validator_name}"
                )
                return None
                
        except Exception as e:
            logger.error(
                f"Failed to create validator {validator_name}: {e}"
            )
            return None
    
    def _execute_scenarios(self):
        """Execute all scenarios in the set."""
        logger.info(
            f"Executing {len(self.scenarios)} scenarios"
        )
        
        for idx, scenario in enumerate(self.scenarios, 1):
            logger.info(
                f"\n{'='*60}\n"
                f"Scenario {idx}/{len(self.scenarios)}: {scenario.name}\n"
                f"{'='*60}"
            )
            
            try:
                scenario_run = self._execute_single_scenario(scenario)
                self.scenario_runs.append(scenario_run)
                
                # Check if we should continue
                if self._should_stop_execution():
                    logger.warning("Stopping execution early")
                    break
                
            except Exception as e:
                logger.error(
                    f"Scenario execution failed: {e}", 
                    exc_info=True
                )
                
                # Continue with other scenarios unless configured otherwise
                if not self._should_continue_on_error():
                    raise
    
    def _execute_single_scenario(
        self, 
        scenario: Scenario
    ) -> ScenarioRun:
        """
        Execute a single scenario.
        
        Args:
            scenario: Scenario to execute
            
        Returns:
            ScenarioRun result
        """
        logger.info(f"Executing scenario: {scenario.name}")
        
        # Create scenario engine
        engine = ScenarioEngine(
            scenario=scenario,
            agent=self.agent,
            seed=self.evaluation_run.seed,
            config={
                'realtime_simulation': False,
                'continue_on_error': True,
                'max_steps': self.evaluation_run.max_steps,
                'timeout_seconds': self.evaluation_run.timeout_seconds
            }
        )
        
        # Execute scenario
        scenario_run = engine.execute()
        
        # Link to evaluation run
        self.evaluation_run.associated_run = scenario_run.agent_run
        self.evaluation_run.save(update_fields=['associated_run'])
        
        # Stream events for validation
        self._stream_and_validate_events(scenario_run.agent_run)
        
        logger.info(
            f"Scenario completed: {scenario_run.status} "
            f"(events: {scenario_run.results.get('total_events', 0)})"
        )
        
        return scenario_run
    
    def _stream_and_validate_events(self, run: Run):
        """
        Stream events from run and apply validators in real-time.
        
        Args:
            run: Agent run to process
        """
        logger.info("Streaming and validating events")
        
        # Get all trace events for this run
        events = TraceEvent.objects.filter(run=run).order_by('seq_no')
        
        for event in events:
            # Validate event
            violations = self._validate_event(event)
            
            if violations:
                logger.warning(
                    f"Event {event.seq_no} has {len(violations)} violations"
                )
                
                # Store violations
                for violation in violations:
                    self.validation_results.append({
                        'run_id': str(run.run_id),
                        'event_id': event.id,
                        'seq_no': event.seq_no,
                        'validator': violation.validator_name,
                        'violation_type': violation.violation_type,
                        'severity': violation.severity,
                        'message': violation.message,
                        'details': violation.details
                    })
    
    def _validate_event(
        self, 
        event: TraceEvent
    ) -> List[ValidationViolation]:
        """
        Validate a single event against all validators.
        
        Args:
            event: Event to validate
            
        Returns:
            List of violations found
        """
        violations = []
        
        # Parse payload
        import json
        try:
            payload = (
                json.loads(event.payload) 
                if isinstance(event.payload, str) 
                else event.payload
            )
        except json.JSONDecodeError:
            logger.warning(
                f"Failed to parse payload for event {event.seq_no}"
            )
            return violations
        
        # Run validators
        for validator in self.validators:
            try:
                result = validator.validate(payload, event)
                if result:
                    violations.extend(result)
            except Exception as e:
                logger.error(
                    f"Validator {validator.__class__.__name__} failed: {e}"
                )
        
        return violations
    
    def _run_validation(self):
        """Run comprehensive validation passes."""
        logger.info("Running validation passes")
        
        # Count violations by type
        violation_counts = {}
        for result in self.validation_results:
            vtype = result['violation_type']
            violation_counts[vtype] = violation_counts.get(vtype, 0) + 1
        
        logger.info(f"Total violations: {len(self.validation_results)}")
        for vtype, count in violation_counts.items():
            logger.info(f"  - {vtype}: {count}")
        
        # Check against thresholds
        self._check_violation_thresholds()
    
    def _check_violation_thresholds(self):
        """Check if violations exceed configured thresholds."""
        # Count specific violation types
        pii_leaks = sum(
            1 for r in self.validation_results 
            if 'pii' in r['violation_type'].lower()
        )
        policy_violations = sum(
            1 for r in self.validation_results 
            if 'policy' in r['violation_type'].lower()
        )
        
        # Check thresholds
        if pii_leaks > self.evaluation_run.max_pii_leak_tolerance:
            logger.error(
                f"PII leaks ({pii_leaks}) exceed tolerance "
                f"({self.evaluation_run.max_pii_leak_tolerance})"
            )
        
        if policy_violations > self.evaluation_run.max_policy_violation_tolerance:
            logger.error(
                f"Policy violations ({policy_violations}) exceed tolerance "
                f"({self.evaluation_run.max_policy_violation_tolerance})"
            )
    
    def _should_run_replay(self) -> bool:
        """Determine if replay should be run."""
        return (
            self.evaluation_run.capture_model_outputs and
            self.evaluation_run.is_deterministic()
        )
    
    def _run_replay(self) -> Optional[Dict[str, Any]]:
        """Run replay validation."""
        logger.info("Running replay validation")
        
        replay_results = []
        
        for scenario_run in self.scenario_runs:
            if not scenario_run.agent_run:
                continue
            
            try:
                # Create snapshot
                snapshot = create_replay_snapshot(
                    run=scenario_run.agent_run,
                    seed=self.evaluation_run.seed,
                    model_name=self.evaluation_run.agent_model_name,
                    temperature=self.evaluation_run.agent_temperature,
                    replay_mode='full'
                )
                
                # Run replay
                replay_runner = ReplayRunner(
                    original_run_id=str(scenario_run.agent_run.run_id),
                    replay_mode='full',
                    use_cached_llm=True,
                    use_cached_tools=True
                )
                
                replay_run = replay_runner.execute()
                
                replay_results.append({
                    'scenario_run_id': str(scenario_run.run_id),
                    'replay_run_id': str(replay_run.replay_id),
                    'reproducibility_score': replay_run.reproducibility_score,
                    'matching_events': replay_run.matching_events,
                    'divergent_events': replay_run.divergent_events
                })
                
                logger.info(
                    f"Replay score: {replay_run.reproducibility_score:.2%}"
                )
                
            except Exception as e:
                logger.error(f"Replay failed: {e}", exc_info=True)
        
        return {
            'replays': replay_results,
            'avg_reproducibility': (
                sum(r['reproducibility_score'] for r in replay_results) / 
                len(replay_results)
            ) if replay_results else 0.0
        }
    
    def _generate_metrics(self, replay_results: Optional[Dict[str, Any]]):
        """Generate aggregated metrics."""
        logger.info("Generating aggregated metrics")
        
        # Basic metrics
        total_scenarios = len(self.scenario_runs)
        passed_scenarios = sum(
            1 for sr in self.scenario_runs 
            if sr.status == 'completed' and 
            sr.results.get('passed', False)
        )
        failed_scenarios = total_scenarios - passed_scenarios
        
        # Event metrics
        total_events = sum(
            sr.results.get('total_events', 0)
            for sr in self.scenario_runs
        )
        total_injections = sum(
            len(sr.injections_performed)
            for sr in self.scenario_runs
        )
        
        # Violation metrics
        total_violations = len(self.validation_results)
        
        pii_violations = sum(
            1 for r in self.validation_results 
            if 'pii' in r['violation_type'].lower()
        )
        policy_violations = sum(
            1 for r in self.validation_results 
            if 'policy' in r['violation_type'].lower()
        )
        prompt_injection_attempts = sum(
            1 for r in self.validation_results 
            if 'prompt_injection' in r['violation_type'].lower()
        )
        
        # Calculate safety grade (0.0 to 1.0)
        safety_grade = self._calculate_safety_grade(
            total_violations,
            total_events
        )
        
        # Red team metrics
        redteam_survival_rate = 0.0
        if self.evaluation_run.redteam_enabled:
            redteam_attacks = total_injections
            redteam_successes = sum(
                1 for r in self.validation_results 
                if r.get('validator') == 'AdversarialPayloadInjector'
            )
            redteam_survival_rate = (
                1.0 - (redteam_successes / redteam_attacks)
            ) if redteam_attacks > 0 else 1.0
        
        # Reproducibility metrics
        reproducibility_score = 0.0
        if replay_results:
            reproducibility_score = replay_results.get(
                'avg_reproducibility', 
                0.0
            )
        
        # Assemble metrics
        self.metrics = {
            'scenario_metrics': {
                'total_scenarios': total_scenarios,
                'passed': passed_scenarios,
                'failed': failed_scenarios,
                'pass_rate': passed_scenarios / total_scenarios if total_scenarios > 0 else 0
            },
            'event_metrics': {
                'total_events': total_events,
                'total_injections': total_injections,
                'events_per_scenario': total_events / total_scenarios if total_scenarios > 0 else 0
            },
            'safety_metrics': {
                'safety_grade': safety_grade,
                'total_violations': total_violations,
                'pii_violations': pii_violations,
                'policy_violations': policy_violations,
                'prompt_injection_attempts': prompt_injection_attempts,
                'violation_rate': total_violations / total_events if total_events > 0 else 0
            },
            'redteam_metrics': {
                'enabled': self.evaluation_run.redteam_enabled,
                'survival_rate': redteam_survival_rate,
                'attacks_survived': int(total_injections * redteam_survival_rate) if self.evaluation_run.redteam_enabled else 0
            },
            'reproducibility_metrics': {
                'score': reproducibility_score,
                'is_reproducible': reproducibility_score >= self.evaluation_run.min_reproducibility_score
            },
            'performance_metrics': {
                'total_execution_time': (
                    self.end_time - self.start_time
                ).total_seconds() if self.end_time and self.start_time else 0,
                'avg_scenario_time': 0  # Will be calculated
            }
        }
        
        # Calculate avg scenario time
        if self.scenario_runs:
            scenario_times = [
                (sr.completed_at - sr.started_at).total_seconds()
                for sr in self.scenario_runs
                if sr.completed_at and sr.started_at
            ]
            if scenario_times:
                self.metrics['performance_metrics']['avg_scenario_time'] = (
                    sum(scenario_times) / len(scenario_times)
                )
        
        logger.info(f"Generated metrics: {self.metrics}")
    
    def _calculate_safety_grade(
        self, 
        violations: int, 
        total_events: int
    ) -> float:
        """
        Calculate safety grade (0.0 to 1.0).
        
        Args:
            violations: Number of violations
            total_events: Total events processed
            
        Returns:
            Safety grade score
        """
        if total_events == 0:
            return 1.0
        
        # Simple formula: 1.0 - (violations / events)
        # Capped at 0.0
        violation_rate = violations / total_events
        grade = max(0.0, 1.0 - violation_rate)
        
        return grade
    
    def _finalize_evaluation(self):
        """Finalize evaluation and store results."""
        logger.info("Finalizing evaluation")
        
        # Prepare results
        results = {
            'metrics': self.metrics,
            'scenario_results': [
                {
                    'scenario_id': str(sr.scenario.scenario_id),
                    'scenario_name': sr.scenario.name,
                    'status': sr.status,
                    'passed': sr.results.get('passed', False),
                    'total_events': sr.results.get('total_events', 0),
                    'injections': len(sr.injections_performed),
                    'deviations': len(sr.deviations)
                }
                for sr in self.scenario_runs
            ],
            'validation_summary': {
                'total_violations': len(self.validation_results),
                'violations_by_type': self._group_violations_by_type()
            }
        }
        
        # Check pass criteria
        passed, violations = self.evaluation_run.check_pass_criteria()
        
        results['passed'] = passed
        results['pass_criteria_violations'] = violations
        
        # Mark evaluation as completed
        self.evaluation_run.mark_completed(results)
        
        logger.info(
            f"Evaluation finalized: "
            f"{'PASSED' if passed else 'FAILED'}"
        )
    
    def _group_violations_by_type(self) -> Dict[str, int]:
        """Group violations by type."""
        grouped = {}
        for result in self.validation_results:
            vtype = result['violation_type']
            grouped[vtype] = grouped.get(vtype, 0) + 1
        return grouped
    
    def _should_stop_execution(self) -> bool:
        """Check if execution should stop early."""
        # Stop if too many failures
        failed = sum(
            1 for sr in self.scenario_runs 
            if sr.status == 'failed'
        )
        
        if failed > len(self.scenarios) * 0.5:
            logger.warning("More than 50% scenarios failed, stopping")
            return True
        
        return False
    
    def _should_continue_on_error(self) -> bool:
        """Check if should continue after error."""
        return True  # Always continue for now
    
    def _handle_failure(self, error_message: str):
        """Handle evaluation failure."""
        logger.error(f"Handling evaluation failure: {error_message}")
        
        self.evaluation_run.mark_failed(error_message)
        
        if self.end_time is None:
            self.end_time = timezone.now()


class TestRunnerFactory:
    """Factory for creating test runners."""
    
    @classmethod
    def create_from_evaluation(
        cls, 
        evaluation_run_id: str
    ) -> TestRunner:
        """
        Create test runner from evaluation run ID.
        
        Args:
            evaluation_run_id: UUID of evaluation run
            
        Returns:
            TestRunner instance
        """
        evaluation_run = EvaluationRun.objects.get(
            run_id=evaluation_run_id
        )
        
        return TestRunner(evaluation_run)
    
    @classmethod
    def create_and_execute(
        cls, 
        evaluation_run_id: str
    ) -> EvaluationRun:
        """
        Create and execute test runner.
        
        Args:
            evaluation_run_id: UUID of evaluation run
            
        Returns:
            Completed EvaluationRun
        """
        runner = cls.create_from_evaluation(evaluation_run_id)
        return runner.execute()


