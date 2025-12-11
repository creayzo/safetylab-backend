"""
Scenario Engine (Orchestrator)

The brain that orchestrates scenario execution:
- Runs scripted scenarios
- Injects user messages
- Triggers adversarial payloads at defined timestamps
- Simulates tool errors
- Simulates system conditions (timeouts, concurrency, file uploads)
- Coordinates agent runs
- Executes tests and collects results
"""

import logging
import time
import random
import asyncio
from typing import Dict, Any, List, Optional, Callable
from datetime import datetime, timedelta
from django.utils import timezone
from django.db import transaction

from api.models import Agent, Run, TraceEvent, EvaluationRun
from api.scenario_models import Scenario, ScenarioRun, InjectionTemplate
from api.scenario_injectors import InjectorFactory, BaseInjector

logger = logging.getLogger(__name__)


class ScenarioEngine:
    """
    Main orchestrator for scenario-based agent testing.
    
    Responsibilities:
    - Load and parse scenarios
    - Initialize environment
    - Execute scenario scripts
    - Coordinate injections
    - Monitor agent behavior
    - Collect and analyze results
    """
    
    def __init__(
        self,
        scenario: Scenario,
        agent: Agent,
        seed: Optional[int] = None,
        config: Optional[Dict[str, Any]] = None
    ):
        """
        Initialize scenario engine.
        
        Args:
            scenario: Scenario to execute
            agent: Agent to test
            seed: Random seed for reproducibility
            config: Additional configuration
        """
        self.scenario = scenario
        self.agent = agent
        self.seed = seed or int(time.time())
        self.config = config or {}
        
        # Initialize random
        random.seed(self.seed)
        
        # State tracking
        self.scenario_run: Optional[ScenarioRun] = None
        self.agent_run: Optional[Run] = None
        self.injectors: List[BaseInjector] = []
        self.event_log: List[Dict[str, Any]] = []
        self.context: Dict[str, Any] = {}
        
        # Execution control
        self.start_time: Optional[datetime] = None
        self.current_step: int = 0
        self.is_running: bool = False
        self.stop_requested: bool = False
    
    def execute(self) -> ScenarioRun:
        """
        Execute the scenario.
        
        Returns:
            ScenarioRun instance with results
        """
        try:
            logger.info(
                f"Starting scenario execution: {self.scenario.name}"
            )
            
            # Step 1: Initialize
            self._initialize()
            
            # Step 2: Setup environment
            self._setup_environment()
            
            # Step 3: Initialize injectors
            self._initialize_injectors()
            
            # Step 4: Execute scenario script
            self._execute_script()
            
            # Step 5: Finalize and collect results
            self._finalize()
            
            logger.info(
                f"Scenario execution completed: {self.scenario.name}"
            )
            return self.scenario_run
            
        except Exception as e:
            logger.error(
                f"Scenario execution failed: {e}", 
                exc_info=True
            )
            self._handle_failure(str(e))
            raise
    
    def _initialize(self):
        """Initialize scenario run."""
        logger.info("Initializing scenario run")
        
        # Create agent run
        self.agent_run = Run.objects.create(
            agent=self.agent,
            scenario_id=str(self.scenario.scenario_id),
            seed=self.seed,
            status='running'
        )
        
        # Create scenario run
        self.scenario_run = ScenarioRun.objects.create(
            scenario=self.scenario,
            agent_run=self.agent_run,
            seed=self.seed,
            status='running',
            started_at=timezone.now()
        )
        
        # Initialize context
        self.context = {
            'scenario_id': str(self.scenario.scenario_id),
            'run_id': str(self.agent_run.run_id),
            'agent_id': self.agent.id,
            'seed': self.seed,
            'start_time': timezone.now(),
            'current_timestamp': 0,
            'event_count': 0,
            'last_action': None,
            'current_action': None,
            'variables': {},
        }
        
        # Load initial state
        initial_state = self.scenario.initial_state or {}
        self.context['variables'].update(initial_state)
        
        self.is_running = True
        self.start_time = timezone.now()
    
    def _setup_environment(self):
        """Setup test environment."""
        logger.info("Setting up test environment")
        
        # Set random seed
        random.seed(self.seed)
        
        # Initialize environment snapshot if specified
        snapshot_config = self.scenario.config.get('environment_snapshot')
        if snapshot_config:
            logger.info(f"Using environment snapshot: {snapshot_config}")
            # TODO: Load environment snapshot
        
        # Apply environment variables
        env_vars = self.scenario.config.get('environment_variables', {})
        for key, value in env_vars.items():
            self.context['variables'][key] = value
        
        logger.info("Environment setup complete")
    
    def _initialize_injectors(self):
        """Initialize all injectors from scenario configuration."""
        logger.info("Initializing injectors")
        
        injection_points = self.scenario.injection_points or []
        
        for injection_config in injection_points:
            injection_type = injection_config.get('type')
            
            try:
                injector = InjectorFactory.create_injector(
                    injection_type,
                    injection_config
                )
                self.injectors.append(injector)
                logger.debug(f"Initialized injector: {injection_type}")
                
            except Exception as e:
                logger.error(
                    f"Failed to initialize injector {injection_type}: {e}"
                )
        
        logger.info(f"Initialized {len(self.injectors)} injectors")
    
    def _execute_script(self):
        """Execute scenario script."""
        logger.info("Executing scenario script")
        
        script = self.scenario.script or []
        
        for step_idx, step in enumerate(script):
            if self.stop_requested:
                logger.warning("Stop requested, halting execution")
                break
            
            self.current_step = step_idx + 1
            
            try:
                self._execute_step(step)
            except Exception as e:
                logger.error(
                    f"Step {self.current_step} failed: {e}",
                    exc_info=True
                )
                
                # Check if we should continue on error
                if not self.config.get('continue_on_error', False):
                    raise
        
        logger.info(f"Script execution complete: {len(script)} steps")
    
    def _execute_step(self, step: Dict[str, Any]):
        """
        Execute a single scenario step.
        
        Args:
            step: Step configuration
        """
        step_type = step.get('type')
        step_timestamp = step.get('timestamp', 0)
        
        logger.debug(
            f"Executing step {self.current_step}: {step_type} "
            f"at t={step_timestamp}"
        )
        
        # Update context
        self.context['current_timestamp'] = step_timestamp
        
        # Wait if needed (for real-time simulation)
        if self.config.get('realtime_simulation', False):
            self._wait_until_timestamp(step_timestamp)
        
        # Check for injections before step
        self._check_injections()
        
        # Execute step based on type
        if step_type == 'user_message':
            self._handle_user_message(step)
        
        elif step_type == 'agent_action':
            self._handle_agent_action(step)
        
        elif step_type == 'tool_call':
            self._handle_tool_call(step)
        
        elif step_type == 'system_event':
            self._handle_system_event(step)
        
        elif step_type == 'wait':
            self._handle_wait(step)
        
        elif step_type == 'assertion':
            self._handle_assertion(step)
        
        else:
            logger.warning(f"Unknown step type: {step_type}")
        
        # Update event count
        self.context['event_count'] += 1
        
        # Log event
        self.event_log.append({
            'step': self.current_step,
            'timestamp': step_timestamp,
            'type': step_type,
            'data': step
        })
    
    def _handle_user_message(self, step: Dict[str, Any]):
        """Handle user message step."""
        message = step.get('message', '')
        metadata = step.get('metadata', {})
        
        logger.info(f"User message: {message[:50]}...")
        
        # Create trace event
        event = self._create_trace_event(
            actor='user',
            event_type='user_input',
            payload={
                'text': message,
                'metadata': metadata
            }
        )
        
        # Trigger agent response (mock)
        self._trigger_agent_response(message)
    
    def _handle_agent_action(self, step: Dict[str, Any]):
        """Handle agent action step."""
        action = step.get('action')
        params = step.get('params', {})
        
        logger.info(f"Agent action: {action}")
        
        # Update context
        self.context['last_action'] = self.context.get('current_action')
        self.context['current_action'] = action
        
        # Create trace event
        event = self._create_trace_event(
            actor='agent',
            event_type='action_request',
            payload={
                'action': action,
                'params': params,
                'context': {}
            }
        )
    
    def _handle_tool_call(self, step: Dict[str, Any]):
        """Handle tool call step."""
        tool_name = step.get('tool')
        params = step.get('params', {})
        
        logger.info(f"Tool call: {tool_name}")
        
        # Check if we should inject error
        error_injection = self._check_tool_error_injection()
        
        if error_injection:
            # Inject error
            payload = {
                'status': 'error',
                'data': {
                    'error_code': error_injection.get('error_code'),
                    'error_message': error_injection.get('error_message')
                },
                'meta': {'latency_ms': error_injection.get('latency_ms', 100)}
            }
        else:
            # Normal response
            result = step.get('expected_result', {})
            payload = {
                'status': 'ok',
                'data': result,
                'meta': {'latency_ms': 100}
            }
        
        # Create trace event
        event = self._create_trace_event(
            actor='tool',
            event_type='action_response',
            payload=payload
        )
    
    def _handle_system_event(self, step: Dict[str, Any]):
        """Handle system event step."""
        event_type = step.get('event')
        data = step.get('data', {})
        
        logger.info(f"System event: {event_type}")
        
        # Create trace event
        event = self._create_trace_event(
            actor='system',
            event_type='system_event',
            payload={
                'event': event_type,
                'data': data
            }
        )
    
    def _handle_wait(self, step: Dict[str, Any]):
        """Handle wait step."""
        duration = step.get('duration', 1.0)
        
        logger.debug(f"Waiting {duration} seconds")
        
        if self.config.get('realtime_simulation', False):
            time.sleep(duration)
    
    def _handle_assertion(self, step: Dict[str, Any]):
        """Handle assertion step."""
        assertion_type = step.get('assertion_type')
        expected = step.get('expected')
        actual_path = step.get('actual_path')
        
        logger.info(f"Assertion: {assertion_type}")
        
        # Get actual value from context
        actual = self._get_context_value(actual_path)
        
        # Compare
        passed = False
        if assertion_type == 'equals':
            passed = actual == expected
        elif assertion_type == 'contains':
            passed = expected in actual
        elif assertion_type == 'greater_than':
            passed = actual > expected
        elif assertion_type == 'less_than':
            passed = actual < expected
        
        if not passed:
            error_msg = (
                f"Assertion failed: {assertion_type} "
                f"expected={expected} actual={actual}"
            )
            logger.error(error_msg)
            
            # Record deviation
            self.scenario_run.deviations.append({
                'step': self.current_step,
                'type': 'assertion_failure',
                'message': error_msg,
                'expected': expected,
                'actual': actual
            })
            
            if self.config.get('fail_on_assertion', True):
                raise AssertionError(error_msg)
    
    def _check_injections(self):
        """Check if any injections should occur."""
        for injector in self.injectors:
            try:
                if injector.should_inject(self.context):
                    injection = injector.inject(self.context)
                    self._apply_injection(injection)
            except Exception as e:
                logger.error(
                    f"Injection failed: {e}", 
                    exc_info=True
                )
    
    def _apply_injection(self, injection: Dict[str, Any]):
        """Apply an injection to the scenario execution."""
        injection_type = injection.get('type')
        
        logger.info(f"Applying injection: {injection_type}")
        
        # Record injection
        self.scenario_run.injections_performed.append({
            'timestamp': timezone.now().isoformat(),
            'step': self.current_step,
            **injection
        })
        
        # Create trace event for injection
        event = self._create_trace_event(
            actor=injection.get('actor', 'redteam'),
            event_type='injection',
            payload=injection
        )
        
        # Handle injection based on type
        if injection_type == 'user_message':
            self._trigger_agent_response(injection.get('message'))
        
        elif injection_type == 'adversarial_payload':
            self._trigger_agent_response(injection.get('payload'))
    
    def _check_tool_error_injection(self) -> Optional[Dict[str, Any]]:
        """Check if tool error should be injected."""
        for injector in self.injectors:
            if injector.__class__.__name__ == 'ToolErrorInjector':
                if injector.should_inject(self.context):
                    return injector.inject(self.context)
        return None
    
    def _trigger_agent_response(self, message: str):
        """Trigger agent to respond to message (mock)."""
        logger.debug(f"Triggering agent response to: {message[:50]}...")
        
        # This would integrate with actual agent
        # For now, create a mock reasoning event
        event = self._create_trace_event(
            actor='agent',
            event_type='reasoning',
            payload={
                'goal': 'Respond to user message',
                'steps': [],
                'safety_checks': [],
                'uncertainty': 'low'
            }
        )
    
    def _create_trace_event(
        self,
        actor: str,
        event_type: str,
        payload: Dict[str, Any]
    ) -> TraceEvent:
        """Create and store a trace event."""
        seq_no = self.context['event_count'] + 1
        
        event = TraceEvent.objects.create(
            run=self.agent_run,
            seq_no=seq_no,
            timestamp=timezone.now(),
            actor=actor,
            type=event_type,
            payload=payload
        )
        
        return event
    
    def _wait_until_timestamp(self, target_timestamp: float):
        """Wait until target timestamp in realtime simulation."""
        if not self.start_time:
            return
        
        elapsed = (timezone.now() - self.start_time).total_seconds()
        wait_time = target_timestamp - elapsed
        
        if wait_time > 0:
            time.sleep(wait_time)
    
    def _get_context_value(self, path: str) -> Any:
        """Get value from context using dot notation path."""
        parts = path.split('.')
        value = self.context
        
        for part in parts:
            if isinstance(value, dict):
                value = value.get(part)
            else:
                return None
        
        return value
    
    def _finalize(self):
        """Finalize scenario run and collect results."""
        logger.info("Finalizing scenario run")
        
        # Mark agent run as completed
        self.agent_run.status = 'success'
        self.agent_run.end_ts = timezone.now()
        self.agent_run.save()
        
        # Collect results
        results = self._collect_results()
        
        # Update scenario run
        self.scenario_run.status = 'completed'
        self.scenario_run.completed_at = timezone.now()
        self.scenario_run.results = results
        self.scenario_run.save()
        
        self.is_running = False
        
        logger.info("Scenario run finalized")
    
    def _collect_results(self) -> Dict[str, Any]:
        """Collect and analyze scenario results."""
        logger.info("Collecting results")
        
        # Get all trace events
        events = TraceEvent.objects.filter(
            run=self.agent_run
        ).order_by('seq_no')
        
        # Analyze results
        results = {
            'scenario_name': self.scenario.name,
            'scenario_type': self.scenario.scenario_type,
            'seed': self.seed,
            'execution_time_seconds': (
                timezone.now() - self.start_time
            ).total_seconds() if self.start_time else 0,
            'total_steps': self.current_step,
            'total_events': events.count(),
            'injections_count': len(
                self.scenario_run.injections_performed
            ),
            'deviations_count': len(self.scenario_run.deviations),
            'events_by_type': {},
            'events_by_actor': {},
        }
        
        # Count events by type and actor
        for event in events:
            # By type
            event_type = event.type
            results['events_by_type'][event_type] = (
                results['events_by_type'].get(event_type, 0) + 1
            )
            
            # By actor
            actor = event.actor
            results['events_by_actor'][actor] = (
                results['events_by_actor'].get(actor, 0) + 1
            )
        
        # Check expected outcomes
        expected_outcomes = self.scenario.expected_outcomes or {}
        results['outcome_checks'] = self._check_expected_outcomes(
            expected_outcomes,
            events
        )
        
        # Calculate pass/fail
        results['passed'] = (
            len(self.scenario_run.deviations) == 0 and
            results['outcome_checks'].get('all_passed', False)
        )
        
        return results
    
    def _check_expected_outcomes(
        self,
        expected_outcomes: Dict[str, Any],
        events
    ) -> Dict[str, Any]:
        """Check if expected outcomes were met."""
        checks = {'all_passed': True, 'checks': []}
        
        # Check event count expectations
        if 'min_events' in expected_outcomes:
            min_events = expected_outcomes['min_events']
            actual = events.count()
            passed = actual >= min_events
            
            checks['checks'].append({
                'type': 'min_events',
                'expected': min_events,
                'actual': actual,
                'passed': passed
            })
            
            if not passed:
                checks['all_passed'] = False
        
        # Check for specific event types
        if 'required_events' in expected_outcomes:
            for required_type in expected_outcomes['required_events']:
                exists = events.filter(type=required_type).exists()
                
                checks['checks'].append({
                    'type': 'required_event',
                    'event_type': required_type,
                    'passed': exists
                })
                
                if not exists:
                    checks['all_passed'] = False
        
        # Check for forbidden events
        if 'forbidden_events' in expected_outcomes:
            for forbidden_type in expected_outcomes['forbidden_events']:
                exists = events.filter(type=forbidden_type).exists()
                passed = not exists
                
                checks['checks'].append({
                    'type': 'forbidden_event',
                    'event_type': forbidden_type,
                    'passed': passed
                })
                
                if not passed:
                    checks['all_passed'] = False
        
        return checks
    
    def _handle_failure(self, error_message: str):
        """Handle scenario execution failure."""
        logger.error(f"Handling failure: {error_message}")
        
        if self.agent_run:
            self.agent_run.status = 'failed'
            self.agent_run.end_ts = timezone.now()
            self.agent_run.save()
        
        if self.scenario_run:
            self.scenario_run.status = 'failed'
            self.scenario_run.completed_at = timezone.now()
            self.scenario_run.error_message = error_message
            self.scenario_run.save()
        
        self.is_running = False
    
    def stop(self):
        """Request scenario execution to stop."""
        logger.info("Stop requested")
        self.stop_requested = True


