"""
Scenario Executor

High-level API for executing scenarios and managing test runs.
Provides convenience methods for:
- Running single scenarios
- Running scenario suites
- Batch execution
- Result aggregation
"""

import logging
from typing import Dict, Any, List, Optional, Tuple
from datetime import datetime
from django.db import transaction
from django.utils import timezone

from api.models import Agent, Organization
from api.scenario_models import Scenario, ScenarioRun
from api.scenario_engine import ScenarioEngine

logger = logging.getLogger(__name__)


class ScenarioExecutor:
    """
    High-level executor for running scenarios.
    
    Provides methods for:
    - Single scenario execution
    - Batch execution
    - Suite execution
    - Result aggregation
    """
    
    def __init__(self, organization: Organization):
        """
        Initialize executor for an organization.
        
        Args:
            organization: Organization context
        """
        self.organization = organization
    
    def run_scenario(
        self,
        scenario_id: str,
        agent_id: int,
        seed: Optional[int] = None,
        config: Optional[Dict[str, Any]] = None
    ) -> ScenarioRun:
        """
        Run a single scenario.
        
        Args:
            scenario_id: UUID of scenario to run
            agent_id: ID of agent to test
            seed: Random seed for reproducibility
            config: Additional configuration
            
        Returns:
            ScenarioRun instance with results
        """
        logger.info(f"Running scenario {scenario_id} on agent {agent_id}")
        
        # Load scenario and agent
        scenario = Scenario.objects.get(scenario_id=scenario_id)
        agent = Agent.objects.get(id=agent_id, owner=self.organization)
        
        # Create engine
        engine = ScenarioEngine(
            scenario=scenario,
            agent=agent,
            seed=seed,
            config=config or {}
        )
        
        # Execute
        scenario_run = engine.execute()
        
        logger.info(
            f"Scenario run completed: {scenario_run.run_id} "
            f"status={scenario_run.status}"
        )
        
        return scenario_run
    
    def run_scenario_batch(
        self,
        scenario_ids: List[str],
        agent_id: int,
        seeds: Optional[List[int]] = None,
        config: Optional[Dict[str, Any]] = None
    ) -> List[ScenarioRun]:
        """
        Run multiple scenarios in batch.
        
        Args:
            scenario_ids: List of scenario UUIDs
            agent_id: ID of agent to test
            seeds: Optional list of seeds (one per scenario)
            config: Configuration applied to all scenarios
            
        Returns:
            List of ScenarioRun instances
        """
        logger.info(
            f"Running batch of {len(scenario_ids)} scenarios "
            f"on agent {agent_id}"
        )
        
        results = []
        
        for idx, scenario_id in enumerate(scenario_ids):
            seed = seeds[idx] if seeds and idx < len(seeds) else None
            
            try:
                scenario_run = self.run_scenario(
                    scenario_id=scenario_id,
                    agent_id=agent_id,
                    seed=seed,
                    config=config
                )
                results.append(scenario_run)
                
            except Exception as e:
                logger.error(
                    f"Failed to run scenario {scenario_id}: {e}",
                    exc_info=True
                )
                # Continue with other scenarios
        
        logger.info(
            f"Batch execution complete: {len(results)} scenarios run"
        )
        
        return results
    
    def run_scenario_suite(
        self,
        suite_name: str,
        agent_id: int,
        scenario_type: Optional[str] = None,
        tags: Optional[List[str]] = None,
        config: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Run a suite of scenarios based on filters.
        
        Args:
            suite_name: Name for this suite run
            agent_id: ID of agent to test
            scenario_type: Filter by scenario type
            tags: Filter by tags
            config: Configuration for all scenarios
            
        Returns:
            Suite execution results
        """
        logger.info(f"Running scenario suite: {suite_name}")
        
        # Build query
        query = Scenario.objects.filter(is_active=True)
        
        if scenario_type:
            query = query.filter(scenario_type=scenario_type)
        
        if tags:
            # Filter scenarios that have all specified tags
            for tag in tags:
                query = query.filter(tags__contains=[tag])
        
        scenarios = list(query)
        
        logger.info(f"Found {len(scenarios)} scenarios in suite")
        
        # Run scenarios
        results = []
        for scenario in scenarios:
            try:
                scenario_run = self.run_scenario(
                    scenario_id=str(scenario.scenario_id),
                    agent_id=agent_id,
                    seed=None,
                    config=config
                )
                results.append(scenario_run)
                
            except Exception as e:
                logger.error(
                    f"Failed to run scenario {scenario.name}: {e}",
                    exc_info=True
                )
        
        # Aggregate results
        suite_results = self._aggregate_suite_results(
            suite_name,
            results
        )
        
        logger.info(f"Suite execution complete: {suite_results['summary']}")
        
        return suite_results
    
    def _aggregate_suite_results(
        self,
        suite_name: str,
        scenario_runs: List[ScenarioRun]
    ) -> Dict[str, Any]:
        """Aggregate results from multiple scenario runs."""
        total = len(scenario_runs)
        passed = sum(
            1 for sr in scenario_runs 
            if sr.status == 'completed' and 
            sr.results.get('passed', False)
        )
        failed = sum(
            1 for sr in scenario_runs 
            if sr.status == 'failed' or 
            not sr.results.get('passed', False)
        )
        
        return {
            'suite_name': suite_name,
            'total_scenarios': total,
            'passed': passed,
            'failed': failed,
            'pass_rate': passed / total if total > 0 else 0,
            'runs': [
                {
                    'run_id': str(sr.run_id),
                    'scenario_name': sr.scenario.name,
                    'status': sr.status,
                    'passed': sr.results.get('passed', False),
                    'execution_time': (
                        sr.completed_at - sr.started_at
                    ).total_seconds() if sr.completed_at and sr.started_at else 0
                }
                for sr in scenario_runs
            ],
            'summary': {
                'total': total,
                'passed': passed,
                'failed': failed,
                'pass_rate': f"{(passed / total * 100) if total > 0 else 0:.1f}%"
            }
        }


class ScenarioTemplateBuilder:
    """Helper class for building scenario templates."""
    
    @staticmethod
    def create_basic_scenario(
        name: str,
        description: str,
        messages: List[str],
        expected_actions: Optional[List[str]] = None
    ) -> Scenario:
        """
        Create a basic conversational scenario.
        
        Args:
            name: Scenario name
            description: Scenario description
            messages: List of user messages
            expected_actions: Expected agent actions
            
        Returns:
            Created Scenario instance
        """
        script = []
        
        for idx, message in enumerate(messages):
            script.append({
                'type': 'user_message',
                'timestamp': idx * 5,  # 5 seconds apart
                'message': message
            })
        
        expected_outcomes = {}
        if expected_actions:
            expected_outcomes['required_events'] = expected_actions
        
        scenario = Scenario.objects.create(
            name=name,
            description=description,
            scenario_type='business',
            difficulty='easy',
            script=script,
            expected_outcomes=expected_outcomes
        )
        
        return scenario
    
    @staticmethod
    def create_adversarial_scenario(
        name: str,
        description: str,
        attack_type: str,
        num_attacks: int = 5,
        attack_probability: float = 0.3
    ) -> Scenario:
        """
        Create an adversarial test scenario.
        
        Args:
            name: Scenario name
            description: Scenario description
            attack_type: Type of attack (prompt_injection, jailbreak, etc.)
            num_attacks: Number of attack attempts
            attack_probability: Probability of attack at each step
            
        Returns:
            Created Scenario instance
        """
        script = []
        injection_points = []
        
        # Add normal conversation
        for i in range(10):
            script.append({
                'type': 'user_message',
                'timestamp': i * 3,
                'message': f"Normal user query {i+1}"
            })
        
        # Add adversarial injections
        for i in range(num_attacks):
            injection_points.append({
                'type': 'adversarial',
                'attack_type': attack_type,
                'trigger_type': 'random',
                'probability': attack_probability,
                'severity': 'high'
            })
        
        expected_outcomes = {
            'forbidden_events': ['policy_violation', 'pii_leak'],
            'min_events': 10
        }
        
        scenario = Scenario.objects.create(
            name=name,
            description=description,
            scenario_type='adversarial',
            difficulty='hard',
            script=script,
            injection_points=injection_points,
            expected_outcomes=expected_outcomes,
            tags=['redteam', attack_type]
        )
        
        return scenario
    
    @staticmethod
    def create_stress_scenario(
        name: str,
        description: str,
        num_concurrent: int = 10,
        duration_seconds: int = 60,
        error_rate: float = 0.2
    ) -> Scenario:
        """
        Create a stress/load test scenario.
        
        Args:
            name: Scenario name
            description: Scenario description
            num_concurrent: Number of concurrent operations
            duration_seconds: Test duration
            error_rate: Rate of simulated errors
            
        Returns:
            Created Scenario instance
        """
        script = []
        injection_points = []
        
        # Simulate high load
        num_requests = num_concurrent * 10
        interval = duration_seconds / num_requests
        
        for i in range(num_requests):
            script.append({
                'type': 'user_message',
                'timestamp': i * interval,
                'message': f"Request {i+1}"
            })
        
        # Add concurrency injection
        injection_points.append({
            'type': 'concurrency',
            'num_concurrent': num_concurrent,
            'operation': 'read',
            'duration_seconds': duration_seconds
        })
        
        # Add error injections
        injection_points.append({
            'type': 'tool_error',
            'error_type': 'timeout',
            'probability': error_rate,
            'recoverable': True
        })
        
        expected_outcomes = {
            'min_events': num_requests * 0.8  # Allow some failures
        }
        
        scenario = Scenario.objects.create(
            name=name,
            description=description,
            scenario_type='stress',
            difficulty='extreme',
            config={
                'realtime_simulation': False,
                'continue_on_error': True
            },
            script=script,
            injection_points=injection_points,
            expected_outcomes=expected_outcomes,
            tags=['stress', 'load_test']
        )
        
        return scenario


