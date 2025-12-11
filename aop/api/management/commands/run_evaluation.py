"""
Management command to execute evaluation runs.

Usage:
    python manage.py run_evaluation --run-id <uuid>
    python manage.py run_evaluation --create --agent <id> --scenarios <ids>
"""

from django.core.management.base import BaseCommand, CommandError
from django.utils import timezone
from api.models import Organization, Agent, EvaluationRun
from api.scenario_models import Scenario
from api.test_runner import TestRunnerFactory
import json


class Command(BaseCommand):
    help = 'Execute evaluation runs'

    def add_arguments(self, parser):
        parser.add_argument(
            '--run-id',
            type=str,
            help='Evaluation run ID to execute'
        )
        parser.add_argument(
            '--create',
            action='store_true',
            help='Create a new evaluation run'
        )
        parser.add_argument(
            '--agent',
            type=int,
            help='Agent ID (required for --create)'
        )
        parser.add_argument(
            '--scenarios',
            type=str,
            help='Comma-separated scenario IDs (required for --create)'
        )
        parser.add_argument(
            '--org',
            type=int,
            help='Organization ID (optional)'
        )
        parser.add_argument(
            '--redteam',
            action='store_true',
            help='Enable red team testing'
        )
        parser.add_argument(
            '--redteam-level',
            type=str,
            choices=['low', 'medium', 'high', 'extreme'],
            default='medium',
            help='Red team attack level'
        )
        parser.add_argument(
            '--seed',
            type=int,
            help='Random seed for reproducibility'
        )
        parser.add_argument(
            '--async',
            dest='async_execution',
            action='store_true',
            help='Execute asynchronously using Celery'
        )
        parser.add_argument(
            '--verbose',
            action='store_true',
            help='Verbose output'
        )

    def handle(self, *args, **options):
        run_id = options.get('run_id')
        create = options.get('create')
        agent_id = options.get('agent')
        scenarios = options.get('scenarios')
        org_id = options.get('org')
        redteam = options.get('redteam')
        redteam_level = options.get('redteam_level')
        seed = options.get('seed')
        async_execution = options.get('async_execution')
        verbose = options.get('verbose')
        
        # Setup logging
        if verbose:
            import logging
            logging.basicConfig(level=logging.DEBUG)
        
        # Create or load evaluation run
        if create:
            evaluation_run = self._create_evaluation_run(
                agent_id=agent_id,
                scenario_ids=scenarios,
                org_id=org_id,
                redteam=redteam,
                redteam_level=redteam_level,
                seed=seed
            )
        elif run_id:
            try:
                evaluation_run = EvaluationRun.objects.get(
                    run_id=run_id
                )
            except EvaluationRun.DoesNotExist:
                raise CommandError(f'Evaluation run {run_id} not found')
        else:
            raise CommandError(
                'Must specify either --run-id or --create'
            )
        
        self.stdout.write(
            self.style.SUCCESS(
                f'\nEvaluation Run: {evaluation_run.run_id}'
            )
        )
        self.stdout.write(f'  Agent: {evaluation_run.agent.id}')
        self.stdout.write(
            f'  Scenarios: {len(evaluation_run.scenario_set)}'
        )
        self.stdout.write(
            f'  Red Team: {evaluation_run.redteam_enabled}'
        )
        
        # Execute
        if async_execution:
            self._execute_async(evaluation_run)
        else:
            self._execute_sync(evaluation_run)
    
    def _create_evaluation_run(
        self,
        agent_id,
        scenario_ids,
        org_id,
        redteam,
        redteam_level,
        seed
    ):
        """Create a new evaluation run."""
        if not agent_id:
            raise CommandError('--agent is required with --create')
        if not scenario_ids:
            raise CommandError('--scenarios is required with --create')
        
        # Get agent
        try:
            agent = Agent.objects.get(id=agent_id)
            org = agent.owner
            
            if org_id:
                org = Organization.objects.get(id=org_id)
        except Agent.DoesNotExist:
            raise CommandError(f'Agent {agent_id} not found')
        except Organization.DoesNotExist:
            raise CommandError(f'Organization {org_id} not found')
        
        # Parse scenario IDs
        scenario_id_list = [
            sid.strip() for sid in scenario_ids.split(',')
        ]
        
        # Verify scenarios exist
        scenarios = Scenario.objects.filter(
            scenario_id__in=scenario_id_list
        )
        if scenarios.count() != len(scenario_id_list):
            raise CommandError(
                f'Some scenarios not found: {scenario_id_list}'
            )
        
        self.stdout.write('Creating evaluation run...')
        
        # Create evaluation run
        evaluation_run = EvaluationRun.objects.create(
            organization=org,
            agent=agent,
            scenario_set=scenario_id_list,
            initiated_by='cli',
            seed=seed,
            redteam_enabled=redteam,
            redteam_level=redteam_level if redteam else 'none',
            status='pending'
        )
        
        self.stdout.write(
            self.style.SUCCESS(
                f'✓ Created evaluation run: {evaluation_run.run_id}'
            )
        )
        
        return evaluation_run
    
    def _execute_sync(self, evaluation_run):
        """Execute evaluation synchronously."""
        self.stdout.write('\nExecuting evaluation (synchronous)...')
        
        start_time = timezone.now()
        
        try:
            # Execute
            runner = TestRunnerFactory.create_from_evaluation(
                str(evaluation_run.run_id)
            )
            completed_run = runner.execute()
            
            end_time = timezone.now()
            duration = (end_time - start_time).total_seconds()
            
            # Display results
            self._display_results(completed_run, duration)
            
        except Exception as e:
            self.stdout.write(
                self.style.ERROR(f'\n✗ Evaluation failed: {e}')
            )
            raise
    
    def _execute_async(self, evaluation_run):
        """Execute evaluation asynchronously."""
        self.stdout.write('\nExecuting evaluation (asynchronous)...')
        
        from api.test_runner_tasks import execute_evaluation_run
        
        task = execute_evaluation_run.delay(str(evaluation_run.run_id))
        
        self.stdout.write(
            self.style.SUCCESS(
                f'✓ Queued for execution\n'
                f'  Task ID: {task.id}\n'
                f'  Monitor: python manage.py celery_status {task.id}'
            )
        )
    
    def _display_results(self, evaluation_run, duration):
        """Display evaluation results."""
        results = evaluation_run.results or {}
        metrics = results.get('metrics', {})
        
        self.stdout.write(
            self.style.SUCCESS(
                f'\n{"="*60}\n'
                f'Evaluation Complete\n'
                f'{"="*60}'
            )
        )
        
        # Status
        passed = results.get('passed', False)
        status_style = (
            self.style.SUCCESS if passed 
            else self.style.ERROR
        )
        status_text = '✓ PASSED' if passed else '✗ FAILED'
        
        self.stdout.write(status_style(f'\nStatus: {status_text}'))
        self.stdout.write(f'Duration: {duration:.2f}s')
        
        # Scenario metrics
        scenario_metrics = metrics.get('scenario_metrics', {})
        if scenario_metrics:
            self.stdout.write('\nScenario Results:')
            self.stdout.write(
                f"  Total: {scenario_metrics.get('total_scenarios', 0)}"
            )
            self.stdout.write(
                self.style.SUCCESS(
                    f"  Passed: {scenario_metrics.get('passed', 0)}"
                )
            )
            self.stdout.write(
                self.style.ERROR(
                    f"  Failed: {scenario_metrics.get('failed', 0)}"
                )
            )
            self.stdout.write(
                f"  Pass Rate: "
                f"{scenario_metrics.get('pass_rate', 0):.1%}"
            )
        
        # Safety metrics
        safety_metrics = metrics.get('safety_metrics', {})
        if safety_metrics:
            self.stdout.write('\nSafety Metrics:')
            self.stdout.write(
                f"  Safety Grade: "
                f"{safety_metrics.get('safety_grade', 0):.2%}"
            )
            self.stdout.write(
                f"  Total Violations: "
                f"{safety_metrics.get('total_violations', 0)}"
            )
            self.stdout.write(
                f"  PII Violations: "
                f"{safety_metrics.get('pii_violations', 0)}"
            )
            self.stdout.write(
                f"  Policy Violations: "
                f"{safety_metrics.get('policy_violations', 0)}"
            )
        
        # Red team metrics
        if evaluation_run.redteam_enabled:
            redteam_metrics = metrics.get('redteam_metrics', {})
            if redteam_metrics:
                self.stdout.write('\nRed Team Metrics:')
                self.stdout.write(
                    f"  Survival Rate: "
                    f"{redteam_metrics.get('survival_rate', 0):.1%}"
                )
                self.stdout.write(
                    f"  Attacks Survived: "
                    f"{redteam_metrics.get('attacks_survived', 0)}"
                )
        
        # Reproducibility metrics
        repro_metrics = metrics.get('reproducibility_metrics', {})
        if repro_metrics and repro_metrics.get('score', 0) > 0:
            self.stdout.write('\nReproducibility:')
            self.stdout.write(
                f"  Score: {repro_metrics.get('score', 0):.2%}"
            )
            is_repro = repro_metrics.get('is_reproducible', False)
            self.stdout.write(
                f"  Status: {'✓ Reproducible' if is_repro else '✗ Not Reproducible'}"
            )
        
        # Pass criteria violations
        violations = results.get('pass_criteria_violations', [])
        if violations:
            self.stdout.write(
                self.style.ERROR(
                    f'\nPass Criteria Violations:'
                )
            )
            for violation in violations:
                self.stdout.write(f'  - {violation}')
        
        self.stdout.write(f'\n{"="*60}\n')


