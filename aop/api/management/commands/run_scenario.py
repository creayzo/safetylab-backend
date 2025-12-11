"""
Management command to run scenarios from CLI.

Usage:
    python manage.py run_scenario --scenario <scenario_id> --agent <agent_id>
    python manage.py run_scenario --suite adversarial --agent <agent_id>
"""

from django.core.management.base import BaseCommand, CommandError
from django.utils import timezone
from api.models import Organization, Agent
from api.scenario_models import Scenario
from api.scenario_executor import ScenarioExecutor
import logging

logger = logging.getLogger(__name__)


class Command(BaseCommand):
    help = 'Run scenario tests on an agent'

    def add_arguments(self, parser):
        parser.add_argument(
            '--scenario',
            type=str,
            help='Scenario ID to run'
        )
        parser.add_argument(
            '--suite',
            type=str,
            help='Run suite of scenarios by type (business, adversarial, stress, etc.)'
        )
        parser.add_argument(
            '--agent',
            type=int,
            required=True,
            help='Agent ID to test'
        )
        parser.add_argument(
            '--seed',
            type=int,
            help='Random seed for reproducibility'
        )
        parser.add_argument(
            '--org',
            type=int,
            help='Organization ID (optional, will use agent\'s org)'
        )
        parser.add_argument(
            '--tags',
            type=str,
            help='Comma-separated tags to filter scenarios (for suite mode)'
        )
        parser.add_argument(
            '--verbose',
            action='store_true',
            help='Verbose output'
        )

    def handle(self, *args, **options):
        scenario_id = options.get('scenario')
        suite_type = options.get('suite')
        agent_id = options['agent']
        seed = options.get('seed')
        org_id = options.get('org')
        tags = options.get('tags')
        verbose = options.get('verbose')
        
        # Setup logging
        if verbose:
            logging.basicConfig(level=logging.DEBUG)
        
        # Get agent
        try:
            agent = Agent.objects.get(id=agent_id)
            org = agent.owner
            
            if org_id:
                org = Organization.objects.get(id=org_id)
            
            self.stdout.write(
                self.style.SUCCESS(
                    f'Testing agent {agent_id} (Org: {org.name})'
                )
            )
        except Agent.DoesNotExist:
            raise CommandError(f'Agent {agent_id} not found')
        except Organization.DoesNotExist:
            raise CommandError(f'Organization {org_id} not found')
        
        # Create executor
        executor = ScenarioExecutor(organization=org)
        
        # Run scenario or suite
        if scenario_id:
            self._run_single_scenario(
                executor, 
                scenario_id, 
                agent_id, 
                seed
            )
        elif suite_type:
            self._run_suite(
                executor, 
                suite_type, 
                agent_id, 
                tags
            )
        else:
            raise CommandError(
                'Must specify either --scenario or --suite'
            )
    
    def _run_single_scenario(
        self, 
        executor, 
        scenario_id, 
        agent_id, 
        seed
    ):
        """Run a single scenario."""
        try:
            scenario = Scenario.objects.get(scenario_id=scenario_id)
            
            self.stdout.write(
                f'\nRunning scenario: {scenario.name}'
            )
            self.stdout.write(
                f'Type: {scenario.scenario_type}, '
                f'Difficulty: {scenario.difficulty}'
            )
            
            # Run scenario
            start_time = timezone.now()
            scenario_run = executor.run_scenario(
                scenario_id=scenario_id,
                agent_id=agent_id,
                seed=seed
            )
            end_time = timezone.now()
            
            # Display results
            duration = (end_time - start_time).total_seconds()
            
            self.stdout.write(
                self.style.SUCCESS(
                    f'\n✓ Scenario completed in {duration:.2f}s'
                )
            )
            self.stdout.write(f'Run ID: {scenario_run.run_id}')
            self.stdout.write(f'Status: {scenario_run.status}')
            
            results = scenario_run.results
            self.stdout.write(
                f'\nTotal events: {results.get("total_events", 0)}'
            )
            self.stdout.write(
                f'Injections: {results.get("injections_count", 0)}'
            )
            self.stdout.write(
                f'Deviations: {results.get("deviations_count", 0)}'
            )
            
            passed = results.get('passed', False)
            if passed:
                self.stdout.write(
                    self.style.SUCCESS('\n✓ PASSED')
                )
            else:
                self.stdout.write(
                    self.style.ERROR('\n✗ FAILED')
                )
                
                if scenario_run.deviations:
                    self.stdout.write('\nDeviations:')
                    for dev in scenario_run.deviations:
                        self.stdout.write(
                            f"  - Step {dev.get('step')}: "
                            f"{dev.get('message')}"
                        )
            
        except Scenario.DoesNotExist:
            raise CommandError(f'Scenario {scenario_id} not found')
        except Exception as e:
            raise CommandError(f'Scenario execution failed: {e}')
    
    def _run_suite(self, executor, suite_type, agent_id, tags):
        """Run a suite of scenarios."""
        self.stdout.write(
            f'\nRunning scenario suite: {suite_type}'
        )
        
        if tags:
            tag_list = [t.strip() for t in tags.split(',')]
            self.stdout.write(f'Tags: {", ".join(tag_list)}')
        else:
            tag_list = None
        
        # Run suite
        start_time = timezone.now()
        results = executor.run_scenario_suite(
            suite_name=f'{suite_type}_suite',
            agent_id=agent_id,
            scenario_type=suite_type,
            tags=tag_list
        )
        end_time = timezone.now()
        
        # Display results
        duration = (end_time - start_time).total_seconds()
        
        self.stdout.write(
            self.style.SUCCESS(
                f'\n✓ Suite completed in {duration:.2f}s'
            )
        )
        
        summary = results['summary']
        self.stdout.write(f'\nTotal scenarios: {summary["total"]}')
        self.stdout.write(
            self.style.SUCCESS(f'Passed: {summary["passed"]}')
        )
        self.stdout.write(
            self.style.ERROR(f'Failed: {summary["failed"]}')
        )
        self.stdout.write(f'Pass rate: {summary["pass_rate"]}')
        
        # Show individual results
        self.stdout.write('\nIndividual Results:')
        for run_info in results['runs']:
            status_style = (
                self.style.SUCCESS if run_info['passed'] 
                else self.style.ERROR
            )
            status_icon = '✓' if run_info['passed'] else '✗'
            
            self.stdout.write(
                status_style(
                    f'  {status_icon} {run_info["scenario_name"]} '
                    f'({run_info["execution_time"]:.2f}s)'
                )
            )


