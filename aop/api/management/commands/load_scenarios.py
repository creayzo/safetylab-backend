"""
Management command to load example scenarios.

Usage:
    python manage.py load_scenarios
    python manage.py load_scenarios --clear  # Clear existing first
"""

from django.core.management.base import BaseCommand
from api.scenario_models import Scenario
from api.scenario_examples import load_all_example_scenarios


class Command(BaseCommand):
    help = 'Load example scenarios into the database'

    def add_arguments(self, parser):
        parser.add_argument(
            '--clear',
            action='store_true',
            help='Clear existing scenarios before loading'
        )

    def handle(self, *args, **options):
        clear = options.get('clear', False)
        
        if clear:
            count = Scenario.objects.count()
            self.stdout.write(
                f'Clearing {count} existing scenarios...'
            )
            Scenario.objects.all().delete()
            self.stdout.write(
                self.style.SUCCESS('✓ Cleared existing scenarios')
            )
        
        self.stdout.write('Loading example scenarios...')
        
        try:
            scenarios = load_all_example_scenarios()
            
            self.stdout.write(
                self.style.SUCCESS(
                    f'\n✓ Successfully loaded {len(scenarios)} scenarios:'
                )
            )
            
            for scenario in scenarios:
                self.stdout.write(
                    f'  - {scenario.name} ({scenario.scenario_type})'
                )
            
            # Show summary
            self.stdout.write('\nScenario Summary:')
            
            from django.db.models import Count
            summary = Scenario.objects.values('scenario_type').annotate(
                count=Count('scenario_type')
            )
            
            for item in summary:
                self.stdout.write(
                    f'  {item["scenario_type"]}: {item["count"]} scenarios'
                )
            
            self.stdout.write(
                self.style.SUCCESS(
                    f'\nTotal scenarios in database: '
                    f'{Scenario.objects.count()}'
                )
            )
            
        except Exception as e:
            self.stdout.write(
                self.style.ERROR(f'✗ Error loading scenarios: {e}')
            )
            raise


