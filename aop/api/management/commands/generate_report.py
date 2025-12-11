"""
Management command to generate safety and reliability reports.

Usage:
    python manage.py generate_report --run-id <uuid>
    python manage.py generate_report --run-id <uuid> --format html
    python manage.py generate_report --run-id <uuid> --output report.html
"""

from django.core.management.base import BaseCommand, CommandError
from api.models import EvaluationRun
from api.reporter_engine import ReporterEngine
from api.report_formatters import ReportFormatterFactory
import json


class Command(BaseCommand):
    help = 'Generate safety and reliability reports'

    def add_arguments(self, parser):
        parser.add_argument(
            '--run-id',
            type=str,
            required=True,
            help='Evaluation run ID'
        )
        parser.add_argument(
            '--format',
            type=str,
            default='json',
            choices=['json', 'markdown', 'md', 'html'],
            help='Report format'
        )
        parser.add_argument(
            '--output',
            type=str,
            help='Output file path (optional, prints to stdout if not specified)'
        )
        parser.add_argument(
            '--verbose',
            action='store_true',
            help='Verbose output'
        )

    def handle(self, *args, **options):
        run_id = options['run_id']
        format_type = options['format']
        output_path = options.get('output')
        verbose = options.get('verbose')
        
        # Load evaluation run
        try:
            evaluation_run = EvaluationRun.objects.get(run_id=run_id)
        except EvaluationRun.DoesNotExist:
            raise CommandError(f'Evaluation run {run_id} not found')
        
        # Check if evaluation is complete
        if evaluation_run.status not in ['completed', 'failed']:
            raise CommandError(
                f'Evaluation run is not complete (status: {evaluation_run.status})'
            )
        
        self.stdout.write(
            f'\nGenerating {format_type.upper()} report for evaluation {run_id}...'
        )
        
        # Generate report
        try:
            reporter = ReporterEngine(evaluation_run)
            report = reporter.generate_report()
            
            if verbose:
                self.stdout.write(
                    self.style.SUCCESS('✓ Report generated successfully')
                )
            
            # Format report
            formatted_report = ReportFormatterFactory.format(
                report, 
                format_type
            )
            
            # Output report
            if output_path:
                with open(output_path, 'w', encoding='utf-8') as f:
                    f.write(formatted_report)
                
                self.stdout.write(
                    self.style.SUCCESS(
                        f'\n✓ Report saved to: {output_path}'
                    )
                )
            else:
                self.stdout.write('\n' + '='*60)
                self.stdout.write(formatted_report)
                self.stdout.write('='*60 + '\n')
            
            # Display summary
            if verbose:
                self._display_summary(report)
            
        except Exception as e:
            raise CommandError(f'Report generation failed: {e}')
    
    def _display_summary(self, report):
        """Display report summary."""
        self.stdout.write('\n' + '='*60)
        self.stdout.write('REPORT SUMMARY')
        self.stdout.write('='*60)
        
        exec_summary = report.get('executive_summary', {})
        
        # Status
        status = exec_summary.get('overall_status', 'Unknown')
        passed = exec_summary.get('passed', False)
        
        status_style = (
            self.style.SUCCESS if passed 
            else self.style.ERROR
        )
        
        self.stdout.write(
            status_style(
                f"\nOverall Status: {status} "
                f"({'PASSED' if passed else 'FAILED'})"
            )
        )
        
        # Safety Grade
        grade = exec_summary.get('safety_grade_letter', 'N/A')
        self.stdout.write(f"Safety Grade: {grade}")
        
        # Key metrics
        safety = report.get('safety_assessment', {})
        pii = safety.get('pii_exposure', {})
        policy = safety.get('policy_compliance', {})
        
        self.stdout.write(f"\nPII Incidents: {pii.get('total_incidents', 0)}")
        self.stdout.write(f"Policy Violations: {policy.get('total_violations', 0)}")
        
        # Recommendations
        recommendations = report.get('recommendations', [])
        if recommendations:
            self.stdout.write(f"\nRecommendations: {len(recommendations)}")
            for rec in recommendations[:3]:  # Show top 3
                priority = rec.get('priority', 'Medium')
                title = rec.get('title', '')
                self.stdout.write(f"  - [{priority}] {title}")
        
        # Severity
        severity = report.get('severity_classification', {})
        overall_severity = severity.get('overall_severity', 'Unknown')
        
        severity_style = self.style.ERROR if overall_severity in ['Critical', 'High'] else self.style.WARNING if overall_severity == 'Medium' else self.style.SUCCESS
        
        self.stdout.write(
            severity_style(f"\nOverall Severity: {overall_severity}")
        )
        self.stdout.write(
            f"Deployment Recommendation: {severity.get('deployment_recommendation', 'N/A')}"
        )
        
        self.stdout.write('\n' + '='*60 + '\n')


