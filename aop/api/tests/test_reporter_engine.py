"""
Tests for Reporter Engine and Report Formatters.

Tests report generation, formatting, and content.
"""

import json
from django.test import TestCase
from django.utils import timezone

from api.models import Organization, Agent, EvaluationRun
from api.reporter_engine import ReporterEngine
from api.report_formatters import (
    JSONFormatter,
    MarkdownFormatter,
    HTMLFormatter,
    ReportFormatterFactory
)


class ReporterEngineTest(TestCase):
    """Test ReporterEngine."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.org = Organization.objects.create(name="Test Org")
        self.agent = Agent.objects.create(owner=self.org)
        
        # Create completed evaluation run
        self.evaluation_run = EvaluationRun.objects.create(
            organization=self.org,
            agent=self.agent,
            scenario_set=["test-scenario-1"],
            initiated_by='test',
            seed=12345,
            status='completed',
            started_at=timezone.now(),
            completed_at=timezone.now(),
            results={
                'passed': True,
                'metrics': {
                    'scenario_metrics': {
                        'total_scenarios': 5,
                        'passed': 4,
                        'failed': 1,
                        'pass_rate': 0.8
                    },
                    'safety_metrics': {
                        'safety_grade': 0.92,
                        'total_violations': 3,
                        'pii_violations': 0,
                        'policy_violations': 1,
                        'prompt_injection_attempts': 2,
                        'violation_rate': 0.05
                    },
                    'redteam_metrics': {
                        'enabled': True,
                        'survival_rate': 0.90,
                        'attacks_survived': 18
                    },
                    'reproducibility_metrics': {
                        'score': 0.98,
                        'is_reproducible': True
                    },
                    'performance_metrics': {
                        'total_execution_time': 125.3,
                        'avg_scenario_time': 25.1
                    },
                    'event_metrics': {
                        'total_events': 50,
                        'total_injections': 5,
                        'events_per_scenario': 10
                    }
                },
                'scenario_results': [],
                'validation_summary': {
                    'total_violations': 3,
                    'violations_by_type': {
                        'policy_violation': 1,
                        'prompt_injection': 2
                    }
                }
            }
        )
    
    def test_reporter_initialization(self):
        """Test reporter initialization."""
        reporter = ReporterEngine(self.evaluation_run)
        
        self.assertEqual(reporter.evaluation_run, self.evaluation_run)
        self.assertIsNotNone(reporter.results)
        self.assertIsNotNone(reporter.metrics)
    
    def test_generate_report(self):
        """Test report generation."""
        reporter = ReporterEngine(self.evaluation_run)
        report = reporter.generate_report()
        
        # Verify report structure
        self.assertIn('report_id', report)
        self.assertIn('generated_at', report)
        self.assertIn('evaluation_metadata', report)
        self.assertIn('executive_summary', report)
        self.assertIn('safety_assessment', report)
        self.assertIn('security_assessment', report)
        self.assertIn('reliability_assessment', report)
        self.assertIn('recommendations', report)
        self.assertIn('severity_classification', report)
        self.assertIn('evidence_pack', report)
    
    def test_executive_summary(self):
        """Test executive summary generation."""
        reporter = ReporterEngine(self.evaluation_run)
        report = reporter.generate_report()
        
        exec_summary = report['executive_summary']
        
        self.assertIn('overall_status', exec_summary)
        self.assertIn('passed', exec_summary)
        self.assertIn('safety_grade', exec_summary)
        self.assertIn('safety_grade_letter', exec_summary)
        self.assertIn('key_findings', exec_summary)
        
        self.assertTrue(exec_summary['passed'])
        self.assertEqual(exec_summary['safety_grade'], 0.92)
    
    def test_safety_assessment(self):
        """Test safety assessment generation."""
        reporter = ReporterEngine(self.evaluation_run)
        report = reporter.generate_report()
        
        safety = report['safety_assessment']
        
        self.assertIn('final_safety_grade', safety)
        self.assertIn('pii_exposure', safety)
        self.assertIn('policy_compliance', safety)
        
        # Verify safety grade
        final_grade = safety['final_safety_grade']
        self.assertEqual(final_grade['score'], 0.92)
        self.assertEqual(final_grade['letter_grade'], 'A-')
    
    def test_security_assessment(self):
        """Test security assessment generation."""
        reporter = ReporterEngine(self.evaluation_run)
        report = reporter.generate_report()
        
        security = report['security_assessment']
        
        self.assertIn('prompt_injection_resistance', security)
        self.assertIn('redteam_assessment', security)
        self.assertIn('tool_misuse_analysis', security)
        
        # Verify red team assessment
        redteam = security['redteam_assessment']
        self.assertTrue(redteam['enabled'])
        self.assertEqual(redteam['survival_rate'], 0.90)
    
    def test_recommendations_generation(self):
        """Test recommendations generation."""
        reporter = ReporterEngine(self.evaluation_run)
        report = reporter.generate_report()
        
        recommendations = report['recommendations']
        
        self.assertIsInstance(recommendations, list)
        
        # Check recommendation structure
        if recommendations:
            rec = recommendations[0]
            self.assertIn('category', rec)
            self.assertIn('priority', rec)
            self.assertIn('title', rec)
            self.assertIn('description', rec)
            self.assertIn('action_items', rec)
    
    def test_severity_classification(self):
        """Test severity classification."""
        reporter = ReporterEngine(self.evaluation_run)
        report = reporter.generate_report()
        
        severity = report['severity_classification']
        
        self.assertIn('overall_severity', severity)
        self.assertIn('critical_issues_count', severity)
        self.assertIn('deployment_recommendation', severity)
        self.assertIn('risk_level', severity)
    
    def test_grade_to_letter_conversion(self):
        """Test grade to letter conversion."""
        reporter = ReporterEngine(self.evaluation_run)
        
        self.assertEqual(reporter._grade_to_letter(0.98), 'A+')
        self.assertEqual(reporter._grade_to_letter(0.95), 'A')
        self.assertEqual(reporter._grade_to_letter(0.92), 'A-')
        self.assertEqual(reporter._grade_to_letter(0.85), 'B')
        self.assertEqual(reporter._grade_to_letter(0.75), 'C')
        self.assertEqual(reporter._grade_to_letter(0.65), 'D')
        self.assertEqual(reporter._grade_to_letter(0.50), 'F')


class ReportFormattersTest(TestCase):
    """Test report formatters."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.report = {
            'report_id': 'test-123',
            'generated_at': '2025-01-01T00:00:00',
            'evaluation_metadata': {
                'organization': 'Test Org',
                'agent_model': 'gpt-4'
            },
            'executive_summary': {
                'overall_status': 'Good',
                'status_color': 'green',
                'passed': True,
                'safety_grade': 0.92,
                'safety_grade_letter': 'A-',
                'key_findings': ['Finding 1', 'Finding 2']
            },
            'safety_assessment': {
                'final_safety_grade': {
                    'score': 0.92,
                    'letter_grade': 'A-',
                    'percentage': '92.0%',
                    'interpretation': 'Excellent'
                },
                'pii_exposure': {
                    'total_incidents': 0,
                    'severity': 'None'
                },
                'policy_compliance': {
                    'total_violations': 1,
                    'severity': 'Low'
                }
            },
            'recommendations': [
                {
                    'category': 'Safety',
                    'priority': 'Medium',
                    'title': 'Test Recommendation',
                    'description': 'Test description',
                    'action_items': ['Action 1', 'Action 2']
                }
            ],
            'severity_classification': {
                'overall_severity': 'Low',
                'critical_issues_count': 0,
                'deployment_recommendation': 'Safe to deploy',
                'risk_level': 'Low'
            }
        }
    
    def test_json_formatter(self):
        """Test JSON formatter."""
        formatter = JSONFormatter()
        output = formatter.format(self.report)
        
        # Should be valid JSON
        parsed = json.loads(output)
        self.assertEqual(parsed['report_id'], 'test-123')
        self.assertTrue(parsed['executive_summary']['passed'])
    
    def test_markdown_formatter(self):
        """Test Markdown formatter."""
        formatter = MarkdownFormatter()
        output = formatter.format(self.report)
        
        # Should contain markdown headers
        self.assertIn('# Agent Safety & Reliability Report', output)
        self.assertIn('## Executive Summary', output)
        self.assertIn('## Safety Assessment', output)
        self.assertIn('## Recommendations', output)
        
        # Should contain key data
        self.assertIn('Good', output)
        self.assertIn('A-', output)
    
    def test_html_formatter(self):
        """Test HTML formatter."""
        formatter = HTMLFormatter()
        output = formatter.format(self.report)
        
        # Should be valid HTML
        self.assertIn('<!DOCTYPE html>', output)
        self.assertIn('<html', output)
        self.assertIn('</html>', output)
        
        # Should contain key sections
        self.assertIn('Agent Safety & Reliability Report', output)
        self.assertIn('Executive Summary', output)
        self.assertIn('Safety Assessment', output)
        
        # Should contain styling
        self.assertIn('<style>', output)
    
    def test_formatter_factory(self):
        """Test formatter factory."""
        # JSON format
        json_output = ReportFormatterFactory.format(self.report, 'json')
        self.assertIn('"report_id"', json_output)
        
        # Markdown format
        md_output = ReportFormatterFactory.format(self.report, 'markdown')
        self.assertIn('# Agent Safety', md_output)
        
        # HTML format
        html_output = ReportFormatterFactory.format(self.report, 'html')
        self.assertIn('<!DOCTYPE html>', html_output)
        
        # Invalid format
        with self.assertRaises(ValueError):
            ReportFormatterFactory.format(self.report, 'invalid')


class ReportContentTest(TestCase):
    """Test report content accuracy."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.org = Organization.objects.create(name="Test Org")
        self.agent = Agent.objects.create(owner=self.org)
        
        # Create evaluation with PII violations
        self.eval_with_pii = EvaluationRun.objects.create(
            organization=self.org,
            agent=self.agent,
            scenario_set=["test"],
            initiated_by='test',
            status='completed',
            max_pii_leak_tolerance=0,
            results={
                'passed': False,
                'metrics': {
                    'safety_metrics': {
                        'safety_grade': 0.75,
                        'pii_violations': 3
                    }
                }
            }
        )
    
    def test_report_reflects_pii_violations(self):
        """Test report accurately reflects PII violations."""
        reporter = ReporterEngine(self.eval_with_pii)
        report = reporter.generate_report()
        
        # Check PII exposure section
        pii = report['safety_assessment']['pii_exposure']
        self.assertEqual(pii['total_incidents'], 3)
        self.assertFalse(pii['within_tolerance'])
        
        # Should have critical severity
        severity = report['severity_classification']
        self.assertIn(severity['overall_severity'], ['Critical', 'High'])
        
        # Should have recommendations
        recommendations = report['recommendations']
        has_pii_rec = any(
            'PII' in rec['title'] or 'Privacy' in rec['category']
            for rec in recommendations
        )
        self.assertTrue(has_pii_rec)


