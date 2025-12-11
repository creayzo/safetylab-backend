"""
Example Usage of Reporter Engine

This script demonstrates how to use the Reporter Engine to generate
safety and reliability reports.
"""

import os
import sys
import django

# Setup Django
sys.path.append(os.path.dirname(os.path.abspath(__file__)))
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'aop.settings')
django.setup()

from api.models import Organization, Agent, EvaluationRun
from api.reporter_engine import ReporterEngine
from api.report_formatters import ReportFormatterFactory


def example_basic_report():
    """Example: Generate a basic report."""
    print("\n=== Example 1: Basic Report Generation ===\n")
    
    # Get a completed evaluation run
    eval_run = EvaluationRun.objects.filter(
        status='completed'
    ).first()
    
    if not eval_run:
        print("No completed evaluation runs found.")
        print("Run an evaluation first using: python manage.py run_evaluation")
        return
    
    print(f"Generating report for evaluation: {eval_run.run_id}")
    print(f"  Organization: {eval_run.organization.name}")
    print(f"  Agent: {eval_run.agent.id}")
    
    # Generate report
    reporter = ReporterEngine(eval_run)
    report = reporter.generate_report()
    
    # Display executive summary
    print("\n--- Executive Summary ---")
    exec_summary = report['executive_summary']
    print(f"Status: {exec_summary['overall_status']}")
    print(f"Passed: {exec_summary['passed']}")
    print(f"Safety Grade: {exec_summary['safety_grade_letter']} ({exec_summary['safety_grade']:.1%})")
    print(f"Critical Issues: {exec_summary['critical_issues']}")
    
    # Display key findings
    print("\nKey Findings:")
    for finding in exec_summary.get('key_findings', []):
        print(f"  • {finding}")


def example_json_report():
    """Example: Generate JSON report."""
    print("\n=== Example 2: JSON Report ===\n")
    
    eval_run = EvaluationRun.objects.filter(status='completed').first()
    if not eval_run:
        return
    
    print(f"Generating JSON report for: {eval_run.run_id}")
    
    # Generate and format as JSON
    reporter = ReporterEngine(eval_run)
    report = reporter.generate_report()
    
    json_report = ReportFormatterFactory.format(report, 'json')
    
    # Save to file
    output_file = f'report_{eval_run.run_id}.json'
    with open(output_file, 'w', encoding='utf-8') as f:
        f.write(json_report)
    
    print(f"✓ JSON report saved to: {output_file}")
    print(f"  Size: {len(json_report)} bytes")


def example_html_report():
    """Example: Generate HTML report."""
    print("\n=== Example 3: HTML Report ===\n")
    
    eval_run = EvaluationRun.objects.filter(status='completed').first()
    if not eval_run:
        return
    
    print(f"Generating HTML report for: {eval_run.run_id}")
    
    # Generate and format as HTML
    reporter = ReporterEngine(eval_run)
    report = reporter.generate_report()
    
    html_report = ReportFormatterFactory.format(report, 'html')
    
    # Save to file
    output_file = f'report_{eval_run.run_id}.html'
    with open(output_file, 'w', encoding='utf-8') as f:
        f.write(html_report)
    
    print(f"✓ HTML report saved to: {output_file}")
    print(f"  Size: {len(html_report)} bytes")
    print(f"  Open in browser: file://{os.path.abspath(output_file)}")


def example_markdown_report():
    """Example: Generate Markdown report."""
    print("\n=== Example 4: Markdown Report ===\n")
    
    eval_run = EvaluationRun.objects.filter(status='completed').first()
    if not eval_run:
        return
    
    print(f"Generating Markdown report for: {eval_run.run_id}")
    
    # Generate and format as Markdown
    reporter = ReporterEngine(eval_run)
    report = reporter.generate_report()
    
    md_report = ReportFormatterFactory.format(report, 'markdown')
    
    # Save to file
    output_file = f'report_{eval_run.run_id}.md'
    with open(output_file, 'w', encoding='utf-8') as f:
        f.write(md_report)
    
    print(f"✓ Markdown report saved to: {output_file}")
    print(f"  Size: {len(md_report)} bytes")
    
    # Display preview
    print("\n--- Report Preview (first 500 chars) ---")
    print(md_report[:500] + "...")


def example_detailed_analysis():
    """Example: Detailed report analysis."""
    print("\n=== Example 5: Detailed Analysis ===\n")
    
    eval_run = EvaluationRun.objects.filter(status='completed').first()
    if not eval_run:
        return
    
    print(f"Analyzing evaluation: {eval_run.run_id}\n")
    
    # Generate report
    reporter = ReporterEngine(eval_run)
    report = reporter.generate_report()
    
    # Safety Analysis
    print("--- Safety Assessment ---")
    safety = report['safety_assessment']
    
    final_grade = safety['final_safety_grade']
    print(f"Safety Grade: {final_grade['letter_grade']} ({final_grade['percentage']})")
    print(f"Interpretation: {final_grade['interpretation']}")
    print(f"Meets Threshold: {final_grade['meets_threshold']}")
    
    pii = safety['pii_exposure']
    print(f"\nPII Exposure:")
    print(f"  Incidents: {pii['total_incidents']}")
    print(f"  Severity: {pii['severity']}")
    print(f"  Within Tolerance: {pii['within_tolerance']}")
    
    policy = safety['policy_compliance']
    print(f"\nPolicy Compliance:")
    print(f"  Violations: {policy['total_violations']}")
    print(f"  Severity: {policy['severity']}")
    print(f"  Within Tolerance: {policy['within_tolerance']}")
    
    # Security Analysis
    print("\n--- Security Assessment ---")
    security = report['security_assessment']
    
    prompt_injection = security['prompt_injection_resistance']
    print(f"Prompt Injection Resistance:")
    print(f"  Attempts: {prompt_injection['total_attempts']}")
    print(f"  Resisted: {prompt_injection['successfully_resisted']}")
    print(f"  Resistance Rate: {prompt_injection['resistance_rate']:.1%}")
    
    if security['redteam_assessment']['enabled']:
        redteam = security['redteam_assessment']
        print(f"\nRed Team Assessment:")
        print(f"  Attack Level: {redteam['attack_level']}")
        print(f"  Survival Rate: {redteam['survival_rate']:.1%}")
        print(f"  Attacks Survived: {redteam['attacks_survived']}")
    
    # Reliability Analysis
    print("\n--- Reliability Assessment ---")
    reliability = report['reliability_assessment']
    
    reproducibility = reliability['reproducibility']
    print(f"Reproducibility:")
    print(f"  Score: {reproducibility['score']:.1%}")
    print(f"  Is Reproducible: {reproducibility['is_reproducible']}")
    print(f"  Meets Threshold: {reproducibility['meets_threshold']}")
    
    # Recommendations
    print("\n--- Recommendations ---")
    recommendations = report['recommendations']
    if recommendations:
        for i, rec in enumerate(recommendations, 1):
            print(f"\n{i}. {rec['title']} ({rec['priority']} Priority)")
            print(f"   Category: {rec['category']}")
            print(f"   {rec['description']}")
            print(f"   Action Items:")
            for action in rec['action_items']:
                print(f"     • {action}")
    else:
        print("No recommendations - all criteria met!")
    
    # Severity Classification
    print("\n--- Severity Classification ---")
    severity = report['severity_classification']
    print(f"Overall Severity: {severity['overall_severity']}")
    print(f"Risk Level: {severity['risk_level']}")
    print(f"Critical Issues: {severity['critical_issues_count']}")
    print(f"Deployment Recommendation: {severity['deployment_recommendation']}")


def example_compare_reports():
    """Example: Compare multiple reports."""
    print("\n=== Example 6: Compare Multiple Reports ===\n")
    
    eval_runs = EvaluationRun.objects.filter(
        status='completed'
    ).order_by('-created_at')[:3]
    
    if len(eval_runs) < 2:
        print("Not enough evaluation runs to compare.")
        return
    
    print(f"Comparing {len(eval_runs)} evaluation runs:\n")
    
    print(f"{'Evaluation ID':<40} {'Grade':<8} {'Passed':<8} {'PII':<6} {'Policy':<8}")
    print("-" * 80)
    
    for eval_run in eval_runs:
        reporter = ReporterEngine(eval_run)
        report = reporter.generate_report()
        
        exec_summary = report['executive_summary']
        safety = report['safety_assessment']
        
        run_id_short = str(eval_run.run_id)[:36]
        grade = exec_summary['safety_grade_letter']
        passed = "✓" if exec_summary['passed'] else "✗"
        pii = safety['pii_exposure']['total_incidents']
        policy = safety['policy_compliance']['total_violations']
        
        print(f"{run_id_short:<40} {grade:<8} {passed:<8} {pii:<6} {policy:<8}")


def main():
    """Run all examples."""
    print("\n" + "="*60)
    print("  Reporter Engine - Example Usage")
    print("="*60)
    
    try:
        # Run examples
        example_basic_report()
        example_json_report()
        example_html_report()
        example_markdown_report()
        example_detailed_analysis()
        example_compare_reports()
        
        print("\n" + "="*60)
        print("  All Examples Completed Successfully!")
        print("="*60 + "\n")
        
    except Exception as e:
        print(f"\n❌ Error: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    main()


