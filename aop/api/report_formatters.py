"""
Report Formatters

Formats reports in various formats:
- JSON
- HTML
- Markdown
- PDF (via HTML)
"""

import json
import logging
from typing import Dict, Any
from datetime import datetime

logger = logging.getLogger(__name__)


class JSONFormatter:
    """Format report as JSON."""
    
    @staticmethod
    def format(report: Dict[str, Any]) -> str:
        """
        Format report as JSON.
        
        Args:
            report: Report dictionary
            
        Returns:
            JSON string
        """
        return json.dumps(report, indent=2, default=str)


class MarkdownFormatter:
    """Format report as Markdown."""
    
    @staticmethod
    def format(report: Dict[str, Any]) -> str:
        """
        Format report as Markdown.
        
        Args:
            report: Report dictionary
            
        Returns:
            Markdown string
        """
        md = []
        
        # Title
        md.append("# Agent Safety & Reliability Report\n")
        
        # Metadata
        metadata = report.get('evaluation_metadata', {})
        md.append(f"**Report ID:** `{report.get('report_id')}`\n")
        md.append(f"**Generated:** {report.get('generated_at')}\n")
        md.append(f"**Organization:** {metadata.get('organization')}\n")
        md.append(f"**Agent:** {metadata.get('agent_model')}\n\n")
        
        # Executive Summary
        md.append("## Executive Summary\n")
        exec_summary = report.get('executive_summary', {})
        
        status = exec_summary.get('overall_status', 'Unknown')
        safety_grade = exec_summary.get('safety_grade_letter', 'N/A')
        
        md.append(f"**Status:** {status}\n")
        md.append(f"**Safety Grade:** {safety_grade}\n")
        md.append(f"**Pass/Fail:** {'✓ PASSED' if exec_summary.get('passed') else '✗ FAILED'}\n\n")
        
        # Key Findings
        md.append("### Key Findings\n")
        for finding in exec_summary.get('key_findings', []):
            md.append(f"- {finding}\n")
        md.append("\n")
        
        # Safety Assessment
        md.append("## Safety Assessment\n")
        safety = report.get('safety_assessment', {})
        
        final_grade = safety.get('final_safety_grade', {})
        md.append(f"**Final Safety Grade:** {final_grade.get('letter_grade')} ({final_grade.get('percentage')})\n")
        md.append(f"*{final_grade.get('interpretation')}*\n\n")
        
        # PII Exposure
        pii = safety.get('pii_exposure', {})
        md.append(f"**PII Exposure:** {pii.get('total_incidents')} incident(s) - Severity: {pii.get('severity')}\n\n")
        
        # Policy Compliance
        policy = safety.get('policy_compliance', {})
        md.append(f"**Policy Violations:** {policy.get('total_violations')} - Severity: {policy.get('severity')}\n\n")
        
        # Security Assessment
        md.append("## Security Assessment\n")
        security = report.get('security_assessment', {})
        
        prompt_injection = security.get('prompt_injection_resistance', {})
        md.append(f"**Prompt Injection Resistance:** {prompt_injection.get('resistance_rate', 0):.1%}\n")
        md.append(f"- Total Attempts: {prompt_injection.get('total_attempts', 0)}\n")
        md.append(f"- Successfully Resisted: {prompt_injection.get('successfully_resisted', 0)}\n\n")
        
        # Red Team
        redteam = security.get('redteam_assessment', {})
        if redteam.get('enabled'):
            md.append(f"**Red Team Assessment:**\n")
            md.append(f"- Attack Level: {redteam.get('attack_level')}\n")
            md.append(f"- Survival Rate: {redteam.get('survival_rate', 0):.1%}\n")
            md.append(f"- Attacks Survived: {redteam.get('attacks_survived', 0)}\n\n")
        
        # Reliability
        md.append("## Reliability Assessment\n")
        reliability = report.get('reliability_assessment', {})
        
        reproducibility = reliability.get('reproducibility', {})
        md.append(f"**Reproducibility Score:** {reproducibility.get('score', 0):.1%}\n")
        md.append(f"**Is Reproducible:** {'Yes' if reproducibility.get('is_reproducible') else 'No'}\n\n")
        
        # Recommendations
        md.append("## Recommendations\n")
        for i, rec in enumerate(report.get('recommendations', []), 1):
            md.append(f"### {i}. {rec.get('title')} ({rec.get('priority')} Priority)\n")
            md.append(f"*Category: {rec.get('category')}*\n\n")
            md.append(f"{rec.get('description')}\n\n")
            md.append("**Action Items:**\n")
            for action in rec.get('action_items', []):
                md.append(f"- {action}\n")
            md.append("\n")
        
        # Severity Classification
        md.append("## Severity Classification\n")
        severity = report.get('severity_classification', {})
        md.append(f"**Overall Severity:** {severity.get('overall_severity')}\n")
        md.append(f"**Critical Issues:** {severity.get('critical_issues_count')}\n")
        md.append(f"**Deployment Recommendation:** {severity.get('deployment_recommendation')}\n")
        md.append(f"**Risk Level:** {severity.get('risk_level')}\n\n")
        
        return "".join(md)


class HTMLFormatter:
    """Format report as HTML."""
    
    @staticmethod
    def format(report: Dict[str, Any]) -> str:
        """
        Format report as HTML.
        
        Args:
            report: Report dictionary
            
        Returns:
            HTML string
        """
        html = []
        
        # HTML header
        html.append("""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Agent Safety & Reliability Report</title>
    <style>
        body {
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
            line-height: 1.6;
            color: #333;
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
            background-color: #f5f5f5;
        }
        .container {
            background-color: white;
            padding: 30px;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }
        h1 {
            color: #2c3e50;
            border-bottom: 3px solid #3498db;
            padding-bottom: 10px;
        }
        h2 {
            color: #34495e;
            margin-top: 30px;
            border-bottom: 2px solid #ecf0f1;
            padding-bottom: 5px;
        }
        h3 {
            color: #7f8c8d;
        }
        .badge {
            display: inline-block;
            padding: 4px 12px;
            border-radius: 12px;
            font-weight: bold;
            font-size: 14px;
        }
        .badge-green { background-color: #2ecc71; color: white; }
        .badge-yellow { background-color: #f39c12; color: white; }
        .badge-red { background-color: #e74c3c; color: white; }
        .badge-blue { background-color: #3498db; color: white; }
        .metric {
            background-color: #ecf0f1;
            padding: 15px;
            margin: 10px 0;
            border-radius: 5px;
            border-left: 4px solid #3498db;
        }
        .metric-label {
            font-weight: bold;
            color: #7f8c8d;
            margin-bottom: 5px;
        }
        .metric-value {
            font-size: 24px;
            color: #2c3e50;
        }
        .recommendation {
            background-color: #fff3cd;
            border-left: 4px solid #f39c12;
            padding: 15px;
            margin: 15px 0;
            border-radius: 5px;
        }
        .recommendation-critical {
            background-color: #f8d7da;
            border-left-color: #e74c3c;
        }
        .finding {
            padding: 10px;
            margin: 5px 0;
            background-color: #e8f4f8;
            border-radius: 5px;
        }
        table {
            width: 100%;
            border-collapse: collapse;
            margin: 15px 0;
        }
        th, td {
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid #ddd;
        }
        th {
            background-color: #3498db;
            color: white;
        }
        .footer {
            margin-top: 50px;
            padding-top: 20px;
            border-top: 1px solid #ddd;
            color: #7f8c8d;
            font-size: 12px;
        }
    </style>
</head>
<body>
    <div class="container">
""")
        
        # Title
        html.append("<h1>🛡️ Agent Safety & Reliability Report</h1>")
        
        # Metadata
        metadata = report.get('evaluation_metadata', {})
        html.append(f"<p><strong>Report ID:</strong> <code>{report.get('report_id')}</code></p>")
        html.append(f"<p><strong>Generated:</strong> {report.get('generated_at')}</p>")
        html.append(f"<p><strong>Organization:</strong> {metadata.get('organization')}</p>")
        html.append(f"<p><strong>Agent Model:</strong> {metadata.get('agent_model')}</p>")
        
        # Executive Summary
        html.append("<h2>Executive Summary</h2>")
        exec_summary = report.get('executive_summary', {})
        
        status = exec_summary.get('overall_status', 'Unknown')
        status_color = exec_summary.get('status_color', 'blue')
        color_class = f'badge-{status_color}'
        
        html.append(f'<p><strong>Status:</strong> <span class="badge {color_class}">{status}</span></p>')
        
        grade = exec_summary.get('safety_grade_letter', 'N/A')
        html.append(f'<p><strong>Safety Grade:</strong> <span class="badge badge-blue">{grade}</span></p>')
        
        passed = exec_summary.get('passed', False)
        pass_badge = '<span class="badge badge-green">✓ PASSED</span>' if passed else '<span class="badge badge-red">✗ FAILED</span>'
        html.append(f'<p><strong>Result:</strong> {pass_badge}</p>')
        
        # Key Findings
        html.append("<h3>Key Findings</h3>")
        html.append("<ul>")
        for finding in exec_summary.get('key_findings', []):
            html.append(f"<li>{finding}</li>")
        html.append("</ul>")
        
        # Safety Assessment
        html.append("<h2>Safety Assessment</h2>")
        safety = report.get('safety_assessment', {})
        
        final_grade = safety.get('final_safety_grade', {})
        html.append('<div class="metric">')
        html.append('<div class="metric-label">Final Safety Grade</div>')
        html.append(f'<div class="metric-value">{final_grade.get("letter_grade")} ({final_grade.get("percentage")})</div>')
        html.append(f'<p><em>{final_grade.get("interpretation")}</em></p>')
        html.append('</div>')
        
        # PII and Policy
        pii = safety.get('pii_exposure', {})
        policy = safety.get('policy_compliance', {})
        
        html.append("<table>")
        html.append("<tr><th>Metric</th><th>Count</th><th>Severity</th></tr>")
        html.append(f"<tr><td>PII Exposure</td><td>{pii.get('total_incidents')}</td><td>{pii.get('severity')}</td></tr>")
        html.append(f"<tr><td>Policy Violations</td><td>{policy.get('total_violations')}</td><td>{policy.get('severity')}</td></tr>")
        html.append("</table>")
        
        # Recommendations
        html.append("<h2>Recommendations</h2>")
        for rec in report.get('recommendations', []):
            priority = rec.get('priority', 'Medium')
            rec_class = 'recommendation-critical' if priority == 'Critical' else 'recommendation'
            
            html.append(f'<div class="{rec_class}">')
            html.append(f'<h3>{rec.get("title")} <span class="badge badge-yellow">{priority} Priority</span></h3>')
            html.append(f'<p><strong>Category:</strong> {rec.get("category")}</p>')
            html.append(f'<p>{rec.get("description")}</p>')
            html.append("<p><strong>Action Items:</strong></p>")
            html.append("<ul>")
            for action in rec.get('action_items', []):
                html.append(f"<li>{action}</li>")
            html.append("</ul>")
            html.append("</div>")
        
        # Severity Classification
        html.append("<h2>Severity Classification</h2>")
        severity = report.get('severity_classification', {})
        
        html.append('<div class="metric">')
        html.append(f'<p><strong>Overall Severity:</strong> {severity.get("overall_severity")}</p>')
        html.append(f'<p><strong>Critical Issues:</strong> {severity.get("critical_issues_count")}</p>')
        html.append(f'<p><strong>Deployment Recommendation:</strong> {severity.get("deployment_recommendation")}</p>')
        html.append(f'<p><strong>Risk Level:</strong> {severity.get("risk_level")}</p>')
        html.append('</div>')
        
        # Footer
        html.append('<div class="footer">')
        html.append(f'<p>Generated by AOP Reporter Engine v{metadata.get("evaluator_version", "1.0.0")}</p>')
        html.append(f'<p>Report ID: {report.get("report_id")}</p>')
        html.append('</div>')
        
        # Close HTML
        html.append("""
    </div>
</body>
</html>
""")
        
        return "".join(html)


class ReportFormatterFactory:
    """Factory for creating report formatters."""
    
    FORMATTERS = {
        'json': JSONFormatter,
        'markdown': MarkdownFormatter,
        'md': MarkdownFormatter,
        'html': HTMLFormatter
    }
    
    @classmethod
    def format(cls, report: Dict[str, Any], format_type: str) -> str:
        """
        Format report in specified format.
        
        Args:
            report: Report dictionary
            format_type: Format type (json, markdown, html)
            
        Returns:
            Formatted report string
        """
        formatter_class = cls.FORMATTERS.get(format_type.lower())
        
        if not formatter_class:
            raise ValueError(f"Unsupported format: {format_type}")
        
        formatter = formatter_class()
        return formatter.format(report)


