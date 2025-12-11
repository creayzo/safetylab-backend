
# Reporter Engine (Safety & Reliability Report) Documentation

## Overview

The **Reporter Engine** is the final component that transforms evaluation results into comprehensive, actionable reports for enterprises. It generates professional safety and reliability reports including:

- **Final Safety Grade (ASG)** - Letter grade and interpretation
- **Policy Violation Summary** - Detailed compliance analysis
- **PII Exposure Summary** - Privacy incident tracking
- **Prompt Injection Resistance** - Security assessment
- **Tool Misuse Analysis** - Action boundary checks
- **Drift/Variance Metrics** - Consistency measurements
- **Replay Reproducibility Score** - Determinism verification
- **Recommendations** - Actionable improvement suggestions
- **Severity Classification** - Risk assessment
- **Evidence Pack Pointer** - Links to trace data and artifacts

## Architecture

```
┌─────────────────────────────────────────────────────┐
│              Reporter Engine                        │
├─────────────────────────────────────────────────────┤
│                                                     │
│  Input: EvaluationRun (with results)               │
│                                                     │
│  ┌──────────────────────────────────────────────┐ │
│  │ 1. Generate Report Sections:                  │ │
│  │    • Executive Summary                        │ │
│  │    • Safety Assessment                        │ │
│  │    • Security Assessment                      │ │
│  │    • Reliability Assessment                   │ │
│  │    • Performance Assessment                   │ │
│  │    • Recommendations                          │ │
│  │    • Severity Classification                  │ │
│  │    • Evidence Pack                            │ │
│  │    • Compliance Summary                       │ │
│  └──────────────────────────────────────────────┘ │
│                        ▼                           │
│  ┌──────────────────────────────────────────────┐ │
│  │ 2. Format Output:                             │ │
│  │    • JSON (machine-readable)                  │ │
│  │    • HTML (web viewing)                       │ │
│  │    • Markdown (documentation)                 │ │
│  │    • PDF (via HTML)                           │ │
│  └──────────────────────────────────────────────┘ │
│                        ▼                           │
│  Output: Comprehensive Report                     │
│                                                     │
└─────────────────────────────────────────────────────┘
```

## Quick Start

### 1. Generate Report (Programmatic)

```python
from api.models import EvaluationRun
from api.reporter_engine import ReporterEngine
from api.report_formatters import ReportFormatterFactory

# Load completed evaluation
eval_run = EvaluationRun.objects.get(run_id=run_id)

# Generate report
reporter = ReporterEngine(eval_run)
report = reporter.generate_report()

# Format as JSON
json_report = ReportFormatterFactory.format(report, 'json')

# Format as HTML
html_report = ReportFormatterFactory.format(report, 'html')

# Format as Markdown
md_report = ReportFormatterFactory.format(report, 'markdown')
```

### 2. Generate Report (CLI)

```bash
# JSON format (default)
python manage.py generate_report --run-id <uuid>

# HTML format
python manage.py generate_report --run-id <uuid> --format html

# Save to file
python manage.py generate_report \
  --run-id <uuid> \
  --format html \
  --output report.html

# Markdown format
python manage.py generate_report \
  --run-id <uuid> \
  --format markdown \
  --output report.md

# With verbose output
python manage.py generate_report \
  --run-id <uuid> \
  --format html \
  --verbose
```

## Report Structure

### Complete Report Sections

1. **Evaluation Metadata**
   - Report ID
   - Organization & Agent details
   - Execution timing
   - Configuration summary

2. **Executive Summary**
   - Overall status (Excellent/Good/Acceptable/Needs Improvement)
   - Pass/Fail result
   - Final safety grade (letter grade)
   - Key findings (top 5)
   - Critical issues count

3. **Safety Assessment**
   - **Final Safety Grade**
     - Numeric score (0.0-1.0)
     - Letter grade (A+ to F)
     - Percentage
     - Interpretation
     - Threshold comparison
   
   - **PII Exposure**
     - Total incidents
     - Severity classification
     - Tolerance comparison
     - Incident details
   
   - **Policy Compliance**
     - Total violations
     - Severity classification
     - Violation types
     - Tolerance comparison
   
   - **Overall Violation Summary**
     - Total violations
     - Violation rate
     - Violations by severity

4. **Security Assessment**
   - **Prompt Injection Resistance**
     - Total attempts
     - Successfully resisted
     - Resistance rate
     - Severity classification
     - Attack types detected
     - Vulnerability score
   
   - **Red Team Assessment** (if enabled)
     - Attack level
     - Survival rate
     - Attacks survived
     - Threshold comparison
     - Attack categories
   
   - **Tool Misuse Analysis**
     - Total tool calls
     - Misuse detected
     - Unauthorized tools
     - Excessive calls
   
   - **Overall Security Score**

5. **Reliability Assessment**
   - **Reproducibility**
     - Reproducibility score
     - Is reproducible (boolean)
     - Threshold comparison
     - Determinism status
     - Replay details
   
   - **Consistency**
     - Scenario pass rate
     - Variance metrics
     - Drift detection
     - Output consistency score
   
   - **Overall Stability Score**

6. **Performance Assessment**
   - **Execution Time**
     - Total seconds
     - Average per scenario
     - Timeout threshold
     - Timeout status
   
   - **Event Throughput**
     - Total events
     - Total injections
     - Events per scenario
     - Events per second
   
   - **Resource Utilization**
     - Compute units consumed
     - Credits used

7. **Recommendations**
   - Category (Safety/Security/Reliability/Performance)
   - Priority (Critical/High/Medium/Low)
   - Title
   - Description
   - Action items (bulleted list)

8. **Severity Classification**
   - Overall severity (Critical/High/Medium/Low)
   - Severity color
   - Action required (Immediate/Urgent/Soon/None)
   - Critical issues count
   - Deployment recommendation
   - Risk level

9. **Evidence Pack**
   - Trace data pointers
   - Replay data
   - Scenario results
   - Validation logs
   - Report artifacts (JSON/HTML/PDF links)

10. **Compliance Summary**
    - GDPR compliance
    - SOC 2 compliance
    - HIPAA compliance
    - Audit trail completeness

11. **Detailed Findings**
    - Individual scenario results
    - Detailed violations
    - Pass criteria violations
    - Validation summary

## Report Formats

### JSON Format

**Use Case**: Machine processing, API responses, archival

```json
{
  "report_id": "uuid",
  "generated_at": "2025-01-01T00:00:00Z",
  "executive_summary": {
    "overall_status": "Good",
    "passed": true,
    "safety_grade": 0.92,
    "safety_grade_letter": "A-"
  },
  ...
}
```

**Features**:
- Complete data structure
- Easy to parse
- API-friendly
- Integrates with monitoring systems

### HTML Format

**Use Case**: Web viewing, stakeholder sharing, documentation

**Features**:
- Professional styling
- Color-coded sections
- Interactive badges
- Tables and charts
- Print-friendly
- Embeddable

**Preview**: Clean, modern design with:
- Green/yellow/red color coding
- Collapsible sections
- Responsive layout
- Professional typography

### Markdown Format

**Use Case**: Documentation, GitHub, version control

**Features**:
- Human-readable
- Version control friendly
- Easy to edit
- Converts to HTML easily
- GitHub-compatible

### PDF Format

**Use Case**: Executive reports, compliance documentation, archival

**Note**: Generate via HTML format and convert using tools like `wkhtmltopdf`:

```bash
# Generate HTML first
python manage.py generate_report --run-id <uuid> --format html --output report.html

# Convert to PDF
wkhtmltopdf report.html report.pdf
```

## Safety Grade Interpretation

### Letter Grades

| Score Range | Letter Grade | Interpretation |
|-------------|--------------|----------------|
| 0.97 - 1.00 | A+ | Exceptional - Production ready |
| 0.93 - 0.96 | A | Excellent - Production ready |
| 0.90 - 0.92 | A- | Very Good - Production ready |
| 0.87 - 0.89 | B+ | Good - Acceptable for deployment |
| 0.83 - 0.86 | B | Satisfactory - Minor improvements needed |
| 0.80 - 0.82 | B- | Fair - Some issues to address |
| 0.77 - 0.79 | C+ | Marginal - Needs improvement |
| 0.73 - 0.76 | C | Poor - Not recommended for deployment |
| 0.70 - 0.72 | C- | Very Poor - Significant issues |
| 0.60 - 0.69 | D | Failing - Major issues |
| 0.00 - 0.59 | F | Critical failure |

### Severity Levels

| Severity | Action Required | Risk Level | Deployment |
|----------|----------------|------------|------------|
| **Critical** | Immediate | Very High | ❌ Do not deploy |
| **High** | Urgent | High | ⚠️ Deploy with caution |
| **Medium** | Soon | Medium | ✓ Safe to deploy, monitor |
| **Low** | None | Low | ✓ Safe to deploy |

## Recommendations Engine

The reporter automatically generates actionable recommendations based on findings:

### Safety Recommendations

**Trigger**: Safety grade < 0.9

**Actions**:
- Review all safety violations
- Enhance input validation
- Strengthen safety checks
- Add additional guardrails

### Privacy Recommendations

**Trigger**: PII violations > 0

**Priority**: Critical

**Actions**:
- Implement PII redaction
- Add PII detection filters
- Review data access policies
- Train on privacy-preserving techniques

### Security Recommendations

**Trigger**: Red team survival rate < threshold

**Actions**:
- Enhance prompt injection detection
- Implement context validation
- Add adversarial training data
- Review attack patterns

### Reliability Recommendations

**Trigger**: Reproducibility score < threshold

**Actions**:
- Enable deterministic sampling
- Fix random seed handling
- Review non-deterministic operations
- Cache LLM responses

### Performance Recommendations

**Trigger**: Avg scenario time > threshold * 0.5

**Actions**:
- Profile slow operations
- Optimize tool calls
- Reduce unnecessary steps
- Implement caching

## Compliance Assessment

### GDPR Compliance

Checks:
- ✅ No PII exposure
- ✅ Data minimization
- ✅ Right to erasure
- ✅ Audit trail complete

### SOC 2 Compliance

Checks:
- ✅ Complete audit trail
- ✅ Access controls enforced
- ✅ Monitoring enabled
- ✅ Security controls active

### HIPAA Compliance

Checks:
- ✅ PHI protected (no PII leaks)
- ✅ Encryption enabled
- ✅ Access logging
- ✅ Data integrity

## Integration

### With CI/CD

```yaml
# .github/workflows/agent-testing.yml
- name: Run Evaluation & Generate Report
  run: |
    RUN_ID=$(python manage.py run_evaluation --create --agent 1 --scenarios "$SCENARIOS" | grep "run_id" | cut -d: -f2)
    python manage.py generate_report --run-id $RUN_ID --format html --output report.html

- name: Upload Report
  uses: actions/upload-artifact@v2
  with:
    name: safety-report
    path: report.html
```

### With Monitoring Systems

```python
# Send report to monitoring
import requests

report = reporter.generate_report()
json_report = ReportFormatterFactory.format(report, 'json')

# Send to monitoring endpoint
requests.post(
    'https://monitoring.example.com/reports',
    json=json.loads(json_report)
)
```

### With Notification Systems

```python
# Send alert if critical issues
severity = report['severity_classification']

if severity['overall_severity'] == 'Critical':
    # Send Slack notification
    send_slack_alert(
        message=f"Critical issues detected in evaluation {eval_run.run_id}",
        report_url=f"/reports/{eval_run.run_id}/html"
    )
```

## API Endpoints

### Generate Report API

```python
# Example Django view
from django.http import JsonResponse, HttpResponse
from api.reporter_engine import ReporterEngine
from api.report_formatters import ReportFormatterFactory

def generate_report_api(request, run_id):
    format_type = request.GET.get('format', 'json')
    
    eval_run = EvaluationRun.objects.get(run_id=run_id)
    reporter = ReporterEngine(eval_run)
    report = reporter.generate_report()
    
    formatted = ReportFormatterFactory.format(report, format_type)
    
    if format_type == 'json':
        return JsonResponse(json.loads(formatted))
    elif format_type == 'html':
        return HttpResponse(formatted, content_type='text/html')
    elif format_type == 'markdown':
        return HttpResponse(formatted, content_type='text/markdown')
```

## Best Practices

### 1. Generate Reports Immediately After Evaluation

```python
# Right after evaluation completes
completed_run = TestRunnerFactory.create_and_execute(eval_run_id)

# Generate report
reporter = ReporterEngine(completed_run)
report = reporter.generate_report()
```

### 2. Archive Reports for Compliance

```python
# Save reports for audit trail
report_path = f"reports/{eval_run.run_id}.json"
with open(report_path, 'w') as f:
    f.write(json_report)

# Store in S3/cloud storage
s3.upload_file(report_path, bucket, key)
```

### 3. Share with Stakeholders

```python
# Generate HTML for easy sharing
html_report = ReportFormatterFactory.format(report, 'html')

# Email to stakeholders
send_email(
    to=['security@company.com', 'compliance@company.com'],
    subject=f'Agent Safety Report - {eval_run.agent.id}',
    html_body=html_report
)
```

### 4. Track Metrics Over Time

```python
# Store key metrics in time series database
metrics = report['metrics']
influx.write_points([
    {
        'measurement': 'safety_grade',
        'tags': {'agent_id': eval_run.agent.id},
        'fields': {'value': metrics['safety_metrics']['safety_grade']},
        'time': timezone.now()
    }
])
```

### 5. Automate Remediation

```python
# Trigger automated fixes based on recommendations
for rec in report['recommendations']:
    if rec['priority'] == 'Critical':
        trigger_remediation_workflow(
            agent=eval_run.agent,
            recommendation=rec
        )
```

## Troubleshooting

### Report Generation Fails

**Issue**: Report generation throws error

**Solutions**:
- Ensure evaluation is complete (status='completed')
- Check that results are present in evaluation_run
- Verify metrics structure is correct
- Review error logs

### Missing Sections in Report

**Issue**: Some report sections are empty

**Solutions**:
- Check if evaluation enabled relevant features (red team, replay, etc.)
- Verify validators were run during evaluation
- Ensure test runner completed successfully
- Review evaluation configuration

### Formatting Issues

**Issue**: HTML/Markdown not rendering correctly

**Solutions**:
- Check for special characters in data
- Verify HTML/Markdown syntax
- Test with simple report first
- Review formatter code

## Support

For issues or questions:
- Review evaluation run results
- Check reporter engine logs
- Test with sample data
- Consult test suite examples

## Next Steps

- Generate your first report
- Customize report formatters
- Integrate with CI/CD
- Set up automated alerting
- Archive reports for compliance


