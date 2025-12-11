# Generated migration for scenario models

from django.db import migrations, models
import django.db.models.deletion
import uuid


class Migration(migrations.Migration):

    dependencies = [
        ('api', '0005_add_comprehensive_evaluation_run'),
    ]

    operations = [
        migrations.CreateModel(
            name='Scenario',
            fields=[
                ('scenario_id', models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ('name', models.CharField(max_length=255, unique=True)),
                ('description', models.TextField()),
                ('scenario_type', models.CharField(choices=[('business', 'Business Logic Test'), ('adversarial', 'Adversarial/Red Team Test'), ('stress', 'Stress/Load Test'), ('edge_case', 'Edge Case Test'), ('integration', 'Integration Test'), ('compliance', 'Compliance/Policy Test')], max_length=20)),
                ('difficulty', models.CharField(choices=[('easy', 'Easy'), ('medium', 'Medium'), ('hard', 'Hard'), ('extreme', 'Extreme')], default='medium', max_length=20)),
                ('config', models.JSONField(default=dict, help_text='Scenario parameters')),
                ('initial_state', models.JSONField(default=dict, help_text='Initial environment/context state')),
                ('script', models.JSONField(default=list, help_text='List of scripted events with timestamps')),
                ('injection_points', models.JSONField(default=list, help_text='List of injection configurations')),
                ('expected_outcomes', models.JSONField(default=dict, help_text='Expected behavior and validation criteria')),
                ('tags', models.JSONField(default=list, help_text='Tags for categorization')),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('updated_at', models.DateTimeField(auto_now=True)),
                ('created_by', models.CharField(blank=True, max_length=255)),
                ('is_active', models.BooleanField(default=True)),
            ],
            options={
                'db_table': 'scenarios',
                'ordering': ['-created_at'],
            },
        ),
        migrations.CreateModel(
            name='InjectionTemplate',
            fields=[
                ('template_id', models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ('name', models.CharField(max_length=255, unique=True)),
                ('description', models.TextField()),
                ('injection_type', models.CharField(choices=[('user_message', 'User Message Injection'), ('adversarial', 'Adversarial Payload'), ('tool_error', 'Tool Error Simulation'), ('timeout', 'Timeout Simulation'), ('network_error', 'Network Error'), ('rate_limit', 'Rate Limit'), ('file_upload', 'File Upload'), ('concurrency', 'Concurrency Stress'), ('system_error', 'System Error'), ('data_corruption', 'Data Corruption')], max_length=30)),
                ('payload_template', models.JSONField(default=dict, help_text='Template payload with variables')),
                ('trigger_config', models.JSONField(default=dict, help_text='Trigger conditions (timestamp, event count, etc.)')),
                ('tags', models.JSONField(default=list)),
                ('severity', models.CharField(choices=[('low', 'Low'), ('medium', 'Medium'), ('high', 'High'), ('critical', 'Critical')], default='medium', max_length=20)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('updated_at', models.DateTimeField(auto_now=True)),
                ('is_active', models.BooleanField(default=True)),
            ],
            options={
                'db_table': 'injection_templates',
                'ordering': ['name'],
            },
        ),
        migrations.CreateModel(
            name='ScenarioRun',
            fields=[
                ('run_id', models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ('seed', models.BigIntegerField(blank=True, help_text='Random seed for reproducibility', null=True)),
                ('environment_snapshot_id', models.CharField(blank=True, max_length=255)),
                ('status', models.CharField(choices=[('pending', 'Pending'), ('running', 'Running'), ('completed', 'Completed'), ('failed', 'Failed'), ('timeout', 'Timeout'), ('cancelled', 'Cancelled')], default='pending', max_length=20)),
                ('started_at', models.DateTimeField(blank=True, null=True)),
                ('completed_at', models.DateTimeField(blank=True, null=True)),
                ('injections_performed', models.JSONField(default=list, help_text='Log of all injections performed')),
                ('events_triggered', models.JSONField(default=list, help_text='Log of all events triggered')),
                ('results', models.JSONField(default=dict, help_text='Scenario execution results')),
                ('deviations', models.JSONField(default=list, help_text='Deviations from expected behavior')),
                ('error_message', models.TextField(blank=True)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('updated_at', models.DateTimeField(auto_now=True)),
                ('agent_run', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.CASCADE, related_name='scenario_runs', to='api.run')),
                ('scenario', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='runs', to='api.scenario')),
            ],
            options={
                'db_table': 'scenario_runs',
                'ordering': ['-created_at'],
            },
        ),
        migrations.AddIndex(
            model_name='scenario',
            index=models.Index(fields=['scenario_type'], name='scenarios_scenari_e3b790_idx'),
        ),
        migrations.AddIndex(
            model_name='scenario',
            index=models.Index(fields=['difficulty'], name='scenarios_difficu_a7e2c1_idx'),
        ),
        migrations.AddIndex(
            model_name='scenario',
            index=models.Index(fields=['is_active'], name='scenarios_is_acti_8f9b12_idx'),
        ),
        migrations.AddIndex(
            model_name='injectiontemplate',
            index=models.Index(fields=['injection_type'], name='injection__injecti_c5d6e3_idx'),
        ),
        migrations.AddIndex(
            model_name='injectiontemplate',
            index=models.Index(fields=['severity'], name='injection__severit_d4e5f2_idx'),
        ),
        migrations.AddIndex(
            model_name='scenariorun',
            index=models.Index(fields=['scenario', 'status'], name='scenario_r_scenari_b6c7d8_idx'),
        ),
        migrations.AddIndex(
            model_name='scenariorun',
            index=models.Index(fields=['started_at'], name='scenario_r_started_e7f8a9_idx'),
        ),
        migrations.AddIndex(
            model_name='scenariorun',
            index=models.Index(fields=['status'], name='scenario_r_status_f9a0b1_idx'),
        ),
    ]


