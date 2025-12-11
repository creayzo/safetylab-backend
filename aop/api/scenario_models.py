"""
Scenario Models for Test Orchestration

Defines scenario configurations, injection points, and test conditions.
"""

from django.db import models
from django.contrib.postgres.fields import JSONField
import uuid
from datetime import datetime
from typing import Dict, Any, List, Optional


class Scenario(models.Model):
    """
    Scenario definition for testing agents.
    
    A scenario is a scripted test case that defines:
    - Initial conditions
    - Sequence of events/messages
    - Injection points for adversarial/error conditions
    - Expected outcomes
    """
    
    SCENARIO_TYPE_CHOICES = [
        ('business', 'Business Logic Test'),
        ('adversarial', 'Adversarial/Red Team Test'),
        ('stress', 'Stress/Load Test'),
        ('edge_case', 'Edge Case Test'),
        ('integration', 'Integration Test'),
        ('compliance', 'Compliance/Policy Test'),
    ]
    
    DIFFICULTY_CHOICES = [
        ('easy', 'Easy'),
        ('medium', 'Medium'),
        ('hard', 'Hard'),
        ('extreme', 'Extreme'),
    ]
    
    scenario_id = models.UUIDField(
        primary_key=True, 
        default=uuid.uuid4, 
        editable=False
    )
    name = models.CharField(max_length=255, unique=True)
    description = models.TextField()
    scenario_type = models.CharField(
        max_length=20, 
        choices=SCENARIO_TYPE_CHOICES
    )
    difficulty = models.CharField(
        max_length=20, 
        choices=DIFFICULTY_CHOICES, 
        default='medium'
    )
    
    # Scenario configuration
    config = models.JSONField(default=dict, help_text='Scenario parameters')
    initial_state = models.JSONField(
        default=dict, 
        help_text='Initial environment/context state'
    )
    
    # Script definition
    script = models.JSONField(
        default=list,
        help_text='List of scripted events with timestamps'
    )
    
    # Injection points
    injection_points = models.JSONField(
        default=list,
        help_text='List of injection configurations'
    )
    
    # Expected outcomes
    expected_outcomes = models.JSONField(
        default=dict,
        help_text='Expected behavior and validation criteria'
    )
    
    # Metadata
    tags = models.JSONField(default=list, help_text='Tags for categorization')
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    created_by = models.CharField(max_length=255, blank=True)
    is_active = models.BooleanField(default=True)
    
    class Meta:
        db_table = 'scenarios'
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['scenario_type']),
            models.Index(fields=['difficulty']),
            models.Index(fields=['is_active']),
        ]
    
    def __str__(self):
        return f"Scenario: {self.name} ({self.scenario_type})"


class ScenarioRun(models.Model):
    """
    Tracks execution of a scenario.
    
    Links a scenario to an actual agent run, tracking:
    - Execution status
    - Injections performed
    - Results and deviations
    """
    
    STATUS_CHOICES = [
        ('pending', 'Pending'),
        ('running', 'Running'),
        ('completed', 'Completed'),
        ('failed', 'Failed'),
        ('timeout', 'Timeout'),
        ('cancelled', 'Cancelled'),
    ]
    
    run_id = models.UUIDField(
        primary_key=True, 
        default=uuid.uuid4, 
        editable=False
    )
    scenario = models.ForeignKey(
        Scenario, 
        on_delete=models.CASCADE, 
        related_name='runs'
    )
    
    # Link to agent run
    agent_run = models.ForeignKey(
        'Run', 
        on_delete=models.CASCADE,
        related_name='scenario_runs',
        null=True,
        blank=True
    )
    
    # Execution context
    seed = models.BigIntegerField(
        null=True, 
        blank=True, 
        help_text='Random seed for reproducibility'
    )
    environment_snapshot_id = models.CharField(
        max_length=255, 
        blank=True
    )
    
    # Status tracking
    status = models.CharField(
        max_length=20, 
        choices=STATUS_CHOICES, 
        default='pending'
    )
    started_at = models.DateTimeField(null=True, blank=True)
    completed_at = models.DateTimeField(null=True, blank=True)
    
    # Execution log
    injections_performed = models.JSONField(
        default=list,
        help_text='Log of all injections performed'
    )
    events_triggered = models.JSONField(
        default=list,
        help_text='Log of all events triggered'
    )
    
    # Results
    results = models.JSONField(
        default=dict,
        help_text='Scenario execution results'
    )
    deviations = models.JSONField(
        default=list,
        help_text='Deviations from expected behavior'
    )
    error_message = models.TextField(blank=True)
    
    # Metadata
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        db_table = 'scenario_runs'
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['scenario', 'status']),
            models.Index(fields=['started_at']),
            models.Index(fields=['status']),
        ]
    
    def __str__(self):
        return f"ScenarioRun {self.run_id} - {self.scenario.name}"


class InjectionTemplate(models.Model):
    """
    Reusable injection templates for common attack patterns.
    
    Templates define:
    - Type of injection (message, error, condition)
    - Payload/configuration
    - Trigger conditions
    """
    
    INJECTION_TYPE_CHOICES = [
        ('user_message', 'User Message Injection'),
        ('adversarial', 'Adversarial Payload'),
        ('tool_error', 'Tool Error Simulation'),
        ('timeout', 'Timeout Simulation'),
        ('network_error', 'Network Error'),
        ('rate_limit', 'Rate Limit'),
        ('file_upload', 'File Upload'),
        ('concurrency', 'Concurrency Stress'),
        ('system_error', 'System Error'),
        ('data_corruption', 'Data Corruption'),
    ]
    
    template_id = models.UUIDField(
        primary_key=True, 
        default=uuid.uuid4, 
        editable=False
    )
    name = models.CharField(max_length=255, unique=True)
    description = models.TextField()
    injection_type = models.CharField(
        max_length=30, 
        choices=INJECTION_TYPE_CHOICES
    )
    
    # Template configuration
    payload_template = models.JSONField(
        default=dict,
        help_text='Template payload with variables'
    )
    trigger_config = models.JSONField(
        default=dict,
        help_text='Trigger conditions (timestamp, event count, etc.)'
    )
    
    # Metadata
    tags = models.JSONField(default=list)
    severity = models.CharField(
        max_length=20,
        choices=[
            ('low', 'Low'),
            ('medium', 'Medium'),
            ('high', 'High'),
            ('critical', 'Critical'),
        ],
        default='medium'
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    is_active = models.BooleanField(default=True)
    
    class Meta:
        db_table = 'injection_templates'
        ordering = ['name']
        indexes = [
            models.Index(fields=['injection_type']),
            models.Index(fields=['severity']),
        ]
    
    def __str__(self):
        return f"InjectionTemplate: {self.name}"


