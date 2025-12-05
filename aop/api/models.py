from django.db import models
from django.contrib.postgres.fields import JSONField
from django.core.exceptions import ValidationError
import uuid
import json

# Import authentication models
from .auth_models import (
    OrganizationSaltKey,
    AgentAPIKey,
    SignatureVerifier,
    MTLSCertificate,
    OAuthToken
)


class Organization(models.Model):
    """
    Organization model with rotatable salt key and policy configuration.
    
    The salt_key field is deprecated - use OrganizationSaltKey model for encrypted storage.
    """
    id = models.AutoField(primary_key=True)
    name = models.CharField(max_length=255, unique=True)
    salt_key = models.CharField(max_length=255, blank=True)  # Deprecated - use OrganizationSaltKey
    policy_config = models.JSONField(default=dict, blank=True)
    retention_policy = models.JSONField(default=dict, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = 'organizations'
        ordering = ['name']

    def __str__(self):
        return self.name
    
    def get_active_salt_key(self):
        """Get the currently active OrganizationSaltKey for this organization."""
        # Import here to avoid circular import
        from .auth_models import OrganizationSaltKey
        return OrganizationSaltKey.objects.filter(
            organization=self,
            is_active=True
        ).first()
    
    def initialize_salt_key(self):
        """Initialize a salt key for this organization if none exists."""
        from .auth_models import OrganizationSaltKey
        if not self.get_active_salt_key():
            return OrganizationSaltKey.create_for_organization(self)
        return self.get_active_salt_key()
    
    def rotate_salt_key(self, expiry_days: int = 90):
        """Rotate the organization's salt key."""
        active_key = self.get_active_salt_key()
        if active_key:
            return active_key.rotate(expiry_days)
        return self.initialize_salt_key()


class Agent(models.Model):
    """Agent model with owner organization and runtime configuration."""
    id = models.AutoField(primary_key=True)
    owner = models.ForeignKey(
        Organization,
        on_delete=models.CASCADE,
        related_name='agents'
    )
    endpoint_metadata = models.JSONField(default=dict, blank=True)  # callback URL or webhook
    runtime_config = models.JSONField(default=dict, blank=True)  # model name, sampling params
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = 'agents'
        ordering = ['-created_at']

    def __str__(self):
        return f"Agent {self.id} (Org: {self.owner.name})"
    
    def create_api_key(self, name: str = "", scopes: list = None, expires_in_days: int = 365, created_by=None):
        """Create a new API key for this agent."""
        from .auth_models import AgentAPIKey
        return AgentAPIKey.create_for_agent(
            agent=self,
            name=name,
            scopes=scopes,
            expires_in_days=expires_in_days,
            created_by=created_by
        )
    
    def get_active_api_keys(self):
        """Get all active API keys for this agent."""
        from .auth_models import AgentAPIKey
        return AgentAPIKey.objects.filter(agent=self, is_active=True)


class Run(models.Model):
    """Run model tracking agent execution with status."""
    STATUS_CHOICES = [
        ('running', 'Running'),
        ('failed', 'Failed'),
        ('success', 'Success'),
    ]

    run_id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    agent = models.ForeignKey(
        Agent,
        on_delete=models.CASCADE,
        related_name='runs'
    )
    scenario_id = models.CharField(max_length=255, null=True, blank=True)
    seed = models.IntegerField(null=True, blank=True)
    start_ts = models.DateTimeField(auto_now_add=True)
    end_ts = models.DateTimeField(null=True, blank=True)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='running')

    class Meta:
        db_table = 'runs'
        ordering = ['-start_ts']
        indexes = [
            models.Index(fields=['agent', 'status']),
            models.Index(fields=['start_ts']),
        ]

    def __str__(self):
        return f"Run {self.run_id} - {self.status}"


class TraceEvent(models.Model):
    """
    TraceEvent model for capturing detailed execution traces.
    
    Follows Toon canonical spec format. Each TraceEvent must include:
    - seq: sequence number in run
    - t: ISO timestamp
    - actor: agent|tool|user|system|redteam
    - type: reasoning|action_request|action_response|final_output|error
    - payload: Toon-formatted object (machine-parseable)
    - meta: Contains seed, run_id, agent_id, session_id, signature (HMAC)
    
    Payload structures by type:
    
    1. Reasoning payload:
       {
         goal: "...",
         steps: [
           { step_id: "s1", description: "...", decision: "...", confidence: 0.82 }
         ],
         safety_checks: [
           { name: "policy_lookup", result: "passed" }
         ],
         uncertainty: "low|medium|high"
       }
    
    2. Action_request payload:
       {
         action: "create_ticket",
         params: { title: "...", order_id: "..." },
         context: { ... }
       }
    
    3. Action_response payload:
       {
         status: "ok|error",
         data: { ticket_id: "..." },
         meta: { latency_ms: 120, policy_flags: [] }
       }
    
    4. Final_output payload:
       {
         text: "Your refund ticket created: T-999",
         structured: { ... }  # optional structured result
       }
    
    All payloads must be machine-parseable by Toon library parser.
    """
    ACTOR_CHOICES = [
        ('agent', 'Agent'),
        ('tool', 'Tool'),
        ('system', 'System'),
        ('user', 'User'),
        ('redteam', 'Red Team'),
    ]

    TYPE_CHOICES = [
        ('reasoning', 'Reasoning'),
        ('action_request', 'Action Request'),
        ('action_response', 'Action Response'),
        ('final_output', 'Final Output'),
        ('error', 'Error'),
    ]

    UNCERTAINTY_CHOICES = [
        ('low', 'Low'),
        ('medium', 'Medium'),
        ('high', 'High'),
    ]

    id = models.BigAutoField(primary_key=True)
    run = models.ForeignKey(
        Run,
        on_delete=models.CASCADE,
        related_name='trace_events'
    )
    seq_no = models.IntegerField()  # seq in Toon spec
    timestamp = models.DateTimeField(auto_now_add=True)  # t in Toon spec (ISO timestamp)
    actor = models.CharField(max_length=20, choices=ACTOR_CHOICES)
    type = models.CharField(max_length=30, choices=TYPE_CHOICES)
    payload = models.TextField()  # Toon-formatted string (machine-parseable)
    signature = models.CharField(max_length=512, blank=True)  # HMAC signature
    meta = models.JSONField(default=dict, blank=True)  # seed, run_id, agent_id, session_id, signature

    class Meta:
        db_table = 'trace_events'
        ordering = ['run', 'seq_no']
        unique_together = [['run', 'seq_no']]
        indexes = [
            models.Index(fields=['run', 'seq_no']),
            models.Index(fields=['timestamp']),
            models.Index(fields=['actor']),
            models.Index(fields=['type']),
        ]

    def __str__(self):
        return f"TraceEvent {self.run.run_id}:{self.seq_no} - {self.type}"
    
    def get_toon_canonical_format(self):
        """
        Returns the event in Toon canonical format.
        """
        try:
            payload_data = json.loads(self.payload) if isinstance(self.payload, str) else self.payload
        except json.JSONDecodeError:
            payload_data = {"raw": self.payload}
        
        return {
            "seq": self.seq_no,
            "t": self.timestamp.isoformat(),
            "actor": self.actor,
            "type": self.type,
            "payload": payload_data,
            "meta": {
                **self.meta,
                "signature": self.signature,
                "run_id": str(self.run.run_id),
                "agent_id": self.run.agent.id,
            }
        }
    
    def validate_payload_structure(self):
        """
        Validates that the payload matches the expected Toon structure for its type.
        """
        try:
            payload_data = json.loads(self.payload) if isinstance(self.payload, str) else self.payload
        except json.JSONDecodeError:
            raise ValidationError("Payload must be valid JSON/Toon format")
        
        if self.type == 'reasoning':
            required_fields = ['goal', 'steps', 'safety_checks', 'uncertainty']
            for field in required_fields:
                if field not in payload_data:
                    raise ValidationError(f"Reasoning payload missing required field: {field}")
            
            if payload_data['uncertainty'] not in ['low', 'medium', 'high']:
                raise ValidationError("Uncertainty must be low, medium, or high")
        
        elif self.type == 'action_request':
            required_fields = ['action', 'params']
            for field in required_fields:
                if field not in payload_data:
                    raise ValidationError(f"Action_request payload missing required field: {field}")
        
        elif self.type == 'action_response':
            required_fields = ['status', 'data']
            for field in required_fields:
                if field not in payload_data:
                    raise ValidationError(f"Action_response payload missing required field: {field}")
            
            if payload_data['status'] not in ['ok', 'error']:
                raise ValidationError("Action_response status must be 'ok' or 'error'")
        
        elif self.type == 'final_output':
            if 'text' not in payload_data:
                raise ValidationError("Final_output payload missing required field: text")
        
        return True
    
    def clean(self):
        """
        Validates the model before saving.
        """
        super().clean()
        self.validate_payload_structure()


class TraceRecord(models.Model):
    """TraceRecord model for aggregated trace summaries."""
    id = models.BigAutoField(primary_key=True)
    run = models.OneToOneField(
        Run,
        on_delete=models.CASCADE,
        related_name='trace_record'
    )
    aggregation_pointer = models.CharField(max_length=512)
    summary_metrics = models.JSONField(default=dict, blank=True)  # ASG placeholders
    object_store_path = models.CharField(max_length=1024)  # Link to stored full trace
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = 'trace_records'
        ordering = ['-created_at']

    def __str__(self):
        return f"TraceRecord for Run {self.run.run_id}"


class EnvironmentSnapshot(models.Model):
    """EnvironmentSnapshot model for reproducibility."""
    id = models.AutoField(primary_key=True)
    snapshot_id = models.UUIDField(default=uuid.uuid4, unique=True, editable=False)
    run = models.ForeignKey(
        Run,
        on_delete=models.CASCADE,
        related_name='environment_snapshots',
        null=True,
        blank=True
    )
    mock_state_pointer = models.CharField(max_length=1024)
    snapshot_data = models.JSONField(default=dict, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = 'environment_snapshots'
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['snapshot_id']),
            models.Index(fields=['run']),
        ]

    def __str__(self):
        return f"EnvironmentSnapshot {self.snapshot_id}"


class AuditLog(models.Model):
    """
    AuditLog model for admin actions and config changes.
    
    Follows same Toon canonical spec format as TraceEvent but for administrative
    actions and configuration changes. Each AuditLog entry includes:
    - timestamp: ISO timestamp
    - actor: agent|tool|user|system|admin|redteam
    - type: includes all TraceEvent types plus config_change, admin_action, policy_update
    - payload: Toon-formatted object (machine-parseable)
    - signature: HMAC signature for integrity verification
    - meta: Additional context (user_id, session_id, etc.)
    
    All payloads must be machine-parseable by Toon library parser.
    """
    ACTOR_CHOICES = [
        ('agent', 'Agent'),
        ('tool', 'Tool'),
        ('system', 'System'),
        ('user', 'User'),
        ('admin', 'Admin'),
        ('redteam', 'Red Team'),
    ]

    TYPE_CHOICES = [
        ('reasoning', 'Reasoning'),
        ('action_request', 'Action Request'),
        ('action_response', 'Action Response'),
        ('final_output', 'Final Output'),
        ('error', 'Error'),
        ('config_change', 'Config Change'),
        ('admin_action', 'Admin Action'),
        ('policy_update', 'Policy Update'),
    ]

    id = models.BigAutoField(primary_key=True)
    organization = models.ForeignKey(
        Organization,
        on_delete=models.CASCADE,
        related_name='audit_logs',
        null=True,
        blank=True
    )
    timestamp = models.DateTimeField(auto_now_add=True)  # ISO timestamp
    actor = models.CharField(max_length=20, choices=ACTOR_CHOICES)
    type = models.CharField(max_length=30, choices=TYPE_CHOICES)
    payload = models.TextField()  # Toon-formatted string (machine-parseable)
    signature = models.CharField(max_length=512, blank=True)  # HMAC signature
    meta = models.JSONField(default=dict, blank=True)  # Additional context
    user_id = models.IntegerField(null=True, blank=True)  # Reference to user performing action

    class Meta:
        db_table = 'audit_logs'
        ordering = ['-timestamp']
        indexes = [
            models.Index(fields=['organization', 'timestamp']),
            models.Index(fields=['actor']),
            models.Index(fields=['type']),
            models.Index(fields=['user_id']),
        ]

    def __str__(self):
        return f"AuditLog {self.id} - {self.type} by {self.actor}"
    
    def get_toon_canonical_format(self):
        """
        Returns the audit log entry in Toon canonical format.
        """
        try:
            payload_data = json.loads(self.payload) if isinstance(self.payload, str) else self.payload
        except json.JSONDecodeError:
            payload_data = {"raw": self.payload}
        
        return {
            "t": self.timestamp.isoformat(),
            "actor": self.actor,
            "type": self.type,
            "payload": payload_data,
            "meta": {
                **self.meta,
                "signature": self.signature,
                "organization_id": self.organization.id if self.organization else None,
                "user_id": self.user_id,
            }
        }
    
    def validate_payload_structure(self):
        """
        Validates that the payload is valid JSON/Toon format.
        """
        try:
            payload_data = json.loads(self.payload) if isinstance(self.payload, str) else self.payload
        except json.JSONDecodeError:
            raise ValidationError("Payload must be valid JSON/Toon format")
        
        # Additional validation for admin-specific types
        if self.type == 'config_change':
            required_fields = ['config_key', 'old_value', 'new_value']
            for field in required_fields:
                if field not in payload_data:
                    raise ValidationError(f"Config_change payload missing required field: {field}")
        
        elif self.type == 'policy_update':
            required_fields = ['policy_name', 'changes']
            for field in required_fields:
                if field not in payload_data:
                    raise ValidationError(f"Policy_update payload missing required field: {field}")
        
        return True
    
    def clean(self):
        """
        Validates the model before saving.
        """
        super().clean()
        self.validate_payload_structure()
