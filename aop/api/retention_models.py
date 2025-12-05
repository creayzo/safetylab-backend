"""
Retention, Redaction & Privacy Models

Implements:
- Per-organization retention policies
- PII redaction and sanitization
- Consent tracking
- Data lifecycle management
- Audit trails for privacy actions
"""

from django.db import models
from django.utils import timezone
from datetime import timedelta
import uuid
import logging

logger = logging.getLogger(__name__)


class RetentionPolicy(models.Model):
    """
    Per-organization data retention policy.
    
    Defines how long different types of data are kept based on:
    - Organization tier (free, paid, enterprise)
    - Data type (traces, snapshots, cached responses)
    - Compliance requirements
    """
    
    policy_id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    organization = models.OneToOneField(
        'Organization',
        on_delete=models.CASCADE,
        related_name='retention_policy_settings'
    )
    
    # Retention periods (in days)
    trace_retention_days = models.IntegerField(
        default=30,
        help_text="How long to keep trace events (default: 30 days for free tier)"
    )
    snapshot_retention_days = models.IntegerField(
        default=90,
        help_text="How long to keep environment snapshots"
    )
    audit_log_retention_days = models.IntegerField(
        default=365,
        help_text="How long to keep audit logs (compliance requirement)"
    )
    cached_response_retention_days = models.IntegerField(
        default=7,
        help_text="How long to keep cached LLM/tool responses"
    )
    wal_retention_days = models.IntegerField(
        default=7,
        help_text="How long to keep WAL entries after completion"
    )
    
    # PII handling
    auto_redact_pii = models.BooleanField(
        default=True,
        help_text="Automatically redact PII before storage"
    )
    pii_redaction_mode = models.CharField(
        max_length=50,
        choices=[
            ('mask', 'Mask PII (keep format, hide content)'),
            ('hash', 'Hash PII (one-way, for deduplication)'),
            ('remove', 'Remove PII entirely'),
            ('none', 'No redaction (requires consent)')
        ],
        default='mask'
    )
    
    # Tier-based settings
    tier = models.CharField(
        max_length=50,
        choices=[
            ('free', 'Free (30 days)'),
            ('paid', 'Paid (90 days)'),
            ('enterprise', 'Enterprise (custom)')
        ],
        default='free'
    )
    
    # Consent requirements
    require_consent_for_raw_traces = models.BooleanField(
        default=True,
        help_text="Require explicit consent to store unredacted traces"
    )
    
    # Cleanup settings
    auto_cleanup_enabled = models.BooleanField(
        default=True,
        help_text="Automatically delete expired data"
    )
    last_cleanup_at = models.DateTimeField(
        null=True,
        blank=True,
        help_text="Last time cleanup ran"
    )
    
    # Metadata
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    custom_rules = models.JSONField(
        default=dict,
        help_text="Custom retention rules for specific data types"
    )
    
    class Meta:
        db_table = 'retention_policies'
        indexes = [
            models.Index(fields=['organization']),
            models.Index(fields=['tier']),
        ]
    
    def __str__(self):
        return f"RetentionPolicy({self.organization.name}, tier={self.tier})"
    
    def get_retention_days(self, data_type: str) -> int:
        """
        Get retention period for a specific data type.
        
        Args:
            data_type: Type of data (trace, snapshot, audit_log, etc.)
            
        Returns:
            Number of days to retain
        """
        field_map = {
            'trace': 'trace_retention_days',
            'snapshot': 'snapshot_retention_days',
            'audit_log': 'audit_log_retention_days',
            'cached_response': 'cached_response_retention_days',
            'wal': 'wal_retention_days'
        }
        
        field_name = field_map.get(data_type)
        if field_name:
            return getattr(self, field_name)
        
        # Check custom rules
        return self.custom_rules.get(data_type, self.trace_retention_days)
    
    def is_expired(self, created_at, data_type: str) -> bool:
        """
        Check if data has expired based on retention policy.
        
        Args:
            created_at: When data was created
            data_type: Type of data
            
        Returns:
            True if expired
        """
        retention_days = self.get_retention_days(data_type)
        expiration_date = created_at + timedelta(days=retention_days)
        return timezone.now() > expiration_date


class DataConsentRecord(models.Model):
    """
    Tracks user consent for data retention.
    
    Required for:
    - Storing unredacted traces with PII
    - Extending retention beyond default period
    - Caching LLM responses
    - Cross-organization data sharing
    """
    
    consent_id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    organization = models.ForeignKey(
        'Organization',
        on_delete=models.CASCADE,
        related_name='consent_records'
    )
    
    # Consent scope
    consent_type = models.CharField(
        max_length=100,
        choices=[
            ('raw_trace_storage', 'Store unredacted traces'),
            ('llm_response_caching', 'Cache LLM responses'),
            ('extended_retention', 'Extend retention period'),
            ('analytics', 'Use data for analytics'),
            ('model_training', 'Use data for model training')
        ],
        help_text="Type of consent granted"
    )
    
    # Scope
    applies_to_runs = models.ManyToManyField(
        'Run',
        blank=True,
        related_name='consent_records',
        help_text="Specific runs this consent applies to"
    )
    applies_to_all_runs = models.BooleanField(
        default=False,
        help_text="Applies to all runs for this organization"
    )
    
    # Status
    is_granted = models.BooleanField(default=True)
    granted_at = models.DateTimeField(auto_now_add=True)
    revoked_at = models.DateTimeField(null=True, blank=True)
    
    # Expiration
    expires_at = models.DateTimeField(
        null=True,
        blank=True,
        help_text="When consent expires"
    )
    
    # Attribution
    granted_by = models.CharField(
        max_length=255,
        help_text="Who granted consent (user ID, email, etc.)"
    )
    
    # Details
    notes = models.TextField(blank=True)
    metadata = models.JSONField(default=dict)
    
    class Meta:
        db_table = 'data_consent_records'
        indexes = [
            models.Index(fields=['organization', 'consent_type']),
            models.Index(fields=['is_granted']),
            models.Index(fields=['expires_at']),
        ]
    
    def __str__(self):
        return f"Consent({self.consent_type}, granted={self.is_granted})"
    
    def is_valid(self) -> bool:
        """Check if consent is currently valid."""
        if not self.is_granted:
            return False
        
        if self.revoked_at:
            return False
        
        if self.expires_at and timezone.now() > self.expires_at:
            return False
        
        return True
    
    def revoke(self, reason: str = ""):
        """Revoke this consent."""
        self.is_granted = False
        self.revoked_at = timezone.now()
        if reason:
            self.notes += f"\nRevoked: {reason}"
        self.save()
        
        logger.info(f"Consent {self.consent_id} revoked: {reason}")


class RedactionLog(models.Model):
    """
    Logs PII redaction actions for audit trail.
    
    Tracks:
    - What was redacted
    - When it was redacted
    - Why (policy, consent, manual request)
    - Reversibility (if hashed, can be looked up)
    """
    
    log_id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    
    # Target data
    run = models.ForeignKey(
        'Run',
        on_delete=models.CASCADE,
        null=True,
        blank=True,
        related_name='redaction_logs'
    )
    trace_event = models.ForeignKey(
        'TraceEvent',
        on_delete=models.CASCADE,
        null=True,
        blank=True,
        related_name='redaction_logs'
    )
    
    # Redaction details
    redaction_type = models.CharField(
        max_length=50,
        choices=[
            ('pii_mask', 'PII masked'),
            ('pii_hash', 'PII hashed'),
            ('pii_remove', 'PII removed'),
            ('full_redact', 'Entire field redacted'),
            ('consent_revoke', 'Redacted due to consent revocation')
        ]
    )
    
    fields_redacted = models.JSONField(
        help_text="List of fields that were redacted",
        default=list
    )
    
    pii_types_found = models.JSONField(
        help_text="Types of PII found (SSN, email, etc.)",
        default=list
    )
    
    # Audit
    redacted_at = models.DateTimeField(auto_now_add=True)
    redacted_by = models.CharField(
        max_length=255,
        help_text="System, user ID, or automated process"
    )
    reason = models.TextField(
        help_text="Why redaction was performed"
    )
    
    # Reversibility
    is_reversible = models.BooleanField(
        default=False,
        help_text="Can this redaction be reversed (e.g., via hash lookup)"
    )
    hash_salt = models.CharField(
        max_length=255,
        null=True,
        blank=True,
        help_text="Salt used for hashing (for reversal)"
    )
    
    class Meta:
        db_table = 'redaction_logs'
        indexes = [
            models.Index(fields=['run']),
            models.Index(fields=['trace_event']),
            models.Index(fields=['redacted_at']),
        ]
    
    def __str__(self):
        return f"RedactionLog({self.redaction_type}, run={self.run_id})"


class PrivacyAuditLog(models.Model):
    """
    Enhanced audit log for privacy-related actions.
    
    Extends base AuditLog with privacy-specific tracking:
    - Data access (who viewed PII)
    - Data exports
    - Consent changes
    - Retention policy changes
    - Data deletion requests
    """
    
    audit_id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    organization = models.ForeignKey(
        'Organization',
        on_delete=models.CASCADE,
        related_name='privacy_audit_logs'
    )
    
    # Action details
    action_type = models.CharField(
        max_length=100,
        choices=[
            ('data_access', 'Data Access'),
            ('data_export', 'Data Export'),
            ('data_deletion', 'Data Deletion'),
            ('consent_granted', 'Consent Granted'),
            ('consent_revoked', 'Consent Revoked'),
            ('retention_policy_change', 'Retention Policy Change'),
            ('pii_redaction', 'PII Redaction'),
            ('key_rotation', 'API Key Rotation'),
            ('policy_update', 'Policy Update')
        ]
    )
    
    # Attribution
    performed_by = models.CharField(
        max_length=255,
        help_text="User ID or system process"
    )
    performed_at = models.DateTimeField(auto_now_add=True)
    
    # Context
    affected_runs = models.ManyToManyField(
        'Run',
        blank=True,
        related_name='privacy_audits'
    )
    
    details = models.JSONField(
        default=dict,
        help_text="Action details (what changed, why, etc.)"
    )
    
    # Compliance
    is_gdpr_related = models.BooleanField(
        default=False,
        help_text="Related to GDPR request"
    )
    is_ccpa_related = models.BooleanField(
        default=False,
        help_text="Related to CCPA request"
    )
    
    # Results
    success = models.BooleanField(default=True)
    error_message = models.TextField(blank=True)
    
    # Metadata
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    user_agent = models.TextField(blank=True)
    
    class Meta:
        db_table = 'privacy_audit_logs'
        indexes = [
            models.Index(fields=['organization', 'action_type']),
            models.Index(fields=['performed_at']),
            models.Index(fields=['is_gdpr_related']),
            models.Index(fields=['is_ccpa_related']),
        ]
    
    def __str__(self):
        return f"PrivacyAudit({self.action_type} by {self.performed_by})"


class DataDeletionRequest(models.Model):
    """
    Tracks data deletion requests (GDPR Right to Erasure, etc.).
    
    Manages:
    - User/org requests to delete data
    - Scheduled deletion
    - Verification of deletion
    - Retention of deletion proof (for compliance)
    """
    
    request_id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    organization = models.ForeignKey(
        'Organization',
        on_delete=models.CASCADE,
        related_name='deletion_requests'
    )
    
    # Request details
    request_type = models.CharField(
        max_length=50,
        choices=[
            ('full_org', 'Delete all organization data'),
            ('specific_runs', 'Delete specific runs'),
            ('time_range', 'Delete data in time range'),
            ('pii_only', 'Delete only PII data')
        ]
    )
    
    # Scope
    runs_to_delete = models.ManyToManyField(
        'Run',
        blank=True,
        related_name='deletion_requests'
    )
    delete_after_date = models.DateTimeField(
        null=True,
        blank=True,
        help_text="Delete data created after this date"
    )
    delete_before_date = models.DateTimeField(
        null=True,
        blank=True,
        help_text="Delete data created before this date"
    )
    
    # Status
    status = models.CharField(
        max_length=50,
        choices=[
            ('pending', 'Pending'),
            ('in_progress', 'In Progress'),
            ('completed', 'Completed'),
            ('failed', 'Failed'),
            ('cancelled', 'Cancelled')
        ],
        default='pending'
    )
    
    # Timeline
    requested_at = models.DateTimeField(auto_now_add=True)
    requested_by = models.CharField(max_length=255)
    scheduled_for = models.DateTimeField(
        help_text="When deletion should occur"
    )
    started_at = models.DateTimeField(null=True, blank=True)
    completed_at = models.DateTimeField(null=True, blank=True)
    
    # Results
    items_deleted = models.JSONField(
        default=dict,
        help_text="Count of deleted items by type"
    )
    
    # Compliance
    legal_basis = models.CharField(
        max_length=100,
        choices=[
            ('gdpr_right_to_erasure', 'GDPR Right to Erasure'),
            ('ccpa_right_to_delete', 'CCPA Right to Delete'),
            ('retention_policy', 'Retention Policy Expiration'),
            ('consent_revocation', 'Consent Revocation'),
            ('user_request', 'User Request'),
            ('admin_request', 'Admin Request')
        ]
    )
    
    notes = models.TextField(blank=True)
    
    # Proof of deletion (for compliance)
    deletion_certificate = models.JSONField(
        default=dict,
        help_text="Cryptographic proof of deletion"
    )
    
    class Meta:
        db_table = 'data_deletion_requests'
        indexes = [
            models.Index(fields=['organization', 'status']),
            models.Index(fields=['scheduled_for']),
            models.Index(fields=['requested_at']),
        ]
    
    def __str__(self):
        return f"DeletionRequest({self.request_type}, status={self.status})"
    
    def execute(self):
        """Execute the deletion request."""
        from api.retention_tasks import execute_deletion_request
        execute_deletion_request.delay(str(self.request_id))
