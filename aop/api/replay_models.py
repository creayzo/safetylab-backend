"""
Replay and Determinism Models

Supports deterministic replay of agent runs by recording:
- Seeds and sampling parameters
- Environment snapshots
- Cached LLM responses
- Tool responses
- Replay execution and verification
"""

from django.db import models
from django.contrib.postgres.fields import ArrayField
import uuid
import json
from datetime import datetime
from typing import Dict, Any, Optional, List


class ReplaySnapshot(models.Model):
    """
    Captures complete state needed for deterministic replay.
    
    Includes:
    - Agent configuration
    - Model sampling parameters
    - Environment state reference
    - Tool response cache
    - Database snapshot ID
    """
    
    snapshot_id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    run = models.OneToOneField('Run', on_delete=models.CASCADE, related_name='replay_snapshot')
    
    # Run configuration
    seed = models.IntegerField(
        help_text="Random seed for reproducibility"
    )
    
    # Model sampling parameters
    model_name = models.CharField(max_length=255, help_text="LLM model identifier")
    temperature = models.FloatField(default=0.7, help_text="Sampling temperature")
    top_p = models.FloatField(default=0.9, help_text="Nucleus sampling threshold")
    max_tokens = models.IntegerField(null=True, blank=True, help_text="Max generation tokens")
    other_params = models.JSONField(
        default=dict,
        help_text="Other model params (top_k, frequency_penalty, etc.)"
    )
    
    # Environment state
    environment_snapshot_id = models.UUIDField(
        null=True,
        blank=True,
        help_text="Reference to EnvironmentSnapshot for system state"
    )
    
    # Database/mock state
    db_snapshot_id = models.CharField(
        max_length=255,
        null=True,
        blank=True,
        help_text="Database snapshot identifier (for mock DB state)"
    )
    db_snapshot_url = models.URLField(
        max_length=1024,
        null=True,
        blank=True,
        help_text="URL to database snapshot storage"
    )
    
    # Tool response cache
    tool_responses_cached = models.BooleanField(
        default=False,
        help_text="Whether tool responses are cached for replay"
    )
    
    # LLM response cache
    llm_responses_cached = models.BooleanField(
        default=False,
        help_text="Whether LLM responses are cached (requires permission)"
    )
    
    # Replay metadata
    is_replayable = models.BooleanField(
        default=True,
        help_text="Whether this run can be replayed"
    )
    replay_mode = models.CharField(
        max_length=50,
        choices=[
            ('full', 'Full replay with cached responses'),
            ('hybrid', 'Hybrid: cached tools, re-run model'),
            ('verification', 'Verification only: re-run and compare')
        ],
        default='full'
    )
    
    # Timestamps
    created_at = models.DateTimeField(auto_now_add=True)
    
    # Additional context
    metadata = models.JSONField(
        default=dict,
        help_text="Additional replay context"
    )
    
    class Meta:
        db_table = 'replay_snapshots'
        indexes = [
            models.Index(fields=['run']),
            models.Index(fields=['is_replayable']),
            models.Index(fields=['created_at']),
        ]
    
    def __str__(self):
        return f"ReplaySnapshot({self.snapshot_id}) for Run({self.run_id})"
    
    def get_environment_snapshot(self):
        """Get associated environment snapshot."""
        if self.environment_snapshot_id:
            from api.models import EnvironmentSnapshot
            try:
                return EnvironmentSnapshot.objects.get(
                    snapshot_id=self.environment_snapshot_id
                )
            except EnvironmentSnapshot.DoesNotExist:
                return None
        return None


class CachedLLMResponse(models.Model):
    """
    Stores cached LLM responses for deterministic replay.
    
    Only stored if:
    - Organization has permission
    - User consents to caching
    - Not prohibited by privacy policy
    """
    
    cache_id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    snapshot = models.ForeignKey(
        ReplaySnapshot,
        on_delete=models.CASCADE,
        related_name='cached_responses'
    )
    
    # Event reference
    seq_no = models.IntegerField(help_text="Sequence number of the event")
    event_type = models.CharField(
        max_length=50,
        help_text="Type of event (reasoning, action_request, etc.)"
    )
    
    # LLM call details
    prompt_hash = models.CharField(
        max_length=64,
        help_text="SHA-256 hash of the prompt for cache lookup",
        db_index=True
    )
    model_name = models.CharField(max_length=255)
    
    # Cached response
    response_text = models.TextField(help_text="Raw LLM response")
    response_tokens = models.IntegerField(help_text="Token count")
    
    # Metadata
    timestamp = models.DateTimeField(auto_now_add=True)
    latency_ms = models.IntegerField(help_text="Original response latency")
    finish_reason = models.CharField(
        max_length=50,
        null=True,
        blank=True,
        help_text="Why generation stopped (length, stop, etc.)"
    )
    
    # Privacy
    consent_given = models.BooleanField(
        default=False,
        help_text="User consented to caching"
    )
    expires_at = models.DateTimeField(
        null=True,
        blank=True,
        help_text="When this cached response should be deleted"
    )
    
    class Meta:
        db_table = 'cached_llm_responses'
        indexes = [
            models.Index(fields=['snapshot', 'seq_no']),
            models.Index(fields=['prompt_hash']),
            models.Index(fields=['expires_at']),
        ]
        unique_together = [['snapshot', 'seq_no']]
    
    def __str__(self):
        return f"CachedLLMResponse(seq={self.seq_no}, model={self.model_name})"
    
    def is_expired(self) -> bool:
        """Check if cache entry has expired."""
        from django.utils import timezone
        if self.expires_at:
            return timezone.now() >= self.expires_at
        return False


class CachedToolResponse(models.Model):
    """
    Stores cached tool/action responses for replay.
    
    Useful for:
    - Deterministic replay without re-executing tools
    - Debugging with exact historical responses
    - Cost reduction (no re-execution of expensive tools)
    """
    
    cache_id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    snapshot = models.ForeignKey(
        ReplaySnapshot,
        on_delete=models.CASCADE,
        related_name='cached_tool_responses'
    )
    
    # Event reference
    seq_no = models.IntegerField(help_text="Sequence number of action_response event")
    action_name = models.CharField(max_length=255, help_text="Name of the action/tool")
    
    # Tool call details
    params_hash = models.CharField(
        max_length=64,
        help_text="SHA-256 hash of parameters for cache lookup",
        db_index=True
    )
    params = models.JSONField(help_text="Original parameters")
    
    # Cached response
    status = models.CharField(
        max_length=50,
        choices=[('success', 'Success'), ('error', 'Error')],
        default='success'
    )
    result = models.JSONField(help_text="Tool response result")
    error = models.TextField(null=True, blank=True, help_text="Error message if failed")
    
    # Metadata
    timestamp = models.DateTimeField(auto_now_add=True)
    latency_ms = models.IntegerField(help_text="Original tool latency")
    
    class Meta:
        db_table = 'cached_tool_responses'
        indexes = [
            models.Index(fields=['snapshot', 'seq_no']),
            models.Index(fields=['params_hash']),
        ]
        unique_together = [['snapshot', 'seq_no']]
    
    def __str__(self):
        return f"CachedToolResponse(seq={self.seq_no}, action={self.action_name})"


class ReplayRun(models.Model):
    """
    Tracks execution of a replay.
    
    Records:
    - Original run being replayed
    - Replay configuration
    - Verification results
    - Reproducibility metrics
    """
    
    replay_id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    original_run = models.ForeignKey(
        'Run',
        on_delete=models.CASCADE,
        related_name='replays'
    )
    snapshot = models.ForeignKey(
        ReplaySnapshot,
        on_delete=models.CASCADE,
        related_name='replay_runs'
    )
    
    # Replay configuration
    replay_mode = models.CharField(
        max_length=50,
        choices=[
            ('full', 'Full replay with cached responses'),
            ('hybrid', 'Hybrid: cached tools, re-run model'),
            ('verification', 'Verification: re-run and compare')
        ],
        default='full'
    )
    
    use_cached_llm = models.BooleanField(
        default=True,
        help_text="Use cached LLM responses"
    )
    use_cached_tools = models.BooleanField(
        default=True,
        help_text="Use cached tool responses"
    )
    
    # Execution
    status = models.CharField(
        max_length=50,
        choices=[
            ('pending', 'Pending'),
            ('running', 'Running'),
            ('completed', 'Completed'),
            ('failed', 'Failed')
        ],
        default='pending'
    )
    started_at = models.DateTimeField(null=True, blank=True)
    completed_at = models.DateTimeField(null=True, blank=True)
    
    # Results
    replayed_run = models.ForeignKey(
        'Run',
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='replay_of',
        help_text="New run created during replay"
    )
    
    # Verification metrics
    total_events = models.IntegerField(default=0)
    matching_events = models.IntegerField(default=0)
    divergent_events = models.IntegerField(default=0)
    
    reproducibility_score = models.FloatField(
        default=0.0,
        help_text="Percentage of matching events (0.0-1.0)"
    )
    
    # Detailed comparison
    comparison_report = models.JSONField(
        default=dict,
        help_text="Detailed comparison results"
    )
    
    # Divergence details
    divergences = models.JSONField(
        default=list,
        help_text="List of specific divergences found"
    )
    
    # Error tracking
    error_message = models.TextField(null=True, blank=True)
    
    class Meta:
        db_table = 'replay_runs'
        indexes = [
            models.Index(fields=['original_run']),
            models.Index(fields=['status']),
            models.Index(fields=['started_at']),
        ]
    
    def __str__(self):
        return f"ReplayRun({self.replay_id}) of Run({self.original_run_id})"
    
    def calculate_reproducibility_score(self):
        """Calculate and update reproducibility score."""
        if self.total_events > 0:
            self.reproducibility_score = self.matching_events / self.total_events
        else:
            self.reproducibility_score = 0.0
        self.save()
    
    def generate_report(self) -> Dict[str, Any]:
        """
        Generate comprehensive reproducibility report.
        
        Returns:
            Dict with replay results, metrics, and recommendations
        """
        report = {
            'replay_id': str(self.replay_id),
            'original_run_id': str(self.original_run_id),
            'replay_mode': self.replay_mode,
            'status': self.status,
            'started_at': self.started_at.isoformat() if self.started_at else None,
            'completed_at': self.completed_at.isoformat() if self.completed_at else None,
            'metrics': {
                'total_events': self.total_events,
                'matching_events': self.matching_events,
                'divergent_events': self.divergent_events,
                'reproducibility_score': self.reproducibility_score,
                'is_reproducible': self.reproducibility_score >= 0.95  # 95% threshold
            },
            'comparison': self.comparison_report,
            'divergences': self.divergences,
            'recommendations': self._generate_recommendations()
        }
        
        if self.error_message:
            report['error'] = self.error_message
        
        return report
    
    def _generate_recommendations(self) -> List[str]:
        """Generate recommendations based on replay results."""
        recommendations = []
        
        if self.reproducibility_score < 0.95:
            recommendations.append(
                "Reproducibility score below 95%. Check for non-deterministic behavior."
            )
        
        if self.divergent_events > 0:
            recommendations.append(
                f"Found {self.divergent_events} divergent events. "
                "Review divergence details for specific differences."
            )
        
        if not self.use_cached_llm:
            recommendations.append(
                "LLM responses were re-generated. Enable LLM caching for full determinism."
            )
        
        if self.status == 'failed':
            recommendations.append(
                "Replay failed. Check error message and environment configuration."
            )
        
        return recommendations
