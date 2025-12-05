"""
Serializers for AOP API endpoints

Handles Toon-formatted request/response serialization with validation.
"""

from rest_framework import serializers
from django.utils import timezone
from api.models import (
    Organization,
    Agent,
    Run,
    TraceEvent,
    TraceRecord,
    EnvironmentSnapshot,
    AuditLog
)
from api.auth_models import (
    OrganizationSaltKey,
    AgentAPIKey,
    MTLSCertificate
)
import json
import uuid


class ToonPayloadField(serializers.Field):
    """
    Custom field for Toon-formatted payloads.
    Accepts dict or string, validates structure, stores as string.
    """
    
    def to_internal_value(self, data):
        """Convert to internal value (JSON string)."""
        if isinstance(data, dict):
            return json.dumps(data)
        elif isinstance(data, str):
            # Validate it's valid JSON
            try:
                json.loads(data)
                return data
            except json.JSONDecodeError:
                raise serializers.ValidationError("Invalid JSON in payload")
        else:
            raise serializers.ValidationError("Payload must be dict or JSON string")
    
    def to_representation(self, value):
        """Convert to representation (dict)."""
        if isinstance(value, str):
            try:
                return json.loads(value)
            except json.JSONDecodeError:
                return {"raw": value}
        return value


class TraceEventSerializer(serializers.Serializer):
    """
    Serializer for TraceEvent in Toon canonical format.
    
    Expected format:
    {
      "seq": 1,
      "t": "2025-12-05T10:00:00Z",
      "actor": "agent",
      "type": "reasoning",
      "payload": {...},
      "meta": {
        "run_id": "uuid",
        "agent_id": 123,
        "signature": "hmac_signature"
      }
    }
    """
    
    seq = serializers.IntegerField(min_value=1)
    t = serializers.DateTimeField(source='timestamp')
    actor = serializers.ChoiceField(choices=['agent', 'tool', 'user', 'system', 'redteam'])
    type = serializers.ChoiceField(choices=[
        'reasoning', 'action_request', 'action_response', 'final_output', 'error'
    ])
    payload = ToonPayloadField()
    meta = serializers.JSONField()
    
    def validate_meta(self, value):
        """Validate meta structure."""
        required_fields = ['run_id', 'agent_id']
        for field in required_fields:
            if field not in value:
                raise serializers.ValidationError(f"Missing required field in meta: {field}")
        
        # Validate run_id is valid UUID
        try:
            uuid.UUID(str(value['run_id']))
        except (ValueError, AttributeError):
            raise serializers.ValidationError("Invalid run_id in meta")
        
        return value
    
    def validate(self, data):
        """Cross-field validation."""
        # Validate payload structure based on type
        event_type = data['type']
        payload = data['payload']
        
        # Parse payload if string
        if isinstance(payload, str):
            try:
                payload_dict = json.loads(payload)
            except json.JSONDecodeError:
                raise serializers.ValidationError("Invalid JSON in payload")
        else:
            payload_dict = payload
        
        # Type-specific validation
        if event_type == 'reasoning':
            required = ['goal', 'steps', 'safety_checks', 'uncertainty']
            for field in required:
                if field not in payload_dict:
                    raise serializers.ValidationError(f"reasoning payload missing: {field}")
            
            if payload_dict['uncertainty'] not in ['low', 'medium', 'high']:
                raise serializers.ValidationError("uncertainty must be low, medium, or high")
        
        elif event_type == 'action_request':
            required = ['action', 'params']
            for field in required:
                if field not in payload_dict:
                    raise serializers.ValidationError(f"action_request payload missing: {field}")
        
        elif event_type == 'action_response':
            required = ['status', 'data']
            for field in required:
                if field not in payload_dict:
                    raise serializers.ValidationError(f"action_response payload missing: {field}")
            
            if payload_dict['status'] not in ['ok', 'error']:
                raise serializers.ValidationError("status must be ok or error")
        
        elif event_type == 'final_output':
            if 'text' not in payload_dict:
                raise serializers.ValidationError("final_output payload missing: text")
        
        return data


class CreateRunSerializer(serializers.Serializer):
    """Serializer for creating a new run."""
    
    agent_id = serializers.IntegerField()
    scenario_id = serializers.CharField(required=False, allow_null=True, allow_blank=True)
    seed = serializers.IntegerField(required=False, allow_null=True)
    
    def validate_agent_id(self, value):
        """Validate agent exists and belongs to authenticated org."""
        try:
            agent = Agent.objects.select_related('owner').get(id=value)
            
            # Check if agent belongs to authenticated organization
            if hasattr(self.context.get('request'), 'organization'):
                if agent.owner != self.context['request'].organization:
                    raise serializers.ValidationError("Agent does not belong to your organization")
            
            return value
        except Agent.DoesNotExist:
            raise serializers.ValidationError("Agent not found")


class RunSerializer(serializers.ModelSerializer):
    """Serializer for Run model."""
    
    run_id = serializers.UUIDField(read_only=True)
    agent_id = serializers.IntegerField(source='agent.id')
    status = serializers.CharField(read_only=True)
    start_ts = serializers.DateTimeField(read_only=True)
    end_ts = serializers.DateTimeField(read_only=True, allow_null=True)
    
    class Meta:
        model = Run
        fields = ['run_id', 'agent_id', 'scenario_id', 'seed', 'status', 'start_ts', 'end_ts']


class BatchTraceEventsSerializer(serializers.Serializer):
    """Serializer for batch event submission."""
    
    run_id = serializers.UUIDField()
    agent_id = serializers.IntegerField()
    events = TraceEventSerializer(many=True)
    idempotency_token = serializers.UUIDField(required=False)
    
    def validate_run_id(self, value):
        """Validate run exists."""
        try:
            run = Run.objects.get(run_id=value)
            return value
        except Run.DoesNotExist:
            raise serializers.ValidationError("Run not found")
    
    def validate(self, data):
        """Cross-field validation."""
        # Validate run belongs to agent
        try:
            run = Run.objects.select_related('agent').get(run_id=data['run_id'])
            if run.agent.id != data['agent_id']:
                raise serializers.ValidationError("Run does not belong to specified agent")
        except Run.DoesNotExist:
            raise serializers.ValidationError("Run not found")
        
        # Validate events are in sequence
        events = data['events']
        if events:
            seq_numbers = [e['seq'] for e in events]
            if len(seq_numbers) != len(set(seq_numbers)):
                raise serializers.ValidationError("Duplicate sequence numbers in batch")
        
        return data


class FinalizeRunSerializer(serializers.Serializer):
    """Serializer for finalizing a run."""
    
    summary_metrics = serializers.JSONField(required=False, default=dict)
    object_store_path = serializers.CharField(required=False, allow_blank=True)
    
    def validate_summary_metrics(self, value):
        """Validate summary metrics structure."""
        if not isinstance(value, dict):
            raise serializers.ValidationError("summary_metrics must be a dictionary")
        return value


class TraceDownloadSerializer(serializers.Serializer):
    """Serializer for trace download options."""
    
    format = serializers.ChoiceField(
        choices=['toon', 'json', 'zip'],
        default='toon'
    )
    include_metadata = serializers.BooleanField(default=True)
    pretty = serializers.BooleanField(default=False)


class AgentValidateCallbackSerializer(serializers.Serializer):
    """Serializer for agent callback validation."""
    
    callback_url = serializers.URLField()
    timeout = serializers.IntegerField(default=5, min_value=1, max_value=30)
    
    def validate_callback_url(self, value):
        """Validate callback URL."""
        # Ensure HTTPS in production
        if not value.startswith(('http://', 'https://')):
            raise serializers.ValidationError("Invalid URL scheme")
        return value


class OrganizationSerializer(serializers.ModelSerializer):
    """Serializer for Organization."""
    
    class Meta:
        model = Organization
        fields = ['id', 'name', 'policy_config', 'retention_policy', 'created_at', 'updated_at']
        read_only_fields = ['id', 'created_at', 'updated_at']


class AgentSerializer(serializers.ModelSerializer):
    """Serializer for Agent."""
    
    owner_id = serializers.IntegerField(source='owner.id', read_only=True)
    owner_name = serializers.CharField(source='owner.name', read_only=True)
    
    class Meta:
        model = Agent
        fields = ['id', 'owner_id', 'owner_name', 'endpoint_metadata', 'runtime_config', 'created_at', 'updated_at']
        read_only_fields = ['id', 'created_at', 'updated_at']


class AgentAPIKeySerializer(serializers.ModelSerializer):
    """Serializer for AgentAPIKey (without revealing the key)."""
    
    class Meta:
        model = AgentAPIKey
        fields = ['key_prefix', 'name', 'scopes', 'is_active', 'created_at', 'expires_at', 'last_used_at']
        read_only_fields = ['key_prefix', 'created_at', 'last_used_at']


class CreateAPIKeySerializer(serializers.Serializer):
    """Serializer for creating a new API key."""
    
    agent_id = serializers.IntegerField()
    name = serializers.CharField(max_length=255, required=False, allow_blank=True)
    scopes = serializers.ListField(
        child=serializers.CharField(),
        required=False,
        default=list
    )
    expires_in_days = serializers.IntegerField(default=365, min_value=1, max_value=3650)
    
    def validate_agent_id(self, value):
        """Validate agent exists and belongs to authenticated org."""
        try:
            agent = Agent.objects.select_related('owner').get(id=value)
            
            if hasattr(self.context.get('request'), 'organization'):
                if agent.owner != self.context['request'].organization:
                    raise serializers.ValidationError("Agent does not belong to your organization")
            
            return value
        except Agent.DoesNotExist:
            raise serializers.ValidationError("Agent not found")


class RotateSaltKeySerializer(serializers.Serializer):
    """Serializer for salt key rotation."""
    
    expiry_days = serializers.IntegerField(default=90, min_value=1, max_value=365)


class UpdateRetentionPolicySerializer(serializers.Serializer):
    """Serializer for updating retention policy."""
    
    trace_retention_days = serializers.IntegerField(min_value=1, max_value=3650)
    audit_log_retention_days = serializers.IntegerField(min_value=1, max_value=3650)
    auto_delete_expired = serializers.BooleanField(default=True)
    
    def validate(self, data):
        """Ensure audit logs are retained at least as long as traces."""
        if data.get('audit_log_retention_days', 0) < data.get('trace_retention_days', 0):
            raise serializers.ValidationError(
                "Audit log retention must be >= trace retention"
            )
        return data


class AuditLogSerializer(serializers.ModelSerializer):
    """Serializer for AuditLog."""
    
    organization_name = serializers.CharField(source='organization.name', read_only=True)
    payload_preview = serializers.SerializerMethodField()
    
    class Meta:
        model = AuditLog
        fields = [
            'id', 'organization_name', 'timestamp', 'actor', 'type',
            'payload_preview', 'user_id', 'signature'
        ]
        read_only_fields = ['id', 'timestamp']
    
    def get_payload_preview(self, obj):
        """Get a preview of the payload (first 100 chars)."""
        return obj.payload[:100] + '...' if len(obj.payload) > 100 else obj.payload
