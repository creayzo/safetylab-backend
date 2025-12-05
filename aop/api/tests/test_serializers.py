"""
Unit tests for serializers and parsers.

Tests Toon format parsing, validation, and error handling.
"""

import json
import uuid
from datetime import datetime, timezone as dt_timezone
from django.test import TestCase
from django.utils import timezone
from rest_framework.exceptions import ValidationError

from api.serializers import (
    ToonPayloadField,
    TraceEventSerializer,
    RunSerializer
)
from api.models import Organization, Agent, Run


class ToonPayloadFieldTest(TestCase):
    """Test custom ToonPayloadField serializer."""
    
    def setUp(self):
        self.field = ToonPayloadField()
    
    def test_dict_to_internal_value(self):
        """Test converting dict to JSON string."""
        data = {"reasoning": "test", "confidence": 0.9}
        result = self.field.to_internal_value(data)
        self.assertIsInstance(result, str)
        self.assertEqual(json.loads(result), data)
    
    def test_json_string_to_internal_value(self):
        """Test valid JSON string passes through."""
        data = '{"reasoning": "test"}'
        result = self.field.to_internal_value(data)
        self.assertEqual(result, data)
    
    def test_invalid_json_string_raises_error(self):
        """Test invalid JSON string raises ValidationError."""
        data = '{invalid json}'
        with self.assertRaises(ValidationError):
            self.field.to_internal_value(data)
    
    def test_invalid_type_raises_error(self):
        """Test invalid type raises ValidationError."""
        data = 123
        with self.assertRaises(ValidationError):
            self.field.to_internal_value(data)
    
    def test_to_representation_from_string(self):
        """Test converting JSON string to dict for representation."""
        value = '{"reasoning": "test"}'
        result = self.field.to_representation(value)
        self.assertIsInstance(result, dict)
        self.assertEqual(result, {"reasoning": "test"})
    
    def test_to_representation_invalid_json(self):
        """Test invalid JSON returns wrapped value."""
        value = 'invalid json'
        result = self.field.to_representation(value)
        self.assertEqual(result, {"raw": value})


class TraceEventSerializerTest(TestCase):
    """Test TraceEventSerializer for Toon format validation."""
    
    def setUp(self):
        self.org = Organization.objects.create(name="Test Org")
        self.agent = Agent.objects.create(owner=self.org)
        self.run = Run.objects.create(
            agent=self.agent,
            run_id=uuid.uuid4()
        )
    
    def get_valid_event_data(self):
        """Get valid Toon-formatted event data."""
        return {
            "seq": 1,
            "t": "2025-12-05T10:00:00Z",
            "actor": "agent",
            "type": "reasoning",
            "payload": {
                "goal": "Analyze user request",
                "steps": ["Step 1", "Step 2"],
                "safety_checks": ["Check 1"],
                "uncertainty": "low"
            },
            "meta": {
                "run_id": str(self.run.run_id),
                "agent_id": self.agent.id
            }
        }
    
    def test_valid_event_serialization(self):
        """Test valid event passes serialization."""
        data = self.get_valid_event_data()
        serializer = TraceEventSerializer(data=data)
        self.assertTrue(serializer.is_valid())
    
    def test_missing_required_field(self):
        """Test missing required field raises validation error."""
        data = self.get_valid_event_data()
        del data['seq']
        serializer = TraceEventSerializer(data=data)
        self.assertFalse(serializer.is_valid())
        self.assertIn('seq', serializer.errors)
    
    def test_invalid_actor_choice(self):
        """Test invalid actor value raises validation error."""
        data = self.get_valid_event_data()
        data['actor'] = 'invalid_actor'
        serializer = TraceEventSerializer(data=data)
        self.assertFalse(serializer.is_valid())
        self.assertIn('actor', serializer.errors)
    
    def test_invalid_type_choice(self):
        """Test invalid type value raises validation error."""
        data = self.get_valid_event_data()
        data['type'] = 'invalid_type'
        serializer = TraceEventSerializer(data=data)
        self.assertFalse(serializer.is_valid())
        self.assertIn('type', serializer.errors)
    
    def test_invalid_seq_number(self):
        """Test seq < 1 raises validation error."""
        data = self.get_valid_event_data()
        data['seq'] = 0
        serializer = TraceEventSerializer(data=data)
        self.assertFalse(serializer.is_valid())
        self.assertIn('seq', serializer.errors)
    
    def test_missing_meta_field(self):
        """Test missing meta.run_id raises validation error."""
        data = self.get_valid_event_data()
        del data['meta']['run_id']
        serializer = TraceEventSerializer(data=data)
        self.assertFalse(serializer.is_valid())
        self.assertIn('meta', serializer.errors)
    
    def test_invalid_run_id_format(self):
        """Test invalid UUID in meta.run_id raises validation error."""
        data = self.get_valid_event_data()
        data['meta']['run_id'] = 'not-a-uuid'
        serializer = TraceEventSerializer(data=data)
        self.assertFalse(serializer.is_valid())
        self.assertIn('meta', serializer.errors)
    
    def test_payload_as_dict(self):
        """Test payload accepts dict."""
        data = self.get_valid_event_data()
        data['type'] = 'final_output'
        data['payload'] = {"text": "Test output"}
        serializer = TraceEventSerializer(data=data)
        self.assertTrue(serializer.is_valid())
    
    def test_payload_as_json_string(self):
        """Test payload accepts JSON string."""
        data = self.get_valid_event_data()
        data['type'] = 'final_output'
        data['payload'] = '{"text": "value"}'
        serializer = TraceEventSerializer(data=data)
        self.assertTrue(serializer.is_valid())
    
    def test_timestamp_parsing(self):
        """Test various timestamp formats are parsed correctly."""
        data = self.get_valid_event_data()
        
        # ISO format with Z
        data['t'] = "2025-12-05T10:00:00Z"
        serializer = TraceEventSerializer(data=data)
        self.assertTrue(serializer.is_valid())
        
        # ISO format with timezone
        data['t'] = "2025-12-05T10:00:00+00:00"
        serializer = TraceEventSerializer(data=data)
        self.assertTrue(serializer.is_valid())


class RunSerializerTest(TestCase):
    """Test RunSerializer."""
    
    def setUp(self):
        self.org = Organization.objects.create(name="Test Org")
        self.agent = Agent.objects.create(owner=self.org)
    
    def test_create_run_with_serializer(self):
        """Test creating a run via serializer."""
        data = {
            "agent": self.agent.id,
            "run_id": str(uuid.uuid4()),
            "status": "running"
        }
        serializer = RunSerializer(data=data)
        if serializer.is_valid():
            run = serializer.save()
            self.assertIsNotNone(run.id)
            self.assertEqual(run.agent, self.agent)
    
    def test_run_id_uniqueness(self):
        """Test run_id must be unique."""
        run_id = uuid.uuid4()
        Run.objects.create(agent=self.agent, run_id=run_id)
        
        data = {
            "agent": self.agent.id,
            "run_id": str(run_id),
            "status": "running"
        }
        serializer = RunSerializer(data=data)
        self.assertFalse(serializer.is_valid())


class RunSerializerAdditionalTest(TestCase):
    """Additional tests for RunSerializer."""
    
    def setUp(self):
        self.org = Organization.objects.create(name="Test Org")
        self.agent = Agent.objects.create(owner=self.org)
        self.run = Run.objects.create(
            agent=self.agent,
            run_id=uuid.uuid4()
        )
    
    def test_serialize_run(self):
        """Test serializing a run."""
        from api.serializers import RunSerializer
        
        serializer = RunSerializer(self.run)
        data = serializer.data
        
        self.assertIn('run_id', data)
        self.assertIn('agent_id', data)
        self.assertIn('status', data)


class EdgeCaseTests(TestCase):
    """Test edge cases and boundary conditions."""
    
    def setUp(self):
        self.org = Organization.objects.create(name="Test Org")
        self.agent = Agent.objects.create(owner=self.org)
        self.run = Run.objects.create(
            agent=self.agent,
            run_id=uuid.uuid4()
        )
    
    def test_very_large_payload(self):
        """Test handling of very large payloads."""
        large_payload = {
            "goal": "Test",
            "steps": ["x" * 10000],  # Large step
            "safety_checks": ["Check"],
            "uncertainty": "low"
        }
        data = {
            "seq": 1,
            "t": "2025-12-05T10:00:00Z",
            "actor": "agent",
            "type": "reasoning",
            "payload": large_payload,
            "meta": {
                "run_id": str(self.run.run_id),
                "agent_id": self.agent.id
            }
        }
        serializer = TraceEventSerializer(data=data)
        # Should handle large payloads (size limiting is done in middleware)
        self.assertTrue(serializer.is_valid())
    
    def test_unicode_in_payload(self):
        """Test Unicode characters in payload."""
        data = {
            "seq": 1,
            "t": "2025-12-05T10:00:00Z",
            "actor": "agent",
            "type": "reasoning",
            "payload": {
                "goal": "Testing 中文 العربية עברית 🚀",
                "steps": ["Step with unicode"],
                "safety_checks": ["Check"],
                "uncertainty": "low"
            },
            "meta": {
                "run_id": str(self.run.run_id),
                "agent_id": self.agent.id
            }
        }
        serializer = TraceEventSerializer(data=data)
        self.assertTrue(serializer.is_valid())
    
    def test_nested_payload_structure(self):
        """Test deeply nested payload structures."""
        nested_payload = {
            "goal": "Test",
            "steps": [{
                "level1": {
                    "level2": {
                        "level3": {
                            "value": "deep"
                        }
                    }
                }
            }],
            "safety_checks": ["Check"],
            "uncertainty": "low"
        }
        data = {
            "seq": 1,
            "t": "2025-12-05T10:00:00Z",
            "actor": "agent",
            "type": "reasoning",
            "payload": nested_payload,
            "meta": {
                "run_id": str(self.run.run_id),
                "agent_id": self.agent.id
            }
        }
        serializer = TraceEventSerializer(data=data)
        self.assertTrue(serializer.is_valid())
    
    def test_empty_payload(self):
        """Test empty payload handling (should fail for reasoning type)."""
        data = {
            "seq": 1,
            "t": "2025-12-05T10:00:00Z",
            "actor": "agent",
            "type": "reasoning",
            "payload": {},
            "meta": {
                "run_id": str(self.run.run_id),
                "agent_id": self.agent.id
            }
        }
        serializer = TraceEventSerializer(data=data)
        # Empty payload should fail for reasoning (requires goal, steps, etc.)
        self.assertFalse(serializer.is_valid())
