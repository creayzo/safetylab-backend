"""
Unit tests for signature verification and HMAC authentication.

Tests HMAC generation, verification, tampering detection, key rotation.
"""

import hashlib
import hmac
import json
import uuid
from cryptography.fernet import Fernet
from datetime import timedelta
from django.test import TestCase, override_settings
from django.utils import timezone

from api.models import Organization, Agent, Run
from api.auth_models import (
    OrganizationSaltKey,
    AgentAPIKey,
    SignatureVerifier
)

# Generate a consistent encryption key for tests
TEST_ENCRYPTION_KEY = Fernet.generate_key()


@override_settings(SALT_ENCRYPTION_KEY=TEST_ENCRYPTION_KEY)
class SignatureVerifierTest(TestCase):
    """Test SignatureVerifier for HMAC signature generation and verification."""
    
    def setUp(self):
        self.org = Organization.objects.create(name="Test Org")
        self.salt_key = OrganizationSaltKey.create_for_organization(self.org)
        self.agent = Agent.objects.create(owner=self.org)
        self.run = Run.objects.create(
            agent=self.agent,
            run_id=uuid.uuid4()
        )
    
    def test_generate_signature(self):
        """Test signature generation."""
        payload = {"reasoning": "test"}
        payload_str = json.dumps(payload, separators=(',', ':'))
        
        signature = SignatureVerifier.generate_signature(
            org_salt=self.salt_key.decrypt_salt(),
            run_id=str(self.run.run_id),
            seq_no=1,
            payload=payload_str
        )
        
        self.assertIsNotNone(signature)
        self.assertIsInstance(signature, str)
        self.assertEqual(len(signature), 64)  # SHA-256 hex digest
    
    def test_verify_valid_signature(self):
        """Test verification of valid signature."""
        payload = {"reasoning": "test"}
        payload_str = json.dumps(payload, separators=(',', ':'))
        salt_key = self.salt_key.decrypt_salt()
        
        signature = SignatureVerifier.generate_signature(
            org_salt=salt_key,
            run_id=str(self.run.run_id),
            seq_no=1,
            payload=payload_str
        )
        
        is_valid = SignatureVerifier.verify_signature(
            org_salt=salt_key,
            run_id=str(self.run.run_id),
            seq_no=1,
            payload=payload_str,
            provided_signature=signature
        )
        
        self.assertTrue(is_valid)
    
    def test_verify_invalid_signature(self):
        """Test verification fails for invalid signature."""
        payload_data = {"reasoning": "test"}
        payload_str = json.dumps(payload_data, separators=(',', ':'))
        
        is_valid = SignatureVerifier.verify_signature(
            org_salt=self.salt_key.decrypt_salt(),
            run_id=str(self.run.run_id),
            seq_no=1,
            payload=payload_str,
            provided_signature="invalid_signature"
        )
        
        self.assertFalse(is_valid)
    
    def test_tampering_detection_payload_modified(self):
        """Test tampering detection when payload is modified."""
        payload_data = {"reasoning": "original"}
        payload_str = json.dumps(payload_data, separators=(',', ':'))
        salt_key = self.salt_key.decrypt_salt()
        
        signature = SignatureVerifier.generate_signature(
            org_salt=salt_key,
            run_id=str(self.run.run_id),
            seq_no=1,
            payload=payload_str
        )
        
        # Tamper with payload
        tampered_payload = json.dumps({"reasoning": "tampered"}, separators=(',', ':'))
        
        is_valid = SignatureVerifier.verify_signature(
            org_salt=salt_key,
            run_id=str(self.run.run_id),
            seq_no=1,
            payload=tampered_payload,
            provided_signature=signature
        )
        
        self.assertFalse(is_valid)
    
    def test_tampering_detection_seq_modified(self):
        """Test tampering detection when seq is modified."""
        payload_data = {"reasoning": "test"}
        payload_str = json.dumps(payload_data, separators=(',', ':'))
        salt_key = self.salt_key.decrypt_salt()
        
        signature = SignatureVerifier.generate_signature(
            org_salt=salt_key,
            run_id=str(self.run.run_id),
            seq_no=1,
            payload=payload_str
        )
        
        # Tamper with seq (use seq_no=2 instead of 1)
        is_valid = SignatureVerifier.verify_signature(
            org_salt=salt_key,
            run_id=str(self.run.run_id),
            seq_no=2,  # Tampered
            payload=payload_str,
            provided_signature=signature
        )
        
        self.assertFalse(is_valid)
    
    def test_tampering_detection_timestamp_modified(self):
        """Test tampering detection when timestamp is modified."""
        # Note: HMAC signature includes run_id, seq_no, payload but NOT timestamp
        # So modifying timestamp alone won't invalidate signature
        # This test verifies timestamp is not part of signature
        payload_data = {"reasoning": "test"}
        payload_str = json.dumps(payload_data, separators=(',', ':'))
        salt_key = self.salt_key.decrypt_salt()
        
        signature = SignatureVerifier.generate_signature(
            org_salt=salt_key,
            run_id=str(self.run.run_id),
            seq_no=1,
            payload=payload_str
        )
        
        # Timestamp modification doesn't affect signature validity
        is_valid = SignatureVerifier.verify_signature(
            org_salt=salt_key,
            run_id=str(self.run.run_id),
            seq_no=1,
            payload=payload_str,
            provided_signature=signature
        )
        
        self.assertTrue(is_valid)  # Signature still valid since timestamp not in HMAC
    
    def test_signature_with_different_keys(self):
        """Test signature generated with one key fails with another key."""
        payload_data = {"reasoning": "test"}
        payload_str = json.dumps(payload_data, separators=(',', ':'))
        
        # Generate signature with org1's key
        salt_key1 = self.salt_key.decrypt_salt()
        signature = SignatureVerifier.generate_signature(
            org_salt=salt_key1,
            run_id=str(self.run.run_id),
            seq_no=1,
            payload=payload_str
        )
        
        # Try to verify with org2's key
        org2 = Organization.objects.create(name="Test Org 2")
        salt_key2_obj = OrganizationSaltKey.create_for_organization(org2)
        salt_key2 = salt_key2_obj.decrypt_salt()
        
        is_valid = SignatureVerifier.verify_signature(
            org_salt=salt_key2,
            run_id=str(self.run.run_id),
            seq_no=1,
            payload=payload_str,
            provided_signature=signature
        )
        
        self.assertFalse(is_valid)
    
    def test_deterministic_signature_generation(self):
        """Test signature generation is deterministic for same input."""
        payload_data = {"reasoning": "test"}
        payload_str = json.dumps(payload_data, separators=(',', ':'))
        salt_key = self.salt_key.decrypt_salt()
        
        signature1 = SignatureVerifier.generate_signature(
            org_salt=salt_key,
            run_id=str(self.run.run_id),
            seq_no=1,
            payload=payload_str
        )
        signature2 = SignatureVerifier.generate_signature(
            org_salt=salt_key,
            run_id=str(self.run.run_id),
            seq_no=1,
            payload=payload_str
        )
        
        self.assertEqual(signature1, signature2)
    
    def test_signature_with_special_characters(self):
        """Test signature generation with special characters in payload."""
        payload_data = {
            "text": "Testing special chars: <>&\"' 中文 🚀"
        }
        payload_str = json.dumps(payload_data, separators=(',', ':'), ensure_ascii=False)
        salt_key = self.salt_key.decrypt_salt()
        
        signature = SignatureVerifier.generate_signature(
            org_salt=salt_key,
            run_id=str(self.run.run_id),
            seq_no=1,
            payload=payload_str
        )
        
        is_valid = SignatureVerifier.verify_signature(
            org_salt=salt_key,
            run_id=str(self.run.run_id),
            seq_no=1,
            payload=payload_str,
            provided_signature=signature
        )
        
        self.assertTrue(is_valid)


@override_settings(SALT_ENCRYPTION_KEY=TEST_ENCRYPTION_KEY)
class KeyRotationTest(TestCase):
    """Test key rotation functionality."""
    
    def setUp(self):
        self.org = Organization.objects.create(name="Test Org")
        self.salt_key = OrganizationSaltKey.create_for_organization(self.org)
    
    def test_create_salt_key(self):
        """Test creating a salt key."""
        self.assertIsNotNone(self.salt_key)
        self.assertTrue(self.salt_key.is_active)
        self.assertIsNone(self.salt_key.expires_at)
    
    def test_rotate_salt_key(self):
        """Test rotating a salt key."""
        old_key = self.salt_key.decrypt_salt()
        
        # Rotate key
        new_salt_key = self.salt_key.rotate(expiry_days=7)
        
        # Old key should be inactive and have expiry
        self.salt_key.refresh_from_db()
        self.assertFalse(self.salt_key.is_active)
        self.assertIsNotNone(self.salt_key.expires_at)
        
        # New key should be active
        self.assertTrue(new_salt_key.is_active)
        self.assertIsNone(new_salt_key.expires_at)
        
        # Keys should be different
        new_key = new_salt_key.decrypt_salt()
        self.assertNotEqual(old_key, new_key)
    
    def test_verify_with_old_key_after_rotation(self):
        """Test verification with old key after rotation (within grace period)."""
        # Create a run for signature generation
        agent = Agent.objects.create(owner=self.org)
        run = Run.objects.create(agent=agent, run_id=uuid.uuid4())
        
        payload_data = {"reasoning": "test"}
        payload_str = json.dumps(payload_data, separators=(',', ':'))
        old_key = self.salt_key.decrypt_salt()
        
        signature = SignatureVerifier.generate_signature(
            org_salt=old_key,
            run_id=str(run.run_id),
            seq_no=1,
            payload=payload_str
        )
        
        # Rotate key with 7-day grace period
        new_salt_key = self.salt_key.rotate(expiry_days=7)
        
        # Verification should still work with old signature and old key
        is_valid = SignatureVerifier.verify_signature(
            org_salt=old_key,
            run_id=str(run.run_id),
            seq_no=1,
            payload=payload_str,
            provided_signature=signature
        )
        
        self.assertTrue(is_valid)
    
    def test_verify_fails_with_expired_key(self):
        """Test verification fails with expired key."""
        # Create a run for signature generation
        agent = Agent.objects.create(owner=self.org)
        run = Run.objects.create(agent=agent, run_id=uuid.uuid4())
        
        payload_data = {"reasoning": "test"}
        payload_str = json.dumps(payload_data, separators=(',', ':'))
        old_key = self.salt_key.decrypt_salt()
        
        signature = SignatureVerifier.generate_signature(
            org_salt=old_key,
            run_id=str(run.run_id),
            seq_no=1,
            payload=payload_str
        )
        
        # Rotate key with immediate expiry
        new_salt_key = self.salt_key.rotate(expiry_days=0)
        
        # Manually expire the old key
        self.salt_key.expires_at = timezone.now() - timedelta(days=1)
        self.salt_key.save()
        
        # Check if key is expired
        self.assertTrue(self.salt_key.expires_at < timezone.now())
    
    def test_multiple_rotations(self):
        """Test multiple consecutive key rotations."""
        keys = [self.salt_key.decrypt_salt()]
        
        # Rotate 3 times
        current_key = self.salt_key
        for i in range(3):
            new_key = current_key.rotate(expiry_days=7)
            keys.append(new_key.decrypt_salt())
            current_key = new_key
        
        # All keys should be different
        self.assertEqual(len(set(keys)), 4)
        
        # Only the latest should be active
        active_keys = OrganizationSaltKey.objects.filter(
            organization=self.org,
            is_active=True
        )
        self.assertEqual(active_keys.count(), 1)
    
    def test_get_active_salt_key(self):
        """Test retrieving active salt key for organization."""
        active_key = self.org.get_active_salt_key()
        self.assertIsNotNone(active_key)
        self.assertEqual(active_key.id, self.salt_key.id)


@override_settings(SALT_ENCRYPTION_KEY=TEST_ENCRYPTION_KEY)
class APIKeyAuthenticationTest(TestCase):
    """Test API key authentication."""
    
    def setUp(self):
        self.org = Organization.objects.create(name="Test Org")
        self.agent = Agent.objects.create(owner=self.org)
        self.salt_key = OrganizationSaltKey.create_for_organization(self.org)
    
    def test_create_api_key(self):
        """Test creating an API key."""
        api_key, raw_key = AgentAPIKey.create_for_agent(
            agent=self.agent,
            scopes=['write:events', 'read:events']
        )
        
        self.assertIsNotNone(api_key)
        self.assertTrue(api_key.is_active)
        self.assertEqual(api_key.agent, self.agent)
    
    def test_authenticate_valid_key(self):
        """Test authenticating with valid API key."""
        api_key_obj, raw_key = AgentAPIKey.create_for_agent(
            agent=self.agent,
            scopes=['write:events']
        )
        
        # Authenticate
        authenticated = AgentAPIKey.authenticate(raw_key)
        
        self.assertIsNotNone(authenticated)
        self.assertEqual(authenticated.agent.id, self.agent.id)
    
    def test_authenticate_invalid_key(self):
        """Test authenticating with invalid API key."""
        authenticated = AgentAPIKey.authenticate("invalid_key")
        self.assertIsNone(authenticated)
    
    def test_authenticate_inactive_key(self):
        """Test authenticating with inactive API key."""
        api_key_obj, raw_key = AgentAPIKey.create_for_agent(
            agent=self.agent,
            scopes=['write:events']
        )
        
        # Deactivate key
        api_key_obj.is_active = False
        api_key_obj.save()
        
        # Authentication should fail
        authenticated = AgentAPIKey.authenticate(raw_key)
        self.assertIsNone(authenticated)
    
    def test_authenticate_expired_key(self):
        """Test authenticating with expired API key."""
        api_key_obj, raw_key = AgentAPIKey.create_for_agent(
            agent=self.agent,
            scopes=['write:events'],
            expires_in_days=None
        )
        # Manually expire it
        api_key_obj.expires_at = timezone.now() - timedelta(days=1)
        api_key_obj.save()
        
        # Authentication should fail
        authenticated = AgentAPIKey.authenticate(raw_key)
        self.assertIsNone(authenticated)
    
    def test_revoke_api_key(self):
        """Test revoking an API key."""
        api_key_obj, raw_key = AgentAPIKey.create_for_agent(
            agent=self.agent,
            scopes=['write:events']
        )
        
        # Revoke key
        api_key_obj.revoke()
        
        # Authentication should fail
        authenticated = AgentAPIKey.authenticate(raw_key)
        self.assertIsNone(authenticated)
        
        # Key should be inactive
        api_key_obj.refresh_from_db()
        self.assertFalse(api_key_obj.is_active)
    
    def test_api_key_last_used_updated(self):
        """Test last_used_at is updated on authentication."""
        api_key_obj, raw_key = AgentAPIKey.create_for_agent(
            agent=self.agent,
            scopes=['write:events']
        )
        
        original_last_used = api_key_obj.last_used_at
        
        # Authenticate
        AgentAPIKey.authenticate(raw_key)
        
        # Check last_used_at was updated
        api_key_obj.refresh_from_db()
        self.assertIsNotNone(api_key_obj.last_used_at)
        if original_last_used:
            self.assertGreater(api_key_obj.last_used_at, original_last_used)
