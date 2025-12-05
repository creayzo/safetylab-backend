#!/usr/bin/env python
"""
Test script to verify AOP Django service configuration
Run with: python test_setup.py
"""

import os
import sys
import django

# Setup Django
sys.path.insert(0, os.path.dirname(__file__))
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'aop.settings')
django.setup()

from api.models import Organization, Agent
from api.auth_models import OrganizationSaltKey, AgentAPIKey
from api.toon_spec import ToonValidator, ToonPayloadExamples


def test_models():
    """Test model imports and basic functionality"""
    print("✓ Models imported successfully")
    print(f"  - Organization: {Organization.__name__}")
    print(f"  - Agent: {Agent.__name__}")
    print(f"  - OrganizationSaltKey: {OrganizationSaltKey.__name__}")
    print(f"  - AgentAPIKey: {AgentAPIKey.__name__}")


def test_toon_validator():
    """Test Toon format validation"""
    validator = ToonValidator()
    
    # Test reasoning payload
    reasoning = ToonPayloadExamples.reasoning_payload()
    is_valid, errors = validator.validate_payload('reasoning', reasoning)
    if is_valid:
        print("✓ Toon reasoning payload validation works")
    else:
        print(f"✗ Reasoning validation failed: {errors}")
    
    # Test action_request payload
    action_req = ToonPayloadExamples.action_request_payload()
    is_valid, errors = validator.validate_payload('action_request', action_req)
    if is_valid:
        print("✓ Toon action_request payload validation works")
    else:
        print(f"✗ Action request validation failed: {errors}")
    
    # Test action_response payload
    action_resp = ToonPayloadExamples.action_response_payload()
    is_valid, errors = validator.validate_payload('action_response', action_resp)
    if is_valid:
        print("✓ Toon action_response payload validation works")
    else:
        print(f"✗ Action response validation failed: {errors}")
    
    # Test final_output payload
    final_out = ToonPayloadExamples.final_output_payload()
    is_valid, errors = validator.validate_payload('final_output', final_out)
    if is_valid:
        print("✓ Toon final_output payload validation works")
    else:
        print(f"✗ Final output validation failed: {errors}")


def test_signature_verification():
    """Test HMAC signature generation and verification"""
    from api.auth_models import SignatureVerifier
    import json
    
    test_payload = {"test": "data", "number": 123}
    test_salt = "test_salt_key_123"
    test_run_id = "550e8400-e29b-41d4-a716-446655440000"
    test_seq_no = 1
    payload_json = json.dumps(test_payload, sort_keys=True)
    
    # Generate signature
    signature = SignatureVerifier.generate_signature(
        org_salt=test_salt,
        run_id=test_run_id,
        seq_no=test_seq_no,
        payload=payload_json
    )
    print(f"✓ Signature generation works: {signature[:16]}...")
    
    # Verify signature
    is_valid = SignatureVerifier.verify_signature(
        org_salt=test_salt,
        run_id=test_run_id,
        seq_no=test_seq_no,
        payload=payload_json,
        provided_signature=signature
    )
    if is_valid:
        print("✓ Signature verification works")
    else:
        print("✗ Signature verification failed")
    
    # Test invalid signature
    is_valid = SignatureVerifier.verify_signature(
        org_salt=test_salt,
        run_id=test_run_id,
        seq_no=test_seq_no,
        payload=payload_json,
        provided_signature="invalid_sig"
    )
    if not is_valid:
        print("✓ Invalid signature correctly rejected")
    else:
        print("✗ Invalid signature was accepted (should fail)")


def test_api_key_hashing():
    """Test API key hashing"""
    test_key = "test_api_key_12345"
    hashed = AgentAPIKey.hash_key(test_key)
    print(f"✓ API key hashing works: {hashed[:32]}...")


def test_settings():
    """Test Django settings configuration"""
    from django.conf import settings
    
    print("\n=== Settings Check ===")
    print(f"✓ DEBUG mode: {settings.DEBUG}")
    print(f"✓ REST_FRAMEWORK configured: {'REST_FRAMEWORK' in dir(settings)}")
    
    if hasattr(settings, 'REST_FRAMEWORK'):
        auth_classes = settings.REST_FRAMEWORK.get('DEFAULT_AUTHENTICATION_CLASSES', [])
        print(f"✓ Authentication classes ({len(auth_classes)}):")
        for cls in auth_classes:
            print(f"    - {cls}")
    
    if hasattr(settings, 'SALT_ENCRYPTION_KEY'):
        has_key = settings.SALT_ENCRYPTION_KEY is not None
        print(f"{'✓' if has_key else '⚠'} SALT_ENCRYPTION_KEY: {'Configured' if has_key else 'Not configured (set in .env)'}")


def main():
    print("=" * 60)
    print("AOP Django Service - Configuration Test")
    print("=" * 60)
    print()
    
    try:
        test_models()
        print()
        test_toon_validator()
        print()
        test_signature_verification()
        print()
        test_api_key_hashing()
        print()
        test_settings()
        print()
        print("=" * 60)
        print("✓ All tests passed!")
        print("=" * 60)
        print()
        print("Next steps:")
        print("1. Copy .env.example to .env and configure")
        print("2. Run: python manage.py migrate")
        print("3. Run: python manage.py createsuperuser")
        print("4. Generate keys with: python manage.py manage_keys create-org --name 'Your Org'")
        print("5. Start server: python manage.py runserver")
        
    except Exception as e:
        print()
        print("=" * 60)
        print(f"✗ Test failed: {e}")
        print("=" * 60)
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == '__main__':
    main()
