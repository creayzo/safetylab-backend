"""
Authentication and Key Management Models

This module handles:
- Organization salt key generation and rotation
- Per-agent API key management
- HMAC signature generation and verification
- Key encryption and secure storage
"""

from django.db import models
from django.contrib.auth.models import User
from django.utils import timezone
from cryptography.fernet import Fernet
from django.conf import settings
import secrets
import hashlib
import hmac
import base64
from datetime import timedelta
from typing import Tuple, Optional


class OrganizationSaltKey(models.Model):
    """
    Manages rotatable HMAC salt keys for organizations.
    Keys are encrypted at rest using Fernet encryption.
    """
    organization = models.ForeignKey(
        'Organization',
        on_delete=models.CASCADE,
        related_name='salt_keys'
    )
    encrypted_salt = models.TextField()  # Fernet-encrypted salt
    version = models.IntegerField(default=1)  # For key rotation tracking
    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    rotated_at = models.DateTimeField(null=True, blank=True)
    expires_at = models.DateTimeField(null=True, blank=True)
    
    class Meta:
        db_table = 'organization_salt_keys'
        ordering = ['-version']
        unique_together = [['organization', 'version']]
        indexes = [
            models.Index(fields=['organization', 'is_active']),
            models.Index(fields=['expires_at']),
        ]
    
    def __str__(self):
        return f"SaltKey v{self.version} for {self.organization.name} (Active: {self.is_active})"
    
    @staticmethod
    def generate_salt() -> str:
        """Generate a cryptographically secure random salt."""
        return secrets.token_urlsafe(32)
    
    @staticmethod
    def get_encryption_key() -> bytes:
        """
        Get the encryption key from Django settings.
        In production, this should be stored in environment variables or a key management service.
        """
        # Get from settings or generate a default (NOT for production)
        encryption_key = getattr(settings, 'SALT_ENCRYPTION_KEY', None)
        if not encryption_key:
            # For development only - generate a key
            # In production, this MUST be set in environment variables
            encryption_key = Fernet.generate_key()
        
        if isinstance(encryption_key, str):
            encryption_key = encryption_key.encode()
        
        return encryption_key
    
    def encrypt_salt(self, plain_salt: str) -> str:
        """Encrypt the salt using Fernet symmetric encryption."""
        f = Fernet(self.get_encryption_key())
        encrypted = f.encrypt(plain_salt.encode())
        return base64.b64encode(encrypted).decode('utf-8')
    
    def decrypt_salt(self) -> str:
        """Decrypt the stored salt."""
        f = Fernet(self.get_encryption_key())
        encrypted_bytes = base64.b64decode(self.encrypted_salt.encode('utf-8'))
        decrypted = f.decrypt(encrypted_bytes)
        return decrypted.decode('utf-8')
    
    @classmethod
    def create_for_organization(cls, organization) -> 'OrganizationSaltKey':
        """
        Create a new salt key for an organization.
        Automatically deactivates previous keys.
        """
        # Deactivate all existing keys
        cls.objects.filter(organization=organization, is_active=True).update(
            is_active=False,
            rotated_at=timezone.now()
        )
        
        # Get next version number
        latest = cls.objects.filter(organization=organization).first()
        next_version = (latest.version + 1) if latest else 1
        
        # Generate and encrypt new salt
        plain_salt = cls.generate_salt()
        salt_key = cls(organization=organization, version=next_version)
        salt_key.encrypted_salt = salt_key.encrypt_salt(plain_salt)
        salt_key.save()
        
        return salt_key
    
    def rotate(self, expiry_days: int = 90) -> 'OrganizationSaltKey':
        """
        Rotate the salt key by creating a new one and scheduling this one for expiration.
        Old key remains valid for a grace period to allow for in-flight requests.
        """
        self.is_active = False
        self.rotated_at = timezone.now()
        self.expires_at = timezone.now() + timedelta(days=expiry_days)
        self.save()
        
        # Create new key
        return self.create_for_organization(self.organization)
    
    def is_expired(self) -> bool:
        """Check if the salt key has expired."""
        if self.expires_at is None:
            return False
        return timezone.now() > self.expires_at


class AgentAPIKey(models.Model):
    """
    Manages rotatable API keys for agents.
    Keys are hashed using SHA-256 before storage (never stored in plaintext).
    """
    agent = models.ForeignKey(
        'Agent',
        on_delete=models.CASCADE,
        related_name='api_keys'
    )
    key_hash = models.CharField(max_length=64, unique=True)  # SHA-256 hash
    key_prefix = models.CharField(max_length=8)  # First 8 chars for identification
    name = models.CharField(max_length=255, blank=True)  # Optional key name/description
    scopes = models.JSONField(default=list, blank=True)  # Permission scopes
    is_active = models.BooleanField(default=True)
    last_used_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField(null=True, blank=True)
    created_by = models.ForeignKey(
        User,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='created_api_keys'
    )
    
    class Meta:
        db_table = 'agent_api_keys'
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['agent', 'is_active']),
            models.Index(fields=['key_hash']),
            models.Index(fields=['key_prefix']),
            models.Index(fields=['expires_at']),
        ]
    
    def __str__(self):
        return f"API Key {self.key_prefix}... for Agent {self.agent.id} (Active: {self.is_active})"
    
    @staticmethod
    def generate_api_key() -> str:
        """
        Generate a cryptographically secure API key.
        Format: aop_<32_random_bytes_base64>
        """
        random_bytes = secrets.token_urlsafe(32)
        return f"aop_{random_bytes}"
    
    @staticmethod
    def hash_key(api_key: str) -> str:
        """Hash the API key using SHA-256."""
        return hashlib.sha256(api_key.encode()).hexdigest()
    
    @classmethod
    def create_for_agent(
        cls,
        agent,
        name: str = "",
        scopes: list = None,
        expires_in_days: int = None,
        created_by: User = None
    ) -> Tuple['AgentAPIKey', str]:
        """
        Create a new API key for an agent.
        Returns tuple of (AgentAPIKey instance, plaintext_key).
        The plaintext key is returned only once and never stored.
        """
        # Generate API key
        plaintext_key = cls.generate_api_key()
        key_hash = cls.hash_key(plaintext_key)
        key_prefix = plaintext_key[:8]
        
        # Set expiration
        expires_at = None
        if expires_in_days:
            expires_at = timezone.now() + timedelta(days=expires_in_days)
        
        # Create key record
        api_key = cls.objects.create(
            agent=agent,
            key_hash=key_hash,
            key_prefix=key_prefix,
            name=name,
            scopes=scopes or [],
            expires_at=expires_at,
            created_by=created_by
        )
        
        # Return instance and plaintext key (shown only once)
        return api_key, plaintext_key
    
    def verify(self, provided_key: str) -> bool:
        """
        Verify a provided API key against this record.
        Returns True if valid and active, False otherwise.
        """
        if not self.is_active:
            return False
        
        if self.expires_at and timezone.now() > self.expires_at:
            return False
        
        provided_hash = self.hash_key(provided_key)
        is_valid = secrets.compare_digest(self.key_hash, provided_hash)
        
        if is_valid:
            # Update last used timestamp
            self.last_used_at = timezone.now()
            self.save(update_fields=['last_used_at'])
        
        return is_valid
    
    @classmethod
    def authenticate(cls, api_key: str) -> Optional['AgentAPIKey']:
        """
        Authenticate an API key and return the associated AgentAPIKey instance.
        Returns None if invalid or expired.
        """
        if not api_key or not api_key.startswith('aop_'):
            return None
        
        key_hash = cls.hash_key(api_key)
        
        try:
            api_key_obj = cls.objects.select_related('agent', 'agent__owner').get(
                key_hash=key_hash,
                is_active=True
            )
            
            # Check expiration
            if api_key_obj.expires_at and timezone.now() > api_key_obj.expires_at:
                return None
            
            # Update last used
            api_key_obj.last_used_at = timezone.now()
            api_key_obj.save(update_fields=['last_used_at'])
            
            return api_key_obj
        except cls.DoesNotExist:
            return None
    
    def revoke(self):
        """Revoke this API key."""
        self.is_active = False
        self.save(update_fields=['is_active'])
    
    def rotate(
        self,
        name: str = None,
        scopes: list = None,
        expires_in_days: int = None
    ) -> Tuple['AgentAPIKey', str]:
        """
        Rotate this API key by revoking it and creating a new one.
        Returns tuple of (new_key_instance, plaintext_key).
        """
        self.revoke()
        
        return self.create_for_agent(
            agent=self.agent,
            name=name or self.name,
            scopes=scopes or self.scopes,
            expires_in_days=expires_in_days,
            created_by=self.created_by
        )


class SignatureVerifier:
    """
    Utility class for generating and verifying HMAC signatures on TraceEvents.
    Signature format: HMAC-SHA256(org_salt, run_id + seq + payload)
    """
    
    @staticmethod
    def generate_signature(
        org_salt: str,
        run_id: str,
        seq_no: int,
        payload: str
    ) -> str:
        """
        Generate HMAC signature for a TraceEvent.
        
        Args:
            org_salt: Organization's decrypted salt key
            run_id: UUID of the run
            seq_no: Sequence number of the event
            payload: JSON string of the payload
            
        Returns:
            Hex-encoded HMAC-SHA256 signature
        """
        message = f"{run_id}{seq_no}{payload}"
        signature = hmac.new(
            org_salt.encode('utf-8'),
            message.encode('utf-8'),
            hashlib.sha256
        ).hexdigest()
        return signature
    
    @staticmethod
    def verify_signature(
        org_salt: str,
        run_id: str,
        seq_no: int,
        payload: str,
        provided_signature: str
    ) -> bool:
        """
        Verify HMAC signature for a TraceEvent.
        
        Args:
            org_salt: Organization's decrypted salt key
            run_id: UUID of the run
            seq_no: Sequence number of the event
            payload: JSON string of the payload
            provided_signature: Signature to verify
            
        Returns:
            True if signature is valid, False otherwise
        """
        expected_signature = SignatureVerifier.generate_signature(
            org_salt, run_id, seq_no, payload
        )
        return secrets.compare_digest(expected_signature, provided_signature)
    
    @staticmethod
    def sign_trace_event(trace_event, org_salt_key: OrganizationSaltKey) -> str:
        """
        Sign a TraceEvent model instance.
        
        Args:
            trace_event: TraceEvent model instance
            org_salt_key: OrganizationSaltKey instance
            
        Returns:
            Generated signature
        """
        org_salt = org_salt_key.decrypt_salt()
        signature = SignatureVerifier.generate_signature(
            org_salt,
            str(trace_event.run.run_id),
            trace_event.seq_no,
            trace_event.payload
        )
        return signature
    
    @staticmethod
    def verify_trace_event(
        trace_event,
        org_salt_key: OrganizationSaltKey
    ) -> bool:
        """
        Verify a TraceEvent's signature.
        
        Args:
            trace_event: TraceEvent model instance
            org_salt_key: OrganizationSaltKey instance
            
        Returns:
            True if signature is valid, False otherwise
        """
        org_salt = org_salt_key.decrypt_salt()
        return SignatureVerifier.verify_signature(
            org_salt,
            str(trace_event.run.run_id),
            trace_event.seq_no,
            trace_event.payload,
            trace_event.signature
        )


class MTLSCertificate(models.Model):
    """
    Manages mutual TLS certificates for enterprise on-prem connectors.
    Used for secure communication between pre-prod environments and orchestrator.
    """
    organization = models.ForeignKey(
        'Organization',
        on_delete=models.CASCADE,
        related_name='mtls_certificates'
    )
    name = models.CharField(max_length=255)
    certificate = models.TextField()  # PEM-encoded certificate
    fingerprint = models.CharField(max_length=64, unique=True)  # SHA-256 fingerprint
    common_name = models.CharField(max_length=255)
    serial_number = models.CharField(max_length=64)
    issuer = models.CharField(max_length=512)
    valid_from = models.DateTimeField()
    valid_until = models.DateTimeField()
    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    revoked_at = models.DateTimeField(null=True, blank=True)
    revocation_reason = models.TextField(blank=True)
    
    class Meta:
        db_table = 'mtls_certificates'
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['organization', 'is_active']),
            models.Index(fields=['fingerprint']),
            models.Index(fields=['valid_until']),
            models.Index(fields=['common_name']),
        ]
    
    def __str__(self):
        return f"mTLS Cert: {self.name} ({self.common_name}) - {self.organization.name}"
    
    def is_valid(self) -> bool:
        """Check if certificate is currently valid."""
        now = timezone.now()
        return (
            self.is_active and
            not self.revoked_at and
            self.valid_from <= now <= self.valid_until
        )
    
    def revoke(self, reason: str = ""):
        """Revoke this certificate."""
        self.is_active = False
        self.revoked_at = timezone.now()
        self.revocation_reason = reason
        self.save()


class OAuthToken(models.Model):
    """
    Manages OAuth2/JWT tokens for admin users and CI/CD systems.
    Integrates with Django's auth system.
    """
    TOKEN_TYPE_CHOICES = [
        ('access', 'Access Token'),
        ('refresh', 'Refresh Token'),
        ('ci', 'CI/CD Token'),
    ]
    
    user = models.ForeignKey(
        User,
        on_delete=models.CASCADE,
        related_name='oauth_tokens'
    )
    token_type = models.CharField(max_length=20, choices=TOKEN_TYPE_CHOICES)
    token_hash = models.CharField(max_length=64, unique=True)  # SHA-256 hash
    scopes = models.JSONField(default=list, blank=True)
    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField()
    last_used_at = models.DateTimeField(null=True, blank=True)
    client_id = models.CharField(max_length=255, blank=True)  # OAuth client
    
    class Meta:
        db_table = 'oauth_tokens'
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['user', 'token_type', 'is_active']),
            models.Index(fields=['token_hash']),
            models.Index(fields=['expires_at']),
        ]
    
    def __str__(self):
        return f"{self.token_type} token for {self.user.username}"
    
    def is_valid(self) -> bool:
        """Check if token is currently valid."""
        return (
            self.is_active and
            timezone.now() <= self.expires_at
        )
    
    @classmethod
    def authenticate(cls, token: str) -> Optional['OAuthToken']:
        """Authenticate a token and return the associated OAuthToken instance."""
        token_hash = hashlib.sha256(token.encode()).hexdigest()
        
        try:
            oauth_token = cls.objects.select_related('user').get(
                token_hash=token_hash,
                is_active=True
            )
            
            if not oauth_token.is_valid():
                return None
            
            # Update last used
            oauth_token.last_used_at = timezone.now()
            oauth_token.save(update_fields=['last_used_at'])
            
            return oauth_token
        except cls.DoesNotExist:
            return None
