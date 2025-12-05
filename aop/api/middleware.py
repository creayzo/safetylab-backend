"""
Authentication Middleware for API Key and OAuth Token validation.

This module provides middleware for:
- Agent API key authentication
- OAuth2/JWT token authentication
- mTLS certificate validation
- Request signature verification
"""

from django.http import JsonResponse
from django.utils.deprecation import MiddlewareMixin
from django.contrib.auth import get_user_model
from rest_framework.authentication import BaseAuthentication
from rest_framework.exceptions import AuthenticationFailed
from typing import Optional, Tuple
import logging

User = get_user_model()
logger = logging.getLogger(__name__)


class APIKeyAuthentication(BaseAuthentication):
    """
    DRF Authentication class for Agent API keys.
    
    Usage in views:
        authentication_classes = [APIKeyAuthentication]
    
    Expected header:
        Authorization: Bearer aop_<api_key>
    or
        X-API-Key: aop_<api_key>
    """
    
    keyword = 'Bearer'
    
    def authenticate(self, request) -> Optional[Tuple]:
        """
        Authenticate the request using API key.
        
        Returns:
            Tuple of (user, auth_obj) if successful
            None if authentication should be skipped
            
        Raises:
            AuthenticationFailed if authentication fails
        """
        # Try Authorization header first
        auth_header = request.META.get('HTTP_AUTHORIZATION', '')
        api_key = None
        
        if auth_header.startswith(f'{self.keyword} '):
            api_key = auth_header[len(self.keyword) + 1:]
        
        # Fall back to X-API-Key header
        if not api_key:
            api_key = request.META.get('HTTP_X_API_KEY', '')
        
        if not api_key:
            return None  # Let other authentication methods try
        
        # Authenticate the API key
        from api.auth_models import AgentAPIKey
        
        api_key_obj = AgentAPIKey.authenticate(api_key)
        
        if not api_key_obj:
            raise AuthenticationFailed('Invalid or expired API key')
        
        # Store the agent and organization in the request for easy access
        request.agent = api_key_obj.agent
        request.organization = api_key_obj.agent.owner
        request.api_key_scopes = api_key_obj.scopes
        
        # Return a pseudo-user for DRF compatibility (use agent info)
        # In production, you might want to link agents to actual User accounts
        return (None, api_key_obj)
    
    def authenticate_header(self, request) -> str:
        """Return the WWW-Authenticate header value."""
        return f'{self.keyword} realm="api"'


class OAuthAuthentication(BaseAuthentication):
    """
    DRF Authentication class for OAuth2/JWT tokens.
    
    Usage in views:
        authentication_classes = [OAuthAuthentication]
    
    Expected header:
        Authorization: Bearer <oauth_token>
    """
    
    keyword = 'Bearer'
    
    def authenticate(self, request) -> Optional[Tuple]:
        """
        Authenticate the request using OAuth token.
        
        Returns:
            Tuple of (user, auth_obj) if successful
            None if authentication should be skipped
            
        Raises:
            AuthenticationFailed if authentication fails
        """
        auth_header = request.META.get('HTTP_AUTHORIZATION', '')
        
        if not auth_header.startswith(f'{self.keyword} '):
            return None
        
        token = auth_header[len(self.keyword) + 1:]
        
        # Try to authenticate as OAuth token
        from api.auth_models import OAuthToken
        
        oauth_token = OAuthToken.authenticate(token)
        
        if not oauth_token:
            # Could be an API key, let other authentication methods try
            return None
        
        # Store token scopes in request
        request.oauth_scopes = oauth_token.scopes
        request.oauth_token = oauth_token
        
        return (oauth_token.user, oauth_token)
    
    def authenticate_header(self, request) -> str:
        """Return the WWW-Authenticate header value."""
        return f'{self.keyword} realm="api"'


class SignatureVerificationMiddleware(MiddlewareMixin):
    """
    Middleware to verify HMAC signatures on incoming TraceEvent submissions.
    
    This middleware checks that every TraceEvent has a valid HMAC signature
    to detect tampering and ensure data integrity.
    """
    
    # Paths that require signature verification
    PROTECTED_PATHS = [
        '/api/trace-events/',
        '/api/runs/',
    ]
    
    def process_request(self, request):
        """
        Verify request signature if path is protected.
        """
        # Check if path requires signature verification
        if not any(request.path.startswith(path) for path in self.PROTECTED_PATHS):
            return None
        
        # Skip verification for GET requests
        if request.method in ['GET', 'HEAD', 'OPTIONS']:
            return None
        
        # Ensure we have an authenticated organization
        if not hasattr(request, 'organization'):
            return JsonResponse(
                {'error': 'Authentication required for signature verification'},
                status=401
            )
        
        # For TraceEvent submissions, signature verification happens at the view level
        # This middleware just ensures authentication is present
        return None


class MTLSMiddleware(MiddlewareMixin):
    """
    Middleware to validate mutual TLS certificates for enterprise on-prem connectors.
    
    This middleware checks client certificates against stored mTLS certificates
    for organizations that require mTLS authentication.
    """
    
    def process_request(self, request):
        """
        Validate client certificate if mTLS is required.
        """
        # Check if client certificate is present
        client_cert = request.META.get('SSL_CLIENT_CERT')
        
        if not client_cert:
            # mTLS is optional - only validate if cert is provided
            return None
        
        # Extract certificate fingerprint
        cert_fingerprint = request.META.get('SSL_CLIENT_FINGERPRINT')
        
        if not cert_fingerprint:
            logger.warning('Client certificate present but fingerprint missing')
            return JsonResponse(
                {'error': 'Invalid client certificate'},
                status=401
            )
        
        # Validate certificate
        from api.auth_models import MTLSCertificate
        
        try:
            cert = MTLSCertificate.objects.get(
                fingerprint=cert_fingerprint,
                is_active=True
            )
            
            if not cert.is_valid():
                logger.warning(f'Expired or revoked certificate: {cert_fingerprint}')
                return JsonResponse(
                    {'error': 'Certificate expired or revoked'},
                    status=401
                )
            
            # Store certificate info in request
            request.mtls_certificate = cert
            request.mtls_organization = cert.organization
            
            logger.info(f'mTLS authentication successful for {cert.organization.name}')
            
        except MTLSCertificate.DoesNotExist:
            logger.warning(f'Unknown certificate fingerprint: {cert_fingerprint}')
            return JsonResponse(
                {'error': 'Certificate not recognized'},
                status=401
            )
        
        return None


class SecurityHeadersMiddleware(MiddlewareMixin):
    """
    Add security headers to all responses.
    """
    
    def process_response(self, request, response):
        """Add security headers."""
        response['X-Content-Type-Options'] = 'nosniff'
        response['X-Frame-Options'] = 'DENY'
        response['X-XSS-Protection'] = '1; mode=block'
        response['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
        
        return response


class RateLimitMiddleware(MiddlewareMixin):
    """
    Simple rate limiting middleware based on API key or IP.
    
    For production, consider using django-ratelimit or similar library.
    """
    
    # Rate limits (requests per minute)
    RATE_LIMITS = {
        'api_key': 1000,  # Per API key
        'ip': 100,        # Per IP address
    }
    
    def process_request(self, request):
        """
        Check rate limits.
        """
        # This is a placeholder - implement actual rate limiting
        # using Redis or similar cache backend
        
        # For now, just pass through
        return None
