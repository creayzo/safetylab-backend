"""
Configuration for AOP Client Library
"""

from dataclasses import dataclass, field
from typing import Optional, Callable, Dict, Any
import os


@dataclass
class ClientConfig:
    """
    Configuration for AOP Client.
    
    Attributes:
        api_key: Agent API key for authentication
        base_url: Base URL of AOP server
        agent_id: Agent ID
        run_id: Run ID (auto-generated if not provided)
        seed: Random seed for reproducibility
        session_id: Session identifier
        
        # Batching config
        batch_size: Maximum events per batch
        batch_interval: Seconds between batch flushes
        max_buffer_size: Maximum events to buffer before forcing flush
        
        # Retry config
        max_retries: Maximum retry attempts
        retry_backoff_base: Base for exponential backoff (seconds)
        retry_backoff_max: Maximum backoff time (seconds)
        
        # Fallback config
        enable_local_fallback: Enable local file storage on server failure
        local_fallback_dir: Directory for fallback storage
        
        # Streaming config
        enable_streaming: Enable WebSocket/streaming mode
        streaming_url: WebSocket URL for streaming
        
        # Hooks
        redaction_hook: Callback for PII redaction
        pre_send_hook: Callback before sending events
        post_send_hook: Callback after sending events
        
        # Replay
        enable_local_replay: Write full trace to local file
        replay_dir: Directory for replay files
        
        # Other
        timeout: Request timeout in seconds
        verify_ssl: Verify SSL certificates
        org_salt_key: Organization salt key for signature generation
    """
    
    # Authentication
    api_key: str = ""
    base_url: str = "http://localhost:8000"
    agent_id: Optional[int] = None
    
    # Run context
    run_id: Optional[str] = None
    seed: Optional[int] = None
    session_id: Optional[str] = None
    
    # Batching
    batch_size: int = 100
    batch_interval: float = 5.0  # seconds
    max_buffer_size: int = 1000
    
    # Retry
    max_retries: int = 3
    retry_backoff_base: float = 1.0
    retry_backoff_max: float = 60.0
    
    # Fallback
    enable_local_fallback: bool = True
    local_fallback_dir: str = "./aop_fallback"
    
    # Streaming
    enable_streaming: bool = False
    streaming_url: Optional[str] = None
    
    # Hooks
    redaction_hook: Optional[Callable[[Dict[str, Any]], Dict[str, Any]]] = None
    pre_send_hook: Optional[Callable[[Dict[str, Any]], None]] = None
    post_send_hook: Optional[Callable[[Dict[str, Any], bool], None]] = None
    
    # Replay
    enable_local_replay: bool = False
    replay_dir: str = "./aop_replay"
    
    # HTTP
    timeout: float = 30.0
    verify_ssl: bool = True
    
    # Signature
    org_salt_key: Optional[str] = None
    
    @classmethod
    def from_env(cls) -> 'ClientConfig':
        """
        Create configuration from environment variables.
        
        Environment variables:
            AOP_API_KEY: Agent API key
            AOP_BASE_URL: Base URL
            AOP_AGENT_ID: Agent ID
            AOP_BATCH_SIZE: Batch size
            AOP_BATCH_INTERVAL: Batch interval
            AOP_ENABLE_STREAMING: Enable streaming
            AOP_STREAMING_URL: Streaming URL
            AOP_ENABLE_LOCAL_REPLAY: Enable local replay
            AOP_REPLAY_DIR: Replay directory
            AOP_ORG_SALT_KEY: Organization salt key
        """
        return cls(
            api_key=os.getenv('AOP_API_KEY', ''),
            base_url=os.getenv('AOP_BASE_URL', 'http://localhost:8000'),
            agent_id=int(os.getenv('AOP_AGENT_ID')) if os.getenv('AOP_AGENT_ID') else None,
            batch_size=int(os.getenv('AOP_BATCH_SIZE', '100')),
            batch_interval=float(os.getenv('AOP_BATCH_INTERVAL', '5.0')),
            enable_streaming=os.getenv('AOP_ENABLE_STREAMING', '').lower() == 'true',
            streaming_url=os.getenv('AOP_STREAMING_URL'),
            enable_local_replay=os.getenv('AOP_ENABLE_LOCAL_REPLAY', '').lower() == 'true',
            replay_dir=os.getenv('AOP_REPLAY_DIR', './aop_replay'),
            org_salt_key=os.getenv('AOP_ORG_SALT_KEY'),
        )
    
    def validate(self) -> tuple[bool, str]:
        """
        Validate configuration.
        
        Returns:
            Tuple of (is_valid, error_message)
        """
        if not self.api_key:
            return False, "api_key is required"
        
        if not self.base_url:
            return False, "base_url is required"
        
        if self.agent_id is None:
            return False, "agent_id is required"
        
        if self.batch_size <= 0:
            return False, "batch_size must be positive"
        
        if self.batch_interval <= 0:
            return False, "batch_interval must be positive"
        
        if self.enable_streaming and not self.streaming_url:
            return False, "streaming_url required when streaming is enabled"
        
        return True, ""
