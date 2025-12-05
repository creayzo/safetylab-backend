"""
AOP Client - Main client implementation

Provides passive (push), active (pull), and hybrid integration modes
with batching, backpressure handling, retry logic, and fallback storage.
"""

import os
import json
import time
import uuid
import hmac
import hashlib
import logging
import threading
from pathlib import Path
from typing import List, Dict, Any, Optional
from datetime import datetime
from queue import Queue, Full
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry as URLRetry

from .config import ClientConfig
from .trace_builder import TraceBuilder, TraceEvent
from .toon_parser import to_toon, parse_toon

logger = logging.getLogger(__name__)


class SignatureGenerator:
    """Generate HMAC signatures for trace events."""
    
    @staticmethod
    def generate_signature(
        org_salt_key: str,
        run_id: str,
        seq_no: int,
        payload: str
    ) -> str:
        """
        Generate HMAC-SHA256 signature for a trace event.
        
        Args:
            org_salt_key: Organization's salt key
            run_id: Run UUID
            seq_no: Sequence number
            payload: JSON payload string
        
        Returns:
            Hex-encoded HMAC signature
        """
        message = f"{run_id}{seq_no}{payload}"
        signature = hmac.new(
            org_salt_key.encode('utf-8'),
            message.encode('utf-8'),
            hashlib.sha256
        ).hexdigest()
        return signature


class LocalFallbackStorage:
    """Local file storage for events when server is unavailable."""
    
    def __init__(self, fallback_dir: str):
        """
        Initialize fallback storage.
        
        Args:
            fallback_dir: Directory for fallback files
        """
        self.fallback_dir = Path(fallback_dir)
        self.fallback_dir.mkdir(parents=True, exist_ok=True)
    
    def save_batch(self, run_id: str, batch: List[Dict[str, Any]]) -> str:
        """
        Save a batch of events to fallback storage.
        
        Args:
            run_id: Run ID
            batch: List of events
        
        Returns:
            Path to saved file
        """
        timestamp = datetime.utcnow().strftime('%Y%m%d_%H%M%S')
        filename = f"fallback_{run_id}_{timestamp}_{uuid.uuid4().hex[:8]}.json"
        filepath = self.fallback_dir / filename
        
        with open(filepath, 'w') as f:
            json.dump(batch, f, indent=2)
        
        logger.info(f"Saved {len(batch)} events to fallback: {filepath}")
        return str(filepath)
    
    def list_fallback_files(self) -> List[Path]:
        """List all fallback files."""
        return list(self.fallback_dir.glob("fallback_*.json"))
    
    def load_batch(self, filepath: Path) -> List[Dict[str, Any]]:
        """Load a batch from fallback storage."""
        with open(filepath, 'r') as f:
            return json.load(f)
    
    def delete_file(self, filepath: Path):
        """Delete a fallback file."""
        filepath.unlink()


class LocalReplayWriter:
    """Write full trace to local file for replay."""
    
    def __init__(self, replay_dir: str):
        """
        Initialize replay writer.
        
        Args:
            replay_dir: Directory for replay files
        """
        self.replay_dir = Path(replay_dir)
        self.replay_dir.mkdir(parents=True, exist_ok=True)
    
    def write_trace(
        self,
        run_id: str,
        events: List[Dict[str, Any]],
        metadata: Optional[Dict[str, Any]] = None
    ) -> str:
        """
        Write complete trace to replay file.
        
        Args:
            run_id: Run ID
            events: List of all events
            metadata: Optional metadata about the run
        
        Returns:
            Path to replay file
        """
        timestamp = datetime.utcnow().strftime('%Y%m%d_%H%M%S')
        filename = f"replay_{run_id}_{timestamp}.json"
        filepath = self.replay_dir / filename
        
        replay_data = {
            "run_id": run_id,
            "timestamp": datetime.utcnow().isoformat() + 'Z',
            "event_count": len(events),
            "metadata": metadata or {},
            "events": events
        }
        
        with open(filepath, 'w') as f:
            json.dump(replay_data, f, indent=2)
        
        logger.info(f"Wrote replay trace with {len(events)} events to: {filepath}")
        return str(filepath)


class AOPClient:
    """
    Main AOP client for sending trace events.
    
    Supports three integration modes:
    1. Passive (push): Call emit_event() as agent reasons
    2. Active (pull): Collect events and return full trace
    3. Hybrid: Stream events + batch upload on completion
    
    Features:
    - Automatic batching with configurable size/interval
    - Retry with exponential backoff
    - Local fallback storage on server failure
    - PII redaction hooks
    - HMAC signature generation
    - Idempotency tokens
    
    Usage:
        # Passive mode
        client = AOPClient(config)
        client.start()  # Start background flusher
        client.emit_event(event)
        client.stop()  # Stop and flush remaining events
        
        # Active mode
        client = AOPClient(config)
        client.emit_event(event)
        trace = client.get_trace()  # Get all events
        
        # Hybrid mode
        client = AOPClient(config, enable_streaming=True)
        client.start()
        client.emit_event(event)  # Streams in background
        client.finalize()  # Final batch upload
    """
    
    def __init__(self, config: ClientConfig):
        """
        Initialize AOP client.
        
        Args:
            config: Client configuration
        """
        self.config = config
        
        # Validate configuration
        is_valid, error = config.validate()
        if not is_valid:
            raise ValueError(f"Invalid configuration: {error}")
        
        # Initialize trace builder
        self.trace_builder = TraceBuilder(
            run_id=config.run_id or str(uuid.uuid4()),
            agent_id=config.agent_id,
            seed=config.seed,
            session_id=config.session_id
        )
        
        # Event buffer and queue
        self._buffer: List[TraceEvent] = []
        self._buffer_lock = threading.Lock()
        
        # Background flusher
        self._flush_thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()
        self._running = False
        
        # HTTP session with retry
        self._session = self._create_session()
        
        # Fallback storage
        if config.enable_local_fallback:
            self._fallback = LocalFallbackStorage(config.local_fallback_dir)
        else:
            self._fallback = None
        
        # Replay writer
        if config.enable_local_replay:
            self._replay_writer = LocalReplayWriter(config.replay_dir)
        else:
            self._replay_writer = None
        
        # Signature generator
        self._signature_gen = SignatureGenerator()
        
        # Statistics
        self._stats = {
            'events_emitted': 0,
            'events_sent': 0,
            'events_failed': 0,
            'batches_sent': 0,
            'batches_failed': 0,
            'fallback_saves': 0,
        }
    
    def _create_session(self) -> requests.Session:
        """Create HTTP session with retry logic."""
        session = requests.Session()
        
        # Configure retry strategy
        retry_strategy = URLRetry(
            total=0,  # We handle retries manually for more control
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=["POST", "PUT"]
        )
        
        adapter = HTTPAdapter(max_retries=retry_strategy)
        session.mount("http://", adapter)
        session.mount("https://", adapter)
        
        # Set default headers
        session.headers.update({
            'Content-Type': 'application/json',
            'Authorization': f'Bearer {self.config.api_key}',
            'User-Agent': 'AOP-Client/0.1.0'
        })
        
        return session
    
    def start(self):
        """Start background flusher thread."""
        if self._running:
            logger.warning("Client already running")
            return
        
        self._running = True
        self._stop_event.clear()
        
        self._flush_thread = threading.Thread(target=self._background_flusher, daemon=True)
        self._flush_thread.start()
        
        logger.info("AOP client started")
    
    def stop(self, timeout: float = 10.0):
        """
        Stop background flusher and flush remaining events.
        
        Args:
            timeout: Timeout for stopping (seconds)
        """
        if not self._running:
            return
        
        logger.info("Stopping AOP client...")
        
        self._stop_event.set()
        
        if self._flush_thread:
            self._flush_thread.join(timeout=timeout)
        
        # Flush remaining events
        self._flush_buffer(force=True)
        
        # Write replay if enabled
        if self._replay_writer:
            self._write_replay()
        
        self._running = False
        logger.info("AOP client stopped")
    
    def _background_flusher(self):
        """Background thread that periodically flushes events."""
        while not self._stop_event.is_set():
            time.sleep(self.config.batch_interval)
            
            if not self._stop_event.is_set():
                self._flush_buffer()
    
    def emit_event(self, event: TraceEvent):
        """
        Emit a trace event (passive mode).
        
        Args:
            event: TraceEvent to emit
        """
        with self._buffer_lock:
            # Sign event if org salt key is configured
            if self.config.org_salt_key:
                event.signature = self._signature_gen.generate_signature(
                    self.config.org_salt_key,
                    self.trace_builder.run_id,
                    event.seq,
                    to_toon(event.payload)
                )
                event.meta['signature'] = event.signature
            
            self._buffer.append(event)
            self._stats['events_emitted'] += 1
            
            # Check if buffer is full
            if len(self._buffer) >= self.config.max_buffer_size:
                logger.warning(f"Buffer full ({len(self._buffer)} events), forcing flush")
                self._flush_buffer(force=True)
            elif len(self._buffer) >= self.config.batch_size:
                # Flush if batch size reached
                self._flush_buffer()
    
    def _flush_buffer(self, force: bool = False):
        """
        Flush buffered events to server.
        
        Args:
            force: Force flush even if batch size not reached
        """
        with self._buffer_lock:
            if not self._buffer:
                return
            
            if not force and len(self._buffer) < self.config.batch_size:
                return
            
            # Extract batch
            batch = self._buffer[:self.config.batch_size]
            self._buffer = self._buffer[self.config.batch_size:]
        
        # Send batch
        success = self._send_batch(batch)
        
        if not success and self._fallback:
            # Save to fallback storage
            batch_dicts = [event.to_dict() for event in batch]
            self._fallback.save_batch(self.trace_builder.run_id, batch_dicts)
            self._stats['fallback_saves'] += 1
    
    def _send_batch(self, batch: List[TraceEvent]) -> bool:
        """
        Send a batch of events to server with retry.
        
        Args:
            batch: List of events to send
        
        Returns:
            True if successful, False otherwise
        """
        if not batch:
            return True
        
        # Apply redaction hook
        batch_dicts = [event.to_dict() for event in batch]
        
        if self.config.redaction_hook:
            batch_dicts = [self.config.redaction_hook(event) for event in batch_dicts]
        
        # Apply pre-send hook
        if self.config.pre_send_hook:
            for event in batch_dicts:
                self.config.pre_send_hook(event)
        
        # Generate idempotency token
        idempotency_token = str(uuid.uuid4())
        
        # Prepare payload
        payload = {
            'run_id': self.trace_builder.run_id,
            'agent_id': self.config.agent_id,
            'events': batch_dicts,
            'idempotency_token': idempotency_token
        }
        
        # Retry loop with exponential backoff
        for attempt in range(self.config.max_retries + 1):
            try:
                response = self._session.post(
                    f"{self.config.base_url}/api/trace-events/batch/",
                    json=payload,
                    timeout=self.config.timeout,
                    verify=self.config.verify_ssl
                )
                
                response.raise_for_status()
                
                # Success
                self._stats['events_sent'] += len(batch)
                self._stats['batches_sent'] += 1
                
                logger.info(f"Sent batch of {len(batch)} events (attempt {attempt + 1})")
                
                # Apply post-send hook
                if self.config.post_send_hook:
                    for event in batch_dicts:
                        self.config.post_send_hook(event, True)
                
                return True
            
            except Exception as e:
                logger.error(f"Failed to send batch (attempt {attempt + 1}/{self.config.max_retries + 1}): {e}")
                
                if attempt < self.config.max_retries:
                    # Calculate backoff
                    backoff = min(
                        self.config.retry_backoff_base * (2 ** attempt),
                        self.config.retry_backoff_max
                    )
                    logger.info(f"Retrying in {backoff:.1f}s...")
                    time.sleep(backoff)
                else:
                    # Final failure
                    self._stats['events_failed'] += len(batch)
                    self._stats['batches_failed'] += 1
                    
                    # Apply post-send hook with failure
                    if self.config.post_send_hook:
                        for event in batch_dicts:
                            self.config.post_send_hook(event, False)
                    
                    return False
        
        return False
    
    def finalize(self):
        """Finalize the run and send all remaining events."""
        logger.info("Finalizing run...")
        self._flush_buffer(force=True)
        
        if self._replay_writer:
            self._write_replay()
    
    def _write_replay(self):
        """Write full trace to replay file."""
        events = self.trace_builder.export_trace()
        
        metadata = {
            'agent_id': self.config.agent_id,
            'seed': self.config.seed,
            'session_id': self.config.session_id,
            'stats': self._stats
        }
        
        self._replay_writer.write_trace(
            self.trace_builder.run_id,
            events,
            metadata
        )
    
    def get_trace(self) -> List[Dict[str, Any]]:
        """
        Get all events (active/pull mode).
        
        Returns:
            List of event dictionaries
        """
        return self.trace_builder.export_trace()
    
    def get_trace_json(self, pretty: bool = False) -> str:
        """
        Get all events as JSON string.
        
        Args:
            pretty: Format with indentation
        
        Returns:
            JSON string
        """
        return self.trace_builder.export_trace_json(pretty=pretty)
    
    def get_stats(self) -> Dict[str, Any]:
        """Get client statistics."""
        return {
            **self._stats,
            'buffer_size': len(self._buffer),
            'run_id': self.trace_builder.run_id,
            'event_count': self.trace_builder.get_event_count()
        }
    
    def __enter__(self):
        """Context manager entry."""
        self.start()
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit."""
        self.stop()
