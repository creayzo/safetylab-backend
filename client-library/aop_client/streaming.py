"""
Streaming Client - WebSocket and chunked HTTP streaming support

Enables real-time streaming of trace events so simulators can observe
the agent's thought process live.
"""

import json
import logging
import threading
import time
from typing import Optional, Callable, Dict, Any
from queue import Queue, Empty
import requests

logger = logging.getLogger(__name__)


class StreamingClient:
    """
    Streaming client for real-time event transmission.
    
    Supports two streaming modes:
    1. WebSocket: Bidirectional streaming (requires websocket-client)
    2. Chunked HTTP: One-way streaming via chunked POST
    
    Usage:
        streaming = StreamingClient(
            url="ws://localhost:8000/ws/trace/",
            api_key="aop_...",
            mode="websocket"
        )
        
        streaming.connect()
        streaming.send_event(event)
        streaming.disconnect()
    """
    
    def __init__(
        self,
        url: str,
        api_key: str,
        mode: str = "websocket",
        on_message: Optional[Callable[[Dict[str, Any]], None]] = None,
        on_error: Optional[Callable[[Exception], None]] = None
    ):
        """
        Initialize streaming client.
        
        Args:
            url: WebSocket or HTTP streaming URL
            api_key: API key for authentication
            mode: Streaming mode ('websocket' or 'http_chunked')
            on_message: Callback for received messages (WebSocket only)
            on_error: Callback for errors
        """
        self.url = url
        self.api_key = api_key
        self.mode = mode
        self.on_message = on_message
        self.on_error = on_error
        
        self._connected = False
        self._ws = None
        self._http_session = None
        self._send_queue: Queue = Queue()
        self._sender_thread: Optional[threading.Thread] = None
        self._receiver_thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()
    
    def connect(self):
        """Connect to streaming endpoint."""
        if self._connected:
            logger.warning("Already connected")
            return
        
        if self.mode == "websocket":
            self._connect_websocket()
        elif self.mode == "http_chunked":
            self._connect_http_chunked()
        else:
            raise ValueError(f"Invalid streaming mode: {self.mode}")
        
        self._connected = True
        logger.info(f"Connected to streaming endpoint: {self.url}")
    
    def _connect_websocket(self):
        """Connect via WebSocket."""
        try:
            import websocket
        except ImportError:
            raise ImportError(
                "websocket-client package required for WebSocket streaming. "
                "Install with: pip install websocket-client"
            )
        
        # Create WebSocket connection
        self._ws = websocket.WebSocketApp(
            self.url,
            header={
                'Authorization': f'Bearer {self.api_key}'
            },
            on_message=self._on_ws_message,
            on_error=self._on_ws_error,
            on_close=self._on_ws_close,
            on_open=self._on_ws_open
        )
        
        # Start WebSocket thread
        self._receiver_thread = threading.Thread(
            target=self._ws.run_forever,
            daemon=True
        )
        self._receiver_thread.start()
        
        # Wait for connection
        time.sleep(0.5)
    
    def _connect_http_chunked(self):
        """Connect via HTTP chunked transfer."""
        self._http_session = requests.Session()
        self._http_session.headers.update({
            'Authorization': f'Bearer {self.api_key}',
            'Content-Type': 'application/json',
            'Transfer-Encoding': 'chunked'
        })
        
        # Start sender thread
        self._stop_event.clear()
        self._sender_thread = threading.Thread(
            target=self._http_sender,
            daemon=True
        )
        self._sender_thread.start()
    
    def _on_ws_open(self, ws):
        """WebSocket connection opened."""
        logger.info("WebSocket connection opened")
    
    def _on_ws_message(self, ws, message):
        """Handle incoming WebSocket message."""
        try:
            data = json.loads(message)
            if self.on_message:
                self.on_message(data)
        except Exception as e:
            logger.error(f"Error processing WebSocket message: {e}")
            if self.on_error:
                self.on_error(e)
    
    def _on_ws_error(self, ws, error):
        """Handle WebSocket error."""
        logger.error(f"WebSocket error: {error}")
        if self.on_error:
            self.on_error(error)
    
    def _on_ws_close(self, ws, close_status_code, close_msg):
        """WebSocket connection closed."""
        logger.info(f"WebSocket connection closed: {close_status_code} - {close_msg}")
        self._connected = False
    
    def _http_sender(self):
        """HTTP chunked sender thread."""
        while not self._stop_event.is_set():
            try:
                # Get event from queue with timeout
                event = self._send_queue.get(timeout=0.1)
                
                # Send as chunked data
                try:
                    response = self._http_session.post(
                        self.url,
                        data=json.dumps(event),
                        stream=True,
                        timeout=5.0
                    )
                    response.raise_for_status()
                    logger.debug(f"Sent event via HTTP chunked: seq={event.get('seq')}")
                except Exception as e:
                    logger.error(f"Failed to send event via HTTP: {e}")
                    if self.on_error:
                        self.on_error(e)
                
                self._send_queue.task_done()
            
            except Empty:
                continue
            except Exception as e:
                logger.error(f"Error in HTTP sender: {e}")
    
    def send_event(self, event: Dict[str, Any]):
        """
        Send an event via streaming connection.
        
        Args:
            event: Event dictionary to send
        """
        if not self._connected:
            raise RuntimeError("Not connected to streaming endpoint")
        
        if self.mode == "websocket":
            if self._ws:
                try:
                    self._ws.send(json.dumps(event))
                    logger.debug(f"Sent event via WebSocket: seq={event.get('seq')}")
                except Exception as e:
                    logger.error(f"Failed to send event via WebSocket: {e}")
                    if self.on_error:
                        self.on_error(e)
        
        elif self.mode == "http_chunked":
            self._send_queue.put(event)
    
    def disconnect(self):
        """Disconnect from streaming endpoint."""
        if not self._connected:
            return
        
        logger.info("Disconnecting from streaming endpoint...")
        
        if self.mode == "websocket":
            if self._ws:
                self._ws.close()
                if self._receiver_thread:
                    self._receiver_thread.join(timeout=2.0)
        
        elif self.mode == "http_chunked":
            self._stop_event.set()
            
            # Wait for queue to empty
            self._send_queue.join()
            
            if self._sender_thread:
                self._sender_thread.join(timeout=2.0)
            
            if self._http_session:
                self._http_session.close()
        
        self._connected = False
        logger.info("Disconnected from streaming endpoint")
    
    def is_connected(self) -> bool:
        """Check if connected."""
        return self._connected
    
    def __enter__(self):
        """Context manager entry."""
        self.connect()
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit."""
        self.disconnect()


class HybridClient:
    """
    Hybrid client combining streaming and batching.
    
    Streams events in real-time while also buffering for batch upload
    on completion. Provides best of both worlds for heavy runs.
    
    Usage:
        from aop_client import AOPClient, HybridClient
        
        base_client = AOPClient(config)
        hybrid = HybridClient(base_client, streaming_url="ws://...")
        
        hybrid.start()
        hybrid.emit_event(event)  # Streams + buffers
        hybrid.finalize()  # Final batch upload
    """
    
    def __init__(
        self,
        aop_client,
        streaming_url: str,
        streaming_mode: str = "websocket"
    ):
        """
        Initialize hybrid client.
        
        Args:
            aop_client: AOPClient instance for batching
            streaming_url: URL for streaming endpoint
            streaming_mode: Streaming mode (websocket or http_chunked)
        """
        self.aop_client = aop_client
        
        self.streaming_client = StreamingClient(
            url=streaming_url,
            api_key=aop_client.config.api_key,
            mode=streaming_mode,
            on_error=self._on_streaming_error
        )
        
        self._streaming_enabled = True
    
    def start(self):
        """Start both streaming and batch clients."""
        self.aop_client.start()
        
        try:
            self.streaming_client.connect()
        except Exception as e:
            logger.warning(f"Failed to connect streaming, continuing with batch only: {e}")
            self._streaming_enabled = False
    
    def emit_event(self, event):
        """
        Emit event to both streaming and batch buffers.
        
        Args:
            event: TraceEvent to emit
        """
        # Always emit to batch client
        self.aop_client.emit_event(event)
        
        # Stream if connected
        if self._streaming_enabled and self.streaming_client.is_connected():
            try:
                self.streaming_client.send_event(event.to_dict())
            except Exception as e:
                logger.warning(f"Failed to stream event, continuing with batch only: {e}")
                self._streaming_enabled = False
    
    def finalize(self):
        """Finalize both streaming and batch uploads."""
        # Disconnect streaming
        if self.streaming_client.is_connected():
            self.streaming_client.disconnect()
        
        # Finalize batch upload
        self.aop_client.finalize()
    
    def stop(self):
        """Stop both clients."""
        if self.streaming_client.is_connected():
            self.streaming_client.disconnect()
        
        self.aop_client.stop()
    
    def _on_streaming_error(self, error: Exception):
        """Handle streaming errors."""
        logger.error(f"Streaming error: {error}")
        # Continue with batch-only mode
        self._streaming_enabled = False
    
    def __enter__(self):
        """Context manager entry."""
        self.start()
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit."""
        self.stop()
