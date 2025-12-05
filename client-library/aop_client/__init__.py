"""
AOP Client Library - Agent Observability Platform

A Python client library for integrating with the AOP tracing system.

Features:
- Toon parser & serializer
- Trace event building and management
- HMAC signature generation
- Batching and backpressure handling
- Streaming support (WebSocket/HTTP)
- Local replay and fallback storage
- PII redaction hooks
- Automatic retry with exponential backoff
- Multiple integration modes (passive push, active pull, hybrid)
"""

__version__ = "0.1.0"
__author__ = "AOP Team"

from .client import AOPClient
from .trace_builder import TraceBuilder, TraceEvent
from .toon_parser import parse_toon, to_toon, ToonParser
from .streaming import StreamingClient
from .config import ClientConfig

__all__ = [
    'AOPClient',
    'TraceBuilder',
    'TraceEvent',
    'parse_toon',
    'to_toon',
    'ToonParser',
    'StreamingClient',
    'ClientConfig',
]
