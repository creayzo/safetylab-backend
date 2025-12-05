"""
Django Channels WebSocket Consumers

Real-time event streaming for live dashboard monitoring.

Features:
- Run-specific channels (subscribe to a run's events)
- Agent-wide monitoring (subscribe to all agent runs)
- Authentication via query params or headers
- Auto-reconnect support
- Heartbeat/ping-pong for connection health

Usage:
  ws://localhost:8000/ws/runs/<run_id>/
  ws://localhost:8000/ws/agents/<agent_id>/
"""

import json
import logging
import uuid
from channels.generic.websocket import AsyncWebsocketConsumer
from channels.db import database_sync_to_async
from django.utils import timezone

from api.models import Run, Agent, TraceEvent
from api.auth_models import AgentAPIKey

logger = logging.getLogger(__name__)


class RunStreamConsumer(AsyncWebsocketConsumer):
    """
    WebSocket consumer for streaming trace events of a specific run.
    
    Clients connect to /ws/runs/<run_id>/ to receive real-time events.
    """
    
    async def connect(self):
        """Handle WebSocket connection."""
        self.run_id = self.scope['url_route']['kwargs']['run_id']
        self.group_name = f"run_{self.run_id}"
        
        # Authenticate
        authenticated = await self.authenticate()
        if not authenticated:
            await self.close(code=4001)  # Authentication failed
            return
        
        # Verify run exists
        run_exists = await self.check_run_exists()
        if not run_exists:
            await self.close(code=4004)  # Run not found
            return
        
        # Join run-specific group
        await self.channel_layer.group_add(
            self.group_name,
            self.channel_name
        )
        
        await self.accept()
        
        # Send connection confirmation
        await self.send(text_data=json.dumps({
            'type': 'connection',
            'status': 'connected',
            'run_id': self.run_id,
            'timestamp': timezone.now().isoformat()
        }))
        
        logger.info(f"Client connected to run {self.run_id}")
        
        # Send existing events
        await self.send_existing_events()
    
    async def disconnect(self, close_code):
        """Handle WebSocket disconnection."""
        # Leave run group
        await self.channel_layer.group_discard(
            self.group_name,
            self.channel_name
        )
        
        logger.info(f"Client disconnected from run {self.run_id} (code: {close_code})")
    
    async def receive(self, text_data):
        """Handle incoming messages from client."""
        try:
            data = json.loads(text_data)
            message_type = data.get('type')
            
            if message_type == 'ping':
                # Heartbeat
                await self.send(text_data=json.dumps({
                    'type': 'pong',
                    'timestamp': timezone.now().isoformat()
                }))
            
            elif message_type == 'subscribe':
                # Client wants to subscribe to specific event types
                event_types = data.get('event_types', [])
                self.subscribed_event_types = set(event_types) if event_types else None
                await self.send(text_data=json.dumps({
                    'type': 'subscribed',
                    'event_types': list(self.subscribed_event_types) if self.subscribed_event_types else 'all'
                }))
            
            elif message_type == 'history':
                # Client requests event history
                limit = data.get('limit', 100)
                await self.send_existing_events(limit=limit)
        
        except json.JSONDecodeError:
            logger.warning(f"Invalid JSON received: {text_data}")
    
    async def trace_event(self, event):
        """
        Receive trace_event from group and forward to client.
        
        This is called by Celery tasks via channel_layer.group_send()
        """
        event_data = event['event']
        
        # Filter by subscribed event types if specified
        if hasattr(self, 'subscribed_event_types') and self.subscribed_event_types:
            if event_data['event_type'] not in self.subscribed_event_types:
                return
        
        # Send to WebSocket client
        await self.send(text_data=json.dumps({
            'type': 'trace_event',
            'event': event_data
        }))
    
    async def run_finalized(self, event):
        """Notify client that run has been finalized."""
        await self.send(text_data=json.dumps({
            'type': 'run_finalized',
            'run_id': self.run_id,
            'status': event.get('status'),
            'timestamp': event.get('timestamp')
        }))
    
    @database_sync_to_async
    def authenticate(self):
        """
        Authenticate WebSocket connection.
        
        Checks for API key in query params or Sec-WebSocket-Protocol header.
        """
        # Try query params first
        query_params = self.scope.get('query_string', b'').decode()
        if 'api_key=' in query_params:
            api_key = query_params.split('api_key=')[1].split('&')[0]
            try:
                AgentAPIKey.authenticate(api_key)
                return True
            except:
                return False
        
        # Try subprotocol header (api_key.YOUR_KEY)
        subprotocols = self.scope.get('subprotocols', [])
        for protocol in subprotocols:
            if protocol.startswith('api_key.'):
                api_key = protocol.split('api_key.')[1]
                try:
                    AgentAPIKey.authenticate(api_key)
                    return True
                except:
                    return False
        
        # No authentication found
        return False
    
    @database_sync_to_async
    def check_run_exists(self):
        """Check if run exists."""
        try:
            Run.objects.get(run_id=uuid.UUID(self.run_id))
            return True
        except Run.DoesNotExist:
            return False
    
    @database_sync_to_async
    def get_existing_events(self, limit=100):
        """Get existing events for the run."""
        try:
            events = TraceEvent.objects.filter(
                run__run_id=uuid.UUID(self.run_id)
            ).order_by('seq_no')[:limit]
            
            return [
                {
                    'event_id': str(e.event_id),
                    'run_id': str(e.run.run_id),
                    'seq_no': e.seq_no,
                    'event_type': e.event_type,
                    'timestamp': e.timestamp.isoformat(),
                    'actor': e.actor,
                    'payload': e.payload,
                }
                for e in events
            ]
        except:
            return []
    
    async def send_existing_events(self, limit=100):
        """Send existing events to newly connected client."""
        events = await self.get_existing_events(limit=limit)
        
        if events:
            await self.send(text_data=json.dumps({
                'type': 'history',
                'count': len(events),
                'events': events
            }))


class AgentStreamConsumer(AsyncWebsocketConsumer):
    """
    WebSocket consumer for monitoring all runs of a specific agent.
    
    Clients connect to /ws/agents/<agent_id>/ to receive events from
    all runs of that agent.
    """
    
    async def connect(self):
        """Handle WebSocket connection."""
        self.agent_id = self.scope['url_route']['kwargs']['agent_id']
        self.group_name = f"agent_{self.agent_id}"
        
        # Authenticate
        authenticated = await self.authenticate()
        if not authenticated:
            await self.close(code=4001)
            return
        
        # Verify agent exists
        agent_exists = await self.check_agent_exists()
        if not agent_exists:
            await self.close(code=4004)
            return
        
        # Join agent-specific group
        await self.channel_layer.group_add(
            self.group_name,
            self.channel_name
        )
        
        await self.accept()
        
        await self.send(text_data=json.dumps({
            'type': 'connection',
            'status': 'connected',
            'agent_id': self.agent_id,
            'timestamp': timezone.now().isoformat()
        }))
        
        logger.info(f"Client connected to agent {self.agent_id}")
    
    async def disconnect(self, close_code):
        """Handle WebSocket disconnection."""
        await self.channel_layer.group_discard(
            self.group_name,
            self.channel_name
        )
        
        logger.info(f"Client disconnected from agent {self.agent_id}")
    
    async def receive(self, text_data):
        """Handle incoming messages."""
        try:
            data = json.loads(text_data)
            message_type = data.get('type')
            
            if message_type == 'ping':
                await self.send(text_data=json.dumps({
                    'type': 'pong',
                    'timestamp': timezone.now().isoformat()
                }))
            
            elif message_type == 'list_runs':
                # Client wants list of active runs
                runs = await self.get_active_runs()
                await self.send(text_data=json.dumps({
                    'type': 'active_runs',
                    'runs': runs
                }))
        
        except json.JSONDecodeError:
            pass
    
    async def trace_event(self, event):
        """Forward trace events to client."""
        await self.send(text_data=json.dumps({
            'type': 'trace_event',
            'event': event['event']
        }))
    
    async def run_created(self, event):
        """Notify client of new run."""
        await self.send(text_data=json.dumps({
            'type': 'run_created',
            'run': event['run']
        }))
    
    async def run_finalized(self, event):
        """Notify client of finalized run."""
        await self.send(text_data=json.dumps({
            'type': 'run_finalized',
            'run_id': event['run_id'],
            'status': event['status']
        }))
    
    @database_sync_to_async
    def authenticate(self):
        """Authenticate connection."""
        query_params = self.scope.get('query_string', b'').decode()
        if 'api_key=' in query_params:
            api_key = query_params.split('api_key=')[1].split('&')[0]
            try:
                AgentAPIKey.authenticate(api_key)
                return True
            except:
                return False
        return False
    
    @database_sync_to_async
    def check_agent_exists(self):
        """Check if agent exists."""
        try:
            Agent.objects.get(id=int(self.agent_id))
            return True
        except (Agent.DoesNotExist, ValueError):
            return False
    
    @database_sync_to_async
    def get_active_runs(self):
        """Get active runs for this agent."""
        try:
            runs = Run.objects.filter(
                agent_id=int(self.agent_id),
                status='running'
            ).order_by('-start_ts')[:10]
            
            return [
                {
                    'run_id': str(r.run_id),
                    'status': r.status,
                    'start_ts': r.start_ts.isoformat(),
                    'scenario_id': r.scenario_id
                }
                for r in runs
            ]
        except:
            return []


class DashboardConsumer(AsyncWebsocketConsumer):
    """
    WebSocket consumer for global dashboard monitoring.
    
    Provides system-wide metrics and alerts.
    """
    
    async def connect(self):
        """Handle connection."""
        # Authenticate as admin
        authenticated = await self.authenticate_admin()
        if not authenticated:
            await self.close(code=4001)
            return
        
        # Join global dashboard group
        await self.channel_layer.group_add(
            "dashboard",
            self.channel_name
        )
        
        await self.accept()
        
        await self.send(text_data=json.dumps({
            'type': 'connection',
            'status': 'connected',
            'timestamp': timezone.now().isoformat()
        }))
    
    async def disconnect(self, close_code):
        """Handle disconnection."""
        await self.channel_layer.group_discard(
            "dashboard",
            self.channel_name
        )
    
    async def receive(self, text_data):
        """Handle incoming messages."""
        try:
            data = json.loads(text_data)
            message_type = data.get('type')
            
            if message_type == 'ping':
                await self.send(text_data=json.dumps({
                    'type': 'pong'
                }))
            
            elif message_type == 'metrics':
                # Send system metrics
                metrics = await self.get_system_metrics()
                await self.send(text_data=json.dumps({
                    'type': 'metrics',
                    'data': metrics
                }))
        
        except json.JSONDecodeError:
            pass
    
    async def system_alert(self, event):
        """Forward system alerts to dashboard."""
        await self.send(text_data=json.dumps({
            'type': 'alert',
            'alert': event['alert']
        }))
    
    async def metrics_update(self, event):
        """Forward metrics updates to dashboard."""
        await self.send(text_data=json.dumps({
            'type': 'metrics_update',
            'metrics': event['metrics']
        }))
    
    @database_sync_to_async
    def authenticate_admin(self):
        """Authenticate as admin user."""
        # Simplified auth - check for admin API key
        query_params = self.scope.get('query_string', b'').decode()
        if 'admin_key=' in query_params:
            admin_key = query_params.split('admin_key=')[1].split('&')[0]
            # TODO: Verify against admin keys
            return True
        return False
    
    @database_sync_to_async
    def get_system_metrics(self):
        """Get system-wide metrics."""
        from api.wal_models import EventWAL
        
        return {
            'active_runs': Run.objects.filter(status='running').count(),
            'pending_events': EventWAL.objects.filter(status='pending').count(),
            'failed_events': EventWAL.objects.filter(status='failed').count(),
            'timestamp': timezone.now().isoformat()
        }
