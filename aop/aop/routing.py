"""
ASGI Routing Configuration

Routes for both HTTP and WebSocket connections.
"""

from django.urls import re_path
from api import consumers

websocket_urlpatterns = [
    re_path(r'ws/runs/(?P<run_id>[0-9a-f-]+)/$', consumers.RunStreamConsumer.as_asgi()),
    re_path(r'ws/agents/(?P<agent_id>[0-9]+)/$', consumers.AgentStreamConsumer.as_asgi()),
    re_path(r'ws/dashboard/$', consumers.DashboardConsumer.as_asgi()),
]
