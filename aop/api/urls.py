"""
URL configuration for API endpoints
"""

from django.urls import path, include
from rest_framework.routers import DefaultRouter
from api import views

app_name = 'api'

urlpatterns = [
    # ============================================================================
    # Run Management
    # ============================================================================
    
    # POST /api/runs/ - Create new run
    path('runs/', views.create_run, name='create_run'),
    
    # POST /api/runs/{run_id}/events/ - Append single trace event
    path('runs/<uuid:run_id>/events/', views.append_trace_event, name='append_trace_event'),
    
    # POST /api/trace-events/batch/ - Batch event submission
    path('trace-events/batch/', views.batch_trace_events, name='batch_trace_events'),
    
    # POST /api/runs/{run_id}/finalize/ - Finalize run
    path('runs/<uuid:run_id>/finalize/', views.finalize_run, name='finalize_run'),
    
    # GET /api/runs/{run_id}/trace - Download full trace
    path('runs/<uuid:run_id>/trace/', views.download_trace, name='download_trace'),
    
    # ============================================================================
    # Agent Management
    # ============================================================================
    
    # POST /api/agents/validate_callback - Test agent connectivity
    path('agents/validate_callback/', views.validate_agent_callback, name='validate_agent_callback'),
    
    # ============================================================================
    # Admin Endpoints (require admin authentication)
    # ============================================================================
    
    # POST /api/admin/organizations/{org_id}/rotate_salt_key
    path('admin/organizations/<int:org_id>/rotate_salt_key/', 
         views.rotate_org_salt_key, 
         name='rotate_org_salt_key'),
    
    # PUT /api/admin/organizations/{org_id}/retention_policy
    path('admin/organizations/<int:org_id>/retention_policy/', 
         views.update_retention_policy, 
         name='update_retention_policy'),
    
    # GET /api/admin/organizations/{org_id}/audit_logs
    path('admin/organizations/<int:org_id>/audit_logs/', 
         views.list_audit_logs, 
         name='list_audit_logs'),
]
