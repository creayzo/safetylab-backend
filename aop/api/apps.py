from django.apps import AppConfig


class ApiConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'api'
    
    def ready(self):
        # Import models to ensure they're registered
        import api.models
        import api.auth_models
        import api.wal_models
        import api.replay_models
        import api.retention_models
