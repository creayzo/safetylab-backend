"""
Django management command for managing authentication keys and certificates.

Usage:
    # Initialize salt key for an organization
    python manage.py manage_keys --org <org_name> --init-salt
    
    # Rotate organization salt key
    python manage.py manage_keys --org <org_name> --rotate-salt
    
    # Create agent API key
    python manage.py manage_keys --agent <agent_id> --create-api-key
    
    # List all API keys for an agent
    python manage.py manage_keys --agent <agent_id> --list-keys
    
    # Revoke an API key
    python manage.py manage_keys --revoke-key <key_prefix>
    
    # Generate encryption key for salt storage
    python manage.py manage_keys --generate-encryption-key
"""

from django.core.management.base import BaseCommand, CommandError
from django.contrib.auth import get_user_model
from api.models import Organization, Agent
from api.auth_models import (
    OrganizationSaltKey,
    AgentAPIKey,
    MTLSCertificate,
    OAuthToken
)
from cryptography.fernet import Fernet
from django.utils import timezone

User = get_user_model()


class Command(BaseCommand):
    help = 'Manage authentication keys, certificates, and tokens'

    def add_arguments(self, parser):
        # Organization options
        parser.add_argument(
            '--org',
            type=str,
            help='Organization name'
        )
        parser.add_argument(
            '--init-salt',
            action='store_true',
            help='Initialize salt key for organization'
        )
        parser.add_argument(
            '--rotate-salt',
            action='store_true',
            help='Rotate salt key for organization'
        )
        
        # Agent options
        parser.add_argument(
            '--agent',
            type=int,
            help='Agent ID'
        )
        parser.add_argument(
            '--create-api-key',
            action='store_true',
            help='Create new API key for agent'
        )
        parser.add_argument(
            '--key-name',
            type=str,
            default='',
            help='Name/description for the API key'
        )
        parser.add_argument(
            '--key-expires',
            type=int,
            default=365,
            help='API key expiration in days (default: 365)'
        )
        parser.add_argument(
            '--list-keys',
            action='store_true',
            help='List all API keys for agent'
        )
        
        # Key revocation
        parser.add_argument(
            '--revoke-key',
            type=str,
            help='Revoke API key by prefix'
        )
        
        # Utility
        parser.add_argument(
            '--generate-encryption-key',
            action='store_true',
            help='Generate a new Fernet encryption key for salt storage'
        )
        
        # List all
        parser.add_argument(
            '--list-all-orgs',
            action='store_true',
            help='List all organizations and their salt key status'
        )

    def handle(self, *args, **options):
        # Generate encryption key
        if options['generate_encryption_key']:
            self.generate_encryption_key()
            return
        
        # List all organizations
        if options['list_all_orgs']:
            self.list_all_organizations()
            return
        
        # Organization operations
        if options['org']:
            org_name = options['org']
            
            try:
                org = Organization.objects.get(name=org_name)
            except Organization.DoesNotExist:
                raise CommandError(f"Organization '{org_name}' does not exist")
            
            if options['init_salt']:
                self.initialize_salt_key(org)
            elif options['rotate_salt']:
                self.rotate_salt_key(org)
            else:
                raise CommandError("Please specify --init-salt or --rotate-salt")
        
        # Agent operations
        elif options['agent']:
            agent_id = options['agent']
            
            try:
                agent = Agent.objects.select_related('owner').get(id=agent_id)
            except Agent.DoesNotExist:
                raise CommandError(f"Agent with ID {agent_id} does not exist")
            
            if options['create_api_key']:
                self.create_api_key(
                    agent,
                    options['key_name'],
                    options['key_expires']
                )
            elif options['list_keys']:
                self.list_api_keys(agent)
            else:
                raise CommandError("Please specify --create-api-key or --list-keys")
        
        # Key revocation
        elif options['revoke_key']:
            self.revoke_api_key(options['revoke_key'])
        
        else:
            raise CommandError(
                "Please specify --org, --agent, --revoke-key, "
                "--generate-encryption-key, or --list-all-orgs"
            )

    def generate_encryption_key(self):
        """Generate a new Fernet encryption key."""
        key = Fernet.generate_key()
        self.stdout.write(self.style.SUCCESS('\nGenerated encryption key:'))
        self.stdout.write(self.style.WARNING(key.decode()))
        self.stdout.write(self.style.SUCCESS(
            '\nAdd this to your .env file as:'
        ))
        self.stdout.write(f'SALT_ENCRYPTION_KEY={key.decode()}')
        self.stdout.write(self.style.WARNING(
            '\n⚠️  Keep this key secure! Store it in environment variables or a key management service.'
        ))

    def list_all_organizations(self):
        """List all organizations and their salt key status."""
        orgs = Organization.objects.all()
        
        if not orgs:
            self.stdout.write(self.style.WARNING('No organizations found'))
            return
        
        self.stdout.write(self.style.SUCCESS('\n=== Organizations ===\n'))
        
        for org in orgs:
            active_key = org.get_active_salt_key()
            
            self.stdout.write(f"Organization: {org.name} (ID: {org.id})")
            
            if active_key:
                self.stdout.write(
                    f"  ✓ Active Salt Key: v{active_key.version} "
                    f"(Created: {active_key.created_at.strftime('%Y-%m-%d %H:%M')})"
                )
            else:
                self.stdout.write(self.style.WARNING('  ✗ No active salt key'))
            
            # Count agents
            agent_count = org.agents.count()
            self.stdout.write(f"  Agents: {agent_count}")
            
            self.stdout.write('')

    def initialize_salt_key(self, org):
        """Initialize a salt key for an organization."""
        existing = org.get_active_salt_key()
        
        if existing:
            self.stdout.write(
                self.style.WARNING(
                    f"Organization '{org.name}' already has an active salt key "
                    f"(v{existing.version})"
                )
            )
            self.stdout.write('Use --rotate-salt to rotate the key')
            return
        
        salt_key = OrganizationSaltKey.create_for_organization(org)
        
        self.stdout.write(
            self.style.SUCCESS(
                f"✓ Created salt key v{salt_key.version} for '{org.name}'"
            )
        )
        self.stdout.write(
            f"Created at: {salt_key.created_at.strftime('%Y-%m-%d %H:%M:%S')}"
        )

    def rotate_salt_key(self, org):
        """Rotate the salt key for an organization."""
        active_key = org.get_active_salt_key()
        
        if not active_key:
            self.stdout.write(
                self.style.WARNING(
                    f"No active salt key for '{org.name}'. Initializing..."
                )
            )
            self.initialize_salt_key(org)
            return
        
        self.stdout.write(
            f"Current active key: v{active_key.version} "
            f"(Created: {active_key.created_at.strftime('%Y-%m-%d %H:%M')})"
        )
        
        # Confirm rotation
        confirm = input(
            f"\nRotate salt key for '{org.name}'? "
            "This will deactivate the current key. (yes/no): "
        )
        
        if confirm.lower() != 'yes':
            self.stdout.write(self.style.WARNING('Rotation cancelled'))
            return
        
        new_key = active_key.rotate(expiry_days=90)
        
        self.stdout.write(
            self.style.SUCCESS(
                f"✓ Rotated salt key from v{active_key.version} to v{new_key.version}"
            )
        )
        self.stdout.write(
            f"Old key will expire on: {active_key.expires_at.strftime('%Y-%m-%d')}"
        )
        self.stdout.write(
            f"New key created at: {new_key.created_at.strftime('%Y-%m-%d %H:%M:%S')}"
        )

    def create_api_key(self, agent, name, expires_in_days):
        """Create a new API key for an agent."""
        self.stdout.write(f"\nCreating API key for Agent {agent.id} ({agent.owner.name})")
        
        api_key_obj, plaintext_key = agent.create_api_key(
            name=name,
            expires_in_days=expires_in_days
        )
        
        self.stdout.write(self.style.SUCCESS('\n✓ API Key created successfully!\n'))
        self.stdout.write(self.style.WARNING('⚠️  Save this API key now - it will not be shown again!\n'))
        self.stdout.write(self.style.SUCCESS(f'API Key: {plaintext_key}\n'))
        self.stdout.write(f"Prefix: {api_key_obj.key_prefix}")
        self.stdout.write(f"Name: {name or '(unnamed)'}")
        self.stdout.write(
            f"Expires: {api_key_obj.expires_at.strftime('%Y-%m-%d') if api_key_obj.expires_at else 'Never'}"
        )
        self.stdout.write(
            f"Created: {api_key_obj.created_at.strftime('%Y-%m-%d %H:%M:%S')}"
        )

    def list_api_keys(self, agent):
        """List all API keys for an agent."""
        keys = AgentAPIKey.objects.filter(agent=agent).order_by('-created_at')
        
        if not keys:
            self.stdout.write(
                self.style.WARNING(f'No API keys found for Agent {agent.id}')
            )
            return
        
        self.stdout.write(
            self.style.SUCCESS(f'\n=== API Keys for Agent {agent.id} ({agent.owner.name}) ===\n')
        )
        
        for key in keys:
            status = '✓ Active' if key.is_active else '✗ Revoked'
            
            if key.is_active and key.expires_at and timezone.now() > key.expires_at:
                status = '⚠ Expired'
            
            self.stdout.write(f"Prefix: {key.key_prefix}...")
            self.stdout.write(f"  Status: {status}")
            self.stdout.write(f"  Name: {key.name or '(unnamed)'}")
            self.stdout.write(
                f"  Created: {key.created_at.strftime('%Y-%m-%d %H:%M')}"
            )
            
            if key.expires_at:
                self.stdout.write(
                    f"  Expires: {key.expires_at.strftime('%Y-%m-%d')}"
                )
            
            if key.last_used_at:
                self.stdout.write(
                    f"  Last used: {key.last_used_at.strftime('%Y-%m-%d %H:%M')}"
                )
            
            self.stdout.write('')

    def revoke_api_key(self, key_prefix):
        """Revoke an API key by its prefix."""
        try:
            key = AgentAPIKey.objects.get(key_prefix=key_prefix, is_active=True)
        except AgentAPIKey.DoesNotExist:
            raise CommandError(f"No active API key found with prefix '{key_prefix}'")
        
        self.stdout.write(
            f"\nFound API key: {key.key_prefix}... (Agent {key.agent.id})"
        )
        
        confirm = input("Revoke this API key? (yes/no): ")
        
        if confirm.lower() != 'yes':
            self.stdout.write(self.style.WARNING('Revocation cancelled'))
            return
        
        key.revoke()
        
        self.stdout.write(
            self.style.SUCCESS(f'✓ API key {key.key_prefix}... revoked')
        )
