"""
Example: Custom Hooks for PII Redaction and Event Processing

Demonstrates how to use pre-send hooks for PII redaction and
post-send hooks for custom event processing.
"""

import re
from aop_client import AOPClient, ClientConfig

# PII patterns
EMAIL_PATTERN = re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b')
PHONE_PATTERN = re.compile(r'\b\d{3}[-.]?\d{3}[-.]?\d{4}\b')
SSN_PATTERN = re.compile(r'\b\d{3}-\d{2}-\d{4}\b')
CREDIT_CARD_PATTERN = re.compile(r'\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b')

def redact_pii(event: dict) -> dict:
    """
    Redact PII from event payloads according to organization policy.
    
    This hook is called before sending each event to the server.
    It scans for and redacts common PII patterns.
    """
    print(f"  [REDACTION] Processing event seq={event['seq']}")
    
    def redact_string(text: str) -> str:
        """Redact PII from a string."""
        if not isinstance(text, str):
            return text
        
        # Redact emails
        text = EMAIL_PATTERN.sub('[EMAIL_REDACTED]', text)
        
        # Redact phone numbers
        text = PHONE_PATTERN.sub('[PHONE_REDACTED]', text)
        
        # Redact SSNs
        text = SSN_PATTERN.sub('[SSN_REDACTED]', text)
        
        # Redact credit card numbers
        text = CREDIT_CARD_PATTERN.sub('[CC_REDACTED]', text)
        
        return text
    
    def redact_dict(d: dict) -> dict:
        """Recursively redact PII from dictionary."""
        for key, value in d.items():
            if isinstance(value, str):
                d[key] = redact_string(value)
            elif isinstance(value, dict):
                d[key] = redact_dict(value)
            elif isinstance(value, list):
                d[key] = [redact_dict(item) if isinstance(item, dict) else redact_string(item) if isinstance(item, str) else item for item in value]
        return d
    
    # Redact payload
    if 'payload' in event:
        event['payload'] = redact_dict(event['payload'])
    
    return event


def pre_send_hook(event: dict):
    """
    Called before sending each event.
    
    Use this for logging, metrics, or additional validation.
    """
    print(f"  [PRE-SEND] Event seq={event['seq']}, type={event['type']}")


def post_send_hook(event: dict, success: bool):
    """
    Called after attempting to send each event.
    
    Args:
        event: The event that was sent
        success: Whether the send was successful
    """
    if success:
        print(f"  [POST-SEND] ✓ Event seq={event['seq']} sent successfully")
    else:
        print(f"  [POST-SEND] ✗ Event seq={event['seq']} failed to send")


def main():
    print("=== PII Redaction Example ===\n")
    
    # Configure client with redaction and hooks
    config = ClientConfig(
        api_key="aop_your_api_key_here",
        base_url="http://localhost:8000",
        agent_id=123,
        
        # Enable hooks
        redaction_hook=redact_pii,
        pre_send_hook=pre_send_hook,
        post_send_hook=post_send_hook,
        
        # Batching (small for demo)
        batch_size=2,
        batch_interval=2.0,
        
        org_salt_key="your_org_salt_key_here"
    )
    
    client = AOPClient(config)
    builder = client.trace_builder
    
    print(f"Run ID: {builder.run_id}\n")
    
    # Start client
    client.start()
    
    try:
        # Event 1: Contains email and phone
        print("Event 1: Customer information (contains PII)")
        event = builder.create_action_request(
            action="lookup_customer",
            params={
                "email": "customer@example.com",
                "phone": "555-123-4567",
                "name": "John Doe"
            }
        )
        client.emit_event(event)
        
        # Event 2: Contains SSN and credit card
        print("\nEvent 2: Payment information (contains PII)")
        event = builder.create_action_request(
            action="process_payment",
            params={
                "ssn": "123-45-6789",
                "credit_card": "4532-1234-5678-9010",
                "amount": 99.99
            }
        )
        client.emit_event(event)
        
        # Event 3: Clean event (no PII)
        print("\nEvent 3: Clean event (no PII)")
        event = builder.create_final_output(
            text="Payment processed successfully. Order ID: ORD-12345",
            structured={
                "order_id": "ORD-12345",
                "status": "completed"
            }
        )
        client.emit_event(event)
        
        print("\n--- PII Redaction in Action ---")
        print("Before sending to server, all PII is redacted:")
        print("  • Emails → [EMAIL_REDACTED]")
        print("  • Phones → [PHONE_REDACTED]")
        print("  • SSNs → [SSN_REDACTED]")
        print("  • Credit Cards → [CC_REDACTED]")
        
        # Wait for batch to be sent
        import time
        time.sleep(3)
        
    finally:
        print("\nStopping client...")
        client.stop()
    
    print("\n=== Summary ===")
    print("✓ All PII was redacted before transmission")
    print("✓ Original data remains on agent side for processing")
    print("✓ Compliance requirements met")
    
    stats = client.get_stats()
    print(f"\nEvents processed: {stats['events_emitted']}")
    print(f"Events sent: {stats['events_sent']}")


if __name__ == "__main__":
    main()
