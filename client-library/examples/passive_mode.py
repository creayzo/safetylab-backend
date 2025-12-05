"""
Example: Passive Mode Integration

Agent calls emit_event() as it reasons. Events are buffered and
automatically flushed to the server in batches.
"""

import uuid
from aop_client import AOPClient, ClientConfig

def main():
    # Configure client
    config = ClientConfig(
        api_key="aop_your_api_key_here",
        base_url="http://localhost:8000",
        agent_id=123,
        seed=42,
        
        # Batching configuration
        batch_size=50,
        batch_interval=5.0,
        
        # Enable local replay
        enable_local_replay=True,
        replay_dir="./replays",
        
        # Enable fallback storage
        enable_local_fallback=True,
        local_fallback_dir="./fallback",
        
        # Signature
        org_salt_key="your_org_salt_key_here"
    )
    
    # Create client
    client = AOPClient(config)
    builder = client.trace_builder
    
    print(f"Starting run: {builder.run_id}")
    
    # Start background flusher
    client.start()
    
    try:
        # Step 1: Initial reasoning
        print("Step 1: Reasoning...")
        event = builder.create_reasoning(
            goal="Process customer refund request for order #12345",
            steps=[
                {
                    "step_id": "s1",
                    "description": "Parse customer input and extract order ID",
                    "decision": "extract_order_id",
                    "confidence": 0.95
                },
                {
                    "step_id": "s2",
                    "description": "Validate order ID format",
                    "decision": "proceed_with_validation",
                    "confidence": 0.98
                }
            ],
            safety_checks=[
                {"name": "input_validation", "result": "passed"},
                {"name": "policy_check", "result": "passed"}
            ],
            uncertainty="low"
        )
        client.emit_event(event)
        
        # Step 2: Action request - look up order
        print("Step 2: Looking up order...")
        event = builder.create_action_request(
            action="database_lookup",
            params={
                "table": "orders",
                "query": {"order_id": "ORD-12345"}
            },
            context={
                "timeout_ms": 5000,
                "retry_count": 3
            }
        )
        client.emit_event(event)
        
        # Step 3: Action response - order found
        print("Step 3: Order found...")
        event = builder.create_action_response(
            status="ok",
            data={
                "order_id": "ORD-12345",
                "customer_id": "CUST-789",
                "amount": 99.99,
                "status": "delivered"
            },
            latency_ms=120,
            policy_flags=[]
        )
        client.emit_event(event)
        
        # Step 4: More reasoning
        print("Step 4: Determining refund eligibility...")
        event = builder.create_reasoning(
            goal="Determine if order is eligible for refund",
            steps=[
                {
                    "step_id": "s3",
                    "description": "Check order status and delivery date",
                    "decision": "order_eligible",
                    "confidence": 0.90
                },
                {
                    "step_id": "s4",
                    "description": "Select appropriate refund action",
                    "decision": "create_refund_ticket",
                    "confidence": 0.88
                }
            ],
            safety_checks=[
                {"name": "refund_policy_check", "result": "passed"},
                {"name": "fraud_check", "result": "passed"}
            ],
            uncertainty="medium"
        )
        client.emit_event(event)
        
        # Step 5: Create refund ticket
        print("Step 5: Creating refund ticket...")
        event = builder.create_action_request(
            action="create_ticket",
            params={
                "type": "refund",
                "order_id": "ORD-12345",
                "customer_id": "CUST-789",
                "amount": 99.99,
                "reason": "Product defect"
            }
        )
        client.emit_event(event)
        
        # Step 6: Ticket created
        print("Step 6: Ticket created successfully...")
        event = builder.create_action_response(
            status="ok",
            data={
                "ticket_id": "T-999",
                "created_at": "2025-12-05T10:30:15Z",
                "status": "open"
            },
            latency_ms=250,
            policy_flags=[]
        )
        client.emit_event(event)
        
        # Step 7: Final output
        print("Step 7: Generating final output...")
        event = builder.create_final_output(
            text="Your refund ticket has been created successfully. Ticket ID: T-999. You will receive an email confirmation shortly.",
            structured={
                "ticket_id": "T-999",
                "status": "created",
                "estimated_processing_time": "24-48 hours",
                "next_steps": [
                    "Check email for confirmation",
                    "Track ticket status at portal.example.com"
                ]
            }
        )
        client.emit_event(event)
        
        print("\nAll events emitted!")
        
        # Get statistics
        stats = client.get_stats()
        print(f"\nStatistics:")
        print(f"  Events emitted: {stats['events_emitted']}")
        print(f"  Events sent: {stats['events_sent']}")
        print(f"  Batches sent: {stats['batches_sent']}")
        print(f"  Buffer size: {stats['buffer_size']}")
        
    finally:
        # Stop and flush remaining events
        print("\nStopping client...")
        client.stop()
        
        # Final statistics
        stats = client.get_stats()
        print(f"\nFinal Statistics:")
        print(f"  Total events: {stats['event_count']}")
        print(f"  Events sent: {stats['events_sent']}")
        print(f"  Events failed: {stats['events_failed']}")
        print(f"  Batches sent: {stats['batches_sent']}")
        print(f"  Fallback saves: {stats['fallback_saves']}")

if __name__ == "__main__":
    main()
