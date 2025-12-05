"""
Example: Active Mode Integration (Pull)

Suitable for serverless environments. Agent collects events locally
and returns the full trace at the end.
"""

import json
from aop_client import AOPClient, ClientConfig

def process_customer_request(customer_input: str):
    """
    Process a customer request and return the full trace.
    
    This is suitable for serverless/FaaS environments where the
    agent needs to return everything at once.
    """
    # Configure client (no background flushing)
    config = ClientConfig(
        api_key="aop_your_api_key_here",
        base_url="http://localhost:8000",
        agent_id=123,
        seed=42,
        org_salt_key="your_org_salt_key_here"
    )
    
    # Create client
    client = AOPClient(config)
    builder = client.trace_builder
    
    print(f"Processing request: {customer_input}")
    print(f"Run ID: {builder.run_id}")
    
    # Step 1: Parse input
    event = builder.create_reasoning(
        goal=f"Parse and understand customer request: {customer_input}",
        steps=[
            {
                "step_id": "s1",
                "description": "Tokenize and analyze input",
                "decision": "classify_as_refund_request",
                "confidence": 0.92
            }
        ],
        safety_checks=[
            {"name": "input_validation", "result": "passed"}
        ],
        uncertainty="low"
    )
    
    # Step 2: Determine action
    event = builder.create_reasoning(
        goal="Determine appropriate action for refund request",
        steps=[
            {
                "step_id": "s2",
                "description": "Check refund eligibility criteria",
                "decision": "proceed_with_refund",
                "confidence": 0.87
            }
        ],
        safety_checks=[
            {"name": "policy_check", "result": "passed"}
        ],
        uncertainty="medium"
    )
    
    # Step 3: Execute action
    event = builder.create_action_request(
        action="create_refund_ticket",
        params={
            "customer_input": customer_input,
            "amount": 99.99
        }
    )
    
    event = builder.create_action_response(
        status="ok",
        data={"ticket_id": "T-888"},
        latency_ms=180
    )
    
    # Step 4: Generate response
    event = builder.create_final_output(
        text="Refund ticket T-888 has been created for your request.",
        structured={
            "ticket_id": "T-888",
            "status": "created"
        }
    )
    
    # Get the complete trace
    trace = client.get_trace()
    
    return {
        "response": "Refund ticket T-888 has been created for your request.",
        "run_id": builder.run_id,
        "trace": trace
    }


def main():
    # Simulate agent invocation
    customer_input = "I need a refund for order #12345"
    
    result = process_customer_request(customer_input)
    
    print("\n=== Agent Response ===")
    print(f"Response: {result['response']}")
    print(f"Run ID: {result['run_id']}")
    print(f"Trace events: {len(result['trace'])}")
    
    print("\n=== Trace Preview ===")
    for i, event in enumerate(result['trace'][:3], 1):
        print(f"\nEvent {i}:")
        print(f"  Seq: {event['seq']}")
        print(f"  Type: {event['type']}")
        print(f"  Actor: {event['actor']}")
    
    if len(result['trace']) > 3:
        print(f"\n... and {len(result['trace']) - 3} more events")
    
    # The orchestrator would now:
    # 1. Return response to user
    # 2. Send trace to AOP server for storage
    print("\n=== Send Trace to AOP Server ===")
    print("POST /api/trace-events/batch/")
    print(json.dumps({
        "run_id": result['run_id'],
        "agent_id": 123,
        "events": result['trace']
    }, indent=2)[:500] + "...")

if __name__ == "__main__":
    main()
