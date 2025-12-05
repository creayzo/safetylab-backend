"""
Example: Hybrid Mode - Streaming + Batch Upload

Combines real-time streaming with batch upload on completion.
Best for heavy runs where you want live monitoring + guaranteed delivery.
"""

from aop_client import AOPClient, ClientConfig
from aop_client.streaming import HybridClient
import time

def main():
    # Configure client
    config = ClientConfig(
        api_key="aop_your_api_key_here",
        base_url="http://localhost:8000",
        agent_id=123,
        seed=42,
        
        # Batching
        batch_size=50,
        batch_interval=5.0,
        
        # Streaming
        enable_streaming=True,
        streaming_url="ws://localhost:8000/ws/trace/",
        
        # Replay
        enable_local_replay=True,
        replay_dir="./replays",
        
        # Signature
        org_salt_key="your_org_salt_key_here"
    )
    
    # Create base client
    base_client = AOPClient(config)
    
    # Wrap with hybrid client
    hybrid = HybridClient(
        aop_client=base_client,
        streaming_url=config.streaming_url,
        streaming_mode="websocket"  # or "http_chunked"
    )
    
    builder = base_client.trace_builder
    print(f"Starting hybrid run: {builder.run_id}")
    print("Events will be streamed AND batched\n")
    
    # Use as context manager (auto start/stop)
    with hybrid:
        # Simulate a longer reasoning process
        for i in range(5):
            print(f"\nReasoning step {i + 1}...")
            
            event = builder.create_reasoning(
                goal=f"Reasoning step {i + 1} of complex problem",
                steps=[
                    {
                        "step_id": f"s{i + 1}",
                        "description": f"Analyze aspect {i + 1} of the problem",
                        "decision": f"proceed_to_step_{i + 2}",
                        "confidence": 0.85 + (i * 0.02)
                    }
                ],
                safety_checks=[
                    {"name": "step_validation", "result": "passed"}
                ],
                uncertainty="medium"
            )
            
            # Event is both streamed (real-time) and buffered (batch)
            hybrid.emit_event(event)
            
            # Simulate thinking time
            time.sleep(0.5)
        
        # Action request
        print("\nExecuting action...")
        event = builder.create_action_request(
            action="complex_calculation",
            params={"iterations": 1000, "precision": "high"}
        )
        hybrid.emit_event(event)
        
        # Simulate action execution
        time.sleep(1.0)
        
        # Action response
        event = builder.create_action_response(
            status="ok",
            data={"result": 42, "computation_time": 1.05},
            latency_ms=1050
        )
        hybrid.emit_event(event)
        
        # Final output
        print("\nGenerating final output...")
        event = builder.create_final_output(
            text="Complex calculation completed. The answer is 42.",
            structured={
                "answer": 42,
                "confidence": 0.99,
                "steps_taken": 5
            }
        )
        hybrid.emit_event(event)
        
        print("\nFinalizing run...")
        hybrid.finalize()
    
    # Get statistics
    stats = base_client.get_stats()
    print(f"\n=== Run Complete ===")
    print(f"Run ID: {builder.run_id}")
    print(f"Total events: {stats['event_count']}")
    print(f"Events streamed: {stats['events_emitted']}")
    print(f"Events sent in batches: {stats['events_sent']}")
    print(f"Batches sent: {stats['batches_sent']}")
    
    print("\nBenefits of hybrid mode:")
    print("  ✓ Real-time monitoring via streaming")
    print("  ✓ Guaranteed delivery via batch upload")
    print("  ✓ Automatic fallback if streaming fails")
    print("  ✓ Local replay for debugging")

if __name__ == "__main__":
    main()
