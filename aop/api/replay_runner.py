"""
Replay Runner Service

Handles deterministic replay of agent runs:
1. Restore environment snapshot
2. Replay events in order
3. Inject cached responses or re-run
4. Compare outputs
5. Generate reproducibility report
"""

import logging
import json
import hashlib
from typing import Dict, Any, List, Optional, Tuple
from datetime import datetime
from django.utils import timezone
from django.db import transaction

from api.models import Run, TraceEvent
from api.replay_models import (
    ReplaySnapshot,
    ReplayRun,
    CachedLLMResponse,
    CachedToolResponse
)

logger = logging.getLogger(__name__)


class ReplayRunner:
    """
    Executes deterministic replay of agent runs.
    
    Supports three modes:
    - full: Use all cached responses (LLM + tools)
    - hybrid: Use cached tools, re-run LLM
    - verification: Re-run everything, compare results
    """
    
    def __init__(
        self,
        original_run_id: str,
        replay_mode: str = 'full',
        use_cached_llm: bool = True,
        use_cached_tools: bool = True
    ):
        """
        Initialize replay runner.
        
        Args:
            original_run_id: UUID of the original run to replay
            replay_mode: Replay mode (full, hybrid, verification)
            use_cached_llm: Whether to use cached LLM responses
            use_cached_tools: Whether to use cached tool responses
        """
        self.original_run_id = original_run_id
        self.replay_mode = replay_mode
        self.use_cached_llm = use_cached_llm
        self.use_cached_tools = use_cached_tools
        
        self.original_run: Optional[Run] = None
        self.snapshot: Optional[ReplaySnapshot] = None
        self.replay_run: Optional[ReplayRun] = None
        self.original_events: List[TraceEvent] = []
        self.replayed_events: List[Dict[str, Any]] = []
    
    def execute(self) -> ReplayRun:
        """
        Execute the replay.
        
        Returns:
            ReplayRun instance with results
        """
        try:
            # Step 1: Load original run and snapshot
            self._load_original_run()
            
            # Step 2: Create replay run record
            self._create_replay_run()
            
            # Step 3: Restore environment
            self._restore_environment()
            
            # Step 4: Replay events
            self._replay_events()
            
            # Step 5: Compare results
            self._compare_results()
            
            # Step 6: Finalize
            self._finalize_replay()
            
            logger.info(f"Replay {self.replay_run.replay_id} completed successfully")
            return self.replay_run
            
        except Exception as e:
            logger.error(f"Replay failed: {e}", exc_info=True)
            if self.replay_run:
                self.replay_run.status = 'failed'
                self.replay_run.error_message = str(e)
                self.replay_run.completed_at = timezone.now()
                self.replay_run.save()
            raise
    
    def _load_original_run(self):
        """Load original run and associated data."""
        try:
            self.original_run = Run.objects.get(run_id=self.original_run_id)
            self.snapshot = ReplaySnapshot.objects.get(run=self.original_run)
            
            # Load original events
            self.original_events = list(
                TraceEvent.objects.filter(run=self.original_run)
                .order_by('seq_no')
            )
            
            logger.info(
                f"Loaded run {self.original_run_id} with {len(self.original_events)} events"
            )
            
        except Run.DoesNotExist:
            raise ValueError(f"Run {self.original_run_id} not found")
        except ReplaySnapshot.DoesNotExist:
            raise ValueError(f"No replay snapshot for run {self.original_run_id}")
    
    def _create_replay_run(self):
        """Create replay run record."""
        self.replay_run = ReplayRun.objects.create(
            original_run=self.original_run,
            snapshot=self.snapshot,
            replay_mode=self.replay_mode,
            use_cached_llm=self.use_cached_llm,
            use_cached_tools=self.use_cached_tools,
            status='running',
            started_at=timezone.now()
        )
        logger.info(f"Created replay run {self.replay_run.replay_id}")
    
    def _restore_environment(self):
        """Restore environment state from snapshot."""
        logger.info("Restoring environment state")
        
        # Get environment snapshot
        env_snapshot = self.snapshot.get_environment_snapshot()
        
        if env_snapshot:
            logger.info(
                f"Environment snapshot: Python {env_snapshot.python_version}, "
                f"OS {env_snapshot.os_type}"
            )
        
        # Database snapshot restoration (if available)
        if self.snapshot.db_snapshot_id:
            logger.info(f"DB snapshot available: {self.snapshot.db_snapshot_id}")
            # TODO: Implement database snapshot restoration
            # This would involve:
            # 1. Download snapshot from storage
            # 2. Restore to temporary database
            # 3. Configure agent to use temp database
        
        # Set random seed
        import random
        random.seed(self.snapshot.seed)
        logger.info(f"Set random seed: {self.snapshot.seed}")
    
    def _replay_events(self):
        """Replay events in sequence."""
        logger.info(f"Replaying {len(self.original_events)} events")
        
        for event in self.original_events:
            replayed_event = self._replay_single_event(event)
            self.replayed_events.append(replayed_event)
    
    def _replay_single_event(self, event: TraceEvent) -> Dict[str, Any]:
        """
        Replay a single event.
        
        Args:
            event: Original TraceEvent
            
        Returns:
            Replayed event data
        """
        replayed = {
            'seq_no': event.seq_no,
            'event_type': event.type,
            'actor': event.actor,
            'timestamp': timezone.now().isoformat(),
            'original_payload': event.payload,
            'replayed_payload': None,
            'source': None  # 'cached', 'regenerated', 'original'
        }
        
        # Handle different event types
        if event.type == 'reasoning':
            replayed['replayed_payload'] = self._replay_reasoning(event)
        elif event.type == 'action_request':
            replayed['replayed_payload'] = self._replay_action_request(event)
        elif event.type == 'action_response':
            replayed['replayed_payload'] = self._replay_action_response(event)
        elif event.type == 'final_output':
            replayed['replayed_payload'] = self._replay_final_output(event)
        else:
            # For other event types, use original
            replayed['replayed_payload'] = event.payload
            replayed['source'] = 'original'
        
        return replayed
    
    def _replay_reasoning(self, event: TraceEvent) -> Dict[str, Any]:
        """Replay reasoning event (LLM call)."""
        # Ensure payload is a dict
        payload = event.payload if isinstance(event.payload, dict) else json.loads(event.payload) if isinstance(event.payload, str) else {}
        
        # Check for cached LLM response
        if self.use_cached_llm:
            cached = self._get_cached_llm_response(event.seq_no)
            if cached:
                logger.debug(f"Using cached LLM response for seq {event.seq_no}")
                return {
                    'thought': cached.response_text,
                    'goal': payload.get('goal'),
                    'steps': payload.get('steps', []),
                    'source': 'cached'
                }
        
        # Otherwise, re-run LLM
        if self.replay_mode != 'full':
            logger.debug(f"Re-running LLM for seq {event.seq_no}")
            # TODO: Integrate with actual LLM
            # For now, return original with marker
            payload = payload.copy()
            payload['source'] = 'regenerated'
            return payload
        
        # Full mode without cache: use original
        result = payload.copy() if isinstance(payload, dict) else {}
        result['source'] = 'original'
        return result
    
    def _replay_action_request(self, event: TraceEvent) -> Dict[str, Any]:
        """Replay action request event."""
        # Ensure payload is a dict
        payload = event.payload if isinstance(event.payload, dict) else json.loads(event.payload) if isinstance(event.payload, str) else {}
        # Action requests are deterministic, just replay
        result = payload.copy() if isinstance(payload, dict) else {}
        result['source'] = 'original'
        return result
    
    def _replay_action_response(self, event: TraceEvent) -> Dict[str, Any]:
        """Replay action response event (tool call)."""
        # Ensure payload is a dict
        payload = event.payload if isinstance(event.payload, dict) else json.loads(event.payload) if isinstance(event.payload, str) else {}
        
        # Check for cached tool response
        if self.use_cached_tools:
            cached = self._get_cached_tool_response(event.seq_no)
            if cached:
                logger.debug(f"Using cached tool response for seq {event.seq_no}")
                # Only include fields that are present in the original payload
                result = {'status': cached.status, 'result': cached.result}
                if 'error' in payload:
                    result['error'] = cached.error
                if 'latency_ms' in payload:
                    result['latency_ms'] = cached.latency_ms
                result['source'] = 'cached'
                return result
        
        # Otherwise, re-execute tool
        if self.replay_mode != 'full':
            logger.debug(f"Re-executing tool for seq {event.seq_no}")
            # TODO: Integrate with actual tool execution
            # For now, return original with marker
            result = payload.copy() if isinstance(payload, dict) else {}
            result['source'] = 'regenerated'
            return result
        
        # Full mode without cache: use original
        result = payload.copy() if isinstance(payload, dict) else {}
        result['source'] = 'original'
        return result
    
    def _replay_final_output(self, event: TraceEvent) -> Dict[str, Any]:
        """Replay final output event."""
        # Ensure payload is a dict
        payload = event.payload if isinstance(event.payload, dict) else json.loads(event.payload) if isinstance(event.payload, str) else {}
        # Final output is deterministic from previous steps
        result = payload.copy() if isinstance(payload, dict) else {}
        result['source'] = 'original'
        return result
    
    def _get_cached_llm_response(self, seq_no: int) -> Optional[CachedLLMResponse]:
        """Get cached LLM response for sequence number."""
        try:
            cached = CachedLLMResponse.objects.get(
                snapshot=self.snapshot,
                seq_no=seq_no
            )
            
            # Check if expired
            if cached.is_expired():
                logger.warning(f"Cached LLM response for seq {seq_no} has expired")
                return None
            
            return cached
            
        except CachedLLMResponse.DoesNotExist:
            return None
    
    def _get_cached_tool_response(self, seq_no: int) -> Optional[CachedToolResponse]:
        """Get cached tool response for sequence number."""
        try:
            return CachedToolResponse.objects.get(
                snapshot=self.snapshot,
                seq_no=seq_no
            )
        except CachedToolResponse.DoesNotExist:
            return None
    
    def _compare_results(self):
        """Compare original and replayed events."""
        logger.info("Comparing original and replayed events")
        
        total_events = len(self.original_events)
        matching_events = 0
        divergent_events = 0
        divergences = []
        
        for i, original in enumerate(self.original_events):
            if i >= len(self.replayed_events):
                divergences.append({
                    'seq_no': original.seq_no,
                    'type': 'missing_replay',
                    'message': 'Replayed event missing'
                })
                divergent_events += 1
                continue
            
            replayed = self.replayed_events[i]
            
            # Compare payloads
            is_match, differences = self._compare_payloads(
                original.payload,
                replayed['replayed_payload'],
                original.type
            )
            
            if is_match:
                matching_events += 1
            else:
                divergent_events += 1
                divergences.append({
                    'seq_no': original.seq_no,
                    'event_type': original.type,
                    'type': 'payload_mismatch',
                    'differences': differences,
                    'source': replayed.get('source')
                })
        
        # Update replay run
        self.replay_run.total_events = total_events
        self.replay_run.matching_events = matching_events
        self.replay_run.divergent_events = divergent_events
        self.replay_run.divergences = divergences
        self.replay_run.calculate_reproducibility_score()
        
        logger.info(
            f"Comparison complete: {matching_events}/{total_events} matching "
            f"(score: {self.replay_run.reproducibility_score:.2%})"
        )
    
    def _compare_payloads(
        self,
        original: Dict[str, Any],
        replayed: Dict[str, Any],
        event_type: str
    ) -> Tuple[bool, List[Dict[str, Any]]]:
        """
        Compare original and replayed payloads.
        
        Returns:
            (is_match, list_of_differences)
        """
        differences = []
        
        # Normalize original to dict if it's a JSON string
        if isinstance(original, str):
            try:
                original = json.loads(original)
            except json.JSONDecodeError:
                pass
        
        # Remove source marker if present
        replayed_clean = {k: v for k, v in replayed.items() if k != 'source'}
        
        # For reasoning events, compare semantically (not exact match)
        if event_type == 'reasoning':
            # Check if key fields are present
            for key in ['thought', 'goal']:
                if key in original and key in replayed_clean:
                    if original[key] != replayed_clean[key]:
                        differences.append({
                            'field': key,
                            'original': original[key][:100] if isinstance(original[key], str) else original[key],
                            'replayed': replayed_clean[key][:100] if isinstance(replayed_clean[key], str) else replayed_clean[key]
                        })
        else:
            # For other events, exact match
            if original != replayed_clean:
                differences.append({
                    'field': 'payload',
                    'original': original,
                    'replayed': replayed_clean
                })
        
        is_match = len(differences) == 0
        return is_match, differences
    
    def _finalize_replay(self):
        """Finalize replay run."""
        self.replay_run.status = 'completed'
        self.replay_run.completed_at = timezone.now()
        
        # Generate comparison report
        self.replay_run.comparison_report = {
            'execution_time_seconds': (
                self.replay_run.completed_at - self.replay_run.started_at
            ).total_seconds(),
            'original_event_count': len(self.original_events),
            'replayed_event_count': len(self.replayed_events),
            'cache_usage': {
                'llm_cached': self.use_cached_llm,
                'tools_cached': self.use_cached_tools
            },
            'reproducibility': {
                'score': self.replay_run.reproducibility_score,
                'is_reproducible': self.replay_run.reproducibility_score >= 0.95,
                'matching_events': self.replay_run.matching_events,
                'divergent_events': self.replay_run.divergent_events
            }
        }
        
        self.replay_run.save()
        
        logger.info(f"Replay finalized: {self.replay_run.comparison_report}")


def create_replay_snapshot(run: Run, **kwargs) -> ReplaySnapshot:
    """
    Create replay snapshot for a run.
    
    Args:
        run: Run instance
        **kwargs: Additional snapshot parameters
        
    Returns:
        ReplaySnapshot instance
    """
    snapshot_data = {
        'run': run,
        'seed': kwargs.get('seed', run.seed),
        'model_name': kwargs.get('model_name', 'gpt-4'),
        'temperature': kwargs.get('temperature', 0.7),
        'top_p': kwargs.get('top_p', 0.9),
        'max_tokens': kwargs.get('max_tokens'),
        'other_params': kwargs.get('other_params', {}),
        'tool_responses_cached': kwargs.get('tool_responses_cached', False),
        'llm_responses_cached': kwargs.get('llm_responses_cached', False),
        'replay_mode': kwargs.get('replay_mode', 'full'),
        'metadata': kwargs.get('metadata', {})
    }
    
    # Get environment snapshot if available
    from api.models import EnvironmentSnapshot
    env_snapshot = EnvironmentSnapshot.objects.filter(run=run).first()
    if env_snapshot:
        snapshot_data['environment_snapshot_id'] = env_snapshot.snapshot_id
    
    snapshot = ReplaySnapshot.objects.create(**snapshot_data)
    logger.info(f"Created replay snapshot {snapshot.snapshot_id} for run {run.run_id}")
    
    return snapshot


def cache_llm_response(
    snapshot: ReplaySnapshot,
    seq_no: int,
    event_type: str,
    prompt: str,
    response_text: str,
    **kwargs
) -> CachedLLMResponse:
    """
    Cache an LLM response for replay.
    
    Args:
        snapshot: ReplaySnapshot instance
        seq_no: Event sequence number
        event_type: Event type
        prompt: Input prompt
        response_text: LLM response
        **kwargs: Additional parameters
        
    Returns:
        CachedLLMResponse instance
    """
    # Hash the prompt
    prompt_hash = hashlib.sha256(prompt.encode()).hexdigest()
    
    cached = CachedLLMResponse.objects.create(
        snapshot=snapshot,
        seq_no=seq_no,
        event_type=event_type,
        prompt_hash=prompt_hash,
        model_name=kwargs.get('model_name', snapshot.model_name),
        response_text=response_text,
        response_tokens=kwargs.get('response_tokens', len(response_text.split())),
        latency_ms=kwargs.get('latency_ms', 0),
        finish_reason=kwargs.get('finish_reason'),
        consent_given=kwargs.get('consent_given', False),
        expires_at=kwargs.get('expires_at')
    )
    
    logger.debug(f"Cached LLM response for seq {seq_no}")
    return cached


def cache_tool_response(
    snapshot: ReplaySnapshot,
    seq_no: int,
    action_name: str,
    params: Dict[str, Any],
    status: str,
    result: Any,
    **kwargs
) -> CachedToolResponse:
    """
    Cache a tool response for replay.
    
    Args:
        snapshot: ReplaySnapshot instance
        seq_no: Event sequence number
        action_name: Name of the action/tool
        params: Action parameters
        status: Response status (success/error)
        result: Tool result
        **kwargs: Additional parameters
        
    Returns:
        CachedToolResponse instance
    """
    # Hash the parameters
    params_json = json.dumps(params, sort_keys=True, separators=(',', ':'))
    params_hash = hashlib.sha256(params_json.encode()).hexdigest()
    
    cached = CachedToolResponse.objects.create(
        snapshot=snapshot,
        seq_no=seq_no,
        action_name=action_name,
        params_hash=params_hash,
        params=params,
        status=status,
        result=result,
        error=kwargs.get('error'),
        latency_ms=kwargs.get('latency_ms', 0)
    )
    
    logger.debug(f"Cached tool response for seq {seq_no}, action {action_name}")
    return cached
