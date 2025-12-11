"""
Celery Tasks for Test Runner

Async execution of evaluation runs.
"""

import logging
from celery import shared_task
from django.utils import timezone

from api.models import EvaluationRun
from api.test_runner import TestRunnerFactory

logger = logging.getLogger(__name__)


@shared_task(bind=True, max_retries=3)
def execute_evaluation_run(self, evaluation_run_id: str):
    """
    Execute an evaluation run asynchronously.
    
    Args:
        evaluation_run_id: UUID of evaluation run
        
    Returns:
        dict with results
    """
    try:
        logger.info(f"Starting async evaluation run: {evaluation_run_id}")
        
        # Load evaluation run
        evaluation_run = EvaluationRun.objects.get(
            run_id=evaluation_run_id
        )
        
        # Execute
        completed_run = TestRunnerFactory.create_and_execute(
            evaluation_run_id
        )
        
        logger.info(
            f"Evaluation run completed: {evaluation_run_id} "
            f"(status: {completed_run.status})"
        )
        
        return {
            'run_id': str(completed_run.run_id),
            'status': completed_run.status,
            'results': completed_run.results
        }
        
    except EvaluationRun.DoesNotExist:
        logger.error(f"Evaluation run not found: {evaluation_run_id}")
        raise
        
    except Exception as exc:
        logger.error(
            f"Evaluation run failed: {exc}", 
            exc_info=True
        )
        
        # Retry with exponential backoff
        raise self.retry(exc=exc, countdown=60 * (2 ** self.request.retries))


@shared_task
def execute_evaluation_batch(evaluation_run_ids: list):
    """
    Execute multiple evaluation runs in parallel.
    
    Args:
        evaluation_run_ids: List of evaluation run UUIDs
        
    Returns:
        dict with batch results
    """
    logger.info(
        f"Starting batch execution: {len(evaluation_run_ids)} runs"
    )
    
    # Launch tasks in parallel
    from celery import group
    
    job = group(
        execute_evaluation_run.s(run_id) 
        for run_id in evaluation_run_ids
    )
    
    result = job.apply_async()
    
    return {
        'batch_id': result.id,
        'total_runs': len(evaluation_run_ids)
    }


@shared_task
def cleanup_old_evaluation_runs(days: int = 90):
    """
    Clean up old evaluation runs based on retention policy.
    
    Args:
        days: Number of days to retain
        
    Returns:
        dict with cleanup stats
    """
    from datetime import timedelta
    
    cutoff_date = timezone.now() - timedelta(days=days)
    
    logger.info(f"Cleaning up evaluation runs older than {cutoff_date}")
    
    old_runs = EvaluationRun.objects.filter(
        created_at__lt=cutoff_date,
        status__in=['completed', 'failed', 'cancelled']
    )
    
    count = old_runs.count()
    old_runs.delete()
    
    logger.info(f"Deleted {count} old evaluation runs")
    
    return {
        'deleted_count': count,
        'cutoff_date': cutoff_date.isoformat()
    }


@shared_task
def schedule_periodic_evaluations():
    """
    Schedule periodic evaluations for agents with auto-monitoring.
    
    Returns:
        dict with scheduled run info
    """
    logger.info("Scheduling periodic evaluations")
    
    # Find evaluation runs configured for auto-monitoring
    auto_runs = EvaluationRun.objects.filter(
        trigger_source='auto_monitor',
        status='pending'
    )
    
    scheduled = []
    
    for eval_run in auto_runs[:10]:  # Limit to 10 at a time
        # Queue for execution
        task = execute_evaluation_run.delay(str(eval_run.run_id))
        
        scheduled.append({
            'run_id': str(eval_run.run_id),
            'task_id': task.id,
            'agent_id': eval_run.agent.id
        })
        
        logger.info(f"Scheduled evaluation: {eval_run.run_id}")
    
    return {
        'scheduled_count': len(scheduled),
        'runs': scheduled
    }


