"""Celery application configuration."""
from __future__ import annotations

import os
import sys

# Ensure the backend directory is in sys.path so workers can resolve 'app', 'agents', etc.
backend_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if backend_dir not in sys.path:
    sys.path.insert(0, backend_dir)

import asyncio
from celery import Celery
from app.config import settings

def run_async(coro):
    """Run an async coroutine synchronously, handling event loops in threads."""
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        loop = None

    if loop and loop.is_running():
        import threading
        result = []
        exception = []

        def worker():
            try:
                new_loop = asyncio.new_event_loop()
                asyncio.set_event_loop(new_loop)
                res = new_loop.run_until_complete(coro)
                result.append(res)
            except Exception as e:
                exception.append(e)
            finally:
                new_loop.close()

        thread = threading.Thread(target=worker)
        thread.start()
        thread.join()

        if exception:
            raise exception[0]
        return result[0]
    else:
        return asyncio.run(coro)

celery_app = Celery(
    "argolock",
    broker=settings.celery_broker_url,
    backend=settings.celery_result_backend,
    include=[
        "workers.recon_worker",
        "workers.scanner_worker",
        "workers.exploit_worker",
        "workers.ai_worker",
    ],
)

celery_app.conf.update(
    task_serializer="json",
    result_serializer="json",
    accept_content=["json"],
    timezone="UTC",
    enable_utc=True,
    task_track_started=True,
    task_acks_late=True,
    worker_prefetch_multiplier=1,
    task_routes={
        "workers.recon_worker.*": {"queue": "recon"},
        "workers.scanner_worker.*": {"queue": "scanner"},
        "workers.exploit_worker.*": {"queue": "exploit"},
        "workers.ai_worker.*": {"queue": "ai"},
    },
    task_default_queue="default",
    task_soft_time_limit=1800,   # 30 min soft limit
    task_time_limit=3600,        # 1 hour hard limit
    worker_max_tasks_per_child=1, # recycle worker after 1 task to prevent OOM
)


@celery_app.task(name="workers.celery_app.run_full_pipeline", bind=True)
def run_full_pipeline(self, scan_id: str, scan_data: dict):
    """
    Orchestrate the full VAPT pipeline as a Celery chain.
    Runs phases sequentially: recon → scan → exploit → AI analysis.
    """
    from celery import chain
    from workers.recon_worker import run_recon
    from workers.scanner_worker import run_scanner
    from workers.exploit_worker import run_exploit
    from workers.ai_worker import run_ai_analysis

    pipeline = chain(
        run_recon.s(scan_id, scan_data),
        run_scanner.s(scan_id),
        run_exploit.s(scan_id),
        run_ai_analysis.s(scan_id),
    )
    pipeline.apply_async()
    return {"scan_id": scan_id, "status": "pipeline_started"}
