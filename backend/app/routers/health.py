from typing import Any, Dict
from fastapi import APIRouter
from loguru import logger

router = APIRouter()

ROUTED_QUEUES = ["recon", "scanner", "exploit", "ai", "default"]


def check_celery_queue_consumers(timeout: float = 0.5) -> Dict[str, Any]:
    """Inspect Celery workers and verify that every routed queue has an active consumer."""
    required_queues = set(ROUTED_QUEUES)
    try:
        from workers.celery_app import celery_app
        inspector = celery_app.control.inspect(timeout=timeout)
        active_queues_map = inspector.active_queues()
        if not active_queues_map:
            return {
                "connected": False,
                "all_routed_queues_active": False,
                "active_queues": [],
                "missing_queues": sorted(list(required_queues)),
                "worker_count": 0,
            }

        active_set = set()
        for worker_name, queues in active_queues_map.items():
            for q in queues:
                qname = q.get("name") if isinstance(q, dict) else str(q)
                if qname:
                    active_set.add(qname)

        missing = required_queues - active_set
        return {
            "connected": True,
            "all_routed_queues_active": len(missing) == 0,
            "active_queues": sorted(list(active_set)),
            "missing_queues": sorted(list(missing)),
            "worker_count": len(active_queues_map),
        }
    except Exception as e:
        return {
            "connected": False,
            "all_routed_queues_active": False,
            "error": str(e),
            "missing_queues": sorted(list(required_queues)),
            "worker_count": 0,
        }


@router.get("/health")
async def health_check():
    """Surfaces system health including verification that every routed Celery queue has a consumer."""
    celery_status = check_celery_queue_consumers(timeout=0.3)
    all_ok = celery_status.get("all_routed_queues_active", False)
    return {
        "status": "ok" if all_ok else "degraded",
        "service": "ArgoLock Backend",
        "celery": celery_status,
    }


@router.get("/health/celery")
async def celery_health():
    try:
        from workers.celery_app import celery_app
        insp = celery_app.control.inspect(timeout=0.5)
        return {
            "registered": insp.registered(),
            "active_queues": insp.active_queues(),
            "ping": insp.ping(),
            "stats": insp.stats(),
            "queue_consumers": check_celery_queue_consumers(timeout=0.5),
        }
    except Exception as e:
        return {"error": str(e)}

