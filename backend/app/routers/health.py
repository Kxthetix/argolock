from fastapi import APIRouter

router = APIRouter()


@router.get("/health")
async def health_check():
    return {"status": "ok", "service": "ArgoLock Backend"}


@router.get("/health/celery")
async def celery_health():
    try:
        from workers.celery_app import celery_app
        insp = celery_app.control.inspect()
        return {
            "registered": insp.registered(),
            "active_queues": insp.active_queues(),
            "ping": insp.ping(),
            "stats": insp.stats(),
        }
    except Exception as e:
        return {"error": str(e)}

