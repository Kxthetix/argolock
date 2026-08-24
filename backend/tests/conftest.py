import asyncio
from unittest.mock import MagicMock
import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient

from app.config import settings

# Force test database configuration
settings.mongodb_db = "argolock_test"

from workers.celery_app import celery_app
celery_app.conf.task_always_eager = True
celery_app.conf.task_eager_propagates = True
celery_app.conf.broker_url = "memory://"
celery_app.conf.result_backend = "cache+memory://"

from app.database import connect_db, disconnect_db, get_db
from app.main import app





@pytest_asyncio.fixture
async def client():
    """Yield a test client with lifespan events triggered (startup/shutdown)."""
    await connect_db()
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        yield ac
    await disconnect_db()


@pytest_asyncio.fixture
async def clean_test_db():
    """Clean up the test database after tests."""
    yield
    try:
        from motor.motor_asyncio import AsyncIOMotorClient
        client = AsyncIOMotorClient(settings.mongodb_url, serverSelectionTimeoutMS=3000)
        await client.drop_database("argolock_test")
        client.close()
    except Exception:
        pass


@pytest.fixture(autouse=True)
def mock_celery_pipeline(monkeypatch):
    """Mock Celery task queue submission during API tests."""
    mock_delay = MagicMock()
    monkeypatch.setattr("workers.celery_app.run_full_pipeline.delay", mock_delay)
    return mock_delay
