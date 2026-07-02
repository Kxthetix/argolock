import asyncio
from unittest.mock import MagicMock
import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient

from app.config import settings

# Force test database configuration
settings.mongodb_db = "argolock_test"

import app.database as database
from app.database import connect_db, disconnect_db, get_db
from app.main import app


def _real_mongo_available() -> bool:
    """Return True if a real MongoDB server is reachable within a short timeout."""
    try:
        from pymongo import MongoClient
        from pymongo.errors import PyMongoError

        client = MongoClient(settings.mongodb_url, serverSelectionTimeoutMS=1500)
        client.admin.command("ping")
        client.close()
        return True
    except Exception:
        return False


# If no real MongoDB is reachable (e.g. local dev / CI without a Mongo service),
# transparently fall back to an in-memory mongomock-motor client so the async
# integration tests can still exercise the full request/DB code path.
if not _real_mongo_available():
    try:
        from mongomock_motor import AsyncMongoMockClient

        database.AsyncIOMotorClient = AsyncMongoMockClient
    except ImportError:  # pragma: no cover - mongomock-motor not installed
        pass


@pytest.fixture(scope="session")
def anyio_backend():
    return "asyncio"


@pytest.fixture(scope="session")
def event_loop():
    """Create an instance of the default event loop for the test session."""
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        loop = asyncio.new_event_loop()
    yield loop
    loop.close()


@pytest_asyncio.fixture(scope="session")
async def client():
    """Yield a test client with lifespan events triggered (startup/shutdown) session-wide."""
    await connect_db()
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        yield ac
    await disconnect_db()


@pytest_asyncio.fixture(scope="session", autouse=True)
async def clean_test_db(event_loop):
    """Clean up the test database after the test session finishes."""
    yield
    # Attempt to drop test DB; silently skip if MongoDB is not reachable
    try:
        from motor.motor_asyncio import AsyncIOMotorClient
        client = AsyncIOMotorClient(settings.mongodb_url, serverSelectionTimeoutMS=3000)
        await client.drop_database("argolock_test")
        client.close()
    except Exception:
        pass  # MongoDB not running — nothing to clean up


@pytest.fixture(autouse=True)
def mock_celery_pipeline(monkeypatch):
    """Mock Celery task queue submission during API tests."""
    mock_delay = MagicMock()
    monkeypatch.setattr("workers.celery_app.run_full_pipeline.delay", mock_delay)
    return mock_delay
