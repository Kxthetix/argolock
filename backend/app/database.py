from __future__ import annotations

from motor.motor_asyncio import AsyncIOMotorClient, AsyncIOMotorDatabase
from loguru import logger

from app.config import settings

_client: AsyncIOMotorClient | None = None
_db: AsyncIOMotorDatabase | None = None


async def connect_db() -> None:
    global _client, _db
    logger.info(f"Connecting to MongoDB: {settings.mongodb_url}")
    _client = AsyncIOMotorClient(settings.mongodb_url)
    _db = _client[settings.mongodb_db]
    # Create indexes
    await _db["scans"].create_index("id", unique=True)
    await _db["findings"].create_index("scan_id")
    await _db["findings"].create_index([("scan_id", 1), ("severity", -1)])
    await _db["reports"].create_index("scan_id", unique=True)
    logger.info("✅ MongoDB connected and indexes created")


async def disconnect_db() -> None:
    global _client
    if _client:
        _client.close()
        logger.info("MongoDB disconnected")


def get_db() -> AsyncIOMotorDatabase:
    if _db is None:
        raise RuntimeError("Database not connected. Call connect_db() first.")
    return _db
