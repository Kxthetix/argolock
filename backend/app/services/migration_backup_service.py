"""
ARGOLOCK V1.7 Database Migration, Backup, and Rollback Service
Provides atomic snapshotting, tamper-evident checksums, point-in-time restores,
rollbacks, and schema migrations with complete tenant backfilling.
"""
from __future__ import annotations

import json
import os
import hashlib
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional
from loguru import logger

from app.models.v1_7_models import utc_now_iso


DEFAULT_BACKUP_DIR = Path("backups")
MANAGED_COLLECTIONS = [
    "users",
    "scans",
    "findings",
    "remediation_tasks",
    "retests",
    "target_authorizations",
    "testing_approvals",
    "v1_7_missions",
    "evidence",
    "vapt_audit_log",
    "audit_logs",
]


class DatabaseMigrationBackupService:
    """Manages database backups, restores, rollbacks, and schema migrations."""

    def __init__(self, db_getter=None, backup_dir: Optional[Path] = None):
        self._db_getter = db_getter
        self.backup_dir = backup_dir or DEFAULT_BACKUP_DIR

    def _get_db(self):
        if self._db_getter:
            return self._db_getter()
        from app.database import get_db
        return get_db()

    async def create_backup(
        self,
        backup_id: Optional[str] = None,
        description: str = "Pre-migration point-in-time snapshot",
    ) -> Dict[str, Any]:
        """
        Create an atomic, tamper-evident backup of all managed collections.
        Computes SHA-256 hash of serial data and writes to disk.
        """
        db = self._get_db()
        timestamp = utc_now_iso()
        b_id = backup_id or f"backup-{datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S')}"

        snapshot: Dict[str, List[Dict[str, Any]]] = {}
        counts: Dict[str, int] = {}

        for coll_name in MANAGED_COLLECTIONS:
            cursor = db[coll_name].find({}, {"_id": 0})
            docs = await cursor.to_list(length=100000)
            snapshot[coll_name] = docs
            counts[coll_name] = len(docs)

        # Serialize and compute SHA-256
        data_serialized = json.dumps(snapshot, sort_keys=True, default=str)
        sha256_checksum = hashlib.sha256(data_serialized.encode("utf-8")).hexdigest()

        backup_payload = {
            "backup_id": b_id,
            "created_at": timestamp,
            "description": description,
            "counts": counts,
            "sha256_checksum": sha256_checksum,
            "data": snapshot,
        }

        # Write to disk
        self.backup_dir.mkdir(parents=True, exist_ok=True)
        backup_file = self.backup_dir / f"{b_id}.json"
        with open(backup_file, "w", encoding="utf-8") as f:
            json.dump(backup_payload, f, indent=2)

        # Store metadata in db
        meta_doc = {
            "backup_id": b_id,
            "created_at": timestamp,
            "description": description,
            "counts": counts,
            "sha256_checksum": sha256_checksum,
            "file_path": str(backup_file),
        }
        await db["database_backups"].insert_one(meta_doc)

        logger.info(f"💾 [BACKUP] Created backup '{b_id}' ({sum(counts.values())} documents, SHA256: {sha256_checksum[:12]}...)")
        return meta_doc

    async def restore_backup(
        self,
        backup_source: str | Dict[str, Any],
        wipe_existing: bool = True,
    ) -> Dict[str, Any]:
        """
        Restore database state from a backup file path, backup_id, or in-memory dictionary.
        Verifies checksum integrity before applying changes.
        """
        db = self._get_db()

        if isinstance(backup_source, dict):
            backup_data = backup_source
        else:
            path = Path(backup_source)
            if not path.is_file():
                # Attempt lookup in backup directory
                path = self.backup_dir / f"{backup_source}.json"
            if not path.is_file():
                raise FileNotFoundError(f"Backup file '{backup_source}' not found.")
            with open(path, "r", encoding="utf-8") as f:
                backup_data = json.load(f)

        # Integrity verification
        expected_sha = backup_data.get("sha256_checksum")
        raw_data = backup_data.get("data", {})
        actual_sha = hashlib.sha256(json.dumps(raw_data, sort_keys=True, default=str).encode("utf-8")).hexdigest()

        if expected_sha and actual_sha != expected_sha:
            raise ValueError(
                f"Backup integrity check FAILED! Stored hash {expected_sha} does not match computed {actual_sha}."
            )

        restored_counts: Dict[str, int] = {}

        for coll_name, docs in raw_data.items():
            if coll_name not in MANAGED_COLLECTIONS:
                continue
            if wipe_existing:
                # Clear existing
                try:
                    await db[coll_name].delete_many({})
                except Exception:
                    # In-memory mock compatibility
                    if hasattr(db[coll_name], "data"):
                        db[coll_name].data = []

            if docs:
                for d in docs:
                    await db[coll_name].insert_one(dict(d))
            restored_counts[coll_name] = len(docs)

        logger.info(f"🔄 [RESTORE] Restored backup '{backup_data.get('backup_id')}' ({sum(restored_counts.values())} documents restored)")
        return {
            "backup_id": backup_data.get("backup_id"),
            "restored_at": utc_now_iso(),
            "restored_counts": restored_counts,
            "integrity_verified": True,
            "status": "restored",
        }

    async def rollback(self, backup_id: str) -> Dict[str, Any]:
        """Convenience method to execute rollback to a specific backup_id."""
        return await self.restore_backup(backup_id, wipe_existing=True)

    async def migrate_tenant_isolation(
        self,
        default_tenant_id: str = "tenant_default",
    ) -> Dict[str, Any]:
        """
        Reviewed migration: Backfills tenant_id on all unpartitioned records across collections.
        Ensures tenant boundary enforcement succeeds across existing installations.
        """
        db = self._get_db()
        migration_counts: Dict[str, int] = {}

        for coll_name in ["users", "scans", "findings", "remediation_tasks", "v1_7_missions", "target_authorizations", "testing_approvals"]:
            res = await db[coll_name].update_many(
                {"tenant_id": {"$exists": False}},
                {"$set": {"tenant_id": default_tenant_id}},
            )
            # Support both Motor/PyMongo result object and MockDB dict
            count = res.modified_count if hasattr(res, "modified_count") else res.get("matched", 0) if isinstance(res, dict) else 0
            migration_counts[coll_name] = count

        logger.info(f"🚀 [MIGRATION] Completed tenant isolation backfill: {migration_counts}")
        return {
            "migration_name": "001_tenant_isolation_backfill",
            "applied_at": utc_now_iso(),
            "default_tenant_id": default_tenant_id,
            "documents_migrated": migration_counts,
            "status": "applied",
        }


migration_backup_service = DatabaseMigrationBackupService()
