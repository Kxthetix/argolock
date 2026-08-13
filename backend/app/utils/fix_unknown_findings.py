"""Database migration utility to repair existing 'Unknown Finding' titles and 'Unknown' OWASP categories."""
from __future__ import annotations

import os
import sys

# Add backend directory to sys.path
backend_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
if backend_dir not in sys.path:
    sys.path.insert(0, backend_dir)

from agents.vulnerability_agent import VulnerabilityAgent


def repair_findings_in_db(db):
    """Repair title and owasp_category in MongoDB findings collection."""
    findings = list(db["findings"].find({}))
    print(f"Inspecting {len(findings)} findings in database...")
    repaired_count = 0

    for f in findings:
        updated = False
        title = f.get("title", "")
        desc = f.get("description", "") or f.get("msg", "")
        tool = f.get("tool_source", "")

        # 1. Fix Title
        if not title or title.strip() in ("", "Unknown Finding", "Unknown", "None"):
            new_title = (
                f.get("name")
                or f.get("template_name")
                or f.get("msg")
                or f.get("vulnerability")
                or f.get("vulnerability_type")
                or f.get("id")
            )
            if not new_title and desc:
                new_title = desc.split(".")[0].strip()
                if len(new_title) > 75:
                    new_title = new_title[:72] + "..."
            if not new_title:
                new_title = f"Security Issue Discovered ({tool or 'Scanner'})"
            
            f["title"] = new_title
            updated = True
            print(f"  Fixed Title [{f.get('id')}]: 'Unknown Finding' -> '{new_title}'")

        # 2. Fix OWASP Category
        owasp = f.get("owasp_category", "")
        if not owasp or owasp.strip() in ("", "Unknown", "None"):
            new_owasp = VulnerabilityAgent.infer_owasp_category(f["title"], desc, tool)
            f["owasp_category"] = new_owasp
            updated = True
            print(f"  Fixed OWASP Category [{f.get('id')}]: 'Unknown' -> '{new_owasp}'")

        if updated:
            db["findings"].update_one(
                {"id": f["id"]},
                {"$set": {
                    "title": f["title"],
                    "owasp_category": f["owasp_category"]
                }}
            )
            repaired_count += 1

    print(f"Successfully repaired {repaired_count} finding documents.")


if __name__ == "__main__":
    from pymongo import MongoClient
    mongo_url = os.environ.get("MONGODB_URL", "mongodb://localhost:27017")
    db_name = os.environ.get("MONGODB_DB", "vaultx")
    print(f"Connecting to MongoDB at {mongo_url} (db: {db_name})...")
    try:
        client = MongoClient(mongo_url)
        db = client[db_name]
        repair_findings_in_db(db)
    except Exception as e:
        print("Database connection error:", e)
