import pytest
from app.database import get_db


@pytest.mark.asyncio(scope="session")
async def test_health_check(client):
    """Verify that the health check endpoint returns 200 and correct payload."""
    response = await client.get("/api/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok", "service": "VaultX Backend"}


@pytest.mark.asyncio(scope="session")
async def test_create_scan_invalid_scope(client):
    """Verify that creating a scan with unauthorized scope fails with 400."""
    payload = {
        "scope": {
            "target": "scanme.nmap.org",
            "authorized": False,  # Unauthorized scope should be rejected
            "max_depth": 3
        },
        "name": "Test Unauthorized Scan"
    }
    
    response = await client.post("/api/scans", json=payload)
    assert response.status_code == 400
    assert "Scope validation failed" in response.json()["detail"]


@pytest.mark.asyncio(scope="session")
async def test_create_and_get_scan(client, mock_celery_pipeline):
    """Verify scan creation, DB persistence, scan retrieval, and list functionality."""
    payload = {
        "scope": {
            "target": "scanme.nmap.org",
            "authorized": True,
            "max_depth": 1
        },
        "name": "Test Real Scan"
    }
    
    # 1. Create scan
    response = await client.post("/api/scans", json=payload)
    assert response.status_code == 201
    data = response.json()
    assert "scan_id" in data
    assert data["status"] == "pending"
    scan_id = data["scan_id"]
    
    # Verify Celery pipeline was enqueued
    mock_celery_pipeline.assert_called_once()
    
    # 2. Verify scan in database directly
    db = get_db()
    scan_in_db = await db["scans"].find_one({"id": scan_id})
    assert scan_in_db is not None
    assert scan_in_db["scope"]["target"] == "scanme.nmap.org"
    
    # 3. Retrieve scan details via API
    response = await client.get(f"/api/scans/{scan_id}")
    assert response.status_code == 200
    scan_data = response.json()
    assert scan_data["id"] == scan_id
    assert scan_data["status"] == "pending"
    
    # 4. List all scans via API
    response = await client.get("/api/scans")
    assert response.status_code == 200
    list_data = response.json()
    assert len(list_data["scans"]) >= 1
    assert any(s["id"] == scan_id for s in list_data["scans"])
