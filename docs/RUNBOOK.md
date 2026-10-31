# 📘 ARGOLOCK NET — Production Operations Runbook

**System**: ARGOLOCK NET Platform  
**Target Environment**: Production / Staging  
**Version**: 1.7  
**Audience**: Security Operations Engineers, Site Reliability Engineers, DevOps  

---

## 1. System Overview & Architecture

ARGOLOCK NET is a distributed Vulnerability Assessment and Penetration Testing (VAPT) platform consisting of:
1. **API Gateway**: FastAPI service handling authentication, multi-tenant RBAC, REST endpoints, and WebSocket telemetry streaming.
2. **Database Layer**: MongoDB 7.0 for persistent storage of tenants, scans, findings, evidence artifacts, and audit trails.
3. **Message Broker**: Redis 7.0 providing task queuing for Celery workers and pub/sub message broadcasting.
4. **Celery Worker Queues**:
   - `recon,default`: DNS, OSINT, subfinder, nmap, and naabu network discovery.
   - `scanner`: Nuclei, Nikto, and OWASP ZAP active web scanners.
   - `ai,exploit`: Shannon entropy secret auditing, deterministic validation engine, and Devil's Advocate adversarial evaluation.
5. **Pipeline Watchdog**: Background process monitoring worker heartbeats, detecting stalls, and marking expired tasks.

---

## 2. Environment Configuration & Secrets

ARGOLOCK reads its configuration from environment variables or a secure `.env` file. **Never commit `.env` to source control.**

### Key Production Variables:
```env
ENVIRONMENT=production
SECRET_KEY=<32-byte-cryptographically-random-secret>
MONGODB_URL=mongodb://mongodb:27017
MONGODB_DB=argolock_prod
REDIS_URL=redis://redis:6379/0
CELERY_BROKER_URL=redis://redis:6379/0
CELERY_RESULT_BACKEND=redis://redis:6379/1

# AI LLM Provider Configuration
AI_PROVIDER=openai
OPENAI_API_KEY=sk-...
OPENAI_MODEL=gpt-4o

# Tool Execution & Safety
TOOL_EXECUTION_MODE=subprocess
SAFE_MODE=true
RATE_LIMIT_PER_MINUTE=10
```

---

## 3. Service Lifecycle Management

### 3.1 Docker Compose Deployment
```bash
# Navigate to deployment directory
cd deploy

# Pull or build production container images
docker compose -f docker-compose.prod.yml build

# Start all services in the background
docker compose -f docker-compose.prod.yml up -d

# Verify all containers are healthy
docker compose -f docker-compose.prod.yml ps

# View live aggregate logs
docker compose -f docker-compose.prod.yml logs -f --tail=100
```

### 3.2 Systemd Bare-Metal / VM Deployment
```bash
# Reload systemd manager configuration
sudo systemctl daemon-reload

# Start core datastores
sudo systemctl start mongod redis

# Start ARGOLOCK services
sudo systemctl start argolock-api
sudo systemctl start argolock-worker-recon
sudo systemctl start argolock-worker-scanner
sudo systemctl start argolock-worker-exploit
sudo systemctl start argolock-watchdog

# Enable services to launch on system boot
sudo systemctl enable argolock-api argolock-worker-recon argolock-worker-scanner argolock-worker-exploit argolock-watchdog

# Check status of all units
sudo systemctl status "argolock-*"
```

### 3.3 Process Supervisor (`supervisord`)
```bash
# Start supervisor daemon
supervisord -c deploy/supervisord.conf

# Check process status
supervisorctl -c deploy/supervisord.conf status

# Restart a specific worker queue
supervisorctl -c deploy/supervisord.conf restart argolock-worker-scanner
```

---

## 4. Database Operations: Migrations, Backup & Restore

### 4.1 Running Tenant Isolation Migrations
To backfill existing legacy records with `tenant_id`:
```powershell
# From backend directory
python -c "import asyncio; from app.services.migration_backup_service import migration_backup_service; asyncio.run(migration_backup_service.migrate_tenant_isolation())"
```

### 4.2 Creating an Atomic Point-in-Time Backup
Before deploying updates or running migrations, generate a tamper-evident backup snapshot:
```powershell
python -c "import asyncio; from app.services.migration_backup_service import migration_backup_service; res = asyncio.run(migration_backup_service.create_backup(description='Pre-update backup')); print(res)"
```
Backups are saved to `backups/<backup_id>.json` along with their SHA-256 integrity checksum.

### 4.3 Restoring from Backup or Rolling Back
If a deployment fails or data corruption occurs:
```powershell
# Restore by backup ID
python -c "import asyncio; from app.services.migration_backup_service import migration_backup_service; res = asyncio.run(migration_backup_service.rollback('<backup_id>')); print(res)"
```
The restore service automatically verifies the SHA-256 hash before applying the restore.

---

## 5. Observability & Alert Triage

### 5.1 Querying Real-Time Observability Metrics
Inspect cluster health via the API:
```bash
curl -H "Authorization: Bearer <TOKEN>" http://localhost:8000/api/v1/observability/metrics
```

### 5.2 Alert Triage Procedure
1. **Critical: Cross-Tenant Access Violation**:
   - *Symptom*: User attempted to access resources with a mismatched `tenant_id`.
   - *Action*: Inspect actor email and IP in `alerts` collection. If anomalous, revoke the user's active JWT token and temporarily suspend the account.
2. **High: Emergency Kill Switch Triggered**:
   - *Symptom*: Kill switch activated by operator.
   - *Action*: All active missions are halted. Query `/api/v1/security-control-plane/status` to review terminated missions.
3. **Medium: Worker Heartbeat Stall**:
   - *Symptom*: Celery worker failed to heartbeat for >120s.
   - *Action*: Inspect worker process memory. If crashed, the watchdog automatically marks the scan stage failed and prevents indefinite queue hanging. Restart worker:
     ```bash
     sudo systemctl restart argolock-worker-scanner
     ```

---

## 6. Emergency Kill Switch Operations

### Activating the Global Kill Switch:
```bash
curl -X POST http://localhost:8000/api/v1/security-control-plane/kill-switch \
  -H "Authorization: Bearer <ADMIN_TOKEN>" \
  -H "Content-Type: application/json" \
  -d '{"activate": true}'
```

### Deactivating the Global Kill Switch:
```bash
curl -X POST http://localhost:8000/api/v1/security-control-plane/kill-switch \
  -H "Authorization: Bearer <ADMIN_TOKEN>" \
  -H "Content-Type: application/json" \
  -d '{"activate": false}'
```
