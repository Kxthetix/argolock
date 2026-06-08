# VaultX Setup Guide

## Prerequisites

| Tool | Required | Purpose |
|------|----------|---------|
| Docker Desktop | ✅ Required | Tool sandboxing, containerized services |
| Docker Compose | ✅ Required | Service orchestration |
| Node.js 20+ | Optional | Frontend dev only |
| Python 3.12+ | Optional | Backend dev only |

---

## Quick Start (Docker)

### 1. Clone / Copy the project
```
vaultx/
├── backend/
├── frontend/
├── docker-compose.yml
└── .env.example
```

### 2. Configure environment
```bash
cp .env.example .env
```

Open `.env` and set your OpenAI API key:
```
OPENAI_API_KEY=sk-your-key-here
```

### 3. Start all services
```bash
docker-compose up --build -d
```

This starts:
- **Frontend**: http://localhost:3000
- **Backend API**: http://localhost:8000/api/docs
- **Celery Flower** (task monitor): http://localhost:5555
- **MongoDB**: port 27017
- **Redis**: port 6379
- **OWASP ZAP**: port 8080

### 4. Wait for services to be ready (~2 min on first run)
```bash
docker-compose logs -f backend
```

Look for: `🚀 VaultX backend starting up...`

### 5. Open dashboard
Navigate to **http://localhost:3000**

---

## Configuration

### AI Providers

**OpenAI (default)**:
```env
AI_PROVIDER=openai
OPENAI_API_KEY=sk-...
OPENAI_MODEL=gpt-4o
```

**Anthropic Claude**:
```env
AI_PROVIDER=claude
ANTHROPIC_API_KEY=sk-ant-...
ANTHROPIC_MODEL=claude-3-5-sonnet-20241022
```

**Ollama (local, free)**:
```env
AI_PROVIDER=ollama
OLLAMA_BASE_URL=http://ollama:11434
OLLAMA_MODEL=llama3
```

Add `ollama` service to docker-compose.yml:
```yaml
ollama:
  image: ollama/ollama:latest
  volumes:
    - ollama_data:/root/.ollama
```

### Tool Execution Mode

**Docker (recommended)**:
```env
TOOL_EXECUTION_MODE=docker
```
Requires Docker socket mount in docker-compose.yml (already configured).

**Subprocess (advanced)**:
```env
TOOL_EXECUTION_MODE=subprocess
```
Requires Nmap, Nuclei, Nikto, Subfinder installed on host.

---

## Development Mode (without Docker)

### Backend
```bash
cd backend
python -m venv venv
source venv/bin/activate   # Windows: venv\Scripts\activate
pip install -r requirements.txt

# Start Redis and MongoDB first (or use Docker for infra only)
docker run -d -p 6379:6379 redis:7-alpine
docker run -d -p 27017:27017 mongo:7

# Run backend
uvicorn app.main:app --reload --port 8000

# Run Celery worker (separate terminal)
celery -A workers.celery_app worker --loglevel=info
```

### Frontend
```bash
cd frontend
npm install
npm run dev
# → http://localhost:5173
```

---

## Safe Test Target

Use the Nmap authorized test server for initial testing:
```
Target: scanme.nmap.org
Authorization: ✅ Check "I confirm I have authorization"
Authorization Note: Nmap's official test server
```

---

## Viewing Logs

```bash
# All services
docker-compose logs -f

# Specific service
docker-compose logs -f celery-recon
docker-compose logs -f backend

# Task queue dashboard
open http://localhost:5555
```

---

## Stopping

```bash
docker-compose down
# With volume cleanup:
docker-compose down -v
```

---

## Troubleshooting

### ZAP not connecting
ZAP takes ~60 seconds to start. Scans will skip ZAP if it's not available and continue with other tools.

### Docker socket permission
On Linux, add your user to the docker group:
```bash
sudo usermod -aG docker $USER
```

### Nuclei/Nmap not finding issues
Ensure the Docker images are pulled:
```bash
docker pull instrumentisto/nmap:latest
docker pull projectdiscovery/nuclei:latest
```
