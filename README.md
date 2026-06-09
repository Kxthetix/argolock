# 🔒 ArgoLock — AI-Powered VAPT Platform

[![Live Demo](https://img.shields.io/badge/Live%20Demo-argolock.vercel.app-6366f1?style=for-the-badge&logo=vercel)](https://argolock.vercel.app)
[![GitHub](https://img.shields.io/badge/GitHub-Kxthetix%2Fargolock-24292e?style=for-the-badge&logo=github)](https://github.com/Kxthetix/argolock)

ArgoLock is a fully automated **Vulnerability Assessment & Penetration Testing (VAPT)** platform powered by AI. It orchestrates industry-standard security tools, analyzes results with AI, and generates professional PDF/JSON security reports.

---

## 🚀 Live Demo

Visit **https://argolock.vercel.app** — all features work in demo mode with realistic sample data (no backend required).
Live Backend API Docs: **https://argolock.onrender.com/api/docs**

---

## ✨ Features

| Feature | Description |
|---------|-------------|
| 🔍 **Automated Scanning** | Nmap, Nuclei, Nikto, Subfinder, SQLmap orchestration |
| 🤖 **AI Analysis** | GPT-4 powered vulnerability analysis and remediation advice |
| 📊 **Real-time Dashboard** | Live scan progress, severity charts, active scan monitoring |
| 📋 **Findings Management** | CVSS scores, OWASP mapping, PoC details, CVE references |
| 📄 **Professional Reports** | Executive summaries, PDF/JSON export, risk scoring |
| 🔒 **Authorization Controls** | Built-in scope validation to prevent unauthorized scanning |

---

## 🏗️ Architecture

```
argolock/
├── frontend/          # React + TypeScript + Vite (deployed on Vercel)
│   ├── src/
│   │   ├── pages/     # Dashboard, Scans, Findings, Reports
│   │   ├── components/# Sidebar, ScanForm, FindingsTable, etc.
│   │   └── lib/       # API client (with demo mode), mock data
│   └── vercel.json    # Vercel deployment config
│
├── backend/           # FastAPI + Python
│   ├── app/           # API routers, models, services
│   ├── agents/        # AI agents (recon, scanner, remediation, report)
│   ├── workers/       # Celery task workers
│   ├── tools/         # Tool wrappers (nmap, nuclei, etc.)
│   └── requirements.txt
│
└── docker-compose.yml # Full stack: MongoDB, Redis, Backend, Workers, ZAP
```

---

## 🖥️ Running Locally (Full Stack)

### Prerequisites
- Python 3.11+
- Node.js 18+
- MongoDB (running on localhost:27017)
- Redis (running on localhost:6379)

### 1. Backend

```powershell
cd backend

# Create virtual environment
python -m venv venv
venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Copy and configure environment
copy .env.example .env
# Edit .env: set OPENAI_API_KEY, adjust MongoDB/Redis URLs if needed

# Start the backend API
uvicorn app.main:app --reload --port 8000
```

### 2. Celery Workers (new terminals)

```powershell
# Terminal 2 - Recon worker
cd backend; venv\Scripts\activate
celery -A workers.celery_app worker -Q recon -n recon@%h --loglevel=info -P solo

# Terminal 3 - Scanner worker  
cd backend; venv\Scripts\activate
celery -A workers.celery_app worker -Q scanner -n scanner@%h --loglevel=info -P solo

# Terminal 4 - AI worker
cd backend; venv\Scripts\activate
celery -A workers.celery_app worker -Q ai -n ai@%h --loglevel=info -P solo
```

### 3. Frontend

```powershell
cd frontend
npm install
npm run dev
# Opens at http://localhost:5173
```

The frontend auto-proxies `/api` requests to `http://localhost:8000`.

---

## 🐳 Running with Docker Compose

```bash
# Copy environment config
cp .env.example .env
# Edit .env with your API keys

# Start everything
docker-compose up -d

# View logs
docker-compose logs -f backend
```

Services:
- Frontend: http://localhost:3000
- Backend API: http://localhost:8000
- API Docs: http://localhost:8000/api/docs
- Flower (Celery monitor): http://localhost:5555

---

## ☁️ Deploying to Vercel (Frontend Only)

The frontend works **without a backend** in demo mode with realistic sample data.

1. Fork this repository
2. Connect to Vercel → Import the `argolock` repository
3. Set **Root Directory** to `frontend`
4. Click **Deploy** — done!

To connect a real backend, set the `VITE_API_URL` environment variable in Vercel:
```
VITE_API_URL=https://your-backend.railway.app/api
```

---

## 🔧 Environment Variables

### Backend (`.env`)
```env
# AI Provider
OPENAI_API_KEY=sk-your-key-here
AI_PROVIDER=openai

# Database
MONGODB_URL=mongodb://localhost:27017
MONGODB_DB=argolock

# Redis
REDIS_URL=redis://localhost:6379/0

# Security
SECRET_KEY=your-secret-key-here
CORS_ORIGINS=["http://localhost:5173","https://argolock.vercel.app"]
```

### Frontend (`.env.local`)
```env
# Leave empty for demo mode, or set to your backend URL:
VITE_API_URL=http://localhost:8000/api
```

---

## 🛠️ Tech Stack

**Frontend**: React 19, TypeScript, Vite, React Router, Recharts, Lucide Icons

**Backend**: FastAPI, Pydantic, Motor (async MongoDB), Celery

**AI**: OpenAI GPT-4o / Claude 3.5 / Ollama (configurable)

**Security Tools**: Nmap, Nuclei, Nikto, Subfinder, SQLmap, OWASP ZAP

**Infrastructure**: MongoDB, Redis, Docker, Vercel

---

## 📸 Screenshots

Visit the **[Live Demo](https://argolock.vercel.app)** to see all features in action.

---

*Built with ❤️ by ArgoLock — AI-Powered Security*
