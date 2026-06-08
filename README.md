# vaultX — AI-Powered VAPT Platform

> **Production-ready Vulnerability Assessment & Penetration Testing platform powered by 4 AI agents**

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/Python-3.12-blue)](backend/)
[![React](https://img.shields.io/badge/React-18-61dafb)](frontend/)
[![Docker](https://img.shields.io/badge/Docker-Compose-2496ed)](docker-compose.yml)

---

## 🚀 What is vaultX?

VaultX is a fully automated security testing platform that performs real vulnerability assessments:

```
Target → Recon → Scanning → Exploitation → AI Analysis → Report
```

**No simulated data. No fake results. Everything is real.**

---

## ⚡ Quick Start

```bash
# 1. Configure
cp .env.example .env
# Add your OPENAI_API_KEY to .env

# 2. Launch
docker-compose up --build -d

# 3. Open
# Dashboard:     http://localhost:3000
# API Docs:      http://localhost:8000/api/docs
# Task Monitor:  http://localhost:5555
```

---

## 🏗️ Architecture

| Layer | Technology |
|-------|-----------|
| Backend API | Python + FastAPI |
| Job Queue | Celery + Redis |
| Database | MongoDB |
| AI Agents | OpenAI GPT-4o / Claude / Ollama |
| Frontend | Vite + React + TypeScript |
| Tool Execution | Docker containers |
| Real-time | WebSocket |

---

## 🔧 Real Tool Integrations

| Tool | Purpose | Execution |
|------|---------|-----------|
| Nmap | Port scan + service detection | Docker |
| Subfinder | Subdomain enumeration | Docker |
| WhatWeb | Technology fingerprinting | Subprocess |
| Nuclei | Template-based vuln scanning | Docker |
| Nikto | Web server analysis | Docker |
| OWASP ZAP | Active web application scanning | Docker sidecar |
| SQLmap | SQL injection (safe mode) | Docker |

---

## 🤖 AI Agents

| Agent | Function |
|-------|---------|
| **Agent 1: Vulnerability Analyzer** | Deduplicates raw findings, maps to OWASP Top 10 2021 |
| **Agent 2: Risk Scoring** | Calculates CVSS 3.1 scores with AI refinement |
| **Agent 3: Root Cause & Fix** | Root cause analysis + step-by-step remediation + secure code |
| **Agent 4: Report Generator** | Executive summary + HackerOne-format PDF report |

---

## 📊 Output Per Finding

```json
{
  "title": "SQL Injection in Login Form",
  "severity": "critical",
  "cvss_score": 9.8,
  "owasp_category": "A03:2021 Injection",
  "affected_endpoint": "https://example.com/login",
  "poc": { "payload": "' OR 1=1--" },
  "remediation": {
    "root_cause": "User input concatenated in SQL",
    "fix_steps": ["Use prepared statements", "..."],
    "secure_code_example": "..."
  }
}
```

---

## 🛡️ Safety Features

- ✅ Scope validation before every scan
- ✅ Authorization confirmation required
- ✅ Blocked cloud metadata endpoints
- ✅ SQLmap safe mode (level=1, risk=1)
- ✅ Exploitation disabled by default
- ✅ Docker sandboxing for all tools
- ✅ Tool execution timeouts

---

## 📁 Project Structure

```
vaultx/
├── backend/                 # FastAPI + Celery
│   ├── app/                 # API routes, models, config
│   ├── agents/              # 4 AI agents
│   ├── tools/               # Tool integrations
│   ├── workers/             # Celery task workers
│   ├── ai_providers/        # OpenAI/Claude/Ollama
│   └── reports/             # PDF generation
├── frontend/                # Vite + React + TypeScript
│   └── src/
│       ├── components/      # UI components
│       ├── pages/           # Dashboard, Scans, Findings, Reports
│       └── lib/             # API client, WebSocket
├── docker-compose.yml       # Full stack orchestration
├── docs/                    # Setup + usage guides
└── .env.example             # Configuration template
```

---

## 📚 Documentation

- [Setup Guide](docs/setup.md)
- [Usage Guide](docs/usage.md)
- [API Reference](http://localhost:8000/api/docs) (when running)

---

## ⚠️ Legal Disclaimer

This tool is for **authorized security testing only**. Only scan systems you own or have explicit written permission to test. Unauthorized scanning is illegal. The authors are not responsible for misuse.

---

## 🧪 Safe Test Targets

- `scanme.nmap.org` — Nmap's official authorized test host
- `testphp.vulnweb.com` — Acunetix intentionally vulnerable test site
- Your own local/private infrastructure

---

*Built with ❤️ by vaultX — AI-Powered Security*
