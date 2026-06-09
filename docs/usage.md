# ArgoLock Usage Guide

## Running Your First Scan

### Step 1: Open the Dashboard
Navigate to http://localhost:3000

### Step 2: Create a New Scan
1. Click **"New Scan"** (top right or sidebar)
2. Enter your target:
   - Domain: `scanme.nmap.org`
   - IP: `192.168.1.1`
   - CIDR: `192.168.1.0/24`
3. Check **"I confirm I have authorization"**
4. Optionally add authorization note (e.g., bug bounty program name)
5. Click **"Launch VAPT Scan"**

### Step 3: Monitor Progress
You'll be redirected to the scan detail page showing:
- **Pipeline**: Queued → Recon → Scanning → AI Analysis → Report
- **Live Logs**: Real-time tool output via WebSocket
- **Tool Status**: Each tool's execution state

### Step 4: Review Findings
Once scanning completes, switch to the **Findings** tab to see:
- All vulnerabilities sorted by CVSS score
- Click any row to expand: PoC, root cause, remediation steps

### Step 5: Download Report
- Click **"Download PDF"** for the professional security report
- Or **"JSON"** for raw machine-readable data

---

## Pipeline Phases

| Phase | Duration | Tools |
|-------|----------|-------|
| Reconnaissance | 2-10 min | Nmap, Subfinder, WhatWeb |
| Vulnerability Scanning | 5-30 min | Nuclei, Nikto, OWASP ZAP |
| Exploitation (if enabled) | 5-15 min | SQLmap (safe mode) |
| AI Analysis | 1-5 min | GPT-4o / Claude / Ollama |
| Report Generation | <1 min | WeasyPrint PDF |

---

## AI Agent Pipeline

### Agent 1: Vulnerability Analyzer
- Receives raw findings from all tools
- Deduplicates overlapping results
- Maps each finding to OWASP Top 10 2021
- Normalizes severity levels

### Agent 2: Risk Scoring
- Calculates CVSS 3.1 base scores
- Rule-based presets + AI refinement
- Prioritizes findings by exploitability

### Agent 3: Root Cause & Remediation
- Explains WHY each vulnerability exists
- Provides step-by-step fix instructions
- Generates secure code examples

### Agent 4: Report Generator
- Writes executive summary
- Calculates overall risk score (0-100)
- Produces HackerOne-format PDF report

---

## API Reference

Base URL: `http://localhost:8000/api`

Interactive docs: http://localhost:8000/api/docs

### Create Scan
```http
POST /api/scans
Content-Type: application/json

{
  "scope": {
    "target": "scanme.nmap.org",
    "authorized": true,
    "authorization_note": "Nmap test server"
  },
  "config": {
    "safe_mode": true,
    "enable_exploitation": false,
    "nuclei_severity": ["critical", "high", "medium"]
  },
  "name": "My First Scan"
}
```

### Get Scan
```http
GET /api/scans/{scan_id}
```

### Get Findings
```http
GET /api/scans/{scan_id}/findings?severity=critical
```

### WebSocket (Live Logs)
```
ws://localhost:8000/ws/scans/{scan_id}
```

Message types:
- `log` → `{ type, level, message, tool }`
- `progress` → `{ type, phase, percent, status }`
- `finding` → `{ type, finding }`
- `tool_status` → `{ type, tool, status }`

---

## Report Format

Each finding in the report includes:
```json
{
  "title": "SQL Injection in Login Form",
  "severity": "critical",
  "cvss_score": 9.8,
  "owasp_category": "A03:2021 Injection",
  "affected_endpoint": "http://example.com/login",
  "affected_parameter": "username",
  "tool_source": "sqlmap",
  "poc": {
    "payload": "' OR 1=1--",
    "reproduction_steps": ["..."]
  },
  "remediation": {
    "root_cause": "User input is concatenated directly into SQL queries",
    "fix_steps": ["Use parameterized queries", "..."],
    "secure_code_example": "cursor.execute('SELECT * FROM users WHERE id = ?', (user_id,))"
  }
}
```

---

## Safety Features

- ✅ Scope validation before every scan
- ✅ Authorization confirmation required
- ✅ Blocked cloud metadata endpoints (169.254.169.254)
- ✅ SQLmap safe mode: level=1, risk=1, no data extraction
- ✅ Max 5 endpoints per SQLmap run
- ✅ Exploitation disabled by default
- ✅ Tool timeouts (5 min default)
- ✅ Docker sandboxing for all tools
