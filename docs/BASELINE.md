# 📊 ARGOLOCK Baseline Verification Report (Phase 0)

**Date**: 2026-10-30  
**Repository**: `github.com/Kxthetix/argolock`  
**Engineer**: Principal Engineer  

---

## 1. Executive Summary

| Verification Target | Engine | Status | Passed | Failed | Skipped | Total / Duration |
|:---|:---|:---:|:---:|:---:|:---:|:---|
| **Backend Test Suite** | pytest 8.2.2 (Python 3.13.14) | **PASS** | 106 | 0 | 0 | 106 in 443.88s |
| **Frontend Test Suite** | vitest 4.1.8 (JSDOM) | **PASS** | 11 | 0 | 0 | 11 in 6.40s |
| **Frontend Linter** | ESLint 10.3.0 | **PASS** | - | 0 | - | Clean (0 errors, 0 warnings) |
| **Frontend Typecheck** | TypeScript 6.0.2 (`tsc -b`) | **FAIL** | - | 5 errors | - | Known type check failures |

---

## 2. Backend Pytest Results

### Exact Counts
- **Total Tests Collected**: 106
- **Passed**: 106
- **Failed**: 0
- **Skipped**: 0
- **Warnings**: 12 (all deprecation warnings in external libraries)
- **Duration**: 443.88s (0:07:23)

### Suite Breakdown
1. `tests/test_auth.py` — **9 passed**
   - User registration, Argon2 hashing, JWT access token issuing, login OTP verification, user profile fetch.
2. `tests/test_exploit_agent.py` — **5 passed**
   - Exploit validation rules, payload bounds, safe-mode execution gate.
3. `tests/test_exploitation.py` — **7 passed**
   - Shannon secrets audit entropy calculation ($H \ge 4.5$), regex credential scanning (AWS, GitHub, Slack, Private Keys), DNS spoof audit.
4. `tests/test_new_tools.py` — **28 passed**
   - Real target testing and schema validation for Amass, httpx-probe, Naabu, and Dalfox (with built-in native Python fallbacks).
5. `tests/test_pipeline_e2e.py` — **2 passed**
   - Sequential Celery pipeline execution (`run_recon` → `run_scanner` → `run_exploit` → `run_ai_analysis`) and Celery chain eager routing against MongoDB.
6. `tests/test_scans.py` — **3 passed**
   - Scan initialization, scope validation, authorization rejection for unauthorized targets.
7. `tests/test_tools.py` — **33 passed**
   - Tool wrappers: Subfinder, Nmap, WhatWeb, Nuclei, Nikto, SQLmap.
8. `tests/test_v1_7_platform.py` — **11 passed**
   - Security Control Plane (Scope Gate whitelist/blacklist, Action Classification, Kill Switch), 60-Agent logical registry, Adversarial Validation engine, Capability Graph, Cyber Risk quantification, Investment Optimizer.
9. `tests/test_vapt_engine.py` — **8 passed**
   - Target authorization windows, exploit safety gate thresholds, evidence collection schemas, false-positive validation, remediation re-test scheduling.

### Warnings Details
- `jose/jwt.py:311`: `DeprecationWarning: datetime.datetime.utcnow() is deprecated and scheduled for removal in a future version. Use timezone-aware objects to represent datetimes in UTC: datetime.datetime.now(datetime.UTC)`.

---

## 3. Frontend Vitest Results

### Exact Counts
- **Total Test Files**: 3
- **Passed Files**: 3
- **Total Tests**: 11
- **Passed**: 11
- **Failed**: 0
- **Skipped**: 0
- **Duration**: 6.40s

### File Breakdown
1. `src/test/api_resilience.test.ts` — **5 passed**
   - `api.findings.list` parameter sanitization (omits `severity=undefined`).
   - `api.system.agents` client defaults fallback on 401 or offline backend.
   - `api.system.tools` client defaults fallback on 401 or offline backend.
   - `api.scans.create` error propagation.
   - `api.reports.get` fallback behavior.
2. `src/components/SeverityBadge.test.tsx` — **3 passed**
   - Renders critical, high, medium, low, and info badges with correct styling.
3. `src/components/ScanForm.test.tsx` — **3 passed**
   - Form inputs, validation state, and launch handler triggers.

---

## 4. Known Issues & Pre-Existing Failures (Not Yet Fixed)

### Failing Component: Frontend Typecheck (`tsc -b`)
- **Command**: `npm run typecheck`
- **Exit Code**: 1
- **Error Count**: 5 errors in 1 file

#### Failing Test Name / File
- `src/test/api_resilience.test.ts`

#### Errors Log
```
src/test/api_resilience.test.ts(12,5): error TS2304: Cannot find name 'global'.
src/test/api_resilience.test.ts(29,5): error TS2304: Cannot find name 'global'.
src/test/api_resilience.test.ts(44,5): error TS2304: Cannot find name 'global'.
src/test/api_resilience.test.ts(59,5): error TS2304: Cannot find name 'global'.
src/test/api_resilience.test.ts(84,5): error TS2304: Cannot find name 'global'.
```

#### Likely Cause & Analysis
In `tsconfig.app.json`, the TypeScript environment targets browser DOM libraries (`"lib": ["ES2020", "DOM", "DOM.Iterable"]`). The Node.js symbol `global` is not defined in browser standard types. While Vitest runs in Node and satisfies `global.fetch` at runtime, `tsc` fails type checking.

#### Planned Remediation (for subsequent phase)
Replace direct `global.fetch = vi.fn(...)` assignments with either `globalThis.fetch = vi.fn(...)` or `vi.stubGlobal('fetch', ...)`, which are both standards-compliant and supported under DOM types.

---

## 5. Cleanups Executed in Phase 0

1. **Stale Scratch Files Removed**:
   - `backend/scratch_debug_e2e.py`
   - `backend/scratch_search_all.py`
   - `backend/scratch_search_tests.py`
   - `backend/scratch_test_login_flow.py`
   - `backend/scratch_test_login_flow_argon2.py`
2. **README Alignment**:
   - Updated repository directory map to include `prompts/`, `reports/`, `ai_providers/`, `tests/`.
   - Updated Celery terminal commands to explicitly document the `exploit` queue worker alongside `recon`, `scanner`, and `ai` queues.
