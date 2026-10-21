# Intent-Aware Zero-Trust Authorization Broker for AI Agents

A runnable educational prototype demonstrating a broker between an AI-agent action proposal and mock tools.

## What is implemented
- FastAPI backend and interactive API docs
- Trusted session intent and allowed action scopes
- Deterministic action proposal parser for the demo (no LLM key required)
- Independent policy decision engine: ALLOW / REVIEW / DENY
- Parameter validation for selected mock actions
- SQLite sessions, capability-token hashes, action audit trail, review decisions
- Scoped, expiring opaque capability tokens
- Duplicate request-ID detection for idempotency/replay-style testing
- Mock Calendar, Wallet, Email, and Files tools
- Browser dashboard at `/`
- Automated tests

## Important limitations
This is a local prototype, not a production security product. The demo parser is rule-based rather than an LLM. It does not connect to real email, calendars, wallets, or files. Do not use real sensitive data. A production deployment would need threat modeling, hardened identity/authentication, HTTPS, secrets management, robust policy semantics, rate limits, monitoring, and independent security review.

## Requirements
- Python 3.11 or 3.12 recommended
- Windows PowerShell, macOS, or Linux

## Windows setup
```powershell
cd intent-aware-broker
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements.txt
python -m uvicorn app.main:app --reload
```
If PowerShell blocks activation, run commands using `.venv\Scripts\python.exe` directly:
```powershell
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe -m uvicorn app.main:app --reload
```

Open:
- Dashboard: http://127.0.0.1:8000
- API docs: http://127.0.0.1:8000/docs
- Health: http://127.0.0.1:8000/health

## Run tests
Open another terminal in the project folder:
```powershell
python -m pytest -q
```

## Suggested demo
1. Open dashboard and create a session with intent: `Schedule meetings and draft emails for me. Never send files or transfer money.`
2. Click **Create demo session**.
3. Run `ALLOW`: `Schedule a meeting with Rahul tomorrow at 10 AM`.
4. Run `REVIEW`: `Send an email to Rahul saying the meeting is confirmed`.
5. Run `DENY`: `Send the confidential file to an external recipient`.
6. Inspect the audit trail.
7. Explain that the broker—not the agent—makes the final decision.

## Architecture
Client UI -> action proposal parser -> authorization broker -> policy decision -> mock tool execution.
SQLite stores sessions, token metadata, review state, and audit records.

## Team work split
- Member 1: broker policies, intent and parameter validation
- Member 2: SQLite, capability tokens, audit history
- Member 3: action parser and mock tools
- Member 4: dashboard, test scenarios, integration/testing
