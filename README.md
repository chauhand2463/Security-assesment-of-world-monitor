# CyberAgent

**Autonomous AI Security Copilot**

CyberAgent is a security assessment platform that orchestrates reconnaissance and
scanning utilities (Nmap, Nuclei, httpx, subfinder, assetfinder, dnsx, gau, WhatWeb)
behind a multi-agent planner workflow, with a React dashboard and live SSE log
streaming.

## Architecture & Tech Stack

### Frontend (`frontend/`)
- React 19, Vite, TypeScript
- Tailwind CSS, Framer Motion
- React Flow (`@xyflow/react`), Recharts, Monaco Editor
- Backend base URL is configured via `VITE_API_URL` (see `frontend/.env.example`).

### Backend (`backend/`)
- FastAPI, SQLAlchemy 2, Pydantic v2
- Alembic migrations (`backend/alembic/`)
- Background scans via thread-pool executor (Celery only if optionally installed)
- SSE streaming for live scan logs

## Setup

### Prerequisites
- Python 3.14+
- Node.js 18+ and npm

### Backend

```bash
cd backend
python -m venv venv
venv\Scripts\activate                # Windows
# venv/bin/activate                  # macOS/Linux
pip install -r requirements.txt -r requirements-dev.txt
cp .env.example .env                # adjust values if needed
alembic upgrade head                # create/migrate the database schema
python -m uvicorn app.main:app --host 127.0.0.1 --port 8003 --reload
```

The backend API docs are available at `http://127.0.0.1:8001/docs`.

> Port convention: in this development environment host ports `8000` and `8001`
> are occupied by unrelated services (an external service and Docker Desktop), so
> run the CyberAgent backend on a free port such as `127.0.0.1:8003` and point the
> frontend at it via `VITE_API_URL=http://127.0.0.1:8003` (see `frontend/.env.example`).
> Always use `127.0.0.1`, not `localhost`, because `localhost` resolves to IPv6
> `::1` here.

### Frontend

```bash
cd frontend
cp .env.example .env                # adjust VITE_API_URL if needed
npm install
npm run dev
```

Open `http://localhost:5173`.

### Testing

```bash
cd backend
python -m pytest -v
```

Tests run against a throwaway SQLite database created under the system temp
directory and never touch `backend/cyberagent.db`.

## Implementation Status

### Implemented (Phase 2 scope)
- Real authentication: `POST /auth/register`, `POST /auth/login`, `POST /auth/logout`,
  `GET /auth/me`. Passwords hashed with stdlib PBKDF2 (no extra deps); sessions are opaque
  32-byte tokens, only SHA-256 digests stored, TTL via `SESSION_TTL_HOURS`.
- Ownership + RBAC: every scan/report/asset/chat record resolves through the signed-in
  user's project; foreign resources return 404. Roles `user`/`admin`
  (`GET /auth/users`, `GET /auth/admin/overview`).
- Scope enforcement: `GET/POST /scans/scope` declares targets (domain/IP/CIDR); triggers
  outside scope are rejected with 403; discovered assets extend the effective scope.
- Scanner-adapter foundation: per-tool adapters with honest states (Not Installed /
  Timeout / Execution Failed / Parse Failed), `shutil.which` availability checks,
  injection-safe list-based argument execution, honest Nuclei JSON parsing.
- Frontend auth flow: real login/register, token storage, `Authorization` headers,
  SSE/download token transport, 401 automatic logout, real user in the sidebar,
  honest Settings copy.
- Phase 1 items: config-driven settings, Alembic-managed schema, `verify_schema()`,
  simulation markers, pinned manifests, isolated pytest suite (81 tests), centralized
  `src/api.ts`.

### Planned (NOT yet implemented — later phases)
- Live scanner executions on this host (tools currently report NOT INSTALLED when
  `SIMULATION_MODE=false`; install binaries to PATH to enable real runs).
- Real PDF generation (current PDF endpoint serves stored report bytes labeled simulated).
- LLM/RAG-based AI analysis, Celery/Redis queueing, and containerization.
- CI pipeline.

## Security & Guardrails

- **Simulation mode is OFF by default** (real execution). The simulation path is an
  explicit, operator-chosen mode for sandboxed environments only; its output is
  always marked `[SIMULATION]`/`[SIMULATED]` and must never be treated as a real
  security assessment. Missing binaries are reported as NOT INSTALLED and never
  faked.
- **Real authentication.** No demo account is auto-created. Registrations are
  open (`/auth/register`) by design for this deployment; password hashing uses
  PBKDF2-SHA256 (600k iterations) and session tokens are stored as SHA-256 digests
  only.
- **Scope enforcement.** Scan triggers outside the declared scope are rejected with
  403; request logging and CORS use explicit origins with `allow_credentials=True`.
- Command execution is parameterized (list-based subprocess arguments, `shell=False`)
  with sanitization, so real tool invocations remain injection-safe.