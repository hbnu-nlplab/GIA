# NetAlly Setup Guide (Updated)

This document is the concise setup reference.  
For beginner-friendly Korean docs, start at `docs/README_ko.md`.

---

## 1. Prerequisites

- Python 3.10+
- `uv`
- Node.js 18+
- `npm`
- Optional: Docker (for Batfish container checks)

---

## 2. Environment Variables

Create `.env` in `NetAlly/`:

```bash
cp .env.example .env
```

Minimum fields to verify:
- `OPENAI_API_KEY`
- `BATFISH_HOST`
- `NSO_BASE_URL`
- `NETALLY_TOOL_BACKEND` (`mcp` recommended)

For PNETLab VM Docker-node deployments:
- `PNETLAB_INVENTORY_BACKEND=labfs_local`
- Mount `/opt/unetlab:/opt/unetlab:ro`

---

## 3. Local Run (Recommended for development)

### 3.1 One-command startup

```bash
cd NetAlly
./scripts/demo_up_local.sh
```

This starts:
- Backend: `127.0.0.1:8111`
- Frontend: `127.0.0.1:3000`
- Built-in precheck (`/api/health`, `/api/settings`, `/api/lab/prepare`)

### 3.2 Manual startup

Backend:
```bash
cd NetAlly
uv sync --extra dev
uv run uvicorn main:app --host 127.0.0.1 --port 8111
```

Frontend:
```bash
cd NetAlly/frontend
npm ci
npm run dev -- --host 127.0.0.1 --port 3000
```

---

## 4. Test Execution

Backend regression:
```bash
cd NetAlly
uv run pytest -q tests
```

Frontend smoke E2E:
```bash
cd NetAlly/frontend
npx playwright install --with-deps
npm run test:e2e
```

---

## 5. PNETLab Deployment Path

If you run NetAlly as a PNETLab Docker Node, use:
- `docs/pnetlab_deployment_guide.md`
- `docs/pnetlab_wiring_runbook_ko.md`

These contain:
- Docker node settings
- `docker_options` examples
- NetAlly/NSO/Chromebook wiring
- Batfish host connectivity checks

---

## 6. Quick Health Checks

```bash
curl -fsS http://127.0.0.1:8111/api/health
curl -fsS http://127.0.0.1:8111/api/settings
curl -fsS -X POST http://127.0.0.1:8111/api/lab/prepare -H 'Content-Type: application/json' -d '{"auto_init_batfish": false}'
```

