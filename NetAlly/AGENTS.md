# Repository Guidelines

## Project Structure & Module Organization
- `main.py`: FastAPI entrypoint and API routes.
- `agent/`: runtime orchestration, MCP wrappers, and NSO/Batfish/PNETLab clients.
- `frontend/`: React + Vite UI (`src/`) and Playwright E2E tests (`e2e/`).
- `tests/`: backend regression and API contract tests.
- `scripts/`: local startup and precheck utilities.
- `docs/`: architecture and runbooks; treat as the operational source of truth.
- `results/`: generated outputs and experiment artifacts (do not hand-edit unless required).

## Build, Test, and Development Commands
Run from `NetAlly/` unless noted:
- `uv sync --extra dev`: install backend dependencies.
- `uv run uvicorn main:app --host 127.0.0.1 --port 8111`: run backend locally.
- `./scripts/demo_up_local.sh`: one-command local demo startup.
- `./scripts/demo_precheck.sh`: preflight checks before demos.

Run from `NetAlly/frontend/`:
- `npm ci`: install frontend dependencies.
- `npm run dev -- --host 127.0.0.1 --port 3000`: run frontend locally.
- `npm run build`: TypeScript check + production build.

## Coding Style & Naming Conventions
- Python: 4-space indentation, prefer type hints, `snake_case` for modules/functions, `PascalCase` for classes.
- TypeScript/React: `PascalCase` component files (for example, `ChatPanel.tsx`), `camelCase` for variables/functions.
- Keep runtime/tool-backend behavior explicit; avoid hidden side effects in configuration paths.
- Naming patterns: backend tests `test_*.py`, frontend E2E tests `*.spec.ts`.

## Testing Guidelines
- Backend regression: `uv run pytest -q tests`.
- Frontend E2E: `npx playwright install --with-deps` (first time), then `npm run test:e2e`.
- Add or update tests for every behavior change, especially chat SSE flow (`planning -> tool_call -> tool_output -> answer`) and runtime switching.

## Commit & Pull Request Guidelines
- Follow Conventional Commit style used in history: `feat(netally): ...`, `fix(netally): ...`, `docs(netally): ...`, `refactor(settings): ...`.
- Keep commits small and scoped to one logical change.
- PRs should include: purpose, impacted paths, test evidence (pytest/Playwright), and screenshots or SSE traces for UI/stream changes.
- Never commit secrets; document new variables in `.env.example`.


