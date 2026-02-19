#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
HOST="${NETALLY_HOST:-127.0.0.1}"
BACKEND_PORT="${NETALLY_BACKEND_PORT:-8111}"
FRONTEND_PORT="${NETALLY_FRONTEND_PORT:-3000}"
RUN_PRECHECK="${NETALLY_RUN_PRECHECK:-true}"
LOG_DIR="${NETALLY_LOG_DIR:-${ROOT_DIR}/.tmp}"

# Demo mode defaults: allow explicit refresh/onboarding mutation tools unless caller disables it.
export NETALLY_MCP_ALLOW_MUTATIONS="${NETALLY_MCP_ALLOW_MUTATIONS:-true}"

mkdir -p "${LOG_DIR}"
BACKEND_LOG="${LOG_DIR}/netally-backend.log"
FRONTEND_LOG="${LOG_DIR}/netally-frontend.log"

echo "[demo-up] root: ${ROOT_DIR}"
echo "[demo-up] logs: ${LOG_DIR}"

cleanup() {
  if [[ -n "${FRONTEND_PID:-}" ]] && kill -0 "${FRONTEND_PID}" >/dev/null 2>&1; then
    kill "${FRONTEND_PID}" >/dev/null 2>&1 || true
  fi
  if [[ -n "${BACKEND_PID:-}" ]] && kill -0 "${BACKEND_PID}" >/dev/null 2>&1; then
    kill "${BACKEND_PID}" >/dev/null 2>&1 || true
  fi
}

trap cleanup EXIT INT TERM

echo "[demo-up] starting backend on ${HOST}:${BACKEND_PORT}"
(
  cd "${ROOT_DIR}"
  uv run uvicorn main:app --host "${HOST}" --port "${BACKEND_PORT}" >"${BACKEND_LOG}" 2>&1
) &
BACKEND_PID=$!

echo "[demo-up] starting frontend on ${HOST}:${FRONTEND_PORT}"
(
  cd "${ROOT_DIR}/frontend"
  npm run dev -- --host "${HOST}" --port "${FRONTEND_PORT}" >"${FRONTEND_LOG}" 2>&1
) &
FRONTEND_PID=$!

for _ in $(seq 1 90); do
  if curl -fsS "http://${HOST}:${BACKEND_PORT}/api/health" >/dev/null 2>&1 && curl -fsS "http://${HOST}:${FRONTEND_PORT}" >/dev/null 2>&1; then
    break
  fi
  sleep 1
done

if ! curl -fsS "http://${HOST}:${BACKEND_PORT}/api/health" >/dev/null 2>&1; then
  echo "[demo-up] backend startup failed. see ${BACKEND_LOG}"
  exit 1
fi
if ! curl -fsS "http://${HOST}:${FRONTEND_PORT}" >/dev/null 2>&1; then
  echo "[demo-up] frontend startup failed. see ${FRONTEND_LOG}"
  exit 1
fi

echo "[demo-up] backend:  http://${HOST}:${BACKEND_PORT}"
echo "[demo-up] frontend: http://${HOST}:${FRONTEND_PORT}"
echo "[demo-up] backend log:  ${BACKEND_LOG}"
echo "[demo-up] frontend log: ${FRONTEND_LOG}"

if [[ "${RUN_PRECHECK}" == "true" ]]; then
  echo "[demo-up] running precheck..."
  NETALLY_BASE_URL="http://${HOST}:${BACKEND_PORT}" "${ROOT_DIR}/scripts/demo_precheck.sh"
fi

echo "[demo-up] ready. press Ctrl+C to stop."
wait "${BACKEND_PID}" "${FRONTEND_PID}"
