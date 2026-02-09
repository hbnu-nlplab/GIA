#!/usr/bin/env bash
set -euo pipefail

BASE_URL="${NETALLY_BASE_URL:-http://127.0.0.1:8111}"

echo "[1/4] Health check: ${BASE_URL}/api/health"
health_json="$(curl -fsS "${BASE_URL}/api/health")"
echo "${health_json}"

echo "[2/4] Settings check: ${BASE_URL}/api/settings"
settings_json="$(curl -fsS "${BASE_URL}/api/settings")"
echo "${settings_json}"

echo "[3/4] Read-only tool ping: /api/lab/prepare"
prepare_json="$(curl -fsS -X POST "${BASE_URL}/api/lab/prepare" -H 'Content-Type: application/json' -d '{"auto_init_batfish": false}')"
echo "${prepare_json}"

echo "[4/4] Contract summary"
python3 - <<'PY' "${health_json}" "${settings_json}" "${prepare_json}"
import json
import sys

health = json.loads(sys.argv[1])
settings = json.loads(sys.argv[2])
prepare = json.loads(sys.argv[3])

tool_backend = health.get("tool_backend")
mcp_health = health.get("mcp_health", {})
mcp_ok = mcp_health.get("ok")
mcp_tool_count = mcp_health.get("tool_count")

settings_backend = settings.get("tool_backend")
settings_mutations = settings.get("mcp_allow_mutations")
settings_url = settings.get("mcp_server_url")
prepare_status = prepare.get("status")

print(f"tool_backend(health): {tool_backend}")
print(f"mcp_health.ok: {mcp_ok}")
print(f"mcp_health.tool_count: {mcp_tool_count}")
print(f"tool_backend(settings): {settings_backend}")
print(f"mcp_allow_mutations(settings): {settings_mutations}")
print(f"mcp_server_url(settings): {settings_url}")
print(f"lab_prepare.status: {prepare_status}")

if tool_backend not in {"mcp", "legacy"}:
    raise SystemExit("FAIL: invalid tool_backend in /api/health")
if settings_backend not in {"mcp", "legacy"}:
    raise SystemExit("FAIL: invalid tool_backend in /api/settings")
if not isinstance(settings_mutations, bool):
    raise SystemExit("FAIL: mcp_allow_mutations must be boolean")
if not isinstance(settings_url, str):
    raise SystemExit("FAIL: mcp_server_url must be string")

print("PASS: demo precheck completed")
PY
