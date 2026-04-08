#!/usr/bin/env bash
# ============================================================
# 전체 인프라 연결 테스트 스크립트
# ============================================================
# WSL에서 실행하여 PNETLab VM, Ubuntu PC, 로컬 서비스 연결 확인
#   bash scripts/test_connectivity.sh
# ============================================================
set -uo pipefail

# .env에서 IP 읽기
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
ENV_FILE="${PROJECT_ROOT}/NetAlly/.env"

if [ ! -f "$ENV_FILE" ]; then
    echo "[ERROR] NetAlly/.env not found. Run setup_wsl_dev.sh first."
    exit 1
fi

# 간단한 env 파싱 (variable substitution 미지원, 직접 값 사용)
get_env() { grep "^$1=" "$ENV_FILE" 2>/dev/null | head -1 | cut -d= -f2- | tr -d '"' ; }

PNETLAB_IP=$(get_env PNETLAB_SSH_HOST)
PNETLAB_IP=${PNETLAB_IP:-$(get_env PNETLAB_TAILSCALE_IP)}
UBUNTU_IP=$(get_env UBUNTU_TAILSCALE_IP)

echo "================================================"
echo " Infrastructure Connectivity Test"
echo "================================================"
echo " PNETLab IP: ${PNETLAB_IP:-NOT_SET}"
echo " Ubuntu IP:  ${UBUNTU_IP:-NOT_SET}"
echo "================================================"
echo ""

PASS=0
FAIL=0
SKIP=0

check() {
    local name="$1"
    local cmd="$2"
    local timeout="${3:-5}"

    printf "  %-35s" "$name"
    if eval "timeout ${timeout} ${cmd}" &>/dev/null; then
        echo "[OK]"
        ((PASS++))
    else
        echo "[FAIL]"
        ((FAIL++))
    fi
}

skip() {
    local name="$1"
    local reason="$2"
    printf "  %-35s[SKIP] %s\n" "$name" "$reason"
    ((SKIP++))
}

# ── 1. 로컬 서비스 ──
echo "── Local Services (WSL) ──"
check "Docker daemon" "docker info"
check "Batfish HTTP (:9997)" "curl -sf http://localhost:9997/"
check "Batfish gRPC (:9996)" "bash -c 'echo | nc -w2 localhost 9996'"

if command -v vllm &>/dev/null || curl -sf http://localhost:8000/v1/models &>/dev/null; then
    check "vLLM Server (:8000)" "curl -sf http://localhost:8000/v1/models"
else
    skip "vLLM Server (:8000)" "not running"
fi

# ── 2. PNETLab VM ──
echo ""
echo "── PNETLab VM (${PNETLAB_IP:-NOT_SET}) ──"
if [ -n "${PNETLAB_IP}" ] && [ "${PNETLAB_IP}" != "CHANGE_ME_PNETLAB_IP" ]; then
    check "Tailscale ping" "tailscale ping --timeout=3s ${PNETLAB_IP}"
    check "SSH connection" "ssh -o ConnectTimeout=3 -o BatchMode=yes root@${PNETLAB_IP} echo ok"
    check "PNETLab Web (:80)" "curl -sf http://${PNETLAB_IP}/"
    check "NSO RESTCONF (:8080)" "curl -sf -u admin:admin http://${PNETLAB_IP}:8080/restconf"

    # LabFS .unl 파일 접근 테스트
    LAB_NAME=$(get_env PNETLAB_LAB_NAME)
    LAB_NAME=${LAB_NAME:-Research_Institute_Internal_DC}
    check "LabFS .unl access" \
        "ssh -o ConnectTimeout=3 -o BatchMode=yes root@${PNETLAB_IP} 'find /opt/unetlab/labs -name \"*.unl\" | head -1'"
else
    skip "PNETLab VM tests" "IP not configured"
fi

# ── 3. Ubuntu PC ──
echo ""
echo "── Ubuntu PC (${UBUNTU_IP:-NOT_SET}) ──"
if [ -n "${UBUNTU_IP}" ] && [ "${UBUNTU_IP}" != "CHANGE_ME_UBUNTU_IP" ]; then
    check "Tailscale ping" "tailscale ping --timeout=3s ${UBUNTU_IP}"
    check "SSH connection" "ssh -o ConnectTimeout=3 -o BatchMode=yes ${UBUNTU_IP} echo ok"
    check "vLLM Server (:8000)" "curl -sf http://${UBUNTU_IP}:8000/v1/models"
else
    skip "Ubuntu PC tests" "IP not configured"
fi

# ── 결과 ──
echo ""
echo "================================================"
echo " Results: ${PASS} passed, ${FAIL} failed, ${SKIP} skipped"
echo "================================================"

if [ $FAIL -gt 0 ]; then
    echo ""
    echo " [FAIL] 실패 항목 확인 후 해당 서비스를 시작하세요."
    exit 1
else
    echo ""
    echo " [ALL OK] 모든 연결 정상!"
fi
