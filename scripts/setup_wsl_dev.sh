#!/usr/bin/env bash
# ============================================================
# Windows WSL 개발 환경 셋업 스크립트
# ============================================================
# 목적: NetAlly 개발 + Batfish + vLLM + 평가 환경 구성
# 실행: WSL 내부에서 실행
#   bash scripts/setup_wsl_dev.sh
# ============================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

echo "================================================"
echo " WSL Development Environment Setup"
echo "================================================"
echo " Project: ${PROJECT_ROOT}"
echo ""

# ── 1. Tailscale 설치 (WSL) ──
echo "── [1/6] Tailscale ──"
if command -v tailscale &>/dev/null; then
    echo "[OK] Tailscale installed: $(tailscale version 2>/dev/null | head -1)"
else
    echo "[INSTALL] Installing Tailscale for WSL..."
    curl -fsSL https://tailscale.com/install.sh | sh
    echo "[ACTION] Run: sudo tailscale up"
fi

# ── 2. Docker 확인 ──
echo ""
echo "── [2/6] Docker ──"
if command -v docker &>/dev/null; then
    echo "[OK] Docker available: $(docker --version)"
else
    echo "[WARN] Docker not found. Docker Desktop (Windows) + WSL integration 필요"
    echo "  Settings > Resources > WSL Integration > Enable"
fi

# ── 3. Batfish Docker ──
echo ""
echo "── [3/6] Batfish Container ──"
if docker ps --format '{{.Names}}' 2>/dev/null | grep -q batfish; then
    echo "[OK] Batfish already running"
else
    echo "[START] Starting Batfish..."
    docker run -d \
        --name batfish \
        -p 9997:9997 \
        -p 9996:9996 \
        --restart unless-stopped \
        batfish/batfish
    echo "[OK] Batfish started on :9997 (HTTP) / :9996 (gRPC)"
fi

# ── 4. Python / uv 환경 ──
echo ""
echo "── [4/6] Python & uv ──"
if command -v uv &>/dev/null; then
    echo "[OK] uv installed: $(uv --version)"
else
    echo "[INSTALL] Installing uv..."
    curl -LsSf https://astral.sh/uv/install.sh | sh
    echo "[OK] uv installed"
fi

# NetAlly 의존성
echo "[SYNC] NetAlly dependencies..."
cd "${PROJECT_ROOT}/NetAlly"
if [ -f "pyproject.toml" ]; then
    uv sync --extra dev 2>&1 | tail -3
    echo "[OK] NetAlly Python dependencies synced"
fi

# Frontend 의존성
echo "[SYNC] Frontend dependencies..."
cd "${PROJECT_ROOT}/NetAlly/frontend"
if [ -f "package.json" ]; then
    npm ci --silent 2>&1 | tail -3
    echo "[OK] Frontend dependencies installed"
fi
cd "${PROJECT_ROOT}"

# ── 5. vLLM (WSL + RTX 3090) ──
echo ""
echo "── [5/6] vLLM ──"
if python3 -c "import vllm" 2>/dev/null; then
    echo "[OK] vLLM installed"
else
    echo "[INFO] vLLM not installed. Install with:"
    echo "  pip install vllm"
    echo ""
    echo "  CUDA 확인:"
    echo "  nvidia-smi"
    echo ""
    echo "  vLLM 서버 실행 예시:"
    echo "  vllm serve openai/gpt-oss-20b --host 0.0.0.0 --port 8000"
fi

# ── 6. .env 파일 생성 ──
echo ""
echo "── [6/6] Environment Configuration ──"
ENV_FILE="${PROJECT_ROOT}/NetAlly/.env"
ENV_TEMPLATE="${PROJECT_ROOT}/NetAlly/.env.tailscale"

if [ -f "$ENV_FILE" ]; then
    echo "[SKIP] .env already exists (backup: .env.bak)"
    cp "$ENV_FILE" "${ENV_FILE}.bak"
else
    if [ -f "$ENV_TEMPLATE" ]; then
        cp "$ENV_TEMPLATE" "$ENV_FILE"
        echo "[OK] .env created from .env.tailscale template"
        echo "[ACTION] Edit .env and replace CHANGE_ME values with actual Tailscale IPs"
    else
        echo "[WARN] .env.tailscale template not found"
    fi
fi

# ── 연결 테스트 ──
echo ""
echo "================================================"
echo " Setup Complete! Next Steps:"
echo "================================================"
echo ""
echo " 1. Edit Tailscale IPs in NetAlly/.env:"
echo "    nano ${PROJECT_ROOT}/NetAlly/.env"
echo ""
echo " 2. Test connectivity to PNETLab VM:"
echo "    PNETLAB_IP=\$(grep PNETLAB_TAILSCALE_IP ${ENV_FILE} | cut -d= -f2)"
echo "    ssh root@\$PNETLAB_IP hostname"
echo "    curl -s http://\$PNETLAB_IP/api/status"
echo ""
echo " 3. Start NetAlly:"
echo "    cd ${PROJECT_ROOT}/NetAlly"
echo "    ./scripts/demo_up_local.sh"
echo ""
echo " 4. Start vLLM (for evaluation):"
echo "    vllm serve openai/gpt-oss-20b --host 0.0.0.0 --port 8000"
echo ""
echo " 5. Run evaluation:"
echo "    cd ${PROJECT_ROOT}/Experiment/code/NetConfigQA2_2"
echo "    python run_eval_vllm_client.py --server localhost:8000 --lab A"
echo ""
