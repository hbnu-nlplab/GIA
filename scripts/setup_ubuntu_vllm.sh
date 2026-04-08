#!/usr/bin/env bash
# ============================================================
# Ubuntu PC (A5000) vLLM 서버 셋업 스크립트
# ============================================================
# 목적: 병렬 LLM 평가를 위한 vLLM 서버 구성
# 실행: Ubuntu PC에서 실행
#   bash scripts/setup_ubuntu_vllm.sh
# ============================================================
set -euo pipefail

echo "================================================"
echo " Ubuntu vLLM Server Setup (A5000)"
echo "================================================"

# ── 1. Tailscale ──
echo "── [1/4] Tailscale ──"
if command -v tailscale &>/dev/null; then
    echo "[OK] Tailscale installed"
    if tailscale status &>/dev/null; then
        echo "  IP: $(tailscale ip -4)"
    else
        echo "[ACTION] Run: sudo tailscale up"
    fi
else
    echo "[INSTALL] Installing Tailscale..."
    curl -fsSL https://tailscale.com/install.sh | sh
    sudo tailscale up
fi

# ── 2. NVIDIA 드라이버 확인 ──
echo ""
echo "── [2/4] GPU & CUDA ──"
if command -v nvidia-smi &>/dev/null; then
    echo "[OK] NVIDIA driver detected"
    nvidia-smi --query-gpu=name,memory.total,driver_version --format=csv,noheader
else
    echo "[ERROR] nvidia-smi not found. NVIDIA driver 설치 필요"
    echo "  sudo apt install nvidia-driver-550"
    exit 1
fi

# ── 3. vLLM 설치 ──
echo ""
echo "── [3/4] vLLM ──"
if python3 -c "import vllm" 2>/dev/null; then
    echo "[OK] vLLM installed: $(python3 -c 'import vllm; print(vllm.__version__)')"
else
    echo "[INSTALL] Installing vLLM..."
    pip install vllm
    echo "[OK] vLLM installed"
fi

# ── 4. 모델 다운로드 안내 ──
echo ""
echo "── [4/4] Model Preparation ──"
echo ""
echo " AWQ 양자화 모델 (A5000 24GB에 최적화):"
echo "   MODEL_DICT from run_eval_vllm_offline.py:"
echo ""
echo "   gpt-oss:20b       → openai/gpt-oss-20b"
echo "   qwen3-coder:30b   → (AWQ 4bit variant)"
echo "   glm-4.7-flash     → (AWQ variant)"
echo "   Qwen3.5-9B        → cyankiwi/Qwen3.5-9B-AWQ-4bit"
echo ""
echo " 사전 다운로드 (선택):"
echo "   huggingface-cli download openai/gpt-oss-20b"
echo ""

# ── systemd 서비스 생성 (선택) ──
echo "================================================"
echo " vLLM 서버 실행 방법"
echo "================================================"
echo ""
echo " [방법 1] 직접 실행:"
echo "   vllm serve openai/gpt-oss-20b \\"
echo "     --host 0.0.0.0 --port 8000 \\"
echo "     --max-model-len 40960 \\"
echo "     --gpu-memory-utilization 0.90"
echo ""
echo " [방법 2] tmux 세션:"
echo "   tmux new -s vllm"
echo "   vllm serve openai/gpt-oss-20b --host 0.0.0.0 --port 8000"
echo "   # Ctrl+B, D to detach"
echo ""
echo " [방법 3] systemd 서비스:"

SYSTEMD_FILE="/etc/systemd/system/vllm.service"
if [ ! -f "$SYSTEMD_FILE" ]; then
    echo "   다음 파일을 생성하면 부팅 시 자동 시작:"
    echo ""
    cat << 'UNIT'
   # /etc/systemd/system/vllm.service
   [Unit]
   Description=vLLM Inference Server
   After=network.target

   [Service]
   Type=simple
   User=$USER
   Environment=CUDA_VISIBLE_DEVICES=0
   ExecStart=/usr/local/bin/vllm serve openai/gpt-oss-20b --host 0.0.0.0 --port 8000 --max-model-len 40960
   Restart=on-failure
   RestartSec=10

   [Install]
   WantedBy=multi-user.target
UNIT
    echo ""
    echo "   sudo systemctl daemon-reload && sudo systemctl enable --now vllm"
fi

echo ""
echo "================================================"
echo " 연결 테스트 (Windows WSL에서):"
echo "================================================"
echo ""
echo "  UBUNTU_IP=$(tailscale ip -4)"
echo ""
echo "  # API 상태 확인"
echo "  curl http://\${UBUNTU_IP}:8000/v1/models"
echo ""
echo "  # 평가 실행"
echo "  python run_eval_vllm_client.py --server \${UBUNTU_IP}:8000 --lab A B C D"
echo ""
