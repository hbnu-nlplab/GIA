#!/usr/bin/env bash
# ============================================================
# PNETLab VM 셋업 스크립트
# ============================================================
# 목적: PNETLab VM에 Tailscale 설치 + NSO Docker 포트 노출
# 실행: PNETLab VM 내부에서 root로 실행
#   ssh root@<pnetlab-ip> 'bash -s' < scripts/setup_pnetlab_vm.sh
# ============================================================
set -euo pipefail

echo "================================================"
echo " PNETLab VM Setup — Tailscale + NSO Docker"
echo "================================================"

# ── 1. Tailscale 설치 ──
if command -v tailscale &>/dev/null; then
    echo "[OK] Tailscale already installed"
    tailscale version
else
    echo "[INSTALL] Installing Tailscale..."
    curl -fsSL https://tailscale.com/install.sh | sh
    echo "[OK] Tailscale installed"
fi

# Tailscale 활성화 (이미 연결된 경우 skip)
if tailscale status &>/dev/null; then
    echo "[OK] Tailscale already connected"
    echo "  IP: $(tailscale ip -4)"
else
    echo "[ACTION] Tailscale 로그인이 필요합니다:"
    echo "  sudo tailscale up"
    echo "  → 출력되는 URL을 브라우저에서 열어 인증하세요"
    sudo tailscale up
fi

TAILSCALE_IP=$(tailscale ip -4)
echo ""
echo "==> PNETLab Tailscale IP: ${TAILSCALE_IP}"
echo "    이 IP를 Windows WSL의 .env에 설정하세요:"
echo "    PNETLAB_TAILSCALE_IP=${TAILSCALE_IP}"
echo ""

# ── 2. SSH 키 인증 설정 ──
echo "[CHECK] SSH key authentication..."
AUTHORIZED_KEYS="/root/.ssh/authorized_keys"
if [ -f "$AUTHORIZED_KEYS" ] && [ -s "$AUTHORIZED_KEYS" ]; then
    echo "[OK] SSH authorized_keys exists ($(wc -l < "$AUTHORIZED_KEYS") keys)"
else
    echo "[WARN] No SSH keys found. Add your WSL public key:"
    echo "  From WSL: ssh-copy-id root@${TAILSCALE_IP}"
fi

# ── 3. NSO Docker 설정 ──
echo ""
echo "[CHECK] NSO Docker container..."
if docker ps --format '{{.Names}}' | grep -q cisco-nso-dev; then
    echo "[OK] cisco-nso-dev is running"

    # 포트 바인딩 확인
    NSO_PORT=$(docker port cisco-nso-dev 8080 2>/dev/null || echo "NOT_BOUND")
    if [ "$NSO_PORT" = "NOT_BOUND" ]; then
        echo "[WARN] NSO :8080 is NOT exposed to host!"
        echo "  NSO 컨테이너를 재시작해야 합니다:"
        echo ""
        echo "  docker stop cisco-nso-dev"
        echo "  docker rm cisco-nso-dev"
        echo "  docker run -d --name cisco-nso-dev \\"
        echo "    -p 8080:8080 \\"
        echo "    -p 830:830 \\"
        echo "    --restart unless-stopped \\"
        echo "    cisco-nso-dev"
        echo ""
    else
        echo "[OK] NSO RESTCONF exposed: ${NSO_PORT}"
    fi
else
    echo "[INFO] cisco-nso-dev not running."
    echo "  NSO Docker가 필요하면 다음 명령으로 실행:"
    echo ""
    echo "  docker run -d --name cisco-nso-dev \\"
    echo "    -p 8080:8080 \\"
    echo "    -p 830:830 \\"
    echo "    --restart unless-stopped \\"
    echo "    cisco-nso-dev"
fi

# ── 4. Batfish Docker 설정 (선택) ──
echo ""
echo "[CHECK] Batfish Docker container..."
if docker ps --format '{{.Names}}' | grep -q batfish; then
    echo "[OK] Batfish is running"
    echo "  Ports: $(docker port batfish 2>/dev/null)"
else
    echo "[INFO] Batfish not running on PNETLab VM (WSL에서 로컬 실행 권장)"
fi

# ── 5. 방화벽 확인 ──
echo ""
echo "[CHECK] Firewall (ufw)..."
if command -v ufw &>/dev/null && ufw status | grep -q "active"; then
    echo "[WARN] UFW is active. 필요한 포트를 확인하세요:"
    echo "  ufw allow 22/tcp    # SSH"
    echo "  ufw allow 80/tcp    # PNETLab Web"
    echo "  ufw allow 8080/tcp  # NSO RESTCONF"
    echo "  ufw allow 9996:9997/tcp  # Batfish (if needed)"
    echo "  ufw allow 30000:30100/tcp  # Device Telnet Console"
else
    echo "[OK] UFW not active (Tailscale handles ACL)"
fi

# ── 6. 연결 테스트 안내 ──
echo ""
echo "================================================"
echo " Setup Complete!"
echo "================================================"
echo ""
echo " PNETLab Tailscale IP: ${TAILSCALE_IP}"
echo ""
echo " Windows WSL에서 연결 테스트:"
echo "   # SSH"
echo "   ssh root@${TAILSCALE_IP} hostname"
echo ""
echo "   # PNETLab Web"
echo "   curl -s http://${TAILSCALE_IP}/api/status"
echo ""
echo "   # NSO RESTCONF"
echo "   curl -s -u admin:admin http://${TAILSCALE_IP}:8080/restconf/data/tailf-ncs:devices"
echo ""
echo "   # 장비 텔넷 (포트는 .unl 또는 wrapper.txt에서 확인)"
echo "   telnet ${TAILSCALE_IP} 30001"
echo ""
