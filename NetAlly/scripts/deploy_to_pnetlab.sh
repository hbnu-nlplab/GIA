#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
NETALLY_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
REPO_ROOT="$(cd "${NETALLY_DIR}/.." && pwd)"

PNETLAB_VM_IP="${PNETLAB_VM_IP:-192.168.50.60}"
PNETLAB_VM_USER="${PNETLAB_VM_USER:-root}"
PNETLAB_VM_DEST_DIR="${PNETLAB_VM_DEST_DIR:-/root}"
PNETLAB_SSH_OPTIONS="${PNETLAB_SSH_OPTIONS:-}"

NETALLY_IMAGE_NAME="${NETALLY_IMAGE_NAME:-netally:latest}"
NETALLY_IMAGE_TAR="${NETALLY_IMAGE_TAR:-${NETALLY_DIR}/.tmp/netally.tar}"
NETALLY_SKIP_BUILD="${NETALLY_SKIP_BUILD:-false}"
NETALLY_SKIP_LOAD="${NETALLY_SKIP_LOAD:-false}"

mkdir -p "$(dirname "${NETALLY_IMAGE_TAR}")"

read -r -a SSH_OPTS <<<"${PNETLAB_SSH_OPTIONS}"

echo "[deploy] repo root: ${REPO_ROOT}"
echo "[deploy] image: ${NETALLY_IMAGE_NAME}"
echo "[deploy] vm: ${PNETLAB_VM_USER}@${PNETLAB_VM_IP}"
echo "[deploy] tar: ${NETALLY_IMAGE_TAR}"

if [[ "${NETALLY_SKIP_BUILD}" != "true" ]]; then
  echo "[deploy] building image..."
  docker build -f "${NETALLY_DIR}/Dockerfile" -t "${NETALLY_IMAGE_NAME}" "${REPO_ROOT}"
else
  echo "[deploy] skip build (NETALLY_SKIP_BUILD=true)"
fi

echo "[deploy] saving image tar..."
docker save -o "${NETALLY_IMAGE_TAR}" "${NETALLY_IMAGE_NAME}"

REMOTE_TAR="${PNETLAB_VM_DEST_DIR%/}/$(basename "${NETALLY_IMAGE_TAR}")"

echo "[deploy] uploading tar -> ${REMOTE_TAR}"
scp "${SSH_OPTS[@]}" "${NETALLY_IMAGE_TAR}" "${PNETLAB_VM_USER}@${PNETLAB_VM_IP}:${REMOTE_TAR}"

if [[ "${NETALLY_SKIP_LOAD}" != "true" ]]; then
  echo "[deploy] loading image on remote host..."
  ssh "${SSH_OPTS[@]}" "${PNETLAB_VM_USER}@${PNETLAB_VM_IP}" "docker load -i '${REMOTE_TAR}'"
else
  echo "[deploy] skip remote docker load (NETALLY_SKIP_LOAD=true)"
fi

cat <<EOF
[deploy] done.
next:
  1) PNETLab UI에서 NetAlly 노드 Stop/Start
  2) 헬스 확인: curl -fsS http://<netally-host>:8000/api/health
EOF
