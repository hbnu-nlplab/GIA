#!/bin/bash

set -euo pipefail

NSO_VERSION="${NSO_VERSION:-6.6}"
NSO_HOME="${NSO_HOME:-/root/nso-${NSO_VERSION}}"
NCS_RUN_DIR="${NCS_RUN_DIR:-/root/ncs-instance}"
EXTRA_NEDS_DIR="${EXTRA_NEDS_DIR:-/opt/nso-extra-neds}"

export LD_LIBRARY_PATH="${LD_LIBRARY_PATH:-}"
export PYTHONPATH="${PYTHONPATH:-}"
export MANPATH="${MANPATH:-}"

source "${NSO_HOME}/ncsrc"

mkdir -p "${NCS_RUN_DIR}"

if [ ! -f "${NCS_RUN_DIR}/ncs.conf" ]; then
    setup_args=()

    if [ -d "${EXTRA_NEDS_DIR}" ]; then
        while IFS= read -r ned_dir; do
            setup_args+=(--package "${ned_dir}")
        done < <(find "${EXTRA_NEDS_DIR}" -maxdepth 1 -mindepth 1 -type d ! -name tarballs | while read -r d; do
            if [ -f "${d}/package-meta-data.xml" ]; then
                echo "${d}"
            fi
        done | sort)
    fi

    echo "Initializing NSO runtime in ${NCS_RUN_DIR}"
    ncs-setup "${setup_args[@]}" --dest "${NCS_RUN_DIR}"
fi

# --- PATCH 1: Generate RSA host key if missing ---
SSH_KEY_DIR="${NSO_HOME}/etc/ncs/ssh"
if [ -d "$SSH_KEY_DIR" ] && [ ! -f "${SSH_KEY_DIR}/ssh_host_rsa_key" ]; then
    echo "[PATCH] Generating RSA host key"
    ssh-keygen -t rsa -b 2048 -f "${SSH_KEY_DIR}/ssh_host_rsa_key" -N "" -q
fi

# --- PATCH 2: Enable ssh-rsa for legacy IOS devices (IOSv 15.x) ---
CONF="${NCS_RUN_DIR}/ncs.conf"
if [ -f "$CONF" ] && ! grep -q 'ssh-rsa' "$CONF"; then
    echo "[PATCH] Adding ssh-rsa to ncs.conf algorithms"
    sed -i 's|<algorithms>|<algorithms>\n      <server-host-key>ssh-rsa</server-host-key>|' "$CONF"
fi

cd "${NCS_RUN_DIR}"
exec ncs --foreground --verbose
