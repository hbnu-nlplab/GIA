"""
Sync PNETLab icon files referenced by a UNL into the NetAlly repo.

Why:
  - Fastest rendering: frontend can load icons from /pnetlab-icons/<name>
  - No runtime dependency on PNETLab filesystem or proxy, when icons exist locally

Supports:
  - labfs_local: copy from PNETLAB_ICON_ROOT
  - labfs_ssh: stream tarball from PNETLab host over SSH (key-based recommended)

Usage (from NetAlly/):
  uv run python scripts/pnetlab_sync_icons.py

Important env:
  PNETLAB_INVENTORY_BACKEND=labfs_local|labfs_ssh
  PNETLAB_LAB_PATH or PNETLAB_LAB_NAME
  PNETLAB_UNETLAB_ROOT (default /opt/unetlab)
  PNETLAB_ICON_ROOT (default /opt/unetlab/html/images/icons)

SSH env (when labfs_ssh):
  PNETLAB_SSH_HOST, PNETLAB_SSH_USER, PNETLAB_SSH_PORT, PNETLAB_SSH_KEY_PATH
  PNETLAB_SSH_OPTIONS (optional, passed to ssh as-is; e.g. "-o StrictHostKeyChecking=accept-new")

Optional output override:
  PNETLAB_ICON_OUT_DIR (default: NetAlly/frontend/public/pnetlab-icons)
"""

from __future__ import annotations

import os
import subprocess
import sys
import shlex
from pathlib import Path
from typing import Iterable, List, Set
import xml.etree.ElementTree as ET


def sh_quote(value: str) -> str:
    return "'" + value.replace("'", "'\"'\"'") + "'"


def _frontend_icon_dir() -> Path:
    override = os.getenv("PNETLAB_ICON_OUT_DIR", "").strip() or os.getenv("NETALLY_PNETLAB_ICON_OUT_DIR", "").strip()
    if override:
        return Path(override).expanduser().resolve()
    here = Path(__file__).resolve()
    # NetAlly/scripts -> NetAlly
    netally_root = here.parent.parent
    return netally_root / "frontend" / "public" / "pnetlab-icons"


def _unetlab_root() -> str:
    return os.getenv("PNETLAB_UNETLAB_ROOT", "/opt/unetlab").strip() or "/opt/unetlab"


def _resolve_unl_path_ssh(ssh: List[str], target: str) -> str:
    # Prefer PNETLAB_LAB_PATH, then name, then newest .unl
    direct = os.getenv("PNETLAB_LAB_PATH", "").strip()
    root = _unetlab_root()
    if direct:
        p = direct if direct.startswith("/") else str(Path(root) / direct)
        return p

    name = os.getenv("PNETLAB_LAB_NAME", "").strip()
    labs_root = str(Path(root) / "labs")
    if name:
        out = subprocess.check_output(
            [*ssh, target, "--", "find", labs_root, "-type", "f", "-name", name + ".unl"],
            text=True,
        )
        paths = [line.strip() for line in out.splitlines() if line.strip()]
        if paths:
            # pick most recent using ls -t on explicit args (avoid empty-substitution pitfalls)
            ls_out = subprocess.check_output(
                [*ssh, target, "--", "ls", "-t", "--", *paths],
                text=True,
            )
            first = next((line.strip() for line in ls_out.splitlines() if line.strip()), "")
            if first:
                return first

    out = subprocess.check_output(
        [*ssh, target, "--", "find", labs_root, "-type", "f", "-name", "*.unl"],
        text=True,
    )
    paths = [line.strip() for line in out.splitlines() if line.strip()]
    if not paths:
        raise RuntimeError("No .unl found on remote host")
    ls_out = subprocess.check_output(
        [*ssh, target, "--", "ls", "-t", "--", *paths],
        text=True,
    )
    first = next((line.strip() for line in ls_out.splitlines() if line.strip()), "")
    if not first:
        raise RuntimeError("No .unl found on remote host")
    return first


def _read_unl_xml_local() -> str:
    root = Path(_unetlab_root())
    direct = os.getenv("PNETLAB_LAB_PATH", "").strip()
    if direct:
        p = Path(direct)
        if not p.is_absolute():
            p = root / p
        return p.read_text(encoding="utf-8", errors="ignore")

    name = os.getenv("PNETLAB_LAB_NAME", "").strip()
    candidates: List[Path] = []
    if name:
        candidates = list((root / "labs").rglob(f"{name}.unl"))
    else:
        candidates = list((root / "labs").rglob("*.unl"))
    if not candidates:
        raise RuntimeError("No .unl found locally")
    candidates.sort(key=lambda x: x.stat().st_mtime, reverse=True)
    return candidates[0].read_text(encoding="utf-8", errors="ignore")


def _extract_icon_names(unl_xml: str) -> Set[str]:
    root = ET.fromstring(unl_xml)
    out: Set[str] = set()
    topo = root.find("topology")
    if topo is None:
        return out

    nodes_el = topo.find("nodes")
    if nodes_el is not None:
        for node in nodes_el.findall("node"):
            icon = (node.get("icon") or "").strip()
            if icon:
                out.add(icon)

    nets_el = topo.find("networks")
    if nets_el is not None:
        for net in nets_el.findall("network"):
            icon = (net.get("icon") or "").strip()
            if icon:
                out.add(icon)

    return out


def _chunked(items: List[str], size: int) -> Iterable[List[str]]:
    for i in range(0, len(items), size):
        yield items[i : i + size]


def _sync_local(icon_root: Path, names: List[str], out_dir: Path) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    missing = []
    for name in names:
        src = icon_root / name
        if not src.exists():
            # case-insensitive fallback
            lower = name.lower()
            match = next((p for p in icon_root.iterdir() if p.is_file() and p.name.lower() == lower), None)
            if match is None:
                missing.append(name)
                continue
            src = match
        (out_dir / name).write_bytes(src.read_bytes())
    if missing:
        print(f"[warn] missing {len(missing)} icons in {icon_root}: {missing[:10]}{'...' if len(missing) > 10 else ''}")


def _sync_ssh(names: List[str], out_dir: Path) -> None:
    host = os.getenv("PNETLAB_SSH_HOST", "").strip()
    user = os.getenv("PNETLAB_SSH_USER", "root").strip() or "root"
    port = os.getenv("PNETLAB_SSH_PORT", "22").strip() or "22"
    key = os.getenv("PNETLAB_SSH_KEY_PATH", "").strip()
    if not host:
        raise RuntimeError("PNETLAB_SSH_HOST required for labfs_ssh")

    target = f"{user}@{host}"
    ssh = [
        "ssh",
        "-p",
        port,
        "-o",
        "BatchMode=yes",
    ]
    if key:
        ssh += ["-i", key]
    extra_opts = os.getenv("PNETLAB_SSH_OPTIONS", "").strip()
    if extra_opts:
        ssh += shlex.split(extra_opts)

    icon_root = os.getenv("PNETLAB_ICON_ROOT", "/opt/unetlab/html/images/icons").strip() or "/opt/unetlab/html/images/icons"
    out_dir.mkdir(parents=True, exist_ok=True)

    # Validate UNL exists remotely early (better error message)
    unl_path = _resolve_unl_path_ssh(ssh, target)
    if unl_path:
        pass

    # Stream tar in chunks to avoid huge command lines.
    for chunk in _chunked(names, 80):
        proc = subprocess.Popen(
            [*ssh, target, "--", "tar", "cz", "-C", icon_root, "--", *chunk],
            stdout=subprocess.PIPE,
        )
        if proc.stdout is None:
            raise RuntimeError("failed to open ssh stdout")
        tar = subprocess.run(["tar", "xz", "-C", str(out_dir)], stdin=proc.stdout)
        proc.wait()
        if proc.returncode != 0 or tar.returncode != 0:
            raise RuntimeError("icon sync via ssh failed")


def main() -> int:
    backend = os.getenv("PNETLAB_INVENTORY_BACKEND", "").lower().strip()
    if not backend:
        # auto mode: prefer local if unetlab exists, otherwise ssh if host set.
        root = Path(_unetlab_root())
        if (root / "labs").exists():
            backend = "labfs_local"
        elif os.getenv("PNETLAB_SSH_HOST", "").strip():
            backend = "labfs_ssh"
        else:
            backend = "labfs_local"
    out_dir = _frontend_icon_dir()

    if backend == "labfs_ssh":
        host = os.getenv("PNETLAB_SSH_HOST", "").strip()
        user = os.getenv("PNETLAB_SSH_USER", "root").strip() or "root"
        port = os.getenv("PNETLAB_SSH_PORT", "22").strip() or "22"
        key = os.getenv("PNETLAB_SSH_KEY_PATH", "").strip()
        if not host:
            raise RuntimeError("labfs_ssh requires PNETLAB_SSH_HOST")
        target = f"{user}@{host}"
        ssh = [
            "ssh",
            "-p",
            port,
            "-o",
            "BatchMode=yes",
        ]
        if key:
            ssh += ["-i", key]
        extra_opts = os.getenv("PNETLAB_SSH_OPTIONS", "").strip()
        if extra_opts:
            ssh += shlex.split(extra_opts)
        unl_path = _resolve_unl_path_ssh(ssh, target)
        unl_xml = subprocess.check_output([*ssh, target, "--", "cat", "--", unl_path], text=True)
    else:
        root = Path(_unetlab_root())
        if not (root / "labs").exists() and not os.getenv("PNETLAB_LAB_PATH", "").strip():
            raise RuntimeError(
                "Local UNetLab root not found. If you're running on your PC, use labfs_ssh "
                "(set PNETLAB_SSH_HOST/PNETLAB_SSH_KEY_PATH) or run this inside the PNETLab VM "
                "so /opt/unetlab/labs is available."
            )
        unl_xml = _read_unl_xml_local()

    names = sorted(_extract_icon_names(unl_xml))
    if not names:
        print("[info] no icons referenced in UNL")
        return 0

    print(f"[info] icons referenced: {len(names)}")
    if backend == "labfs_ssh":
        _sync_ssh(names, out_dir)
    else:
        icon_root = Path(os.getenv("PNETLAB_ICON_ROOT", "/opt/unetlab/html/images/icons"))
        _sync_local(icon_root, names, out_dir)

    print(f"[ok] synced to {out_dir}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as e:
        print(f"[error] {e}", file=sys.stderr)
        raise
