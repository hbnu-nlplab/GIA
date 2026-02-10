"""
PNETLab LabFS parser (UNL + runtime wrapper logs).

Goal: replicate the PNETLab topology view without relying on the web API
(cookies/XSRF/CAPTCHA). We parse:
  - /opt/unetlab/labs/*.unl (XML) for nodes/networks/interfaces/visual metadata
  - /opt/unetlab/tmp/*/*/wrapper.txt for runtime console ports (best-effort)

This module is intentionally tolerant: we only parse fields we need and ignore
unknown attributes so it keeps working across PNETLab versions.
"""

from __future__ import annotations

import os
import re
import subprocess
import shlex
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple
import xml.etree.ElementTree as ET


_PORT_RE = re.compile(r"\b(?:ts_port|port)\s*=\s*(\d{4,6})\b")
_DEVICE_ID_RE = re.compile(r"\bDevice_id\s*=\s*(\d+)\b")


@dataclass(frozen=True)
class UnlInterface:
    node_id: str
    iface_id: str
    iface_name: str
    network_id: str
    label: str = ""
    style: str = ""
    color: str = ""
    width: str = ""
    fontsize: str = ""


@dataclass(frozen=True)
class UnlNode:
    node_id: str
    name: str
    kind: str  # docker, iol, qemu, ...
    template: str = ""
    icon: str = ""
    left: int = 0
    top: int = 0


@dataclass(frozen=True)
class UnlNetwork:
    network_id: str
    name: str
    net_type: str = ""
    icon: str = ""
    visibility: int = 0
    left: int = 0
    top: int = 0


def _int(value: Any, default: int = 0) -> int:
    try:
        return int(str(value))
    except Exception:
        return default


def parse_unl(unl_xml: str) -> Tuple[List[UnlNode], List[UnlNetwork], List[UnlInterface]]:
    root = ET.fromstring(unl_xml)

    nodes: List[UnlNode] = []
    networks: List[UnlNetwork] = []
    ifaces: List[UnlInterface] = []

    topo = root.find("topology")
    if topo is None:
        return nodes, networks, ifaces

    nodes_el = topo.find("nodes")
    if nodes_el is not None:
        for n in nodes_el.findall("node"):
            node_id = n.get("id", "") or ""
            name = n.get("name", "") or f"node_{node_id}"
            kind = n.get("type", "") or "unknown"
            template = n.get("template", "") or ""
            icon = n.get("icon", "") or ""
            left = _int(n.get("left", 0))
            top = _int(n.get("top", 0))
            nodes.append(
                UnlNode(
                    node_id=node_id,
                    name=name,
                    kind=kind,
                    template=template,
                    icon=icon,
                    left=left,
                    top=top,
                )
            )

            for i in n.findall("interface"):
                network_id = i.get("network_id", "") or ""
                if not network_id or network_id == "0":
                    continue
                iface_id = i.get("id", "") or ""
                iface_name = i.get("name", "") or ""
                ifaces.append(
                    UnlInterface(
                        node_id=node_id,
                        iface_id=iface_id,
                        iface_name=iface_name,
                        network_id=network_id,
                        label=i.get("label", "") or "",
                        style=i.get("style", "") or "",
                        color=i.get("color", "") or "",
                        width=i.get("width", "") or "",
                        fontsize=i.get("fontsize", "") or "",
                    )
                )

    nets_el = topo.find("networks")
    if nets_el is not None:
        for net in nets_el.findall("network"):
            network_id = net.get("id", "") or ""
            name = net.get("name", "") or f"net_{network_id}"
            net_type = net.get("type", "") or ""
            icon = net.get("icon", "") or ""
            visibility = _int(net.get("visibility", 0))
            left = _int(net.get("left", 0))
            top = _int(net.get("top", 0))
            networks.append(
                UnlNetwork(
                    network_id=network_id,
                    name=name,
                    net_type=net_type,
                    icon=icon,
                    visibility=visibility,
                    left=left,
                    top=top,
                )
            )

    return nodes, networks, ifaces


def _read_text(path: Path) -> str:
    return path.read_text(encoding="utf-8", errors="ignore")


def _iter_wrapper_files(tmp_root: Path) -> Iterable[Path]:
    # /opt/unetlab/tmp/<lab_session>/<node_or_pid>/wrapper.txt
    if not tmp_root.exists():
        return []
    return tmp_root.glob("*/*/wrapper.txt")


def parse_wrapper_ports(tmp_root: Path) -> Dict[str, int]:
    """
    Build node_id -> telnet_port mapping from wrapper logs.
    Best-effort, supports multiple wrapper formats.
    """
    ports: Dict[str, Tuple[int, float]] = {}
    for wrapper in _iter_wrapper_files(tmp_root):
        try:
            text = _read_text(wrapper)
            m_port = _PORT_RE.search(text)
            if not m_port:
                continue
            port = _int(m_port.group(1), 0)
            if port <= 0:
                continue

            m_dev = _DEVICE_ID_RE.search(text)
            node_id = m_dev.group(1) if m_dev else wrapper.parent.name
            if not node_id:
                continue

            mtime = wrapper.stat().st_mtime
            existing = ports.get(node_id)
            # Keep the most recent observation per node.
            if existing is None or mtime >= existing[1]:
                ports[node_id] = (port, mtime)
        except Exception:
            continue

    return {k: v[0] for k, v in ports.items()}


def resolve_unetlab_root() -> Path:
    return Path(os.getenv("PNETLAB_UNETLAB_ROOT", "/opt/unetlab"))

def resolve_inventory_backend() -> str:
    """
    Resolve the effective inventory backend with a sane default:
    - If PNETLAB_INVENTORY_BACKEND is explicitly set, honor it.
    - Else prefer labfs_local when /opt/unetlab/labs exists (running inside PNETLab VM/container).
    - Else prefer labfs_ssh when PNETLAB_SSH_HOST is set.
    - Else fall back to api.
    """
    raw = os.getenv("PNETLAB_INVENTORY_BACKEND", "").strip().lower()
    if raw:
        return raw

    unetlab_root = resolve_unetlab_root()
    if (unetlab_root / "labs").exists():
        return "labfs_local"

    if os.getenv("PNETLAB_SSH_HOST", "").strip():
        return "labfs_ssh"

    return "api"


def sh_quote(value: str) -> str:
    # minimal POSIX shell quoting
    return "'" + value.replace("'", "'\"'\"'") + "'"


class _Reader:
    def exists(self, path: str) -> bool:  # pragma: no cover - interface
        raise NotImplementedError

    def read_text(self, path: str) -> str:  # pragma: no cover - interface
        raise NotImplementedError

    def list_unl_candidates(self, labs_root: str) -> List[str]:  # pragma: no cover - interface
        raise NotImplementedError

    def find_unl_by_name(self, labs_root: str, name: str) -> List[str]:  # pragma: no cover - interface
        raise NotImplementedError

    def list_wrapper_files(self, tmp_root: str) -> List[str]:  # pragma: no cover - interface
        raise NotImplementedError

    def stat_mtime(self, path: str) -> float:  # pragma: no cover - interface
        raise NotImplementedError


class _LocalReader(_Reader):
    def exists(self, path: str) -> bool:
        return Path(path).exists()

    def read_text(self, path: str) -> str:
        return Path(path).read_text(encoding="utf-8", errors="ignore")

    def list_unl_candidates(self, labs_root: str) -> List[str]:
        root = Path(labs_root)
        if not root.exists():
            return []
        return [str(p) for p in root.rglob("*.unl") if p.is_file()]

    def find_unl_by_name(self, labs_root: str, name: str) -> List[str]:
        root = Path(labs_root)
        if not root.exists():
            return []
        return [str(p) for p in root.rglob(f"{name}.unl") if p.is_file()]

    def list_wrapper_files(self, tmp_root: str) -> List[str]:
        root = Path(tmp_root)
        if not root.exists():
            return []
        return [str(p) for p in root.glob("*/*/wrapper.txt") if p.is_file()]

    def stat_mtime(self, path: str) -> float:
        try:
            return Path(path).stat().st_mtime
        except Exception:
            return 0.0


class _SshReader(_Reader):
    """
    Minimal SSH reader based on system `ssh`.

    This intentionally requires key-based auth (non-interactive).
    """

    def __init__(self) -> None:
        host = os.getenv("PNETLAB_SSH_HOST", "").strip()
        user = os.getenv("PNETLAB_SSH_USER", "root").strip() or "root"
        port = os.getenv("PNETLAB_SSH_PORT", "22").strip() or "22"
        key = os.getenv("PNETLAB_SSH_KEY_PATH", "").strip()
        if not host:
            raise RuntimeError("PNETLAB_SSH_HOST is required for labfs_ssh")
        if not key:
            raise RuntimeError("PNETLAB_SSH_KEY_PATH is required for labfs_ssh (key-based auth)")

        extra_opts = os.getenv("PNETLAB_SSH_OPTIONS", "").strip()
        self._base: List[str] = [
            "ssh",
            "-p",
            port,
            "-i",
            key,
            "-o",
            "BatchMode=yes",
        ]
        if extra_opts:
            # Allow users to opt into accept-new etc. safely.
            self._base += shlex.split(extra_opts)
        self._target = f"{user}@{host}"

    def _run(self, cmd: str) -> str:
        res = subprocess.run(
            # Avoid login shells: some PNETLab images print banners to stdout on -l.
            [*self._base, self._target, "--", "sh", "-c", cmd],
            capture_output=True,
            text=True,
        )
        if res.returncode != 0:
            raise RuntimeError((res.stderr or res.stdout or "").strip() or f"ssh failed: {cmd}")
        return res.stdout

    def exists(self, path: str) -> bool:
        try:
            out = self._run(f"test -e {sh_quote(path)} && echo ok || echo no")
            return "ok" in out
        except Exception:
            return False

    def read_text(self, path: str) -> str:
        return self._run(f"cat {sh_quote(path)}")

    def list_unl_candidates(self, labs_root: str) -> List[str]:
        out = self._run(f"find {sh_quote(labs_root)} -type f -name '*.unl' 2>/dev/null || true")
        return [line.strip() for line in out.splitlines() if line.strip()]

    def find_unl_by_name(self, labs_root: str, name: str) -> List[str]:
        out = self._run(
            f"find {sh_quote(labs_root)} -type f -name {sh_quote(name + '.unl')} 2>/dev/null || true"
        )
        return [line.strip() for line in out.splitlines() if line.strip()]

    def list_wrapper_files(self, tmp_root: str) -> List[str]:
        out = self._run(f"find {sh_quote(tmp_root)} -type f -name 'wrapper.txt' 2>/dev/null || true")
        return [line.strip() for line in out.splitlines() if line.strip()]

    def stat_mtime(self, path: str) -> float:
        try:
            out = self._run(f"stat -c %Y {sh_quote(path)} 2>/dev/null || echo 0")
            return float(out.strip().splitlines()[-1])
        except Exception:
            return 0.0


def resolve_unl_path_reader(reader: _Reader, unetlab_root: str) -> Optional[str]:
    direct = os.getenv("PNETLAB_LAB_PATH", "").strip()
    if direct:
        p = direct
        if not p.startswith("/"):
            p = str(Path(unetlab_root) / p)
        return p if reader.exists(p) else None

    labs_root = str(Path(unetlab_root) / "labs")
    name = os.getenv("PNETLAB_LAB_NAME", "").strip()
    if name:
        candidates = reader.find_unl_by_name(labs_root, name)
        if not candidates:
            return None
        candidates.sort(key=lambda x: reader.stat_mtime(x), reverse=True)
        return candidates[0]

    candidates = reader.list_unl_candidates(labs_root)
    if not candidates:
        return None
    candidates.sort(key=lambda x: reader.stat_mtime(x), reverse=True)
    return candidates[0]


def parse_wrapper_ports_reader(reader: _Reader, tmp_root: str) -> Dict[str, int]:
    ports: Dict[str, Tuple[int, float]] = {}
    for wrapper in reader.list_wrapper_files(tmp_root):
        try:
            text = reader.read_text(wrapper)
            m_port = _PORT_RE.search(text)
            if not m_port:
                continue
            port = _int(m_port.group(1), 0)
            if port <= 0:
                continue

            m_dev = _DEVICE_ID_RE.search(text)
            parent = wrapper.rstrip("/").rsplit("/", 2)[-2] if "/" in wrapper else ""
            node_id = m_dev.group(1) if m_dev else parent
            if not node_id:
                continue

            mtime = reader.stat_mtime(wrapper)
            existing = ports.get(node_id)
            if existing is None or mtime >= existing[1]:
                ports[node_id] = (port, mtime)
        except Exception:
            continue

    return {k: v[0] for k, v in ports.items()}


def resolve_unl_path(unetlab_root: Path) -> Optional[Path]:
    direct = os.getenv("PNETLAB_LAB_PATH", "").strip()
    if direct:
        p = Path(direct)
        if not p.is_absolute():
            p = unetlab_root / p
        return p if p.exists() else None

    name = os.getenv("PNETLAB_LAB_NAME", "").strip()
    if name:
        # Search under /opt/unetlab/labs (including store subfolders)
        candidates = list((unetlab_root / "labs").rglob(f"{name}.unl"))
        if not candidates:
            return None
        # pick most recently modified
        candidates.sort(key=lambda x: x.stat().st_mtime, reverse=True)
        return candidates[0]

    # fallback: most recent unl
    candidates = list((unetlab_root / "labs").rglob("*.unl"))
    if not candidates:
        return None
    candidates.sort(key=lambda x: x.stat().st_mtime, reverse=True)
    return candidates[0]


def build_pnetlab_map_from_labfs() -> Dict[str, Any]:
    """
    Return a topology payload compatible with /api/topology/pnetlab output:
      { nodes: [...], edges: [...] }
    Includes networks as nodes when visible or when network has >2 endpoints.
    """
    backend = resolve_inventory_backend()
    reader: _Reader = _LocalReader()
    if backend == "labfs_ssh":
        reader = _SshReader()
    elif backend not in {"labfs_local", "labfs_ssh"}:
        return {
            "error": "LabFS backend not selected (set PNETLAB_INVENTORY_BACKEND=labfs_local|labfs_ssh)",
            "nodes": [],
            "edges": [],
        }

    unetlab_root = str(resolve_unetlab_root())
    unl_path = resolve_unl_path_reader(reader, unetlab_root)
    if unl_path is None:
        return {"error": "UNL not found", "nodes": [], "edges": []}

    nodes, networks, ifaces = parse_unl(reader.read_text(unl_path))
    node_by_id = {n.node_id: n for n in nodes if n.node_id}
    net_by_id = {n.network_id: n for n in networks if n.network_id}

    # Runtime ports are optional: only present for running nodes.
    ports = parse_wrapper_ports_reader(reader, str(Path(unetlab_root) / "tmp"))

    # network_id -> endpoints
    endpoints: Dict[str, List[UnlInterface]] = {}
    for i in ifaces:
        endpoints.setdefault(i.network_id, []).append(i)

    api_nodes: List[Dict[str, Any]] = []
    api_edges: List[Dict[str, Any]] = []

    # Add device nodes
    for n in nodes:
        api_nodes.append(
            {
                "id": n.name,
                "type": "device",
                "data": {
                    "label": n.name,
                    "template": n.template,
                    "kind": n.kind,
                    "icon": n.icon,
                    "telnet_port": ports.get(n.node_id, 0),
                },
                "position": {"x": n.left, "y": n.top},
            }
        )

    def edge_style_from_iface(i: UnlInterface) -> Dict[str, Any]:
        style: Dict[str, Any] = {}
        if i.color:
            style["stroke"] = i.color
        if i.width:
            style["strokeWidth"] = _int(i.width, 2)
        if i.style.lower() in {"dotted", "dashed"}:
            style["strokeDasharray"] = "4 4" if i.style.lower() == "dotted" else "8 6"
        return style

    # Add networks (as nodes) when needed, otherwise connect device<->device directly.
    for net_id, eps in endpoints.items():
        if not eps:
            continue
        net = net_by_id.get(net_id)
        # PNETLab hides some networks; if hidden and exactly 2 endpoints, draw direct link.
        should_draw_hub = True
        if net is not None and int(net.visibility) == 0 and len(eps) == 2:
            should_draw_hub = False

        if not should_draw_hub:
            a, b = eps[0], eps[1]
            na = node_by_id.get(a.node_id)
            nb = node_by_id.get(b.node_id)
            if not na or not nb:
                continue
            label = a.label or b.label or (net.name if net else "")
            api_edges.append(
                {
                    "source": na.name,
                    "target": nb.name,
                    "label": label,
                    "data": {
                        "src_iface": a.iface_name,
                        "dst_iface": b.iface_name,
                        "network_id": net_id,
                    },
                    "style": edge_style_from_iface(a) or edge_style_from_iface(b),
                }
            )
            continue

        # Hub node
        hub_id = f"net:{net_id}"
        hub_label = net.name if net else f"net_{net_id}"
        hub_left = net.left if net else 0
        hub_top = net.top if net else 0
        hub_icon = net.icon if net else "cloud.png"
        api_nodes.append(
            {
                "id": hub_id,
                "type": "network",
                "data": {
                    "label": hub_label,
                    "network_id": net_id,
                    "icon": hub_icon,
                    "visibility": int(net.visibility) if net else 0,
                },
                "position": {"x": hub_left, "y": hub_top},
            }
        )
        for ep in eps:
            dev = node_by_id.get(ep.node_id)
            if not dev:
                continue
            api_edges.append(
                {
                    "source": dev.name,
                    "target": hub_id,
                    "label": ep.label or "",
                    "data": {
                        "src_iface": ep.iface_name,
                        "network_id": net_id,
                    },
                    "style": edge_style_from_iface(ep),
                }
            )

    return {"nodes": api_nodes, "edges": api_edges, "meta": {"unl_path": str(unl_path), "backend": backend}}
