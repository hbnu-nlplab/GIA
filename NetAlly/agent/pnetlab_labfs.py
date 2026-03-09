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
import ipaddress
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple
from urllib.parse import urlparse
import xml.etree.ElementTree as ET


_PORT_RE = re.compile(r"\b(?:ts_port|port)\s*=\s*(\d{4,6})\b")
_DEVICE_ID_RE = re.compile(r"\bDevice_id\s*=\s*(\d+)\b")
_LABEL_IPV4_RE = re.compile(r"\b((?:\d{1,3}\.){3}\d{1,3})(?:/(\d{1,2}))?\b")
_MGMT_NET_KEYWORDS = ("mgmt", "management", "oob", "admin")


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
    linkstyle: str = ""
    linkcfg: str = ""


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
                        linkstyle=i.get("linkstyle", "") or "",
                        linkcfg=i.get("linkcfg", "") or "",
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


def resolve_ssh_host() -> str:
    """
    Resolve SSH host with practical fallbacks so labfs_ssh works even when only VM IP is set.
    Priority:
      1) PNETLAB_SSH_HOST
      2) PNETLAB_VM_IP
      3) hostname from PNETLAB_URL / PNETLAB_HOST
    """
    host = os.getenv("PNETLAB_SSH_HOST", "").strip()
    if host:
        return host

    vm_ip = os.getenv("PNETLAB_VM_IP", "").strip()
    if vm_ip:
        return vm_ip

    raw_url = os.getenv("PNETLAB_URL", "").strip() or os.getenv("PNETLAB_HOST", "").strip()
    if not raw_url:
        return ""

    try:
        parsed = urlparse(raw_url if "://" in raw_url else f"http://{raw_url}")
    except Exception:
        return ""
    return str(parsed.hostname or "").strip()


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

    if resolve_ssh_host():
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

    def discover_iol_ports(self) -> Dict[str, int]:  # pragma: no cover - interface
        """Parse running iol_wrapper processes for port discovery (IOL devices have empty wrapper.txt)."""
        return {}


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

    def discover_iol_ports(self) -> Dict[str, int]:
        try:
            res = subprocess.run(["ps", "aux"], capture_output=True, text=True)
            out = res.stdout
        except Exception:
            return {}
        ports: Dict[str, int] = {}
        for line in out.splitlines():
            if "iol_wrapper" not in line or "grep" in line:
                continue
            m_dev = re.search(r"-D\s+(\d+)", line)
            m_port = re.search(r"-P\s+(\d+)", line)
            if m_dev and m_port:
                ports[m_dev.group(1)] = int(m_port.group(1))
        return ports


class _SshReader(_Reader):
    """
    Minimal SSH reader based on system `ssh`.

    Key path is optional; users can rely on default SSH agent/key discovery.
    """

    def __init__(self) -> None:
        host = resolve_ssh_host()
        user = os.getenv("PNETLAB_SSH_USER", "root").strip() or "root"
        port = os.getenv("PNETLAB_SSH_PORT", "22").strip() or "22"
        key = os.getenv("PNETLAB_SSH_KEY_PATH", "").strip()
        if not host:
            raise RuntimeError(
                "PNETLAB_SSH_HOST is required for labfs_ssh "
                "(or set PNETLAB_VM_IP / PNETLAB_URL so host can be inferred)"
            )

        extra_opts = os.getenv("PNETLAB_SSH_OPTIONS", "").strip()
        self._base: List[str] = [
            "ssh",
            "-p",
            port,
        ]
        if key:
            self._base += ["-i", key]
        self._base += ["-o", "BatchMode=yes"]
        if extra_opts:
            # Allow users to opt into accept-new etc. safely.
            self._base += shlex.split(extra_opts)
        self._target = f"{user}@{host}"

    def _run(self, cmd: str) -> str:
        # Some PNETLab shells mishandle argument-passed `sh -c` forms.
        # Execute as a single remote command string for portability.
        remote_cmd = f"sh -c {sh_quote(cmd)}"
        res = subprocess.run(
            # Avoid login shells: some PNETLab images print banners to stdout on -l.
            [*self._base, self._target, remote_cmd],
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

    def discover_iol_ports(self) -> Dict[str, int]:
        try:
            out = self._run("ps aux 2>/dev/null || true")
        except Exception:
            return {}
        ports: Dict[str, int] = {}
        for line in out.splitlines():
            if "iol_wrapper" not in line or "grep" in line:
                continue
            m_dev = re.search(r"-D\s+(\d+)", line)
            m_port = re.search(r"-P\s+(\d+)", line)
            if m_dev and m_port:
                ports[m_dev.group(1)] = int(m_port.group(1))
        return ports


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

    result = {k: v[0] for k, v in ports.items()}

    # IOL devices have empty wrapper.txt — discover ports from running processes.
    # These OVERRIDE wrapper.txt because wrapper.txt may contain stale ports from other labs.
    iol_ports = reader.discover_iol_ports()
    for node_id, port in iol_ports.items():
        result[node_id] = port

    return result


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
                    "platform": n.template or n.kind or "",
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

    def _parse_linkcfg(raw: str) -> Dict[str, Any]:
        """Parse linkcfg JSON string from UNL, e.g. '{"curviness":150}'."""
        if not raw or raw == "{}":
            return {}
        import json
        try:
            cleaned = raw.replace("&quot;", '"')
            return json.loads(cleaned)
        except Exception:
            return {}

    def edge_data_from_iface(i: UnlInterface) -> Dict[str, Any]:
        """Extract linkstyle and linkcfg for edge data."""
        data: Dict[str, Any] = {}
        if i.linkstyle:
            data["linkstyle"] = i.linkstyle
        cfg = _parse_linkcfg(i.linkcfg)
        if cfg:
            data["linkcfg"] = cfg
        return data

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
                        **edge_data_from_iface(a),
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
                        **edge_data_from_iface(ep),
                    },
                    "style": edge_style_from_iface(ep),
                }
            )

    return {"nodes": api_nodes, "edges": api_edges, "meta": {"unl_path": str(unl_path), "backend": backend}}


def discover_management_interfaces(
    nso_node_name: str = "",
) -> Dict[str, str]:
    """
    UNL 토폴로지에서 관리 인터페이스를 범용적으로 감지.

    알고리즘:
    1. NSO 노드를 찾음 (PNETLAB_NSO_NODE env, 기본값 "NSO")
    2. NSO가 연결된 네트워크(들)를 찾음 → 관리 네트워크 후보
    3. 각 장비에서 관리 네트워크에 연결된 인터페이스를 반환

    Returns: {device_name: interface_name}
    """
    endpoints = discover_management_endpoints(nso_node_name=nso_node_name)
    return {name: str(meta.get("iface", "")) for name, meta in endpoints.items() if str(meta.get("iface", ""))}


def discover_management_endpoints(
    nso_node_name: str = "",
) -> Dict[str, Dict[str, Any]]:
    """
    Discover management interface metadata from UNL.

    Returns:
      {
        "R1": {"iface":"Ethernet0/0","ip":"10.10.10.2","prefix":24,"network_id":"7","source":"label|network|nso"},
        ...
      }
    """
    nso_name = nso_node_name or os.getenv("PNETLAB_NSO_NODE", "NSO")

    backend = resolve_inventory_backend()
    reader: _Reader = _SshReader() if backend == "labfs_ssh" else _LocalReader()

    unetlab_root = str(resolve_unetlab_root())
    unl_path = resolve_unl_path_reader(reader, unetlab_root)
    if not unl_path:
        return {}

    try:
        nodes, networks, ifaces = parse_unl(reader.read_text(unl_path))
    except Exception:
        return {}

    node_by_id = {n.node_id: n for n in nodes if n.node_id}
    net_by_id = {n.network_id: n for n in networks if n.network_id}

    nso_node_id = ""
    for n in nodes:
        if n.name.lower() == nso_name.lower():
            nso_node_id = n.node_id
            break

    nso_net_ids: set[str] = set()
    if nso_node_id:
        for iface in ifaces:
            if iface.node_id == nso_node_id:
                nso_net_ids.add(iface.network_id)

    net_has_label_ip: set[str] = set()
    for iface in ifaces:
        if _LABEL_IPV4_RE.search(iface.label or ""):
            net_has_label_ip.add(iface.network_id)

    keyword_net_ids: set[str] = set()
    for net_id, net in net_by_id.items():
        lowered = str(net.name or "").lower()
        if any(k in lowered for k in _MGMT_NET_KEYWORDS):
            keyword_net_ids.add(net_id)

    candidate_net_ids = nso_net_ids | net_has_label_ip | keyword_net_ids
    if not candidate_net_ids:
        return {}

    best_by_node: Dict[str, Dict[str, Any]] = {}

    for iface in ifaces:
        if iface.network_id not in candidate_net_ids:
            continue
        if iface.node_id == nso_node_id:
            continue

        node = node_by_id.get(iface.node_id)
        if not node:
            continue

        label = str(iface.label or "")
        ip_val: Optional[str] = None
        prefix: Optional[int] = None
        m = _LABEL_IPV4_RE.search(label)
        if m:
            raw_ip = str(m.group(1))
            raw_prefix = str(m.group(2) or "24")
            try:
                addr = ipaddress.IPv4Address(raw_ip)
                ip_val = raw_ip
                p = int(raw_prefix)
                if 0 <= p <= 32:
                    prefix = p
                else:
                    prefix = 24
                try:
                    net = ipaddress.IPv4Network(f"{raw_ip}/{prefix}", strict=False)
                    if net.num_addresses > 2 and (addr == net.network_address or addr == net.broadcast_address):
                        ip_val = None
                        prefix = None
                except Exception:
                    pass
            except Exception:
                ip_val = None
                prefix = None

        net = net_by_id.get(iface.network_id)
        net_name = str(net.name or "")
        score = 0
        reason: List[str] = []
        if iface.network_id in nso_net_ids:
            score += 1
            reason.append("nso")
        if iface.network_id in keyword_net_ids:
            score += 2
            reason.append("network")
        if ip_val:
            score += 3
            reason.append("label")

        existing = best_by_node.get(node.name)
        if existing and int(existing.get("_score", -1)) >= score:
            continue

        best_by_node[node.name] = {
            "iface": iface.iface_name,
            "ip": ip_val,
            "prefix": prefix,
            "network_id": iface.network_id,
            "network_name": net_name,
            "source": "|".join(reason) if reason else "candidate",
            "_score": score,
        }

    # strip internal field
    for meta in best_by_node.values():
        meta.pop("_score", None)
    return best_by_node
