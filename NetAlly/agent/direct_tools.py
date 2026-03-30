"""Direct tool wrappers — bypass MCP HTTP for evaluation.

Same interface as mcp_tools.py (LangChain @tool), but calls
agent/tools.py functions directly via asyncio.to_thread().

Includes session-level caching: bulk queries (all_device_info,
all_interfaces) are cached so repeated calls across questions
hit memory instead of NSO 20×2 HTTP calls.

Usage (eval runner only):
    from agent.direct_tools import DIRECT_TOOLS, clear_cache
    tool_dict = {t.name: t for t in DIRECT_TOOLS}
"""

from __future__ import annotations

import asyncio
import logging
import sys
from typing import Any, Dict, List, Literal, Optional

from langchain_core.tools import tool

from agent.tools import (
    check_logs as legacy_check_logs,
    lab_bootstrap as legacy_lab_bootstrap,
    lab_manage as legacy_lab_manage,
    network_query as legacy_network_query,
    network_verify as legacy_network_verify,
    scan_and_sync as legacy_scan_and_sync,
)

logger = logging.getLogger(__name__)

# ─── Session-level cache ─────────────────────────────────────────────────────
# Device configs don't change during an eval run. Cache bulk results.
_CACHE: Dict[str, Any] = {}


def clear_cache() -> None:
    """Clear all cached results. Call between eval sessions if needed."""
    _CACHE.clear()
    logger.info("Direct tools cache cleared")


def _invoke_sync(tool_obj: Any, payload: Dict[str, Any]) -> Any:
    """Call a LangChain tool synchronously. No async."""
    return tool_obj.invoke(payload)


def _ensure_batfish():
    """Get BatfishClient + ensure snapshot loaded. Returns (bf, builder)."""
    import os
    from agent.tools import get_batfish_client
    bf = get_batfish_client()
    if not bf.is_available:
        raise RuntimeError("Batfish SDK not available")
    if not bf._builder:
        topo = os.getenv("BATFISH_SNAPSHOT") or os.getenv("BATFISH_NETWORK") or "default"
        if not bf.load_snapshot(topo):
            raise RuntimeError("Batfish not initialized")
    return bf, bf._builder


def _unwrap_result(result) -> Dict[str, Any]:
    """Unwrap BatfishBuilder AnswerResult (.value) or pass through dict."""
    if hasattr(result, 'value'):
        return result.value if isinstance(result.value, dict) else {"result": str(result.value)}
    if isinstance(result, dict):
        return result
    return {"result": str(result)}


def _batfish_subprocess(func_name: str, args: Dict[str, Any], timeout: int = 120) -> Dict[str, Any]:
    """Execute Batfish function in a separate subprocess.

    Avoids pybatfish session thread-safety issues by running in a clean process.
    Same environment as dataset generation — no event loop, no async.
    """
    import subprocess as _sp
    import json as _json
    from pathlib import Path

    worker = str(Path(__file__).parent / "batfish_worker.py")
    args_json = _json.dumps(args, ensure_ascii=False)

    try:
        proc = _sp.run(
            [sys.executable, worker, func_name, args_json],
            capture_output=True, text=True, timeout=timeout,
            cwd=str(Path(__file__).parent.parent),  # NetAlly root
        )
        if proc.stdout.strip():
            return _json.loads(proc.stdout.strip())
        if proc.stderr.strip():
            logger.warning(f"batfish_worker stderr: {proc.stderr[:200]}")
        return {"error": f"Empty output from batfish_worker (exit={proc.returncode})"}
    except _sp.TimeoutExpired:
        return {"error": f"batfish_worker timed out after {timeout}s"}
    except Exception as e:
        return {"error": f"batfish_worker failed: {type(e).__name__}: {e}"}


# ─── NSO tools ───────────────────────────────────────────────────────────────

@tool
def nso_list_devices() -> Dict[str, Any]:
    """[Direct] List all devices from NSO."""
    return _invoke_sync(legacy_network_query, {"category": "device"})


@tool
def nso_get_device_info(device: str) -> Dict[str, Any]:
    """[Direct] Get a device summary from NSO. Cached per session."""
    cache_key = f"device_info:{device}"
    if cache_key in _CACHE:
        logger.info(f"Cache HIT: nso_get_device_info({device})")
        return _CACHE[cache_key]
    result = _invoke_sync(legacy_network_query, {"category": "device", "device": device})
    _CACHE[cache_key] = result
    return result


@tool
def nso_get_all_device_info() -> Dict[str, Any]:
    """[Direct] Get device info for ALL devices in one call. Cached per session."""
    if "all_device_info" in _CACHE:
        logger.info("Cache HIT: nso_get_all_device_info")
        return _CACHE["all_device_info"]

    devices_result = _invoke_sync(legacy_network_query, {"category": "device"})
    if isinstance(devices_result, dict):
        device_names = devices_result.get("devices", [])
    elif isinstance(devices_result, list):
        device_names = [d.get("name", d) if isinstance(d, dict) else d for d in devices_result]
    else:
        device_names = []
    # Fetch full summaries (cached individually too)
    all_full = {}
    for name in device_names:
        info = _invoke_sync(legacy_network_query, {"category": "device", "device": name})
        summary = info.get("config_summary", info) if isinstance(info, dict) else info
        all_full[name] = summary
        # Cache individual device info for nso_get_device_info hits
        _CACHE[f"device_info:{name}"] = info

    # Pre-compute aggregations so LLM doesn't have to iterate
    agg = {
        "devices_with_aaa": [],
        "devices_with_ssh": [],
        "devices_with_mpls": [],
        "devices_with_ospf": [],
        "devices_with_bgp": [],
        "devices_with_snmp": [],
        "devices_with_ntp": [],
        "devices_with_logging": [],
        "interface_counts": {},
        "vrf_counts": {},
        "vrf_details_per_device": {},
        "bgp_as_per_device": {},
        "ospf_ids_per_device": {},
        "ssh_versions": {},
        "timezones": {},
    }
    for name, s in all_full.items():
        if not isinstance(s, dict):
            continue
        if s.get("aaa_enabled"):
            agg["devices_with_aaa"].append(name)
        if s.get("ssh_version"):
            agg["devices_with_ssh"].append(name)
            agg["ssh_versions"][name] = s["ssh_version"]
        if s.get("mpls_enabled"):
            agg["devices_with_mpls"].append(name)
        if "ospf" in s.get("routing_protocols", []):
            agg["devices_with_ospf"].append(name)
        if "bgp" in s.get("routing_protocols", []):
            agg["devices_with_bgp"].append(name)
        if s.get("snmp"):
            agg["devices_with_snmp"].append(name)
        if s.get("ntp"):
            agg["devices_with_ntp"].append(name)
        if s.get("logging"):
            agg["devices_with_logging"].append(name)
        agg["interface_counts"][name] = s.get("interface_count", 0)
        agg["vrf_counts"][name] = len(s.get("vrf_list", []))
        if s.get("vrf_details"):
            agg["vrf_details_per_device"][name] = s["vrf_details"]
        if s.get("bgp_as_number"):
            agg["bgp_as_per_device"][name] = s["bgp_as_number"]
        if s.get("ospf_process_ids"):
            agg["ospf_ids_per_device"][name] = s["ospf_process_ids"]
        if s.get("clock_timezone"):
            agg["timezones"][name] = s["clock_timezone"]

    # Compact: aggregations + 장비별 핵심 필드만 (full summary 제거 → 토큰 절감)
    compact_devices = {}
    for name, s in all_full.items():
        if not isinstance(s, dict):
            compact_devices[name] = s
            continue
        compact_devices[name] = {
            "hostname": s.get("hostname", name),
            "routing_protocols": s.get("routing_protocols", []),
            "interface_count": s.get("interface_count", 0),
            "vrf_list": s.get("vrf_list", []),
            "aaa_enabled": s.get("aaa_enabled", False),
        }

    result = {"devices": compact_devices, "count": len(compact_devices), "aggregations": agg}
    _CACHE["all_device_info"] = result
    logger.info(f"Cache SET: nso_get_all_device_info ({len(all_full)} devices)")
    return result


@tool
def nso_get_interfaces(device: str) -> Dict[str, Any]:
    """[Direct] Get interfaces for a device from NSO."""
    return _invoke_sync(legacy_network_query, {"category": "interface", "device": device})


@tool
def nso_get_all_interfaces() -> Dict[str, Any]:
    """[Direct] Get interfaces for ALL devices in one call. Cached per session."""
    if "all_interfaces" in _CACHE:
        logger.info("Cache HIT: nso_get_all_interfaces")
        return _CACHE["all_interfaces"]

    devices_result = _invoke_sync(legacy_network_query, {"category": "device"})
    if isinstance(devices_result, dict):
        device_names = devices_result.get("devices", [])
    elif isinstance(devices_result, list):
        device_names = [d.get("name", d) if isinstance(d, dict) else d for d in devices_result]
    else:
        device_names = []
    all_intfs = {}
    for name in device_names:
        intfs = _invoke_sync(legacy_network_query, {"category": "interface", "device": name})
        all_intfs[name] = intfs

    # Pre-compute per-device interface counts
    iface_counts = {}
    for name, data in all_intfs.items():
        ilist = data.get("interfaces", data) if isinstance(data, dict) else data
        iface_counts[name] = len(ilist) if isinstance(ilist, list) else 0

    result = {"devices": all_intfs, "count": len(all_intfs), "interface_counts": iface_counts}
    _CACHE["all_interfaces"] = result
    logger.info(f"Cache SET: nso_get_all_interfaces ({len(all_intfs)} devices)")
    return result


@tool
def nso_get_routing(device: str, protocol: Literal["bgp", "ospf"] = "bgp") -> Dict[str, Any]:
    """[Direct] Get routing data (BGP/OSPF) for a device."""
    return _invoke_sync(
        legacy_network_query,
        {"category": "routing", "device": device, "params": {"protocol": protocol}},
    )


@tool
def nso_get_logs(device: str, lines: int = 50, keyword: Optional[str] = None) -> Dict[str, Any]:
    """[Direct] Get recent logs from NSO live-status output."""
    data = _invoke_sync(
        legacy_check_logs,
        {"device": device, "lines": lines, "keyword": keyword},
    )
    return {"logs": data}


# ─── Batfish tools (sync @tool + subprocess — no async, no event loop) ───────

@tool
def batfish_reachability(src: str, dst: str, protocol: str = "icmp") -> Dict[str, Any]:
    """[Direct] Run Batfish reachability test."""
    return _batfish_subprocess("reachability", {"src": src.lower(), "dst": dst.lower(), "protocol": protocol})


@tool
def batfish_traceroute(src: str, dst: str) -> Dict[str, Any]:
    """[Direct] Run Batfish traceroute between two nodes. Returns path, hop_count."""
    return _batfish_subprocess("traceroute", {"src": src.lower(), "dst": dst.lower()})


@tool
def batfish_bgp_sessions(device: Optional[str] = None) -> Dict[str, Any]:
    """[Direct] List BGP session status with summary (established, under-peered)."""
    return _batfish_subprocess("bgp_sessions", {"device": device.lower() if device else None})


@tool
def batfish_route_table(device: str) -> Dict[str, Any]:
    """[Direct] Get routing table for a device. Returns routes and route_count."""
    return _batfish_subprocess("route_table", {"device": device.lower()})


# ─── Batfish L4 analysis (sync subprocess) ────────────────────────────────────

@tool
def batfish_acl_check(src_ip: str, dst_ip: str, dst_port: int = 80) -> Dict[str, Any]:
    """[Direct] Check if any ACL blocks traffic between src and dst IP."""
    return _batfish_subprocess("acl_check", {"src_ip": src_ip, "dst_ip": dst_ip, "dst_port": dst_port})


@tool
def batfish_loop_check() -> Dict[str, Any]:
    """[Direct] Detect routing loops in the network."""
    return _batfish_subprocess("loop_check", {})


@tool
def batfish_blackhole_check(dst_prefix: str = "0.0.0.0/0") -> Dict[str, Any]:
    """[Direct] Detect blackhole routes (traffic silently dropped)."""
    return _batfish_subprocess("blackhole_check", {"dst_prefix": dst_prefix})


@tool
def batfish_waypoint_check(src_ip: str, dst_ip: str, waypoint: str) -> Dict[str, Any]:
    """[Direct] Verify traffic passes through a specific waypoint device."""
    return _batfish_subprocess("waypoint_check", {"src_ip": src_ip, "dst_ip": dst_ip, "waypoint": waypoint.lower()})


# ─── Batfish L5 analysis (sync subprocess — fork_snapshot safe) ──────────────

@tool
def batfish_link_failure(node1: str, node2: str, src: Optional[str] = None, dst: Optional[str] = None) -> Dict[str, Any]:
    """[Direct] Simulate a link failure between two nodes and check traffic impact."""
    args = {"node1": node1.lower(), "node2": node2.lower()}
    if src:
        args["src"] = src.lower()
    if dst:
        args["dst"] = dst.lower()
    return _batfish_subprocess("link_failure", args)


@tool
def batfish_multi_link_failure(
    link1_node1: str, link1_node2: str,
    link2_node1: str, link2_node2: str,
    src: str, dst: str,
) -> Dict[str, Any]:
    """[Direct] Simulate TWO links failing simultaneously and check traffic impact."""
    return _batfish_subprocess("multi_link_failure", {
        "link1_node1": link1_node1.lower(), "link1_node2": link1_node2.lower(),
        "link2_node1": link2_node1.lower(), "link2_node2": link2_node2.lower(),
        "src": src.lower(), "dst": dst.lower()})


@tool
def batfish_node_failure(node: str) -> Dict[str, Any]:
    """[Direct] Simulate a node going down and calculate blast radius.
    Returns: affected_count (disrupted flows), newly_blocked_flows list."""
    return _batfish_subprocess("node_failure", {"node": node.lower()})


@tool
def batfish_multi_node_failure(node1: str, node2: str) -> Dict[str, Any]:
    """[Direct] Simulate TWO nodes failing simultaneously and calculate blast radius."""
    return _batfish_subprocess("multi_node_failure", {"node1": node1.lower(), "node2": node2.lower()})


@tool
def batfish_spof_detection() -> Dict[str, Any]:
    """[Direct] Detect Single Points of Failure (SPOF) in the network."""
    return _batfish_subprocess("spof_detection", {})


@tool
def batfish_find_blocker(src: str, dst: str) -> Dict[str, Any]:
    """[Direct] Find which device blocks/drops traffic from src to dst.
    Returns: blocking_device name, disposition, full path."""
    return _batfish_subprocess("find_blocker", {"src": src.lower(), "dst": dst.lower()})


def _lower_params(params: Dict[str, Any], keys: list) -> Dict[str, Any]:
    """Lowercase specific string params for Batfish compatibility."""
    return {k: (v.lower() if isinstance(v, str) and k in keys else v) for k, v in params.items()}


# Keep batfish_advanced_verify as fallback (not in DIRECT_TOOLS)
@tool
def batfish_advanced_verify(
    analysis_type: Literal[
        "acl_blocking",
        "loop_detection",
        "blackhole_detection",
        "waypoint_check",
        "link_failure_impact",
        "node_failure_impact",
        "spof_detection",
    ],
    params: Dict[str, Any] = {},
) -> Dict[str, Any]:
    """[Direct] Run advanced Batfish analysis (generic). Prefer specific tools instead."""
    return _invoke_sync(
        legacy_network_verify,
        {"test_type": analysis_type, "params": params},
    )


# ─── Lab tools ───────────────────────────────────────────────────────────────

@tool
def lab_show_inventory() -> Dict[str, Any]:
    """[Direct] Show lab topology inventory."""
    return _invoke_sync(legacy_lab_manage, {"action": "show_inventory"})


@tool
def lab_get_status(device: Optional[str] = None) -> Dict[str, Any]:
    """[Direct] Get lab device status."""
    return _invoke_sync(
        legacy_lab_manage,
        {"action": "get_status", "params": {"device": device} if device else {}},
    )


@tool
def lab_export_configs(
    output_dir: str = "./snapshot",
    export_xml: bool = True,
    export_yang_json: bool = True,
    devices: Optional[List[str]] = None,
) -> Dict[str, Any]:
    """[Direct] Export device configs from NSO."""
    return _invoke_sync(
        legacy_lab_manage,
        {
            "action": "export_configs",
            "params": {
                "output_dir": output_dir,
                "export_xml": export_xml,
                "export_yang_json": export_yang_json,
                "devices": devices,
            },
        },
    )


@tool
def lab_init_batfish(
    topology_name: Optional[str] = None,
    output_dir: str = "./snapshot",
    devices: Optional[List[str]] = None,
    use_restconf: bool = False,
) -> Dict[str, Any]:
    """[Direct] Initialize Batfish snapshot from lab configs."""
    params: Dict[str, Any] = {
        "output_dir": output_dir,
        "devices": devices,
        "use_restconf": use_restconf,
    }
    if topology_name:
        params["topology_name"] = topology_name
    return _invoke_sync(
        legacy_lab_manage,
        {"action": "init_batfish", "params": params},
    )


# ─── Compat wrappers ────────────────────────────────────────────────────────

@tool
def network_query(category: str, device: Optional[str] = None, params: Optional[Dict] = None) -> Dict[str, Any]:
    """[Direct] Generic network query (legacy compat)."""
    payload: Dict[str, Any] = {"category": category}
    if device:
        payload["device"] = device
    if params:
        payload["params"] = params
    return _invoke_sync(legacy_network_query, payload)


@tool
def network_verify(test_type: str, params: Optional[Dict] = None) -> Dict[str, Any]:
    """[Direct] Generic network verification (legacy compat)."""
    return _invoke_sync(
        legacy_network_verify,
        {"test_type": test_type, "params": params or {}},
    )


@tool
def scan_and_sync(action: str = "scan", **kwargs) -> Dict[str, Any]:
    """[Direct] Scan and sync devices."""
    payload = {"action": action, **kwargs}
    return _invoke_sync(legacy_scan_and_sync, payload)


@tool
def check_logs(device: str, lines: int = 50, keyword: Optional[str] = None) -> Dict[str, Any]:
    """[Direct] Check device logs."""
    return _invoke_sync(
        legacy_check_logs,
        {"device": device, "lines": lines, "keyword": keyword},
    )


@tool
def lab_bootstrap() -> Dict[str, Any]:
    """[Direct] Bootstrap lab environment."""
    return _invoke_sync(legacy_lab_bootstrap, {})


@tool
def lab_manage(action: str, params: Optional[Dict] = None) -> Dict[str, Any]:
    """[Direct] Lab management actions."""
    payload: Dict[str, Any] = {"action": action}
    if params:
        payload["params"] = params
    return _invoke_sync(legacy_lab_manage, payload)


# ─── Export ──────────────────────────────────────────────────────────────────

# Eval용: QA 답변에 사용되는 도구만 노출
DIRECT_TOOLS = [
    # NSO (5) — config 쿼리
    nso_get_device_info,
    nso_get_all_device_info,
    nso_get_interfaces,
    nso_get_all_interfaces,
    nso_get_routing,
    # Batfish basic (4) — 경로/세션/라우팅
    batfish_reachability,
    batfish_traceroute,
    batfish_bgp_sessions,
    batfish_route_table,
    # Batfish L4 (4) — 상세 분석
    batfish_acl_check,
    batfish_loop_check,
    batfish_blackhole_check,
    batfish_waypoint_check,
    # Batfish L5 (6) — What-If 시뮬레이션
    batfish_link_failure,
    batfish_multi_link_failure,
    batfish_node_failure,
    batfish_multi_node_failure,
    batfish_spof_detection,
    batfish_find_blocker,
]

# 전체 도구 (웹서버, Lab 관리 등 포함)
ALL_DIRECT_TOOLS = [
    nso_list_devices,
    nso_get_device_info,
    nso_get_all_device_info,
    nso_get_interfaces,
    nso_get_all_interfaces,
    nso_get_routing,
    nso_get_logs,
    batfish_reachability,
    batfish_traceroute,
    batfish_bgp_sessions,
    batfish_route_table,
    batfish_advanced_verify,
    lab_show_inventory,
    lab_get_status,
    lab_export_configs,
    lab_init_batfish,
    network_query,
    network_verify,
    scan_and_sync,
    check_logs,
    lab_bootstrap,
    lab_manage,
]
