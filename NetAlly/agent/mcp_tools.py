"""LangChain tool proxies backed by MCP client."""

from __future__ import annotations

from typing import Any, Dict, List, Literal, Optional

from langchain_core.tools import tool

from agent.mcp_client import get_mcp_client


async def _mcp_call(tool_name: str, arguments: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    client = get_mcp_client()
    resp = await client.call_tool(tool_name, arguments or {})
    if resp.get("ok"):
        return resp.get("result", {})

    return {
        "error": resp.get("error", "MCP call failed"),
        "tool": tool_name,
        "raw": resp,
    }


# -----------------------------------------------------------------------------
# 16 core tools
# -----------------------------------------------------------------------------

@tool
async def nso_list_devices() -> Dict[str, Any]:
    """[MCP] List all devices from NSO."""
    return await _mcp_call("nso_list_devices")


@tool
async def nso_get_device_info(device: str) -> Dict[str, Any]:
    """[MCP] Get a device summary from NSO."""
    return await _mcp_call("nso_get_device_info", {"device": device})


@tool
async def nso_get_interfaces(device: str) -> Dict[str, Any]:
    """[MCP] Get interfaces for a device from NSO."""
    return await _mcp_call("nso_get_interfaces", {"device": device})


@tool
async def nso_get_routing(device: str, protocol: Literal["bgp", "ospf"] = "bgp") -> Dict[str, Any]:
    """[MCP] Get routing data (BGP/OSPF) for a device."""
    return await _mcp_call("nso_get_routing", {"device": device, "protocol": protocol})


@tool
async def nso_get_logs(device: str, lines: int = 50, keyword: Optional[str] = None) -> Dict[str, Any]:
    """[MCP] Get recent logs from NSO live-status output."""
    return await _mcp_call(
        "nso_get_logs",
        {"device": device, "lines": lines, "keyword": keyword},
    )


@tool
async def batfish_reachability(src: str, dst: str, protocol: str = "icmp") -> Dict[str, Any]:
    """[MCP] Run Batfish reachability test."""
    return await _mcp_call(
        "batfish_reachability",
        {"src": src, "dst": dst, "protocol": protocol},
    )


@tool
async def batfish_traceroute(src: str, dst: str) -> Dict[str, Any]:
    """[MCP] Run Batfish traceroute."""
    return await _mcp_call("batfish_traceroute", {"src": src, "dst": dst})


@tool
async def batfish_bgp_sessions(device: Optional[str] = None) -> Dict[str, Any]:
    """[MCP] Get Batfish BGP session status."""
    return await _mcp_call("batfish_bgp_sessions", {"device": device})


@tool
async def batfish_route_table(device: str) -> Dict[str, Any]:
    """[MCP] Get Batfish route table for a device."""
    return await _mcp_call("batfish_route_table", {"device": device})


@tool
async def batfish_advanced_verify(
    analysis_type: Literal[
        "acl_blocking",
        "loop_detection",
        "blackhole_detection",
        "waypoint_check",
        "link_failure_impact",
        "node_failure_impact",
        "spof_detection",
    ],
    params: Dict[str, Any],
) -> Dict[str, Any]:
    """[MCP] Run advanced Batfish analysis."""
    return await _mcp_call(
        "batfish_advanced_verify",
        {"analysis_type": analysis_type, "params": params},
    )


@tool
async def lab_show_inventory() -> Dict[str, Any]:
    """[MCP] Show current PNETLab inventory."""
    return await _mcp_call("lab_show_inventory")


@tool
async def lab_get_status(device: Optional[str] = None) -> Dict[str, Any]:
    """[MCP] Get PNETLab status for all devices or one device."""
    return await _mcp_call("lab_get_status", {"device": device})


@tool
async def lab_export_configs(
    output_dir: str = "./snapshot",
    export_xml: bool = True,
    export_yang_json: bool = True,
    devices: Optional[List[str]] = None,
) -> Dict[str, Any]:
    """[MCP] Export device configs from NSO."""
    return await _mcp_call(
        "lab_export_configs",
        {
            "output_dir": output_dir,
            "export_xml": export_xml,
            "export_yang_json": export_yang_json,
            "devices": devices,
        },
    )


@tool
async def lab_init_batfish(
    topology_name: Optional[str] = None,
    output_dir: str = "./snapshot",
    devices: Optional[List[str]] = None,
    use_restconf: bool = False,
) -> Dict[str, Any]:
    """[MCP] Initialize Batfish snapshot via NSO export."""
    return await _mcp_call(
        "lab_init_batfish",
        {
            "topology_name": topology_name,
            "output_dir": output_dir,
            "devices": devices,
            "use_restconf": use_restconf,
        },
    )


@tool
async def sync_scan(
    action: Literal["scan", "sync", "scan_and_sync"] = "scan",
    auto_onboard: bool = False,
    auto_remove: bool = False,
    oob_ip: str = "",
    protocol: Literal["telnet", "ssh"] = "telnet",
) -> Dict[str, Any]:
    """[MCP] Scan/sync reconciliation between PNETLab and NSO."""
    return await _mcp_call(
        "sync_scan",
        {
            "action": action,
            "auto_onboard": auto_onboard,
            "auto_remove": auto_remove,
            "oob_ip": oob_ip,
            "protocol": protocol,
        },
    )


@tool
async def bootstrap_refresh_onboard(
    config_path: Optional[str] = None,
    overrides: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """[MCP] Refresh onboarding for newly discovered devices."""
    return await _mcp_call(
        "bootstrap_refresh_onboard",
        {"config_path": config_path, "overrides": overrides},
    )


# -----------------------------------------------------------------------------
# 6 compatibility wrappers (deprecated)
# -----------------------------------------------------------------------------

@tool
async def network_query(
    category: Literal["device", "interface", "routing", "vrf", "security", "acl"],
    device: Optional[str] = None,
    params: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """[MCP][Deprecated] Compatibility wrapper for legacy network_query."""
    return await _mcp_call(
        "network_query",
        {"category": category, "device": device, "params": params or {}},
    )


@tool
async def network_verify(
    test_type: Literal[
        "reachability",
        "traceroute",
        "bgp_session",
        "route_table",
        "acl_blocking",
        "loop_detection",
        "blackhole_detection",
        "waypoint_check",
        "link_failure_impact",
        "node_failure_impact",
        "spof_detection",
    ],
    params: Dict[str, Any],
) -> Dict[str, Any]:
    """[MCP][Deprecated] Compatibility wrapper for legacy network_verify."""
    return await _mcp_call("network_verify", {"test_type": test_type, "params": params})


@tool
async def lab_manage(
    action: Literal["show_inventory", "get_status", "export_configs", "init_batfish"],
    params: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """[MCP][Deprecated] Compatibility wrapper for legacy lab_manage."""
    return await _mcp_call("lab_manage", {"action": action, "params": params or {}})


@tool
async def scan_and_sync(
    action: Literal["scan", "sync", "scan_and_sync"],
    auto_onboard: bool = False,
    auto_remove: bool = False,
    oob_ip: str = "",
    protocol: Literal["telnet", "ssh"] = "telnet",
) -> Dict[str, Any]:
    """[MCP][Deprecated] Compatibility wrapper for legacy scan_and_sync."""
    return await _mcp_call(
        "scan_and_sync",
        {
            "action": action,
            "auto_onboard": auto_onboard,
            "auto_remove": auto_remove,
            "oob_ip": oob_ip,
            "protocol": protocol,
        },
    )


@tool
async def check_logs(device: str, lines: int = 50, keyword: Optional[str] = None) -> str:
    """[MCP][Deprecated] Compatibility wrapper for legacy check_logs (returns plain text)."""
    result = await _mcp_call(
        "check_logs",
        {"device": device, "lines": lines, "keyword": keyword},
    )
    if isinstance(result, str):
        return result
    if isinstance(result, dict):
        if isinstance(result.get("logs"), str):
            return result["logs"]
        if result.get("error"):
            return f"Error fetching logs: {result['error']}"
    return str(result)


@tool
async def lab_bootstrap(
    action: Literal[
        "enable_ssh",
        "register_nso",
        "check_connectivity",
        "sync_from",
        "detect_changes",
        "sync_changed",
        "diff_report",
        "generate_device_info",
        "refresh_onboard",
        "full",
        "discover_nso",
    ],
    params: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """[MCP][Deprecated] Compatibility wrapper for legacy lab_bootstrap."""
    return await _mcp_call("lab_bootstrap", {"action": action, "params": params or {}})


CORE_TOOLS: List[Any] = [
    nso_list_devices,
    nso_get_device_info,
    nso_get_interfaces,
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
    sync_scan,
    bootstrap_refresh_onboard,
]

COMPATIBILITY_TOOLS: List[Any] = [
    network_query,
    network_verify,
    lab_manage,
    scan_and_sync,
    check_logs,
    lab_bootstrap,
]


def get_core_tools() -> List[Any]:
    """MCP core tools only (16)."""
    return list(CORE_TOOLS)


def get_tools() -> List[Any]:
    """All MCP-backed LangChain tools (16 core + 6 compatibility wrappers)."""
    return list(CORE_TOOLS) + list(COMPATIBILITY_TOOLS)
