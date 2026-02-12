"""NetAlly MCP server (MCP-lite).

Exposes 16 core tools plus 6 deprecated compatibility wrappers.
"""

from __future__ import annotations

import asyncio
import os
from typing import Any, Dict, List, Literal, Optional
from urllib.parse import urlparse

import uvicorn
from mcp.server.fastmcp import FastMCP

from agent.tools import (
    check_logs as legacy_check_logs,
    lab_bootstrap as legacy_lab_bootstrap,
    lab_manage as legacy_lab_manage,
    network_query as legacy_network_query,
    network_verify as legacy_network_verify,
    scan_and_sync as legacy_scan_and_sync,
)

DEFAULT_MCP_URL = "http://127.0.0.1:8811/mcp"

_mcp_instance: FastMCP | None = None
_mcp_server_task: asyncio.Task | None = None
_mcp_uvicorn_server: uvicorn.Server | None = None


def _mcp_server_url() -> str:
    return os.getenv("NETALLY_MCP_SERVER_URL", DEFAULT_MCP_URL)


def _parse_runtime_from_url(url: str) -> tuple[str, int, str]:
    parsed = urlparse(url)
    host = parsed.hostname or "127.0.0.1"
    port = parsed.port or 8811
    path = parsed.path or "/mcp"
    return host, port, path


def _allow_mutations() -> bool:
    return os.getenv("NETALLY_MCP_ALLOW_MUTATIONS", "false").lower() == "true"


async def _invoke_legacy(tool_obj: Any, payload: Dict[str, Any]) -> Any:
    return await asyncio.to_thread(tool_obj.invoke, payload)


def _blocked(tool_name: str, reason: str = "mutating operation") -> Dict[str, Any]:
    return {
        "error": f"{tool_name} blocked: {reason}. Set NETALLY_MCP_ALLOW_MUTATIONS=true to enable.",
        "code": "mutations_blocked",
        "blocked": True,
        "tool": tool_name,
    }


def _build_server() -> FastMCP:
    host, port, stream_path = _parse_runtime_from_url(_mcp_server_url())
    mcp = FastMCP(
        "NetAlly-MCP-lite",
        host=host,
        port=port,
        streamable_http_path=stream_path,
        log_level="INFO",
    )

    # ---------------------------------------------------------------------
    # 16 core MCP tools
    # ---------------------------------------------------------------------

    @mcp.tool(name="nso_list_devices")
    async def nso_list_devices() -> Dict[str, Any]:
        return await _invoke_legacy(legacy_network_query, {"category": "device"})

    @mcp.tool(name="nso_get_device_info")
    async def nso_get_device_info(device: str) -> Dict[str, Any]:
        return await _invoke_legacy(
            legacy_network_query,
            {"category": "device", "device": device},
        )

    @mcp.tool(name="nso_get_interfaces")
    async def nso_get_interfaces(device: str) -> Dict[str, Any]:
        return await _invoke_legacy(
            legacy_network_query,
            {"category": "interface", "device": device},
        )

    @mcp.tool(name="nso_get_routing")
    async def nso_get_routing(device: str, protocol: Literal["bgp", "ospf"] = "bgp") -> Dict[str, Any]:
        return await _invoke_legacy(
            legacy_network_query,
            {
                "category": "routing",
                "device": device,
                "params": {"protocol": protocol},
            },
        )

    @mcp.tool(name="nso_get_logs")
    async def nso_get_logs(device: str, lines: int = 50, keyword: Optional[str] = None) -> Dict[str, Any]:
        data = await _invoke_legacy(
            legacy_check_logs,
            {"device": device, "lines": lines, "keyword": keyword},
        )
        return {"logs": data}

    @mcp.tool(name="batfish_reachability")
    async def batfish_reachability(src: str, dst: str, protocol: str = "icmp") -> Dict[str, Any]:
        return await _invoke_legacy(
            legacy_network_verify,
            {
                "test_type": "reachability",
                "params": {"src": src, "dst": dst, "protocol": protocol},
            },
        )

    @mcp.tool(name="batfish_traceroute")
    async def batfish_traceroute(src: str, dst: str) -> Dict[str, Any]:
        return await _invoke_legacy(
            legacy_network_verify,
            {
                "test_type": "traceroute",
                "params": {"src": src, "dst": dst},
            },
        )

    @mcp.tool(name="batfish_bgp_sessions")
    async def batfish_bgp_sessions(device: Optional[str] = None) -> Dict[str, Any]:
        return await _invoke_legacy(
            legacy_network_verify,
            {
                "test_type": "bgp_session",
                "params": {"device": device},
            },
        )

    @mcp.tool(name="batfish_route_table")
    async def batfish_route_table(device: str) -> Dict[str, Any]:
        return await _invoke_legacy(
            legacy_network_verify,
            {
                "test_type": "route_table",
                "params": {"device": device},
            },
        )

    @mcp.tool(name="batfish_advanced_verify")
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
        return await _invoke_legacy(
            legacy_network_verify,
            {"test_type": analysis_type, "params": params},
        )

    @mcp.tool(name="lab_show_inventory")
    async def lab_show_inventory() -> Dict[str, Any]:
        return await _invoke_legacy(legacy_lab_manage, {"action": "show_inventory"})

    @mcp.tool(name="lab_get_status")
    async def lab_get_status(device: Optional[str] = None) -> Dict[str, Any]:
        return await _invoke_legacy(
            legacy_lab_manage,
            {"action": "get_status", "params": {"device": device} if device else {}},
        )

    @mcp.tool(name="lab_export_configs")
    async def lab_export_configs(
        output_dir: str = "./snapshot",
        export_xml: bool = True,
        export_yang_json: bool = True,
        devices: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        if not _allow_mutations():
            return _blocked("lab_export_configs")
        return await _invoke_legacy(
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

    @mcp.tool(name="lab_init_batfish")
    async def lab_init_batfish(
        topology_name: Optional[str] = None,
        output_dir: str = "./snapshot",
        devices: Optional[List[str]] = None,
        use_restconf: bool = False,
    ) -> Dict[str, Any]:
        if not _allow_mutations():
            return _blocked("lab_init_batfish")
        params: Dict[str, Any] = {
            "output_dir": output_dir,
            "devices": devices,
            "use_restconf": use_restconf,
        }
        if topology_name:
            params["topology_name"] = topology_name
        return await _invoke_legacy(
            legacy_lab_manage,
            {"action": "init_batfish", "params": params},
        )

    @mcp.tool(name="sync_scan")
    async def sync_scan(
        action: Literal["scan", "sync", "scan_and_sync"] = "scan",
        auto_onboard: bool = False,
        auto_remove: bool = False,
        oob_ip: str = "localhost",
        protocol: Literal["telnet", "ssh"] = "telnet",
    ) -> Dict[str, Any]:
        will_mutate = action in {"sync", "scan_and_sync"} and (auto_onboard or auto_remove)
        if will_mutate and not _allow_mutations():
            return _blocked("sync_scan")
        return await _invoke_legacy(
            legacy_scan_and_sync,
            {
                "action": action,
                "auto_onboard": auto_onboard,
                "auto_remove": auto_remove,
                "oob_ip": oob_ip,
                "protocol": protocol,
            },
        )

    @mcp.tool(name="bootstrap_refresh_onboard")
    async def bootstrap_refresh_onboard(
        config_path: Optional[str] = None,
        overrides: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        if not _allow_mutations():
            return _blocked("bootstrap_refresh_onboard")
        params: Dict[str, Any] = {}
        if config_path:
            params["config_path"] = config_path
        if overrides:
            params["overrides"] = overrides
        return await _invoke_legacy(
            legacy_lab_bootstrap,
            {"action": "refresh_onboard", "params": params},
        )

    # ---------------------------------------------------------------------
    # 6 compatibility wrappers (deprecated)
    # ---------------------------------------------------------------------

    @mcp.tool(
        name="network_query",
        description="Deprecated compatibility wrapper. Prefer nso_* tools.",
    )
    async def network_query(
        category: Literal["device", "interface", "routing", "vrf", "security", "acl"],
        device: Optional[str] = None,
        params: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        return await _invoke_legacy(
            legacy_network_query,
            {"category": category, "device": device, "params": params or {}},
        )

    @mcp.tool(
        name="network_verify",
        description="Deprecated compatibility wrapper. Prefer batfish_* tools.",
    )
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
        return await _invoke_legacy(
            legacy_network_verify,
            {"test_type": test_type, "params": params},
        )

    @mcp.tool(
        name="lab_manage",
        description="Deprecated compatibility wrapper. Prefer lab_* tools.",
    )
    async def lab_manage(
        action: Literal["show_inventory", "get_status", "export_configs", "init_batfish"],
        params: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        if action in {"export_configs", "init_batfish"} and not _allow_mutations():
            return _blocked("lab_manage", reason=f"action={action}")
        return await _invoke_legacy(
            legacy_lab_manage,
            {"action": action, "params": params or {}},
        )

    @mcp.tool(
        name="scan_and_sync",
        description="Deprecated compatibility wrapper. Prefer sync_scan.",
    )
    async def scan_and_sync(
        action: Literal["scan", "sync", "scan_and_sync"],
        auto_onboard: bool = False,
        auto_remove: bool = False,
        oob_ip: str = "localhost",
        protocol: Literal["telnet", "ssh"] = "telnet",
    ) -> Dict[str, Any]:
        will_mutate = action in {"sync", "scan_and_sync"} and (auto_onboard or auto_remove)
        if will_mutate and not _allow_mutations():
            return _blocked("scan_and_sync")
        return await _invoke_legacy(
            legacy_scan_and_sync,
            {
                "action": action,
                "auto_onboard": auto_onboard,
                "auto_remove": auto_remove,
                "oob_ip": oob_ip,
                "protocol": protocol,
            },
        )

    @mcp.tool(
        name="check_logs",
        description="Deprecated compatibility wrapper. Prefer nso_get_logs.",
    )
    async def check_logs(device: str, lines: int = 50, keyword: Optional[str] = None) -> str:
        return await _invoke_legacy(
            legacy_check_logs,
            {"device": device, "lines": lines, "keyword": keyword},
        )

    @mcp.tool(
        name="lab_bootstrap",
        description="Deprecated compatibility wrapper. Prefer bootstrap_refresh_onboard.",
    )
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
        mutating_actions = {
            "enable_ssh",
            "register_nso",
            "sync_from",
            "sync_changed",
            "generate_device_info",
            "refresh_onboard",
            "full",
        }
        if action in mutating_actions and not _allow_mutations():
            return _blocked("lab_bootstrap", reason=f"action={action}")
        return await _invoke_legacy(
            legacy_lab_bootstrap,
            {"action": action, "params": params or {}},
        )

    return mcp


def get_mcp_server() -> FastMCP:
    global _mcp_instance
    if _mcp_instance is None:
        _mcp_instance = _build_server()
    return _mcp_instance


async def start_embedded_mcp_server() -> Dict[str, Any]:
    """Start MCP server in-process using a background uvicorn task."""
    global _mcp_server_task, _mcp_uvicorn_server

    if _mcp_server_task and not _mcp_server_task.done():
        return {"started": False, "already_running": True}

    host, port, _ = _parse_runtime_from_url(_mcp_server_url())
    app = get_mcp_server().streamable_http_app()

    # Streamable HTTP transport does not require websocket support.
    # Force ws="none" to avoid importing deprecated websockets.legacy paths.
    config = uvicorn.Config(app, host=host, port=port, log_level="warning", ws="none")
    server = uvicorn.Server(config)
    task = asyncio.create_task(server.serve())

    _mcp_uvicorn_server = server
    _mcp_server_task = task

    await asyncio.sleep(0.25)
    if task.done() and task.exception() is not None:
        return {"started": False, "error": str(task.exception())}

    return {
        "started": True,
        "host": host,
        "port": port,
        "url": _mcp_server_url(),
    }


async def stop_embedded_mcp_server() -> None:
    """Stop background MCP server task if running."""
    global _mcp_instance, _mcp_server_task, _mcp_uvicorn_server

    if _mcp_uvicorn_server is not None:
        _mcp_uvicorn_server.should_exit = True

    if _mcp_server_task is not None:
        try:
            await asyncio.wait_for(_mcp_server_task, timeout=3)
        except Exception:
            pass

    _mcp_server_task = None
    _mcp_uvicorn_server = None
    _mcp_instance = None


if __name__ == "__main__":
    # Standalone execution (for tests/manual run): python -m agent.mcp_server
    get_mcp_server().run(transport="streamable-http")
