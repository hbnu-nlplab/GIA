from contextlib import asynccontextmanager
import socket

import pytest

from agent.mcp_client import MCPClient, reset_mcp_client
from agent.mcp_server import start_embedded_mcp_server, stop_embedded_mcp_server

ALL_EXPECTED_TOOLS = {
    "nso_list_devices",
    "nso_get_device_info",
    "nso_get_interfaces",
    "nso_get_routing",
    "nso_get_logs",
    "batfish_reachability",
    "batfish_traceroute",
    "batfish_bgp_sessions",
    "batfish_route_table",
    "batfish_advanced_verify",
    "lab_show_inventory",
    "lab_get_status",
    "lab_export_configs",
    "lab_init_batfish",
    "sync_scan",
    "bootstrap_refresh_onboard",
    "network_query",
    "network_verify",
    "lab_manage",
    "scan_and_sync",
    "check_logs",
    "lab_bootstrap",
}

READ_ONLY_CALLS = [
    ("nso_list_devices", {}),
    ("nso_get_device_info", {"device": "dummy"}),
    ("nso_get_interfaces", {"device": "dummy"}),
    ("nso_get_routing", {"device": "dummy", "protocol": "bgp"}),
    ("nso_get_logs", {"device": "dummy", "lines": 1}),
    ("batfish_reachability", {"src": "ce1", "dst": "ce2", "protocol": "icmp"}),
    ("batfish_traceroute", {"src": "ce1", "dst": "ce2"}),
    ("batfish_bgp_sessions", {}),
    ("batfish_route_table", {"device": "p1"}),
    ("batfish_advanced_verify", {"analysis_type": "loop_detection", "params": {}}),
    ("lab_show_inventory", {}),
    ("lab_get_status", {}),
]

BLOCKED_MUTATING_CALLS = [
    ("lab_export_configs", {}),
    ("lab_init_batfish", {}),
    ("bootstrap_refresh_onboard", {}),
    ("lab_bootstrap", {"action": "full", "params": {}}),
]


@asynccontextmanager
async def running_mcp_server(
    monkeypatch: pytest.MonkeyPatch,
    allow_mutations: bool = False,
    port: int | None = None,
):
    def pick_free_port() -> int:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.bind(("127.0.0.1", 0))
            return int(sock.getsockname()[1])

    selected_url: str | None = None
    last_started = {}

    for _ in range(5):
        chosen_port = port if port is not None else pick_free_port()
        url = f"http://127.0.0.1:{chosen_port}/mcp"
        monkeypatch.setenv("NETALLY_MCP_SERVER_URL", url)
        monkeypatch.setenv("NETALLY_MCP_ALLOW_MUTATIONS", "true" if allow_mutations else "false")
        reset_mcp_client()
        started = await start_embedded_mcp_server()
        last_started = started
        if started.get("started") is True or started.get("already_running") is True:
            selected_url = url
            break
        await stop_embedded_mcp_server()
        if port is not None:
            break

    assert selected_url is not None, f"failed to start embedded MCP server: {last_started}"

    try:
        yield MCPClient(server_url=selected_url)
    finally:
        await stop_embedded_mcp_server()
        reset_mcp_client()


@pytest.mark.asyncio
async def test_mcp_server_lists_exact_22_tools(monkeypatch):
    async with running_mcp_server(monkeypatch) as client:
        listed = await client.list_tools()
        assert listed.get("ok") is True
        names = {tool["name"] for tool in listed.get("tools", [])}
        assert len(names) == 22
        assert names == ALL_EXPECTED_TOOLS


@pytest.mark.asyncio
async def test_read_only_tools_not_blocked_when_mutations_disabled(monkeypatch):
    async with running_mcp_server(monkeypatch, allow_mutations=False) as client:
        for tool_name, arguments in READ_ONLY_CALLS:
            result = await client.call_tool(tool_name, arguments)
            payload = result.get("result")
            payload_text = str(payload)
            assert "Set NETALLY_MCP_ALLOW_MUTATIONS=true to enable." not in payload_text
            if isinstance(payload, dict):
                assert payload.get("code") != "mutations_blocked"


@pytest.mark.asyncio
async def test_mutating_tools_blocked_when_mutations_disabled(monkeypatch):
    async with running_mcp_server(monkeypatch, allow_mutations=False) as client:
        for tool_name, arguments in BLOCKED_MUTATING_CALLS:
            result = await client.call_tool(tool_name, arguments)
            payload = result.get("result", {})
            payload_code = payload.get("code") if isinstance(payload, dict) else None

            assert result.get("ok") is False
            assert "blocked" in str(result.get("error", "")).lower()
            assert result.get("code") == "mutations_blocked" or payload_code == "mutations_blocked"


@pytest.mark.asyncio
async def test_network_query_security_and_acl_categories_are_accepted(monkeypatch):
    async with running_mcp_server(monkeypatch) as client:
        for category in ("security", "acl"):
            result = await client.call_tool("network_query", {"category": category})
            payload = result.get("result")
            assert isinstance(payload, dict)
            assert "device required" in str(payload.get("error", "")).lower()
