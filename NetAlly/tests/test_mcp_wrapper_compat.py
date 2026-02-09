from contextlib import asynccontextmanager

import pytest

from agent.mcp_client import MCPClient, reset_mcp_client
from agent.mcp_server import start_embedded_mcp_server, stop_embedded_mcp_server
from agent.tools import (
    check_logs as legacy_check_logs,
    lab_bootstrap as legacy_lab_bootstrap,
    lab_manage as legacy_lab_manage,
    network_query as legacy_network_query,
    network_verify as legacy_network_verify,
    scan_and_sync as legacy_scan_and_sync,
)

WRAPPER_CASES = [
    ("network_query", legacy_network_query, {"category": "device"}),
    (
        "network_verify",
        legacy_network_verify,
        {"test_type": "reachability", "params": {"src": "ce1", "dst": "ce2", "protocol": "icmp"}},
    ),
    ("lab_manage", legacy_lab_manage, {"action": "show_inventory", "params": {}}),
    (
        "scan_and_sync",
        legacy_scan_and_sync,
        {"action": "scan", "auto_onboard": False, "auto_remove": False, "oob_ip": "localhost", "protocol": "telnet"},
    ),
    ("check_logs", legacy_check_logs, {"device": "dummy", "lines": 1}),
    ("lab_bootstrap", legacy_lab_bootstrap, {"action": "discover_nso", "params": {}}),
]


@asynccontextmanager
async def running_mcp_server(monkeypatch: pytest.MonkeyPatch, port: int):
    url = f"http://127.0.0.1:{port}/mcp"
    monkeypatch.setenv("NETALLY_MCP_SERVER_URL", url)
    monkeypatch.setenv("NETALLY_MCP_ALLOW_MUTATIONS", "false")
    reset_mcp_client()
    try:
        await start_embedded_mcp_server()
        yield MCPClient(server_url=url)
    finally:
        await stop_embedded_mcp_server()
        reset_mcp_client()


@pytest.mark.asyncio
async def test_deprecated_wrappers_keep_legacy_output_shapes(monkeypatch):
    async with running_mcp_server(monkeypatch, port=18921) as client:
        for wrapper_name, legacy_tool, payload in WRAPPER_CASES:
            legacy_result = legacy_tool.invoke(payload)
            mcp_result = await client.call_tool(wrapper_name, payload)

            assert type(mcp_result.get("result")) is type(legacy_result)


@pytest.mark.asyncio
async def test_deprecated_check_logs_returns_plain_text(monkeypatch):
    async with running_mcp_server(monkeypatch, port=18922) as client:
        result = await client.call_tool("check_logs", {"device": "dummy", "lines": 1})
        assert isinstance(result.get("result"), str)
