import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient

import main
from agent.mcp_client import MCPClient, reset_mcp_client


@pytest_asyncio.fixture
async def api_client():
    transport = ASGITransport(app=main.app)
    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        yield client


@pytest.fixture(autouse=True)
def patch_mcp_runtime(monkeypatch):
    async def fake_stop():
        return None

    async def fake_start():
        return {"started": True}

    async def fake_health(self):
        return {"ok": True, "tool_count": 22, "server_url": self.server_url}

    monkeypatch.setattr("agent.mcp_server.stop_embedded_mcp_server", fake_stop)
    monkeypatch.setattr("agent.mcp_server.start_embedded_mcp_server", fake_start)
    monkeypatch.setattr(MCPClient, "health_check", fake_health)
    reset_mcp_client()


@pytest.mark.asyncio
async def test_get_settings_returns_mcp_runtime_fields(api_client, monkeypatch):
    monkeypatch.setenv("NETALLY_TOOL_BACKEND", "mcp")
    monkeypatch.setenv("NETALLY_AGENT_BACKEND", "single_executor")
    monkeypatch.setenv("NETALLY_MCP_SERVER_URL", "http://127.0.0.1:18881/mcp")
    monkeypatch.setenv("NETALLY_MCP_ALLOW_MUTATIONS", "false")
    monkeypatch.setenv("NETALLY_TEAM_MULTI_MODULE", "agents.main_netconfig")
    monkeypatch.setenv("NETALLY_TEAM_MULTI_DATASET_TYPE", "netconfig")

    response = await api_client.get("/api/settings")
    assert response.status_code == 200

    payload = response.json()
    assert "tool_backend" in payload
    assert "agent_backend" in payload
    assert "agent_prompt_mode" in payload
    assert "bound_tool_count" in payload
    assert "mcp_server_url" in payload
    assert "mcp_allow_mutations" in payload
    assert "team_multi_module" in payload
    assert "team_multi_dataset_type" in payload
    assert isinstance(payload["tool_backend"], str)
    assert isinstance(payload["agent_backend"], str)
    assert isinstance(payload["agent_prompt_mode"], str)
    assert isinstance(payload["bound_tool_count"], int)
    assert isinstance(payload["mcp_server_url"], str)
    assert isinstance(payload["mcp_allow_mutations"], bool)
    assert isinstance(payload["team_multi_module"], str)
    assert isinstance(payload["team_multi_dataset_type"], str)


@pytest.mark.asyncio
async def test_post_settings_accepts_mcp_or_legacy_backend(api_client, monkeypatch):
    monkeypatch.setenv("NETALLY_TOOL_BACKEND", "mcp")
    monkeypatch.setenv("NETALLY_MCP_SERVER_URL", "http://127.0.0.1:18882/mcp")

    to_legacy = await api_client.post("/api/settings", json={"tool_backend": "legacy"})
    assert to_legacy.status_code == 200

    settings_after_legacy = await api_client.get("/api/settings")
    assert settings_after_legacy.status_code == 200
    assert settings_after_legacy.json()["tool_backend"] == "legacy"

    to_mcp = await api_client.post("/api/settings", json={"tool_backend": "mcp"})
    assert to_mcp.status_code == 200

    settings_after_mcp = await api_client.get("/api/settings")
    assert settings_after_mcp.status_code == 200
    assert settings_after_mcp.json()["tool_backend"] == "mcp"


@pytest.mark.asyncio
async def test_post_settings_rejects_invalid_backend_with_422(api_client):
    response = await api_client.post("/api/settings", json={"tool_backend": "invalid-backend"})
    assert response.status_code == 422
    payload = response.json()
    assert "detail" in payload


@pytest.mark.asyncio
async def test_mcp_server_url_update_is_reflected_in_health(api_client, monkeypatch):
    old_url = "http://127.0.0.1:18883/mcp"
    new_url = "http://127.0.0.1:18884/mcp"

    monkeypatch.setenv("NETALLY_TOOL_BACKEND", "mcp")
    monkeypatch.setenv("NETALLY_MCP_SERVER_URL", old_url)
    reset_mcp_client()

    response = await api_client.post("/api/settings", json={"mcp_server_url": new_url})
    assert response.status_code == 200

    health = await api_client.get("/api/health")
    assert health.status_code == 200
    health_payload = health.json()
    assert health_payload["mcp_health"]["server_url"] == new_url
    assert "agent_backend" in health_payload
    assert "agent_runtime_loaded" in health_payload
    assert "bound_tool_count" in health_payload


@pytest.mark.asyncio
async def test_post_settings_allows_clearing_string_values(api_client, monkeypatch):
    monkeypatch.setenv("NSO_BASE_URL", "http://10.0.0.1:8080/restconf")

    response = await api_client.post("/api/settings", json={"nso_base_url": ""})
    assert response.status_code == 200

    settings_after = await api_client.get("/api/settings")
    assert settings_after.status_code == 200
    assert settings_after.json()["nso_base_url"] is None
