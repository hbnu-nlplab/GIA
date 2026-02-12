import json
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
def patch_mcp_runtime(monkeypatch, tmp_path):
    async def fake_stop():
        return None

    async def fake_start():
        return {"started": True}

    async def fake_health(self):
        return {"ok": True, "tool_count": 22, "server_url": self.server_url}

    monkeypatch.setattr("agent.mcp_server.stop_embedded_mcp_server", fake_stop)
    monkeypatch.setattr("agent.mcp_server.start_embedded_mcp_server", fake_start)
    monkeypatch.setattr(MCPClient, "health_check", fake_health)
    monkeypatch.setenv("NETALLY_RUNTIME_SETTINGS_PATH", str(tmp_path / "settings.runtime.json"))
    reset_mcp_client()


@pytest.mark.asyncio
async def test_get_settings_returns_mcp_runtime_fields(api_client, monkeypatch):
    monkeypatch.setenv("NETALLY_TOOL_BACKEND", "mcp")
    monkeypatch.setenv("NETALLY_AGENT_BACKEND", "single_executor")
    monkeypatch.setenv("NETALLY_MCP_SERVER_URL", "http://127.0.0.1:18881/mcp")
    monkeypatch.setenv("NETALLY_MCP_ALLOW_MUTATIONS", "false")
    monkeypatch.setenv("NETALLY_TEAM_MULTI_MODULE", "agents.main_netconfig")
    monkeypatch.setenv("NETALLY_TEAM_MULTI_DATASET_TYPE", "netconfig")
    monkeypatch.setenv("PNETLAB_INVENTORY_BACKEND", "labfs_local")
    monkeypatch.setenv("PNETLAB_LAB_NAME", "test_nso")
    monkeypatch.setenv("PNETLAB_NSO_NODE", "NSO")
    monkeypatch.setenv("PNETLAB_EXCLUDE_NODE_NAMES", "NSO,Docker,NetAlly,Admin")
    monkeypatch.setenv("BATFISH_SNAPSHOT", "test_nso")
    monkeypatch.setenv("AUTO_PREPARE_ON_CHAT", "false")
    monkeypatch.setenv("AUTO_INIT_BATFISH", "true")

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
    assert "pnetlab_inventory_backend" in payload
    assert "pnetlab_lab_name" in payload
    assert "pnetlab_nso_node" in payload
    assert "pnetlab_exclude_node_names" in payload
    assert "batfish_snapshot" in payload
    assert "auto_prepare_on_chat" in payload
    assert "auto_init_batfish" in payload
    assert "runtime_settings_path" in payload
    assert "runtime_settings_loaded_keys" in payload
    assert isinstance(payload["tool_backend"], str)
    assert isinstance(payload["agent_backend"], str)
    assert isinstance(payload["agent_prompt_mode"], str)
    assert isinstance(payload["bound_tool_count"], int)
    assert isinstance(payload["mcp_server_url"], str)
    assert isinstance(payload["mcp_allow_mutations"], bool)
    assert isinstance(payload["team_multi_module"], str)
    assert isinstance(payload["team_multi_dataset_type"], str)
    assert isinstance(payload["pnetlab_inventory_backend"], str)
    assert isinstance(payload["pnetlab_lab_name"], str)
    assert isinstance(payload["pnetlab_nso_node"], str)
    assert isinstance(payload["pnetlab_exclude_node_names"], str)
    assert isinstance(payload["batfish_snapshot"], str)
    assert isinstance(payload["auto_prepare_on_chat"], bool)
    assert isinstance(payload["auto_init_batfish"], bool)
    assert isinstance(payload["runtime_settings_path"], str)
    assert isinstance(payload["runtime_settings_loaded_keys"], list)


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


@pytest.mark.asyncio
async def test_post_settings_updates_pnetlab_and_batfish_runtime_fields(api_client):
    response = await api_client.post(
        "/api/settings",
        json={
            "pnetlab_inventory_backend": "labfs_local",
            "pnetlab_lab_name": "test_nso",
            "pnetlab_nso_node": "NSO",
            "pnetlab_exclude_node_names": "NSO,Docker,NetAlly,Admin",
            "batfish_snapshot": "test_nso",
            "auto_prepare_on_chat": True,
            "auto_init_batfish": True,
        },
    )
    assert response.status_code == 200

    settings_after = await api_client.get("/api/settings")
    assert settings_after.status_code == 200
    payload = settings_after.json()
    assert payload["pnetlab_inventory_backend"] == "labfs_local"
    assert payload["pnetlab_lab_name"] == "test_nso"
    assert payload["pnetlab_nso_node"] == "NSO"
    assert payload["pnetlab_exclude_node_names"] == "NSO,Docker,NetAlly,Admin"
    assert payload["batfish_snapshot"] == "test_nso"
    assert payload["auto_prepare_on_chat"] is True
    assert payload["auto_init_batfish"] is True


@pytest.mark.asyncio
async def test_post_settings_persists_runtime_settings_file(api_client, monkeypatch, tmp_path):
    runtime_file = tmp_path / "runtime.settings.json"
    monkeypatch.setenv("NETALLY_RUNTIME_SETTINGS_PATH", str(runtime_file))

    response = await api_client.post(
        "/api/settings",
        json={
            "pnetlab_lab_name": "lab_alpha",
            "mcp_allow_mutations": True,
        },
    )
    assert response.status_code == 200
    assert runtime_file.exists()

    payload = json.loads(runtime_file.read_text(encoding="utf-8"))
    assert payload["PNETLAB_LAB_NAME"] == "lab_alpha"
    assert payload["NETALLY_MCP_ALLOW_MUTATIONS"] == "true"

    clear_response = await api_client.post("/api/settings", json={"pnetlab_lab_name": ""})
    assert clear_response.status_code == 200
    updated = json.loads(runtime_file.read_text(encoding="utf-8"))
    assert "PNETLAB_LAB_NAME" not in updated
