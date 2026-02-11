import pytest
from pydantic import ValidationError

import main
from agent.mcp_client import MCPClient, get_mcp_client, reset_mcp_client


@pytest.mark.asyncio
async def test_update_settings_resets_mcp_client_when_url_changes(monkeypatch):
    old_url = "http://127.0.0.1:19991/mcp"
    new_url = "http://127.0.0.1:19992/mcp"

    monkeypatch.setenv("NETALLY_TOOL_BACKEND", "mcp")
    monkeypatch.setenv("NETALLY_MCP_SERVER_URL", old_url)
    reset_mcp_client()

    old_client = get_mcp_client()
    assert old_client.server_url == old_url

    async def fake_stop():
        return None

    async def fake_start():
        return {"started": True}

    async def fake_health(self):
        return {"ok": True, "tool_count": 22, "server_url": self.server_url}

    monkeypatch.setattr("agent.mcp_server.stop_embedded_mcp_server", fake_stop)
    monkeypatch.setattr("agent.mcp_server.start_embedded_mcp_server", fake_start)
    monkeypatch.setattr(MCPClient, "health_check", fake_health)

    response = await main.update_settings(main.SettingsRequest(mcp_server_url=new_url))
    assert response["status"] == "updated"

    new_client = get_mcp_client()
    assert new_client is not old_client
    assert new_client.server_url == new_url
    assert main.app.state.mcp_health["server_url"] == new_url


@pytest.mark.asyncio
async def test_get_settings_includes_mcp_runtime_fields(monkeypatch):
    monkeypatch.setenv("NETALLY_TOOL_BACKEND", "mcp")
    monkeypatch.setenv("NETALLY_AGENT_BACKEND", "single_executor")
    monkeypatch.setenv("NETALLY_MCP_SERVER_URL", "http://127.0.0.1:18881/mcp")
    monkeypatch.setenv("NETALLY_MCP_ALLOW_MUTATIONS", "false")
    monkeypatch.setenv("NETALLY_TEAM_MULTI_MODULE", "agents.main_netconfig")
    monkeypatch.setenv("NETALLY_TEAM_MULTI_DATASET_TYPE", "netconfig")

    payload = await main.get_settings()
    assert "tool_backend" in payload
    assert "agent_backend" in payload
    assert "agent_prompt_mode" in payload
    assert "bound_tool_count" in payload
    assert "mcp_server_url" in payload
    assert "mcp_allow_mutations" in payload
    assert payload["tool_backend"] == "mcp"
    assert payload["agent_backend"] == "single_executor"
    assert payload["agent_prompt_mode"] == "prompt_only"
    assert isinstance(payload["bound_tool_count"], int)
    assert payload["mcp_server_url"] == "http://127.0.0.1:18881/mcp"
    assert payload["mcp_allow_mutations"] is False
    assert payload["team_multi_module"] == "agents.main_netconfig"
    assert payload["team_multi_dataset_type"] == "netconfig"


@pytest.mark.asyncio
async def test_update_settings_syncs_backend_state_and_mutation_env(monkeypatch):
    monkeypatch.setenv("NETALLY_TOOL_BACKEND", "mcp")
    monkeypatch.setenv("NETALLY_MCP_SERVER_URL", "http://127.0.0.1:18882/mcp")
    reset_mcp_client()

    async def fake_stop():
        return None

    async def fake_start():
        return {"started": True}

    async def fake_health(self):
        return {"ok": True, "tool_count": 22, "server_url": self.server_url}

    monkeypatch.setattr("agent.mcp_server.stop_embedded_mcp_server", fake_stop)
    monkeypatch.setattr("agent.mcp_server.start_embedded_mcp_server", fake_start)
    monkeypatch.setattr(MCPClient, "health_check", fake_health)

    response = await main.update_settings(
        main.SettingsRequest(
            tool_backend="legacy",
            mcp_allow_mutations=True,
            team_multi_module="agents.main_netconfig",
            team_multi_dataset_type="descriptive",
            team_multi_root="/tmp/team-multi",
            team_multi_context_path="/tmp/team-context.txt",
        )
    )
    assert response["status"] == "updated"
    assert main.app.state.tool_backend == "legacy"
    assert main.get_tool_backend() == "legacy"
    assert main.os.getenv("NETALLY_MCP_ALLOW_MUTATIONS") == "true"
    assert main.os.getenv("NETALLY_TEAM_MULTI_MODULE") == "agents.main_netconfig"
    assert main.os.getenv("NETALLY_TEAM_MULTI_DATASET_TYPE") == "descriptive"
    assert main.os.getenv("NETALLY_TEAM_MULTI_ROOT") == "/tmp/team-multi"
    assert main.os.getenv("NETALLY_TEAM_MULTI_CONTEXT_PATH") == "/tmp/team-context.txt"


def test_settings_rejects_invalid_tool_backend():
    with pytest.raises(ValidationError):
        main.SettingsRequest(tool_backend="invalid-backend")


def test_settings_rejects_invalid_agent_backend():
    with pytest.raises(ValidationError):
        main.SettingsRequest(agent_backend="invalid-agent")


def test_settings_rejects_invalid_team_multi_dataset_type():
    with pytest.raises(ValidationError):
        main.SettingsRequest(team_multi_dataset_type="invalid-dataset")
