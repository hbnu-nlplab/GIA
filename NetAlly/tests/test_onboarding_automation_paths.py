from typing import Any, Dict, List

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient

import main
from agent.onboarding import DeviceInfo, GlobalSettings, register_devices_nso
import agent.tools as tools


class FakeNSOClient:
    def __init__(self) -> None:
        self.authgroup_calls: List[Dict[str, str]] = []
        self.register_calls: List[Dict[str, Any]] = []
        self.host_key_calls: List[str] = []
        self.sync_calls: List[str] = []

    def create_authgroup(self, group: str, username: str, password: str) -> bool:
        self.authgroup_calls.append(
            {"group": group, "username": username, "password": password}
        )
        return True

    def register_device(self, device_info: Dict[str, Any]) -> bool:
        self.register_calls.append(device_info.copy())
        return True

    def fetch_host_keys(self, device_name: str) -> bool:
        self.host_key_calls.append(device_name)
        return True

    def sync_from(self, device_name: str) -> bool:
        self.sync_calls.append(device_name)
        return device_name == "R1"


@pytest_asyncio.fixture
async def api_client():
    transport = ASGITransport(app=main.app)
    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        yield client


def _sample_global_settings() -> GlobalSettings:
    return GlobalSettings(
        pnetlab_vm_ip="172.16.10.10",
        gateway_ip="172.16.10.1",
        enable_password="",
        admin_password="admin",
        domain_name="lab.local",
        nso_authgroup="default",
        nso_ned_id="cisco-ios-cli-6.110",
        nso_username="admin",
        nso_password="admin",
    )


def test_register_devices_nso_applies_protocol_and_port_rules():
    gs = _sample_global_settings()
    devices = [
        DeviceInfo(name="R1", oob_ip="10.0.0.11", oob_intf="Gig0/0", telnet_port=30011),
        DeviceInfo(name="R2", oob_ip=None, oob_intf="", telnet_port=30022),
    ]
    fake_nso = FakeNSOClient()

    result = register_devices_nso(gs, devices, fake_nso)

    assert result["registered"] == ["R1"]
    assert result["failed"] == ["R2"]
    assert len(fake_nso.authgroup_calls) == 1

    r1 = next(call for call in fake_nso.register_calls if call["name"] == "R1")
    r2 = next(call for call in fake_nso.register_calls if call["name"] == "R2")

    assert r1["protocol"] == "ssh"
    assert r1["oob_ip"] == "10.0.0.11"
    assert r1["port"] == 22

    assert r2["protocol"] == "telnet"
    assert r2["oob_ip"] == "172.16.10.10"
    assert r2["port"] == 30022

    assert fake_nso.host_key_calls == ["R1"]
    assert fake_nso.sync_calls == ["R1", "R2"]


def test_lab_bootstrap_refresh_onboard_only_targets_new_devices(monkeypatch: pytest.MonkeyPatch):
    gs = _sample_global_settings()
    devices = [
        DeviceInfo(name="R1", oob_ip="10.0.0.11", oob_intf="Gig0/0", telnet_port=30011),
        DeviceInfo(name="R2", oob_ip=None, oob_intf="", telnet_port=30022),
    ]
    observed: Dict[str, Any] = {}

    monkeypatch.setattr(tools, "get_pnetlab_client", lambda: object())
    monkeypatch.setattr(tools, "ensure_device_info", lambda *args, **kwargs: {"devices": []})
    monkeypatch.setattr(tools, "parse_config", lambda _cfg: (gs, devices))

    def fake_scan_and_sync(
        action: str,
        auto_onboard: bool = False,
        auto_remove: bool = False,
        oob_ip: str = "localhost",
        protocol: str = "telnet",
    ) -> Dict[str, Any]:
        assert action == "scan"
        assert auto_onboard is False
        assert auto_remove is False
        return {"missing": [{"name": "R2"}, {"name": "R3"}]}

    async def fake_enable_ssh_all(_gs: GlobalSettings, target_devices: List[DeviceInfo]) -> Dict[str, bool]:
        observed["ssh_targets"] = [d.name for d in target_devices]
        return {d.name: True for d in target_devices}

    def fake_register_devices_nso(
        _gs: GlobalSettings, target_devices: List[DeviceInfo], _nso: Any
    ) -> Dict[str, Any]:
        observed["nso_targets"] = [d.name for d in target_devices]
        return {"registered": observed["nso_targets"], "failed": []}

    monkeypatch.setattr(tools, "scan_and_sync", fake_scan_and_sync)
    monkeypatch.setattr(tools, "enable_ssh_all", fake_enable_ssh_all)
    monkeypatch.setattr(tools, "get_nso_client", lambda: object())
    monkeypatch.setattr(tools, "register_devices_nso", fake_register_devices_nso)

    result = tools.lab_bootstrap.invoke({"action": "refresh_onboard", "params": {"config_path": "dummy.json"}})

    assert result["status"] == "completed"
    assert result["missing"] == ["R2", "R3"]
    assert observed["ssh_targets"] == ["R2"]
    assert observed["nso_targets"] == ["R2"]
    assert result["nso"]["registered"] == ["R2"]


@pytest.mark.asyncio
async def test_lab_refresh_uses_mcp_tool_in_mcp_backend(api_client, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("NETALLY_TOOL_BACKEND", "mcp")
    called: Dict[str, Any] = {}

    async def fake_call_mcp_tool(tool_name: str, arguments: Dict[str, Any]) -> Dict[str, Any]:
        called["tool_name"] = tool_name
        called["arguments"] = arguments
        return {"status": "completed", "source": "mcp"}

    monkeypatch.setattr(main, "call_mcp_tool", fake_call_mcp_tool)

    response = await api_client.post(
        "/api/lab/refresh",
        json={"config_path": "Data/Pnetlab/device_info.json", "overrides": {"PNETLAB_VM_IP": "10.10.10.10"}},
    )

    assert response.status_code == 200
    assert response.json()["source"] == "mcp"
    assert called["tool_name"] == "bootstrap_refresh_onboard"
    assert called["arguments"]["config_path"] == "Data/Pnetlab/device_info.json"
    assert called["arguments"]["overrides"] == {"PNETLAB_VM_IP": "10.10.10.10"}


@pytest.mark.asyncio
async def test_lab_refresh_uses_legacy_tool_in_legacy_backend(api_client, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("NETALLY_TOOL_BACKEND", "legacy")

    class FakeBootstrapTool:
        def __init__(self) -> None:
            self.last_payload: Dict[str, Any] = {}

        def invoke(self, payload: Dict[str, Any]) -> Dict[str, Any]:
            self.last_payload = payload
            return {"status": "completed", "source": "legacy"}

    fake_tool = FakeBootstrapTool()
    monkeypatch.setattr(tools, "lab_bootstrap", fake_tool)

    response = await api_client.post(
        "/api/lab/refresh",
        json={"config_path": "Data/Pnetlab/device_info.json", "overrides": {"NSO_AUTHGROUP": "default"}},
    )

    assert response.status_code == 200
    assert response.json()["source"] == "legacy"
    assert fake_tool.last_payload == {
        "action": "refresh_onboard",
        "params": {
            "config_path": "Data/Pnetlab/device_info.json",
            "overrides": {"NSO_AUTHGROUP": "default"},
        },
    }
