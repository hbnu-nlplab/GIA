import inspect
from typing import Any, Dict, List

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient

import main
import agent.mcp_tools as mcp_tools
from agent.onboarding import (
    assign_missing_oob_ips,
    DeviceInfo,
    GlobalSettings,
    generate_device_info_from_pnetlab,
    register_devices_nso,
)
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


def test_generate_device_info_excludes_default_infra_nodes(tmp_path):
    class FakePnetlab:
        def get_session_topology(self):
            return {"data": {}}

        def get_nodes_from_topology(self, _topology):
            return [
                {"name": "NSO", "status": 2, "telnet_port": 30014, "template": "docker"},
                {"name": "Docker", "status": 2, "telnet_port": 30013, "template": "docker"},
                {"name": "CE01", "status": 2, "telnet_port": 30005, "template": "iol"},
            ]

    out = tmp_path / "device_info.json"
    payload = generate_device_info_from_pnetlab(FakePnetlab(), str(out))
    names = [d.get("name") for d in payload.get("devices", [])]
    assert names == ["CE01"]


def test_scan_and_sync_ignores_infra_nodes(monkeypatch: pytest.MonkeyPatch):
    class FakeNso:
        def get_devices(self):
            return ["CE01", "NSO", "Docker"]

    monkeypatch.setattr(tools, "get_pnetlab_client", lambda: object())
    monkeypatch.setattr(
        tools,
        "_get_inventory_nodes",
        lambda _p: {
            "nodes": [
                {"name": "CE01", "status": 2, "telnet_port": 30005},
                {"name": "NSO", "status": 2, "telnet_port": 30014},
                {"name": "Docker", "status": 2, "telnet_port": 30013},
            ]
        },
    )
    monkeypatch.setattr(tools, "get_nso_client", lambda: FakeNso())

    result = tools.scan_and_sync.invoke(
        {
            "action": "scan",
            "auto_onboard": False,
            "auto_remove": False,
            "oob_ip": "localhost",
            "protocol": "telnet",
        }
    )

    assert result["already_registered"] == ["CE01"]
    assert result["missing"] == []
    assert set(result["ignored_nodes"]) == {"NSO", "Docker"}


def test_scan_and_sync_defaults_are_safe_scan_mode():
    legacy_sig = inspect.signature(tools.scan_and_sync.func)
    assert legacy_sig.parameters["auto_onboard"].default is False
    assert legacy_sig.parameters["oob_ip"].default == ""

    mcp_sig = inspect.signature(mcp_tools.sync_scan.coroutine)
    assert mcp_sig.parameters["auto_onboard"].default is False
    assert mcp_sig.parameters["oob_ip"].default == ""


def test_build_missing_device_candidates_overrides_stale_telnet_port():
    existing = [
        DeviceInfo(name="R1", oob_ip=None, oob_intf="Ethernet0/0", telnet_port=12345),
    ]
    missing = [
        {"name": "R1", "telnet_port": 30011},
        {"name": "R2", "telnet_port": 30022},
    ]

    candidates = tools._build_missing_device_candidates(
        missing_nodes=missing,
        all_devices=existing,
        mgmt_ifaces={"R1": "Ethernet0/1"},
        mgmt_ips={},
        oob_intf_fallback="Ethernet0/0",
    )

    by_name = {d.name: d for d in candidates}
    assert by_name["R1"].telnet_port == 30011
    assert by_name["R1"].oob_intf == "Ethernet0/1"
    assert by_name["R2"].telnet_port == 30022


def test_assign_missing_oob_ips_allocates_from_gateway_subnet():
    gs = _sample_global_settings()
    existing = [DeviceInfo(name="R1", oob_ip="172.16.10.11", oob_intf="Gig0/0", telnet_port=30011)]
    candidates = [
        DeviceInfo(name="R2", oob_ip=None, oob_intf="Gig0/0", telnet_port=30022),
        DeviceInfo(name="R3", oob_ip=None, oob_intf="Gig0/0", telnet_port=30033),
    ]

    assigned = assign_missing_oob_ips(gs, candidates, existing_devices=existing)

    assert assigned["R2"] == "172.16.10.12"
    assert assigned["R3"] == "172.16.10.13"
    assert candidates[0].oob_ip == "172.16.10.12"
    assert candidates[1].oob_ip == "172.16.10.13"


def test_scan_and_sync_skips_non_ssh_ready_candidates(monkeypatch: pytest.MonkeyPatch):
    gs = _sample_global_settings()
    candidates = [
        DeviceInfo(name="R1", oob_ip="10.0.0.11", oob_intf="Gig0/0", telnet_port=30011),
        DeviceInfo(name="R2", oob_ip=None, oob_intf="Gig0/0", telnet_port=30022),
        DeviceInfo(name="R3", oob_ip=None, oob_intf="Gig0/0", telnet_port=0),
    ]
    observed: Dict[str, Any] = {}

    class FakeNso:
        def get_devices(self):
            return []

    monkeypatch.setattr(tools, "get_pnetlab_client", lambda: object())
    monkeypatch.setattr(
        tools,
        "_get_inventory_nodes",
        lambda _p: {
            "nodes": [
                {"name": "R1", "status": 2, "telnet_port": 30011},
                {"name": "R2", "status": 2, "telnet_port": 30022},
                {"name": "R3", "status": 2, "telnet_port": 30033},
            ]
        },
    )
    monkeypatch.setattr(tools, "get_nso_client", lambda: FakeNso())
    monkeypatch.setattr(
        tools,
        "_collect_onboarding_candidates",
        lambda **_kwargs: (gs, list(candidates), list(candidates)),
    )
    monkeypatch.setattr(tools, "save_device_info", lambda *args, **kwargs: None)
    monkeypatch.setattr(tools, "assign_missing_oob_ips", lambda *_args, **_kwargs: {})

    async def fake_enable_ssh_all(_gs: GlobalSettings, target_devices: List[DeviceInfo]) -> Dict[str, bool]:
        observed["ssh_targets"] = [d.name for d in target_devices]
        return {"R1": True, "R2": True, "R3": False}

    def fake_register_devices_nso(
        _gs: GlobalSettings, target_devices: List[DeviceInfo], _nso: Any
    ) -> Dict[str, Any]:
        observed["nso_targets"] = [d.name for d in target_devices]
        return {"registered": ["R1"], "failed": []}

    monkeypatch.setattr(tools, "enable_ssh_all", fake_enable_ssh_all)
    monkeypatch.setattr(tools, "register_devices_nso", fake_register_devices_nso)

    result = tools.scan_and_sync.invoke(
        {
            "action": "sync",
            "auto_onboard": True,
            "auto_remove": False,
        }
    )

    assert observed["ssh_targets"] == ["R1", "R2", "R3"]
    assert observed["nso_targets"] == ["R1"]
    assert result["onboarded"] == ["R1"]
    assert {"device": "R2", "reason": "mgmt_ip_not_discovered"} in result["skipped"]
    assert {"device": "R3", "reason": "console_unreachable"} in result["skipped"]


def test_scan_and_sync_returns_actionable_error_when_nso_unreachable(monkeypatch: pytest.MonkeyPatch):
    class FakeNso:
        def _request(self, method: str, path: str):
            return {"status": "error", "message": "connection refused"}

        def get_devices(self):
            return []

    monkeypatch.setattr(tools, "get_pnetlab_client", lambda: object())
    monkeypatch.setattr(
        tools,
        "_get_inventory_nodes",
        lambda _p: {"nodes": [{"name": "R1", "status": 2, "telnet_port": 30011}]},
    )
    monkeypatch.setattr(tools, "get_nso_client", lambda: FakeNso())

    result = tools.scan_and_sync.invoke(
        {
            "action": "scan",
            "auto_onboard": False,
            "auto_remove": False,
        }
    )

    assert result["code"] == "nso_unreachable"
    assert "NSO RESTCONF is unreachable" in result["error"]
    assert result["debug"]["nso_probe"]["ok"] is False


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
    monkeypatch.setattr(tools, "save_device_info", lambda *args, **kwargs: None)
    monkeypatch.setattr(tools, "assign_missing_oob_ips", lambda *_args, **_kwargs: {})
    monkeypatch.setattr(
        tools,
        "_collect_onboarding_candidates",
        lambda **_kwargs: (
            gs,
            devices,
            [
                DeviceInfo(name="R2", oob_ip="10.0.0.22", oob_intf="Gig0/0", telnet_port=30022),
                DeviceInfo(name="R3", oob_ip=None, oob_intf="Gig0/0", telnet_port=30033),
            ],
        ),
    )

    result = tools.lab_bootstrap.invoke({"action": "refresh_onboard", "params": {"config_path": "dummy.json"}})

    assert result["status"] == "completed"
    assert result["missing"] == ["R2", "R3"]
    assert observed["ssh_targets"] == ["R2", "R3"]
    assert observed["nso_targets"] == ["R2"]
    assert result["nso"]["registered"] == ["R2"]
    assert {"device": "R3", "reason": "mgmt_ip_not_discovered"} in result["skipped"]


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


@pytest.mark.asyncio
async def test_lab_refresh_returns_403_when_mcp_mutations_blocked(api_client, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("NETALLY_TOOL_BACKEND", "mcp")

    async def fake_call_mcp_tool(tool_name: str, arguments: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "error": "bootstrap_refresh_onboard blocked",
            "tool": tool_name,
            "raw": {"code": "mutations_blocked", "tool": tool_name, "error": "blocked"},
        }

    monkeypatch.setattr(main, "call_mcp_tool", fake_call_mcp_tool)

    response = await api_client.post("/api/lab/refresh", json={"config_path": "dummy.json"})
    assert response.status_code == 403
    payload = response.json()
    assert payload["code"] == "mutations_blocked"
    assert payload["tool"] == "bootstrap_refresh_onboard"


@pytest.mark.asyncio
async def test_lab_prepare_returns_403_when_mcp_mutations_blocked(api_client, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("NETALLY_TOOL_BACKEND", "mcp")

    class DummyBatfishClient:
        is_available = True
        _builder = None

        def load_snapshot(self, _snapshot: str) -> bool:
            return False

    async def fake_call_mcp_tool(tool_name: str, arguments: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "error": "lab_init_batfish blocked",
            "tool": tool_name,
            "raw": {"code": "mutations_blocked", "tool": tool_name, "error": "blocked"},
        }

    monkeypatch.setattr(main, "_get_batfish_client", lambda: DummyBatfishClient())
    monkeypatch.setattr(main, "call_mcp_tool", fake_call_mcp_tool)

    response = await api_client.post("/api/lab/prepare", json={"auto_init_batfish": True})
    assert response.status_code == 403
    payload = response.json()
    assert payload["code"] == "mutations_blocked"
    assert payload["tool"] == "lab_init_batfish"
    assert payload["status"] == "blocked"
