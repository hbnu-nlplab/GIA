import pytest

import main


class DummyBatfishNotReady:
    is_available = True
    _builder = None


class DummyBatfishReady:
    is_available = True
    _builder = object()


@pytest.mark.asyncio
async def test_runtime_health_degraded_when_batfish_not_ready_and_services_unconfigured(monkeypatch):
    monkeypatch.setattr(main, "_get_batfish_client", lambda: DummyBatfishNotReady())
    monkeypatch.setenv("BATFISH_SNAPSHOT", "snap-a")
    monkeypatch.delenv("NSO_BASE_URL", raising=False)
    monkeypatch.delenv("PNETLAB_URL", raising=False)
    monkeypatch.delenv("PNETLAB_HOST", raising=False)
    monkeypatch.setenv("PNETLAB_INVENTORY_BACKEND", "api")

    payload = await main.runtime_health()
    assert payload["overall"] == "degraded"
    assert payload["recommendedMode"] == "limited"
    assert payload["services"]["batfish"]["status"] == "not_ready"
    assert payload["services"]["nso"]["status"] == "not_configured"
    assert payload["services"]["pnetlab"]["status"] == "disabled"


@pytest.mark.asyncio
async def test_runtime_health_healthy_when_all_services_ok(monkeypatch):
    class DummyNSOClient:
        def __init__(self, base_url, username, password, timeout=2):
            self.base_url = base_url
            self.username = username
            self.password = password
            self.timeout = timeout

        def get_devices(self):
            return ["R1", "R2"]

    class DummyPnetlabClient:
        def __init__(self, base_url, username="", password="", timeout=2):
            self.base_url = base_url
            self.username = username
            self.password = password
            self.timeout = timeout
            self._is_authenticated = True

        @property
        def is_authenticated(self):
            return self._is_authenticated

        def get_session_topology(self):
            return {"nodes": {"1": {}, "2": {}}, "name": "lab"}

    monkeypatch.setattr(main, "_get_batfish_client", lambda: DummyBatfishReady())
    monkeypatch.setenv("BATFISH_SNAPSHOT", "snap-b")
    monkeypatch.setenv("NSO_BASE_URL", "http://nso:8080/restconf")
    monkeypatch.setenv("NSO_USERNAME", "admin")
    monkeypatch.setenv("NSO_PASSWORD", "admin")
    monkeypatch.setenv("PNETLAB_URL", "http://pnetlab")
    monkeypatch.setenv("PNETLAB_INVENTORY_BACKEND", "api")
    monkeypatch.setenv("PNETLAB_ENABLE_API_AUTH", "true")

    monkeypatch.setattr("agent.clients.nso.NSOClient", DummyNSOClient)
    monkeypatch.setattr("agent.clients.pnetlab.PnetlabClient", DummyPnetlabClient)

    payload = await main.runtime_health()
    assert payload["overall"] == "healthy"
    assert payload["recommendedMode"] == "full"
    assert payload["services"]["batfish"]["status"] == "ready"
    assert payload["services"]["nso"]["status"] == "ok"
    assert payload["services"]["pnetlab"]["status"] == "ok"


@pytest.mark.asyncio
async def test_runtime_health_pnetlab_labfs_mode_skips_api_auth(monkeypatch):
    monkeypatch.setattr(main, "_get_batfish_client", lambda: DummyBatfishReady())
    monkeypatch.delenv("NSO_BASE_URL", raising=False)
    monkeypatch.setenv("PNETLAB_INVENTORY_BACKEND", "labfs_local")
    monkeypatch.setenv("PNETLAB_ENABLE_API_AUTH", "false")

    class ShouldNotConstructPnetlabClient:
        def __init__(self, *args, **kwargs):
            raise AssertionError("PnetlabClient should not be constructed in LabFS health mode")

    monkeypatch.setattr("agent.clients.pnetlab.PnetlabClient", ShouldNotConstructPnetlabClient)

    payload = await main.runtime_health()
    assert payload["services"]["pnetlab"]["status"] == "ok"
    assert payload["services"]["pnetlab"]["backend"] == "labfs_local"
