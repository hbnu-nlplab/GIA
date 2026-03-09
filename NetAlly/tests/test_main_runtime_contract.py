import pytest

import main


def test_batfish_client_singleton_reuses_instance_per_host(monkeypatch: pytest.MonkeyPatch):
    created = []

    class DummyBatfishClient:
        def __init__(self, host: str):
            self.host = host
            self.is_available = False
            self._builder = None
            created.append(host)

    monkeypatch.setattr("agent.clients.batfish.BatfishClient", DummyBatfishClient)
    monkeypatch.setenv("BATFISH_HOST", "host-a")
    main.app.state.batfish_client = None

    c1 = main._get_batfish_client()
    c2 = main._get_batfish_client()
    assert c1 is c2
    assert created == ["host-a"]

    monkeypatch.setenv("BATFISH_HOST", "host-b")
    c3 = main._get_batfish_client()
    assert c3 is not c1
    assert created == ["host-a", "host-b"]


@pytest.mark.asyncio
async def test_topology_nso_fallback_handles_device_name_list(monkeypatch: pytest.MonkeyPatch):
    class DummyBatfishClient:
        def __init__(self, host: str):
            self.host = host
            self.is_available = False
            self._builder = None

    class DummyNSOClient:
        def __init__(self, base_url: str, username: str, password: str):
            self.base_url = base_url
            self.username = username
            self.password = password

        def get_devices(self):
            return ["R1", "R2"]

        def get_device_info(self, device: str):
            return {
                "name": device,
                "address": f"10.0.0.{1 if device == 'R1' else 2}",
                "platform": {"name": "ios"},
                "device-type": {"cli": {}},
            }

    monkeypatch.setattr("agent.clients.batfish.BatfishClient", DummyBatfishClient)
    monkeypatch.setattr("agent.clients.nso.NSOClient", DummyNSOClient)
    main.app.state.batfish_client = None

    payload = await main.get_topology(layer="l1")
    assert len(payload.nodes) == 2
    assert payload.nodes[0].id == "R1"
    assert payload.nodes[1].id == "R2"
