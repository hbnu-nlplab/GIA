import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient

import main


@pytest_asyncio.fixture
async def api_client():
    transport = ASGITransport(app=main.app)
    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        yield client


def _assert_protocol_shape(protocol_payload):
    assert isinstance(protocol_payload, dict)
    assert set(protocol_payload.keys()) == {"total", "up", "down", "status"}
    assert isinstance(protocol_payload["total"], int)
    assert isinstance(protocol_payload["up"], int)
    assert isinstance(protocol_payload["down"], int)
    assert isinstance(protocol_payload["status"], str)


@pytest.mark.asyncio
async def test_dashboard_summary_fallback_contract_includes_bgp_and_ospf(api_client, monkeypatch):
    class DummyBatfishClient:
        def __init__(self, host: str):
            self.is_available = False
            self._builder = None

    monkeypatch.setattr("agent.clients.batfish.BatfishClient", DummyBatfishClient)

    response = await api_client.get("/api/dashboard/summary?mode=lab")
    assert response.status_code == 200
    payload = response.json()

    assert isinstance(payload.get("health_score"), int)
    assert payload.get("mode") == "lab"
    assert isinstance(payload.get("issues"), list)
    assert isinstance(payload.get("device_status"), dict)
    assert isinstance(payload.get("compliance"), dict)

    protocols = payload.get("protocols")
    assert isinstance(protocols, dict)
    assert "bgp" in protocols
    assert "ospf" in protocols
    _assert_protocol_shape(protocols["bgp"])
    _assert_protocol_shape(protocols["ospf"])


@pytest.mark.asyncio
async def test_dashboard_summary_normalizes_partial_batfish_payload(api_client, monkeypatch):
    class DummyBatfishClient:
        def __init__(self, host: str):
            self.is_available = True
            self._builder = object()

        def get_dashboard_data(self, mode: str):
            return {
                "health_score": 77,
                "protocols": {"bgp": {"total": 3}},
                "issues": [],
                "device_status": {},
                "compliance": {"routing": 90},
            }

    monkeypatch.setattr("agent.clients.batfish.BatfishClient", DummyBatfishClient)

    response = await api_client.get("/api/dashboard/summary?mode=production")
    assert response.status_code == 200
    payload = response.json()

    assert payload["health_score"] == 77
    assert payload["mode"] == "production"
    assert payload["protocols"]["bgp"]["total"] == 3
    assert payload["protocols"]["bgp"]["up"] == 0
    assert payload["protocols"]["bgp"]["down"] == 0
    assert payload["protocols"]["ospf"]["total"] == 0
    assert payload["compliance"]["routing"] == 90
    assert payload["compliance"]["security"] == 0
