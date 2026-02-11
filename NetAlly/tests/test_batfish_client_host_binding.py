import importlib
from pathlib import Path


class _FakeBuilder:
    init_calls = []

    def __init__(self, snapshot_path: str, network_name: str, batfish_host: str):
        self.snapshot_path = snapshot_path
        self.network_name = network_name
        self.batfish_host = batfish_host
        self.nodes = []
        _FakeBuilder.init_calls.append(
            {
                "snapshot_path": snapshot_path,
                "network_name": network_name,
                "batfish_host": batfish_host,
            }
        )

    def initialize(self) -> bool:
        return True


def test_init_snapshot_passes_batfish_host(tmp_path, monkeypatch):
    batfish_module = importlib.import_module("agent.clients.batfish")
    monkeypatch.setattr(batfish_module, "BATFISH_AVAILABLE", True)
    monkeypatch.setattr(batfish_module, "BatfishBuilder", _FakeBuilder)
    monkeypatch.setattr(batfish_module.BatfishClient, "ROOT_DIR", tmp_path)
    _FakeBuilder.init_calls.clear()

    client = batfish_module.BatfishClient(host="host.docker.internal:30997")
    result = client.init_snapshot("demo_lab", {"r1": "hostname r1\n!"})

    assert result.get("status") == "success"
    assert _FakeBuilder.init_calls[0]["batfish_host"] == "host.docker.internal:30997"


def test_load_snapshot_passes_batfish_host(tmp_path, monkeypatch):
    batfish_module = importlib.import_module("agent.clients.batfish")
    monkeypatch.setattr(batfish_module, "BATFISH_AVAILABLE", True)
    monkeypatch.setattr(batfish_module, "BatfishBuilder", _FakeBuilder)
    monkeypatch.setattr(batfish_module.BatfishClient, "ROOT_DIR", tmp_path)
    _FakeBuilder.init_calls.clear()

    snapshot_dir = Path(tmp_path) / "demo_lab" / "configs"
    snapshot_dir.mkdir(parents=True, exist_ok=True)

    client = batfish_module.BatfishClient(host="host.docker.internal:9997")
    loaded = client.load_snapshot("demo_lab")

    assert loaded is True
    assert _FakeBuilder.init_calls[0]["batfish_host"] == "host.docker.internal:9997"
