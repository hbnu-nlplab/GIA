from pathlib import Path

from agent.pnetlab_labfs import (
    _SshReader,
    build_pnetlab_map_from_labfs,
    resolve_inventory_backend,
    resolve_ssh_host,
)


def test_labfs_unl_parser_builds_nodes_and_edges(tmp_path: Path, monkeypatch):
    unetlab = tmp_path / "opt" / "unetlab"
    labs = unetlab / "labs"
    tmp = unetlab / "tmp" / "1" / "13"
    labs.mkdir(parents=True)
    tmp.mkdir(parents=True)

    unl = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<lab name="test_nso" id="x" version="1">
  <topology>
    <nodes>
      <node id="1" type="docker" template="docker" icon="Router.png" left="10" top="20" name="NSO">
        <interface id="1" name="eth1" type="ethernet" network_id="100" label="192.168.1.0/24" style="dotted" color="rgba(208, 2, 27, 1)" width="2" fontsize="13"/>
      </node>
      <node id="2" type="iol" template="iol" icon="Router.png" left="50" top="70" name="R1">
        <interface id="1" name="e0/0" type="ethernet" network_id="100" label="192.168.1.0/24" style="dotted" color="rgba(208, 2, 27, 1)"/>
      </node>
    </nodes>
    <networks>
      <network id="100" type="bridge" name="link100" left="0" top="0" visibility="0" icon="cloud.png"/>
    </networks>
  </topology>
</lab>
"""
    (labs / "test.unl").write_text(unl, encoding="utf-8")
    (tmp / "wrapper.txt").write_text("Device_id = 2\nport = 30013\n", encoding="utf-8")

    monkeypatch.setenv("PNETLAB_UNETLAB_ROOT", str(unetlab))
    monkeypatch.setenv("PNETLAB_LAB_PATH", str(labs / "test.unl"))
    monkeypatch.setenv("PNETLAB_INVENTORY_BACKEND", "labfs_local")

    payload = build_pnetlab_map_from_labfs()
    assert "error" not in payload
    assert len(payload["nodes"]) >= 2
    # hidden net with 2 endpoints => direct edge
    assert any(e.get("source") == "NSO" and e.get("target") == "R1" for e in payload["edges"])


def test_resolve_ssh_host_prefers_vm_ip(monkeypatch):
    monkeypatch.delenv("PNETLAB_SSH_HOST", raising=False)
    monkeypatch.setenv("PNETLAB_VM_IP", "192.0.2.10")
    monkeypatch.setenv("PNETLAB_URL", "http://198.51.100.20")
    assert resolve_ssh_host() == "192.0.2.10"


def test_resolve_inventory_backend_auto_ssh_with_inferred_host(monkeypatch):
    monkeypatch.delenv("PNETLAB_INVENTORY_BACKEND", raising=False)
    monkeypatch.delenv("PNETLAB_SSH_HOST", raising=False)
    monkeypatch.setenv("PNETLAB_VM_IP", "192.0.2.11")
    monkeypatch.setenv("PNETLAB_UNETLAB_ROOT", "/nonexistent-for-test")
    assert resolve_inventory_backend() == "labfs_ssh"


def test_ssh_reader_allows_default_key_resolution(monkeypatch):
    monkeypatch.delenv("PNETLAB_SSH_HOST", raising=False)
    monkeypatch.setenv("PNETLAB_VM_IP", "192.0.2.12")
    monkeypatch.delenv("PNETLAB_SSH_KEY_PATH", raising=False)
    monkeypatch.delenv("PNETLAB_SSH_OPTIONS", raising=False)

    reader = _SshReader()
    assert reader._target == "root@192.0.2.12"
    assert "-i" not in reader._base
