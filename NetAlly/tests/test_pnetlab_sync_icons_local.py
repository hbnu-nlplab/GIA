import importlib.util
from pathlib import Path


def _load_sync_module():
    # scripts/ is not a python package; load by filepath.
    script = Path(__file__).resolve().parents[1] / "scripts" / "pnetlab_sync_icons.py"
    spec = importlib.util.spec_from_file_location("pnetlab_sync_icons", script)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_pnetlab_sync_icons_local_copies_referenced_icons(tmp_path: Path, monkeypatch):
    mod = _load_sync_module()

    # Build a minimal fake UNetLab tree
    unetlab = tmp_path / "unetlab"
    labs = unetlab / "labs"
    icons = unetlab / "html" / "images" / "icons"
    labs.mkdir(parents=True)
    icons.mkdir(parents=True)

    (icons / "Router.png").write_bytes(b"PNG1")
    (icons / "ASA 5500.png").write_bytes(b"PNG2")

    unl = """<lab>
  <topology>
    <nodes>
      <node id="1" name="R1" type="qemu" icon="Router.png" left="10" top="20">
        <interface id="0" name="e0/0" network_id="1"/>
      </node>
      <node id="2" name="FW1" type="qemu" icon="ASA 5500.png" left="30" top="40">
        <interface id="0" name="e0/0" network_id="1"/>
      </node>
    </nodes>
    <networks>
      <network id="1" name="NET1" type="bridge" icon="cloud.png" visibility="1" left="0" top="0"/>
    </networks>
  </topology>
</lab>
"""
    (labs / "test_nso.unl").write_text(unl, encoding="utf-8")

    out_dir = tmp_path / "out"
    monkeypatch.setenv("PNETLAB_INVENTORY_BACKEND", "labfs_local")
    monkeypatch.setenv("PNETLAB_UNETLAB_ROOT", str(unetlab))
    monkeypatch.setenv("PNETLAB_ICON_ROOT", str(icons))
    monkeypatch.setenv("PNETLAB_LAB_NAME", "test_nso")
    monkeypatch.setenv("PNETLAB_ICON_OUT_DIR", str(out_dir))

    rc = mod.main()
    assert rc == 0

    # cloud.png is referenced by UNL but missing from icon_root, so it's ok if not copied.
    assert (out_dir / "Router.png").read_bytes() == b"PNG1"
    assert (out_dir / "ASA 5500.png").read_bytes() == b"PNG2"

