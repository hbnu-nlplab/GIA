from pathlib import Path

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient

import main


@pytest_asyncio.fixture
async def api_client():
    transport = ASGITransport(app=main.app)
    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        yield client


@pytest.mark.asyncio
async def test_pnetlab_icon_endpoint_serves_from_root_and_sanitizes(tmp_path: Path, api_client, monkeypatch):
    icon_root = tmp_path / "icons"
    icon_root.mkdir(parents=True)
    # doesn't need to be a valid PNG for FileResponse
    (icon_root / "Router.png").write_bytes(b"PNGDATA")

    monkeypatch.setenv("PNETLAB_ICON_ROOT", str(icon_root))
    monkeypatch.setenv("NETALLY_CACHE_DIR", str(tmp_path / "cache"))

    ok = await api_client.get("/api/pnetlab/icon/Router.png")
    assert ok.status_code == 200
    assert ok.content == b"PNGDATA"

    # Case-insensitive resolution
    ok2 = await api_client.get("/api/pnetlab/icon/router.png")
    assert ok2.status_code == 200
    assert ok2.content == b"PNGDATA"

    bad = await api_client.get("/api/pnetlab/icon/.hidden.png")
    assert bad.status_code == 400
