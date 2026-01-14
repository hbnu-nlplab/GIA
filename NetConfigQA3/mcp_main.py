import asyncio
import logging
import os
import sys
from pathlib import Path
from typing import Any, Dict, List, Literal, Optional

# mcp 라이브러리
from mcp.server.fastmcp import FastMCP

# 프로젝트 루트를 경로에 추가
sys.path.insert(0, str(Path(__file__).resolve().parent))

from mcp_servers.nso_server import NSOServer
from mcp_servers.batfish_server import BatfishServer
from mcp_servers.pnetlab_server import PnetlabServer
from mcp_servers.telemetry_server import TelemetryServer

# 로그 설정
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("mcp_main")

# 1. FastMCP 서버 인스턴스 생성
mcp = FastMCP("NetConfigQA3-Unified-Server")

# 2. 서버 객체 초기화
_nso = NSOServer()
_batfish = BatfishServer()
_pnetlab = PnetlabServer()
_telemetry = TelemetryServer()

# === NSO 도구 노출 ===

@mcp.tool()
async def nso_get_devices() -> Dict[str, Any]:
    """NSO에 등록된 모든 장비 목록을 조회합니다."""
    devices = await asyncio.to_thread(_nso.get_devices)
    return {"devices": devices}

@mcp.tool()
async def nso_get_config(device: str, config_path: str = "") -> Dict[str, Any]:
    """특정 장비의 설정을 조회합니다."""
    return await asyncio.to_thread(_nso.get_config, device, config_path)

@mcp.tool()
async def nso_get_device_info(device: str) -> Dict[str, Any]:
    """특정 장비의 기본 정보(이름, 주소, 포트, authgroup, 장비 타입 등)를 조회합니다."""
    return await asyncio.to_thread(_nso.get_device_info, device)

@mcp.tool()
async def nso_export_configs(
    devices: Optional[List[str]] = None,
    output_dir: str = "./exported_configs",
    export_xml: bool = True,
    export_yang_json: bool = True
) -> Dict[str, Any]:
    """
    장비 설정을 추출합니다 (하이브리드 전략):
    - CFG: Batfish 분석용 (Native CLI)
    - XML: 레거시 호환성
    - YANG JSON: 향후 확장성 (표준 기반)
    """
    return await asyncio.to_thread(
        _nso.export_batfish_configs,
        devices,
        output_dir,
        export_xml,
        export_yang_json
    )

# === Batfish 도구 노출 ===

@mcp.tool()
async def batfish_init(snapshot_path: str) -> Dict[str, Any]:
    """Batfish 분석을 위해 스냅샷을 초기화합니다."""
    # batfish_server.py의 메소드명이 async def init_snapshot 임
    return await _batfish.init_snapshot(snapshot_path)

@mcp.tool()
async def batfish_verify_reachability(src: str, dst: str) -> Dict[str, Any]:
    """두 지점 간의 네트워크 도달성을 확인합니다."""
    return await _batfish.check_reachability(src, dst)

# === PNETLab 도구 노출 ===

@mcp.tool()
async def pnetlab_inventory() -> Dict[str, Any]:
    """현재 PNETLab 실험실의 인벤토리를 조회합니다."""
    return await asyncio.to_thread(_pnetlab.show_inventory)

@mcp.tool()
async def pnetlab_get_status(device: Optional[str] = None) -> Dict[str, Any]:
    """PNETLab 장비의 실행 상태를 확인합니다."""
    return await asyncio.to_thread(_pnetlab.get_status, device)

# 메인 실행
if __name__ == "__main__":
    mcp.run()
