"""
NSO MCP Server

NSO RESTCONF API 및 Docker CLI를 통한 네트워크 설정 관리
cfg 추출 기능 포함 (Batfish 입력용)

도구:
- nso.get_devices: 장비 목록 조회
- nso.get_config: 설정 조회
- nso.export_batfish_configs: Batfish용 cfg/xml 추출
- nso.run_command: CLI 명령 실행
"""

import os
import sys
import json
import logging
import subprocess
from pathlib import Path
from typing import Dict, Any, List, Optional
from dataclasses import dataclass

# MCP SDK import
try:
    from mcp.server import Server
    from mcp.server.stdio import stdio_server
    from mcp.types import Tool, TextContent
    MCP_AVAILABLE = True
except ImportError:
    MCP_AVAILABLE = False

# 프로젝트 경로 설정
sys.path.insert(0, str(Path(__file__).parent.parent))

from clients.nso import NSOClient
from config.settings import settings

logger = logging.getLogger(__name__)


@dataclass
class ConfigExportResult:
    """cfg/xml/yang 추출 결과 (하이브리드 전략)"""
    device: str
    success: bool
    cfg_path: Optional[str] = None       # Native CLI (Batfish용)
    xml_path: Optional[str] = None       # XML (레거시)
    yang_path: Optional[str] = None      # YANG JSON (향후 확장)
    cfg_size: int = 0
    xml_size: int = 0
    yang_size: int = 0
    error: Optional[str] = None


class NSOServer:
    """
    NSO MCP 서버
    
    RESTCONF API와 Docker CLI를 통해 NSO와 상호작용
    """
    
    def __init__(
        self,
        base_url: Optional[str] = None,
        username: Optional[str] = None,
        password: Optional[str] = None,
        docker_container: str = "cisco-nso-dev",
        timeout: int = 60
    ):
        """
        Args:
            base_url: NSO RESTCONF URL
            username: NSO 사용자명
            password: NSO 비밀번호
            docker_container: NSO Docker 컨테이너 이름
            timeout: 요청 타임아웃
        """
        self.base_url = base_url or settings.nso.base_url
        self.username = username or settings.nso.username
        self.password = password or settings.nso.password
        self.docker_container = docker_container
        self.timeout = timeout
        
        # NSOClient 초기화
        self._client: Optional[NSOClient] = None
        
        # MCP 서버 초기화
        if MCP_AVAILABLE:
            self._server = Server("nso-server")
            self._register_tools()
        else:
            self._server = None
            logger.warning("MCP SDK not available. Server functionality disabled.")
    
    @property
    def client(self) -> NSOClient:
        """NSOClient 싱글톤"""
        if self._client is None:
            self._client = NSOClient(
                base_url=self.base_url,
                username=self.username,
                password=self.password,
                timeout=self.timeout
            )
        return self._client
    
    def _register_tools(self):
        """MCP 도구 등록"""
        if not self._server:
            return
        
        @self._server.list_tools()
        async def list_tools() -> List[Tool]:
            return [
                Tool(
                    name="nso.get_devices",
                    description="NSO에 등록된 모든 장비 목록을 조회합니다",
                    inputSchema={
                        "type": "object",
                        "properties": {},
                        "required": []
                    }
                ),
                Tool(
                    name="nso.get_config",
                    description="장비의 설정을 조회합니다",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "device": {"type": "string", "description": "장비명"},
                            "config_path": {"type": "string", "description": "설정 경로 (예: router/bgp)"}
                        },
                        "required": ["device"]
                    }
                ),
                Tool(
                    name="nso.export_batfish_configs",
                    description="Batfish 분석용 cfg 파일 + YANG JSON을 추출합니다 (하이브리드 전략)",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "devices": {
                                "type": "array",
                                "items": {"type": "string"},
                                "description": "추출할 장비 목록 (비어있으면 전체)"
                            },
                            "output_dir": {"type": "string", "description": "출력 디렉토리"},
                            "export_xml": {"type": "boolean", "description": "XML도 추출할지 여부", "default": True},
                            "export_yang_json": {"type": "boolean", "description": "YANG JSON도 추출할지 여부 (향후 확장성)", "default": True}
                        },
                        "required": ["output_dir"]
                    }
                ),
                Tool(
                    name="nso.run_command",
                    description="장비에서 CLI 명령을 실행합니다",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "device": {"type": "string", "description": "장비명"},
                            "command": {"type": "string", "description": "실행할 명령어"}
                        },
                        "required": ["device", "command"]
                    }
                ),
            ]
        
        @self._server.call_tool()
        async def call_tool(name: str, arguments: Dict[str, Any]) -> List[TextContent]:
            result = await self._handle_tool_call(name, arguments)
            return [TextContent(type="text", text=json.dumps(result, ensure_ascii=False, indent=2))]
    
    async def _handle_tool_call(self, name: str, arguments: Dict[str, Any]) -> Dict[str, Any]:
        """도구 호출 처리"""
        try:
            if name == "nso.get_devices":
                return {"devices": self.get_devices()}
            
            elif name == "nso.get_config":
                device = arguments.get("device")
                config_path = arguments.get("config_path", "")
                return self.get_config(device, config_path)
            
            elif name == "nso.export_batfish_configs":
                devices = arguments.get("devices", [])
                output_dir = arguments.get("output_dir")
                export_xml = arguments.get("export_xml", True)
                export_yang_json = arguments.get("export_yang_json", True)
                return self.export_batfish_configs(devices, output_dir, export_xml, export_yang_json)
            
            elif name == "nso.run_command":
                device = arguments.get("device")
                command = arguments.get("command")
                return {"output": self.run_command(device, command)}
            
            else:
                return {"error": f"Unknown tool: {name}"}
                
        except Exception as e:
            logger.error(f"Tool call error: {e}")
            return {"error": str(e)}
    
    # =========================================================================
    # Public API Methods
    # =========================================================================
    
    def get_devices(self) -> List[str]:
        """NSO에 등록된 장비 목록 반환"""
        return self.client.get_devices()
    
    def get_config(self, device: str, config_path: str = "") -> Dict[str, Any]:
        """장비 설정 조회"""
        return self.client._fetch_config(device, config_path)
    
    def run_command(self, device: str, command: str) -> str:
        """장비에서 CLI 명령 실행"""
        return self.client._run_command(device, command)
    
    def get_device_info(self, device: str) -> Dict[str, Any]:
        """장비 상세 정보 조회"""
        return self.client.get_device_info(device)
    
    def get_interfaces(self, device: str) -> List[Dict[str, Any]]:
        """장비 인터페이스 목록"""
        return self.client.get_interfaces(device)
    
    # =========================================================================
    # Batfish Config Export (3-Config_Export_Batfish.py 통합)
    # =========================================================================
    
    def export_batfish_configs(
        self,
        devices: Optional[List[str]] = None,
        output_dir: str = ".",
        export_xml: bool = True,
        export_yang_json: bool = True
    ) -> Dict[str, Any]:
        """
        Batfish 분석용 cfg/xml 파일 + YANG JSON 추출 (하이브리드 전략)
        
        Args:
            devices: 추출할 장비 목록 (None이면 전체)
            output_dir: 출력 디렉토리
            export_xml: XML도 추출할지 여부
            export_yang_json: YANG JSON도 추출할지 여부 (향후 확장성)
            
        Returns:
            추출 결과 요약
        """
        # 1. 장비 목록 확보
        if not devices:
            devices = self.get_devices()
        
        if not devices:
            return {"error": "No devices found", "results": []}
        
        # 2. 디렉토리 생성
        configs_dir = Path(output_dir) / "configs"  # Batfish용 Native CLI
        xml_dir = Path(output_dir) / "xml" if export_xml else None
        yang_dir = Path(output_dir) / "yang" if export_yang_json else None  # YANG JSON
        
        configs_dir.mkdir(parents=True, exist_ok=True)
        if xml_dir:
            xml_dir.mkdir(parents=True, exist_ok=True)
        if yang_dir:
            yang_dir.mkdir(parents=True, exist_ok=True)
        
        # 3. 각 장비 설정 추출
        results: List[ConfigExportResult] = []
        
        for device in devices:
            result = self._export_device_config(device, configs_dir, xml_dir, yang_dir)
            results.append(result)
        
        # 4. 결과 요약
        success_count = sum(1 for r in results if r.success)
        
        return {
            "status": "completed",
            "total": len(devices),
            "success": success_count,
            "failed": len(devices) - success_count,
            "configs_dir": str(configs_dir),
            "xml_dir": str(xml_dir) if xml_dir else None,
            "yang_dir": str(yang_dir) if yang_dir else None,
            "results": [
                {
                    "device": r.device,
                    "success": r.success,
                    "cfg_path": r.cfg_path,
                    "xml_path": r.xml_path,
                    "yang_path": r.yang_path,
                    "cfg_size": r.cfg_size,
                    "xml_size": r.xml_size,
                    "yang_size": r.yang_size,
                    "error": r.error
                }
                for r in results
            ]
        }
    
    def _export_device_config(
        self,
        device: str,
        configs_dir: Path,
        xml_dir: Optional[Path],
        yang_dir: Optional[Path] = None
    ) -> ConfigExportResult:
        """
        단일 장비 설정 추출 (하이브리드 전략)
        
        - Native CLI (CFG): Batfish 분석용
        - XML: 레거시 호환성
        - YANG JSON: 향후 확장성 (표준 기반)
        """
        result = ConfigExportResult(device=device, success=False)
        
        try:
            # === 1. CFG 추출 (Native CLI) - Batfish용 ===
            # NSO CDB에서 Native CLI 형식으로 직접 조회 (Docker CLI 방식)
            # ⚠️ '| display native'는 필요 없음 (NSO CLI 옵션에 존재하지 않음)
            cmd_cfg = f"show running-config devices device {device} config"
            raw_cfg = self._run_nso_docker_cmd(cmd_cfg)
            
            if not raw_cfg:
                result.error = "Failed to get native config via CLI"
                return result
            
            # CFG 정제 및 저장
            cleaned_cfg = self._clean_config(raw_cfg)
            cfg_path = configs_dir / f"{device}.cfg"
            
            with open(cfg_path, "w", encoding="utf-8") as f:
                f.write(cleaned_cfg)
            
            result.cfg_path = str(cfg_path)
            result.cfg_size = len(cleaned_cfg)
            logger.info(f"✅ Exported Native CLI: {cfg_path} ({result.cfg_size} bytes)")
            
            # === 2. XML 추출 (선택적) ===
            if xml_dir:
                # NSO CDB에서 XML 형식으로 조회
                cmd_xml = f"show running-config devices device {device} config | display xml"
                raw_xml = self._run_nso_docker_cmd(cmd_xml)
                
                if raw_xml:
                    cleaned_xml = self._clean_xml_output(raw_xml)
                    xml_path = xml_dir / f"{device}.xml"
                    with open(xml_path, "w", encoding="utf-8") as f:
                        f.write(cleaned_xml)
                    
                    result.xml_path = str(xml_path)
                    result.xml_size = len(cleaned_xml)
                    logger.info(f"✅ Exported XML: {xml_path} ({result.xml_size} bytes)")
            
            # === 3. YANG JSON 추출 (선택적) - 향후 확장성 ===
            if yang_dir:
                # RESTCONF GET으로 YANG 구조화된 JSON 가져오기
                yang_config = self.client._fetch_config(device)
                
                if yang_config:
                    import json
                    yang_path = yang_dir / f"{device}.json"
                    with open(yang_path, "w", encoding="utf-8") as f:
                        json.dump(yang_config, f, ensure_ascii=False, indent=2)
                    
                    yang_json_str = json.dumps(yang_config, ensure_ascii=False, indent=2)
                    result.yang_path = str(yang_path)
                    result.yang_size = len(yang_json_str)
                    logger.info(f"✅ Exported YANG JSON: {yang_path} ({result.yang_size} bytes)")
            
            result.success = True
            
        except Exception as e:
            result.error = str(e)
            logger.error(f"❌ Export error for {device}: {e}")
        
        return result
    
    def _run_nso_docker_cmd(self, cmd_input: str) -> str:
        """
        NSO CLI 명령어를 Docker 컨테이너 내부에서 실행
        
        ⚠️ NSO CDB 방식 사용 (live-status가 아님!)
        - CDB: NSO에 이미 저장된 설정 (빠르고 안정적)
        - live-status: 실제 장비에 SSH 연결 (느리고 타임아웃 가능)
        
        📚 연구 설계 근거 (Netconfiga3_system.md):
        "Static Facts Database - 스냅샷 기반, 변경 시점이 명확함"
        """
        # heredoc(<<<) 방식으로 명령 전달
        bash_cmd = f'cd ~/ncs-instance && source ~/nso-6.6/ncsrc && ncs_cli -C -u admin <<< "{cmd_input}"'
        full_cmd = ['docker', 'exec', self.docker_container, 'bash', '-c', bash_cmd]
        
        try:
            result = subprocess.run(full_cmd, capture_output=True, text=False, timeout=self.timeout)
            
            # 인코딩 처리
            stdout_text = ""
            if result.stdout:
                for encoding in ['utf-8', 'cp949']:
                    try:
                        stdout_text = result.stdout.decode(encoding)
                        break
                    except UnicodeDecodeError:
                        continue
                else:
                    stdout_text = result.stdout.decode('utf-8', errors='ignore')
            
            return stdout_text
            
        except subprocess.TimeoutExpired:
            raise TimeoutError(f"Command timed out after {self.timeout}s")
        except Exception as e:
            raise RuntimeError(f"Docker command failed: {e}")
    
    def _clean_config(self, raw_config: str) -> str:
        """
        NSO live-status에서 가져온 설정을 Batfish 형식으로 정제
        (3-Config_Export_Batfish.py의 clean_config 함수 포팅)
        """
        lines = raw_config.splitlines()
        cleaned_lines = []
        skip_until_config = True
        in_banner = False
        banner_delimiter = ""
        
        for line in lines:
            # NSO 프롬프트 및 노이즈 제거
            if "admin@ncs#" in line or "admin@ncs%" in line:
                continue
            if "live-status exec" in line or "devices device" in line:
                continue
            if line.strip().endswith("#") and len(line.strip().split()) == 1:
                continue
            if "Building configuration" in line or "Current configuration" in line:
                continue
            if line.strip().startswith("result"):
                continue
            
            # 설정 시작 지점 찾기
            if skip_until_config:
                if line.strip() and (line.strip().startswith("!") or line.strip().startswith("version")):
                    skip_until_config = False
                    cleaned_lines.append(line)
                continue
            
            # Banner 제거
            if line.strip().startswith("banner "):
                banner_delimiter = line.strip()[-1]
                in_banner = True
                continue
            
            if in_banner:
                if line.strip().endswith(banner_delimiter):
                    in_banner = False
                continue
            
            cleaned_lines.append(line)
        
        return "\n".join(cleaned_lines)
    
    def _clean_xml_output(self, raw_output: str) -> str:
        """
        NSO XML 출력에서 프롬프트 및 불필요한 부분 제거
        (3-Config_Export_Batfish.py의 clean_xml_output 함수 포팅)
        """
        lines = raw_output.splitlines()
        xml_lines = []
        in_xml = False
        in_banner_xml = False
        
        for line in lines:
            if "admin@ncs#" in line or "admin@ncs%" in line:
                continue
            if line.strip().startswith("show "):
                continue
            
            if line.strip().startswith("<") and not in_xml:
                in_xml = True
            
            if in_xml:
                if "<banner" in line:
                    in_banner_xml = True
                
                if in_banner_xml:
                    if "</banner>" in line:
                        in_banner_xml = False
                    continue
                
                xml_lines.append(line)
        
        return "\n".join(xml_lines)
    
    # =========================================================================
    # MCP Server Lifecycle
    # =========================================================================
    
    async def run(self):
        """MCP 서버 실행"""
        if not MCP_AVAILABLE:
            raise RuntimeError("MCP SDK not available")
        
        async with stdio_server() as (read_stream, write_stream):
            await self._server.run(read_stream, write_stream)


# CLI Entry Point
if __name__ == "__main__":
    import asyncio
    
    logging.basicConfig(level=logging.INFO)
    server = NSOServer()
    asyncio.run(server.run())
