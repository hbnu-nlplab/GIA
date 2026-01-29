"""
Batfish Client
Batfish 상호작용 및 파일 스토리지 관리

기능:
- Pnetlab_Data/{topology_name} 디렉토리 관리
- 설정 파일 및 정보 저장
- Batfish 스냅샷 초기화 및 분석
"""

import logging
import json
import shutil
from pathlib import Path
from typing import Dict, Any, List, Optional, Union

# Make_Dataset/src 경로 추가 (BatfishBuilder 사용)
import sys
# agent/clients/batfish.py -> agent/clients -> agent -> LabMate -> GIA
MAKE_DATASET_PATH = Path(__file__).parent.parent.parent.parent / "Make_Dataset" / "src"
sys.path.insert(0, str(MAKE_DATASET_PATH))

try:
    from core_batfish.batfish_builder import BatfishBuilder
    from core_batfish.batfish_base import BATFISH_AVAILABLE
except ImportError:
    BatfishBuilder = None
    BATFISH_AVAILABLE = False

logger = logging.getLogger(__name__)


class BatfishClient:
    """
    Batfish 분석 및 파일 관리 클라이언트
    """
    
    ROOT_DIR = Path(__file__).parent.parent / "Pnetlab_Data"

    def __init__(self, host: str = "localhost"):
        self.host = host
        self._builder: Optional[BatfishBuilder] = None
        self._current_topology: Optional[str] = None
        
        # Root 디렉토리 생성
        self.ROOT_DIR.mkdir(parents=True, exist_ok=True)

    @property
    def is_available(self) -> bool:
        return BATFISH_AVAILABLE and BatfishBuilder is not None

    def init_snapshot(
        self, 
        topology_name: str, 
        configs: Union[Dict[str, str], List[str]], 
        device_info: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        스냅샷 초기화: 파일 저장 -> Batfish 로드
        
        Args:
            topology_name: 토폴로지 이름 (폴더명)
            configs: 설정 파일 내용 ({hostname: content}) 또는 파일 경로 리스트
            device_info: 장비 정보 (JSON 저장용)
            
        Returns:
            초기화 결과
        """
        if not self.is_available:
            return {"error": "Batfish SDK not available"}

        self._current_topology = topology_name
        topology_dir = self.ROOT_DIR / topology_name
        configs_dir = topology_dir / "configs"
        
        # 1. 디렉토리 초기화 (기존 데이터 삭제 후 재생성)
        if topology_dir.exists():
            shutil.rmtree(topology_dir)
        configs_dir.mkdir(parents=True, exist_ok=True)
        
        # 2. device_info.json 저장
        if device_info:
            info_path = topology_dir / f"{topology_name}_device_info.json"
            with open(info_path, "w", encoding="utf-8") as f:
                json.dump(device_info, f, indent=2, ensure_ascii=False)
        
        # 3. Config 파일 저장
        saved_files = []
        if isinstance(configs, dict):
            for name, content in configs.items():
                # 확장자 없으면 .cfg 추가
                filename = name if name.endswith(".cfg") else f"{name}.cfg"
                path = configs_dir / filename
                with open(path, "w", encoding="utf-8") as f:
                    f.write(content)
                saved_files.append(str(path))
                
        elif isinstance(configs, list):
            # 파일 경로 리스트인 경우 복사
            for src_path in configs:
                src = Path(src_path)
                if src.exists():
                    dst = configs_dir / src.name
                    shutil.copy2(src, dst)
                    saved_files.append(str(dst))

        # 4. Batfish 초기화
        try:
            self._builder = BatfishBuilder(
                snapshot_path=str(topology_dir),
                network_name=topology_name
            )
            
            if self._builder.initialize():
                logger.info(f"Batfish initialized for {topology_name}")
                return {
                    "status": "success",
                    "topology": topology_name,
                    "nodes": self._builder.nodes,
                    "saved_files": len(saved_files)
                }
            else:
                return {"error": "Batfish initialization failed"}
                
        except Exception as e:
            logger.error(f"Batfish init error: {e}")
            return {"error": str(e)}

    def load_snapshot(self, topology_name: str) -> bool:
        """
        기존 스냅샷 로드 (Batfish 서비스에 이미 존재하는 경우)
        """
        if not self.is_available:
            return False

        try:
            topology_dir = self.ROOT_DIR / topology_name
            if not topology_dir.exists():
                logger.warning(f"Snapshot directory not found: {topology_dir}")
                return False

            self._current_topology = topology_name
            self._builder = BatfishBuilder(
                snapshot_path=str(topology_dir),
                network_name=topology_name
            )
            
            # 반드시 initialize()를 호출하여 Batfish 세션 연결
            if self._builder.initialize():
                logger.info(f"Successfully loaded snapshot: {topology_name}")
                return True
            else:
                logger.error(f"Failed to initialize Batfish for {topology_name}")
                self._builder = None
                return False

        except Exception as e:
            logger.error(f"Error loading snapshot {topology_name}: {e}")
            self._builder = None
            return False

    def check_reachability(
        self,
        src: str,
        dst: str,
        protocol: str = "icmp",
        dst_port: Optional[int] = None
    ) -> Dict[str, Any]:
        """도달성 검증"""
        if not self._builder:
            return {"error": "Snapshot not initialized"}

        try:
            from pybatfish.datamodel.flow import HeaderConstraints
            
            # IP vs Node 구분 로직 (간단화)
            src_ip = src if "." in src else None
            src_node = src if "." not in src else None
            
            headers = HeaderConstraints(
                srcIps=src_ip,
                dstIps=dst,
                ipProtocols=[protocol.upper()],
                dstPorts=[str(dst_port)] if dst_port else None
            )
            
            result = self._builder.bf.q.reachability(
                pathConstraints={"startLocation": src_node} if src_node else None,
                headers=headers
            ).answer().frame()
            
            if result.empty:
                return {"reachable": False, "reason": "No path"}
                
            first_row = result.iloc[0]
            disposition = str(first_row.get("Flow_Disposition", "UNKNOWN"))
            
            return {
                "reachable": "ACCEPTED" in disposition,
                "disposition": disposition,
                "hops": len(first_row.get("Traces", [[]])[0]) if "Traces" in first_row else 0
            }
            
        except Exception as e:
            return {"error": str(e)}

    def traceroute(self, src: str, dst: str) -> Dict[str, Any]:
        """경로 추적"""
        if not self._builder:
            return {"error": "Snapshot not initialized"}
            
        try:
            from pybatfish.datamodel.flow import HeaderConstraints
            
            result = self._builder.bf.q.traceroute(
                startLocation=src,
                headers=HeaderConstraints(dstIps=dst)
            ).answer().frame()
            
            if result.empty:
                return {"path": [], "found": False}
                
            traces = result.iloc[0].get("Traces", [])
            path = []
            if traces:
                for hop in traces[0]:
                    node = getattr(hop, 'node', str(hop))
                    path.append(node)
                    
            return {
                "found": True,
                "path": path,
                "disposition": str(result.iloc[0].get("Flow_Disposition", "UNKNOWN"))
            }
            
        except Exception as e:
            return {"error": str(e)}

    def get_bgp_sessions(self, device_filter: Optional[str] = None) -> List[Dict[str, Any]]:
        """BGP 세션 상태"""
        if not self._builder:
            return []
            
        try:
            result = self._builder.bf.q.bgpSessionStatus().answer().frame()
            sessions = []
            
            for _, row in result.iterrows():
                node = str(row.get("Node", ""))
                if device_filter and device_filter.lower() not in node.lower():
                    continue
                    
                sessions.append({
                    "node": node,
                    "remote_node": str(row.get("Remote_Node", "")),
                    "status": str(row.get("Established_Status", "UNKNOWN"))
                })
            return sessions
        except Exception:
            return []

    def get_route_table(self, device: str) -> List[Dict[str, Any]]:
        """라우팅 테이블"""
        if not self._builder:
            return []
            
        try:
            result = self._builder.bf.q.routes(nodes=device).answer().frame()
            routes = []
            for _, row in result.iterrows():
                routes.append({
                    "network": str(row.get("Network", "")),
                    "next_hop": str(row.get("Next_Hop", "")),
                    "protocol": str(row.get("Protocol", ""))
                })
            return routes
        except Exception:
            return []
