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

    def get_dashboard_data(self, mode: str = "lab") -> Dict[str, Any]:
        """
        대시보드 요약을 위한 종합 데이터 수집
        - BGP 상태, OSPF 호환성, 인터페이스 상태 등
        
        Args:
            mode: "lab" (실험실) 또는 "production" (운영 환경)
        """
        if not self._builder:
            return {}

        results = {
            "health_score": 100,
            "mode": mode,
            "protocols": {
                "bgp": {"total": 0, "up": 0, "down": 0, "status": "healthy"},
                "ospf": {"total": 0, "up": 0, "down": 0, "status": "healthy"}
            },
            "issues": [],
            "device_status": {},
            "compliance": {"routing": 0, "security": 0}
        }

        try:
            bf = self._builder.bf
            
            # 1. BGP 분석
            try:
                bgp_status = bf.q.bgpSessionStatus().answer().frame()
                results["protocols"]["bgp"]["total"] = len(bgp_status)
                up_sessions = len(bgp_status[bgp_status["Established_Status"] == "ESTABLISHED"])
                down_sessions = results["protocols"]["bgp"]["total"] - up_sessions
                results["protocols"]["bgp"]["up"] = up_sessions
                results["protocols"]["bgp"]["down"] = down_sessions
                
                if down_sessions > 0:
                    results["protocols"]["bgp"]["status"] = "critical" if down_sessions > 2 else "warning"
                    results["health_score"] -= (down_sessions * 5)
                    
                    # 이슈 리스트 추가
                    for _, row in bgp_status[bgp_status["Established_Status"] != "ESTABLISHED"].iterrows():
                        results["issues"].append({
                            "severity": "critical",
                            "type": "BGP_DOWN",
                            "title": f"BGP Down: {row['Node']}",
                            "message": f"BGP session to {row['Remote_Node']} is {row['Established_Status']}",
                            "affected_nodes": [row['Node'], row['Remote_Node']]
                        })
            except Exception as e:
                logger.warning(f"Dashboard BGP analysis failed: {e}")

            # 2. OSPF 분석
            try:
                ospf_status = bf.q.ospfSessionCompatibility().answer().frame()
                results["protocols"]["ospf"]["total"] = len(ospf_status)
                
                if not ospf_status.empty:
                    # Session_Status (더 일반적임) 또는 Config_Status 컬럼 확인
                    status_col = 'Session_Status' if 'Session_Status' in ospf_status.columns else 'Config_Status'
                    
                    if status_col in ospf_status.columns:
                        up_mask = ospf_status[status_col].astype(str).str.contains("ESTABLISHED|SESSION_COMPATIBLE", case=False)
                        up_ospf = len(ospf_status[up_mask])
                        down_ospf = len(ospf_status[~up_mask])
                        
                        results["protocols"]["ospf"]["up"] = up_ospf
                        results["protocols"]["ospf"]["down"] = down_ospf
                        
                        if down_ospf > 0:
                            results["protocols"]["ospf"]["status"] = "warning"
                            results["health_score"] -= (down_ospf * 3)
                            
                            for _, row in ospf_status[~up_mask].iterrows():
                                iface = str(row.get('Interface', 'Unknown'))
                                results["issues"].append({
                                    "severity": "warning",
                                    "type": "OSPF_MISMATCH",
                                    "title": f"OSPF Issue: {iface}",
                                    "message": f"OSPF issue: {row.get(status_col, 'Unknown')}",
                                    "affected_nodes": [row['Interface'].hostname] if hasattr(row.get('Interface'), 'hostname') else []
                                })
            except Exception as e:
                logger.warning(f"Dashboard OSPF analysis failed: {e}")

            # 3. Routing Hygiene 검사
            routing_issues = 0
            try:
                # 3.1 중복 Router ID 검사 (BGP)
                if len(bgp_status) > 0 and 'Local_IP' in bgp_status.columns:
                    router_ids = bgp_status.groupby('Local_IP').size()
                    duplicates = router_ids[router_ids > 1]
                    for router_id in duplicates.index:
                        results["issues"].append({
                            "severity": "critical",
                            "type": "DUPLICATE_ROUTER_ID",
                            "title": f"중복 Router ID 감지: {router_id}",
                            "message": f"여러 장비가 동일한 Router ID ({router_id})를 사용 중입니다.",
                            "affected_nodes": []
                        })
                        routing_issues += 1
                        results["health_score"] -= 10
            except Exception as e:
                logger.warning(f"Router ID check failed: {e}")

            # 4. Security Compliance (Production 모드만)
            security_issues = 0
            if mode == "production":
                try:
                    # 4.1 Plaintext Passwords 검사
                    # 설정 파일에서 'password 0' 또는 'password ' 뒤에 평문이 올 수 있는 패턴 검색
                    # Batfish에서는 'nodeProperties'의 'Domain_Name' 등이 비어있는지 등으로 대체하거나 
                    # 직접 설정 데이터를 파싱해야 함. 여기서는 데모를 위해 nodeProperties 일부 활용
                    props = bf.q.nodeProperties().answer().frame()
                    for _, row in props.iterrows():
                        node = row['Node']
                        # AAA 미설정 체크 (간이)
                        if 'AAA_Authentication' in row and not row['AAA_Authentication']:
                            results["issues"].append({
                                "severity": "warning",
                                "type": "SECURITY_AAA",
                                "title": f"AAA 미설정: {node}",
                                "message": "장비에 AAA 인증이 활성화되어 있지 않습니다.",
                                "affected_nodes": [node]
                            })
                            security_issues += 1
                        
                except Exception as e:
                    logger.warning(f"Security compliance check failed: {e}")

            results["compliance"]["routing"] = max(0, 100 - routing_issues * 10)
            results["compliance"]["security"] = max(0, 100 - security_issues * 10) if mode == "production" else 100

            # 5. 장비별 상태 요약
            for node in self._builder.nodes:
                node_issues = [i for i in results["issues"] if node in i.get("affected_nodes", [])]
                if any(i["severity"] == "critical" for i in node_issues):
                    results["device_status"][node] = "critical"
                elif node_issues:
                    results["device_status"][node] = "warning"
                else:
                    results["device_status"][node] = "healthy"

            results["health_score"] = max(0, results["health_score"])
            return results

        except Exception as e:
            logger.error(f"Error gathering dashboard data: {e}")
            return results

    def get_reachability_matrix(self, src_node: Optional[str] = None) -> List[Dict[str, Any]]:
        """
        장비 간 도달성 분석 (Reachability Matrix)
        - 모든 노드 또는 특정 소스 노드 기준
        """
        if not self._builder:
            return []
            
        bf = self._builder.bf
        from pybatfish.datamodel.flow import HeaderConstraints
        results = []
        
        nodes = self._builder.nodes
        targets = [src_node] if src_node else nodes
        
        for src in targets:
            for dst in nodes:
                if src == dst: continue
                
                try:
                    # 간단한 도달성 체크 (ICMP)
                    tr_res = bf.q.traceroute(
                        startLocation=src,
                        headers=HeaderConstraints(dstIps=self.get_node_ip(dst))
                    ).answer().frame()
                    
                    status = "unknown"
                    message = ""
                    
                    if not tr_res.empty:
                        trace = tr_res['Traces'].iloc[0][0]
                        disp = getattr(trace, 'disposition', 'UNKNOWN')
                        
                        if disp == 'ACCEPTED':
                            status = "success"
                        elif 'DENIED' in disp:
                            status = "error"
                            message = f"Blocked by ACL/Policy ({disp})"
                        elif 'NO_ROUTE' in disp:
                            status = "warning"
                            message = "No routing path to destination"
                        else:
                            status = "error"
                            message = f"Failed: {disp}"
                            
                    results.append({
                        "source": src,
                        "target": dst,
                        "status": status,
                        "message": message
                    })
                except Exception as e:
                    logger.warning(f"Reachability check failed for {src}->{dst}: {e}")
                    
        return results

    def get_bgp_details(self) -> List[Dict[str, Any]]:
        """BGP 세션 상세 정보 반환"""
        if not self._builder: return []
        try:
            df = self._builder.bf.q.bgpSessionStatus().answer().frame()
            if df.empty: return []
            
            # 필요한 컬럼만 추출 및 변환
            # ['Node', 'VRF', 'Local_AS', 'Local_Interface', 'Local_IP', 'Remote_AS', 'Remote_Node', 'Remote_Interface', 'Remote_IP', 'Address_Families', 'Session_Type', 'Established_Status']
            return df.to_dict(orient='records')
        except Exception as e:
            logger.error(f"Failed to get BGP details: {e}")
            return []

    def get_ospf_details(self) -> List[Dict[str, Any]]:
        """OSPF 세션 상세 정보 반환"""
        if not self._builder: return []
        try:
            df = self._builder.bf.q.ospfSessionCompatibility().answer().frame()
            if df.empty: return []
            
            # DataFrame을 dict 리스트로 변환 (Interface 객체 등은 str로 변환 필요)
            results = []
            for _, row in df.iterrows():
                item = row.to_dict()
                # Interface나 IPAddress 같은 Batfish 특수 객체들 문자열 변환
                for k, v in item.items():
                    if hasattr(v, 'hostname') and hasattr(v, 'interface'):
                        item[k] = f"{v.hostname}[{v.interface}]"
                    elif not isinstance(v, (str, int, float, bool, type(None))):
                        item[k] = str(v)
                results.append(item)
            return results
        except Exception as e:
            logger.error(f"Failed to get OSPF details: {e}")
            return []

    def get_node_ip(self, node: str) -> str:
        """노드 대표 IP 가져오기 (Loopback0 선호)"""
        try:
            ifaces = self._builder.bf.q.interfaceProperties(nodes=node).answer().frame()
            # Loopback0 또는 첫 번째 IP가 있는 인터페이스
            lb = ifaces[ifaces['Interface'].astype(str).str.contains('Loopback0')]
            if not lb.empty and len(lb['All_Prefixes'].iloc[0]) > 0:
                return lb['All_Prefixes'].iloc[0][0].split('/')[0]
            
            # IP가 있는 아무 인터페이스나
            with_ip = ifaces[ifaces['All_Prefixes'].apply(lambda x: len(x) > 0)]
            if not with_ip.empty:
                return with_ip['All_Prefixes'].iloc[0][0].split('/')[0]
        except:
            pass
        return "0.0.0.0" # Fallback

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
