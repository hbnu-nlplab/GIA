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
# Resolve Make_Dataset/src robustly for both:
# - local dev: <repo>/NetAlly/agent/clients/batfish.py
# - docker image: /app/agent/clients/batfish.py + /app/Make_Dataset/src
def _resolve_make_dataset_path() -> Path:
    this_file = Path(__file__).resolve()
    for ancestor in this_file.parents:
        candidate = ancestor / "Make_Dataset" / "src"
        if candidate.exists():
            return candidate
    # Fallback to the previous relative assumption
    return this_file.parent.parent.parent.parent / "Make_Dataset" / "src"


MAKE_DATASET_PATH = _resolve_make_dataset_path()
if str(MAKE_DATASET_PATH) not in sys.path:
    # Avoid prepending external paths to prevent import shadowing (e.g. "main").
    sys.path.append(str(MAKE_DATASET_PATH))

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
                network_name=topology_name,
                batfish_host=self.host,
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
        기존 스냅샷 로드.
        1) 로컬 디렉토리가 있으면 BatfishBuilder로 초기화
        2) 없으면 Batfish 서버에 이미 로드된 네트워크를 직접 사용 (pybatfish set_network/set_snapshot)
        """
        if not self.is_available:
            return False

        # 방법 1: 로컬 디렉토리 기반
        try:
            topology_dir = self.ROOT_DIR / topology_name
            if topology_dir.exists():
                self._current_topology = topology_name
                self._builder = BatfishBuilder(
                    snapshot_path=str(topology_dir),
                    network_name=topology_name,
                    batfish_host=self.host,
                )
                if self._builder.initialize():
                    logger.info(f"Successfully loaded snapshot from local dir: {topology_name}")
                    return True
                self._builder = None
        except Exception as e:
            logger.warning(f"Local snapshot load failed for {topology_name}: {e}")
            self._builder = None

        # 방법 2: Batfish 서버에 이미 존재하는 네트워크 직접 연결
        try:
            from pybatfish.client.session import Session
            bf_session = Session(host=self.host.split(":")[0] if ":" in self.host else self.host)
            networks = bf_session.list_networks()
            if topology_name in networks:
                bf_session.set_network(topology_name)
                snapshots = bf_session.list_snapshots()
                if snapshots:
                    snap_name = "baseline" if "baseline" in snapshots else snapshots[0]
                    bf_session.set_snapshot(snap_name)
                    # BatfishBuilder 없이 세션만 설정 — traceroute 등 직접 호출용
                    # 임시로 topology_dir 생성하여 BatfishBuilder 초기화
                    topology_dir = self.ROOT_DIR / topology_name / "configs"
                    topology_dir.mkdir(parents=True, exist_ok=True)
                    self._current_topology = topology_name
                    self._builder = BatfishBuilder(
                        snapshot_path=str(self.ROOT_DIR / topology_name),
                        network_name=topology_name,
                        batfish_host=self.host.split(":")[0] if ":" in self.host else self.host,
                    )
                    # initialize()는 이미 서버에 있으므로 set_network/set_snapshot만
                    self._builder._initialized = True
                    self._builder.bf = bf_session
                    self._builder.snapshot_name = snap_name
                    self._builder.nodes = [n for n in bf_session.q.nodeProperties().answer().frame()["Node"]]
                    # node_ips/interfaces 채우기 (L5 link_failure 등에 필요)
                    try:
                        intf_df = bf_session.q.interfaceProperties().answer().frame()
                        for _, row in intf_df.iterrows():
                            intf = row.get("Interface", None)
                            if intf is None:
                                continue
                            node = intf.hostname if hasattr(intf, "hostname") else str(intf).split("[")[0]
                            if node not in self._builder.interfaces:
                                self._builder.interfaces[node] = []
                                self._builder.node_ips[node] = []
                            primary = str(row.get("Primary_Address", ""))
                            ip = primary.split("/")[0] if primary and primary != "None" else ""
                            if ip:
                                self._builder.node_ips[node].append(ip)
                        logger.info(f"Populated node_ips for {len(self._builder.node_ips)} nodes")
                    except Exception as e:
                        logger.warning(f"Failed to populate node_ips: {e}")
                    logger.info(f"Connected to existing Batfish network: {topology_name}/{snap_name} ({len(self._builder.nodes)} nodes)")
                    return True
        except Exception as e:
            logger.warning(f"Batfish server snapshot load failed for {topology_name}: {e}")
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

    def _resolve_location(self, addr: str) -> str:
        """IP 주소를 Batfish 장비명으로 변환.

        Batfish startLocation은 장비명이어야 함 (@enter(IP)는 동작 안 함).
        - 장비명(예: 'PE1') → 소문자로
        - IP(예: '10.0.12.1') → interfaceProperties에서 해당 IP 가진 장비명 검색
        """
        import re
        if not re.match(r'^\d+\.\d+\.\d+\.\d+$', addr):
            return addr.lower()

        # IP → 장비명 매핑: interfaceProperties에서 검색
        try:
            bf = self._builder.bf
            intf_df = bf.q.interfaceProperties(
                properties="Primary_Address"
            ).answer().frame()
            for _, row in intf_df.iterrows():
                primary = str(row.get("Primary_Address", ""))
                # "10.0.12.1/30" contains "10.0.12.1"
                if primary.startswith(addr + "/") or primary == addr:
                    intf_str = str(row.get("Interface", ""))
                    node = intf_str.split("[")[0] if "[" in intf_str else intf_str
                    return node
        except Exception:
            pass

        # Fallback: 장비명 없으면 IP 그대로 (srcIps만 사용, startLocation은 생략)
        return addr

    def traceroute(self, src: str, dst: str) -> Dict[str, Any]:
        """경로 추적"""
        if not self._builder:
            return {"error": "Snapshot not initialized"}

        try:
            from pybatfish.datamodel.flow import HeaderConstraints

            start_loc = self._resolve_location(src)

            import re as _re
            is_ip = bool(_re.match(r'^\d+\.\d+\.\d+\.\d+$', src))
            header_kwargs = {"dstIps": dst}

            if is_ip:
                header_kwargs["srcIps"] = src
            result = self._builder.bf.q.traceroute(
                startLocation=start_loc,
                headers=HeaderConstraints(**header_kwargs)
            ).answer().frame()

            if result.empty:
                return {"path": [], "found": False}

            # 모든 trace 중 가장 긴 경로를 선택 (완전한 경로 우선)
            best_path = []
            best_disposition = "UNKNOWN"
            for _, row in result.iterrows():
                traces = row.get("Traces", [])
                disp = str(row.get("Flow_Disposition", "UNKNOWN"))
                if traces:
                    for trace in traces:
                        hops = [getattr(hop, 'node', str(hop)) for hop in trace]
                        if len(hops) > len(best_path):
                            best_path = hops
                            best_disposition = disp

            return {
                "found": len(best_path) > 0,
                "path": best_path,
                "hop_count": len(best_path),
                "path_str": " -> ".join(best_path),
                "src_resolved": start_loc,
                "disposition": best_disposition,
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
            bgp_status = None
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
                if bgp_status is not None and len(bgp_status) > 0 and 'Local_IP' in bgp_status.columns:
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
        except Exception as e:
            logger.warning("get_node_ip(%s) failed: %s", node, e)
        return "0.0.0.0" # Fallback

    def get_bgp_sessions(self, device_filter: Optional[str] = None) -> Dict[str, Any]:
        """BGP 세션 상태 + 요약 통계"""
        if not self._builder:
            return {"sessions": [], "summary": {}}

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
                    "local_as": str(row.get("Local_AS", "")),
                    "remote_as": str(row.get("Remote_AS", "")),
                    "status": str(row.get("Established_Status", "UNKNOWN")),
                })

            # Compute summary
            established = sum(1 for s in sessions if s["status"] == "ESTABLISHED")
            not_established = len(sessions) - established

            # Per-node peer counts (for under-peered detection)
            from collections import Counter
            node_peer_count = Counter(s["node"] for s in sessions if s["status"] == "ESTABLISHED")
            # iBGP full-mesh: each node should peer with (N-1) nodes in same AS
            as_node_map: Dict[str, set] = {}
            for s in sessions:
                as_node_map.setdefault(s["local_as"], set()).add(s["node"])
            under_peered = []
            for as_no, nodes in as_node_map.items():
                expected = len(nodes) - 1
                if expected > 0:
                    for n in nodes:
                        actual = node_peer_count.get(n, 0)
                        if actual < expected:
                            under_peered.append({"node": n, "as": as_no, "peers": actual, "expected": expected})

            summary = {
                "total_sessions": len(sessions),
                "established": established,
                "not_established": not_established,
                "unique_nodes": len(set(s["node"] for s in sessions)),
                "under_peered_nodes": under_peered,
                "under_peered_count": len(under_peered),
            }

            return {"sessions": sessions, "summary": summary}
        except Exception as e:
            return {"sessions": [], "summary": {}, "error": str(e)}

    def get_route_table(self, device: str) -> Dict[str, Any]:
        """라우팅 테이블 + 요약 통계"""
        if not self._builder:
            return {"routes": [], "route_count": 0}

        try:
            result = self._builder.bf.q.routes(nodes=device).answer().frame()
            routes = []
            for _, row in result.iterrows():
                routes.append({
                    "network": str(row.get("Network", "")),
                    "next_hop": str(row.get("Next_Hop", "")),
                    "protocol": str(row.get("Protocol", ""))
                })
            # Pre-compute counts
            from collections import Counter
            protocol_counts = dict(Counter(r["protocol"] for r in routes))
            return {
                "routes": routes,
                "route_count": len(routes),
                "protocol_counts": protocol_counts,
            }
        except Exception as e:
            return {"routes": [], "route_count": 0, "error": str(e)}
