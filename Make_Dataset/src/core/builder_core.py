from __future__ import annotations
from typing import Dict, Any, List, Set, Tuple, Union
import json
import re
import copy
import random
from itertools import combinations
from collections import defaultdict, deque

class BuilderCore:
    """
    Facts → expected_answer 계산 엔진.
    - 핵심 메트릭 연산(_precompute, _answer_for_metric)
    - DSL 확장(expand_from_dsl)
    """
    def __init__(self, facts: Union[List[Dict[str, Any]], Dict[str, Any]]):
        self.facts = facts

        if isinstance(facts, dict) and "devices" in facts:
            self.devices = facts["devices"]
        elif isinstance(facts, list):
            self.devices = facts
        else:
            self.devices = []
        self.host_index = { (d.get("system",{}).get("hostname") or d.get("file")): d for d in self.devices }
        self.loop_ip_index = {}
        for d in self.devices:
            host = d.get("system",{}).get("hostname") or d.get("file")
            ip = self._loop_ip(d)
            if ip:
                self.loop_ip_index[ip] = host

    # ---------- helpers ----------
    def _hostname(self, d) -> str:
        return d.get("system",{}).get("hostname") or d.get("file") or "unknown"

    def _loop_ip(self, d) -> str | None:
        for i in d.get("interfaces", []) or []:
            if (i.get("name") or "").lower().startswith("loopback"):
                ip = (i.get("ipv4") or "").split("/",1)[0]
                if ip: return ip
        return None

    def _bgp(self, d):  return d.get("routing",{}).get("bgp",{}) or {}
    def _bgp_neighbors(self, d):  return self._bgp(d).get("neighbors",[]) or []
    def _bgp_vrfs(self, d):  return self._bgp(d).get("vrfs",[]) or []
    def _bgp_local_as(self, d):  return self._bgp(d).get("local_as")
    def _ospf(self, d): return d.get("routing",{}).get("ospf",{}) or {}
    def _ssh_on(self,d): return d.get("security",{}).get("ssh",{}).get("present",False)
    def _aaa_on(self,d): return d.get("security",{}).get("aaa",{}).get("present",False)
    def _services_vrf(self, d): return d.get("services",{}).get("vrf",[]) or []
    def _l2vpns(self, d): return d.get("services",{}).get("l2vpn",[]) or []

    def _is_supported_answer(self, answer_type: str, value: Any) -> bool:
        if value is None:
            return False
        at = (answer_type or "").lower()
        if at in ("set", "list"):
            return isinstance(value, (list, set, tuple))
        if at in ("map", "dict"):
            return isinstance(value, dict)
        if at == "text":
            try:
                str(value)
                return True
            except Exception:
                return False
        return True

    def _as_groups(self):
        groups={}
        for d in self.devices:
            las=self._bgp_local_as(d)
            if not las: continue
            groups.setdefault(las,[]).append(d)
        return groups

    # ---------- 공통 계산(여러 테스트에서 재활용할 집합/맵) ----------
    def _precompute(self) -> Dict[str, Any]:
        pre: Dict[str, Any] = {}

        # BGP missing_pairs / under_peered (AS 단위)
        missing_by_as: Dict[str, Set[str]] = {}
        under_by_as: Dict[str, Set[str]] = {}
        for asn, group in self._as_groups().items():
            loop_of = { (d.get("system",{}).get("hostname") or d.get("file")): self._loop_ip(d) for d in group }
            host_peers: Dict[str, Set[str]] = {}
            for d in group:
                host = d.get("system",{}).get("hostname") or d.get("file")
                peers = { (n.get("id") or n.get("ip")) for n in self._bgp_neighbors(d) if (n.get("id") or n.get("ip")) }
                host_peers[host] = peers
            miss: Set[str] = set()
            hosts = list(host_peers.keys())
            for i in range(len(hosts)):
                for j in range(i+1, len(hosts)):
                    a,b = hosts[i], hosts[j]
                    a2b = loop_of.get(b); b2a = loop_of.get(a)
                    a_has = (a2b in host_peers[a]) if a2b else False
                    b_has = (b2a in host_peers[b]) if b2a else False
                    if not (a_has and b_has):
                        miss.add(f"{a}<->{b}")
            missing_by_as[asn] = miss
            loop_set = { self._loop_ip(e) for e in group if self._loop_ip(e) }
            under: Set[str] = set()
            for d in group:
                host = d.get("system",{}).get("hostname") or d.get("file")
                self_ip = self._loop_ip(d)
                expected = max(0, len(loop_set - ({self_ip} if self_ip else set())))
                peers = { (n.get("id") or n.get("ip")) for n in self._bgp_neighbors(d) if (n.get("id") or n.get("ip")) }
                if len(peers) < expected:
                    under.add(host)
            under_by_as[asn] = under
        pre["bgp_missing_pairs_by_as"] = missing_by_as
        pre["bgp_under_by_as"] = under_by_as

        # VRF without RT pairs
        without_rt: List[str] = []
        for d in self.devices:
            host = d.get("system",{}).get("hostname") or d.get("file")
            for sv in self._services_vrf(d):
                if not (sv.get("route_targets") or []):
                    without_rt.append(f"{host}/{sv.get('name')}")
        pre["vrf_without_rt_pairs"] = set(without_rt)

        # L2VPN pairs/unidir/mismatch
        loop_of_all = { (d.get("system",{}).get("hostname") or d.get("file")): self._loop_ip(d) for d in self.devices }
        pairs: List[Tuple[str, str | None, Any]] = []
        for d in self.devices:
            host = self._hostname(d)
            for xc in self._l2vpns(d):
                peer_host = self.loop_ip_index.get(xc.get("neighbor"))
                pairs.append((host, peer_host, xc.get("pw_id")))
        pair_keys: Set[str] = set(); unidir: Set[str] = set(); mismatch: Set[str] = set(); listed: Set[str] = set()
        for a, b, pw in pairs:
            key_str = f"{a}<->{b or 'UNKNOWN'}"
            if key_str in pair_keys:
                continue
            pair_keys.add(key_str)
            listed.add(key_str)
            if not b:
                unidir.add(key_str)
                continue
            peer = self.host_index[b]
            a_loop = loop_of_all.get(a)
            back=None; pw_back=None
            for xc in self._l2vpns(peer):
                if xc.get("neighbor")==a_loop:
                    back=xc; pw_back=xc.get("pw_id"); break
            if not back:
                unidir.add(key_str)
            elif (pw is not None and pw_back is not None and str(pw)!=str(pw_back)):
                mismatch.add(key_str)
        pre["l2vpn_pairs"] = listed
        pre["l2vpn_unidir"] = unidir
        pre["l2vpn_mismatch"] = mismatch

        # Security
        pre["ssh_enabled"] = set([
            (d.get("system",{}).get("hostname") or d.get("file"))
            for d in self.devices if self._ssh_on(d)
        ])
        pre["ssh_missing"] = set([
            (d.get("system",{}).get("hostname") or d.get("file"))
            for d in self.devices if not self._ssh_on(d)
        ])
        pre["aaa_enabled"] = set([
            (d.get("system",{}).get("hostname") or d.get("file"))
            for d in self.devices if self._aaa_on(d)
        ])
        pre["aaa_missing"] = set([
            (d.get("system",{}).get("hostname") or d.get("file"))
            for d in self.devices if not self._aaa_on(d)
        ])
        return pre

    def calculate_metric(self, metric: str, params: Dict[str, Any] | None = None) -> tuple[Any, List[str]]:
        """주어진 메트릭을 계산하여 값과 관련 소스 파일 목록을 반환합니다.

        Parameters
        ----------
        metric: str
            계산할 메트릭 이름
        params: Dict[str, Any] | None
            메트릭 계산에 필요한 추가 파라미터. 예) {"asn": "65000"}
        """
        pre = self._precompute()
        _atype, value = self._answer_for_metric(metric, params or {}, pre)
        files = self._infer_source_files(params or {}, value)
        return value, sorted(files)

    # Public intent-based compute to support hybrid validators
    def compute(self, intent: Dict[str, Any] | None, facts: Dict[str, Any] | None = None) -> Dict[str, Any]:
        """Compute answer from an intent object.

        Supports simple metric intents and composite intents.

        Parameters
        ----------
        intent: Dict[str, Any]
            Ex: {"metric": "ssh_missing_count", "params": {"host": "CE1"}}
            or composite: {"type": "comparison", "metric": "bgp_neighbor_count", "scopes": [...], "operator": "=="}
        facts: Dict[str, Any] | None
            Unused (compat placeholder).

        Returns
        -------
        Dict[str, Any]
            {"answer_type": str, "value": Any, "files": List[str]}
        """
        if not isinstance(intent, dict):
            return {"answer_type": "error", "value": None, "files": []}

        try:
            # Simple metric
            metric = intent.get("metric")
            if metric:
                params = intent.get("params") or intent.get("scope") or {}
                atype, value = self._answer_for_metric(metric, params, self._precompute())
                files = self._infer_source_files(params, value)
                return {"answer_type": atype, "value": value, "files": sorted(files)}

            # Composite intent
            if intent.get("type"):
                atype, value = self._answer_for_composite_intent(intent, self._precompute())
                files = self._infer_source_files(intent.get("params") or intent.get("scope") or {}, value)
                return {"answer_type": atype, "value": value, "files": sorted(files)}

        except Exception:
            pass

        return {"answer_type": "error", "value": None, "files": []}

    def _infer_source_files(self, params: Dict[str, Any], value: Any) -> Set[str]:
        """메트릭 계산에 사용된 설정 파일 목록을 추론합니다."""
        files: Set[str] = set()

        # 1) 파라미터에 host가 명시된 경우 해당 장비 파일 추가
        host = params.get("host") if isinstance(params, dict) else None
        if host:
            dev = self.host_index.get(host)
            if dev and dev.get("file"):
                files.add(dev.get("file"))

        # 2) 결과 값이 호스트명의 리스트/집합인 경우 해당 장비 파일 추가
        hostnames: Set[str] = set()
        if isinstance(value, (list, set, tuple)):
            hostnames.update(str(v) for v in value)
        elif isinstance(value, dict):
            hostnames.update(str(v) for v in value.keys())

        for hn in hostnames:
            dev = self.host_index.get(hn)
            if dev and dev.get("file"):
                files.add(dev.get("file"))

        # 2.5) 결과 값에서 IP 주소를 추출하여 역매핑 (개선사항)
        import re
        ips: Set[str] = set()
        
        def collect_ips(x):
            s = str(x)
            if re.match(r'^\d{1,3}(\.\d{1,3}){3}$', s):
                ips.add(s)
        
        if isinstance(value, (list, set, tuple)):
            for v in value:
                collect_ips(v)
        elif isinstance(value, dict):
            for k in value.keys():
                collect_ips(k)
        else:
            collect_ips(value)

        for ip in ips:
            hn = self.loop_ip_index.get(ip)
            if hn:
                dev = self.host_index.get(hn)
                if dev and dev.get("file"):
                    files.add(dev["file"])

        # 3) 아무 것도 없으면 전체 장비 파일 반환 (보수적)
        if not files:
            for d in self.devices:
                if d.get("file"):
                    files.add(d.get("file"))

        return files

    def find_alternative_path(self, down_link: tuple[str, str]) -> List[str]:
        """주어진 링크가 끊겼을 때 두 장비 간의 대체 경로를 탐색한다.

        Parameters
        ----------
        down_link: tuple[str, str]
            장애가 발생한 링크의 양 끝단 장비명 (src, dst)

        Returns
        -------
        list[str]
            src에서 dst까지의 새로운 최단 경로에 포함된 장비 이름 리스트.
            경로가 없으면 빈 리스트를 반환한다.
        """

        if not down_link or len(down_link) != 2:
            return []
        src, dst = down_link

        # 1) 그래프 구성
        graph: Dict[str, Set[str]] = defaultdict(set)
        for d in self.devices:
            host = self._hostname(d)
            graph.setdefault(host, set())

            for nb in self._bgp_neighbors(d):
                peer = nb.get("id") or nb.get("ip")
                peer_host = self.host_index.get(peer) or self.loop_ip_index.get(peer)
                if peer_host:
                    graph[host].add(peer_host)
                    graph.setdefault(peer_host, set()).add(host)

            for iface in d.get("interfaces") or []:
                peer = iface.get("peer") or iface.get("neighbor")
                peer_host = self.host_index.get(peer) or self.loop_ip_index.get(peer)
                if peer_host:
                    graph[host].add(peer_host)
                    graph.setdefault(peer_host, set()).add(host)

        # 2) 장애 링크 제거
        a, b = src, dst
        if a in graph:
            graph[a].discard(b)
        if b in graph:
            graph[b].discard(a)

        # 3) 최단 경로 탐색 (BFS)
        if src not in graph or dst not in graph:
            return []
        q = deque([(src, [src])])
        visited = {src}
        while q:
            node, path = q.popleft()
            if node == dst:
                return path
            for nxt in graph.get(node, []):
                if nxt not in visited:
                    visited.add(nxt)
                    q.append((nxt, path + [nxt]))
        return []

    # GIA-Re/utils/builder_core.py 에 새로운 함수 추가
    def _answer_for_composite_intent(self, intent: Dict[str, Any], pre: Dict[str, Any]) -> tuple[str, Any]:
        """복합/추론 intent를 처리하여 최종 답변을 계산합니다."""
        intent_type = intent.get("type")

        if intent_type == "comparison":
            metric = intent.get("metric")
            scopes = intent.get("scopes", [])
            operator = intent.get("operator")

            if not all([metric, len(scopes) >= 2, operator]):
                return "error", {"error": "Invalid comparison intent schema"}

            # 각 scope에 대해 _answer_for_metric을 호출하여 값들을 수집
            values = []
            for sc in scopes:
                _atype, val = self._answer_for_metric(metric, sc, pre)
                values.append(val)
            
            # 연산자에 따라 비교 수행
            result = False
            if operator == "==":
                result = (values[0] == values[1])
            elif operator == "!=":
                result = (values[0] != values[1])
            # (향후 다른 연산자들 추가 가능: >, < 등)

            return "boolean", result
        
        # (향후 다른 복합 intent type 추가 가능, 예: 'causality')

        # 처리할 수 없는 타입이면 에러 반환
        return "error", {"error": f"Unknown composite intent type: {intent_type}"}

    # ---------- DSL 지원: metric → expected_answer 계산 ----------
    def _answer_for_metric(self, metric: str, scope: Dict[str,Any], pre: Dict[str,Any]) -> tuple[str, Any]:
        if not hasattr(self, "devices"):
            self.devices = []

        if metric == "system_hostname_text":
            host = scope.get("host")
            for d in self.devices:
                if host and self._hostname(d) != host: continue
                return "text", self._hostname(d)
            return "text", ""

        elif metric == "logging_buffered_severity_text":
            host = scope.get("host")
            for d in self.devices:
                if host and self._hostname(d) != host: continue
                val = ((d.get("logging") or {}).get("buffered_severity"))
                return "text", val or ""
            return "text", ""
        
        # ---- New L1 metrics: NTP, SNMP, Syslog ----
        elif metric == "ntp_server_list":
            host = scope.get("host")
            for d in self.devices:
                if host and self._hostname(d) != host:
                    continue
                ntp = (d.get("services") or {}).get("ntp") or {}
                servers = ntp.get("servers") or []
                if isinstance(servers, list):
                    return "set", sorted([str(s.get("address") if isinstance(s, dict) else s) for s in servers if s])
                return "set", []
            return "set", []
        
        elif metric == "snmp_community_list":
            host = scope.get("host")
            for d in self.devices:
                if host and self._hostname(d) != host:
                    continue
                snmp = (d.get("services") or {}).get("snmp") or {}
                communities = snmp.get("communities") or []
                if isinstance(communities, list):
                    result = []
                    for c in communities:
                        if isinstance(c, dict):
                            name = c.get("name") or c.get("community")
                            if name:
                                result.append(str(name))
                        elif isinstance(c, str):
                            result.append(c)
                    return "set", sorted(set(result))
                return "set", []
            return "set", []
        
        elif metric == "syslog_server_list":
            host = scope.get("host")
            for d in self.devices:
                if host and self._hostname(d) != host:
                    continue
                logging_cfg = d.get("logging") or {}
                servers = logging_cfg.get("hosts") or logging_cfg.get("servers") or []
                if isinstance(servers, list):
                    result = []
                    for s in servers:
                        if isinstance(s, dict):
                            addr = s.get("address") or s.get("host") or s.get("ip")
                            if addr:
                                result.append(str(addr))
                        elif isinstance(s, str):
                            result.append(s)
                    return "set", sorted(set(result))
                return "set", []
            return "set", []
        elif metric == "vty_login_mode_text":
            host = scope.get("host")
            for d in self.devices:
                if host and self._hostname(d) != host: continue
                vty = ((d.get("line") or {}).get("vty") or {})
                return "text", (vty.get("login_mode") or "")
            return "text", ""
        elif metric == "vty_transport_input_text":
            host = scope.get("host")
            for d in self.devices:
                if host and self._hostname(d) != host: continue
                vty = ((d.get("line") or {}).get("vty") or {})
                return "text", (vty.get("transport_input") or "")
            return "text", ""
        elif metric == "system_version_text":
            host = scope.get("host")
            for d in self.devices:
                if host and self._hostname(d) != host: continue
                val = (d.get("system") or {}).get("version") or ""
                return "text", val
            return "text", ""

        elif metric == "system_timezone_text":
            host = scope.get("host")
            for d in self.devices:
                if host and self._hostname(d) != host: continue
                val = (d.get("system") or {}).get("timezone") or ""
                return "text", val
            return "text", ""

        elif metric == "system_user_list":
            host = scope.get("host")
            for d in self.devices:
                if host and self._hostname(d) != host: continue
                users = (d.get("system") or {}).get("users") or []
                names: List[str] = []
                for u in users:
                    if isinstance(u, dict):
                        nm = u.get("name")
                        if nm:
                            names.append(nm)
                    elif isinstance(u, str):
                        names.append(u)
                names = [n for n in names if n]
                return "set", sorted(set(names))
            return "set", []

        elif metric == "system_user_count":
            host = scope.get("host")
            for d in self.devices:
                if host and self._hostname(d) != host: continue
                users = (d.get("system") or {}).get("users") or []
                names = []
                for u in users:
                    if isinstance(u, dict):
                        nm = u.get("name")
                        if nm:
                            names.append(nm)
                    elif isinstance(u, str):
                        names.append(u)
                return "numeric", len([n for n in names if n])
            return "numeric", 0

        elif metric == "ssh_present_bool":
            host = scope.get("host")
            for d in self.devices:
                if host and self._hostname(d) != host: continue
                ssh_info = (d.get("security") or {}).get("ssh") or {}
                is_present = bool(ssh_info.get("present"))
                if is_present:
                    version = ssh_info.get("version")
                    if version:
                        return "text", f"SSHv{version}"
                    return "text", "SSHv2"  # 기본값
                return "text", "비활성화"
            return "text", "비활성화"

        elif metric == "ssh_version_text":
            host = scope.get("host")
            for d in self.devices:
                if host and self._hostname(d) != host: continue
                val = ((d.get("security") or {}).get("ssh") or {}).get("version")
                return "text", str(val) if val is not None else ""
            return "text", ""

        elif metric == "aaa_present_bool":
            host = scope.get("host")
            for d in self.devices:
                if host and self._hostname(d) != host: continue
                aaa_info = (d.get("security") or {}).get("aaa") or {}
                is_present = bool(aaa_info.get("present"))
                if is_present:
                    # AAA 방식 추출 (TACACS+, RADIUS, Local 등)
                    auth_method = aaa_info.get("authentication") or aaa_info.get("method") or ""
                    if "tacacs" in str(auth_method).lower():
                        return "text", "TACACS+"
                    elif "radius" in str(auth_method).lower():
                        return "text", "RADIUS"
                    elif "local" in str(auth_method).lower():
                        return "text", "Local"
                    return "text", "Local"  # 기본값
                return "text", "미설정"
            return "text", "미설정"

        elif metric == "mpls_ldp_present_bool":
            host = scope.get("host")
            for d in self.devices:
                if host and self._hostname(d) != host:
                    continue
                mpls = ((d.get("services") or {}).get("mpls") or {})
                ldp_info = mpls.get("ldp") or {}
                is_present = bool(ldp_info) or bool(mpls.get("ldp_interfaces")) or bool(mpls.get("ldp_enabled"))
                if is_present:
                    router_id = ldp_info.get("router_id") or ldp_info.get("router-id") or ""
                    if router_id:
                        return "text", f"Router-ID: {router_id}"
                    return "text", "활성화 (Router-ID 미지정)"
                return "text", "미설정"
            return "text", "미설정"

        elif metric == "interface_count":
            host = scope.get("host")
            for d in self.devices:
                if host and self._hostname(d) != host: continue
                arr = d.get("interfaces") or []
                return "numeric", len(arr)
            return "numeric", 0

        elif metric == "interface_ip_map":
            host = scope.get("host")
            for d in self.devices:
                if host and self._hostname(d) != host: continue
                mp={}
                for i in d.get("interfaces") or []:
                    name=i.get("name") or i.get("id") or ""
                    ip  =(i.get("ipv4") or i.get("ip") or "")
                    if name: mp[name]=ip
                return "map", mp
            return "map", {}

        elif metric == "subinterface_count":
            host = scope.get("host")
            for d in self.devices:
                if host and self._hostname(d) != host: continue
                c = sum(1 for i in (d.get("interfaces") or []) if "." in (i.get("name") or ""))
                
                return "numeric", c
            return "numeric", 0

        elif metric == "vrf_bind_map":
            host = scope.get("host")
            for d in self.devices:
                if host and self._hostname(d) != host: continue
                mp={}
                for i in d.get("interfaces") or []:
                    name=i.get("name") or i.get("id") or ""
                    vrf = i.get("vrf") or i.get("l3vrf")
                    if name:
                        mp[name] = vrf if vrf else "default"
                return "map", mp
            return "map", {}

        elif metric == "bgp_local_as_numeric":
            host = scope.get("host")
            for d in self.devices:
                if host and self._hostname(d) != host: continue
                las = ((d.get("routing") or {}).get("bgp") or {}).get("local_as")
                try:
                    return "numeric", int(las) if las is not None else 0
                except Exception:
                    return "numeric", 0
            return "numeric", 0

        elif metric == "bgp_neighbor_count":
            host = scope.get("host")
            for d in self.devices:
                if host and self._hostname(d) != host: continue
                cnt=0
                bgp = ((d.get("routing") or {}).get("bgp") or {})
                for n in (bgp.get("neighbors") or []):
                    cnt+=1
                for v in (bgp.get("vrfs") or []):
                    for n in (v.get("neighbors") or []):
                        cnt+=1
                return "numeric", cnt
            return "numeric", 0

        elif metric == "ospf_process_ids_set":
            host = scope.get("host")
            for d in self.devices:
                if host and self._hostname(d) != host: continue
                s=set()
                ospf = ((d.get("routing") or {}).get("ospf") or {})
                for pid in (ospf.get("process_ids") or []):
                    s.add(str(pid))

                return "set", sorted(s)
            return "set", []

        elif metric == "ospf_area_set":
            host = scope.get("host")
            for d in self.devices:
                if host and self._hostname(d) != host: continue
                s=set()
                ospf = ((d.get("routing") or {}).get("ospf") or {})
                areas = ospf.get("areas") or {}
                for aid in areas.keys():
                    if aid is not None: s.add(str(aid))
                return "set", sorted(s)
            return "set", []

        elif metric == "vrf_names_set":
            host = scope.get("host")
            for d in self.devices:
                if host and self._hostname(d) != host: continue
                s=set()
                for v in (((d.get("routing") or {}).get("bgp") or {}).get("vrfs") or []):
                    nm = v.get("name");  
                    if nm: s.add(nm)
                return "set", sorted(s)
            return "set", []

        elif metric == "vrf_count":
            host = scope.get("host")
            for d in self.devices:
                if host and self._hostname(d) != host: continue
                s=set()
                for v in (((d.get("routing") or {}).get("bgp") or {}).get("vrfs") or []):
                    if v.get("name"): s.add(v.get("name"))
                return "numeric", len(s)
            return "numeric", 0

        elif metric == "vrf_rd_map":
            host = scope.get("host")
            for d in self.devices:
                if host and self._hostname(d) != host:
                    continue
                mp = {}
                for v in (((d.get("routing") or {}).get("bgp") or {}).get("vrfs") or []):
                    nm = v.get("name"); rd = v.get("rd")
                    if nm:
                        mp[nm] = rd or ""
                return "map", mp
            return "map", {}

        elif metric == "rt_import_count":
            host = scope.get("host")
            for d in self.devices:
                if host and self._hostname(d) != host:
                    continue
                c = 0
                for v in (((d.get("routing") or {}).get("bgp") or {}).get("vrfs") or []):
                    c += len(v.get("rt_import", []) or [])
                return "numeric", c
            return "numeric", 0

        elif metric == "rt_export_count": 
            host = scope.get("host")
            for d in self.devices:
                if host and self._hostname(d) != host: continue
                c=0
                for v in (((d.get("routing") or {}).get("bgp") or {}).get("vrfs") or []):
                    c += len(v.get("rt_export", []) or [])
                return "numeric", c
            return "numeric", 0

        elif metric == "l2vpn_pw_id_set":
            host = scope.get("host")
            for d in self.devices:
                if host and self._hostname(d) != host:
                    continue
                s = set()
                for xc in self._l2vpns(d):
                    if xc.get("pw_id") is not None:
                        s.add(str(xc.get("pw_id")))
                return "set", sorted(s)
            return "set", []

        elif metric in ("neighbor_list_ibgp","neighbor_list_ebgp"):
            host = scope.get("host")
            want_ibgp = (metric == "neighbor_list_ibgp")
            for d in self.devices:
                if host and self._hostname(d) != host:
                    continue
                las = self._bgp_local_as(d)
                peers = set()
                for n in self._bgp_neighbors(d):
                    pid = n.get("id") or n.get("ip")
                    ras = n.get("remote_as")
                    if not pid or ras is None:
                        continue
                    if (ras == las) == want_ibgp:
                        peers.add(pid)
                for v in self._bgp_vrfs(d):
                    for n in v.get("neighbors") or []:
                        pid = n.get("id") or n.get("ip")
                        ras = n.get("remote_as")
                        if not pid or ras is None:
                            continue
                        if (ras == las) == want_ibgp:
                            peers.add(pid)
                return "set", sorted(peers)
            return "set", []

        elif metric == "vrf_interface_bind_count":
            host = scope.get("host"); vrf = scope.get("vrf")
            cnt = 0
            if not vrf:
                return "numeric", 0  # VRF 미지정이면 0
            for d in self.devices:
                if host and (d.get("system",{}).get("hostname") != host):
                    continue
                for iface in (d.get("interfaces") or []):
                    if (iface.get("vrf") or iface.get("l3vrf")) == vrf:
                        cnt += 1
            return "numeric", cnt


        elif metric == "ibgp_fullmesh_ok":
            asn = scope.get("asn")
            miss = pre["bgp_missing_pairs_by_as"].get(asn, set())
            if len(miss) == 0:
                return "text", "완전"
            else:
                # 누락된 피어링 목록 표시 (최대 5개)
                miss_list = sorted(list(miss))[:5]
                miss_str = ", ".join(miss_list)
                if len(miss) > 5:
                    miss_str += f" 외 {len(miss) - 5}개"
                return "text", f"누락: {miss_str}"
        elif metric == "ibgp_missing_pairs":
            asn = scope.get("asn")
            miss = sorted(list(pre["bgp_missing_pairs_by_as"].get(asn, set())))
            return "set", miss
        elif metric == "ibgp_missing_pairs_count":
            asn = scope.get("asn")
            miss = pre["bgp_missing_pairs_by_as"].get(asn, set())
            return "numeric", len(miss)
        elif metric == "ibgp_under_peered_devices":
            asn = scope.get("asn")
            under = sorted(list(pre["bgp_under_by_as"].get(asn, set())))
            return "set", under
        elif metric == "ibgp_under_peered_count":
            asn = scope.get("asn")
            under = pre["bgp_under_by_as"].get(asn, set())
            return "numeric", len(under)

        elif metric == "vrf_without_rt_pairs":
            return "set", sorted(list(pre["vrf_without_rt_pairs"]))
        elif metric == "vrf_without_rt_count":
            return "numeric", len(pre["vrf_without_rt_pairs"])
        elif metric == "vrf_rt_list_per_device":
            host = scope.get("host")
            d = self.host_index.get(host)
            if not d: return "set", []
            rts: List[str] = []
            for v in self._services_vrf(d):
                if v.get("route_targets"):
                    rts.extend(v.get("route_targets"))
            return "set", sorted(list(set(rts)))

        elif metric == "l2vpn_pairs":
            return "set", sorted(list(pre["l2vpn_pairs"]))
        elif metric == "l2vpn_unidirectional_pairs":
            return "set", sorted(list(pre["l2vpn_unidir"]))
        elif metric == "l2vpn_unidir_count":
            return "numeric", len(pre["l2vpn_unidir"]) 
        elif metric == "l2vpn_pwid_mismatch_pairs":
            return "set", sorted(list(pre["l2vpn_mismatch"]))
        elif metric == "l2vpn_mismatch_count":
            return "numeric", len(pre["l2vpn_mismatch"]) 

        elif metric == "ospf_area0_if_list":
            host = scope.get("host")
            d = self.host_index.get(host)
            if not d: return "set", []
            areas = self._ospf(d).get("areas",{}) or {}
            if isinstance(areas, dict):
                intfs = areas.get("0") or areas.get(0) or []
            elif isinstance(areas, list):
                intfs = []
                for area in areas:
                    if isinstance(area, dict) and (area.get("id") == "0" or area.get("area") == "0"):
                        intfs = area.get("interfaces", [])
                        break
            else:
                intfs = []
            return "set", sorted(intfs)
        elif metric == "ospf_area0_if_count":
            host = scope.get("host")
            d = self.host_index.get(host)
            if not d: return "numeric", 0
            areas = self._ospf(d).get("areas",{}) or {}
            if isinstance(areas, dict):
                intfs = areas.get("0") or areas.get(0) or []
            elif isinstance(areas, list):
                intfs = []
                for area in areas:
                    if isinstance(area, dict) and (area.get("id") == "0" or area.get("area") == "0"):
                        intfs = area.get("interfaces", [])
                        break
            else:
                intfs = []
            return "numeric", len(intfs)
        elif metric == "ssh_enabled_devices":
            return "set", sorted(list(pre["ssh_enabled"]))
        elif metric == "ssh_missing_devices":
            return "set", sorted(list(pre["ssh_missing"]))
        elif metric == "ssh_missing_count":
            return "numeric", len(pre["ssh_missing"])
        elif metric == "aaa_enabled_devices":
            return "set", sorted(list(pre["aaa_enabled"]))
        elif metric == "aaa_missing_devices":
            return "set", sorted(list(pre["aaa_missing"]))
        
        # ---- New L2 metrics: devices_with_same_vrf, ospf_area_membership ----
        elif metric == "devices_with_same_vrf":
            vrf_name = scope.get("vrf")
            if not vrf_name:
                return "set", []
            devices_with_vrf = set()
            for d in self.devices:
                host = self._hostname(d)
                # Check BGP VRFs
                for v in self._bgp_vrfs(d):
                    if v.get("name") == vrf_name:
                        devices_with_vrf.add(host)
                        break
                # Check services VRF
                for sv in self._services_vrf(d):
                    if sv.get("name") == vrf_name:
                        devices_with_vrf.add(host)
                        break
                # Check interface VRF bindings
                for iface in (d.get("interfaces") or []):
                    if (iface.get("vrf") or iface.get("l3vrf")) == vrf_name:
                        devices_with_vrf.add(host)
                        break
            return "set", sorted(devices_with_vrf)
        
        elif metric == "ospf_area_membership":
            area_id = scope.get("area")
            if area_id is None:
                return "set", []
            area_str = str(area_id)
            devices_in_area = set()
            for d in self.devices:
                host = self._hostname(d)
                ospf = self._ospf(d)
                areas = ospf.get("areas") or {}
                if isinstance(areas, dict):
                    if area_str in areas or int(area_id) in areas if area_str.isdigit() else False:
                        devices_in_area.add(host)
                elif isinstance(areas, list):
                    for a in areas:
                        if isinstance(a, dict):
                            aid = a.get("id") or a.get("area")
                            if str(aid) == area_str:
                                devices_in_area.add(host)
                                break
            return "set", sorted(devices_in_area)
        elif metric == "find_alternative_path":
            dl = scope.get("down_link") or scope.get("link")
            if isinstance(dl, (list, tuple)) and len(dl) == 2:
                path = self.find_alternative_path((dl[0], dl[1]))
                return "list", path
            return "list", []
        
        # ---- L3 Comparison metrics ----
        elif metric == "compare_bgp_neighbor_count":
            host1 = scope.get("host1")
            host2 = scope.get("host2")
            d1 = self.host_index.get(host1)
            d2 = self.host_index.get(host2)
            if not d1 or not d2:
                return "text", f"{host1}: 정보 없음, {host2}: 정보 없음, 차이: 계산 불가"
            cnt1 = len(self._bgp_neighbors(d1))
            cnt2 = len(self._bgp_neighbors(d2))
            diff = abs(cnt1 - cnt2)
            return "text", f"{host1}: {cnt1}개, {host2}: {cnt2}개, 차이: {diff}개"
        
        elif metric == "compare_interface_count":
            host1 = scope.get("host1")
            host2 = scope.get("host2")
            d1 = self.host_index.get(host1)
            d2 = self.host_index.get(host2)
            if not d1 or not d2:
                return "text", f"{host1}: 정보 없음, {host2}: 정보 없음, 차이: 계산 불가"
            cnt1 = len(d1.get("interfaces") or [])
            cnt2 = len(d2.get("interfaces") or [])
            diff = abs(cnt1 - cnt2)
            return "text", f"{host1}: {cnt1}개, {host2}: {cnt2}개, 차이: {diff}개"
        
        elif metric == "compare_vrf_count":
            host1 = scope.get("host1")
            host2 = scope.get("host2")
            d1 = self.host_index.get(host1)
            d2 = self.host_index.get(host2)
            if not d1 or not d2:
                return "text", f"{host1}: 정보 없음, {host2}: 정보 없음, 차이: 계산 불가"
            cnt1 = len(self._bgp_vrfs(d1))
            cnt2 = len(self._bgp_vrfs(d2))
            diff = abs(cnt1 - cnt2)
            return "text", f"{host1}: {cnt1}개, {host2}: {cnt2}개, 차이: {diff}개"
        
        elif metric == "compare_bgp_as":
            host1 = scope.get("host1")
            host2 = scope.get("host2")
            d1 = self.host_index.get(host1)
            d2 = self.host_index.get(host2)
            if not d1 or not d2:
                return "text", f"{host1}: 정보없음, {host2}: 정보없음"
            as1 = self._bgp_local_as(d1)
            as2 = self._bgp_local_as(d2)
            as1_str = str(as1) if as1 is not None else "없음"
            as2_str = str(as2) if as2 is not None else "없음"
            return "text", f"{host1}: AS {as1_str}, {host2}: AS {as2_str}"
        
        elif metric == "compare_ospf_areas":
            host1 = scope.get("host1")
            host2 = scope.get("host2")
            d1 = self.host_index.get(host1)
            d2 = self.host_index.get(host2)
            if not d1 or not d2:
                return "text", f"{host1}: 정보없음, {host2}: 정보없음"
            areas1 = set((self._ospf(d1).get("areas") or {}).keys())
            areas2 = set((self._ospf(d2).get("areas") or {}).keys())
            areas1_str = ", ".join(sorted(str(a) for a in areas1)) if areas1 else "없음"
            areas2_str = ", ".join(sorted(str(a) for a in areas2)) if areas2 else "없음"
            return "text", f"{host1}: Area {areas1_str}, {host2}: Area {areas2_str}"
        
        elif metric == "max_interface_device":
            max_count = -1
            max_host = None
            for d in self.devices:
                cnt = len(d.get("interfaces") or [])
                if cnt > max_count:
                    max_count = cnt
                    max_host = self._hostname(d)
            if max_host:
                return "text", f"{max_host}: {max_count}개"
            return "text", "정보없음"
        
        elif metric == "max_bgp_peer_device":
            max_count = -1
            max_host = None
            for d in self.devices:
                cnt = len(self._bgp_neighbors(d))
                if cnt > max_count:
                    max_count = cnt
                    max_host = self._hostname(d)
            if max_host:
                return "text", f"{max_host}: {max_count}개"
            return "text", "정보없음"
        
        elif metric == "all_devices_same_as":
            as_info = []
            for d in self.devices:
                host = self._hostname(d)
                las = self._bgp_local_as(d)
                if las is not None:
                    as_info.append(f"{host}: AS {las}")
            info_str = ", ".join(as_info) if as_info else "정보없음"
            return "text", info_str

        # ---- New L1 metrics ----
        elif metric == "interface_status_map":
            host = scope.get("host")
            for d in self.devices:
                if host and self._hostname(d) != host: continue
                status_map = {}
                for i in d.get("interfaces") or []:
                    name = i.get("name") or i.get("id") or ""
                    status = i.get("status") or i.get("state") or "unknown"
                    if name:
                        status_map[name] = status
                return "map", status_map
            return "map", {}

        elif metric == "routing_table_entry_count":
            host = scope.get("host")
            for d in self.devices:
                if host and self._hostname(d) != host: continue
                routing = d.get("routing", {})
                total_entries = 0

                # BGP routes
                bgp = routing.get("bgp", {})
                for vrf in bgp.get("vrfs", []):
                    total_entries += len(vrf.get("rib", []))
                total_entries += len(bgp.get("rib", []))

                # OSPF routes
                ospf = routing.get("ospf", {})
                for area in ospf.get("areas", {}).values():
                    if isinstance(area, dict):
                        total_entries += len(area.get("rib", []))

                # Connected routes
                interfaces = d.get("interfaces", [])
                total_entries += len(interfaces)  # connected routes

                return "number", total_entries
            return "number", 0

        # ---- New L2 metrics ----
        elif metric == "devices_in_as":
            asn = scope.get("asn")
            if not asn:
                return "set", []
            devices_in_as = set()
            for d in self.devices:
                las = self._bgp_local_as(d)
                if las == asn:
                    devices_in_as.add(self._hostname(d))
            return "set", sorted(devices_in_as)

        elif metric == "interfaces_in_vrf":
            vrf_name = scope.get("vrf")
            if not vrf_name:
                return "number", 0
            count = 0
            for d in self.devices:
                for iface in d.get("interfaces", []):
                    if iface.get("vrf") == vrf_name or iface.get("l3vrf") == vrf_name:
                        count += 1
            return "number", count

        elif metric == "ospf_neighbor_count_per_area":
            area_id = scope.get("area")
            if area_id is None:
                return "number", 0
            total_neighbors = 0
            for d in self.devices:
                ospf = self._ospf(d)
                areas = ospf.get("areas", {})
                if isinstance(areas, dict):
                    area_data = areas.get(str(area_id)) or areas.get(area_id)
                    if area_data and isinstance(area_data, dict):
                        total_neighbors += len(area_data.get("neighbors", []))
                elif isinstance(areas, list):
                    for area in areas:
                        if isinstance(area, dict) and (area.get("id") == area_id or area.get("area") == area_id):
                            total_neighbors += len(area.get("neighbors", []))
                            break
            return "number", total_neighbors

        # ---- New L3 metrics ----
        elif metric == "min_interface_device":
            min_count = float('inf')
            min_host = None
            for d in self.devices:
                cnt = len(d.get("interfaces") or [])
                if cnt > 0 and cnt < min_count:
                    min_count = cnt
                    min_host = self._hostname(d)
            if min_host:
                return "text", f"{min_host}: {min_count}개"
            return "text", "정보없음"

        elif metric == "bgp_as_distribution":
            as_counts = {}
            for d in self.devices:
                las = self._bgp_local_as(d)
                if las is not None:
                    as_counts[las] = as_counts.get(las, 0) + 1
            # 형식: 'AS X: N대, AS Y: M대'
            dist_parts = [f"AS {asn}: {cnt}대" for asn, cnt in sorted(as_counts.items())]
            return "text", ", ".join(dist_parts) if dist_parts else "정보없음"

        elif metric == "vrf_usage_statistics":
            vrf_stats = {}
            for d in self.devices:
                host = self._hostname(d)
                vrf_count = len(self._bgp_vrfs(d))
                if vrf_count > 0:
                    vrf_stats[host] = vrf_count
            # 형식: '장비1: N개, 장비2: M개'
            stats_parts = [f"{host}: {cnt}개" for host, cnt in sorted(vrf_stats.items())]
            return "text", ", ".join(stats_parts) if stats_parts else "정보없음"

        return "text", None

    # ---------- DSL → 테스트 인스턴스 확장 ----------
    def expand_from_dsl(self, dsl: List[Dict[str,Any]], k_variant: int = 1, 
                        l1_sample_ratio: float = 0.3, seed: int = 42) -> Dict[str, List[Dict[str, Any]]]:
        """
        DSL 템플릿을 실제 질문/정답으로 확장합니다.
        
        Parameters
        ----------
        dsl: DSL 템플릿 목록
        k_variant: 변형 수 (미사용)
        l1_sample_ratio: L1 메트릭에서 샘플링할 장비 비율 (0.0-1.0)
        seed: 랜덤 시드 (재현성 보장)
        """
        out: Dict[str, List[Dict[str, Any]]] = {}
        pre = self._precompute()
        rng = random.Random(seed)

        # 후보 값들
        asns = sorted(list(self._as_groups().keys())) or []
        hosts = list(self.host_index.keys())
        vrfs: Set[str] = set()
        for d in self.devices:
            for v in self._bgp_vrfs(d):
                if v.get("name"): vrfs.add(v["name"])
            for sv in self._services_vrf(d):
                if sv.get("name"): vrfs.add(sv["name"])
        vrf_list = sorted(list(vrfs))

        # OSPF Area 후보
        ospf_areas: Set[str] = set()
        for d in self.devices:
            ospf = self._ospf(d)
            for area in ospf.get("areas", {}):
                ospf_areas.add(area)
        area_list = sorted(list(ospf_areas))

        # 인터페이스 후보
        iface_names: List[str] = []
        for d in self.devices:
            for i in (d.get("interfaces") or []):
                if i.get("name"):
                    iface_names.append(i["name"])
        iface_names = sorted(list(set(iface_names)))
        
        # L1 샘플링: 랜덤하게 장비 선택
        l1_sample_count = max(1, int(len(hosts) * l1_sample_ratio))
        l1_sampled_hosts = rng.sample(hosts, min(l1_sample_count, len(hosts))) if hosts else []

        def iter_scopes(scope: Dict[str,Any], level: str = None):
            st = scope.get("type")
            if st=="AS" and scope.get("asn")=="{asn}":
                for a in asns:
                    s=dict(scope); s["asn"]=a; yield s
            elif st=="DEVICE" and scope.get("host")=="{host}":
                # L1 레벨이면 샘플링된 장비만, 그 외는 전체
                target_hosts = l1_sampled_hosts if level == "L1" else hosts
                for h in target_hosts:
                    s=dict(scope); s["host"]=h; yield s
            elif st=="VRF" and scope.get("vrf")=="{vrf}":
                for v in vrf_list:
                    s=dict(scope); s["vrf"]=v; yield s
            elif st=="OSPF_AREA" and scope.get("area")=="{area}":
                for a in area_list:
                    s=dict(scope); s["area"]=a; yield s
            elif st=="DEVICE_VRF":
                for h in hosts:
                    for v in vrf_list:
                        s=dict(scope); s["host"]=h; s["vrf"]=v; yield s
            elif st=="DEVICE_IF":
                for h in hosts:
                    for ifn in iface_names:
                        s=dict(scope); s["host"]=h; s["if"]=ifn; yield s
            elif st=="DEVICE_PAIR":
                # 모든 장비 쌍 조합 (CE-PE 포함)
                for h1, h2 in combinations(hosts, 2):
                    s=dict(scope); s["host1"]=h1; s["host2"]=h2; yield s
            else:
                yield scope

        for t in dsl:
            cat = t["category"]; out.setdefault(cat, [])
            patt = t.get("pattern")
            if patt is None:
                patt = t.get("question")
            metric = t.get("intent",{}).get("metric")
            scope = t.get("intent",{}).get("scope", {"type":"GLOBAL"})
            level = t.get("level")
            origin = t.get("origin")

            params_ctx = (t.get("intent") or {}).get("params")
            for sc in iter_scopes(scope, level):
                ctx = dict(sc) if isinstance(sc, dict) else {"value": sc}
                if isinstance(params_ctx, dict):
                    for k, v in params_ctx.items():
                        ctx.setdefault(k, v)
                atype, val = self._answer_for_metric(metric, ctx, pre)
                if not self._is_supported_answer(atype, val):
                    continue
                try:
                    q = patt.format(**ctx) if isinstance(patt, str) else str(patt)
                except Exception:
                    q = str(patt)
                out[cat].append({
                    "test_id": f"DSL-{(metric or 'METRIC').upper()}-{hash(str(ctx)) & 0xffff}",
                    "category": cat,
                    "answer_type": atype,
                    "question": q,
                    "expected_answer": {"value": val},
                    "evaluation_method": "exact_match",
                    "evidence_hint": {"scope": ctx, "metric": metric},
                    "source_files": self._files_for_scope(ctx),
                    "level": level,
                    "origin": origin
                })
        return out

    def _files_for_scope(self, sc: dict) -> List[str]:
        st = (sc.get("type") or "GLOBAL").upper()
        host_param = sc.get("host")
        hosts_list = sc.get("hosts") if isinstance(sc.get("hosts"), (list, set, tuple)) else None
        candidates: Set[str] = set()
        if isinstance(host_param, str):
            candidates.add(host_param)
        if hosts_list:
            candidates.update(str(h) for h in hosts_list)
        for key in ("jump_host", "destination_host", "target", "mgmt"):
            val = sc.get(key)
            if isinstance(val, str):
                candidates.add(val)
        def file_for(host: str) -> List[str]:
            dev = self.host_index.get(host)
            return [dev.get("file") or ""] if dev and dev.get("file") else []

        if st == "DEVICE":
            return file_for(sc.get("host"))
        if st == "AS":
            files = []
            for d in self.devices:
                if str(((d.get("routing") or {}).get("bgp") or {}).get("local_as")) == str(sc.get("asn")):
                    file_name = d.get("file")
                    if file_name:
                        files.append(file_name)
            return files
        if st == "VRF":
            files = []
            for d in self.devices:
                for v in (((d.get("routing") or {}).get("bgp") or {}).get("vrfs") or []):
                    if v.get("name") == sc.get("vrf"):
                        file_name = d.get("file")
                        if file_name:
                            files.append(file_name)
                        break
            return files
        if st == "DEVICE_VRF":
            return file_for(sc.get("host"))
        if st == "DEVICE_IF":
            return file_for(sc.get("host"))
        if candidates:
            files: List[str] = []
            for host in candidates:
                files.extend(file_for(host))
            if files:
                return sorted(set(files))
        return [d.get("file") or "" for d in self.devices if d.get("file")]

SUPPORTED_METRICS: List[str] = [
    # === L1: System Inventory ===
    "system_hostname_text",
    "system_version_text",
    "system_timezone_text",
    "system_user_list",
    "system_user_count",
    "logging_buffered_severity_text",
    "ntp_server_list",
    "snmp_community_list",
    "syslog_server_list",
    
    # === L1: Security Inventory ===
    "ssh_present_bool",
    "ssh_version_text",
    "aaa_present_bool",
    "vty_transport_input_text",
    "vty_login_mode_text",
    
    # === L1: Interface Inventory ===
    "interface_count",
    "interface_ip_map",
    "subinterface_count",
    "vrf_bind_map",
    
    # === L1: Routing Inventory ===
    "bgp_local_as_numeric",
    "bgp_neighbor_count",
    "neighbor_list_ibgp",
    "neighbor_list_ebgp",
    "ospf_process_ids_set",
    "ospf_area_set",
    "ospf_area0_if_list",
    
    # === L1: Services Inventory ===
    "vrf_names_set",
    "vrf_count",
    "vrf_rd_map",
    "rt_import_count",
    "rt_export_count",
    "mpls_ldp_present_bool",
    "l2vpn_pw_id_set",
    
    # === L2: Security Policy ===
    "ssh_enabled_devices",
    "ssh_missing_devices",
    "ssh_missing_count",
    "aaa_enabled_devices",
    "aaa_missing_devices",
    "devices_with_same_vrf",
    
    # === L2: OSPF Consistency ===
    "ospf_area_membership",
    "ospf_area0_if_count",
    
    # === L2: L2VPN Consistency ===
    "l2vpn_pairs",
    
    # === L3: BGP Consistency ===
    "ibgp_fullmesh_ok",
    "ibgp_missing_pairs",
    "ibgp_missing_pairs_count",
    "ibgp_under_peered_devices",
    "ibgp_under_peered_count",
    
    # === L3: VRF Consistency ===
    "vrf_without_rt_pairs",
    "vrf_without_rt_count",
    "vrf_interface_bind_count",
    "vrf_rt_list_per_device",
    
    # === L3: L2VPN Consistency ===
    "l2vpn_unidirectional_pairs",
    "l2vpn_unidir_count",
    "l2vpn_pwid_mismatch_pairs",
    "l2vpn_mismatch_count",
    
    # === L3: Comparison Analysis ===
    "compare_bgp_neighbor_count",
    "compare_interface_count",
    "compare_vrf_count",
    "compare_bgp_as",
    "compare_ospf_areas",
    "max_interface_device",
    "max_bgp_peer_device",
    "all_devices_same_as",
    
    # === L4/L5: Batfish-based (placeholder) ===
    "find_alternative_path",
]


def list_available_metrics() -> List[str]:
    return sorted(list(set(SUPPORTED_METRICS)))


# // GIA/utils/builder_core.py

# GIA-Re/utils/builder_core.py

def make_grounding(facts: Any) -> Dict[str, Any]:
    """
    LLM에 제공할 '근거(grounding)' 스냅샷을 생성한다.
    [개선] 이상 징후가 없을 때도 질문을 생성할 수 있도록 기본 현황 통계를 추가한다.
    """
    fx = facts.get("devices") if isinstance(facts, dict) else facts
    if not fx:
        return {"inventory": {}, "anomalies": {}}

    core = BuilderCore(fx or [])
    pre = core._precompute()

    # --- 1. 기본 현황 정보 (Inventory) ---
    inventory = {
        "device_count": len(core.devices),
        "total_interfaces": sum(len(d.get("interfaces", [])) for d in core.devices),
        "l2vpn_pair_count": len(pre.get("l2vpn_pairs", [])),
    }
    
    # --- 2. AS 그룹 정보 요약 (AS-specific context) ---
    as_groups: Dict[str, Any] = {}
    for asn, devices in core._as_groups().items():
        as_groups[str(asn)] = {
            "device_count": len(devices),
            # [변경] AS별 이상 징후는 아래 anomalies 섹션으로 이동하여 통합
        }
    if as_groups:
        inventory["as_groups"] = as_groups
        
    # --- 3. 이상 징후 정보 (Anomalies) ---
    anomalies = {
        "ssh_missing_count": len(pre.get("ssh_missing", [])),
        "vrf_without_rt_count": len(pre.get("vrf_without_rt_pairs", [])),
        "l2vpn_unidir_count": len(pre.get("l2vpn_unidir", [])),
        "l2vpn_mismatch_count": len(pre.get("l2vpn_mismatch", [])),
    }

    # [추가] AS별 BGP 이상 징후 정보를 anomalies 섹션에 명시적으로 추가
    for asn in as_groups.keys():
        missing_count = len(pre.get("bgp_missing_pairs_by_as", {}).get(asn, []))
        under_peered_count = len(pre.get("bgp_under_by_as", {}).get(asn, []))
        if missing_count > 0:
            anomalies[f"as_{asn}_ibgp_missing_pairs_count"] = missing_count
        if under_peered_count > 0:
            anomalies[f"as_{asn}_ibgp_under_peered_count"] = under_peered_count

    out = {
        # 비어있지 않은 항목만 포함하여 LLM에게 깔끔한 컨텍스트 제공
        "inventory": {k: v for k, v in inventory.items() if v}, 
        "anomalies": {k: v for k, v in anomalies.items() if v} 
    }
    return out


def _deepcopy_facts(facts: Any) -> Any:
    import copy
    try:
        return copy.deepcopy(facts)
    except Exception:
        return json.loads(json.dumps(facts))


def _apply_simulation(facts: Any, conditions: List[Dict[str, Any]]) -> Any:
    if not conditions:
        return facts
    devices = facts.get("devices") if isinstance(facts, dict) else facts
    for cond in conditions:
        target = (cond or {}).get("target")
        component = (cond or {}).get("component") or ""
        state = (cond or {}).get("state") or ""
        if not target or not component:
            continue
        # 예: component="interface:GigabitEthernet0/0/0/0" → 해당 인터페이스 down 처리
        if component.startswith("interface:"):
            if_name = component.split(":",1)[1]
            for d in devices or []:
                host = (d.get("system",{}) or {}).get("hostname") or d.get("file")
                if host != target:
                    continue
                for i in (d.get("interfaces") or []):
                    if i.get("name") == if_name:
                        if state.lower() == "down":
                            i["admin_state"] = "down"
                            i["oper_state"] = "down"
                        elif state.lower() == "up":
                            i["admin_state"] = "up"
                            i["oper_state"] = "up"
                        break
        elif component.startswith("bgp_peer:"):
            peer_ip = component.split(":",1)[1]
            for d in devices or []:
                host = (d.get("system",{}) or {}).get("hostname") or d.get("file")
                if host != target:
                    continue
                for n in (((d.get("routing") or {}).get("bgp") or {}).get("neighbors") or []):
                    ip = (n.get("id") or n.get("ip"))
                    if ip == peer_ip:
                        if state.lower() == "down":
                            n["session_state"] = "Idle"
                        elif state.lower() == "up":
                            n["session_state"] = "Established"
                        break
    return facts


def _check_expected_error(intent: Dict[str, Any], facts: Any) -> Dict[str, Any] | None:
    exp = intent.get("expected_error") or {}
    if not isinstance(exp, dict) or not exp:
        return None
    etype = (exp.get("type") or "").upper()
    cond = exp.get("condition_to_check")
    expected_value = exp.get("expected_value")
    # 예: device_bgp_as_check
    if cond == "device_bgp_as_check":
        device = (intent.get("scope") or {}).get("host")
        if not device:
            return {"ok": False, "reason": "MISSING_HOST_FOR_PRECONDITION"}
        devices = facts.get("devices") if isinstance(facts, dict) else facts
        for d in devices or []:
            host = (d.get("system",{}) or {}).get("hostname") or d.get("file")
            if host == device:
                las = (((d.get("routing") or {}).get("bgp") or {}).get("local_as"))
                if str(las) != str(expected_value):
                    return {"ok": False, "reason": "PRECONDITION_MISMATCH", "actual": las, "expected": expected_value}
                break
        # 조건을 만족함(오류 유도 실패) → 정상 진행
        return {"ok": True}
    # 모르는 조건은 패스
    return None


def execute_intent(intent: Dict[str, Any], facts: Any) -> Dict[str, Any]:
    if not isinstance(intent, dict):
        raise ValueError("intent must be a dict")
    metric = intent.get("metric")
    scope = intent.get("scope") or {}
    if not isinstance(metric, str) or not metric:
        raise ValueError("intent.metric is required")
    if not isinstance(scope, dict):
        raise ValueError("intent.scope must be an object")

    # Lint: metric 유효성 (경고만, 중단하지 않음)
    if metric not in set(SUPPORTED_METRICS):
        print(f"[WARNING] unsupported metric: {metric}, trying anyway...")

    # scope 키 검증 (관대하게 수정)
    allowed_scope_keys = {"host","asn","vrf","vrf_name","if","interface","peer","_q"}
    for k in scope.keys():
        if k not in allowed_scope_keys:
            print(f"[WARNING] unusual scope key: {k}, continuing...")

    # "모든 장치" 의도 자동 매핑: ssh_all_enabled_bool ↔ ssh_missing_count
    if metric in ("ssh_present_bool", "ssh_all_enabled_bool") and not scope:
        metric = "ssh_all_enabled_bool"

    # expected_error (오류 주입) 사전 체크
    chk = _check_expected_error(intent, facts)
    if isinstance(chk, dict) and not chk.get("ok", True):
        return {"answer_type": "error", "value": {"error": chk.get("reason"), "details": chk}}

    # simulation
    sim = intent.get("simulation_conditions") or []
    fx = facts.get("devices") if isinstance(facts, dict) else facts
    fx2 = _deepcopy_facts(fx)
    if sim:
        fx2 = _apply_simulation({"devices": fx2} if not isinstance(fx2, dict) else fx2, sim)

    # compute
    try:
        devices_data = fx2.get("devices") if isinstance(fx2, dict) else fx2
        if devices_data is None:
            devices_data = []
        core = BuilderCore(devices_data)
        pre = core._precompute()

        # [수정] intent의 구조를 확인하여 분기 처리
        if "type" in intent: # 복합/추론 intent일 경우
            answer_type, value = core._answer_for_composite_intent(intent, pre)
        else: # 기존의 단일 metric intent일 경우
            metric = intent.get("metric")
            scope = intent.get("scope") or {}
            if not metric:
                raise ValueError("intent.metric is required for single metric questions")
            answer_type, value = core._answer_for_metric(metric, scope, pre)

        return {"answer_type": answer_type, "value": value}
    except Exception as e:
        print(f"[WARNING] metric computation failed for {intent.get('metric', 'composite_intent')}: {e}")
        return {"answer_type": "error", "value": {"error": "computation_failed", "details": str(e)}}
