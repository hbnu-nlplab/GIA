from __future__ import annotations
from typing import Dict, Any, List, Set, Tuple, Union
import json

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
        if at in ("set","list"):
            try:
                return len(value) > 0
            except Exception:
                return False
        if at in ("map","dict"):
            try:
                return len(value.keys() if hasattr(value, "keys") else value) > 0
            except Exception:
                return False
        if at == "text":
            try:
                return str(value).strip() != ""
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
        pre["ssh_enabled"] = set([ (d.get("system",{}).get("hostname") or d.get("file")) for d in self.devices if self._ssh_on(d)])
        pre["ssh_missing"] = set([ (d.get("system",{}).get("hostname") or d.get("file")) for d in self.devices if not self._ssh_on(d)])
        return pre

    def calculate_metric(self, metric: str) -> Any:
        """주어진 메트릭을 계산하여 값을 반환합니다."""
        pre = self._precompute()
        _atype, value = self._answer_for_metric(metric, {}, pre)
        return value

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

        # ---- basic info additions ----
        elif metric == "system_mgmt_address_text":
            host = scope.get("host")
            for d in self.devices:
                if host and self._hostname(d) != host: continue
                return "text", ((d.get("system") or {}).get("mgmt_address") or "")
            return "text", ""
        elif metric == "ios_config_register_text":
            host = scope.get("host")
            for d in self.devices:
                if host and self._hostname(d) != host: continue
                return "text", ((d.get("system") or {}).get("config_register") or "")
            return "text", ""
        elif metric == "http_server_enabled_bool":
            host = scope.get("host")
            for d in self.devices:
                if host and self._hostname(d) != host: continue
                val = (((d.get("security") or {}).get("http") or {}).get("server_enabled"))
                return "boolean", bool(val)
            return "boolean", False
        elif metric == "ip_forward_protocol_nd_bool":
            host = scope.get("host")
            for d in self.devices:
                if host and self._hostname(d) != host: continue
                val = (((d.get("services") or {}).get("ip") or {}).get("forward_protocol_nd"))
                return "boolean", bool(val)
            return "boolean", False
        elif metric == "ip_cef_enabled_bool":
            host = scope.get("host")
            for d in self.devices:
                if host and self._hostname(d) != host: continue
                val = (((d.get("services") or {}).get("ip") or {}).get("cef_enabled"))
                return "boolean", bool(val)
            return "boolean", False
        elif metric == "logging_buffered_severity_text":
            host = scope.get("host")
            for d in self.devices:
                if host and self._hostname(d) != host: continue
                val = ((d.get("logging") or {}).get("buffered_severity"))
                return "text", val or ""
            return "text", ""
        elif metric == "vty_first_last_text":
            host = scope.get("host")
            for d in self.devices:
                if host and self._hostname(d) != host: continue
                vty = ((d.get("line") or {}).get("vty") or {})
                first = vty.get("first"); last = vty.get("last")
                return "text", f"{first}~{last}" if (first is not None and last is not None) else ""
            return "text", ""
        elif metric == "vty_login_mode_text":
            host = scope.get("host")
            for d in self.devices:
                if host and self._hostname(d) != host: continue
                vty = ((d.get("line") or {}).get("vty") or {})
                return "text", (vty.get("login_mode") or "")
            return "text", ""
        elif metric == "vty_password_secret_text":
            host = scope.get("host")
            for d in self.devices:
                if host and self._hostname(d) != host: continue
                vty = ((d.get("line") or {}).get("vty") or {})
                return "text", (vty.get("password_secret") or "")
            return "text", ""
        elif metric == "vty_transport_input_text":
            host = scope.get("host")
            for d in self.devices:
                if host and self._hostname(d) != host: continue
                vty = ((d.get("line") or {}).get("vty") or {})
                return "text", (vty.get("transport_input") or "")
            return "text", ""
        elif metric == "interface_mop_xenabled_bool":
            host = scope.get("host"); if_name = scope.get("if")
            for d in self.devices:
                if host and self._hostname(d) != host: continue
                for i in d.get("interfaces") or []:
                    if i.get("name") == if_name:
                        return "boolean", bool(i.get("mop_xenabled"))
            return "boolean", False
        elif metric == "system_users_detail_map":
            host = scope.get("host")
            for d in self.devices:
                if host and self._hostname(d) != host: continue
                mp = {}
                for u in ((d.get("system") or {}).get("users") or []):
                    nm = (u or {}).get("name")
                    if not nm: continue
                    mp[nm] = {k:v for k,v in u.items() if k!="name" and v is not None}
                return "map", mp
            return "map", {}

        # ---- existing metrics continue ----
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
                val = bool(((d.get("security") or {}).get("ssh") or {}).get("present"))
                return "boolean", val
            return "boolean", False

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
                val = bool(((d.get("security") or {}).get("aaa") or {}).get("present"))
                return "boolean", val
            return "boolean", False

        elif metric == "password_policy_present_bool":
            host = scope.get("host")
            for d in self.devices:
                if host and self._hostname(d) != host: continue
                val = bool(((d.get("security") or {}).get("password_policy") or {}).get("present"))
                return "boolean", val
            return "boolean", False

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

        elif metric == "interface_vlan_set":
            host = scope.get("host")
            for d in self.devices:
                if host and self._hostname(d) != host: continue
                vl=set()
                for i in d.get("interfaces") or []:
                    v = i.get("vlan") or i.get("switchport_vlan")
                    if v: vl.add(str(v))
                return "set", sorted(vl)
            return "set", []

        elif metric == "subinterface_count":
            host = scope.get("host")
            for d in self.devices:
                if host and self._hostname(d) != host: continue
                c=0
                for i in d.get("interfaces") or []:
                    subs=i.get("subinterfaces") or []
                    c += len(subs)
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
                    if name: mp[name]=vrf or ""
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
                for p in (ospf.get("processes") or []):
                    if p.get("id") is not None: s.add(str(p.get("id")))
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

        elif metric == "ebgp_remote_as_map":
            host = scope.get("host")
            vrf  = scope.get("vrf")
            mp = {}
            for d in self.devices:
                if host and (d.get("system",{}).get("hostname") != host): 
                    continue
                bgp = (d.get("routing",{}) or {}).get("bgp",{}) or {}
                for v in (bgp.get("vrfs") or []):
                    if vrf and v.get("name") != vrf: 
                        continue
                    for n in (v.get("neighbors") or []):
                        if n.get("type") == "ebgp":
                            peer = n.get("ip") or n.get("id")
                            if peer:
                                mp[peer] = n.get("remote_as")
            return "map", mp

        elif metric == "ibgp_update_source_missing_set":
            asn = scope.get("asn")
            missing=[]
            for d in self.devices:
                bgp = (d.get("routing",{}) or {}).get("bgp",{}) or {}
                if asn and str(bgp.get("local_as")) != str(asn): 
                    continue
                for n in (bgp.get("neighbors") or []):
                    if n.get("type") == "ibgp":
                        if not n.get("update_source"):
                            host = d.get("system",{}).get("hostname") or d.get("file")
                            peer = n.get("ip") or n.get("id")
                            missing.append(f"{host}~{peer}")
            return "set", sorted(set(missing))

        elif metric == "vrf_interface_bind_count":
            host = scope.get("host"); vrf = scope.get("vrf")
            cnt=0
            for d in self.devices:
                if host and (d.get("system",{}).get("hostname") != host): 
                    continue
                for iface in (d.get("interfaces") or []):
                    if (iface.get("vrf") or iface.get("l3vrf")) == (vrf or iface.get("vrf")):
                        cnt += 1
            return "numeric", cnt

        elif metric == "vrf_rd_format_invalid_set":
            bad=[]
            import re
            pat_asn = re.compile(r"^\d{1,10}:\d{1,10}$")
            pat_ip  = re.compile(r"^\d{1,3}(\.\d{1,3}){3}:\d{1,10}$")
            for d in self.devices:
                bgp = (d.get("routing",{}) or {}).get("bgp",{}) or {}
                for v in (bgp.get("vrfs") or []):
                    rd = (v.get("rd") or "").strip()
                    if not rd:
                        continue
                    if not (pat_asn.match(rd) or pat_ip.match(rd)):
                        bad.append(v.get("name") or "unknown")
            return "set", sorted(set(bad))

        elif metric == "ibgp_fullmesh_ok":
            asn = scope.get("asn")
            miss = pre["bgp_missing_pairs_by_as"].get(asn, set())
            return "boolean", (len(miss)==0)
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
        elif metric == "ospf_proc_ids":
            host = scope.get("host")
            d = self.host_index.get(host)
            if not d: return "text", None
            pids = (self._ospf(d).get("process_ids") or [])[:1]
            return "text", (pids[0] if pids else None)

        elif metric == "ssh_enabled_devices":
            return "set", sorted(list(pre["ssh_enabled"]))
        elif metric == "ssh_missing_devices":
            return "set", sorted(list(pre["ssh_missing"]))
        elif metric == "ssh_missing_count":
            return "numeric", len(pre["ssh_missing"]) 
        elif metric == "ssh_all_enabled_bool":
            return "boolean", (len(pre["ssh_missing"]) == 0)
        
        return "text", None

    # ---------- DSL → 테스트 인스턴스 확장 ----------
    def expand_from_dsl(self, dsl: List[Dict[str,Any]], k_variant: int = 1) -> Dict[str, List[Dict[str, Any]]]:
        out: Dict[str, List[Dict[str, Any]]] = {}
        pre = self._precompute()

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

        # 인터페이스 후보
        iface_names: List[str] = []
        for d in self.devices:
            for i in (d.get("interfaces") or []):
                if i.get("name"):
                    iface_names.append(i["name"])
        iface_names = sorted(list(set(iface_names)))

        def iter_scopes(scope: Dict[str,Any]):
            st = scope.get("type")
            if st=="AS" and scope.get("asn")=="{asn}":
                for a in asns:
                    s=dict(scope); s["asn"]=a; yield s
            elif st=="DEVICE" and scope.get("host")=="{host}":
                for h in hosts:
                    s=dict(scope); s["host"]=h; yield s
            elif st=="VRF" and scope.get("vrf")=="{vrf}":
                for v in vrf_list:
                    s=dict(scope); s["vrf"]=v; yield s
            elif st=="DEVICE_VRF":
                for h in hosts:
                    for v in vrf_list:
                        s=dict(scope); s["host"]=h; s["vrf"]=v; yield s
            elif st=="DEVICE_IF":
                for h in hosts:
                    for ifn in iface_names:
                        s=dict(scope); s["host"]=h; s["if"]=ifn; yield s
            else:
                yield scope

        for t in dsl:
            cat = t["category"]; out.setdefault(cat, [])
            patt = t.get("pattern")
            metric = t.get("intent",{}).get("metric")
            scope = t.get("intent",{}).get("scope", {"type":"GLOBAL"})
            level = t.get("level")
            origin = t.get("origin")

            for sc in iter_scopes(scope):
                atype, val = self._answer_for_metric(metric, sc, pre)
                if not self._is_supported_answer(atype, val):
                    continue
                try:
                    q = patt.format(**sc) if isinstance(patt, str) else str(patt)
                except Exception:
                    q = str(patt)
                out[cat].append({
                    "test_id": f"DSL-{(metric or 'METRIC').upper()}-{hash(str(sc)) & 0xffff}",
                    "category": cat,
                    "answer_type": atype,
                    "question": q,
                    "expected_answer": {"value": val},
                    "evaluation_method": "exact_match",
                    "evidence_hint": {"scope": sc, "metric": metric},
                    "source_files": self._files_for_scope(sc),
                    "level": level,
                    "origin": origin
                })
        return out

    def _files_for_scope(self, sc: dict) -> List[str]:
        st = (sc.get("type") or "GLOBAL").upper()
        if st == "DEVICE":
            d = self.host_index.get(sc.get("host"))
            return [d.get("file") or ""] if d and d.get("file") else []
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
            d = self.host_index.get(sc.get("host"))
            return [d.get("file") or ""] if d and d.get("file") else []
        if st == "DEVICE_IF":
            d = self.host_index.get(sc.get("host"))
            return [d.get("file") or ""] if d and d.get("file") else []
        return [d.get("file") or "" for d in self.devices if d.get("file")]

SUPPORTED_METRICS: List[str] = [
    "system_hostname_text",
    "system_mgmt_address_text",
    "ios_config_register_text",
    "http_server_enabled_bool",
    "ip_forward_protocol_nd_bool",
    "ip_cef_enabled_bool",
    "logging_buffered_severity_text",
    "vty_first_last_text",
    "vty_login_mode_text",
    "vty_password_secret_text",
    "vty_transport_input_text",
    "interface_mop_xenabled_bool",
    "system_users_detail_map",
    "system_version_text",
    "system_timezone_text",
    "system_user_list",
    "system_user_count",
    "ssh_present_bool",
    "ssh_version_text",
    "aaa_present_bool",
    "password_policy_present_bool",
    "interface_count",
    "interface_ip_map",
    "interface_vlan_set",
    "subinterface_count",
    "vrf_bind_map",
    "bgp_local_as_numeric",
    "bgp_neighbor_count",
    "ospf_process_ids_set",
    "ospf_area_set",
    "vrf_names_set",
    "vrf_count",
    "vrf_rd_map",
    "rt_import_count",
    "rt_export_count",
    "l2vpn_pw_id_set",
    "neighbor_list_ibgp",
    "ebgp_remote_as_map",
    "ibgp_update_source_missing_set",
    "vrf_interface_bind_count",
    "vrf_rd_format_invalid_set",
    "ibgp_fullmesh_ok",
    "ibgp_missing_pairs",
    "ibgp_missing_pairs_count",
    "ibgp_under_peered_devices",
    "ibgp_under_peered_count",
    "vrf_without_rt_pairs",
    "vrf_without_rt_count",
    "vrf_rt_list_per_device",
    "l2vpn_pairs",
    "l2vpn_unidirectional_pairs",
    "l2vpn_unidir_count",
    "l2vpn_pwid_mismatch_pairs",
    "l2vpn_mismatch_count",
    "ospf_area0_if_list",
    "ospf_area0_if_count",
    "ospf_proc_ids",
    "ssh_enabled_devices",
    "ssh_missing_devices",
    "ssh_missing_count",
    "ssh_all_enabled_bool",
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
            if not metric: # metric이 없는 경우 에러 처리
                 raise ValueError("intent.metric is required for single metric questions")
            answer_type, value = core._answer_for_metric(metric, scope, pre)

        return {"answer_type": answer_type, "value": value}
    except Exception as e:
        print(f"[WARNING] metric computation failed for {intent.get('metric', 'composite_intent')}: {e}")
        return {"answer_type": "error", "value": {"error": "computation_failed", "details": str(e)}}