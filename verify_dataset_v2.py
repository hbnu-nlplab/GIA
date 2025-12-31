"""NetConfigQA Dataset Verification Tool (L1-L5)

독립적으로 정답을 재계산하여 데이터셋의 정확성을 검증합니다.
- L1-L3: facts.json 기반 계산
- L4: Batfish traceroute 검증
- L5: Batfish what-if 분석 검증

Usage:
    python verify_dataset_v2.py \
        --csv Data/Pnetlab/.../dataset.csv \
        --facts Data/Pnetlab/.../facts.json \
        --snapshot Data/Pnetlab/Research_Institute_Internal_DC \
        --batfish-host localhost
"""

from __future__ import annotations

import argparse
import ast
import csv
import json
import re
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

# ============================================================================
# Data Classes
# ============================================================================

@dataclass
class VerifyResult:
    row_num: int
    row_id: str
    level: str
    category: str
    metric: str
    answer_type: str
    status: str  # PASS | FAIL | SKIP
    reason: str
    expected: str = ""
    actual: str = ""
    question: str = ""


@dataclass  
class VerifyStats:
    total: int = 0
    passed: int = 0
    failed: int = 0
    skipped: int = 0
    by_level: Dict[str, Counter] = field(default_factory=lambda: {})
    by_metric: Counter = field(default_factory=Counter)
    failures: List[VerifyResult] = field(default_factory=list)


# ============================================================================
# Utility Functions
# ============================================================================

def normalize_text(val: Any) -> str:
    """텍스트 정규화: 소문자, 공백 제거, 따옴표 제거"""
    if val is None:
        return ""
    s = str(val).strip()
    # Remove surrounding quotes
    for q in ['"""', "'''", '"', "'"]:
        if s.startswith(q) and s.endswith(q):
            s = s[len(q):-len(q)]
    return s.lower().strip()


def normalize_set(val: Any) -> Set[str]:
    """집합 정규화: 순서 무관 비교용"""
    if val is None:
        return set()
    if isinstance(val, set):
        return {normalize_text(x) for x in val}
    if isinstance(val, (list, tuple)):
        return {normalize_text(x) for x in val}
    if isinstance(val, str):
        try:
            parsed = json.loads(val)
            if isinstance(parsed, list):
                return {normalize_text(x) for x in parsed}
        except:
            pass
        try:
            parsed = ast.literal_eval(val)
            if isinstance(parsed, (list, set)):
                return {normalize_text(x) for x in parsed}
        except:
            pass
    return {normalize_text(val)}


def parse_answer(raw: str, answer_type: str) -> Any:
    """CSV의 answer 필드 파싱"""
    if raw is None or raw == "":
        return None
    
    txt = str(raw).strip()
    
    # Remove triple quotes
    for q in ['"""', "'''"]:
        if txt.startswith(q) and txt.endswith(q):
            txt = txt[len(q):-len(q)]
    
    if answer_type in {"set", "map"}:
        for loader in (json.loads, ast.literal_eval):
            try:
                return loader(txt)
            except:
                continue
        return txt
    
    if answer_type in {"numeric", "number"}:
        try:
            # Remove quotes first
            cleaned = txt.strip('"').strip("'")
            return float(cleaned) if '.' in cleaned else int(cleaned)
        except:
            return None
    
    # text
    return normalize_text(txt)


def compare_answers(expected: Any, actual: Any, answer_type: str) -> bool:
    """정답 비교 (관용적 비교)"""
    if expected is None or actual is None:
        return expected is None and actual is None
    
    if answer_type in {"numeric", "number"}:
        try:
            return float(expected) == float(actual)
        except:
            return False
    
    if answer_type == "set":
        return normalize_set(expected) == normalize_set(actual)
    
    if answer_type == "map":
        try:
            exp_keys = set(expected.keys())
            act_keys = set(actual.keys())
            if exp_keys != act_keys:
                return False
            for k in exp_keys:
                if normalize_text(expected[k]) != normalize_text(actual[k]):
                    return False
            return True
        except:
            return False
    
    # text
    return normalize_text(expected) == normalize_text(actual)


def extract_host_from_question(question: str) -> Optional[str]:
    """질문에서 호스트명 추출"""
    patterns = [
        r"(\w+) 장비",
        r"(\w+)에서",
        r"장비 (\w+)",
    ]
    for p in patterns:
        m = re.search(p, question, re.IGNORECASE)
        if m:
            return m.group(1).lower()
    return None


def extract_scope_from_evidence(evidence: str) -> Dict[str, Any]:
    """evidence 필드에서 scope 정보 추출"""
    try:
        evid = json.loads(evidence)
        return evid.get("scope", {})
    except:
        return {}


# ============================================================================
# Facts-based Evaluators (L1-L3)
# ============================================================================

class FactsEvaluator:
    """Facts JSON 기반 정답 계산기"""
    
    def __init__(self, facts: Dict[str, Any]):
        self.facts = facts
        self.devices = {
            d.get("system", {}).get("hostname", "").lower(): d
            for d in facts.get("devices", [])
        }
        # Also index by filename
        for d in facts.get("devices", []):
            fname = d.get("file", "").lower().removesuffix(".cfg")
            if fname and fname not in self.devices:
                self.devices[fname] = d
    
    def get_device(self, host: str) -> Optional[Dict[str, Any]]:
        return self.devices.get(host.lower())
    
    def evaluate(self, metric: str, host: str) -> Tuple[Optional[Any], str]:
        """메트릭별 정답 계산. (값, 이유) 반환"""
        device = self.get_device(host)
        if not device:
            return None, f"device_not_found:{host}"
        
        # Metric-specific evaluators
        evaluators = {
            # System Inventory
            "system_hostname_text": lambda d: d.get("system", {}).get("hostname"),
            "system_version_text": lambda d: d.get("system", {}).get("version"),
            "system_user_list": lambda d: d.get("system", {}).get("users", []),
            "system_user_count": lambda d: len(d.get("system", {}).get("users", []) or []),
            "domain_name_text": lambda d: d.get("system", {}).get("domain_name"),
            
            # Interface Inventory
            "interface_count": lambda d: d.get("num_interfaces") or len(d.get("interfaces", [])),
            "interface_status_map": lambda d: {
                iface.get("name"): iface.get("status")
                for iface in d.get("interfaces", [])
            },
            "interface_ip_map": lambda d: {
                iface.get("name"): iface.get("ipv4", "")
                for iface in d.get("interfaces", [])
            },
            
            # Security Inventory
            "ssh_version_text": lambda d: d.get("security", {}).get("ssh", {}).get("version"),
            "aaa_authentication_method": lambda d: d.get("security", {}).get("aaa", {}).get("method"),
            "vty_transport_input_text": lambda d: d.get("line", {}).get("vty", {}).get("transport_input"),
            "vty_login_mode_text": lambda d: d.get("line", {}).get("vty", {}).get("login_mode"),
            
            # Routing Inventory
            "bgp_local_as_numeric": lambda d: d.get("routing", {}).get("bgp", {}).get("local_as"),
            "bgp_neighbor_count": lambda d: len(d.get("routing", {}).get("bgp", {}).get("neighbors", []) or []),
            "ospf_process_ids_set": lambda d: d.get("routing", {}).get("ospf", {}).get("process_ids", []),
            "ospf_area_set": lambda d: list(d.get("routing", {}).get("ospf", {}).get("areas", {}).keys()) if isinstance(d.get("routing", {}).get("ospf", {}).get("areas"), dict) else [],
            
            # Services Inventory
            "ntp_server_list": lambda d: d.get("services", {}).get("ntp", {}).get("servers", []),
            "vrf_names_set": lambda d: [v.get("name") for v in d.get("services", {}).get("vrf", []) if v.get("name")],
            "vrf_count": lambda d: len(d.get("services", {}).get("vrf", []) or []) if d.get("services", {}).get("vrf") else 0,
            "mpls_ldp_router_id": lambda d: d.get("services", {}).get("mpls", {}).get("ldp_router_id"),
            
            # Configuration Check
            "static_route_count": lambda d: d.get("configuration", {}).get("routing", {}).get("static_routes_count"),
            "ip_routing_enabled": lambda d: d.get("configuration", {}).get("routing", {}).get("ip_routing"),
            "cdp_enabled": lambda d: d.get("configuration", {}).get("routing", {}).get("cdp_run"),
            
            # Logging
            "syslog_server_list": lambda d: d.get("logging", {}).get("hosts", []),
        }
        
        metric_lower = metric.lower()
        if metric_lower in evaluators:
            try:
                val = evaluators[metric_lower](device)
                return val, "evaluated"
            except Exception as e:
                return None, f"eval_error:{e}"
        
        return None, f"no_evaluator:{metric}"


# ============================================================================
# Batfish-based Evaluators (L4-L5)
# ============================================================================

class BatfishEvaluator:
    """Batfish 기반 L4/L5 검증기"""
    
    def __init__(self, snapshot_path: str, host: str = "localhost"):
        self.snapshot_path = Path(snapshot_path)
        self.host = host
        self.bf = None
        self._initialized = False
    
    def _init_batfish(self) -> bool:
        """Batfish 세션 초기화"""
        if self._initialized:
            return self.bf is not None
        
        self._initialized = True
        try:
            from pybatfish.client.session import Session
            self.bf = Session(host=self.host)
            self.bf.set_network("verify_dataset_network")
            self.bf.init_snapshot(str(self.snapshot_path), name="verify_snapshot", overwrite=True)
            return True
        except Exception as e:
            print(f"[WARN] Batfish init failed: {e}")
            self.bf = None
            return False
    
    def verify_traceroute(self, src: str, dst_ip: str, expected_path: str) -> Tuple[bool, str, str]:
        """L4 Traceroute 검증. (일치여부, 실제경로, 이유) 반환"""
        if not self._init_batfish():
            return False, "", "batfish_unavailable"
        
        try:
            from pybatfish.datamodel.flow import HeaderConstraints
            
            result = self.bf.q.traceroute(
                startLocation=src.lower(),
                headers=HeaderConstraints(dstIps=dst_ip)
            ).answer().frame()
            
            if result.empty:
                return False, "결과 없음", "empty_result"
            
            traces = result['Traces'].iloc[0]
            if not traces or len(traces) == 0:
                actual = "경로 없음"
            else:
                trace = traces[0]
                disposition = getattr(trace, 'disposition', 'UNKNOWN')
                hops = getattr(trace, 'hops', [])
                
                if disposition in ['NO_ROUTE', 'NULL_ROUTED', 'UNREACHABLE']:
                    actual = "경로 없음"
                else:
                    path_nodes = []
                    for hop in hops:
                        node = getattr(hop, 'node', None)
                        if node:
                            path_nodes.append(getattr(node, 'hostname', str(node)))
                    actual = " → ".join(path_nodes) if path_nodes else "경로 없음"
            
            # Compare
            expected_norm = normalize_text(expected_path)
            actual_norm = normalize_text(actual)
            
            match = expected_norm == actual_norm
            return match, actual, "verified"
            
        except Exception as e:
            return False, "", f"traceroute_error:{e}"
    
    def verify_bounded_path_length(self, src: str, dst_ip: str, expected_hops: int) -> Tuple[bool, Any, str]:
        """L4 Bounded Path Length 검증 (홉 수)"""
        if not self._init_batfish():
            return False, None, "batfish_unavailable"
        
        try:
            from pybatfish.datamodel.flow import HeaderConstraints
            
            result = self.bf.q.traceroute(
                startLocation=src.lower(),
                headers=HeaderConstraints(dstIps=dst_ip)
            ).answer().frame()
            
            if result.empty:
                return False, 0, "empty_result"
            
            traces = result['Traces'].iloc[0]
            if not traces or len(traces) == 0:
                return False, 0, "no_trace"
            
            trace = traces[0]
            disposition = getattr(trace, 'disposition', 'UNKNOWN')
            hops = getattr(trace, 'hops', [])
            
            if disposition in ['NO_ROUTE', 'NULL_ROUTED', 'UNREACHABLE']:
                return False, 0, "no_route"
            
            actual_hops = len(hops)
            match = (actual_hops == expected_hops)
            return match, actual_hops, "verified"
            
        except Exception as e:
            return False, None, f"traceroute_error:{e}"
    
    def verify_reachability(self, src: str, dst_ip: str, expected: str) -> Tuple[bool, str, str]:
        """L4 Reachability 검증"""
        if not self._init_batfish():
            return False, "", "batfish_unavailable"
        
        try:
            from pybatfish.datamodel.flow import HeaderConstraints
            
            result = self.bf.q.reachability(
                headers=HeaderConstraints(dstIps=dst_ip),
                pathConstraints={"startLocation": src.lower()}
            ).answer().frame()
            
            actual = "도달 가능" if not result.empty else "도달 불가"
            expected_norm = normalize_text(expected)
            
            match = ("가능" in expected_norm) == (actual == "도달 가능")
            return match, actual, "verified"
            
        except Exception as e:
            return False, "", f"reachability_error:{e}"
    
    def verify_ospf_area0_routers(self, expected: Any) -> Tuple[bool, Any, str]:
        """L5 OSPF Area 0 라우터 검증"""
        if not self._init_batfish():
            return False, [], "batfish_unavailable"
        
        try:
            # OSPF 프로세스 설정에서 Area 0 확인
            ospf_config = self.bf.q.ospfProcessConfiguration().answer().frame()
            
            area0_routers = set()
            for _, row in ospf_config.iterrows():
                areas = row.get('Areas', [])
                node = row.get('VRF', '').split(':')[0] if ':' in str(row.get('VRF', '')) else str(row.get('Router_ID', ''))
                # Node name 추출 시도
                vrf_str = str(row.get('VRF', ''))
                if ':' in vrf_str:
                    node = vrf_str.split(':')[0]
                
                if 0 in areas or '0' in str(areas) or '0.0.0.0' in str(areas):
                    area0_routers.add(node.lower())
            
            actual = sorted(list(area0_routers))
            expected_set = normalize_set(expected)
            actual_set = {x.lower() for x in actual}
            
            match = expected_set == actual_set
            return match, actual, "verified"
            
        except Exception as e:
            return False, [], f"ospf_error:{e}"


# ============================================================================
# Main Verifier
# ============================================================================

class DatasetVerifier:
    """데이터셋 검증 메인 클래스"""
    
    def __init__(
        self,
        csv_path: Path,
        facts_path: Path,
        snapshot_path: Optional[Path] = None,
        batfish_host: str = "localhost"
    ):
        self.csv_path = csv_path
        self.facts_path = facts_path
        self.snapshot_path = snapshot_path
        self.batfish_host = batfish_host
        
        # Load data
        self.rows = self._load_csv()
        self.facts = self._load_json(facts_path)
        
        # Initialize evaluators
        self.facts_eval = FactsEvaluator(self.facts)
        self.batfish_eval = None
        if snapshot_path:
            self.batfish_eval = BatfishEvaluator(str(snapshot_path), batfish_host)
    
    def _load_csv(self) -> List[Dict[str, Any]]:
        with self.csv_path.open("r", encoding="utf-8-sig", newline="") as f:
            return list(csv.DictReader(f))
    
    def _load_json(self, path: Path) -> Dict[str, Any]:
        with path.open("r", encoding="utf-8") as f:
            return json.load(f)
    
    def verify_row(self, row: Dict[str, Any], row_num: int) -> VerifyResult:
        """단일 행 검증"""
        row_id = row.get("id", "")
        level = row.get("level", "")
        category = row.get("category", "")
        answer_type = row.get("answer_type", "")
        question = row.get("question", "")
        answer_raw = row.get("answer", "")
        evidence = row.get("evidence", "")
        
        # Extract metric from evidence or id
        try:
            evid = json.loads(evidence)
            metric = evid.get("metric", row_id).lower()
            scope = evid.get("scope", {})
        except:
            metric = row_id.lower()
            scope = {}
        
        # Parse actual answer from CSV
        actual = parse_answer(answer_raw, answer_type)
        
        # Route to appropriate verifier based on level
        if level in ["L1", "L2", "L3"]:
            return self._verify_facts_based(
                row_num, row_id, level, category, metric, answer_type,
                question, scope, actual
            )
        elif level == "L4":
            return self._verify_l4(
                row_num, row_id, level, category, metric, answer_type,
                question, scope, actual
            )
        elif level == "L5":
            return self._verify_l5(
                row_num, row_id, level, category, metric, answer_type,
                question, scope, actual
            )
        else:
            return VerifyResult(
                row_num=row_num, row_id=row_id, level=level, category=category,
                metric=metric, answer_type=answer_type,
                status="SKIP", reason=f"unknown_level:{level}",
                question=question[:100]
            )
    
    def _verify_facts_based(
        self, row_num: int, row_id: str, level: str, category: str,
        metric: str, answer_type: str, question: str,
        scope: Dict[str, Any], actual: Any
    ) -> VerifyResult:
        """L1-L3 Facts 기반 검증"""
        
        # Determine host
        scope_type = scope.get("type", "")
        if scope_type == "DEVICE":
            host = extract_host_from_question(question)
        elif scope_type == "GLOBAL":
            # Global metrics need special handling
            return VerifyResult(
                row_num=row_num, row_id=row_id, level=level, category=category,
                metric=metric, answer_type=answer_type,
                status="SKIP", reason="global_scope_not_implemented",
                question=question[:100]
            )
        else:
            host = extract_host_from_question(question)
        
        if not host:
            return VerifyResult(
                row_num=row_num, row_id=row_id, level=level, category=category,
                metric=metric, answer_type=answer_type,
                status="SKIP", reason="host_not_extracted",
                question=question[:100]
            )
        
        # Calculate expected value
        expected, reason = self.facts_eval.evaluate(metric, host)
        
        if expected is None:
            return VerifyResult(
                row_num=row_num, row_id=row_id, level=level, category=category,
                metric=metric, answer_type=answer_type,
                status="SKIP", reason=reason,
                question=question[:100]
            )
        
        # Compare
        if compare_answers(expected, actual, answer_type):
            return VerifyResult(
                row_num=row_num, row_id=row_id, level=level, category=category,
                metric=metric, answer_type=answer_type,
                status="PASS", reason="match",
                expected=str(expected), actual=str(actual),
                question=question[:100]
            )
        else:
            return VerifyResult(
                row_num=row_num, row_id=row_id, level=level, category=category,
                metric=metric, answer_type=answer_type,
                status="FAIL", reason="mismatch",
                expected=str(expected), actual=str(actual),
                question=question[:100]
            )
    
    def _verify_l4(
        self, row_num: int, row_id: str, level: str, category: str,
        metric: str, answer_type: str, question: str,
        scope: Dict[str, Any], actual: Any
    ) -> VerifyResult:
        """L4 Batfish Traceroute/Reachability 검증"""
        
        if not self.batfish_eval:
            return VerifyResult(
                row_num=row_num, row_id=row_id, level=level, category=category,
                metric=metric, answer_type=answer_type,
                status="SKIP", reason="batfish_not_configured",
                question=question[:100]
            )
        
        # Extract src/dst from scope or question
        src = scope.get("src", "")
        dst = scope.get("dst", "")
        
        # Extract dst IP from question
        ip_match = re.search(r"(\d+\.\d+\.\d+\.\d+)", question)
        dst_ip = ip_match.group(1) if ip_match else ""
        
        if not src or not dst_ip:
            return VerifyResult(
                row_num=row_num, row_id=row_id, level=level, category=category,
                metric=metric, answer_type=answer_type,
                status="SKIP", reason="missing_src_dst",
                question=question[:100]
            )
        
        if "traceroute" in metric and "bounded" not in metric:
            match, computed, reason = self.batfish_eval.verify_traceroute(src, dst_ip, str(actual))
        elif "bounded_path_length" in metric:
            try:
                expected_hops = int(actual)
                match, computed, reason = self.batfish_eval.verify_bounded_path_length(src, dst_ip, expected_hops)
            except (ValueError, TypeError):
                return VerifyResult(
                    row_num=row_num, row_id=row_id, level=level, category=category,
                    metric=metric, answer_type=answer_type,
                    status="SKIP", reason="invalid_hop_count",
                    question=question[:100]
                )
        else:
            match, computed, reason = self.batfish_eval.verify_reachability(src, dst_ip, str(actual))
        
        if reason.startswith("batfish"):
            return VerifyResult(
                row_num=row_num, row_id=row_id, level=level, category=category,
                metric=metric, answer_type=answer_type,
                status="SKIP", reason=reason,
                question=question[:100]
            )
        
        status = "PASS" if match else "FAIL"
        return VerifyResult(
            row_num=row_num, row_id=row_id, level=level, category=category,
            metric=metric, answer_type=answer_type,
            status=status, reason=reason,
            expected=str(actual), actual=computed,
            question=question[:100]
        )
    
    def _verify_l5(
        self, row_num: int, row_id: str, level: str, category: str,
        metric: str, answer_type: str, question: str,
        scope: Dict[str, Any], actual: Any
    ) -> VerifyResult:
        """L5 What-If Analysis 검증"""
        
        if not self.batfish_eval:
            return VerifyResult(
                row_num=row_num, row_id=row_id, level=level, category=category,
                metric=metric, answer_type=answer_type,
                status="SKIP", reason="batfish_not_configured",
                question=question[:100]
            )
        
        if "ospf_area0_routers" in metric:
            match, computed, reason = self.batfish_eval.verify_ospf_area0_routers(actual)
            status = "PASS" if match else "FAIL"
            return VerifyResult(
                row_num=row_num, row_id=row_id, level=level, category=category,
                metric=metric, answer_type=answer_type,
                status=status, reason=reason,
                expected=str(actual), actual=str(computed),
                question=question[:100]
            )
        
        # Other L5 metrics: skip for now
        return VerifyResult(
            row_num=row_num, row_id=row_id, level=level, category=category,
            metric=metric, answer_type=answer_type,
            status="SKIP", reason=f"l5_metric_not_implemented:{metric}",
            question=question[:100]
        )
    
    def verify_all(self) -> VerifyStats:
        """전체 데이터셋 검증"""
        stats = VerifyStats(total=len(self.rows))
        
        print(f"\n검증 시작: {len(self.rows)} 문항")
        print("=" * 60)
        
        for i, row in enumerate(self.rows, start=2):
            result = self.verify_row(row, i)
            
            # Update stats
            if result.status == "PASS":
                stats.passed += 1
            elif result.status == "FAIL":
                stats.failed += 1
                stats.failures.append(result)
            else:
                stats.skipped += 1
            
            # By level
            if result.level not in stats.by_level:
                stats.by_level[result.level] = Counter()
            stats.by_level[result.level][result.status] += 1
            
            # By metric (failures only)
            if result.status == "FAIL":
                stats.by_metric[result.metric] += 1
            
            # Progress
            if (i - 1) % 100 == 0:
                print(f"  진행: {i-1}/{len(self.rows)} ({stats.passed} PASS, {stats.failed} FAIL, {stats.skipped} SKIP)")
        
        print("=" * 60)
        print(f"완료: PASS={stats.passed}, FAIL={stats.failed}, SKIP={stats.skipped}")
        
        return stats
    
    def generate_report(self, stats: VerifyStats) -> str:
        """Markdown 리포트 생성"""
        lines = []
        lines.append("# NetConfigQA Dataset Verification Report")
        lines.append(f"\n> Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        lines.append(f"> Dataset: `{self.csv_path.name}`")
        lines.append("")
        
        # Summary
        lines.append("## 1. Summary")
        lines.append("")
        lines.append("| Metric | Count | Percentage |")
        lines.append("|--------|------:|------------|")
        lines.append(f"| Total | {stats.total} | 100% |")
        lines.append(f"| ✅ PASS | {stats.passed} | {stats.passed/stats.total*100:.1f}% |")
        lines.append(f"| ❌ FAIL | {stats.failed} | {stats.failed/stats.total*100:.1f}% |")
        lines.append(f"| ⏭️ SKIP | {stats.skipped} | {stats.skipped/stats.total*100:.1f}% |")
        lines.append("")
        
        # By Level
        lines.append("## 2. Results by Level")
        lines.append("")
        lines.append("| Level | PASS | FAIL | SKIP | Total |")
        lines.append("|-------|-----:|-----:|-----:|------:|")
        for lvl in sorted(stats.by_level.keys()):
            c = stats.by_level[lvl]
            total = c["PASS"] + c["FAIL"] + c["SKIP"]
            lines.append(f"| {lvl} | {c['PASS']} | {c['FAIL']} | {c['SKIP']} | {total} |")
        lines.append("")
        
        # Top Failures by Metric
        if stats.by_metric:
            lines.append("## 3. Top Failed Metrics")
            lines.append("")
            lines.append("| Metric | Fail Count |")
            lines.append("|--------|----------:|")
            for metric, count in stats.by_metric.most_common(10):
                lines.append(f"| {metric} | {count} |")
            lines.append("")
        
        # Sample Failures
        if stats.failures:
            lines.append("## 4. Sample Failures (Top 20)")
            lines.append("")
            for r in stats.failures[:20]:
                lines.append(f"### Row {r.row_num}: {r.row_id}")
                lines.append(f"- **Level**: {r.level}, **Category**: {r.category}")
                lines.append(f"- **Metric**: {r.metric}")
                lines.append(f"- **Reason**: {r.reason}")
                lines.append(f"- **Expected**: `{r.expected}`")
                lines.append(f"- **Actual**: `{r.actual}`")
                lines.append(f"- **Question**: {r.question}...")
                lines.append("")
        
        return "\n".join(lines)
    
    def save_failures_csv(self, path: Path, stats: VerifyStats) -> None:
        """실패 목록 CSV 저장"""
        if not stats.failures:
            return
        
        with path.open("w", encoding="utf-8", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=[
                "row_num", "row_id", "level", "category", "metric",
                "answer_type", "status", "reason", "expected", "actual", "question"
            ])
            writer.writeheader()
            for r in stats.failures:
                writer.writerow({
                    "row_num": r.row_num,
                    "row_id": r.row_id,
                    "level": r.level,
                    "category": r.category,
                    "metric": r.metric,
                    "answer_type": r.answer_type,
                    "status": r.status,
                    "reason": r.reason,
                    "expected": r.expected,
                    "actual": r.actual,
                    "question": r.question,
                })


# ============================================================================
# CLI Entry Point
# ============================================================================

def main():
    parser = argparse.ArgumentParser(description="NetConfigQA Dataset Verification Tool")
    parser.add_argument("--csv", required=True, help="Path to dataset CSV")
    parser.add_argument("--facts", required=True, help="Path to facts JSON")
    parser.add_argument("--snapshot", help="Path to Batfish snapshot (configs directory parent)")
    parser.add_argument("--batfish-host", default="localhost", help="Batfish server host")
    parser.add_argument("--output-md", help="Output markdown report path")
    parser.add_argument("--output-csv", help="Output failures CSV path")
    args = parser.parse_args()
    
    csv_path = Path(args.csv)
    facts_path = Path(args.facts)
    snapshot_path = Path(args.snapshot) if args.snapshot else None
    
    # Verify
    verifier = DatasetVerifier(
        csv_path=csv_path,
        facts_path=facts_path,
        snapshot_path=snapshot_path,
        batfish_host=args.batfish_host
    )
    
    stats = verifier.verify_all()
    
    # Generate report
    report = verifier.generate_report(stats)
    
    md_path = Path(args.output_md) if args.output_md else csv_path.with_name(csv_path.stem + "_verification.md")
    md_path.write_text(report, encoding="utf-8")
    print(f"\n📄 Report saved: {md_path}")
    
    # Save failures
    csv_out = Path(args.output_csv) if args.output_csv else csv_path.with_name(csv_path.stem + "_verification_failures.csv")
    verifier.save_failures_csv(csv_out, stats)
    if stats.failures:
        print(f"📋 Failures CSV: {csv_out}")
    
    print("\n" + report)


if __name__ == "__main__":
    main()
