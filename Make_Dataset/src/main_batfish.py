
import argparse
import json
import time
import subprocess
from pathlib import Path
import sys
import random
import itertools
import pandas as pd

"""
python Make_Dataset\\src\\main_batfish.py --lab-path Data\\Pnetlab\\Research_Institute_Internal_DC --policies Make_Dataset\\policies.json
"""

# src 패키지를 찾기 위해 경로 추가
sys.path.append(str(Path(__file__).parent))

from core_batfish.parser import UniversalParser
from core_batfish.rule_based_generator import RuleBasedGenerator, RuleBasedGeneratorConfig
from core_batfish.builder_core import BuilderCore
from core_batfish.batfish_builder import BatfishBuilder, AnswerResult

# ============================================================================
# NetConfigQA 벤치마크 파이프라인 - Phase 1: 스키마 검증
# ============================================================================

# JSON Schema 정의: 각 answer_type에 대한 검증 규칙
ANSWER_SCHEMAS = {
    "set_str": {"type": "array", "items": {"type": "string"}},
    "edge_set": {
        "type": "array",
        "items": {
            "type": "array",
            "items": {"type": "string"},
            "minItems": 2,
            "maxItems": 2
        }
    },
    "map_str_int": {"type": "object", "additionalProperties": {"type": "integer"}},
    "map_str_str": {"type": "object", "additionalProperties": {"type": "string"}},
    "path": {"type": "array", "items": {"type": "string"}},
    "enum": {"type": "string"},
    "scalar_str": {"type": "string"},
    "scalar_int": {"type": "integer"},
    "bool": {"type": "boolean"},
}


def validate_answer(value, answer_type: str) -> tuple:
    """
    정답이 스키마를 준수하는지 검증
    
    Args:
        value: 검증할 정답 값
        answer_type: 정답 타입
    
    Returns:
        (is_valid: bool, error_message: str)
    """
    if answer_type not in ANSWER_SCHEMAS:
        return True, ""  # 알려지지 않은 타입은 통과
    
    schema = ANSWER_SCHEMAS[answer_type]
    
    try:
        # 간단한 타입 검증 (jsonschema 라이브러리 없이도 동작)
        if schema["type"] == "array":
            if not isinstance(value, list):
                return False, f"Expected array, got {type(value).__name__}"
            if "items" in schema:
                item_schema = schema["items"]
                for i, item in enumerate(value):
                    if item_schema.get("type") == "string" and not isinstance(item, str):
                        return False, f"Item {i} should be string, got {type(item).__name__}"
                    if item_schema.get("type") == "array" and not isinstance(item, list):
                        return False, f"Item {i} should be array, got {type(item).__name__}"
        
        elif schema["type"] == "object":
            if not isinstance(value, dict):
                return False, f"Expected object, got {type(value).__name__}"
            if "additionalProperties" in schema:
                expected_type = schema["additionalProperties"]["type"]
                for k, v in value.items():
                    if expected_type == "integer" and not isinstance(v, int):
                        return False, f"Value for '{k}' should be integer, got {type(v).__name__}"
                    if expected_type == "string" and not isinstance(v, str):
                        return False, f"Value for '{k}' should be string, got {type(v).__name__}"
        
        elif schema["type"] == "string":
            if not isinstance(value, str):
                return False, f"Expected string, got {type(value).__name__}"
        
        elif schema["type"] == "integer":
            if not isinstance(value, int):
                return False, f"Expected integer, got {type(value).__name__}"
        
        elif schema["type"] == "boolean":
            if not isinstance(value, bool):
                return False, f"Expected boolean, got {type(value).__name__}"
        
        return True, ""
    
    except Exception as e:
        return False, f"Validation error: {e}"


def get_pipeline_version() -> str:
    """Git commit hash를 파이프라인 버전으로 사용"""
    try:
        return subprocess.check_output(
            ["git", "rev-parse", "--short", "HEAD"],
            cwd=Path(__file__).parent.parent.parent,
            stderr=subprocess.DEVNULL
        ).decode().strip()
    except:
        return "unknown"


PIPELINE_VERSION = get_pipeline_version()


def print_quality_report(rows: list):
    """
    데이터 품질 리포트 출력
    
    Args:
        rows: CSV 행 리스트
    """
    total = len(rows)
    if total == 0:
        print("\n[품질 리포트] 데이터가 없습니다.")
        return
    
    status_counts = {"OK": 0, "NOT_CONFIGURED": 0, "NOT_APPLICABLE": 0, "UNKNOWN": 0}
    unknown_by_reason = {}
    
    for r in rows:
        s = r.get("answer_status", "OK")  # 기존 호환성을 위해 기본값 OK
        status_counts[s] = status_counts.get(s, 0) + 1
        if s == "UNKNOWN":
            reason = r.get("unknown_reason", "UNSPECIFIED")
            unknown_by_reason[reason] = unknown_by_reason.get(reason, 0) + 1
    
    print("\n" + "=" * 60)
    print("📊 NetConfigQA 데이터 품질 리포트")
    print("=" * 60)
    
    # Status 분포
    print("\n[Status Distribution]")
    for status, count in status_counts.items():
        pct = count / total * 100
        bar = "█" * int(pct / 2)
        print(f"  {status:18s}: {count:4d} ({pct:5.1f}%) {bar}")
    
    # 핵심 지표
    valid_total = total - status_counts.get("UNKNOWN", 0)
    coverage = (1 - status_counts.get("UNKNOWN", 0) / total) * 100 if total > 0 else 0
    na_rate = status_counts.get("NOT_APPLICABLE", 0) / valid_total * 100 if valid_total > 0 else 0
    neg_rate = status_counts.get("NOT_CONFIGURED", 0) / valid_total * 100 if valid_total > 0 else 0
    
    print(f"\n[Key Metrics]")
    print(f"  📈 Coverage (1 - unknown_rate): {coverage:.1f}%")
    print(f"  📈 NOT_APPLICABLE Rate: {na_rate:.1f}%")
    print(f"  📈 Negative Evidence Rate: {neg_rate:.1f}%")
    print(f"  📈 Pipeline Version: {PIPELINE_VERSION}")
    
    # UNKNOWN 상세 분석
    if status_counts.get("UNKNOWN", 0) > 0:
        print(f"\n[UNKNOWN Breakdown by Reason]")
        for reason, cnt in sorted(unknown_by_reason.items(), key=lambda x: -x[1]):
            print(f"  ⚠️ {reason}: {cnt}건")
        
        if status_counts.get("UNKNOWN", 0) / total > 0.05:
            print(f"\n  🚨 UNKNOWN 비율이 5%를 초과합니다. 파이프라인 점검이 필요합니다.")
    
    print("=" * 60 + "\n")


def main():
    parser = argparse.ArgumentParser(description="Generate Network Q&A Dataset (Batfish Edition)")
    parser.add_argument("--lab-path", required=True, help="Path to Lab directory (e.g. Data/Pnetlab/Research_Institute_Internal_DC)")
    parser.add_argument("--out-dir", default=None, help="Output directory (default: <lab-path>/Dataset)")
    parser.add_argument("--policies", default="policies.json", help="Path to policies JSON")
    parser.add_argument("--batfish-host", default="localhost", help="Batfish server host (e.g. localhost:8889)")
    parser.add_argument("--min-per-cat", type=int, default=50, help="Minimal questions per category")
    parser.add_argument(
        "--include-l6",
        action="store_true",
        help="Include L6 diagnostic question generation (disabled by default for IEEE TNMS submission scope).",
    )
    args = parser.parse_args()

    # [Antigravity Mod v3] - 8889 Port & Snapshot Root Fix
    print(f"[Info] NetConfigQA Dataset Generator (Batfish Edition) - v20240129-01")
    print(f"[Info] L6 generation mode: {'ENABLED (--include-l6)' if args.include_l6 else 'DISABLED (submission default)'}")
    
    lab_path = Path(args.lab_path).resolve()
    if not lab_path.exists():
        print(f"[Error] Lab path not found: {lab_path}")
        return
    
    # Batfish 스냅샷 루트(configs 폴더의 부모) 결정
    if lab_path.name in ["configs", "xml"]:
        snapshot_root = lab_path.parent
    elif (lab_path / "configs").exists():
        snapshot_root = lab_path
    elif (lab_path.parent / "configs").exists():
        snapshot_root = lab_path.parent
    else:
        # Fallback: 현재 경로를 일단 루트로 가정
        snapshot_root = lab_path
    
    # 텍스트 파이싱을 위한 실제 설정 파일 위치
    xml_dir = snapshot_root / "configs"
    if not xml_dir.exists():
        xml_dir = snapshot_root / "xml"
    if not xml_dir.exists():
        xml_dir = snapshot_root # Fallback

    # 결과 저장 디렉토리
    if not args.out_dir:
        out_dir = snapshot_root / "Dataset"
    else:
        out_dir = Path(args.out_dir).resolve()
    out_dir.mkdir(parents=True, exist_ok=True)

    timestamp = time.strftime("%Y%m%d_%H%M%S")
    
    # 2. 파싱 (Batfish Engine - Static Facts)
    print(f"[1] Parsing configurations using Batfish from root: {snapshot_root}")
    u_parser = UniversalParser()
    try:
        # snapshot_root를 넘겨서 내부에서 configs 폴더를 찾게 함
        facts = u_parser.parse_dir(str(snapshot_root), batfish_host=args.batfish_host)
    except Exception as e:
        print(f"[Error] Batfish parsing failed: {e}")
        import traceback
        traceback.print_exc()
        return

    # Facts 저장
    facts_out = out_dir / f"{snapshot_root.name}_batfish_facts_{timestamp}.json"
    facts_out.write_text(json.dumps(facts, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"    -> Saved facts to {facts_out}")

    # 3. Batfish Dynamic Engine 초기화 (for L4/L5) & Policy 로드
    print(f"[1.5] Initializing Batfish Simulation Engine and Resolving Policies...")
    
    # Policy Resolution (Moved UP)
    print(f"      Resolving policies from: {args.policies}")
    if args.policies == "policies.json":
        policy_path = Path(__file__).parent.parent / "policies.json"
    else:
        policy_path = Path(args.policies)
        
    if not policy_path.exists():
        print(f"[Error] Policy file not found: {policy_path.resolve()}")
        return

    # Batfish Init with policies_path
    bf_builder = BatfishBuilder(
        snapshot_path=str(snapshot_root), 
        network_name=snapshot_root.name,
        policies_path=str(policy_path),
        batfish_host=args.batfish_host
    )
    bf_active = bf_builder.initialize()
    if bf_active:
        print(f"    -> Batfish Engine Ready (Nodes: {len(bf_builder.nodes)})")
    else:
        print(f"    -> [Warning] Batfish Engine failed to initialize. L4/L5 questions will be skipped.")

    # 4. 질문 생성 (Rule Based)
    print(f"[2] Generating questions using policies: {policy_path}")
    # (policy_path is already resolved)
        
    cfg = RuleBasedGeneratorConfig(policies_path=str(policy_path), min_per_cat=args.min_per_cat)
    gen = RuleBasedGenerator(cfg)
    
    categories = [
        "Configuration_Check", "Hardware_Inventory",
        "System_Inventory", "Security_Inventory", "Interface_Inventory", 
        "Routing_Inventory", "Services_Inventory", "Security_Policy",
        "OSPF_Consistency", "BGP_Consistency", "VRF_Consistency", 
        "L2VPN_Consistency", "Comparison_Analysis", "Reachability_Analysis", "What_If_Analysis"
    ]
    
    dsl_items = gen.compile(capabilities={}, categories=categories)
    print(f"    -> Compiled {len(dsl_items)} logic rules. Generating instances...")

    # 5. 답변 계산 (Builder Core + Batfish Builder)
    print(f"[3] Building answers...")
    builder = BuilderCore(facts)
    
    # --- Helper: IP Address Map for Flows ---
    host_ips = {} 
    if "devices" in facts:
        for d in facts["devices"]:
            h = d.get("system", {}).get("hostname") or d.get("file")
            ips = []
            for i in d.get("interfaces", []):
                ip_cidr = i.get("ipv4") or i.get("ip")
                if ip_cidr:
                    ip = ip_cidr.split("/")[0]
                    ips.append(ip)
            ips.sort(key=lambda x: 0 if x.startswith("10.255") else 1)
            host_ips[h] = ips

    all_hosts = [d["system"]["hostname"] for d in facts["devices"]]
    all_asns = set()
    for d in facts["devices"]:
        las = d.get("routing", {}).get("bgp", {}).get("local_as")
        if las: all_asns.add(str(las))
    
    qa_list = []
    
    for dsl in dsl_items:
        level = dsl.get("level", "L1")
        if level in ["L4", "L5"] and not bf_active:
            continue

        intent_template = dsl["intent"]
        scope_template = intent_template.get("scope") or intent_template.get("params") or {}
        scope_type = scope_template.get("type", "GLOBAL")
        metric_name = intent_template.get("metric")
        
        instances = []
        
        # Scope Expansion

        if scope_type == "GLOBAL":
            instances.append({})
            
        elif scope_type == "DEVICE":
            for h in all_hosts:
                instances.append({"host": h})
                
        elif scope_type == "AS":
            for a in all_asns:
                instances.append({"asn": a})
                
        elif scope_type == "DEVICE_PAIR":
            pairs = list(itertools.combinations(all_hosts, 2))
            if len(pairs) > 20: pairs = random.sample(pairs, 20)
            for h1, h2 in pairs:
                instances.append({"host1": h1, "host2": h2})
        
        elif scope_type == "OSPF_AREA":
            areas = set()
            for d in facts["devices"]:
                ospf = d.get("routing", {}).get("ospf", {})
                for a in ospf.get("areas", {}):
                    if a is not None: areas.add(str(a))
            for a in areas:
                instances.append({"area": a})

        elif scope_type == "VRF":
            vrfs = set()
            for d in facts["devices"]:
                bgp_vrfs = d.get("routing", {}).get("bgp", {}).get("vrfs", [])
                for v in bgp_vrfs:
                    if v.get("name"): vrfs.add(v["name"])
            for v in vrfs:
                instances.append({"vrf": v})

        elif scope_type == "FLOW": 
            valid_hosts = [h for h in all_hosts if host_ips.get(h)]
            if len(valid_hosts) >= 2:
                for _ in range(5): 
                    src, dst = random.sample(valid_hosts, 2)
                    src_ip = host_ips[src][0]
                    dst_ip = host_ips[dst][0]
                    instances.append({
                        "src_host": src, "dst_host": dst,
                        "src_ip": src_ip, "dst_ip": dst_ip,
                        "dst_port": 80, "protocol": "TCP"
                    })

        elif scope_type == "LINK_FAILURE":
             # Use real edges from Batfish
             if bf_active:
                 edges = bf_builder.get_layer3_edges()
                 if edges:
                     # Sample edges if too many
                     if len(edges) > 10: edges = random.sample(edges, 10)
                     for edge in edges:
                         # For each link failure, we need a test flow
                         # Randomly pick 3 src-dst pairs
                         valid_hosts = [h for h in all_hosts if host_ips.get(h)]
                         if len(valid_hosts) >= 2:
                             for _ in range(3):
                                 t_src, t_dst = random.sample(valid_hosts, 2)
                                 instances.append({
                                     "node1": edge["node1"], 
                                     "node2": edge["node2"],
                                     "test_src": t_src,
                                     "test_dst": t_dst,
                                     "link": f"{edge['node1']} <-> {edge['node2']}",
                                     "src": t_src,
                                     "dst": t_dst
                                 })
        
        elif scope_type == "VRF_PAIR":
            if bf_active:
                vrfs = bf_builder.get_vrfs()
                if len(vrfs) >= 2:
                     pairs = list(itertools.combinations(vrfs, 2))
                     for v1, v2 in pairs:
                         instances.append({"vrf1": v1, "vrf2": v2})
        
        elif scope_type == "POLICY":
            instances.append({"policy_name": "Standard Security Policy"})

        random.shuffle(instances)
        if len(instances) > 20:
            instances = instances[:20]

        for inst in instances:
            intent = intent_template.copy()
            scope = scope_template.copy()
            for k, v in inst.items():
                scope[k] = v
            intent["scope"] = scope
            metric = intent.get("metric")
            
            res = None
            if level in ["L4", "L5"] and bf_active:
                try:
                    if metric == "traceroute_path":
                        src = inst.get("src_host") or inst.get("host")
                        dst_ip = inst.get("dst_ip")
                        dst_host = inst.get("dst_host")
                        if src and dst_ip:
                            res = bf_builder.traceroute_path(src, dst_ip, target_name=dst_host or "")
                            
                    elif metric == "reachability_status":
                        src_ip = inst.get("src_ip")
                        dst_ip = inst.get("dst_ip")
                        if src_ip and dst_ip:
                            res = bf_builder.reachability_status(src_ip, dst_ip)

                    elif metric == "loop_detection":
                        res = bf_builder.loop_detection()
                        
                    elif metric == "blackhole_detection":
                        res = bf_builder.blackhole_detection()
                        
                    elif metric == "acl_blocking_point":
                        src_ip = inst.get("src_ip")
                        dst_ip = inst.get("dst_ip")
                        if src_ip and dst_ip:
                            res = bf_builder.acl_blocking_point(src_ip, dst_ip)
                            
                    elif metric == "waypoint_check":
                         src_ip = inst.get("src_ip")
                         dst_ip = inst.get("dst_ip")
                         waypoint = inst.get("waypoint")
                         # Pick a PE/P node if not specified
                         if not waypoint and bf_active:
                             pe_nodes = bf_builder.get_pe_nodes()
                             if pe_nodes: 
                                 waypoint = pe_nodes[0]
                                 inst["waypoint"] = waypoint  # Update instance for question generation
                         
                         if src_ip and dst_ip and waypoint:
                             res = bf_builder.waypoint_check(src_ip, dst_ip, waypoint)
                         else:
                             print(f"[DEBUG] waypoint_check missing params: {inst}, wp={waypoint}")

                    elif metric == "bounded_path_length":
                         src = inst.get("src_host")
                         dst_ip = inst.get("dst_ip")
                         if src and dst_ip:
                             res = bf_builder.bounded_path_length(src, dst_ip)
                         else:
                             print(f"[DEBUG] bounded_path_length missing params: {inst}")

                    elif metric == "isolation_check":
                         v1 = inst.get("vrf1")
                         v2 = inst.get("vrf2")
                         if v1 and v2:
                             res = bf_builder.isolation_check(v1, v2)
                         else:
                             print(f"[DEBUG] isolation_check missing vrf1/vrf2: {inst}")

                    elif metric == "link_failure_impact":
                         n1 = inst.get("node1")
                         n2 = inst.get("node2")
                         ts = inst.get("test_src")
                         td = inst.get("test_dst")
                         if n1 and n2 and ts and td:
                             res = bf_builder.link_failure_impact(n1, n2, ts, td)

                    elif metric == "k_failure_tolerance":
                         src = inst.get("src_host") or inst.get("host1")
                         dst_ip = inst.get("dst_ip")
                         # If no dst_ip, lookup host2
                         if not dst_ip and inst.get("host2") and host_ips.get(inst.get("host2")):
                             dst_ip = host_ips[inst.get("host2")][0]
                             
                         if src and dst_ip:
                             res = bf_builder.k_failure_tolerance(src, dst_ip)
                         else:
                             print(f"[DEBUG] k_failure_tolerance missing params: {inst}")

                    elif metric == "policy_compliance_check":
                         res = bf_builder.policy_compliance_check()

                    elif metric == "ospf_backbone_contiguity":
                         res = bf_builder.ospf_backbone_contiguity()

                    else:
                        continue
                except Exception as e:
                    print(f"[DEBUG] Exception in metric {metric}: {e}")
                    import traceback
                    traceback.print_exc()
                    continue
            else:
                res = builder.compute(intent)
            
            if not res:
                continue
            
            if isinstance(res, dict):
                if res.get("answer_type") == "error":
                    continue
            # AnswerResult does not use "error" type for skip, it has status


            q_text = dsl["pattern"]
            for k, v in inst.items():
                if isinstance(v, (str, int, float)):
                    q_text = q_text.replace(f"{{{k}}}", str(v))
            
            if isinstance(res, dict):
                a_val = res["value"]
                # res is dict
            else:
                # res is AnswerResult
                a_val = res.value
            
            # ================================================================
            # NetConfigQA 벤치마크 파이프라인 - Phase 3: CSV 컬럼 확장
            # ================================================================
            
            # 정답 직렬화 (JSON 형식 유지)
            # AnswerResult인 경우와 dict인 경우를 통합 관리
            if isinstance(res, AnswerResult):
                a_val = res.value
                answer_status = res.status
                unknown_reason = res.unknown_reason
                evidence_dict = res.evidence or {}
            else:
                a_val = res["value"]
                answer_status = "OK"  
                unknown_reason = ""
                evidence_dict = {}

            # 값이 빈 문자열("")인 경우 None(NOT_CONFIGURED)으로 취급
            if a_val == "":
                a_val = None

            # Evidence 자동 채우기 (기존 정보 보존하며 병합)
            default_evidence = {
                "snapshot": lab_path.name,
                "metric": metric_name,
                "scope": scope_template
            }
            # 기존 evidence_dict에 default_evidence 병합 (기존 내용 우선)
            # 단, 기존에 없으면 채워넣기 위해 default_evidence를 base로 하고 update
            final_evidence = default_evidence.copy()
            if evidence_dict:
                final_evidence.update(evidence_dict)
            
            evidence_str = json.dumps(final_evidence, ensure_ascii=False)

            # 값 직렬화 및 Status 최종 보정
            if a_val is None:
                a_json = "null"
                # 명시적으로 OK로 되어있다면 NOT_CONFIGURED로 변경
                if answer_status == "OK":
                    answer_status = "NOT_CONFIGURED"
            else:
                # L1/L2 Inventory 및 Configuration_Check 카테고리에 대한 NOT_CONFIGURED 로직 강화
                # 빈 리스트, 0, "Disabled", "Not Configured" 등을 NOT_CONFIGURED로 처리
                target_categories = ["Inventory", "Configuration_Check"]
                is_target_cat = any(cat in dsl["category"] for cat in target_categories)
                is_target_level = level in ["L1", "L2"]
                
                if is_target_level and is_target_cat and answer_status == "OK":
                    is_empty = False
                    if isinstance(a_val, (list, set, tuple, dict)) and len(a_val) == 0:
                        is_empty = True
                    elif isinstance(a_val, str) and a_val in ["Disabled", "Not Configured", "None", ""]:
                        is_empty = True
                    elif isinstance(a_val, (int, float)) and a_val == 0:
                        # 0이어도 유효한 경우가 있을 수 있으나, Inventory/Check에서는 '없음'을 의미하므로 NOT_CONFIGURED 처리
                        is_empty = True
                    
                    if is_empty:
                        answer_status = "NOT_CONFIGURED"

                if isinstance(a_val, (list, set, tuple)):
                    # set_str, edge_set, path 등
                    a_val_list = list(a_val)
                    if a_val_list and isinstance(a_val_list[0], str):
                        a_json = json.dumps(sorted(a_val_list), ensure_ascii=False)
                    else:
                        a_json = json.dumps(a_val_list, ensure_ascii=False)
                elif isinstance(a_val, dict):
                    # map_str_int, map_str_str 등
                    a_json = json.dumps(dict(sorted(a_val.items())), ensure_ascii=False)
                elif isinstance(a_val, bool):
                    a_json = json.dumps(a_val)
                elif isinstance(a_val, (int, float)):
                    a_json = json.dumps(a_val)
                else:
                    # 문자열 등
                    a_json = json.dumps(str(a_val), ensure_ascii=False)
            
            # Legacy "정보없음" fallback 제거됨 (a_json은 항상 유효한 JSON 문자열)
            
            qa_list.append({
                "id": str(dsl["id"]),
                "category": dsl["category"],
                "level": level,
                "question": q_text,
                "answer_status": answer_status,
                "answer_type": res["answer_type"] if isinstance(res, dict) else res.answer_type,
                "answer": a_json,
                "unknown_reason": unknown_reason,
                "evidence": evidence_str,
                "pipeline_version": PIPELINE_VERSION,
                "files": str(res.get("files", []) if isinstance(res, dict) else [])
            })

    # =========================================================================
    # L4/L5 추가 질문 생성 (BatfishBuilder 자체 생성 함수 활용)
    # =========================================================================
    if bf_active:
        print("[3.5] Generating additional L4/L5 questions via BatfishBuilder...")
        
        # Helper function to process builder questions
        def process_builder_questions(questions, level):
            for q in questions:
                # 1. Update evidence with snapshot info if missing
                evidence = q.get("evidence_hint", {})
                if "snapshot" not in evidence:
                    evidence["snapshot"] = lab_path.name
                
                # 2. Handle numeric types in ground_truth
                answer_val = q["ground_truth"]
                if q["answer_type"] in ["number", "numeric", "int", "float"]:
                    try:
                         # If it's a string, try to convert to number
                         if isinstance(answer_val, str):
                             if '.' in answer_val:
                                 answer_val = float(answer_val)
                                 # If it's an integer stored as float (e.g. 4.0), convert to int
                                 if answer_val.is_integer():
                                     answer_val = int(answer_val)
                             else:
                                 answer_val = int(answer_val)
                    except ValueError:
                        pass # Keep as is if conversion fails
                
                qa_list.append({
                    "id": str(q["id"]),
                    "category": q["category"],
                    "level": q["level"],
                    "question": q["question"],
                    "answer_status": "OK",
                    "answer_type": q["answer_type"],
                    "answer": json.dumps(answer_val, ensure_ascii=False),
                    "unknown_reason": "",
                    "evidence": json.dumps(evidence, ensure_ascii=False),
                    "pipeline_version": PIPELINE_VERSION,
                    "files": "[]"
                })

        # L4 질문 생성
        print("[3.5.1] Generating L4 questions (Reachability, Traceroute, Advanced)...")
        l4_questions = bf_builder.generate_l4_questions()
        process_builder_questions(l4_questions, "L4")
        print(f"  -> Generated {len(l4_questions)} L4 questions.")
            
        # L5 질문 생성
        print("[3.5.2] Generating L5 questions (What-If, Multi-Failure, RCA)...")
        l5_questions = bf_builder.generate_l5_questions()
        process_builder_questions(l5_questions, "L5")
        print(f"  -> Generated {len(l5_questions)} L5 questions.")

        l6_questions = []
        if args.include_l6:
            print("[3.5.3] Generating L6 questions (Diagnostic Troubleshooting)...")
            l6_questions = bf_builder.generate_l6_questions()
            process_builder_questions(l6_questions, "L6")
            print(f"  -> Generated {len(l6_questions)} L6 questions.")
        else:
            print("[3.5.3] Skipping L6 question generation.")
            print("  -> Reason: L6 diagnostic requires per-fault snapshot/context packaging and is out of scope for this IEEE TNMS submission.")

        if args.include_l6:
            print(f"  -> Total Added: {len(l4_questions)} L4 + {len(l5_questions)} L5 + {len(l6_questions)} L6 questions")
        else:
            print(f"  -> Total Added: {len(l4_questions)} L4 + {len(l5_questions)} L5 questions")


    # 결과 저장 (CSV + JSON)
    base_filename = f"{lab_path.name}_dataset_batfish_{timestamp}"
    csv_path = out_dir / f"{base_filename}.csv"
    json_path = out_dir / f"{base_filename}.json"
    
    if qa_list:
        df = pd.DataFrame(qa_list)
        # 컬럼 순서 정렬
        column_order = ["id", "category", "level", "question", "answer_status", "answer_type", "answer", "unknown_reason", "evidence", "pipeline_version", "files"]
        df = df[[c for c in column_order if c in df.columns]]
        
        # CSV 저장
        df.to_csv(csv_path, index=False, encoding="utf-8-sig")
        print(f"[Done] CSV saved: {csv_path}")
        
        # JSON 저장 (더 구조화된 형식)
        json_output = {
            "meta": {
                "lab_name": lab_path.name,
                "timestamp": timestamp,
                "total_questions": len(qa_list),
                "pipeline_version": PIPELINE_VERSION,
                "policies_file": str(policy_path) if policy_path else None
            },
            "questions": qa_list
        }
        
        with open(json_path, 'w', encoding='utf-8') as f:
            json.dump(json_output, f, indent=2, ensure_ascii=False)
        print(f"[Done] JSON saved: {json_path}")
        
        # 품질 리포트 출력
        print_quality_report(qa_list)
    else:
        print("[Done] No questions generated.")

if __name__ == "__main__":
    main()
