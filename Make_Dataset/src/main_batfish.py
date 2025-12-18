
import argparse
import json
import time
from pathlib import Path
import sys
import random
import itertools
import pandas as pd

"""
python Make_Dataset\src\main_batfish.py --lab-path Data\Pnetlab\Research_Institute_Internal_DC --policies Make_Dataset\policies.json
"""

# src 패키지를 찾기 위해 경로 추가
sys.path.append(str(Path(__file__).parent))

from core_batfish.parser import UniversalParser
from core_batfish.rule_based_generator import RuleBasedGenerator, RuleBasedGeneratorConfig
from core_batfish.builder_core import BuilderCore
from core_batfish.batfish_builder import BatfishBuilder

def main():
    parser = argparse.ArgumentParser(description="Generate Network Q&A Dataset (Batfish Edition)")
    parser.add_argument("--lab-path", required=True, help="Path to Lab directory (e.g. Data/Pnetlab/Research_Institute_Internal_DC)")
    parser.add_argument("--out-dir", default=None, help="Output directory (default: <lab-path>/Dataset)")
    parser.add_argument("--policies", default="policies.json", help="Path to policies JSON")
    parser.add_argument("--min-per-cat", type=int, default=50, help="Minimal questions per category")
    args = parser.parse_args()

    lab_path = Path(args.lab_path)
    if not lab_path.exists():
        print(f"[Error] Lab path not found: {lab_path}")
        return

    # 1. 경로 설정
    xml_dir = lab_path / "xml" 
    if not xml_dir.exists():
        xml_dir = lab_path / "configs"
        
    if not args.out_dir:
        out_dir = lab_path / "Dataset"
    else:
        out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    timestamp = time.strftime("%Y%m%d_%H%M%S")
    
    # 2. 파싱 (Batfish Engine - Static Facts)
    print(f"[1] Parsing configurations using Batfish from: {xml_dir} (target: configs)")
    u_parser = UniversalParser()
    try:
        facts = u_parser.parse_dir(str(xml_dir))
    except Exception as e:
        print(f"[Error] Batfish parsing failed: {e}")
        import traceback
        traceback.print_exc()
        return

    # Facts 저장
    facts_out = out_dir / f"{lab_path.name}_batfish_facts_{timestamp}.json"
    facts_out.write_text(json.dumps(facts, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"    -> Saved facts to {facts_out}")

    # 3. Batfish Dynamic Engine 초기화 (for L4/L5)
    print(f"[1.5] Initializing Batfish Simulation Engine...")
    bf_builder = BatfishBuilder(snapshot_path=str(lab_path), network_name=lab_path.name)
    bf_active = bf_builder.initialize()
    if bf_active:
        print(f"    -> Batfish Engine Ready (Nodes: {len(bf_builder.nodes)})")
    else:
        print(f"    -> [Warning] Batfish Engine failed to initialize. L4/L5 questions will be skipped.")

    # 4. 질문 생성 (Rule Based)
    print(f"[2] Generating questions using policies: {args.policies}")
    if args.policies == "policies.json":
        policy_path = Path(__file__).parent.parent / "policies.json"
    else:
        policy_path = Path(args.policies)
        
    if not policy_path.exists():
        print(f"[Error] Policy file not found: {policy_path.resolve()}")
        return
        
    cfg = RuleBasedGeneratorConfig(policies_path=str(policy_path), min_per_cat=args.min_per_cat)
    gen = RuleBasedGenerator(cfg)
    
    categories = [
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
             instances.append({"link": "p1_to_p2_mock"})

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
                            atype, val = bf_builder.traceroute_path(src, dst_ip, target_name=dst_host or "")
                            res = {"answer_type": atype, "value": val, "files": []}
                            
                    elif metric == "reachability_status":
                        src_ip = inst.get("src_ip")
                        dst_ip = inst.get("dst_ip")
                        if src_ip and dst_ip:
                            atype, val = bf_builder.reachability_status(src_ip, dst_ip)
                            res = {"answer_type": atype, "value": val, "files": []}

                    elif metric == "loop_detection":
                        atype, val = bf_builder.loop_detection()
                        res = {"answer_type": atype, "value": val, "files": []}
                        
                    elif metric == "blackhole_detection":
                        atype, val = bf_builder.blackhole_detection()
                        val_str = ", ".join(val) if val else "없음"
                        res = {"answer_type": atype, "value": val_str, "files": []}
                        
                    elif metric == "acl_blocking_point":
                        src_ip = inst.get("src_ip")
                        dst_ip = inst.get("dst_ip")
                        if src_ip and dst_ip:
                            atype, val = bf_builder.acl_blocking_point(src_ip, dst_ip)
                            res = {"answer_type": atype, "value": val, "files": []}
                    else:
                        continue
                except Exception as e:
                    continue
            else:
                res = builder.compute(intent)
            
            if not res or res["answer_type"] == "error":
                continue

            q_text = dsl["pattern"]
            for k, v in inst.items():
                if isinstance(v, (str, int, float)):
                    q_text = q_text.replace(f"{{{k}}}", str(v))
            
            a_val = res["value"]
            if isinstance(a_val, (list, set, tuple)):
                a_str = ", ".join(sorted(map(str, a_val)))
            elif isinstance(a_val, dict):
                a_str = str(a_val)
            else:
                a_str = str(a_val)
            if not a_str: a_str = "정보없음"
            
            qa_list.append({
                "id": str(dsl["id"]),
                "category": dsl["category"],
                "question": q_text,
                "answer": a_str,
                "type": res["answer_type"],
                "level": level,
                "files": str(res.get("files", []))
            })

    csv_path = out_dir / f"{lab_path.name}_dataset_batfish_{timestamp}.csv"
    if qa_list:
        df = pd.DataFrame(qa_list)
        df.to_csv(csv_path, index=False, encoding="utf-8-sig")
        print(f"[Done] Generated {len(qa_list)} Q&A pairs at {csv_path}")
    else:
        print("[Done] No questions generated.")

if __name__ == "__main__":
    main()
