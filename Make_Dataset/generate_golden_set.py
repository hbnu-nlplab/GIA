
import json
import random
import logging
from pathlib import Path
import sys
import pandas as pd

# Add src path
sys.path.append(str(Path(__file__).parent / "src"))

from core_batfish.parser import UniversalParser
from core_batfish.rule_based_generator import RuleBasedGenerator, RuleBasedGeneratorConfig
from core_batfish.builder_core import BuilderCore
from core_batfish.batfish_builder import BatfishBuilder, AnswerResult

# Setup logging
logging.basicConfig(level=logging.INFO, format="[%(levelname)s] %(message)s")
logger = logging.getLogger("GoldenSetGenerator")

def main():
    lab_path = Path("Data/Pnetlab/Research_Institute_Internal_DC")
    policy_path = Path("Make_Dataset/policies.json")
    out_file = Path("golden_set_candidates.json")
    
    # 1. Load Policy to know the target list of metrics
    try:
        policy_data = json.loads(policy_path.read_text(encoding="utf-8"))
        metrics_metadata = policy_data.get("metrics_metadata", {})
        target_metrics = list(metrics_metadata.keys())
        logger.info(f"Target Metrics defined in policy: {len(target_metrics)}")
    except Exception as e:
        logger.error(f"Failed to load policy: {e}")
        return

    # 2. Parse Facts (L1-L3)
    logger.info("Parsing configurations...")
    xml_dir = lab_path / "configs"
    u_parser = UniversalParser()
    facts = u_parser.parse_dir(str(xml_dir))
    
    # 3. Initialize Builders
    logger.info("Initializing Generators...")
    
    # L1-L3 Generator
    l1_l3_cfg = RuleBasedGeneratorConfig(policies_path=str(policy_path), min_per_cat=1) # min_per_cat=1 mostly irrelevant here as we filter manually
    l1_l3_gen = RuleBasedGenerator(l1_l3_cfg)
    builder_core = BuilderCore(facts)
    
    # L4-L5 Generator (Batfish)
    bf_builder = BatfishBuilder(
        snapshot_path=str(lab_path), 
        network_name=lab_path.name,
        policies_path=str(policy_path),
        batfish_host="localhost:8889"
    )
    if not bf_builder.initialize():
        logger.error("Batfish initialization failed!")
        return

    # --- Generation Phase ---
    
    golden_set = {} # metric_name -> question_dict
    
    # A. Generate L1-L3 Candidates
    logger.info("Generating L1-L3 candidates...")
    # Helper to setup mock instances (copied logic from main_batfish.py, simplifed)
    # We need to construct instances for all scopes to ensure we trigger every rule
    
    categories = list(set([m.get("category") for m in metrics_metadata.values()]))
    dsl_items = l1_l3_gen.compile(capabilities={}, categories=categories)
    
    # Pre-compute common scopes
    all_hosts = [d["system"]["hostname"] for d in facts["devices"]]
    all_asns = set()
    for d in facts["devices"]:
        las = d.get("routing", {}).get("bgp", {}).get("local_as")
        if las: all_asns.add(str(las))
    
    host_ips = {} 
    for d in facts["devices"]:
        h = d.get("system", {}).get("hostname")
        ips = []
        for i in d.get("interfaces", []):
            if i.get("ipv4"): ips.append(i.get("ipv4").split("/")[0])
        host_ips[h] = ips

    for dsl in dsl_items:
        metric = dsl["intent"]["metric"]
        if metric in golden_set: continue # Already found unique one
        
        level = dsl.get("level")
        if level in ["L4", "L5"]: continue # Validated below
        
        # Determine scope and create ONE instance
        scope_type = dsl["intent"]["scope"].get("type", "GLOBAL")
        instances = []
        
        if scope_type == "GLOBAL":
            instances.append({})
        elif scope_type == "DEVICE":
            instances.append({"host": all_hosts[0]}) # Pick first host
        elif scope_type == "AS":
            if all_asns: instances.append({"asn": list(all_asns)[0]})
        elif scope_type == "DEVICE_PAIR":
            if len(all_hosts)>=2: instances.append({"host1": all_hosts[0], "host2": all_hosts[1]})
        elif scope_type == "OSPF_AREA":
            instances.append({"area": "0"}) # Try area 0
        elif scope_type == "VRF":
            instances.append({"vrf": "default"}) # Try default
        
        # Try to generate answer
        for inst in instances:
            intent = dsl["intent"].copy()
            scope = intent["scope"].copy()
            scope.update(inst)
            intent["scope"] = scope
            
            res = builder_core.compute(intent)
            if res:
                # Build Question Text
                q_text = dsl["pattern"]
                for k, v in inst.items():
                    q_text = q_text.replace(f"{{{k}}}", str(v))
                
                golden_set[metric] = {
                    "id": str(dsl["id"]),
                    "category": dsl["category"],
                    "level": level,
                    "metric": metric,
                    "question": q_text,
                    "answer": res["value"] if isinstance(res, dict) else res.value,
                    "status": "Generated"
                }
                break
    
    # B. Generate L4-L5 Candidates
    logger.info("Generating L4-L5 candidates...")
    
    # Helper to associate questions back to metrics
    def map_questions_to_metrics(questions_list):
        for q in questions_list:
            # Try to find metric in evidence hint
            metric = q.get("evidence_hint", {}).get("metric")
            if not metric:
                # Fallback: try to guess from ID if possible, or skip
                continue
            
            if metric not in golden_set:
                golden_set[metric] = {
                    "id": q["id"],
                    "category": q["category"],
                    "level": q["level"],
                    "metric": metric,
                    "question": q["question"],
                    "answer": q["ground_truth"],
                    "status": "Generated"
                }

    l4_qs = bf_builder.generate_l4_questions()
    map_questions_to_metrics(l4_qs)
    
    l5_qs = bf_builder.generate_l5_questions()
    map_questions_to_metrics(l5_qs)

    # 4. Report & Save
    logger.info(f"\nTotal Candidates Generated: {len(golden_set)}")
    
    missing_metrics = set(target_metrics) - set(golden_set.keys())
    if missing_metrics:
        logger.warning(f"Missing Metrics ({len(missing_metrics)}): {missing_metrics}")
        for m in missing_metrics:
            golden_set[m] = {"status": "MISSING", "reason": "No valid instance generated"}
    
    # Sort by ID or Metric
    sorted_items = sorted(golden_set.items())
    
    result_list = []
    for m, data in sorted_items:
        data["metric_key"] = m
        result_list.append(data)
        
    with open(out_file, "w", encoding="utf-8") as f:
        json.dump(result_list, f, indent=2, ensure_ascii=False)
        
    logger.info(f"Saved Golden Set candidates to {out_file}")

if __name__ == "__main__":
    main()
