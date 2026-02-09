from __future__ import annotations
from typing import Dict, Any, List, Optional
from dataclasses import dataclass
import json
from pathlib import Path

# ---- Level definitions for dataset generation ----
LEVEL_DEFINITIONS = {
    "L1": "단일 장비 설정값 조회",
    "L2": "복수 장비 설정값 집계",
    "L3": "복수 장비 + 계산/비교",
    "L4": "네트워크 흐름 도달성 (Batfish)",
    "L5": "What-If / Differential 분석 (Batfish)"
}

# Scope hints map abstract targets to specific context variables
SCOPE_HINT = {
    "GLOBAL":      ({"type": "GLOBAL"}, []),
    "AS":          ({"type": "AS", "asn": "{asn}"}, ["asn"]),
    "DEVICE":      ({"type": "DEVICE", "host": "{host}"}, ["host"]),
    "VRF":         ({"type": "VRF", "vrf": "{vrf}"}, ["vrf"]),
    "DEVICE_VRF":  ({"type": "DEVICE_VRF", "host": "{host}", "vrf": "{vrf}"}, ["host", "vrf"]),
    "DEVICE_IF":   ({"type": "DEVICE_IF", "host": "{host}", "if": "{if}"}, ["host", "if"]),
    "DEVICE_PAIR": ({"type": "DEVICE_PAIR", "host1": "{host1}", "host2": "{host2}"}, ["host1", "host2"]),
    "OSPF_AREA":   ({"type": "OSPF_AREA", "area": "{area}"}, ["area"]),
    "FLOW":        ({"type": "FLOW", "src_ip": "{src_ip}", "dst_ip": "{dst_ip}"}, ["src_ip", "dst_ip"]),
    "LINK_FAILURE": ({"type": "LINK_FAILURE", "link": "{link}"}, ["link"]),
    "CONFIG_CHANGE": ({"type": "CONFIG_CHANGE"}, []),
    "POLICY":      ({"type": "POLICY", "policy_name": "{policy_name}"}, ["policy_name"])
}


def normalize_to_plain_text(data: Any) -> str:
    """모든 데이터 타입을 '정규화된 평문'으로 변환합니다."""
    if data is None:
        return ""

    if isinstance(data, list):
        str_items = sorted(list(set(map(str, data))))
        return ", ".join(str_items)

    if isinstance(data, dict):
        sorted_items = sorted(data.items())
        return ", ".join([f"{k}: {v}" for k, v in sorted_items])

    return str(data)


@dataclass
class RuleBasedGeneratorConfig:
    policies_path: str
    min_per_cat: int = 4
    scenario_type: str = "normal"


class RuleBasedGenerator:
    def __init__(self, cfg: RuleBasedGeneratorConfig):
        self.cfg = cfg
        self._bundle = json.loads(
            Path(self.cfg.policies_path).read_text(encoding="utf-8"))
        
        # New Schema: metrics_metadata is the SSOT
        self.metadata = self._bundle.get("metrics_metadata", {})
        
        # Fallback for old schema compatibility (if needed) or empty
        self.policies_list = self._bundle.get("policies", [])

    def _get_metric_agg_type(self, metric: str) -> str:
        """Get aggregation type (answer_type) from metadata."""
        meta = self.metadata.get(metric)
        if not meta:
            return "set" # Default fallback
        
        atype = meta.get("answer_type", "set_str")
        # Simplify answer types to internal aggregation types if needed
        # But generally we pass the raw type or map it
        if "scalar_int" in atype or "numeric" in atype or "number" in atype:
            return "numeric"
        if "bool" in atype:
            return "boolean"
        if "map" in atype:
            return "map"
        if "text" in atype:
            return "text"
        return "set" # set_str, edge_set etc map to set

    def _get_scope_from_meta(self, metric: str) -> tuple:
        """Determine scope based on metric metadata or naming convention."""
        meta = self.metadata.get(metric, {})
        template = meta.get("template", "")
        
        # Implicit scope inference from template variables
        if "{host1}" in template and "{host2}" in template:
            return SCOPE_HINT["DEVICE_PAIR"]
        if "{src_ip}" in template and "{dst_ip}" in template:
            return SCOPE_HINT["FLOW"]
        if "{link}" in template:
            return SCOPE_HINT["LINK_FAILURE"]
        if "{host}" in template and "{vrf}" in template:
            return SCOPE_HINT["DEVICE_VRF"]
        if "{host}" in template:
            return SCOPE_HINT["DEVICE"]
        if "{asn}" in template:
            return SCOPE_HINT["AS"]
        if "{vrf}" in template:
            return SCOPE_HINT["VRF"]
        if "{area}" in template:
            return SCOPE_HINT["OSPF_AREA"]
        if "{policy_name}" in template:
            return SCOPE_HINT["POLICY"]
            
        return SCOPE_HINT["GLOBAL"]

    def compile(
        self,
        capabilities: Dict[str, Any],
        categories: List[str],
        scenario_type: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """정책 기반 DSL 생성 (Data-Driven)"""

        dsl: List[Dict[str, Any]] = []
        scen = (scenario_type or self.cfg.scenario_type or "normal").lower()
        label_map = {"normal": "정상", "failure": "장애", "expansion": "확장"}
        scen_label = label_map.get(scen, scen)

        # Iterate through all metrics in metadata
        for metric, meta in self.metadata.items():
            cat = meta.get("category")
            if cat not in categories:
                continue
            
            # Skip L4/L5 metrics for RuleBasedGenerator as they are handled by BatfishBuilder
            # unless we decide to unify generation later.
            lvl = meta.get("level", "L1")
            if lvl in ["L4", "L5"]:
                continue

            template = meta.get("template")
            agg = self._get_metric_agg_type(metric)
            scope, placeholders = self._get_scope_from_meta(metric)
            
            dsl.append({
                "id": metric.upper(),
                "category": cat,
                "intent": {
                    "metric": metric,
                    "scope": scope,
                    "aggregation": agg,
                    "placeholders": placeholders
                },
                "pattern": template.strip(),
                "scenario": scen_label,
                "level": lvl,
                "goal": "extraction", # Default goal for simple L1-L3
                "policy_hints": {
                    "description": meta.get("description"),
                    "verification": meta.get("verification"),
                    "logic_ref": meta.get("logic_ref")
                },
                "origin": "policies.json"
            })

        # 얕은 중복 제거
        import json as _json
        seen = set()
        out = []
        for t in dsl:
            key = (t["category"], t["intent"]["metric"], _json.dumps(
                t["intent"]["scope"], sort_keys=True, ensure_ascii=False))
            if key in seen:
                continue
            seen.add(key)
            out.append(t)
        return out

    def fix_coverage_budget(self, dsl: List[Dict[str, Any]], budget: Dict[str, int]) -> List[Dict[str, Any]]:
        """Deprecated: Budget logic now handled by min_per_cat in main"""
        # Data-driven mode generates ALL possible intent templates.
        # Sampling happens at instantiation time in main_batfish.py or similar.
        # For compatibility, we just return the full list or a simple slice if needed.
        # However, to avoid breaking calls, we return dsl as is.
        return dsl
