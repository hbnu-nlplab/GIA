from __future__ import annotations
from typing import Dict, Any, List, Optional
import json
from dataclasses import dataclass
import os
import sys

# Allow running this script directly (e.g. `python assemblers/test_assembler.py`)
# by ensuring the project root is on the module search path.
sys.path.append(os.path.dirname(os.path.dirname(__file__)))

from utils.builder_core import BuilderCore

# --- Embedded minimal Postprocessor (from legacy) ---
import re
SCENARIO_TAG = re.compile(r"^\[(.+?)\]\s*")

def _strip_scenario_prefix(q: str) -> tuple[str, str]:
    if not isinstance(q, str):
        return str(q), ""
    m = SCENARIO_TAG.match(q)
    if m:
        return q[m.end():].strip(), m.group(1)
    return q.strip(), ""

BAD_SENTINELS = {"value", "n/a", "na", "none", "null", "미정", "없음", "unknown", "??", "..."}

def _is_bad_value(v):
    if v is None:
        return True
    if isinstance(v, str):
        s = v.strip().lower()
        return (not s) or (s in BAD_SENTINELS)
    if isinstance(v, (list, set, tuple, dict)):
        return len(v) == 0
    return False

def lint_drop_unanswerable(by_cat: dict):
    out = {}
    for cat, arr in (by_cat or {}).items():
        keep = []
        for t in arr:
            q = (t.get("question") or "").strip()
            if "{" in q and "}" in q:
                continue
            # Support both old and new expected_answer structures
            expected_answer = t.get("expected_answer") or {}
            ans = expected_answer.get("value") or expected_answer.get("ground_truth")
            at  = (t.get("answer_type") or "").strip().lower()
            if _is_bad_value(ans):
                continue
            if at in ("set","list"):
                if not isinstance(ans, (list, set, tuple)) or len(ans) == 0:
                    continue
            elif at in ("map","dict"):
                if not isinstance(ans, dict) or len(ans) == 0:
                    continue
            elif at == "text":
                if not isinstance(ans, str) or not ans.strip():
                    continue
            keep.append(t)
        out[cat] = keep
    return out

def assign_task_tags(t: dict):
    q = (t.get("question") or "").lower()
    tags = set(t.get("tags") or [])
    if any(k in q for k in ["rd", "rt", "vrf"]):
        tags.add("L3VPN 개통/검증")
    if any(k in q for k in ["pseudowire", "pw-id", "l2vpn"]):
        tags.add("L2 회선 점검")
    if any(k in q for k in ["ssh", "aaa", "보안"]):
        tags.add("보안 감사")
    if any(k in q for k in ["ibgp", "ebgp", "as ", "풀메시"]):
        tags.add("라우팅 점검")
    t["tags"] = sorted(tags)


def _auto_tag_difficulty_and_type_rule_based(t: dict) -> None:
    q = (t.get("question") or "").lower()
    intent = t.get("intent") or {}
    sim = (t.get("simulation_conditions") or []) or (intent.get("simulation_conditions") or [])
    expected_error = t.get("expected_error") or intent.get("expected_error")
    tags = set(t.get("tags") or [])
    # 유형 태그
    if expected_error:
        tags.add("adversarial")
    elif sim:
        tags.add("inferential")
    else:
        tags.add("factual")
    # 난이도 태그(간단 규칙)
    if "모든" in q or "전체" in q or expected_error or sim:
        t["level"] = max(3, int(t.get("level") or 3))
    else:
        t["level"] = t.get("level") or 1
    t["tags"] = sorted(tags)


def strip_unwanted_fields(by_cat: dict) -> dict:
    out = {}
    for cat, arr in (by_cat or {}).items():
        cleaned = []
        for t in arr:
            if isinstance(t, dict):
                q, scn = _strip_scenario_prefix(t.get("question"))
                t["question"] = q
                if scn:
                    t["scenario"] = scn
                    exp = t.get("expected_answer")
                    if isinstance(exp, dict):
                        exp["scenario"] = scn
                t.pop("alternates", None)
                _auto_tag_difficulty_and_type_rule_based(t)
            cleaned.append(t)
        out[cat] = cleaned
    return out

# --- Embedded Retriever (from legacy) ---
from pathlib import Path
import xml.etree.ElementTree as ET
NS = {
    "cfg": "http://tail-f.com/ns/config/1.0",
    "ncs": "http://tail-f.com/ns/ncs",
    "xr":  "http://tail-f.com/ned/cisco-ios-xr",
    "ios": "urn:ios"
}

def _read_text(base: Path, file_name: str) -> str:
    return (base / file_name).read_text(encoding="utf-8", errors="ignore")

def _load_xml(base: Path, file_name: str):
    p = base / file_name
    try:
        return ET.parse(p).getroot()
    except Exception:
        return None

def _snippet_lines(text: str, needle: str, window: int = 1) -> List[str]:
    lines = text.splitlines()
    hits=[]
    low = str(needle).lower()
    for i, raw in enumerate(lines):
        if low in raw.lower():
            s=max(0,i-window); e=min(len(lines), i+window+1)
            snip="\n".join(lines[s:e]).strip()
            if snip and snip not in hits: hits.append(snip)
        if len(hits)>=2: break
    return hits

class _Retriever:
    def __init__(self, base_dir: str = "."):
        self.base = Path(base_dir)

    def _xpaths_for(self, cat: str, hint: Dict[str,Any]) -> List[str]:
        x = []
        if cat == "BGP_Consistency":
            if isinstance(hint.get("vrf"), dict):
                vname = hint["vrf"].get("name") or ""
            else:
                vname = hint.get("vrf") or hint.get("vrf_name") or ""
            x.extend([".//xr:router/xr:bgp/xr:bgp-no-instance/xr:id",
                      ".//xr:router/xr:bgp/xr:bgp-no-instance/xr:neighbor/xr:id"])
            x.extend([".//ios:router/ios:bgp/ios:as-no",
                      ".//ios:router/ios:bgp/ios:neighbor/ios:id",
                      ".//ios:router/ios:bgp/ios:neighbor/ios:remote-as"])
            x += [
                ".//xr:router/xr:bgp/xr:bgp-no-instance/xr:neighbor/xr:id",
                ".//xr:bgp-no-instance/xr:vrf/xr:neighbor/xr:id",
                ".//ios:router/ios:bgp/ios:neighbor/ios:id",
                ".//ios:bgp-no-instance/ios:vrf/ios:neighbor/ios:id",
            ]
            x += [
                ".//ncs:devices/ncs:device/ncs:config/xr:router/xr:bgp/xr:bgp-no-instance/xr:id",
                ".//ncs:devices/ncs:device/ncs:config/xr:router/xr:bgp/xr:bgp-no-instance/xr:neighbor/xr:id",
                ".//ncs:devices/ncs:device/ncs:config/xr:router/xr:bgp/xr:bgp-no-instance/xr:neighbor/xr:remote-as",
            ]
            x += [
                ".//ncs:devices/ncs:device/ncs:config/xr:router/xr:bgp/xr:bgp-no-instance/xr:vrf/xr:neighbor/xr:id",
                ".//ncs:devices/ncs:device/ncs:config/xr:router/xr:bgp/xr:bgp-no-instance/xr:vrf/xr:rd",
            ]
            if vname:
                x += [
                    f".//ncs:devices/ncs:device/ncs:config/xr:router/xr:bgp/xr:bgp-no-instance/xr:vrf[xr:name='{vname}']/xr:neighbor/xr:id",
                    f".//ncs:devices/ncs:device/ncs:config/xr:router/xr:bgp/xr:bgp-no-instance/xr:vrf[xr:name='{vname}']/xr:rd",
                ]
        if cat == "VRF_Consistency":
            x += [
                ".//ncs:devices/ncs:device/ncs:config/xr:vrf/xr:vrf-list//xr:route-target//xr:address-list/xr:name",
                ".//ncs:devices/ncs:device/ncs:config/xr:router/xr:bgp/xr:bgp-no-instance/xr:vrf/xr:rd",
            ]
        if cat == "L2VPN_Consistency":
            x += [
                ".//ncs:devices/ncs:device/ncs:config/xr:l2vpn//xr:neighbor/xr:address",
                ".//ncs:devices/ncs:device/ncs:config/xr:l2vpn//xr:neighbor/xr:pw-id",
                ".//ncs:devices/ncs:device/ncs:config/xr:xconnect//xr:p2p/xr:neighbor/xr:address",
                ".//ncs:devices/ncs:device/ncs:config/xr:xconnect//xr:p2p/xr:neighbor/xr:pw-id",
            ]
        if cat == "OSPF_Consistency":
            x += [
                ".//ncs:devices/ncs:device/ncs:config/xr:router/xr:ospf/xr:name",
                ".//ncs:devices/ncs:device/ncs:config/xr:router/xr:ospf/xr:area/xr:interface/xr:name",
                ".//ios:router/ios:ospf/ios:name",
                ".//ios:router/ios:ospf//ios:area//ios:interface/ios:name",
            ]
        if cat == "Security_Policy":
            x += [
                ".//ncs:devices/ncs:device/ncs:config/xr:ssh",
                ".//ncs:devices/ncs:device/ncs:config/xr:admin/xr:aaa",
                ".//ios:ssh", ".//ios:aaa",
                ".//ncs:devices/ncs:device/ncs:ssh",
                ".//ncs:devices/ncs:device/ncs:port",
            ]
        return x

    def _xml_evidence_smart(self, file: str, cat: str, hint: Dict[str,Any], expected: Any) -> List[Dict[str,str]]:
        ev=[]
        root=_load_xml(self.base, file)
        if root is not None:
            for xp in self._xpaths_for(cat, hint):
                try:
                    for el in root.findall(xp, NS):
                        txt = (el.text or "").strip()
                        if not txt:
                            for ctag in ("xr:id","xr:remote-as","xr:name","xr:address","xr:pw-id"):
                                c = el.find(ctag, NS)
                                if c is not None and c.text:
                                    txt=c.text.strip(); break
                        if txt:
                            ev.append({"file": file, "xpath": xp, "snippet": txt})
                            if len(ev)>=5: return ev
                except Exception:
                    continue
        raw = _read_text(self.base, file)
        if cat=="Security_Policy":
            if re.search(r"\bip\s+ssh\b", raw, re.IGNORECASE) or re.search(r"line\s+vty[\s\S]*transport\s+input\s+ssh", raw, re.IGNORECASE):
                for s in _snippet_lines(raw, "ssh", 1)[:2]:
                    ev.append({"file": file, "xpath": None, "snippet": s})
            if re.search(r"\baaa\s+(new-model|authentication|authorization|accounting)\b", raw, re.IGNORECASE):
                for s in _snippet_lines(raw, "aaa", 1)[:2]:
                    ev.append({"file": file, "xpath": None, "snippet": s})
        if cat=="BGP_Consistency" and not ev:
            if isinstance(hint, dict) and hint.get("type") in ("iBGP","eBGP"):
                if isinstance(expected, list) and len(expected)==0:
                    ev.append({"file": file, "xpath": None, 
                            "snippet": "[sentinel] 이 장비에서는 해당 타입의 BGP 이웃이 구성되어 있지 않습니다."})
        if cat=="VRF_Consistency" and not ev:
            if isinstance(expected, list) and len(expected)==0:
                ev.append({"file": file, "xpath": None, 
                        "snippet": "[sentinel] 해당 VRF에서 route-target 항목을 찾지 못했습니다(미설정 또는 비적용)."})
        if cat=="OSPF_Consistency" and not ev:
            if isinstance(expected, (int, float)) and expected == 0:
                ev.append({"file": file, "xpath": None,
                        "snippet": "[sentinel] 이 장비에서 OSPF Area 0 인터페이스 구성을 찾지 못했습니다."})
            if isinstance(expected, list) and len(expected)==0:
                ev.append({"file": file, "xpath": None,
                        "snippet": "[sentinel] 이 장비에서 OSPF Area 0 인터페이스 목록이 비어있습니다(미설정 또는 비적용)."})
        if isinstance(expected,(int,float,str)) and raw:
            needle = str(expected)
            if len(needle) >= 3:
                for s in _snippet_lines(raw, needle, 1):
                    ev.append({"file": file, "xpath": None, "snippet": s})
                    if len(ev)>=5: break
        return ev

    def enrich(self, tests: List[Dict[str, Any]], base_dir: str) -> List[Dict[str, Any]]:
        enriched=[]
        for t in tests:
            files=t.get("source_files") or []
            cat=t.get("category","")
            hint=t.get("evidence_hint",{}) or {}
            exp=(t.get("expected_answer",{}) or {}).get("value")
            snippets=[]
            for f in files:
                snippets.extend(self._xml_evidence_smart(f, cat, hint, exp))
                if len(snippets)>=5: break
            nt=dict(t); nt["evidence_snippets"]=snippets[:5]
            enriched.append(nt)
        return enriched

# --- Assembler ---
@dataclass
class AssembleOptions:
    base_xml_dir: str = "data/raw/XML_Data"
    paraphrase_k: int = 5

class TestAssembler:
    def __init__(self, options: AssembleOptions):
        self.options = options
        self._retr = _Retriever(base_dir=options.base_xml_dir)

    def _paraphrase_variants(self, pattern: str) -> List[str]:
        # Stage 2: LLM 미사용, 원문 유지
        return [pattern]

    # 시나리오 변환 적용 유틸리티
    def apply_scenario(
        self,
        tests: Any,
        scenario_conditions: Optional[Dict[str, Any]] = None,
    ) -> Any:
        """주어진 테스트들에 시나리오 조건을 적용하여 정답을 변형한다.

        scenario_conditions 구조 예시::

            {
                "overrides": {"metric_id": new_value, ...}
            }

        현재는 단순히 metric 기준으로 정답 값을 치환한다.
        """

        if not scenario_conditions:
            return tests

        overrides = scenario_conditions.get("overrides") if isinstance(scenario_conditions, dict) else None
        if not overrides:
            return tests

        def _apply_one(t: Dict[str, Any]):
            metric = (t.get("intent") or {}).get("metric") or t.get("id")
            if metric in overrides:
                exp = t.get("expected_answer") or {}
                exp["value"] = overrides[metric]
                t["expected_answer"] = exp

        if isinstance(tests, dict):
            for arr in tests.values():
                for t in arr:
                    _apply_one(t)
        elif isinstance(tests, list):
            for t in tests:
                _apply_one(t)
        return tests

    def assemble(
        self,
        facts: Dict[str, Any],
        dsl: List[Dict[str, Any]],
        scenario_conditions: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, List[Dict[str, Any]]]:
        # 1) 패턴 다양화
        dsl_expanded: List[Dict[str, Any]] = []
        for item in dsl:
            variants = self._paraphrase_variants(str(item.get("pattern")))
            for v in variants:
                tmp = dict(item)
                tmp["pattern"] = v
                dsl_expanded.append(tmp)

        # 2) 빌드(정답 계산)
        builder = BuilderCore(facts.get("devices") or facts)
        by_cat = self._expand_from_dsl(builder, dsl_expanded)

        # 2-1) 시나리오 조건에 따른 정답 변형
        by_cat = self.apply_scenario(by_cat, scenario_conditions)

        # 3) 태그/린트
        for cat, arr in by_cat.items():
            for t in arr:
                assign_task_tags(t)
        by_cat = lint_drop_unanswerable(by_cat)
        by_cat = strip_unwanted_fields(by_cat)

        # 4) 증거
        enriched = {cat: self._retr.enrich(arr, self.options.base_xml_dir) for cat, arr in by_cat.items()}
        return enriched

    def _expand_from_dsl(self, builder: BuilderCore, dsl_expanded: List[Dict[str, Any]]) -> Dict[str, List[Dict[str, Any]]]:
        """Expand DSL and wrap answers into ground_truth/explanation fields."""
        by_cat = builder.expand_from_dsl(dsl_expanded)
        for cat, arr in by_cat.items():
            for t in arr:
                original = (t.get("expected_answer") or {}).get("value")
                metric_name = ((t.get("evidence_hint") or {}).get("metric"))
                if isinstance(original, list):
                    ground_truth = original
                    explanation = f"The list of devices for {metric_name} is {original}."
                else:
                    ground_truth = original
                    explanation = f"The value for {metric_name} is {original}."
                t["expected_answer"] = {
                    "ground_truth": ground_truth,
                    "explanation": explanation,
                }
        return by_cat
