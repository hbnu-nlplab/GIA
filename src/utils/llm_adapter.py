# -*- coding: utf-8 -*-
"""
LLM Adapter (OpenAI) — robust JSON with multi-stage fallbacks.

- Prefers Responses API Structured Outputs (response_format)
- If Responses fails (e.g., 400 'text.format.name'), fallback to Chat Completions
  * Chat path: json_schema → json_object
- Final fallback: Chat tools(function calling) with an OBJECT-wrapped schema
- Correct Chat param: max_tokens (not max_completion_tokens)
"""

from __future__ import annotations
from typing import List, Dict, Any, Optional
import json, os, time, re
from dataclasses import dataclass

from utils.config_manager import get_settings

try:
    from openai import OpenAI
except Exception as e:
    raise RuntimeError("Install OpenAI SDK: `pip install openai`") from e


@dataclass
class _ClientConfig:
    api_key: Optional[str]
    base_url: Optional[str]
    org_id: Optional[str]
    project: Optional[str]
    timeout: float
    max_retries: int

    @classmethod
    def from_settings(cls) -> "_ClientConfig":
        api = get_settings().api
        return cls(
            api_key=api.api_key,
            base_url=api.base_url,
            org_id=api.org_id,
            project=api.project,
            timeout=api.timeout,
            max_retries=api.max_retries,
        )


def _build_client() -> OpenAI:
    cfg = _ClientConfig.from_settings()
    if not cfg.api_key:
        raise RuntimeError("OPENAI_API_KEY is not set.")
    return OpenAI(
        api_key=cfg.api_key,
        base_url=cfg.base_url or None,
        organization=cfg.org_id or None,
        project=cfg.project or None,
        timeout=cfg.timeout,
        max_retries=0,  # we manage retries ourselves
    )


def _ensure_schema_strict(schema: Dict[str, Any]) -> Dict[str, Any]:
    """Recursively apply additionalProperties=False for objects."""
    def _walk(node: Any):
        if isinstance(node, dict):
            t = node.get("type")
            if t == "object":
                node.setdefault("additionalProperties", False)
                props = node.get("properties", {})
                if isinstance(props, dict):
                    for _, v in list(props.items()):
                        _walk(v)
            elif t == "array":
                if "items" in node:
                    _walk(node["items"])
    # make a deep copy
    data = json.loads(json.dumps(schema, ensure_ascii=False))
    _walk(data)
    return data


def _extract_output_text(resp: Any) -> str:
    """Try various SDK fields to extract text."""
    txt = getattr(resp, "output_text", None)
    if isinstance(txt, str) and txt.strip():
        return txt

    out = getattr(resp, "output", None)
    if isinstance(out, list) and out:
        pieces = []
        for item in out:
            val = getattr(item, "text", None)
            if isinstance(val, str) and val:
                pieces.append(val)
            content = getattr(item, "content", None)
            if isinstance(content, str):
                pieces.append(content)
            elif isinstance(content, list):
                for c in content:
                    val = getattr(c, "text", None) or getattr(c, "content", None)
                    if isinstance(val, str) and val:
                        pieces.append(val)
        if pieces:
            return "\n".join(pieces).strip()

    choices = getattr(resp, "choices", None)
    if isinstance(choices, list) and choices:
        msg = getattr(choices[0], "message", None) or {}
        content = getattr(msg, "content", None)
        if isinstance(content, str) and content.strip():
            return content

    return ""


def _safe_json_loads(s: str) -> Any:
    s = (s or "").strip()
    if not s:
        raise ValueError("Empty model response; cannot parse JSON.")
    try:
        return json.loads(s)
    except Exception:
        # try largest object
        first = s.find("{"); last = s.rfind("}")
        if first != -1 and last != -1 and last > first:
            return json.loads(s[first:last+1])
        # try largest array
        first = s.find("["); last = s.rfind("]")
        if first != -1 and last != -1 and last > first:
            return json.loads(s[first:last+1])
        raise


def _extract_json_from_codeblock(s: str) -> Optional[str]:
    if not s:
        return None
    m = re.search(r"```json\s*([\s\S]*?)```", s, flags=re.MULTILINE)
    if m: return m.group(1).strip()
    m = re.search(r"```\s*([\s\S]*?)```", s, flags=re.MULTILINE)
    if m: return m.group(1).strip()
    return None


def _retry_backoff(attempt: int, base: float = 0.8, cap: float = 6.0) -> float:
    delay = min(cap, base * (2 ** attempt))
    return delay * (0.8 + 0.4 * (os.urandom(1)[0] / 255.0))


def _call_llm_json(
    messages: List[Dict[str, str]],
    schema: Dict[str, Any],
    temperature: float = 0.6,
    *,
    model: Optional[str] = None,
    max_output_tokens: int = 1200,
    use_responses_api: bool = True,
) -> Any:
    """
    Robust JSON caller:
      Responses(JSON schema) → Chat(json_schema/json_object) → Chat tools(function calling)
    """
    client = _build_client()
    strict_schema = _ensure_schema_strict(schema)
    chosen_model = model or get_settings().models.paraphrase
    cfg = _ClientConfig.from_settings()
    attempts = cfg.max_retries + 1

    def log_header(api: str):
        print(f"[LLM] call start | api={api} | model={chosen_model} | temp={temperature} | max_out={max_output_tokens} | schema={strict_schema.get('title','(no-title)')} | messages={len(messages)}")
        for i, m in enumerate(messages[:3]):
            prev = (m.get("content") or "")[:240].replace("\n", " ")
            print(f"  - msg[{i}] role={m.get('role')} len={len(m.get('content') or '')} preview={prev}")

    # 1) Responses API first (optional)
    if use_responses_api:
        for attempt in range(1, attempts + 1):
            try:
                log_header("Responses")
                resp = client.responses.create(
                    model=chosen_model,
                    input=messages,
                    response_format={
                        "type": "json_schema",
                        "json_schema": {
                            "name": strict_schema.get("title", "structured_output"),
                            "schema": strict_schema,
                            "strict": True,
                        },
                    },
                    temperature=temperature,
                    max_output_tokens=max_output_tokens,
                )
                text = _extract_output_text(resp)
                if not isinstance(text, str) or not text.strip():
                    raise ValueError("Empty output_text from model")
                print(f"[LLM] raw text len={len(text)}")
                return _safe_json_loads(_extract_json_from_codeblock(text) or text)
            except Exception as e:
                print(f"[LLM] error on attempt {attempt}: {e}")
                if attempt >= attempts:
                    print("[LLM] fall back to Chat API")
                else:
                    time.sleep(_retry_backoff(attempt-1))

    # 2) Chat API (json_schema → json_object)
    for attempt in range(1, attempts + 1):
        try:
            log_header("Chat")
            # try json_schema first
            try:
                resp = client.chat.completions.create(
                    model=chosen_model,
                    messages=messages,
                    response_format={
                        "type": "json_schema",
                        "json_schema": {
                            "name": strict_schema.get("title", "structured_output"),
                            "schema": strict_schema,
                            "strict": True,
                        },
                    },
                    max_tokens=max_output_tokens,
                    temperature=temperature,
                )
            except Exception:
                print("[LLM] json_schema rejected; retrying with response_format=json_object")
                # OpenAI 요구사항: response_format=json_object 사용 시 메시지 내에 'json' 단어가 포함되어야 함
                # 메시지에 'json'이 없다면 개발자 메시지를 추가해 안전하게 통과시킨다.
                messages_json = list(messages)
                try:
                    has_json_kw = any(
                        isinstance(m, dict) and isinstance(m.get("content"), str) and ("json" in m["content"].lower())
                        for m in messages_json
                    )
                except Exception:
                    has_json_kw = False
                if not has_json_kw:
                    messages_json.append({
                        "role": "developer",
                        "content": (
                            "Return only JSON. Output a single valid JSON object or array that strictly follows the schema. "
                            "Do not include any prose, markdown, or code fences. json"
                        )
                    })
                resp = client.chat.completions.create(
                    model=chosen_model,
                    messages=messages_json,
                    response_format={"type": "json_object"},
                    max_tokens=max_output_tokens,
                    temperature=temperature,
                )
            text = _extract_output_text(resp)
            if not isinstance(text, str) or not text.strip():
                raise ValueError("Empty output_text from model")
            print(f"[LLM] raw text len={len(text)}")
            payload = _extract_json_from_codeblock(text) or text
            try:
                return _safe_json_loads(payload)
            except Exception:
                # 괄호 내 JSON 추출 재시도
                import re as _re
                m = _re.search(r"\[\s*\{[\s\S]*\}\s*\]", payload)
                if m:
                    return _safe_json_loads(m.group(0))
                m = _re.search(r"\{[\s\S]*\}", payload)
                if m:
                    return _safe_json_loads(m.group(0))
                raise
        except Exception as e:
            print(f"[LLM] error on attempt {attempt}: {e}")
            if attempt >= attempts:
                print("[LLM] final fallback → tools(function calling)")
            else:
                time.sleep(_retry_backoff(attempt-1))

    # 3) Chat tools(function calling) — wrap schema as OBJECT
    try:
        tool_parameters = {
            "type": "object",
            "properties": {
                "data": strict_schema  # allow any top-level (array/object) via wrapper
            },
            "required": ["data"],
            "additionalProperties": False
        }
        resp = client.chat.completions.create(
            model=chosen_model,
            messages=messages + [
                {"role": "system", "content": "Call function `return_json` with the JSON payload in the `data` field. Do not output anything else."}
            ],
            tools=[{"type": "function", "function": {
                "name": "return_json",
                "description": "Return the JSON strictly following the provided schema.",
                "parameters": tool_parameters
            }}],
            tool_choice={"type": "function", "function": {"name": "return_json"}},
            max_tokens=max_output_tokens,
            temperature=temperature,
        )
        tc = resp.choices[0].message.tool_calls
        if tc and len(tc) > 0:
            args_text = tc[0].function.arguments
            payload = json.loads(args_text)
            print("[LLM] tools fallback success")
            return payload.get("data", payload)
        raise RuntimeError("No tool_calls returned")
    except Exception as e_tools:
        print(f"[LLM] tools fallback failed: {e_tools}")
        raise

# -----------------------------
# High-level wrappers
# -----------------------------
def paraphrase_llm(pattern: str, ctx: Dict[str, Any]) -> List[str]:
    import re, os, json
    placeholders = re.findall(r"\{[a-zA-Z0-9_]+\}", pattern)

    schema = {
        "title": "ParaphraseVariants",
        "type": "object",
        "properties": {"variants": {"type": "array","items":{"type":"string","minLength":2,"maxLength":180},"minItems":1,"maxItems":20}},
        "required": ["variants"], "additionalProperties": False
    }

    system_msg = (
        "You are a Korean question rewriter. "
        "Return natural, concise Korean variants that keep placeholders unchanged."
    )
    developer_msg = (
        "HARD RULES:\n"
        f"- NEVER add/remove/rename placeholders. Exact set: {', '.join(placeholders) if placeholders else '(none)'}\n"
        "- Do NOT add bracketed scenario labels like [운영], [감사], etc.\n"
        "- Do NOT add 5W1H prompts (누가/언제/어디/왜/어떻게) unless they are directly answerable from data.\n"
        "- Do NOT leak metric identifiers or English tokens.\n"
        "- Keep each sentence <= 180 chars. Avoid near-duplicates.\n"
        "Return only JSON."
    )
    user_msg = json.dumps({"pattern": pattern, "max_variants": 12}, ensure_ascii=False)

    messages = [
        {"role": "system", "content": system_msg},
        {"role": "developer", "content": developer_msg},
        {"role": "user", "content": user_msg},
    ]

    model = get_settings().models.paraphrase
    data = _call_llm_json(messages, schema, temperature=0.6, model=model, max_output_tokens=800, use_responses_api=False)

    def same_placeholders(s: str) -> bool:
        return sorted(re.findall(r"\{[a-zA-Z0-9_]+\}", s)) == sorted(placeholders)

    variants_raw = data.get("variants", []) if isinstance(data, dict) else []
    out, seen = [], set()
    for v in variants_raw:
        if not isinstance(v, str): continue
        if "[" in v and "]" in v:  # 안전장치: 시나리오 라벨 유입 차단
            continue
        if not same_placeholders(v): continue
        if v in seen: continue
        out.append(v); seen.add(v)
    return out[:12] or [pattern]



def synth_llm(payload: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    DSL synth/refine.
    - If 'draft' exists: refine (GROUNDING/CREATIVE/PRUNING)
    - else: synth within allowed_metrics
    """
    categories = payload.get("categories", [])
    min_per_cat = int(payload.get("min_per_cat", 4))
    draft = payload.get("draft")

    schema = {
        "title": "TestIntentDSLList",
        "type": "array",
        "items": {
            "type": "object",
            "properties": {
                "id": {"type": "string", "minLength": 3, "maxLength": 80},
                "category": {"type": "string"},
                "intent": {
                    "type": "object",
                    "properties": {
                        "metric": {"type": "string"},
                        "scope": {"type": "object"},
                        "aggregation": {"type": "string", "enum": ["boolean","numeric","set","map","text"]},
                        "placeholders": {"type": "array", "items": {"type":"string"}, "maxItems": 4}
                    },
                    "required": ["metric","scope","aggregation","placeholders"],
                    "additionalProperties": False
                },
                "pattern": {"type": "string", "minLength": 4, "maxLength": 180},
                "level": {"type": "number"},
                "goal": {"type": "string"},
                "policy_hints": {"type": "object"},
                "origin": {"type": "string"}
            },
            "required": ["id","category","intent","pattern"],
            "additionalProperties": False
        },
        "minItems": 1,
        "maxItems": 200,
        "additionalProperties": False
    }

    if draft:
        system_msg = "You are a network test synthesizer. Return ONLY JSON following the schema."
        developer_msg = (
            "REFINE THE DRAFT DSL ITEMS WITH TWO STEPS:\n"
            "1) GROUNDING: adjust 'scope' to fit CAPABILITIES. If only one AS exists, drop or simplify multi-AS comparisons. NEVER change 'metric'.\n"
            "2) CREATIVE: rewrite 'pattern' into concise, fluent Korean reflecting 'goal' and any 'policy_hints'. Keep placeholders like {host},{asn},{vrf}.\n"
            "RULES:\n"
            f"- Ensure ~{min_per_cat} items per category when possible.\n"
            "- Use allowed metrics only. Remove duplicates or trivial items.\n"
                "REFINE THE DRAFT DSL ITEMS WITH TWO STEPS:\n"
            "1) GROUNDING: adjust 'scope' to fit CAPABILITIES. If only one AS exists, drop or simplify multi-AS comparisons. NEVER change 'metric'.\n"
            "2) CREATIVE: rewrite 'pattern' into concise, fluent Korean reflecting 'goal' and any 'policy_hints'. Keep placeholders like {host},{asn},{vrf}.\n"
            "STRICT RULES:\n"
            "- Do NOT add bracketed scenario labels like [운영], [감사], etc.\n"
            "- Do NOT include 5W1H fillers unless directly answerable by data.\n"
            "- Do NOT expose metric identifiers (e.g., ibgp_fullmesh_ok) in the pattern.\n"
            "- Remove duplicates or trivial items.\n"
            "- Keep 'level' and 'origin' as in draft.\n"
        )
    else:
        system_msg = "You are a network test template synthesizer. Return ONLY JSON following the schema."
        developer_msg = (
            "Synthesize DSL items using ONLY the provided allowed metrics. "
            f"Aim for at least {min_per_cat} items per category when supported by capabilities. "
            "Use placeholders {host},{asn},{vrf} appropriately. Keep Korean patterns concise."
        )

    messages = [
        {"role":"system","content":system_msg},
        {"role":"developer","content":developer_msg},
        {"role":"user","content":json.dumps(payload, ensure_ascii=False)},

    ]

    model = get_settings().models.enhanced_generation
    data = _call_llm_json(
        messages, schema, temperature=0.25, model=model,
        max_output_tokens=2000, use_responses_api=False  # Chat 우선
    )

    allowed = payload.get("allowed_metrics", {})
    out=[]
    if isinstance(data, list):
        for x in data:
            cat = x.get("category"); metric = (x.get("intent") or {}).get("metric")
            if not cat or cat not in categories:
                continue
            if metric not in (allowed.get(cat) or []):
                continue
            out.append(x)
    return out


def generate_questions_llm(
    network_facts: Dict[str, Any], 
    category: str, 
    sample_questions: List[Dict[str, Any]], 
    count: int = 3
) -> List[Dict[str, Any]]:
    """
    단순화된 LLM 질문 생성 - 1회 호출로 완성된 질문 리스트 반환
    """
    schema = {
        "title": "NetworkQuestions",
        "type": "object", 
        "properties": {
            "questions": {
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {
                        "question": {"type": "string"},
                        "expected_answer": {"type": "string"},
                        "answer_type": {"type": "string", "enum": ["text", "numeric", "boolean", "list"]},
                        "notes": {"type": "string"}
                    },
                    "required": ["question", "expected_answer", "answer_type"],
                    "additionalProperties": False
                },
                "maxItems": count
            }
        },
        "required": ["questions"],
        "additionalProperties": False
    }
    
    system_msg = f"""네트워크 테스트 질문 생성 전문가입니다.
{category} 카테고리에 대해 주어진 네트워크 현황을 바탕으로 실용적인 질문을 생성하세요.

요구사항:
1. 샘플 질문들과 유사한 스타일이지만 중복되지 않는 질문
2. 네트워크 데이터로부터 실제 계산/확인 가능한 답변
3. 명확하고 구체적인 한국어 질문
4. 운영자가 실무에서 물어볼 만한 실용적 내용"""

    user_msg = json.dumps({
        "category": category,
        "network_summary": _summarize_network_for_llm(network_facts),
        "sample_questions": sample_questions[:3],  # 예시로 3개만
        "requested_count": count
    }, ensure_ascii=False, indent=2)

    messages = [
        {"role": "system", "content": system_msg},
        {"role": "user", "content": user_msg}
    ]

    try:
        data = _call_llm_json(
            messages, schema, temperature=0.7,
            model=get_settings().models.question_generation,
            max_output_tokens=1200, use_responses_api=False
        )
        
        if isinstance(data, dict) and "questions" in data:
            return data["questions"]
        return []
        
    except Exception as e:
        print(f"[QuestionGen] LLM 호출 실패: {e}")
        return []


def generate_questions_llm(network_summary: str, category: str, num_questions: int = 3, examples: str = "") -> List[Dict[str, Any]]:
    """
    단일 LLM 호출로 카테고리별 추가 질문 생성
    """
    schema = {
        "type": "object",
        "title": "QuestionList",
        "properties": {
            "questions": {
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {
                        "question": {"type": "string"},
                        "expected_answer": {"type": "string"},
                        "answer_type": {"type": "string", "enum": ["exact", "contains", "numeric", "boolean"]},
                        "difficulty": {"type": "string", "enum": ["easy", "medium", "hard"]},
                        "confidence": {"type": "number", "minimum": 0.0, "maximum": 1.0}
                    },
                    "required": ["question", "expected_answer"],
                    "additionalProperties": False
                }
            }
        },
        "required": ["questions"],
        "additionalProperties": False
    }
    
    prompt = f"""Generate {num_questions} additional network configuration questions for category '{category}'.

Network Context:
{network_summary}

Existing Examples:
{examples}

Requirements:
- Focus on {category} configuration and status
- Questions should be answerable from the network context
- Vary difficulty levels (easy/medium/hard)
- Provide specific, factual expected answers
- Use clear, professional language

Generate questions that complement but don't duplicate the examples."""

    messages = [{"role": "user", "content": prompt}]
    
    try:
        result = _call_llm_json(messages, schema, temperature=0.7)
        return result.get("questions", [])
    except Exception as e:
        print(f"[LLM] Question generation failed: {e}")
        return []


def review_questions_llm(questions: List[Any]) -> List[int]:
    """
    LLM을 사용한 질문 품질 검토
    승인된 질문의 인덱스 리스트 반환
    """
    schema = {
        "type": "object", 
        "title": "QuestionReview",
        "properties": {
            "approved_indices": {
                "type": "array",
                "items": {"type": "integer", "minimum": 0}
            },
            "review_notes": {"type": "string"}
        },
        "required": ["approved_indices"],
        "additionalProperties": False
    }
    
    # 질문들을 텍스트로 변환
    question_texts = []
    for i, q in enumerate(questions):
        if hasattr(q, 'question'):
            question_texts.append(f"{i}: {q.question} -> {q.expected_answer}")
        else:
            question_texts.append(f"{i}: {q.get('question', '')} -> {q.get('expected_answer', '')}")
    
    prompt = f"""Review these network configuration questions for quality and appropriateness:

{chr(10).join(question_texts)}

Approve questions that are:
- Clear and well-formed
- Answerable from network configuration
- Technically accurate
- Not duplicated
- Have reasonable expected answers

Return the indices (0-based) of approved questions."""

    messages = [{"role": "user", "content": prompt}]
    
    try:
        result = _call_llm_json(messages, schema, temperature=0.3)
        approved = result.get("approved_indices", [])
        # 유효한 인덱스만 반환
        return [i for i in approved if 0 <= i < len(questions)]
    except Exception as e:
        print(f"[LLM] Question review failed: {e}")
        # 실패시 모든 질문 승인
        return list(range(len(questions)))


def _summarize_network_for_llm(facts: Dict[str, Any]) -> Dict[str, Any]:
    """LLM용 네트워크 요약"""
    devices = facts.get("devices", [])
    summary = {
        "device_count": len(devices),
        "device_types": [],
        "as_numbers": set(),
        "technologies": set()
    }
    
    for device in devices:
        file_name = device.get("file", "")
        if "ce" in file_name.lower():
            summary["device_types"].append("CE")
        elif "sample" in file_name.lower():
            summary["device_types"].append("PE")
        
        # AS 번호
        bgp = device.get("routing", {}).get("bgp", {})
        if bgp.get("local_as"):
            summary["as_numbers"].add(str(bgp["local_as"]))
        
        # 기술스택
        if bgp:
            summary["technologies"].add("BGP")
        if device.get("routing", {}).get("ospf"):
            summary["technologies"].add("OSPF")
        if device.get("services", {}).get("l2vpn"):
            summary["technologies"].add("L2VPN")
        if device.get("services", {}).get("vrf"):
            summary["technologies"].add("VRF")
        if device.get("security", {}).get("ssh"):
            summary["technologies"].add("SSH")
    
    summary["as_numbers"] = list(summary["as_numbers"])
    summary["technologies"] = list(summary["technologies"])
    return summary


def _salvage_hypotheses(capabilities: Dict[str, Any], n: int, metrics: List[str]) -> List[Dict[str, Any]]:
    """LLM 실패/빈 응답 시, grounding/anomalies 기반 기본 가설 생성"""
    out: List[Dict[str, Any]] = []
    anomalies = (capabilities or {}).get("anomalies", {}) or {}
    as_groups = (capabilities or {}).get("as_groups", {}) or {}
    ssh_missing_cnt = capabilities.get("ssh_missing_count") if isinstance(capabilities, dict) else None
    # 후보 메트릭 헬퍼
    def pick(*cands: str) -> str:
        for c in cands:
            if c in metrics:
                return c
        return metrics[0] if metrics else ""
    # 1) SSH 미구현
    if isinstance(ssh_missing_cnt, int) and ssh_missing_cnt > 0 and len(out) < n:
        out.append({
            "question": f"SSH 미구현 장비 {ssh_missing_cnt}대를 모두 식별하고 보안 정책 위반 여부를 확인할 수 있는가?",
            "hypothesis_type": "ImpactAnalysis",
            "intent_hint": {"metric": pick("ssh_missing_count","ssh_missing_devices"), "scope": {}},
            "expected_condition": "ssh_missing_count == 0",
            "reasoning_steps": "grounding 에서 ssh_missing_count > 0 발견 → 보안 영향 평가",
            "cited_values": {"ssh_missing_count": ssh_missing_cnt}
        })
    # 2) iBGP under-peered / missing
    for asn, meta in as_groups.items():
        if len(out) >= n: break
        miss = meta.get("ibgp_missing_pairs_count", 0)
        under = meta.get("ibgp_under_peered_count", 0)
        if miss:
            out.append({
                "question": f"AS {asn} 내 iBGP 페어 {miss}쌍 누락이 전체 전파에 영향을 주는가?",
                "hypothesis_type": "ImpactAnalysis",
                "intent_hint": {"metric": pick("ibgp_missing_pairs_count","ibgp_missing_pairs"), "scope": {"asn": asn}},
                "expected_condition": "ibgp_missing_pairs_count == 0",
                "reasoning_steps": "as_groups 에서 missing_pairs_count > 0",
                "cited_values": {"asn": asn, "ibgp_missing_pairs_count": miss}
            })
        if len(out) >= n: break
        if under:
            out.append({
                "question": f"AS {asn} 내 피어 수 부족(under-peered) 장비 {under}대가 라우트 수렴을 저해하는가?",
                "hypothesis_type": "RootCauseAnalysis",
                "intent_hint": {"metric": pick("ibgp_under_peered_count","ibgp_under_peered_devices"), "scope": {"asn": asn}},
                "expected_condition": "ibgp_under_peered_count == 0",
                "reasoning_steps": "as_groups 메타에서 under_peered_count > 0",
                "cited_values": {"asn": asn, "ibgp_under_peered_count": under}
            })
    # 3) VRF / L2VPN anomaly
    if len(out) < n and anomalies.get("vrf_without_rt_count"):
        c = anomalies["vrf_without_rt_count"]
        out.append({
            "question": f"Route-Target 미설정 VRF {c}건이 L3VPN 경로 유통을 저해하는가?",
            "hypothesis_type": "ImpactAnalysis",
            "intent_hint": {"metric": pick("vrf_without_rt_count","vrf_rd_map","vrf_rt_list_per_device","vrf_without_rt_pairs"), "scope": {}},
            "expected_condition": "vrf_without_rt_count == 0",
            "reasoning_steps": "anomalies.vrf_without_rt_count > 0",
            "cited_values": {"vrf_without_rt_count": c}
        })
    if len(out) < n and anomalies.get("l2vpn_unidir_count"):
        c = anomalies["l2vpn_unidir_count"]
        out.append({
            "question": f"L2VPN 단방향(unidirectional) 세션 {c}건이 서비스 장애를 유발하는가?",
            "hypothesis_type": "RootCauseAnalysis",
            "intent_hint": {"metric": pick("l2vpn_unidir_count","l2vpn_unidirectional_pairs"), "scope": {}},
            "expected_condition": "l2vpn_unidir_count == 0",
            "reasoning_steps": "anomalies.l2vpn_unidir_count > 0",
            "cited_values": {"l2vpn_unidir_count": c}
        })
    if len(out) < n and anomalies.get("l2vpn_mismatch_count"):
        c = anomalies["l2vpn_mismatch_count"]
        out.append({
            "question": f"L2VPN PW ID 불일치 {c}건이 트래픽 블랙홀을 초래하는가?",
            "hypothesis_type": "AdversarialCheck",
            "intent_hint": {"metric": pick("l2vpn_mismatch_count","l2vpn_pwid_mismatch_pairs"), "scope": {}},
            "expected_condition": "l2vpn_mismatch_count == 0",
            "reasoning_steps": "anomalies.l2vpn_mismatch_count > 0",
            "cited_values": {"l2vpn_mismatch_count": c}
        })
    # 4) 부족하면 일반 보안/구성 정상성 가설 채우기
    fillers = [
        ("SSH 기능이 모든 장비에 일관되게 적용되어 있는가?", pick("ssh_all_enabled_bool","ssh_missing_count"), "ssh_all_enabled_bool == true"),
        ("각 AS의 iBGP 페어링이 완전 메시인지 확인할 수 있는가?", pick("ibgp_fullmesh_ok","ibgp_missing_pairs_count"), "ibgp_fullmesh_ok == true"),
    ]
    for q, m, cond in fillers:
        if len(out) >= n: break
        out.append({
            "question": q,
            "hypothesis_type": "ImpactAnalysis",
            "intent_hint": {"metric": m, "scope": {}},
            "expected_condition": cond,
            "reasoning_steps": "fallback filler",
            "cited_values": {}
        })
    return out[:n]


# -----------------------------
# 추가: 의도 파싱(parse_intent_llm) 및 가설 리뷰(review_hypotheses_llm)
# -----------------------------
from typing import Iterable

def parse_intent_llm(question: str, metrics: Iterable[str], hint_metric: str | None = None, hint_scope: dict | None = None, cited_values: dict | None = None) -> Dict[str, Any]:
    """질문을 기반으로 metric / scope 힌트를 산출.
    - 우선순위: hint_metric → 질문 키워드 휴리스틱 → metrics[0]
    - scope 추출: AS 번호, hostname (cited_values 또는 질문), VRF 이름 패턴
    - 환경변수 GIA_USE_INTENT_LLM=1 이면 LLM 호출 (schema 강제) 시도, 실패 시 휴리스틱으로 폴백
    """
    metrics_list = list(metrics or [])
    q = (question or "").strip()
    out_metric: str | None = None
    if hint_metric and hint_metric in metrics_list:
        out_metric = hint_metric
    else:
        low = q.lower()
        # 간단 키워드 매핑
        KEYMAP = [
            ("ssh", ["ssh_missing_count","ssh_missing_devices","ssh_enabled_devices"]),
            ("bgp", ["ibgp_missing_pairs_count","ibgp_fullmesh_ok","ibgp_under_peered_count","neighbor_list_ibgp"]),
            ("vrf", ["vrf_without_rt_count","vrf_rd_map","vrf_rt_list_per_device","vrf_without_rt_pairs"]),
            ("l2vpn", ["l2vpn_unidir_count","l2vpn_mismatch_count","l2vpn_unidirectional_pairs"]),
            ("ospf", ["ospf_area0_if_count","ospf_proc_ids"]),
        ]
        for kw, cands in KEYMAP:
            if kw in low:
                for c in cands:
                    if c in metrics_list:
                        out_metric = c; break
            if out_metric: break
    if not out_metric and metrics_list:
        out_metric = metrics_list[0]

    # scope 휴리스틱
    scope: Dict[str, Any] = {}
    import re
    m_as = re.search(r"AS\s*(\d+)", q, flags=re.IGNORECASE)
    if m_as:
        scope["asn"] = m_as.group(1)
    # hostname 추출(간단): 대문자/소문자/숫자 포함 단어 중 host, rtr 등 패턴
    m_host = re.search(r"\b([A-Za-z][A-Za-z0-9_-]{2,})\b", q)
    if m_host and not scope.get("asn"):
        # 너무 일반 단어 제외
        token = m_host.group(1)
        if token.lower() not in {"count","device","devices","vrf","bgp","ssh"}:
            scope["host"] = token
    # VRF 이름 (vrf XXX)
    m_vrf = re.search(r"vrf\s+([A-Za-z0-9_-]{2,})", q, flags=re.IGNORECASE)
    if m_vrf:
        scope["vrf"] = m_vrf.group(1)

    # hint_scope 병합(우선)
    if isinstance(hint_scope, dict):
        scope.update({k:v for k,v in hint_scope.items() if v not in (None,"")})

    intent = {"metric": out_metric or "", "scope": scope}

    # 선택적 LLM 보강 (환경변수 ON)
    if get_settings().features.use_intent_llm:
        schema = {
            "title": "IntentParse",
            "type": "object",
            "properties": {
                "metric": {"type": "string"},
                "scope": {"type": "object"},
                "reasoning": {"type": "string"}
            },
            "required": ["metric","scope"],
            "additionalProperties": False
        }
        messages = [
            {"role": "system", "content": "네트워크 테스트 의도 추출기. 질문에서 metric 과 scope 를 선택. 제공된 metrics 후보 외 값 생성 금지."},
            {"role": "user", "content": json.dumps({
                "question": q,
                "candidates": metrics_list,
                "hint_metric": hint_metric,
                "hint_scope": hint_scope,
                "cited_values": cited_values
            }, ensure_ascii=False)}
        ]
        try:
            data = _call_llm_json(messages, schema, temperature=0.0, model=get_settings().models.intent_parsing, max_output_tokens=500, use_responses_api=False)
            if isinstance(data, dict):
                msel = data.get("metric")
                if isinstance(msel, str) and msel in metrics_list:
                    intent["metric"] = msel
                if isinstance(data.get("scope"), dict):
                    intent["scope"].update({k:v for k,v in data["scope"].items() if v not in (None,"")})
        except Exception as e:
            print(f"[IntentParse] LLM 실패 → 휴리스틱 유지: {e}")
    return intent


def review_hypotheses_llm(hypotheses: List[Dict[str, Any]], capabilities: Dict[str, Any], max_items: int = 20) -> List[Dict[str, Any]]:
    """가설 품질을 LLM 또는 휴리스틱으로 점수화.
    반환: [{hypothesis_index, total_score, is_recommended, justification, ...}]
    - 휴리스틱: 길이, intent_hint.metric 존재 여부, cited_values 존재 여부, 정량/조건 키워드
    - 환경변수 GIA_DISABLE_HYPO_REVIEW=1 이면 즉시 패스
    """
    if not hypotheses:
        return []
    if get_settings().features.disable_hypo_review:
        return [
            {"hypothesis_index": i, "total_score": 100, "is_recommended": True, "justification": "disabled"}
            for i,_ in enumerate(hypotheses)
        ]

    schema = {
        "title": "HypothesisReviewList",
        "type": "array",
        "items": {
            "type": "object",
            "properties": {
                "hypothesis_index": {"type": "integer"},
                "clarity_score": {"type": "integer"},
                "evidential_score": {"type": "integer"},
                "risk_score": {"type": "integer"},
                "total_score": {"type": "integer"},
                "is_recommended": {"type": "boolean"},
                "justification": {"type": "string"}
            },
            "required": ["hypothesis_index","total_score","is_recommended"],
            "additionalProperties": False
        },
        "maxItems": min(max_items, len(hypotheses)),
        "additionalProperties": False
    }

    messages = [
        {"role": "system", "content": "네트워크 테스트 가설 품질 평가자. JSON만 출력."},
        {"role": "user", "content": json.dumps({
            "capabilities_summary": {k: (v if isinstance(v,(int,str,float)) else str(type(v).__name__)) for k,v in (capabilities or {}).items() if k in ("ssh_missing_count","anomalies","as_groups")},
            "hypotheses": hypotheses,
            "scoring_criteria": {
                "clarity": "문장이 명확/측정가능 (0-4)",
                "evidence": "cited_values 또는 intent_hint 근거 활용 (0-4)",
                "risk": "운영/보안/가용성 위험 관련성 (0-4)"
            }
        }, ensure_ascii=False)}
    ]

    try:
        data = _call_llm_json(messages, schema, temperature=0.0, model=get_settings().models.hypothesis_review, max_output_tokens=1200, use_responses_api=False)
        if isinstance(data, list):
            # total_score 누락 시 합산
            for it in data:
                if isinstance(it, dict):
                    if "total_score" not in it:
                        ts = (it.get("clarity_score",0)+it.get("evidential_score",0)+it.get("risk_score",0))
                        it["total_score"] = ts
            return data
    except Exception as e:
        print(f"[HypoReview] LLM 실패 → 휴리스틱 전환: {e}")

    # 휴리스틱 백업
    reviews: List[Dict[str, Any]] = []
    import re
    kw_numeric = re.compile(r"\b(개|수|count|==|!=|>|<|>=|<=)\b")
    for i, h in enumerate(hypotheses):
        q = (h.get("question") or "").strip()
        length_score = 2 if 10 <= len(q) <= 150 else 1
        has_metric = 2 if (h.get("intent_hint") or {}).get("metric") else 0
        has_evidence = 2 if (h.get("cited_values") or {}) else 0
        numeric_hint = 2 if kw_numeric.search(q) else 0
        total = length_score + has_metric + has_evidence + numeric_hint
        reviews.append({
            "hypothesis_index": i,
            "total_score": total,
            "is_recommended": total >= 4,
            "justification": f"len={len(q)} metric={has_metric>0} evidence={has_evidence>0} numeric_kw={numeric_hint>0}"
        })
    return reviews

