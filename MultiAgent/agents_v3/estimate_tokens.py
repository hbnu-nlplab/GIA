"""
estimate_tokens.py
------------------
기존 결과 JSON에서 LLM API 토큰 사용량을 소급 추정한다.

각 노드의 프롬프트를 저장된 데이터로 재구성하여 토크나이저로 계산:
  Collector   : COLLECTOR_SYSTEM + question + full_config (configs/ 에서 로드)
  Verifier    : VERIFIER_RUBRIC  + question + current_passage
  Synthesizer : SYNTH_SYSTEM     + question + current_passage [+ feedback × retry]
  Supporter   : SUPPORTER_SYSTEM + question + current_passage + candidate_answer [× rounds]
  Skeptic     : SKEPTIC_SYSTEM   + question + current_passage + candidate_answer + pro_arg [× rounds]

출력 토큰:
  Collector   : current_passage  (≈ Collector 출력, 근사치)
  Verifier    : 소형 JSON (~80 tokens 고정 추정)
  Synthesizer : candidate_answer (각 라운드, [START]/[DONE] 태그 포함 추정)
  Supporter   : proponent_history 항목
  Skeptic     : critic_history 항목

토크나이저 우선순위:
  1. tiktoken (cl100k_base) — 빠르고 경량
  2. transformers AutoTokenizer (모델 지정)
  3. 문자 수 / 3.5 — 최후 폴백

사용법:
  python agents_v3/estimate_tokens.py \\
      data/debate_results/agents_v3/results1/gpt_oss_20b/labA/results_raw_...json \\
      [data/original/netconfig2/lab_a]   # configs/ 폴더 상위 (생략 시 Collector 입력 제외)

  # 출력 파일 지정 (기본: 같은 폴더에 _token_estimate.json)
  python agents_v3/estimate_tokens.py result.json lab_a --out output.json
"""

import argparse
import json
import sys
from pathlib import Path

# ============================================================
# 토크나이저
# ============================================================
def _make_tokenizer():
    """가용한 토크나이저를 반환한다. 계산 함수 count_tokens(text) → int."""
    try:
        import tiktoken
        enc = tiktoken.get_encoding("cl100k_base")
        print("[Tokenizer] tiktoken cl100k_base 사용")
        return lambda text: len(enc.encode(str(text)))
    except ImportError:
        pass

    try:
        from transformers import AutoTokenizer
        # gpt-oss-20b 토크나이저 (캐시돼 있으면 즉시 로드)
        model_id = "openai/gpt-oss-20b"
        tok = AutoTokenizer.from_pretrained(model_id, trust_remote_code=True)
        print(f"[Tokenizer] transformers AutoTokenizer ({model_id}) 사용")
        return lambda text: len(tok.encode(str(text), add_special_tokens=False))
    except Exception:
        pass

    print("[Tokenizer] ⚠️ tiktoken/transformers 없음 → 문자 수 / 3.5 폴백 사용 (근사치)")
    return lambda text: int(len(str(text)) / 3.5)


# ============================================================
# 시스템 프롬프트 (debate1.py / debate2.py 에서 복사)
# ============================================================
COLLECTOR_SYSTEM = """You are a Network Info Collector.
TASK:
DEVICE BOUNDARY: The context separates devices using these markers:
  === START OF CONFIG: HOSTNAME ===
  ...configuration lines...
  === END OF CONFIG: HOSTNAME ===

Your output is scored by a Verifier on 4 criteria. Follow these rules to maximize your score:

[C1 — Device Match: you MUST preserve device identity]
- AGGREGATE questions (e.g., "which devices have X", "how many devices", "list all devices"): Extract the relevant section from EVERY device block. Do NOT pick just 1-2 devices.
- Single-device questions: Find the EXACT hostname mentioned in the question.
- ALWAYS include the === START OF CONFIG: HOSTNAME === and === END OF CONFIG: HOSTNAME === boundary markers for each extracted block.
- ALWAYS include the "hostname <name>" line from inside each block.

[C2 — Feature/Command Presence: extract the exact section asked about]
- Identify the specific command or section the question targets.
- For AGGREGATE questions: scan EVERY device block and extract the relevant section (or mark [FEATURE_NOT_FOUND] per device if absent).
- Extract ALL lines of that section completely.
- Also extract: negation lines ("no aaa new-model", "no ip routing") — they prove a feature is disabled.
- If the specific command is completely absent from the target block, write: [FEATURE_NOT_FOUND]

[C3 — Completeness: never truncate]
- Extract the COMPLETE configuration block — do not stop early.
- Include lines before "hostname" (e.g., "version 15.7", "boot" lines).

[C4 — Format Integrity: raw config only]
- Output ONLY raw configuration lines verbatim. Do NOT convert to natural language.
- No commentary, no explanations, no JSON wrappers, no metadata.

- Extract all relevant information VERBATIM.
- Do not summarize or lose technical precision.

### OUTPUT FORMAT (MANDATORY):
[START]
Context:
<the raw configuration lines here, verbatim>
[DONE]

CRITICAL RULES:
- You MUST output [START] and [DONE] tags. No exceptions.
- Between the tags, output ONLY raw config lines copied verbatim from the context.
- Do NOT answer the question. Do NOT output numbers, values, or interpretations.
- Do NOT paraphrase or convert config lines into natural language.
- If the feature is absent in the config, write exactly: [FEATURE_NOT_FOUND]
- Never output just a hostname, number, or short value without surrounding config lines."""

VERIFIER_RUBRIC = """You are a Network Config Verifier. Score the Extracted Context against the Question using the rubric below.
Output ONLY a valid JSON object. No markdown, no preamble, no explanation outside the JSON.

## SCORING RUBRIC (total 10 points)

[C1] Device Match (0–3 pts)
  3 = The exact hostname(s) mentioned in the question appear in the extracted context.
  1 = Hostname is partially matched or unclear.
  0 = The extracted context is for a different device, or no hostname is present.

[C2] Feature / Command Presence (0–4 pts)
  4 = The specific command or configuration section asked about is present.
  2 = A related section exists but the specific command is missing.
  0 = The extracted context has no lines related to the feature asked.

[C3] Completeness (0–2 pts)
  2 = The relevant configuration block is extracted completely.
  1 = Partial extraction.
  0 = Only 1–2 lines, or the context is too sparse to answer the question.

[C4] Format Integrity (0–1 pt)
  1 = Output is raw config lines verbatim.
  0 = The extracted context has been converted to sentences or summaries.

## OUTPUT FORMAT (strict JSON):
{
  "scores": {...},
  "total": <0–10>,
  "failed_criteria": [...],
  "feedback": "..."
}"""

SYNTHESIZER_SYSTEM = """You are a Network Info Synthesizer.
TASK: Based on the provided configuration passage, answer the question precisely.

# Answer FORMAT RULES (CRITICAL - MUST FOLLOW EXACTLY):
1. output the raw answer value in ONE line
2. CORE SEARCH RULES: Identify the target device and search ONLY within its specific configuration block.
3. If NOT_CONFIGURED or information missing: text: null / numeric: 0 / set: [] / map: {} / boolean: false / path: No path

### OUTPUT FORMAT:
[START]
Answer:
[DONE]"""

SUPPORTER_SYSTEM = """You are a Supporter Network Engineer.
Your job is to defend the Candidate Answer using evidence from the Passage.

RULES:
1. Find the exact line(s) in the Passage that support the Candidate Answer. Quote them directly.
2. If there is Critic Feedback from a previous round, address each point specifically using Passage evidence.
3. Do NOT change the Candidate Answer — only justify why it is correct.
4. If a value in the Candidate Answer appears verbatim in the Passage, cite it as direct evidence.
5. Be concise and technical. No vague claims — every assertion must reference a specific Passage line."""

SKEPTIC_SYSTEM = """You are a Network Answer Critic. Evaluate the Candidate Answer using the Passage and Supporter's defense.

### EVALUATION ORDER:
1. Read Question + Passage + Candidate Answer first.
2. Find the exact line(s) in the Passage that support or contradict the answer.
3. Read the Supporter's defense — check if their cited Passage lines are accurate.

### ACCEPT criteria (all must hold):
- The exact value/config line answering the question appears in the Passage.
- The Candidate Answer matches that line precisely (no hallucinated values).

### REVISE criteria (any one triggers REVISE):
- The Candidate Answer contains a value NOT found verbatim in the Passage.
- The Candidate Answer is "null"/0/{}/[] but the Passage contains the relevant feature/lines.

### OUTPUT FORMAT (valid JSON only):
{
    "status": "ACCEPT" | "REVISE",
    "evidence_quote": "...",
    "con_argument": "...",
    "synthesizer_feedback": "..."
}"""

# Verifier JSON 응답에서 scores/total/구조 고정 부분 토큰 (실측 근사)
# {"scores":{"C1_device_match":X,"C2_feature_presence":X,"C3_completeness":X,"C4_format_integrity":X},"total":X,"failed_criteria":[...],"feedback":"..."}
VERIFIER_BASE_JSON = '{"scores":{"C1_device_match":3,"C2_feature_presence":4,"C3_completeness":2,"C4_format_integrity":1},"total":10,"failed_criteria":[],"feedback":""}'


# ============================================================
# config 파일 로드
# ============================================================
def load_full_config(lab_dir: Path) -> str:
    """configs/ 디렉토리의 모든 .cfg 파일을 헤더와 함께 합산해 반환."""
    configs_dir = lab_dir / "configs"
    if not configs_dir.exists():
        return ""
    combined = ""
    for cfg in sorted(configs_dir.glob("*.cfg")):
        host = cfg.stem.upper()
        combined += f"\n=== START OF CONFIG: {host} ===\n"
        combined += cfg.read_text(encoding="utf-8", errors="ignore")
        combined += f"\n=== END OF CONFIG: {host} ===\n"
    return combined


# ============================================================
# 아이템별 토큰 추정
# ============================================================
def estimate_item(item: dict, full_config: str, count: callable) -> dict:
    """
    단일 결과 항목의 입력/출력 토큰을 추정한다.

    Returns:
        dict: {
            "input":  {"collector", "verifier", "synthesizer", "supporter", "skeptic", "total"},
            "output": {"collector", "verifier", "synthesizer", "supporter", "skeptic", "total"},
        }
    """
    question          = item.get("question", "")
    current_passage   = item.get("current_passage", "")
    candidate_answer  = item.get("candidate_answer", "")
    proponent_history = item.get("proponent_history", [])   # list[str]
    critic_history    = item.get("critic_history", [])      # list[str]
    collector_retries = item.get("collector_retries", [])
    synth_retries     = item.get("synthesizer_retries", [])
    n_rounds          = max(len(proponent_history), 1)

    # ── Collector ──────────────────────────────────────────
    col_prompt = f"{COLLECTOR_SYSTEM}\n\nQuestion: {question}\nContext: {full_config}"
    for retry in collector_retries:
        col_prompt += f"\n[Critic Feedback - Re-extract based on this]: {retry.get('feedback', '')}"
    col_in  = count(col_prompt)
    col_out = count(current_passage)   # ≈ Collector 출력

    # ── Verifier ───────────────────────────────────────────
    # 입력: VERIFIER_RUBRIC + question + current_passage (마지막 RELEVANT 라운드 기준)
    ver_prompt = f"{VERIFIER_RUBRIC}\n\nQuestion: {question}\nExtracted Context:\n{current_passage}"
    ver_in  = count(ver_prompt)
    # 출력: JSON 구조 고정 부분 + feedback 가변 부분
    #   - IRRELEVANT 라운드: feedback = collector_retries[i].feedback (저장된 텍스트)
    #   - RELEVANT 라운드 (마지막): feedback = "" → base JSON만
    ver_base_tokens = count(VERIFIER_BASE_JSON)
    ver_out = ver_base_tokens  # 마지막 RELEVANT 라운드 (feedback 없음)
    for retry in collector_retries:
        feedback_text = retry.get("feedback", "")
        # IRRELEVANT 라운드: base JSON + feedback 텍스트 추가분
        ver_out += ver_base_tokens + count(feedback_text)
        # 해당 라운드의 입력도 추가 (raw_data ≈ current_passage 근사)
        ver_in  += count(ver_prompt)

    # ── Synthesizer ────────────────────────────────────────
    # 첫 라운드 + retry 횟수만큼 프롬프트 재구성
    synth_in = 0
    synth_out = 0
    base_synth = f"{SYNTHESIZER_SYSTEM}\n\nQuestion: {question}\nOptions: N/A\nContext (Passage): {current_passage}"
    synth_in += count(base_synth)   # 첫 라운드
    synth_out += count(f"[START]\nAnswer:\n{candidate_answer}\n[DONE]")

    for retry in synth_retries:
        feedback = retry.get("feedback", "")
        synth_in  += count(base_synth + f"\n\n[Critic Feedback - Revise your answer]:\n{feedback}")
        synth_out += count(f"[START]\nAnswer:\n{candidate_answer}\n[DONE]")   # 재생성 근사

    # ── Supporter ──────────────────────────────────────────
    sup_in = sup_out = 0
    for i, pro_arg in enumerate(proponent_history):
        prev_feedback = critic_history[i - 1] if i > 0 else ""
        sup_prompt = (
            f"{SUPPORTER_SYSTEM}\n\n"
            f"Question: {question}\n"
            f"Passage: {current_passage}\n"
            f"Candidate Answer: {candidate_answer}\n"
            f"Previous Critic Feedback: {prev_feedback if prev_feedback else 'None'}"
        )
        sup_in  += count(sup_prompt)
        sup_out += count(pro_arg)

    if not proponent_history:
        # 최소 1라운드 추정
        sup_in += count(
            f"{SUPPORTER_SYSTEM}\n\nQuestion: {question}\n"
            f"Passage: {current_passage}\nCandidate Answer: {candidate_answer}\n"
            f"Previous Critic Feedback: None"
        )
        sup_out += count(candidate_answer)   # rough

    # ── Skeptic ────────────────────────────────────────────
    skep_in = skep_out = 0
    for i, crit_resp in enumerate(critic_history):
        pro_arg = proponent_history[i] if i < len(proponent_history) else ""
        skep_prompt = (
            f"{SKEPTIC_SYSTEM}\n\n"
            f"Question: {question}\n"
            f"Passage: {current_passage}\n"
            f"Candidate Answer: {candidate_answer}\n"
            f"Supporter's Defense: {pro_arg}"
        )
        skep_in  += count(skep_prompt)
        skep_out += count(crit_resp)

    if not critic_history:
        skep_in += count(
            f"{SKEPTIC_SYSTEM}\n\nQuestion: {question}\n"
            f"Passage: {current_passage}\nCandidate Answer: {candidate_answer}\n"
            f"Supporter's Defense: "
        )
        skep_out += 60   # ACCEPT JSON 최소 크기

    # ── 합산 (모델별) ──────────────────────────────────────
    # Model A: Verifier, Synthesizer, Supporter
    # Model B: Collector, Skeptic
    a_in  = ver_in  + synth_in  + sup_in
    a_out = ver_out + synth_out + sup_out
    b_in  = col_in  + skep_in
    b_out = col_out + skep_out

    return {
        "model_a": {"input": a_in,  "output": a_out},   # Verifier + Synthesizer + Supporter
        "model_b": {"input": b_in,  "output": b_out},   # Collector + Skeptic
        "total":   {"input": a_in + b_in, "output": a_out + b_out},
    }


# ============================================================
# 메인
# ============================================================
def main():
    parser = argparse.ArgumentParser(description="기존 결과 JSON에서 토큰 사용량을 추정한다.")
    parser.add_argument("result_json", help="결과 JSON 파일 경로")
    parser.add_argument("lab_dir",     nargs="?", default=None,
                        help="netconfig2/lab_x 디렉토리 (configs/ 상위). 생략 시 Collector 입력 = 0")
    parser.add_argument("--out", default=None,
                        help="출력 JSON 파일 경로 (기본: 결과 파일과 같은 폴더에 _token_estimate.json)")
    args = parser.parse_args()

    result_path = Path(args.result_json)
    if not result_path.exists():
        print(f"ERROR: {result_path} 없음")
        sys.exit(1)

    # 출력 경로
    out_path = Path(args.out) if args.out else result_path.with_name(
        result_path.stem + "_token_estimate.json"
    )

    # 전체 config 로드
    full_config = ""
    if args.lab_dir:
        lab_dir = Path(args.lab_dir)
        full_config = load_full_config(lab_dir)
        print(f"[Config] {lab_dir}/configs/ → {len(full_config):,} chars")
    else:
        print("[Config] lab_dir 미지정 → Collector 입력 토큰은 0으로 처리 (과소 추정)")

    # 토크나이저
    count = _make_tokenizer()

    # 결과 JSON 로드
    with open(result_path, encoding="utf-8") as f:
        payload = json.load(f)
    rows = payload.get("results", payload) if isinstance(payload, dict) else payload
    print(f"[Data] {len(rows)}개 항목 처리 중...")

    # ── 아이템별 추정 ─────────────────────────────────────
    results_with_tokens = []
    agg = {
        "model_a": {"input": 0, "output": 0},
        "model_b": {"input": 0, "output": 0},
    }

    for item in rows:
        tok = estimate_item(item, full_config, count)
        for m in ("model_a", "model_b"):
            agg[m]["input"]  += tok[m]["input"]
            agg[m]["output"] += tok[m]["output"]
        results_with_tokens.append({**item, "token_estimate": tok})

    n = len(rows)
    total_in  = agg["model_a"]["input"]  + agg["model_b"]["input"]
    total_out = agg["model_a"]["output"] + agg["model_b"]["output"]

    token_stats = {
        "note": (
            "소급 추정값 (실제 API usage_metadata 아님). "
            "Collector 입력 = full config 기준. "
            "Verifier 출력 = JSON 구조 고정 + collector_retries feedback 텍스트 합산."
        ),
        "model_a": {                              # Verifier + Synthesizer + Supporter
            "total_input":  agg["model_a"]["input"],
            "total_output": agg["model_a"]["output"],
            "avg_input":    round(agg["model_a"]["input"]  / n, 1) if n else 0,
            "avg_output":   round(agg["model_a"]["output"] / n, 1) if n else 0,
        },
        "model_b": {                              # Collector + Skeptic
            "total_input":  agg["model_b"]["input"],
            "total_output": agg["model_b"]["output"],
            "avg_input":    round(agg["model_b"]["input"]  / n, 1) if n else 0,
            "avg_output":   round(agg["model_b"]["output"] / n, 1) if n else 0,
        },
        "total": {
            "total_input":  total_in,
            "total_output": total_out,
            "total_tokens": total_in + total_out,
            "avg_input":    round(total_in  / n, 1) if n else 0,
            "avg_output":   round(total_out / n, 1) if n else 0,
            "avg_total":    round((total_in + total_out) / n, 1) if n else 0,
        },
        "samples": n,
    }

    # ── 출력 ──────────────────────────────────────────────
    output = {
        "meta":        payload.get("meta", {}) if isinstance(payload, dict) else {},
        "token_stats": token_stats,
        "results":     results_with_tokens,
    }

    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(output, f, indent=4, ensure_ascii=False)

    s = token_stats
    print("\n" + "=" * 62)
    print(f"  {'':30s}  {'입력':>10}  {'출력':>10}")
    print(f"  {'-'*56}")
    print(f"  Model A (Verifier+Synth+Supporter)  "
          f"{s['model_a']['total_input']:>10,}  {s['model_a']['total_output']:>10,}")
    print(f"  Model B (Collector+Skeptic)         "
          f"{s['model_b']['total_input']:>10,}  {s['model_b']['total_output']:>10,}")
    print(f"  {'─'*56}")
    print(f"  Total                               "
          f"{s['total']['total_input']:>10,}  {s['total']['total_output']:>10,}")
    print(f"  합계 (input+output)                 "
          f"{s['total']['total_tokens']:>10,}")
    print(f"  {'─'*56}")
    print(f"  평균/건 Model A                     "
          f"{s['model_a']['avg_input']:>10.1f}  {s['model_a']['avg_output']:>10.1f}")
    print(f"  평균/건 Model B                     "
          f"{s['model_b']['avg_input']:>10.1f}  {s['model_b']['avg_output']:>10.1f}")
    print(f"  평균/건 Total                       "
          f"{s['total']['avg_input']:>10.1f}  {s['total']['avg_output']:>10.1f}")
    print(f"  샘플 수                             {n:>10,}")
    print("=" * 62)
    print(f"  저장 → {out_path}")


if __name__ == "__main__":
    main()
