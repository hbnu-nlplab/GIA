"""
single_llm_netconfig.py
-----------------------
NetConfig 데이터셋에 대한 단일 LLM 평가 실행 모듈.

Multi-Agent(Collector→Verifier→Synthesizer→Supporter→Skeptic) 없이
단일 LLM 한 번의 호출로 답변을 생성한다.

결과 필드는 기존 evaluate 스크립트와 호환되도록
debate2_answer에 최종 답변을 저장한다.

Usage:
    python single_llm_netconfig.py
    python single_llm_netconfig.py --limit 50
    python single_llm_netconfig.py --level L1 L2
"""

import re
import sys
import os
import json
import time
import argparse
import traceback
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed

try:
    from tqdm import tqdm
except ImportError:
    def tqdm(iterable, *args, **kwargs):
        return iterable

# 프로젝트 루트를 sys.path에 추가
CURRENT_DIR = Path(__file__).resolve().parent
sys.path.append(str(CURRENT_DIR))

from config.load_env import load_louter
from langchain_openai import ChatOpenAI


# ==========================================
# 설정
# ==========================================

INPUT_PATH  = CURRENT_DIR / "data" / "passages" / "full_w_context" / "netconfig_en2.json"
CONFIG_PATH = CURRENT_DIR / "data" / "original" / "netconfig" / "configs.txt"
OUTPUT_DIR  = CURRENT_DIR / "data" / "debate_results" / "single_llm"

MAX_WORKERS = 20   # 동시 요청 수
MAX_TOKENS  = 4096
TEMPERATURE = 0.0


# ==========================================
# 시스템 프롬프트
# ==========================================

SYSTEM_PROMPT = """You are an expert Network Engineer analyzing network device configurations.

CRITICAL: Carefully read ALL provided configuration files before answering.

OUTPUT FORMAT (strictly follow based on [ANSWER TYPE]):
- text        : Output the exact string value only (e.g., R1  or  10.0.0.1)
                 For network paths use '->' between nodes (e.g., nodeA -> nodeB -> nodeC)
- number      : Output the numeric value only (e.g., 5)
- boolean     : Output only 'true' or 'false' (lowercase)
- set / list  : Output a valid JSON array with double quotes (e.g., ["item1", "item2"])
                 List ALL matching items — do not truncate.
- map / dict  : Output a valid JSON object with double quotes (e.g., {"key": "value"})
                 Include ALL matching key-value pairs — do not truncate.

If the information is NOT_CONFIGURED or not found, output:
- text → null  |  number → 0  |  boolean → false  |  set → []  |  map → {}

Your entire response will be parsed programmatically.
Output ONLY the raw answer — no explanation, no markdown, no code blocks."""


# ==========================================
# 설정 파일 로더
# ==========================================

def load_netconfigs(config_path: Path) -> dict:
    """configs.txt를 읽어 {장비명(소문자): 설정내용} 딕셔너리를 반환한다."""
    if not config_path.exists():
        print(f"Warning: Config file not found: {config_path}")
        return {}

    print(f"Loading configs from: {config_path}")
    text = config_path.read_text(encoding='utf-8', errors='ignore')

    result = {}
    current_device = None
    current_lines = []

    for line in text.splitlines():
        m = re.match(r'^\[(.+?)\.cfg\]$', line.strip())
        if m:
            if current_device:
                result[current_device.lower()] = "\n".join(current_lines)
            current_device = m.group(1)
            current_lines = []
        else:
            current_lines.append(line)

    if current_device:
        result[current_device.lower()] = "\n".join(current_lines)

    print(f"Loaded {len(result)} device configs: {list(result.keys())}")
    return result


# ==========================================
# 컨텍스트 선택
# ==========================================

TOPO_KEYWORDS = ('hop', 'path', 'route', 'block', 'flow', 'reach', 'traceroute')

def select_context(item: dict, global_configs: dict) -> str:
    """질문 특성에 따라 관련 config를 선택해 반환한다."""
    q_text = item.get('question', '')
    level  = item.get('level', '')
    answer_type = item.get('answer_type', '')

    needs_full = (
        level in ('L4', 'L5') or
        answer_type == 'number' or
        any(kw in q_text.lower() for kw in TOPO_KEYWORDS)
    )

    if needs_full:
        return "\n".join(global_configs.values())

    # 질문에 언급된 장비명과 매칭
    matched = [cfg for dev, cfg in global_configs.items() if dev in q_text.lower()]
    if matched:
        return "\n".join(matched)

    # 매칭 실패 → 전체 사용
    return "\n".join(global_configs.values())


# ==========================================
# 응답 정제
# ==========================================

def clean_response(raw: str) -> str:
    """<think> 블록 제거 후 첫 번째 유효 줄만 반환한다."""
    text = re.sub(r"<think>.*?</think>", "", raw, flags=re.DOTALL).strip()
    # 마크다운 코드블록 제거
    text = re.sub(r"```[a-zA-Z]*\n?", "", text).replace("```", "").strip()
    # 첫 줄만 반환 (설명이 붙는 경우 대응)
    lines = [l.strip() for l in text.splitlines() if l.strip()]
    return lines[0] if lines else ""


# ==========================================
# 단일 항목 처리
# ==========================================

def process_item(llm, item: dict, global_configs: dict) -> dict | None:
    item_id  = item.get('id', '')
    q_text   = item.get('question', '')
    answer_type = item.get('answer_type', 'text')

    context = select_context(item, global_configs)

    user_msg = (
        f"=== NETWORK CONFIGURATIONS ===\n{context}\n\n"
        f"=== QUESTION ===\n{q_text}\n\n"
        f"=== ANSWER TYPE ===\n{answer_type}\n\n"
        f"=== YOUR ANSWER (ONE LINE ONLY) ==="
    )

    messages = [
        {"role": "system", "content": SYSTEM_PROMPT},
        {"role": "user",   "content": user_msg},
    ]

    start = time.time()
    try:
        response = llm.invoke(messages)
        raw = response.content if hasattr(response, 'content') else str(response)
        answer = clean_response(raw)

        return {
            "id":           item_id,
            "question":     q_text,
            "gold_answer":  item.get('gold_answer'),
            "level":        item.get('level', ''),
            "answer_type":  answer_type,
            "answer_status": item.get('answer_status', ''),
            "debate2_answer": answer,   # 기존 평가 스크립트 호환 필드명
            "raw_response": raw,
            "duration":     time.time() - start,
        }
    except Exception as e:
        print(f"Error on id={item_id}: {e}")
        traceback.print_exc()
        return None


# ==========================================
# 메인
# ==========================================

def main():
    parser = argparse.ArgumentParser(description="Single-LLM NetConfigQA evaluator")
    parser.add_argument("--limit",  type=int, default=None, help="처리 항목 수 제한 (디버그용)")
    parser.add_argument("--level",  nargs="+", default=None, help="특정 레벨만 실행 (예: L1 L2)")
    parser.add_argument("--resume", action="store_true",     help="기존 결과 이어서 실행")
    args = parser.parse_args()

    # 모델 초기화
    api_key, base_url, model1, _ = load_louter()
    llm = ChatOpenAI(
        model=model1,
        base_url=base_url,
        api_key=api_key,
        temperature=TEMPERATURE,
        max_tokens=MAX_TOKENS,
    )
    print(f"Model: {model1}")

    # 데이터 로드
    if not INPUT_PATH.exists():
        print(f"Input not found: {INPUT_PATH}")
        return

    with open(INPUT_PATH, encoding='utf-8') as f:
        data: list = json.load(f)
    if isinstance(data, dict):
        data = [data]
    print(f"Loaded {len(data)} questions")

    # Config 로드
    global_configs = load_netconfigs(CONFIG_PATH)

    # 레벨 필터
    if args.level:
        data = [d for d in data if d.get('level', '') in args.level]
        print(f"After level filter {args.level}: {len(data)} questions")

    # 출력 경로
    model_safe = re.sub(r"[/:\\]", "_", model1)
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    output_path = OUTPUT_DIR / f"{model_safe}_result.json"

    # 기존 결과 로드 (resume)
    existing: dict = {}
    if args.resume and output_path.exists():
        try:
            with open(output_path, encoding='utf-8') as f:
                for r in json.load(f):
                    existing[str(r['id'])] = r
            print(f"Resumed: {len(existing)} existing results")
        except Exception:
            print("Failed to load existing results, starting fresh.")

    # 처리 대상 선정
    items_to_run = [
        d for d in data
        if str(d.get('id', '')) not in existing
    ]
    if args.limit:
        items_to_run = items_to_run[:args.limit]

    print(f"To process: {len(items_to_run)} / {len(data)}")

    # 병렬 처리
    processed = 0
    start_total = time.time()

    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = {
            executor.submit(process_item, llm, item, global_configs): item
            for item in items_to_run
        }

        for future in tqdm(as_completed(futures), total=len(futures), desc="Evaluating"):
            res = future.result()
            if res:
                existing[str(res['id'])] = res
                processed += 1

                if processed % 20 == 0:
                    with open(output_path, 'w', encoding='utf-8') as f:
                        json.dump(list(existing.values()), f, indent=2, ensure_ascii=False)

    # 최종 저장
    final = list(existing.values())
    with open(output_path, 'w', encoding='utf-8') as f:
        json.dump(final, f, indent=2, ensure_ascii=False)

    elapsed = time.time() - start_total
    print(f"\nDone! {len(final)} results saved to {output_path}")
    print(f"Total time: {elapsed:.1f}s  ({elapsed/max(processed,1):.1f}s/item)")


if __name__ == "__main__":
    main()
