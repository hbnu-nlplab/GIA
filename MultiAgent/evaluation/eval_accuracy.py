import json
import re
import sys
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parents[1]
sys.path.append(str(BASE_DIR))

DATA_PATH = BASE_DIR / "data" / "debate_results" / "agents_v2" /  "mas" / "teleqna" / "teleqna_result.json"
MODEL_KEY = "debate2_answer"

def extract_option_number_from_gold(text):
    """
    gold_answer에서 'option 숫자' 패턴을 찾아 숫자를 반환합니다.
    예: "option 3: Core network..." -> "3"
    예: "Option 4" -> "4"
    """
    if not isinstance(text, str):
        return None
    
    # 대소문자 구분 없이 'option' 뒤에 오는 숫자 추출
    match = re.search(r"option\s*(\d+)", text, re.IGNORECASE)
    if match:
        return match.group(1)
    return None

def extract_option_number_from_llm(text):
    """
    debate2_answer에서 숫자를 추출합니다.
    1. 먼저 'option 숫자' 패턴을 찾습니다.
    2. 없으면 문자열에서 첫 번째 숫자를 추출합니다.
    예: "option 3: ..." -> "3"
    예: "5" -> "5"
    예: "The answer is 4" -> "4"
    """
    if not isinstance(text, str):
        return None
    
    # 먼저 'option 숫자' 패턴 시도
    match = re.search(r"option\s*(\d+)", text, re.IGNORECASE)
    if match:
        return match.group(1)
    
    # 없으면 단순히 첫 번째 숫자 추출
    match = re.search(r"(\d+)", text)
    if match:
        return match.group(1)
    
    return None

def calculate_accuracy():
    try:
        with open(DATA_PATH, "r", encoding="utf-8") as f:
            data = json.load(f)
    except FileNotFoundError:
        print(f"Error: {DATA_PATH} 파일을 찾을 수 없습니다.")
        return

    correct_count = 0
    total_count = 0
    parse_error_count = 0
    
    # 틀린 문제 확인용 리스트
    wrong_answers = []

    for idx, item in enumerate(data):
        gold_raw = item.get("gold_answer", "")
        llm_raw = item.get(MODEL_KEY, "")

        # 옵션 번호만 추출
        gold_opt = extract_option_number_from_gold(gold_raw)
        llm_opt = extract_option_number_from_llm(llm_raw)

        # 정답 데이터 자체가 이상한 경우 건너뜀
        if not gold_opt:
            continue

        total_count += 1

        # LLM이 형식을 지키지 못해 번호를 못 찾은 경우 (오답 처리)
        if not llm_opt:
            parse_error_count += 1
            wrong_answers.append({
                "idx": idx,
                "type": "Parse Error",
                "question": item.get("question", "")[:50] + "...",
                "gold": gold_raw,
                "llm": llm_raw
            })
            continue

        # 번호 비교
        if gold_opt == llm_opt:
            correct_count += 1
        else:
            wrong_answers.append({
                "idx": idx,
                "type": "Wrong",
                "question": item.get("question", "")[:50] + "...",
                "gold": gold_raw,
                "llm": llm_raw
            })

    # 결과 출력
    if total_count == 0:
        print("평가할 데이터가 없습니다.")
        return

    accuracy = (correct_count / total_count) * 100
    
    print("=" * 40)
    print(f"MODEL: {MODEL_KEY}")
    print("=" * 40)
    print(f"Total Questions : {total_count}")
    print(f"Correct Answers : {correct_count}")
    print(f"Wrong Answers   : {total_count - correct_count}")
    print(f" - Mismatch     : {len(wrong_answers) - parse_error_count}")
    print(f" - Parse Error  : {parse_error_count} (형식 불일치)")
    print("-" * 40)
    print(f"Accuracy        : {accuracy:.2f}%")
    print("=" * 40)

    # Parse Error 상세 출력
    parse_errors = [w for w in wrong_answers if w['type'] == 'Parse Error']
    if parse_errors:
        print(f"\n[Parse Error 상세 ({len(parse_errors)}개)]")
        print("=" * 60)
        for i, wrong in enumerate(parse_errors[:10], 1):  # 최대 10개만 출력
            print(f"{i}. Idx: {wrong['idx']}")
            print(f"   Question: {wrong['question']}")
            print(f"   Gold    : {wrong['gold']}")
            print(f"   LLM     : {wrong['llm']}")
            print("-" * 60)

    # 일반 오답 예시
    mismatch_errors = [w for w in wrong_answers if w['type'] == 'Wrong']
    if mismatch_errors:
        print(f"\n[오답 예시 (상위 5개)]")
        print("=" * 60)
        for i, wrong in enumerate(mismatch_errors[:5], 1):
            print(f"{i}. Idx: {wrong['idx']}")
            print(f"   Question: {wrong['question']}")
            print(f"   Gold    : {wrong['gold']}")
            print(f"   LLM     : {wrong['llm']}")
            print("-" * 60)

if __name__ == "__main__":
    calculate_accuracy()