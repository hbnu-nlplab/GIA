import json
import re

# 파일 경로 설정 (사용자 환경에 맞게 수정)
DATA_PATH = "../data/llm_answer_teleqna/llm_answer_gpt4o-mini.json"
MODEL_KEY = "gpt-4o-mini"

def extract_option_number(text):
    """
    문자열에서 'option 숫자' 또는 'option숫자' 패턴을 찾아 숫자를 반환합니다.
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
        gold_opt = extract_option_number(gold_raw)
        llm_opt = extract_option_number(llm_raw)

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

    # (선택사항) 오답 예시 3개만 출력해보기
    if wrong_answers:
        print("\n[오답 예시 (상위 3개)]")
        for wrong in wrong_answers[:3]:
            print(f"Idx: {wrong['idx']} | Type: {wrong['type']}")
            print(f"Gold: {wrong['gold']}")
            print(f"LLM : {wrong['llm']}")
            print("-" * 20)

if __name__ == "__main__":
    calculate_accuracy()