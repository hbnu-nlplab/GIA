import json
from pathlib import Path

def find_missing_question_only():
    base_dir = Path(".").resolve()
    # 경로 확인 필수
    input_path = base_dir / "data" / "passages" / "full_w_context" / "telequad_passage.json"
    output_path = base_dir / "data" / "debate_results" / "full_w_context" / "telequad_result.json"

    print(f"Loading Input: {input_path}")
    print(f"Loading Output: {output_path}")

    try:
        with open(input_path, 'r', encoding='utf-8') as f:
            input_data = json.load(f)
        with open(output_path, 'r', encoding='utf-8') as f:
            output_data = json.load(f)
    except FileNotFoundError:
        print("파일을 찾을 수 없습니다.")
        return

    print(f"Input Count: {len(input_data)}")
    print(f"Output Count: {len(output_data)}")

    # 1. 출력 파일의 질문들만 리스트로 추출 (공백 제거)
    # 비교를 위해 미리 문자열 리스트로 만듭니다.
    output_questions_pool = [item.get('question', '').strip() for item in output_data]
    
    missing_indices = []

    print("\n======== Scanning for Missing Questions ========")

    # 2. 입력 데이터를 하나씩 순회하며 Pool에서 제거
    for idx, item in enumerate(input_data):
        input_q = item.get('question', '').strip()
        
        # 출력 Pool에 이 질문이 존재하는가?
        if input_q in output_questions_pool:
            # 존재하면 Pool에서 *하나만* 제거 (remove는 첫 번째 일치 항목만 지움)
            # 이를 통해 중복 질문도 정확히 1:1 매칭됨
            output_questions_pool.remove(input_q)
        else:
            # Pool에 없으면 누락된 것임
            print(f"🚨 MISSING at Index {idx}")
            print(f"   Question: {input_q}")
            missing_indices.append(idx)

    print("\n======== Summary ========")
    print(f"Total Missing: {len(missing_indices)}")
    print(f"Missing Indices: {missing_indices}")

if __name__ == "__main__":
    find_missing_question_only()