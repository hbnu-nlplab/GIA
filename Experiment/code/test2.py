import os
import json
import time
from dotenv import load_dotenv
from openai import OpenAI

# ---------------------------------------------------------
# 설정 (경로 및 모델)
# ---------------------------------------------------------
RAW_DATA_PATH = "../data/teleQnA/TeleQnA.json"
DATA_PATH = "../data/llm_answer_teleqna/"
FINAL_JSON = os.path.join(DATA_PATH, "llm_answer_gpt5.json")

# 사용할 모델명
target_model = "gpt-5-mini"

# API 키 로드
load_dotenv("openai_key.env")
client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))

# ---------------------------------------------------------
# 1. 데이터 로드 함수 (기존 유지)
# ---------------------------------------------------------
def load_qna():
    print(f"[*] 데이터 로드 중: {RAW_DATA_PATH}")
    
    with open(RAW_DATA_PATH, "r", encoding="utf-8") as f:
        data = json.load(f)

    qna_list = []
    
    # data가 리스트인지 딕셔너리인지 확인하여 반복자 설정
    iterator = data.values() if isinstance(data, dict) else data

    for item in iterator:
        if not isinstance(item, dict):
            continue
        
        if "question" not in item:
            continue

        question = item.get("question", "")
        gold_answer = item.get("answer", "")
        
        # 옵션 추출 및 정렬
        raw_options = {k: v for k, v in item.items() if k.startswith("option")}
        sorted_keys = sorted(
            raw_options.keys(), 
            key=lambda x: int(x.split()[-1]) if x.split()[-1].isdigit() else 999
        )
        
        options_list = []
        for key in sorted_keys:
            options_list.append(f"{key}: {raw_options[key]}")
        
        options_str = "\n".join(options_list)

        qna_list.append({
            "question": question,
            "options": options_str,
            "gold_answer": gold_answer
        })

    print(f"[+] 총 {len(qna_list)}개의 유효한 문항을 로드했습니다.")
    return qna_list

# ---------------------------------------------------------
# 2. LLM 응답 생성 함수 (직접 호출)
# ---------------------------------------------------------
def get_llm_response(question, options, model):
    PROMPT_TEMPLATE = """
### Role
You are a Senior Network Specification Engineer. Your task is to select the correct answer based on your expert knowledge of network standards and theory.

### Rules
1. **Knowledge Base:** Use your internal knowledge to identify the correct option. Pay close attention to the specific standard version mentioned (e.g., [3GPP Release 18]).
2. **Format:** Output the answer as "option [num]: [Content]".

### Example
Question: "When are devices required to send the GTS Request command? [IEEE 802.15.4]"
Options:
option 1: Only devices without a short address
option 2: Only devices using extended addressing
option 3: Only devices capable of sending it
option 4: All devices
Answer: "option 3: Only devices capable of sending it"

---
### Question
{question}

### Options
{options}

Answer:
"""
    prompt = PROMPT_TEMPLATE.format(question=question, options=options)

    try:
        response = client.chat.completions.create(
            model=model,
            messages=[{"role": "user", "content": prompt}],
            temperature=1,
            max_tokens=100
        )
        return response.choices[0].message.content.strip()
    except Exception as e:
        print(f"[!] API 호출 에러: {e}")
        return "Error"

# ---------------------------------------------------------
# 메인 실행
# ---------------------------------------------------------
if __name__ == "__main__":
    # 1. 데이터 로드
    qna_list = load_qna()

    if not qna_list:
        print("[!] 로드된 데이터가 없습니다.")
        exit()

    os.makedirs(DATA_PATH, exist_ok=True)
    final_results = []
    
    print(f"[*] {target_model} 모델로 추론 시작 (총 {len(qna_list)}개)...")
    
    # 시간 측정 시작
    start_time = time.time()

    for idx, item in enumerate(qna_list):
        # 진행 상황 출력 (10개 단위)
        if (idx + 1) % 10 == 0:
            elapsed = time.time() - start_time
            print(f" -> 진행 중: {idx + 1}/{len(qna_list)} (경과 시간: {elapsed:.1f}초)")

        # API 호출
        llm_answer = get_llm_response(item["question"], item["options"], target_model)
        
        # 결과 저장 구조
        result_entry = {
            "question": item["question"],
            "gold_answer": item["gold_answer"],
            target_model: llm_answer  # 예: "gpt-4o": "option 1: ..."
        }
        final_results.append(result_entry)

    # 3. 결과 저장
    with open(FINAL_JSON, "w", encoding="utf-8") as f:
        json.dump(final_results, f, ensure_ascii=False, indent=2)

    print(f"[+] 모든 작업 완료. 결과 저장됨: {FINAL_JSON}")