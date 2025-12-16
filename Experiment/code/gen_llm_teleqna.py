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
FINAL_JSON = os.path.join(DATA_PATH, "llm_answer_gpt4o.json")

# 사용할 모델명 (OpenAI Batch API 지원 모델)
MODELS = ["gpt-4o"]

# API 키 로드
load_dotenv("openai_key.env")
client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))

# ---------------------------------------------------------
# 1. 데이터 로드 함수 (수정됨)
# ---------------------------------------------------------
def load_qna():
    print(f"[*] 데이터 로드 중: {RAW_DATA_PATH}")
    
    with open(RAW_DATA_PATH, "r", encoding="utf-8") as f:
        data = json.load(f)

    qna_list = []
    
    # data가 리스트인지 딕셔너리인지 확인하여 반복자 설정
    iterator = data.values() if isinstance(data, dict) else data

    for item in iterator:
        # [핵심 수정] item이 딕셔너리가 아니면(예: "version": "v4" 같은 문자열 메타데이터) 건너뜀
        if not isinstance(item, dict):
            continue
        
        # 질문 데이터가 맞는지 확인 ("question" 키가 없으면 건너뜀)
        if "question" not in item:
            continue

        question = item.get("question", "")
        gold_answer = item.get("answer", "")
        
        # 옵션 추출 (option 1, option 2...)
        raw_options = {k: v for k, v in item.items() if k.startswith("option")}
        
        # 옵션 정렬 (숫자 기준 정렬: option 1 -> option 2 -> option 10)
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
# 2. 배치 입력 파일(.jsonl) 생성 함수
# ---------------------------------------------------------
def create_input_jsonl(qna_list, model):
    os.makedirs(DATA_PATH, exist_ok=True)
    input_jsonl_path = os.path.join(DATA_PATH, f"input_{model}.jsonl")
    
    # 프롬프트 템플릿
    PROMPT_TEMPLATE = """
### Role
You are a Senior Network Specification Engineer. Your task is to select the correct answer based on your expert knowledge of network standards and theory.

### Rules
1. **Knowledge Base:** Use your internal knowledge to identify the correct option. Pay close attention to the specific standard version mentioned (e.g., [3GPP Release 18]).
2. **Format:** Output the answer as "option [num]: [Content]".
3. **Brevity:** If the content is long, summarize it to capture the key technical meaning within 50 characters.

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
    print(f"[*] {model}용 JSONL 파일 생성 중...")
    with open(input_jsonl_path, "w", encoding="utf-8") as f:
        for idx, item in enumerate(qna_list):
            prompt = PROMPT_TEMPLATE.format(question=item["question"], options=item['options'])
            
            # API 요청 객체 생성
            entry = {
                "custom_id": f"{idx}", # 나중에 순서 맞출 때 사용
                "method": "POST",
                "url": "/v1/chat/completions",
                "body": {
                    "model": model,
                    "messages": [{"role": "user", "content": prompt}],
                    "temperature": 0.0, # 객관식 문제이므로 일관성을 위해 0.0 권장
                    "max_tokens": 100
                }
            }
            f.write(json.dumps(entry, ensure_ascii=False) + "\n")
            
    print(f"[+] 생성 완료: {input_jsonl_path}")
    return input_jsonl_path

# ---------------------------------------------------------
# 3. 배치 실행 및 대기 함수
# ---------------------------------------------------------
def run_batch(input_jsonl_path):
    print("[*] OpenAI 서버에 배치 파일 업로드 중...")
    batch_input_file = client.files.create(
        file=open(input_jsonl_path, "rb"),
        purpose="batch"
    )

    print(f"[*] 배치 작업 생성 중 (File ID: {batch_input_file.id})...")
    batch = client.batches.create(
        input_file_id=batch_input_file.id,
        endpoint="/v1/chat/completions",
        completion_window="24h"
    )
    print(f"[+] 배치 시작됨 ID: {batch.id}")

    # 상태 폴링
    while True:
        batch = client.batches.retrieve(batch.id)
        print(f" - [{time.strftime('%H:%M:%S')}] 현재 상태: {batch.status}")
        
        if batch.status == "completed":
            return batch
        elif batch.status in ["failed", "cancelled", "expired"]:
            print(f"[!] 배치 실패. 상태: {batch.status}")
            # 에러 로그가 있다면 출력
            if batch.errors:
                print(batch.errors)
            return batch
        
        time.sleep(10) # 10초마다 상태 확인

# ---------------------------------------------------------
# 4. 결과 다운로드 함수
# ---------------------------------------------------------
def download_output(batch, model):
    if not batch.output_file_id:
        print(f"[!] {model} 결과 파일 ID가 없습니다. (실패했을 가능성 있음)")
        return None
        
    print(f"[*] 결과 다운로드 중 (Output File ID: {batch.output_file_id})...")
    content = client.files.content(batch.output_file_id)
    
    output_jsonl_path = os.path.join(DATA_PATH, f"output_{model}.jsonl")
    with open(output_jsonl_path, "wb") as f:
        f.write(content.read())
        
    print(f"[+] {model} 결과 저장 완료: {output_jsonl_path}")
    return output_jsonl_path

# ---------------------------------------------------------
# 5. 최종 결과 병합 함수
# ---------------------------------------------------------
def merge_outputs(qna_list, models):
    final = []
    
    # 각 모델별 결과를 딕셔너리에 로드 { "gpt-4o-mini": { "0": "답...", "1": "답..." } }
    model_outputs_map = {model: {} for model in models}

    for model in models:
        output_jsonl_path = os.path.join(DATA_PATH, f"output_{model}.jsonl")
        
        if not os.path.exists(output_jsonl_path):
            print(f"[!] 경고: {model} 결과 파일이 존재하지 않습니다.")
            continue
            
        with open(output_jsonl_path, "r", encoding="utf-8") as f:
            for line in f:
                item = json.loads(line)
                idx = item["custom_id"] # 문자열로 된 인덱스
                
                # 응답 성공 여부 확인
                if item.get("response") and item["response"]["status_code"] == 200:
                    answer_content = item["response"]["body"]["choices"][0]["message"]["content"]
                    model_outputs_map[model][idx] = answer_content
                else:
                    model_outputs_map[model][idx] = "Error: API Request Failed"

    # 원본 리스트와 합치기
    for idx, qa in enumerate(qna_list):
        entry = {
            "question": qa["question"],
            "gold_answer": qa["gold_answer"]
        }
        
        str_idx = str(idx) # custom_id와 매칭하기 위해 문자열 변환
        for model in models:
            # 해당 인덱스의 답이 있으면 가져오고, 없으면 빈 문자열
            entry[model] = model_outputs_map[model].get(str_idx, "")
            
        final.append(entry)

    with open(FINAL_JSON, "w", encoding="utf-8") as f:
        json.dump(final, f, ensure_ascii=False, indent=2)
    print(f"[+] 최종 데이터 병합 완료: {FINAL_JSON}")

# ---------------------------------------------------------
# 메인 실행
# ---------------------------------------------------------
if __name__ == "__main__":
    # 1. 데이터 로드
    qna_list = load_qna()

    if qna_list:
        for model in MODELS:
            # 2. 입력 파일 생성
            input_path = create_input_jsonl(qna_list, model)
            
            # 3. 배치 실행
            batch = run_batch(input_path)
            
            # 4. 완료 시 다운로드
            if batch.status == "completed":
                download_output(batch, model)
            else:
                print(f"[!] {model} 배치 처리가 완료되지 못했습니다.")

        # 5. 결과 병합
        merge_outputs(qna_list, MODELS)
        print("[+] 모든 프로세스 완료")
    else:
        print("[!] 로드된 데이터가 없습니다. JSON 파일 경로와 내용을 확인하세요.")