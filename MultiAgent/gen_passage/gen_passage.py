import json
import sys
import os
from openai import OpenAI
from pathlib import Path

from config.load_env import load_api_key

BASE_DIR = Path(__file__).resolve().parents[1] 

# 경로 설정 업데이트 (Batch용 입력 및 참조 파일 경로 추가)
DATA_PATHS = {
    "telequad": {
        "input": BASE_DIR / "data" / "original" / "telequad.json",
        "batch_jsonl": BASE_DIR / "data" / "batch_input" / "telequad_batch.jsonl",      # OpenAI 전송용
        "reference": BASE_DIR / "data" / "passages" / "reference" / "telequad_ref.json" # 나중에 결과 매칭용
    },
    "teleqna": {
        "input": BASE_DIR / "data" / "original" / "teleqna.json",
        "batch_jsonl": BASE_DIR / "data" / "batch_input" / "teleqna_batch.jsonl",
        "reference": BASE_DIR / "data" / "passages" / "reference" / "teleqna_ref.json"
    },
    "netbench": {
        "input": BASE_DIR / "data" / "original" / "netbench_original.json",
        "batch_jsonl": BASE_DIR / "data" / "batch_input" / "netbench_batch.jsonl",
        "reference": BASE_DIR / "data" / "passages" / "reference" / "netbench_ref.json"
    },
    "netconfig": {
        "input": BASE_DIR / "data" / "original" / "qa_dataset.json",
        "batch_jsonl": BASE_DIR / "data" / "batch_input" / "netconfig_batch.jsonl",
        "reference": BASE_DIR / "data" / "passages" / "reference" / "netconfig_ref.json",
        "context_file": BASE_DIR / "data" / "original" / "netconfig_context.txt"
    }
}

# 데이터 처리 함수들은 그대로 유지
def process_tele_data(item):
    question = item.get('question', '')
    gold_answer = item.get('gold_answer', '')
    return question, gold_answer 

def process_netbench_data(item):
    context = item.get('Context', '')
    question = item.get('Question', '')
    gold_answer = item.get('Answer', '')
    return question, context, gold_answer

def process_netconfig_data(item):
    question = item.get('question', '')
    gold_answer = item.get('ground_truth', '')
    return question, gold_answer

def create_batch_files_and_run(dataset_key):
    api_key = load_api_key()
    if not api_key:
        print("API Key not found")
        return

    client = OpenAI(api_key=api_key)
    paths = DATA_PATHS.get(dataset_key)
    
    # 1. 데이터 로드
    try:
        with open(paths['input'], 'r', encoding='utf-8') as f:
            data_list = json.load(f)
    except FileNotFoundError:
        print(f"File not found: {paths['input']}")
        return

    # Netconfig Context 로드
    netconfig_context = ""
    if dataset_key == 'netconfig':
        context_file = paths.get('context_file')
        if os.path.exists(context_file):
            with open(context_file, 'r', encoding='utf-8') as f:
                netconfig_context = f.read()
        else:
            print(f"Warning: Context file not found.")
            return

    print(f"Creating Batch Input for '{dataset_key}' ({len(data_list)} items)...")
    
    batch_lines = []      # OpenAI로 보낼 JSONL 라인들
    reference_data = []   # 로컬에 저장할 질문/정답 원본 (매칭용)

    for idx, item in enumerate(data_list):
        # 데이터셋별 전처리
        if dataset_key in ['telequad', 'teleqna']:
            question, gold_answer = process_tele_data(item)
            combined_input = f"Question: {question}"
        elif dataset_key == 'netbench':
            question, context, gold_answer = process_netbench_data(item)
            combined_input = f"Scenario Context: {context}\n\nQuestion: {question}"
        elif dataset_key == 'netconfig':
            question, gold_answer = process_netconfig_data(item)
            combined_input = f"If there is no answer in context, write \"정보없음\". Network Configurations (Minified XML): {netconfig_context}\n\nQuestion: {question}"
        else:
            continue

        if not gold_answer:
            continue

        # 프롬프트 구성 (기존 동일)
        prompt_template = '''
        Your job is to act as a network management expert. You will write a good-quality concise passage that can answer the question based on your factual knowledge. If context is provided, you can write a passage based on it. Do not write a passage if you don’t know accurate information about the question.
Now, let's start. Write [NONE] if you cannot write a factual good passage. 
{combined_input}
Passage:
'''
        system_content = prompt_template.replace("{combined_input}", combined_input)
        
        # 고유 ID 생성 (결과 매칭용)
        custom_id = f"{dataset_key}-{idx}"

        # 2. Batch API용 Request Object 생성
        request_obj = {
            "custom_id": custom_id,
            "method": "POST",
            "url": "/v1/chat/completions",
            "body": {
                "model": "gpt-4o-mini",
                "messages": [
                    {"role": "system", "content": system_content},
                    {"role": "user", "content": "Write the passage."}
                ],
                "max_tokens": 250,
                "temperature": 0.0
            }
        }
        
        batch_lines.append(json.dumps(request_obj))

        # 3. Reference 데이터 저장 (Question, Gold Answer 보존)
        reference_data.append({
            "custom_id": custom_id,
            "question": question,
            "gold_answer": gold_answer,
            "passage": None  # 아직 생성되지 않음
        })

    # 파일 저장 디렉토리 생성
    os.makedirs(os.path.dirname(paths["batch_jsonl"]), exist_ok=True)
    os.makedirs(os.path.dirname(paths["reference"]), exist_ok=True)

    # 4. JSONL 파일 쓰기 (OpenAI 전송용)
    with open(paths["batch_jsonl"], 'w', encoding='utf-8') as f:
        f.write('\n'.join(batch_lines))
    
    # 5. Reference JSON 파일 쓰기 (사용자 요청: Question, Gold Answer 유지)
    with open(paths["reference"], 'w', encoding='utf-8') as f:
        json.dump(reference_data, f, ensure_ascii=False, indent=4)
        
    print(f"Files ready:\n - Batch Input: {paths['batch_jsonl']}\n - Reference: {paths['reference']}")

    # 6. OpenAI에 파일 업로드 및 배치 실행
    try:
        print("Uploading file to OpenAI...")
        batch_input_file = client.files.create(
            file=open(paths["batch_jsonl"], "rb"),
            purpose="batch"
        )
        file_id = batch_input_file.id

        print(f"Creating Batch Job for {dataset_key} (File ID: {file_id})...")
        batch_job = client.batches.create(
            input_file_id=file_id,
            endpoint="/v1/chat/completions",
            completion_window="24h", # 24시간 내 완료 (50% 할인)
            metadata={
                "description": f"Passage generation for {dataset_key}"
            }
        )
        
        print(f"✅ Batch Job Created! Batch ID: {batch_job.id}")
        print("Tip: Save this Batch ID to retrieve results later.\n")
        
    except Exception as e:
        print(f"❌ Error creating batch: {e}")

if __name__ == "__main__":
    DATA = ["telequad", "teleqna", "netbench", "netconfig"]
    for dataset_key in DATA:
        create_batch_files_and_run(dataset_key)