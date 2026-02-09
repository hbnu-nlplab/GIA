import json
import sys
import os
import time
from openai import OpenAI
from pathlib import Path

from config.load_env import load_api_key

BASE_DIR = Path(__file__).resolve().parents[1] 

# 경로 설정 업데이트 (Batch용 입력 및 참조 파일 경로 추가)
DATA_PATHS = {
    # "telequad": {
    #     "input": BASE_DIR / "data" / "original" / "telequad.json",
    #     "batch_jsonl": BASE_DIR / "data" / "batch_input" / "telequad_batch.jsonl",    
    #     "reference": BASE_DIR / "data" / "passages" / "reference" / "telequad_ref.json",
    #     "final_output": BASE_DIR / "data" / "passages" / "generated" / "telequad_passage.json"
    # }
    # "teleqna": {
    #     "input": BASE_DIR / "data" / "original" / "teleqna_original.json",
    #     "batch_jsonl": BASE_DIR / "data" / "batch_input" / "teleqna_batch.jsonl",
    #     "reference": BASE_DIR / "data" / "passages" / "reference" / "teleqna_ref.json",
    #     "final_output": BASE_DIR / "data" / "passages" / "generated" / "teleqna_passage.json"
    # }
    # "netbench": {
    #     "input": BASE_DIR / "data" / "original" / "netbench_original.json",
    #     "batch_jsonl": BASE_DIR / "data" / "batch_input" / "netbench_batch.jsonl",
    #     "reference": BASE_DIR / "data" / "passages" / "reference" / "netbench_ref.json"
    # },
    "netconfig": {
        "input": BASE_DIR / "data" / "original" / "Research_Institute_Internal_DC" / "netconfig.json",
        "batch_jsonl": BASE_DIR / "data" / "batch_input" / "netconfig_batch.jsonl",
        "reference": BASE_DIR / "data" / "passages" / "reference" / "netconfig_ref.json",
        "final_output": BASE_DIR / "data" / "passages" / "generated" / "netconfig_passage2.json",
        "config_dir": BASE_DIR / "data" / "original" / "Research_Institute_Internal_DC" / "configs"
    }
}

# 데이터 처리 함수들은 그대로 유지
def process_telequad_data(item):
    question = item.get('question', '')
    gold_answer = item.get('gold_answer', '')
    context = item.get('gold_context', '')
    return question, gold_answer, context 


def process_teleqna_data(item):
    question = item.get('question', '')
    gold_answer = item.get('answer', '')
    
    # 옵션 처리
    raw_options = {k: v for k, v in item.items() if k.startswith("option")}
    sorted_keys = sorted(
        raw_options.keys(), 
        key=lambda x: int(x.split()[-1]) if x.split()[-1].isdigit() else 999
    )
    options_list = [f"{key}: {raw_options[key]}" for key in sorted_keys]
    options_str = "\n".join(options_list)
    
    return question, gold_answer, context, options_str

def process_netbench_data(item):
    context = item.get('Context', '')
    question = item.get('Question', '')
    gold_answer = item.get('Answer', '')
    return question, context, gold_answer

def process_netconfig_data(item):
    question = item.get('question', '')
    gold_answer = item.get('answer', '')
    return question, gold_answer



def create_batch_files_and_run(dataset_key):
    api_key = load_api_key()
    if not api_key:
        print("API Key not found")
        return

    client = OpenAI(api_key=api_key)
    paths = DATA_PATHS.get(dataset_key)
    if not paths:
        print(f"Skipping {dataset_key}: No configuration found.")
        return
    
    # 1. 데이터 로드
    try:
        with open(paths['input'], 'r', encoding='utf-8') as f:
            raw_data = json.load(f)
            if dataset_key == 'netconfig':
                data_list = raw_data.get('questions', [])
                print("+++++++++++++++++++++++")
                print("data_list: ", data_list[:10])
                print("+++++++++++++++++++++++")
            elif isinstance(raw_data, dict):
                data_list = list(raw_data.values())
            else:
                data_list = raw_data
    except FileNotFoundError:
        print(f"File not found: {paths['input']}")
        return

    # Netconfig Context 로드
    netconfig_context = ""
    if dataset_key == 'netconfig':
        config_dir = paths.get('config_dir')
        if config_dir and os.path.exists(config_dir):
            configs = []
            files = sorted([f for f in os.listdir(config_dir) if f.endswith(".cfg")])
            for filename in files:
                file_path = os.path.join(config_dir, filename)
                with open(file_path, 'r', encoding='utf-8') as f:
                    content = f.read()
                    configs.append(f"--- File: {filename} ---\n{content}")
            netconfig_context = "\n\n".join(configs)
        else:
            print(f"Warning: Config directory not found.")
            return

    print(f"Creating Batch Input for '{dataset_key}' ({len(data_list)} items)...")
    
    batch_lines = []      # OpenAI로 보낼 JSONL 라인들
    reference_data = []   # 로컬에 저장할 질문/정답 원본 (매칭용)

    for idx, item in enumerate(data_list):
        # 데이터셋별 전처리
        if dataset_key == 'telequad':
            question, gold_answer, context = process_telequad_data(item)
            combined_input = f"Question: {question}\n\nContext: {context}"
        elif dataset_key == 'teleqna':
            question, gold_answer, options_str = process_teleqna_data(item)
            combined_input = f"Question: {question}\n\nOptions:\n{options_str}"
        elif dataset_key == 'netbench':
            question, context, gold_answer = process_netbench_data(item)
            combined_input = f"Scenario Context: {context}\n\nQuestion: {question}"
        elif dataset_key == 'netconfig':
            question, gold_answer = process_netconfig_data(item)
            combined_input = f"Network Configurations:\n{netconfig_context}\n\nQuestion: {question}"
        else:
            continue

        if not gold_answer:
            continue

        prompt_template = '''
        Your job is to act as a network management expert. You will write a good-quality concise passage that can answer the question based on your factual knowledge. If context is provided, you have to find the answer from the context. Do not write a passage if you don’t know accurate information about the question. Write [NONE] if you cannot write a factual good passage. 
{combined_input}
Passage:
'''
        system_content = prompt_template.replace("{combined_input}", combined_input)
        
        custom_id = f"{dataset_key}-{idx}"

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
        
        batch_lines.append(json.dumps(request_obj, ensure_ascii=False))

        # Debug print for the first item
        if idx == 0:
            print(f"[{dataset_key} First Item Verification]")
            print(f"Question: {question}")
            print(f"Gold Answer: {gold_answer}")
            print(f"Combined Context Length: {len(combined_input)}")

        if dataset_key == 'teleqna':
            reference_data.append({
            "custom_id": custom_id,
            "question": question,
            "gold_answer": gold_answer,
            "passage": None,
            "options": options_str
        })
        else:
            reference_data.append({
                "custom_id": custom_id,
                "question": question,
                "gold_answer": gold_answer,
                "passage": None  
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
        
        # Polling & Downloading
        print("Waiting for batch completion...")
        while True:
            batch_job = client.batches.retrieve(batch_job.id)
            print(f" - [{time.strftime('%H:%M:%S')}] Status: {batch_job.status}")
            
            if batch_job.status == "completed":
                break
            elif batch_job.status in ["failed", "cancelled", "expired"]:
                print(f"❌ Batch failed with status: {batch_job.status}")
                if batch_job.errors:
                    print(batch_job.errors)
                return
            
            time.sleep(10)

        if batch_job.output_file_id:
            print("Downloading output...")
            content = client.files.content(batch_job.output_file_id)
            
            # Define output path
            output_dir = BASE_DIR / "data" / "batch_output"
            os.makedirs(output_dir, exist_ok=True)
            output_file = output_dir / f"{dataset_key}_output.jsonl"
            
            with open(output_file, 'wb') as f:
                f.write(content.read())
            print(f"✅ Saved output to {output_file}")
            
            # Merge results automatically
            merge_batch_results(dataset_key)
        else:
            print("No output file ID found.")

    except Exception as e:
        print(f"❌ Error creating batch: {e}")

def merge_batch_results(dataset_key):
    paths = DATA_PATHS.get(dataset_key)
    output_dir = BASE_DIR / "data" / "batch_output"
    output_file = output_dir / f"{dataset_key}_output.jsonl"
    
    if not os.path.exists(output_file):
        print(f"Skipping merge: Output file not found for {dataset_key}")
        return

    print(f"Merging results for {dataset_key}...")
    
    # 1. Load Reference Data
    try:
        with open(paths['reference'], 'r', encoding='utf-8') as f:
            reference_data = json.load(f)
            # Create a map for quick lookup
            ref_map = {item['custom_id']: item for item in reference_data}
    except Exception as e:
        print(f"Error loading reference file: {e}")
        return

    # 2. Parse Batch Output
    with open(output_file, 'r', encoding='utf-8') as f:
        for line in f:
            try:
                res_item = json.loads(line)
                custom_id = res_item.get('custom_id')
                response_body = res_item.get('response', {}).get('body', {})
                
                if not custom_id or custom_id not in ref_map:
                    continue
                
                # Extract content
                choices = response_body.get('choices', [])
                if choices:
                    passage = choices[0]['message']['content']
                    ref_map[custom_id]['passage'] = passage
                else:
                    print(f"Warning: No choices found for {custom_id}")
                    
            except json.JSONDecodeError:
                continue

    # 3. Save Final JSON
    final_output_path = paths.get('final_output')
    if final_output_path:
        os.makedirs(os.path.dirname(final_output_path), exist_ok=True)
        
        # Convert map back to list (preserving original order if possible, or just values)
        # reference_data list already has the order, we updated the dict objects within it because they are mutable references? 
        # Yes, checking: ref_map values are references to objects in reference_data list.
        
        # We only want question, gold_answer, passage
        final_data = []
        for item in reference_data:
            final_data.append({
                "question": item['question'],
                "gold_answer": item['gold_answer'],
                "passage": item['passage']
            })

        with open(final_output_path, 'w', encoding='utf-8') as f:
            json.dump(final_data, f, ensure_ascii=False, indent=4)
        
        print(f"✅ Final merged file created: {final_output_path}")
    else:
        print("Final output path not defined.")


if __name__ == "__main__":
    DATA = ["telequad", "teleqna", "netbench", "netconfig"]
    for dataset_key in DATA:
        create_batch_files_and_run(dataset_key)