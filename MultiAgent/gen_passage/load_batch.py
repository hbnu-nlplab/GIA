import json
import os
import sys
from openai import OpenAI
from pathlib import Path

# 기존 설정 불러오기
from config.load_env import load_api_key

BASE_DIR = Path(__file__).resolve().parents[1]

# 이전에 정의했던 경로들 (참조 파일 로드용)
DATA_PATHS = {
    "telequad": {
        "reference": BASE_DIR / "data" / "passages" / "reference" / "telequad_ref.json",
        "final_output": BASE_DIR / "data" / "passages" / "full_w_context" / "telequad_passage.json"
    # },
    # "teleqna": {
    #     "reference": BASE_DIR / "data" / "passages" / "reference" / "teleqna_ref.json",
    #     "final_output": BASE_DIR / "data" / "passages" / "full" / "teleqna_passage.json"
    # },
    # "netbench": {
    #     "reference": BASE_DIR / "data" / "passages" / "reference" / "netbench_ref.json",
    #     "final_output": BASE_DIR / "data" / "passages" / "full" / "netbench_passage.json"
    # },
    # "netconfig": {
    #     "reference": BASE_DIR / "data" / "passages" / "reference" / "netconfig_ref.json",
    #     "final_output": BASE_DIR / "data" / "passages" / "full" / "netconfig_passage.json"
    }
}

def merge_results(dataset_key, batch_output_content):
    """
    OpenAI 결과(JSONL)와 로컬의 참조 파일(JSON)을 합치는 함수
    """
    paths = DATA_PATHS.get(dataset_key)
    if not paths or not os.path.exists(paths["reference"]):
        print(f"⚠️ Reference file not found for {dataset_key}. Cannot merge.")
        return

    # 1. 참조 파일 로드 (Question, Gold Answer가 있음)
    with open(paths["reference"], 'r', encoding='utf-8') as f:
        ref_data = json.load(f)
    
    # 검색 속도를 위해 custom_id를 키로 하는 딕셔너리로 변환
    ref_map = {item['custom_id']: item for item in ref_data}
    
    # 2. 배치 결과 파싱
    for line in batch_output_content.strip().split('\n'):
        if not line: continue
        
        res_json = json.loads(line)
        custom_id = res_json.get('custom_id')
        
        # 결과에서 Passage 추출
        try:
            passage = res_json['response']['body']['choices'][0]['message']['content']
        except (KeyError, TypeError):
            passage = "[ERROR: Generation Failed]"

        # 참조 데이터에 합치기
        if custom_id in ref_map:
            ref_map[custom_id]['passage'] = passage

    # 3. 최종 리스트 변환 (불필요한 custom_id 제거하고 원래 포맷대로)
    final_results = []
    for item in ref_data:
        final_results.append({
            "question": item['question'],
            "gold_answer": item['gold_answer'],
            "passage": item.get('passage', "[NONE]") # 혹시 매칭 안됐으면 NONE
        })

    # 4. 저장
    os.makedirs(os.path.dirname(paths["final_output"]), exist_ok=True)
    with open(paths["final_output"], 'w', encoding='utf-8') as f:
        json.dump(final_results, f, indent=4, ensure_ascii=False)
    
    print(f"✅ Merged & Saved: {paths['final_output']}")

def check_and_retrieve():
    api_key = load_api_key()
    client = OpenAI(api_key=api_key)

    print("🔍 Checking Batch Job Status (Last 10 jobs)...")
    
    batches = client.batches.list(limit=10)
    
    for batch in batches.data:
        status = batch.status
        batch_id = batch.id
        
        # === [수정된 부분] ===
        # metadata가 None이면 빈 딕셔너리처럼 취급하거나 기본값 설정
        if batch.metadata:
            description = batch.metadata.get("description", "No description")
        else:
            description = "No description"
        # ===================
        
        print(f"\n[Batch ID: {batch_id}]")
        print(f" - Status: {status}")
        print(f" - Desc: {description}")
        
        if status == 'completed' and batch.output_file_id:
            print(f" - Output File ID: {batch.output_file_id}")
            
            dataset_key = None
            for key in DATA_PATHS.keys():
                if key in description:
                    dataset_key = key
                    break
            
            if dataset_key:
                print(f"⬇️ Downloading results for '{dataset_key}'...")
                try:
                    file_response = client.files.content(batch.output_file_id)
                    content = file_response.text
                    merge_results(dataset_key, content)
                except Exception as e:
                    print(f"⚠️ Error downloading/merging: {e}")
            else:
                print("⚠️ Could not identify dataset from description. Skipping merge.")

        elif status == 'failed':
            print(f"❌ Failed. Error: {batch.errors}")
        
        elif status in ['in_progress', 'validating', 'finalizing']:
            print("⏳ Still processing... Check again later.")
            
            
if __name__ == "__main__":
    check_and_retrieve()