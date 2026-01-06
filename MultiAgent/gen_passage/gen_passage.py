
import json
import sys
import os
import re
from openai import OpenAI
from pathlib import Path

from config.load_env import load_api_key

TARGET_DATASET = "netconfig"
BASE_DIR = Path(__file__).resolve().parents[1] 

DATA_PATHS = {
    "telequad": {
        "input": BASE_DIR / "data" / "original" / "telequad.json",
        "output": BASE_DIR / "data" / "passages" / "test3" / "telequad_passage.json"
    },
    "teleqna": {
        "input": BASE_DIR / "data" / "original" / "teleqna.json",
        "output": BASE_DIR / "data" / "passages" / "test3" / "teleqna_passage.json"
    },
    "netbench": {
        "input": BASE_DIR / "data" / "original" / "netbench_original.json",
        "output": BASE_DIR / "data" / "passages" / "test3" / "netbench_passage.json"
    },
    "netconfig": {
        "input": BASE_DIR / "data" / "original" / "qa_dataset.json",
        "output": BASE_DIR / "data" / "passages" / "test3" / "netconfig_passage.json",
        "context_file": BASE_DIR / "data" / "original" / "netconfig_context.txt"
    }
}


# 데이터에서 필요한 정보 가져오기
def process_tele_data(item):
    """TeleQuAD 및 TeleQnA용: 질문만 추출"""
    question = item.get('question', '')
    gold_answer = item.get('gold_answer', '')
    
    return question, gold_answer 

def process_netbench_data(item):
    """NetBench용: Context + Question 결합"""
    context = item.get('Context', '')
    question = item.get('Question', '')
    gold_answer = item.get('Answer', '')

    return question, context, gold_answer

def process_netconfig_data(item):
    """NetConfigQA용: XML 로드 및 최적화 + Question 결합"""
    question = item.get('question', '')
    gold_answer = item.get('ground_truth', '')
    
    return question, gold_answer



# passage 생성
def gen_paragraph(dataset_key):
    api_key = load_api_key()
    if not api_key:
        print("API Key not found")
        return

    client = OpenAI(api_key=api_key)
    
    paths = DATA_PATHS.get(dataset_key)
    if not paths:
        print(f"Dataset key '{dataset_key}' error.")
        return

    try:
        with open(paths['input'], 'r', encoding='utf-8') as f:
            data_list = json.load(f)
    except FileNotFoundError:
        print(f"File not found: {paths['input']}")
        return

    netconfig_context = ""
    if dataset_key == 'netconfig':
        context_file = paths.get('context_file')
        if os.path.exists(context_file):
            with open(context_file, 'r', encoding='utf-8') as f:
                netconfig_context = f.read()
            print(f"Loaded context from {context_file} ({len(netconfig_context)} chars)")
        else:
            print(f"Warning: Context file not found at {context_file}. Run merge_xml.py first.")
            return
    # print(f"Netconfig context: {netconfig_context}")
    print(f"Processing '{dataset_key}' ({len(data_list)} items)...")
    results = []

    for item in data_list[:10]:
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
            print("Unknown dataset type")
            break

        if not gold_answer:
            continue

        prompt_template = '''
        Your job is to act as a network management expert. You will write a good-quality concise passage that can answer the question based on your factual knowledge. If context is provided, you can write a passage based on it. Do not write a passage if you don’t know accurate information about the question.
Now, let's start. Write [NONE] if you cannot write a factual good passage. 
{combined_input}
Passage:
'''
        
        system_content = prompt_template.replace("{combined_input}", combined_input)

        try:
            completion = client.chat.completions.create(
                model="gpt-4o-mini",
                messages=[
                    {"role": "system", "content": system_content},
                    {"role": "user", "content": "Write the passage."}
                ],
                max_tokens=250,
                temperature=0.0
            )
            
            passage = completion.choices[0].message.content
            
            result_item = {
                "question": question,
                "gold_answer": gold_answer,
                "passage": passage
            }
            
            results.append(result_item)
            
        except Exception as e:
            print(f"Error: {e}")
            continue

    output_path = DATA_PATHS[dataset_key]["output"]
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    with open(output_path, 'w', encoding='utf-8') as f:
        json.dump(results, f, ensure_ascii=False, indent=4)
    print(f"Done. Saved to {output_path}")

if __name__ == "__main__":
    gen_paragraph(TARGET_DATASET)