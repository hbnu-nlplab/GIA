import os
import json
import time
from dotenv import load_dotenv
from openai import OpenAI

RAW_DATA_PATH = "../data/telequad/TeleQuAD-v4-full.json"
DATA_PATH = "../data/llm_answer_revised/"
FINAL_JSON = os.path.join(DATA_PATH, "llm_answer_gpt5.json")

# 여기 아래에 모델들 넣으면 됨
MODELS = ["gpt-5"]

load_dotenv("openai_key.env")
client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))


# 데이터셋에서 question과 answer 가져오는 함수
def load_qna():
    with open(RAW_DATA_PATH, "r", encoding="utf-8") as f:
        data = json.load(f)

    qna_list = []
    for doc in data.get("data", []):
        for para in doc.get("paragraphs", []):
            context = para.get("context", "")
            for qa in para.get("qas", []):
                question = qa.get("question", "")
                gold_answer = qa.get("answers", [{}])[0].get("text", "")
                if not gold_answer.strip():
                    continue
                qna_list.append({"question": question, "gold_answer": gold_answer, "context": context})
    return qna_list


# 배치로 돌릴 jsonl 만드는 함수
def create_input_jsonl(qna_list, model):
    os.makedirs(DATA_PATH, exist_ok=True)
    input_jsonl_path = os.path.join(DATA_PATH, f"input_{model}.jsonl")
    PROMPT_TEMPLATE = PROMPT_TEMPLATE = """
### Role
You are a Senior Network Specification Engineer. Your task is to extract technical parameters from the provided text with extreme precision.

### Rules
1. **Source of Truth:** Base your answer on the provided context.
2. **Format:** Output raw technical values, units, or states. Do not use full sentences.
4. **Brevity:** Use standard abbreviations to keep the answer under 50 characters equivalent.

### Examples
Context: "For the PDSCH, the maximum throughput is 100 Mbps in Downlink when using 64QAM."
Question: "What is the max DL throughput?"
Answer: "100 Mbps (64QAM)"

Context: "The subcarrier spacing can be 15 kHz for normal cyclic prefix and 30 kHz is supported for extended cyclic prefix cases."
Question: "What is the SCS?"
Answer: "Normal: 15kHz, Ext: 30kHz"

---
### Context
{context}

### Question
{question}

Answer:
"""

    # gpt 5 모델은 temperature 0이 안되어서 1로 설정
    with open(input_jsonl_path, "w", encoding="utf-8") as f:
        for idx, item in enumerate(qna_list):
            prompt = PROMPT_TEMPLATE.format(question=item["question"], context=item['context'])
            entry = {
                "custom_id": f"{idx}",
                "method": "POST",
                "url": "/v1/chat/completions",
                "body": {
                    "model": model,
                    "messages": [{"role": "user", "content": prompt}],
                    "temperature": 1 
                }
            }
            f.write(json.dumps(entry, ensure_ascii=False) + "\n")
    return input_jsonl_path


# 배치로 돌리기
def run_batch(input_jsonl_path):
    batch_input_file = client.files.create(
        file=open(input_jsonl_path, "rb"),
        purpose="batch"
    )

    batch = client.batches.create(
        input_file_id=batch_input_file.id,
        endpoint="/v1/chat/completions",
        completion_window="24h"
    )
    print(f"[+] 배치 생성 완료: {batch.id}")

    while True:
        batch = client.batches.retrieve(batch.id)
        print(f" - 현재 상태: {batch.status}")
        if batch.status in ["completed", "failed", "cancelled", "expired"]:
            return batch
        time.sleep(20)



# 배치 결과 jsonl 가져오기
def download_output(batch, model):
    if not batch.output_file_id:
        print(f"[!] {model} 배치 실패: output_file_id 없음. 건너뜁니다.")
        return None
    content = client.files.content(batch.output_file_id)
    output_jsonl_path = os.path.join(DATA_PATH, f"output_{model}.jsonl")
    with open(output_jsonl_path, "wb") as f:
        f.write(content.read())
    print(f"[+] {model} output.jsonl 다운로드 완료:", output_jsonl_path)
    return output_jsonl_path



# 여러 모델의 output jsonl을 하나의 json으로 병합
def merge_outputs(qna_list, models):
    final = []
    model_outputs = {model: {} for model in models}

    for model in models:
        output_jsonl_path = os.path.join(DATA_PATH, f"output_{model}.jsonl")
        with open(output_jsonl_path, "r", encoding="utf-8") as f:
            for line in f:
                item = json.loads(line)
                idx = item["custom_id"]
                response_text = item["response"]["body"]["choices"][0]["message"]["content"]
                model_outputs[model][idx] = response_text

    for idx, qa in enumerate(qna_list):
        entry = {
            "question": qa["question"],
            "gold_answer": qa["gold_answer"]
        }
        for model in models:
            entry[model] = model_outputs[model].get(str(idx), "")
        final.append(entry)

    with open(FINAL_JSON, "w", encoding="utf-8") as f:
        json.dump(final, f, ensure_ascii=False, indent=2)
    print("[+] 최종 llm_answer.json 생성 완료:", FINAL_JSON)




if __name__ == "__main__":
    qna_list = load_qna()

    for model in MODELS:
        input_path = create_input_jsonl(qna_list, model)
        batch = run_batch(input_path)
        if batch.status == "completed":
            download_output(batch, model)
        else:
            print(f"[!] {model} 배치 실패 상태: {batch.status}")

    merge_outputs(qna_list, MODELS)
    print("[+] 전체 파이프라인 완료")

