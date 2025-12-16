import json
import torch
from transformers import AutoModelForCausalLM, AutoTokenizer
from tqdm import tqdm

model_name = "Qwen/Qwen3-32B"

RAW_DATA_PATH = "../data/telequad/TeleQuAD-v4-full.json"
FINAL_JSON = "../data/qwen_answer.json"

BATCH_SIZE = 4   
MAX_INPUT_TOKENS = 4096
MAX_NEW_TOKENS = 128


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
                qna_list.append({
                    "question": question,
                    "gold_answer": gold_answer,
                    "context": context
                })
    return qna_list


def build_prompt(context, question):
    return f"""### Role
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


def qwen_answer(qna_list):
    tokenizer = AutoTokenizer.from_pretrained(
        model_name,
        padding_side="left"
    )
    tokenizer.pad_token = tokenizer.eos_token

    model = AutoModelForCausalLM.from_pretrained(
        model_name,
        torch_dtype="auto",
        device_map="auto"
    )
    model.eval()

    results = []

    for i in tqdm(range(0, len(qna_list), BATCH_SIZE)):
        batch = qna_list[i:i + BATCH_SIZE]

        prompts = [
            build_prompt(item["context"], item["question"])
            for item in batch
        ]

        inputs = tokenizer(
            prompts,
            return_tensors="pt",
            padding=True,
            truncation=True,
            max_length=MAX_INPUT_TOKENS
        ).to(model.device)

        with torch.inference_mode():
            outputs = model.generate(
                **inputs,
                max_new_tokens=MAX_NEW_TOKENS,
                do_sample=False,
                use_cache=True
            )

        decoded = tokenizer.batch_decode(
            outputs[:, inputs.input_ids.shape[1]:],
            skip_special_tokens=True
        )

        for item, answer in zip(batch, decoded):
            results.append({
                "question": item["question"],
                "gold_answer": item["gold_answer"],
                "qwen_answer": answer.strip()
            })

        torch.cuda.empty_cache()

    with open(FINAL_JSON, "w", encoding="utf-8") as f:
        json.dump(results, f, ensure_ascii=False, indent=2)

    print(f"[+] 생성 완료: {FINAL_JSON} (총 {len(results)}개)")


if __name__ == "__main__":
    qna_list = load_qna()
    qwen_answer(qna_list)