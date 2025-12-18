import os
import json
import torch
from tqdm import tqdm
from transformers import AutoModelForCausalLM, AutoTokenizer

MODEL_NAME = "Qwen/Qwen2.5-3B-Instruct"

BATCH_SIZE = 4
MAX_INPUT_TOKENS = 4096
MAX_NEW_TOKENS = 128

OUTPUT_DIR = "../data/qwen_answer"


def load_telequad(raw_path):
    with open(raw_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    qna_list = []
    for doc in data.get("data", []):
        for para in doc.get("paragraphs", []):
            context = para.get("context", "")
            for qa in para.get("qas", []):
                gold = qa.get("answers", [{}])[0].get("text", "")
                if not gold.strip():
                    continue

                qna_list.append({
                    "type": "telequad",
                    "question": qa.get("question", ""),
                    "context": context,
                    "gold_answer": gold
                })
    return qna_list


def load_teleqna(raw_path):
    with open(raw_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    qna_list = []
    iterator = data.values() if isinstance(data, dict) else data

    for item in iterator:
        if not isinstance(item, dict) or "question" not in item:
            continue

        question = item.get("question", "")
        gold_answer = item.get("answer", "")

        raw_options = {k: v for k, v in item.items() if k.startswith("option")}
        sorted_keys = sorted(
            raw_options.keys(),
            key=lambda x: int(x.split()[-1]) if x.split()[-1].isdigit() else 999
        )

        options = "\n".join([f"{k}: {raw_options[k]}" for k in sorted_keys])

        qna_list.append({
            "type": "teleqna",
            "question": question,
            "options": options,
            "gold_answer": gold_answer
        })

    return qna_list


def load_netbench(raw_path):
    with open(raw_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    qna_list = []
    for item in data:
        qna_list.append({
            "type": "netbench",
            "question": item.get("Question", ""),
            "context": item.get("Context", ""),
            "gold_answer": item.get("Answer", "")
        })

    return qna_list


def build_prompt(item):
    if item["type"] in ["telequad"]:
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
{item["context"]}

### Question
{item["question"]}

Answer:
"""
    if item["type"] in ["netbench"]:
        return f"""### Role
You are a Senior Network Specification Engineer. Your task is to extract technical parameters from the provided text with extreme precision.

### Rules
1. **Source of Truth:** Base your answer on the provided context.
2. **Format:** Output raw technical values, units, or states. Do not use full sentences.

### Examples
Context: "BGP Policy: Requirement is to prevent transit AS functionality for AS65000. Routes learned from Peer ISP_A should not be advertised to Peer ISP_B."
Question: "What common BGP filtering technique is used on AS65000's routers to prevent advertising routes learned from ISP_A to ISP_B?
Answer: "A common technique is using an AS_PATH filter list or route map. On the outbound policy towards ISP_B, implement a filter that denies any route whose AS_PATH contains the ASN of ISP_A. This prevents AS65000 from becoming a transit AS between ISP_A and ISP_B."

### Context
{item["context"]}

### Question
{item["question"]}

Answer:
"""
    else:  # teleqna
        return f"""### Role
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
{item["question"]}

### Options
{item["options"]}

Answer:
"""


def run_single_dataset(qna_list, output_path):
    os.makedirs(os.path.dirname(output_path), exist_ok=True)

    tokenizer = AutoTokenizer.from_pretrained(
        MODEL_NAME,
        padding_side="left"
    )
    tokenizer.pad_token = tokenizer.eos_token

    model = AutoModelForCausalLM.from_pretrained(
        MODEL_NAME,
        torch_dtype="auto",
        device_map="auto"
    )
    model.eval()

    results = []

    for i in tqdm(range(0, len(qna_list), BATCH_SIZE)):
        batch = qna_list[i:i + BATCH_SIZE]
        prompts = [build_prompt(item) for item in batch]

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

        answers = tokenizer.batch_decode(
            outputs[:, inputs.input_ids.shape[1]:],
            skip_special_tokens=True
        )

        for item, ans in zip(batch, answers):
            results.append({
                "question": item["question"],
                "gold_answer": item["gold_answer"],
                "model_answer": ans.strip()
            })

        torch.cuda.empty_cache()

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(results, f, ensure_ascii=False, indent=2)

    print(f"[+] 생성 완료: {output_path} ({len(results)}개)")



if __name__ == "__main__":
    telequad = load_telequad("../data/telequad/TeleQuAD-v4-full.json")
    teleqna = load_teleqna("../data/teleQnA/TeleQnA.json")
    netbench = load_netbench("../data/netbench/netbench.json")

    run_single_dataset(
        telequad,
        os.path.join(OUTPUT_DIR, "telequad.json")
    )

    run_single_dataset(
        teleqna,
        os.path.join(OUTPUT_DIR, "teleqna.json")
    )

    run_single_dataset(
        netbench,
        os.path.join(OUTPUT_DIR, "netbench.json")
    )