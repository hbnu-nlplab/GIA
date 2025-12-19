
import os
import json
import logging
import datetime
import sys
import gc
import pandas as pd
import numpy as np
import torch
from vllm import LLM, SamplingParams
from evaluate import load as load_metric

# === Configuration ===
class Config:
    BASE_DIR = os.path.dirname(os.path.abspath(__file__))
    DATA_DIR = os.path.join(BASE_DIR, "data")
    LOG_DIR = os.path.join(BASE_DIR, "logs")
    RESULT_DIR = os.path.join(BASE_DIR, "results")
    
    # Model Dictionary (AWQ optimized)
    MODEL_DICT = {
        "Llama4-8B": "hugging-quants/Meta-Llama-3.1-8B-Instruct-AWQ-INT4",
        "Gemma3-7B": "hugging-quants/gemma-2-9b-it-AWQ-INT4",
        "Mistral3-8B": "slinpkh/Mistral-7B-Instruct-v0.3-AWQ",
        "Qwen3-8B": "Qwen/Qwen2.5-7B-Instruct-AWQ",
        "GPT-OSS-20B": "Qwen/Qwen2.5-14B-Instruct-AWQ"
    }

    # Data Paths
    DATA_PATHS = {
        "telequad": os.path.join(DATA_DIR, "TeleQuAD", "TeleQuAD-v4-full.json"),
        "teleqna": os.path.join(DATA_DIR, "TeleQnA", "TeleQnA.json"),
        "netbench": os.path.join(DATA_DIR, "NetBench", "T-NetEval.csv")
    }

# === Logger ===
def setup_logger():
    os.makedirs(Config.LOG_DIR, exist_ok=True)
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    log_file = os.path.join(Config.LOG_DIR, f"eval_log_{timestamp}.txt")
    
    logger = logging.getLogger("NetEval")
    logger.setLevel(logging.INFO)
    logger.handlers = []
    
    fh = logging.FileHandler(log_file)
    fh.setFormatter(logging.Formatter('%(asctime)s | %(levelname)s | %(message)s'))
    logger.addHandler(fh)
    
    sh = logging.StreamHandler(sys.stdout)
    sh.setFormatter(logging.Formatter('%(asctime)s | %(message)s'))
    logger.addHandler(sh)
    
    return logger

logger = setup_logger()

# === Prompt Manager ===
class PromptManager:
    @staticmethod
    def get_system_prompt(dataset_name):
        if dataset_name == "teleqna":
            return (
                "You are a telecommunications expert taking a multiple-choice exam. "
                "Read the question and options carefully. "
                "You must select the best option. "
                "CRITICAL: Application of strict output format is required. "
                "Format your final answer as: 'Final Answer: Option X' where X is the option number."
            )
        elif dataset_name == "netbench":
            return (
                "You are a Senior Network Engineer (SME). "
                "You will be given a network scenario and a question. "
                "Answer the question using ONLY the provided context and your expert knowledge. "
                "Provide a logical reasoning followed by a concise answer."
            )
        elif dataset_name == "telequad":
            return (
                "You are a strict Reading Comprehension AI. "
                "Your task is to answer the question using ONLY the information found in the provided Context. "
                "Do not use outside knowledge. Answer as concisely as possible."
            )
        return "You are a helpful assistant."

    @staticmethod
    def build_user_prompt(dataset_name, item):
        if dataset_name == "teleqna":
            return (
                f"Question: {item['question']}\n\n"
                f"{item['context']}\n\n"
                "Select the correct option. Provide a brief explanation, then end with 'Final Answer: Option X'."
            )
        elif dataset_name == "netbench":
            return (
                f"Context:\n{item['context']}\n\n"
                f"Question:\n{item['question']}\n\n"
                "Answer:"
            )
        else:
            return (
                f"Context:\n{item['context']}\n\n"
                f"Question:\n{item['question']}\n\n"
                "Answer:"
            )

# === Response Parser ===
import re
def parse_response(dataset_name, response):
    """
    Parses the raw model output to extract a clean answer for metrics.
    """
    response = response.strip()
    
    if dataset_name == "teleqna":
        # Extract "Option X" or "option X"
        match = re.search(r"Final Answer:\s*Option\s*(\d+)", response, re.IGNORECASE)
        if match:
            return f"option {match.group(1)}"
        
        # Fallback: Look for "Option X" at the start
        match = re.search(r"^Option\s*(\d+)", response, re.IGNORECASE)
        if match:
            return f"option {match.group(1)}"
            
        return response # Return full text if parse fails (will likely get low score)
        
    return response

# === Data Loader ===
def load_dataset_normalized(name, path):
    if not os.path.exists(path):
        logger.warning(f"File not found: {path}")
        return []
    
    data_list = []
    try:
        if name == "netbench":
            # Load CSV
            df = pd.read_csv(path)
            for _, row in df.iterrows():
                data_list.append({
                    "question": str(row.get("Question", "")),
                    "context": str(row.get("Context", "")),
                    "gold": str(row.get("Answer", "")),
                    "id": str(row.get("Scenario_ID", ""))
                })
        
        elif name == "teleqna":
            # Load JSON
            with open(path, "r", encoding="utf-8") as f:
                raw = json.load(f)
            # Handle dictionary of questions
            iterator = raw.values() if isinstance(raw, dict) else raw
            for item in iterator:
                if "question" not in item: continue
                # Format options
                options = {k: v for k, v in item.items() if k.startswith("option")}
                # Sorted keys to ensure Order 1, 2, 3...
                sorted_keys = sorted(options.keys(), key=lambda x: int(x.split()[-1]) if x.split()[-1].isdigit() else 99)
                options_str = "\n".join([f"{k.capitalize()}: {options[k]}" for k in sorted_keys])
                
                data_list.append({
                    "question": item["question"],
                    "context": f"Options:\n{options_str}",
                    "gold": str(item.get("answer", "")).lower(), # gold format: "option 2: ..."
                })

        elif name == "telequad":
            with open(path, "r", encoding="utf-8") as f:
                raw = json.load(f)
            for doc in raw.get("data", []):
                for para in doc.get("paragraphs", []):
                    context = para.get("context", "")
                    for qa in para.get("qas", []):
                        data_list.append({
                            "question": qa["question"],
                            "context": context,
                            "gold": qa["answers"][0]["text"] if qa["answers"] else ""
                        })

        logger.info(f"[{name}] Loaded {len(data_list)} items from {path}")
        return data_list

    except Exception as e:
        logger.error(f"Error loading {name}: {e}")
        return []

# === Evaluator ===
class Evaluator:
    def __init__(self):
        self.bert_metric = None
        self.rouge_metric = None

    def load_metrics(self):
        if self.bert_metric is None:
            logger.info("Loading BERTScore & ROUGE...")
            self.bert_metric = load_metric("bertscore")
            self.rouge_metric = load_metric("rouge")

    def compute_exact_match(self, pred, gold):
        return 1.0 if normalize_answer(pred) == normalize_answer(gold) else 0.0

    def compute_f1(self, pred, gold):
        pred_toks = normalize_answer(pred).split()
        gold_toks = normalize_answer(gold).split()
        common = set(pred_toks) & set(gold_toks)
        if not common: return 0.0
        prec = len(common) / len(pred_toks)
        rec = len(common) / len(gold_toks)
        return 2 * (prec * rec) / (prec + rec + 1e-9)

    def evaluate_batch(self, preds, refs, dataset_name):
        # 1. TeleQnA: Accuracy only (MCQ)
        if dataset_name == "teleqna":
            correct = 0
            for p, r in zip(preds, refs):
                if p.lower() in r.lower().split(":")[0]: 
                    correct += 1
            return {"Accuracy": (correct / len(preds)) * 100}
            
        # 2. Others: ROUGE, BERTScore, F1, EM
        self.load_metrics()
        
        # Exact Match & F1 (Token overlap)
        em_scores = [self.compute_exact_match(p, r) for p, r in zip(preds, refs)]
        f1_scores = [self.compute_f1(p, r) for p, r in zip(preds, refs)]
        
        scores = {
            "EM": np.mean(em_scores) * 100,
            "F1": np.mean(f1_scores) * 100
        }
        
        # ROUGE
        try:
            rouge_res = self.rouge_metric.compute(predictions=preds, references=refs)
            scores["ROUGE-L"] = rouge_res["rougeL"].mid.fmeasure * 100
        except Exception as e:
            logger.warning(f"ROUGE error: {e}")
            
        # BERTScore (Semantic)
        try:
            bert_res = self.bert_metric.compute(predictions=preds, references=refs, lang="en")
            scores["BERTScore"] = np.mean(bert_res['f1']) * 100
        except Exception as e:
            logger.warning(f"BERTScore error: {e}")
            
        return scores

def normalize_answer(s):
    import string, re
    def remove_articles(text):
        return re.sub(r'\b(a|an|the)\b', ' ', text)
    def white_space_fix(text):
        return ' '.join(text.split())
    def remove_punc(text):
        exclude = set(string.punctuation)
        return ''.join(ch for ch in text if ch not in exclude)
    def lower(text):
        return text.lower()
    return white_space_fix(remove_articles(remove_punc(lower(str(s)))))

# === Main Execution ===
def main():
    # 1. Load Data
    all_datasets = {}
    for name, path in Config.DATA_PATHS.items():
        d = load_dataset_normalized(name, path)
        if d: all_datasets[name] = d

    # 2. Iterate Models
    for model_alias, model_path in Config.MODEL_DICT.items():
        logger.info(f"=== Evaluation: {model_alias} ===")
        
        res_dir = os.path.join(Config.RESULT_DIR, model_alias)
        os.makedirs(res_dir, exist_ok=True)
        
        # Check pending
        pending = [n for n in all_datasets if not os.path.exists(os.path.join(res_dir, f"{n}.json"))]
        if not pending:
            logger.info(f"Skipping {model_alias} (Already done).")
            continue

        # Load LLM
        try:
            logger.info(f"Loading vLLM: {model_path}")
            llm = LLM(
                model=model_path,
                quantization="awq",
                dtype="float16",
                trust_remote_code=True,
                gpu_memory_utilization=0.9,
                max_model_len=4096,
                tensor_parallel_size=1
            )
            tokenizer = llm.get_tokenizer()
            sampling = SamplingParams(temperature=0, max_tokens=512)
            
            for ds_name in pending:
                items = all_datasets[ds_name]
                logger.info(f"Processing {ds_name} ({len(items)} items)...")
                
                prompts = []
                for item in items:
                    msgs = [
                        {"role": "system", "content": PromptManager.get_system_prompt(ds_name)},
                        {"role": "user", "content": PromptManager.build_user_prompt(ds_name, item)}
                    ]
                    prompts.append(tokenizer.apply_chat_template(msgs, tokenize=False, add_generation_prompt=True))
                
                outputs = llm.generate(prompts, sampling)
                
                results = []
                preds = []
                refs = []
                
                for i, out in enumerate(outputs):
                    raw_answer = out.outputs[0].text.strip()
                    parsed_answer = parse_response(ds_name, raw_answer)
                    
                    results.append({
                        "question": items[i]["question"],
                        "gold": items[i]["gold"],
                        "model_answer_raw": raw_answer,
                        "model_answer_parsed": parsed_answer,
                        "context": items[i].get("context", "")
                    })
                    preds.append(parsed_answer)
                    refs.append(items[i]["gold"])
                
                # Compute Metrics immediately
                metrics = evaluator.evaluate_batch(preds, refs, ds_name)
                logger.info(f"[{ds_name}] Results: {metrics}")
                
                # Save Raw + Metrics
                save_path = os.path.join(res_dir, f"{ds_name}.json")
                with open(save_path, "w", encoding="utf-8") as f:
                    final_out = {"metrics": metrics, "data": results}
                    json.dump(final_out, f, indent=2, ensure_ascii=False)
                logger.info(f"Saved {save_path}")

            # Clean up VLLM
            from vllm.model_executor.parallel_utils.parallel_state import destroy_model_parallel
            destroy_model_parallel()
            del llm
            gc.collect()
            torch.cuda.empty_cache()

        except Exception as e:
            logger.error(f"Failed {model_alias}: {e}")

    # 3. Final Aggregation
    # (Simplified: Results are already printed/saved)
    
if __name__ == "__main__":
    main()
