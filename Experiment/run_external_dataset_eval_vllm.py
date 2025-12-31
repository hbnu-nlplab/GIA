
import os
import json
import logging
import datetime
import sys
import gc
import time
import pandas as pd
import torch
import warnings
from vllm import LLM, SamplingParams

# Suppress Mistral tokenizer warnings
warnings.filterwarnings("ignore", message=".*apply_chat_template.*")
warnings.filterwarnings("ignore", message=".*tokenize=False.*")
warnings.filterwarnings("ignore", category=UserWarning, module="transformers")

# Hugging Face Authentication
try:
    from huggingface_hub import login
    hf_token = os.getenv("HF_TOKEN")
    if hf_token:
        login(token=hf_token)
        print(f"✅ Logged in to Hugging Face with token")
    else:
        print("⚠️ HF_TOKEN not found. Proceeding without authentication.")
except ImportError:
    print("⚠️ huggingface_hub not installed. Run: pip install huggingface_hub")
except Exception as e:
    print(f"⚠️ HF authentication error: {e}")

# === Configuration ===
class Config:
    BASE_DIR = os.path.dirname(os.path.abspath(__file__))
    DATA_DIR = os.path.join(BASE_DIR, "data")
    LOG_DIR = os.path.join(BASE_DIR, "logs")
    RESULT_DIR = os.path.join(BASE_DIR, "results")
    
    # Model Dictionary
    MODEL_DICT = {
        "Mistral3-8B": "mistralai/Ministral-3-8B-Instruct-2512",
        "Qwen3-8B": "Qwen/Qwen3-8B",
        "GPT-OSS-20B": "openai/gpt-oss-20b",
        "LLlama-3.1": "meta-llama/Meta-Llama-3.1-8B-Instruct",
    }

    # Data Paths
    DATA_PATHS = {
        "telequad": os.path.join(DATA_DIR, "telequad", "TeleQuAD-v4-full.json"),
        "teleqna": os.path.join(DATA_DIR, "teleQnA", "TeleQnA.json"),
        "netbench": os.path.join(DATA_DIR, "NetBench", "T-NetEval.csv"), 
    }

# === Logger ===
def setup_logger():
    os.makedirs(Config.LOG_DIR, exist_ok=True)
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    log_file = os.path.join(Config.LOG_DIR, f"inference_log_{timestamp}.txt")
    
    logger = logging.getLogger("NetEval_Inference")
    logger.setLevel(logging.INFO)
    logger.handlers = []
    
    fh = logging.FileHandler(log_file)
    fh.setFormatter(logging.Formatter('%(asctime)s | %(levelname)s | %(message)s'))
    logger.addHandler(fh)
    
    sh = logging.StreamHandler(sys.stdout)
    sh.setFormatter(logging.Formatter('%(message)s'))
    logger.addHandler(sh)
    
    return logger

logger = setup_logger()

def print_separator(char="=", length=80):
    logger.info(char * length)

def print_subseparator(char="-", length=80):
    logger.info(char * length)

# === Prompt Manager ===
class PromptManager:
    @staticmethod
    def get_system_prompt(dataset_name):
        if dataset_name == "teleqna":
            return """### Role
You are a Senior Network Specification Engineer. Your task is to select the correct answer based on your expert knowledge of network standards and theory.
 
### Rules
1. **Knowledge Base:** Use your internal knowledge to identify the correct option. Pay close attention to the specific standard version mentioned (e.g., [3GPP Release 18]).
2. **Format:** Output the answer as "option [num]: [Content]"."""
        elif dataset_name == "telequad":
            return """### Role
You are a Senior Network Specification Engineer. Your task is to extract technical parameters from the provided text with extreme precision.
 
### Rules
1. **Source of Truth:** Base your answer on the provided context.
2. **Format:** Output raw technical values, units, or states.
4. **Brevity:** Use standard abbreviations to keep the answer under 50 characters equivalent."""
        elif dataset_name == "netbench":
            return """### Task
Answer the Question by producing an output that matches the format and structure implied by the Context and Question.
 
### Rules
- Base the answer on the Context.
- Preserve the expected output format:
  - If the answer is a configuration, output the full configuration (e.g., YAML or JSON).
  - If the answer is structured data, return it as structured data.
  - If the answer is a definition, respond in clear sentences.
- Do not summarize or paraphrase configurations."""
        return "You are a helpful assistant."

    @staticmethod
    def build_user_prompt(dataset_name, item):
        if dataset_name == "teleqna":
            options = item['context'].replace("Options:\n", "").strip()
            return f"""---
### Question
{item['question']}
 
### Options
{options}
 
Answer:"""
        elif dataset_name == "telequad":
            return f"""### Examples
Context: "For the PDSCH, the maximum throughput is 100 Mbps in Downlink when using 64QAM."
Question: "What is the max DL throughput?"
Answer: "100 Mbps (64QAM)"
---
### Context
{item['context']}
 
### Question
{item['question']}
 
Answer:"""
        else: # netbench
            return f"""---
Context:
{item['context']}
 
Question:
{item['question']}
 
Answer:"""

# === Data Loader ===
def load_dataset_normalized(name, path):
    if not os.path.exists(path):
        logger.warning(f"File not found: {path}")
        return []
    
    data_list = []
    try:
        if name == "netbench":
            df = pd.read_csv(path)
            for _, row in df.iterrows():
                data_list.append({
                    "question": str(row.get("Question", "")),
                    "context": str(row.get("Context", "")),
                    "gold": str(row.get("Answer", "")),
                    "id": str(row.get("Scenario_ID", ""))
                })
        
        elif name == "teleqna":
            with open(path, "r", encoding="utf-8") as f:
                raw = json.load(f)
            iterator = raw.values() if isinstance(raw, dict) else raw
            for item in iterator:
                if "question" not in item: continue
                options = {k: v for k, v in item.items() if k.startswith("option")}
                sorted_keys = sorted(options.keys(), key=lambda x: int(x.split()[-1]) if x.split()[-1].isdigit() else 99)
                options_str = "\n".join([f"{k.capitalize()}: {options[k]}" for k in sorted_keys])
                
                context = f"Options:\n{options_str}"

                data_list.append({
                    "question": item["question"],
                    "context": context,
                    "gold": str(item.get("answer", "")).lower(),
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

# === Main Execution ===
import argparse

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--debug", action="store_true", help="Run in debug mode (no GPU, mock responses)")
    parser.add_argument("--model", type=str, help="Specific model to run (optional)")
    args = parser.parse_args()
    
    # 1. Load Data
    all_datasets = {}
    for name, path in Config.DATA_PATHS.items():
        d = load_dataset_normalized(name, path)
        if d: 
            all_datasets[name] = d
            if args.debug:
                all_datasets[name] = d[:2]

    # 2. Filter Models
    models_to_run = Config.MODEL_DICT
    if args.model:
        if args.model in Config.MODEL_DICT:
            models_to_run = {args.model: Config.MODEL_DICT[args.model]}
        else:
            logger.error(f"Model {args.model} not found in MODEL_DICT")
            return

    # 3. Iterate Models
    for model_alias, model_path in models_to_run.items():
        print_separator("=", 80)
        logger.info(f"\n🚀 Starting Inference: {model_alias}")
        logger.info(f"   Model Path: {model_path}")
        print_separator("=", 80)
        
        pending_datasets = []
        for ds_name in all_datasets:
            ds_result_dir = os.path.join(Config.RESULT_DIR, ds_name)
            os.makedirs(ds_result_dir, exist_ok=True)
            res_file = os.path.join(ds_result_dir, f"{model_alias}.json")
            if not os.path.exists(res_file):
                pending_datasets.append(ds_name)
        
        if not pending_datasets and not args.debug:
            logger.info(f"\n✅ All datasets completed for {model_alias}. Skipping...\n")
            continue
        
        if pending_datasets:
            logger.info(f"\n📋 Pending datasets: {', '.join(pending_datasets)}")

        llm = None
        sampling = None
        tokenizer = None
        
        if not args.debug:
            try:
                print_subseparator("-", 80)
                logger.info(f"⏳ Loading vLLM engine...")
                llm = LLM(
                    model=model_path,
                    dtype="auto",
                    trust_remote_code=True,
                    gpu_memory_utilization=0.85,
                    max_model_len=16384,
                    tensor_parallel_size=1
                )
                logger.info(f"   ✓ LLM engine initialized")
                
                logger.info(f"⏳ Loading tokenizer...")
                tokenizer = llm.get_tokenizer()
                logger.info(f"   ✓ Tokenizer loaded")
                
                sampling = SamplingParams(temperature=0, max_tokens=512)
                logger.info(f"   ✓ Sampling parameters configured")
                print_subseparator("-", 80)
            except Exception as e:
                logger.error(f"Failed to load {model_alias}: {e}")
                continue
        else:
            logger.info("DEBUG MODE: Skipping vLLM load")

        # Process Datasets
        try:
            for ds_idx, ds_name in enumerate(pending_datasets, 1):
                items = all_datasets[ds_name]
                logger.info(f"\n{'='*80}")
                logger.info(f"📦 Dataset [{ds_idx}/{len(pending_datasets)}]: {ds_name.upper()}")
                logger.info(f"   Total items: {len(items)}")
                logger.info(f"{'='*80}\n")
                
                logger.info(f"⏳ Building prompts...")
                prompts = []
                valid_items = []
                for item in items:
                    msgs = [
                        {"role": "system", "content": PromptManager.get_system_prompt(ds_name)},
                        {"role": "user", "content": PromptManager.build_user_prompt(ds_name, item)}
                    ]
                    if not args.debug:
                        prompt_str = tokenizer.apply_chat_template(msgs, tokenize=False, add_generation_prompt=True)
                        prompt_tokens = tokenizer.encode(prompt_str)
                        if len(prompt_tokens) > 15872:
                            logger.warning(f"Skipping item with {len(prompt_tokens)} tokens (exceeds limit)")
                            continue
                        prompts.append(prompt_str)
                        valid_items.append(item)
                    else:
                        prompts.append(str(msgs))
                        valid_items.append(item)
                
                items = valid_items
                logger.info(f"   ✓ Built {len(prompts)} valid prompts\n")

                outputs = []
                if not args.debug:
                    logger.info(f"🔄 Running inference...")
                    outputs = llm.generate(prompts, sampling)
                    logger.info(f"   ✓ Inference completed\n")
                else:
                    class MockOutput:
                        def __init__(self, text): self.outputs = [type('obj', (object,), {'text': text})]
                    outputs = [MockOutput("option 1: Test Answer" if ds_name == "teleqna" else "Test Answer")] * len(prompts)
                
                results = []
                for i, out in enumerate(outputs):
                    raw_answer = out.outputs[0].text.strip()
                    results.append({
                        "question": items[i]["question"],
                        "gold": items[i]["gold"],
                        "model_answer_raw": raw_answer,
                        "context": items[i].get("context", "")
                    })
                
                # Save Raw Results
                ds_result_dir = os.path.join(Config.RESULT_DIR, ds_name)
                os.makedirs(ds_result_dir, exist_ok=True)
                save_path = os.path.join(ds_result_dir, f"{model_alias}.json")
                
                with open(save_path, "w", encoding="utf-8") as f:
                    final_out = {"metrics": {}, "data": results}
                    json.dump(final_out, f, indent=2, ensure_ascii=False)
                logger.info(f"💾 Raw results saved: {save_path}\n")

        except Exception as e:
            logger.error(f"\n❌ Error during inference for {model_alias}: {e}")
        
        # Cleanup
        logger.info(f"\n🧹 Cleaning up GPU memory...")
        if llm:
            try:
                from vllm.distributed.parallel_state import destroy_model_parallel
                destroy_model_parallel()
                del llm
                if tokenizer: del tokenizer
                for _ in range(3): gc.collect()
                if torch.cuda.is_available():
                    torch.cuda.empty_cache()
                    torch.cuda.synchronize()
                time.sleep(3)
                logger.info(f"   ✓ GPU memory cleanup completed\n")
            except Exception as cleanup_error:
                logger.error(f"Error during cleanup: {cleanup_error}")

    print_separator("=", 80)
    logger.info("\n🎉 All inferences completed successfully!\n")
    print_separator("=", 80)
    
if __name__ == "__main__":
    main()
