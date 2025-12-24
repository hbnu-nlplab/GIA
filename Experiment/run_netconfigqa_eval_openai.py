
import os
import json
import csv
import argparse
import time
import logging
import datetime
from pathlib import Path
from typing import List, Dict, Any, Union, Set
import glob
import re
import ast
from collections import Counter

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s | %(levelname)s | %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler(f"netconfigqa_eval_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.log")
    ]
)
logger = logging.getLogger(__name__)

try:
    from openai import OpenAI
except ImportError:
    logger.error("OpenAI package not found. Please install: pip install openai")
    sys.exit(1)

class Config:
    # Default Paths (Can be overridden by args)
    BASE_DIR = os.path.dirname(os.path.abspath(__file__))
    DEFAULT_DATASET_PATH = os.path.join(BASE_DIR, "Data/Pnetlab/Research_Institute_Internal_DC/Dataset/Research_Institute_Internal_DC_dataset_batfish_20251224_012740.csv")
    DEFAULT_CONFIG_DIR = os.path.join(BASE_DIR, "Data/Pnetlab/Research_Institute_Internal_DC/configs")
    DEFAULT_MODEL = "gpt-4o-mini"
    
class ConfigManager:
    """Manages loading and caching of network device configuration files."""
    def __init__(self, config_dirs: List[str]):
        self.config_dirs = [Path(d) for d in config_dirs]
        self._cache: Dict[str, str] = {} # hostname -> content
        self._load_all_configs()

    def _load_all_configs(self):
        """Pre-load all .cfg files from directories."""
        for config_dir in self.config_dirs:
            if not config_dir.exists():
                logger.warning(f"Config directory not found: {config_dir}")
                continue
            
            # Recursive search for .cfg files
            for cfg_path in config_dir.rglob("*.cfg"):
                try:
                    hostname = cfg_path.stem  # Assume filename is hostname (e.g., PE1.cfg -> PE1)
                    with open(cfg_path, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read()
                    self._cache[hostname.lower()] = content # Case-insensitive key
                    logger.debug(f"Loaded config for {hostname}")
                except Exception as e:
                    logger.error(f"Failed to load {cfg_path}: {e}")
        
        logger.info(f"Loaded {len(self._cache)} configuration files.")

    def get_configs(self, hostnames: List[str]) -> str:
        """Retrieves and concatenates config contents for requested devices."""
        combined_config = ""
        missing = []
        
        # Deduplicate hostnames and handle potential varying naming conventions
        targets = set(h.lower() for h in hostnames if h)
        
        for host in targets:
            if host in self._cache:
                combined_config += f"\n=== START OF CONFIG: {host.upper()} ===\n"
                combined_config += self._cache[host]
                combined_config += f"\n=== END OF CONFIG: {host.upper()} ===\n"
            else:
                missing.append(host)
        
        if missing:
            logger.warning(f"Missing configs for: {missing}")
            
        return combined_config

class NetConfigQAScorer:
    """Handles scoring based on answer types."""
    
    def score(self, pred: str, gold: str, answer_type: str) -> Dict[str, float]:
        """
        Returns a dictionary of metrics, e.g., {"accuracy": 1.0, "f1": 0.5}.
        Main metric is always 'score'.
        """
        # Normalize inputs
        pred = str(pred).strip()
        gold = str(gold).strip()
        
        # Strip surrounding quotes if present in gold (common in CSV exported from JSON)
        if len(gold) >= 2 and gold.startswith('"') and gold.endswith('"'):
            gold = gold[1:-1]
        
        # Handle 'not configured' or empty gold properly
        if gold.lower() in ['null', 'none', '']:
            gold = ""
        
        try:
            if answer_type == "boolean":
                return self._score_boolean(pred, gold)
            elif answer_type in ["numeric", "scalar_int", "number"]: # 'number' from json
                return self._score_numeric(pred, gold)

            elif answer_type in ["set", "set_str", "list"]: # 'set_str' from json
                return self._score_set(pred, gold)
            elif answer_type in ["map", "map_str_str", "dictionary", "json"]: # 'map_str_str', 'json'
                return self._score_map(pred, gold)
            else: # text, etc.
                return self._score_text(pred, gold)
        except Exception as e:
            logger.error(f"Scoring error for type {answer_type}: {e} | Pred: {pred} | Gold: {gold}")
            return {"score": 0.0, "error": 1.0}

    def _clean_bool(self, val: str) -> bool:
        val = val.lower()
        if val in ['true', 'yes', 'on', 'enabled', '1']:
            return True
        return False

    def _score_boolean(self, pred: str, gold: str) -> Dict[str, float]:
        p_bool = self._clean_bool(pred)
        g_bool = self._clean_bool(gold)
        return {"score": 1.0 if p_bool == g_bool else 0.0}

    def _extract_number(self, val: str) -> float:
        # Extract first number found
        match = re.search(r'-?\d+(\.\d+)?', val)
        return float(match.group()) if match else None

    def _score_numeric(self, pred: str, gold: str) -> Dict[str, float]:
        p_num = self._extract_number(pred)
        g_num = self._extract_number(gold)
        
        if p_num is None or g_num is None:
            # Fallback for Exact Match if number parsing fails but strings match
            return {"score": 1.0 if pred.lower() == gold.lower() else 0.0}
            
        return {"score": 1.0 if p_num == g_num else 0.0}

    def _parse_set(self, val: str) -> Set[str]:
        try:
            # Try parsing as JSON first
            if val.startswith('[') and val.endswith(']'):
                items = json.loads(val.replace("'", '"')) # Simple quote fix
                return set(str(i).strip().lower() for i in items)
        except:
            pass
        
        # Fallback: comma separated
        items = [i.strip().lower() for i in val.split(',')]
        return set(items)

    def _score_set(self, pred: str, gold: str) -> Dict[str, float]:
        p_set = self._parse_set(pred)
        g_set = self._parse_set(gold)
        
        if not g_set and not p_set: # Both empty
            return {"score": 1.0, "f1": 1.0, "precision": 1.0, "recall": 1.0}
            
        intersection = len(p_set & g_set)
        precision = intersection / len(p_set) if p_set else 0.0
        recall = intersection / len(g_set) if g_set else 0.0
        f1 = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0.0
        
        return {"score": f1, "f1": f1, "precision": precision, "recall": recall}

    def _score_map(self, pred: str, gold: str) -> Dict[str, float]:
        # Simple string match for JSON maps for now, or key-wise comparison
        # To be robust, we need to parse JSON
        try:
            p_obj = json.loads(pred.replace("'", '"'))
            g_obj = json.loads(gold.replace("'", '"'))
        except:
            return {"score": 1.0 if pred.lower() == gold.lower() else 0.0}

        if not isinstance(p_obj, dict) or not isinstance(g_obj, dict):
             return {"score": 1.0 if str(p_obj) == str(g_obj) else 0.0}
             
        # Compare keys matches
        common_keys = set(p_obj.keys()) & set(g_obj.keys())
        all_keys = set(p_obj.keys()) | set(g_obj.keys())
        
        if not all_keys:
            return {"score": 1.0}
            
        key_match_score = len(common_keys) / len(all_keys)
        
        # Compare values for common keys
        value_matches = 0
        for k in common_keys:
            if str(p_obj[k]).lower() == str(g_obj[k]).lower():
                value_matches += 1
                
        value_score = value_matches / len(common_keys) if common_keys else 0.0
        
        final_score = (key_match_score * 0.5) + (value_score * 0.5)
        return {"score": final_score}

    def _score_text(self, pred: str, gold: str) -> Dict[str, float]:
        # Exact match (case insensitive)
        is_correct = pred.lower() == gold.lower()
        
        # TODO: Add F1 or BLEU/ROUGE for longer text if needed
        # For NetConfigQA text answers are usually short values (filenames, versions, etc.)
        
        return {"score": 1.0 if is_correct else 0.0}


class Evaluator:
    def __init__(self, api_key: str, model: str, config_dir: str):
        self.client = OpenAI(api_key=api_key)
        self.model = model
        self.config_manager = ConfigManager([config_dir])
        self.scorer = NetConfigQAScorer()
        self.results = []
    
    def generate_answer(self, question: str, answer_type: str, configs: str) -> str:
        
        system_prompt = f"""You are a Network Engineer.
Answer the question based ONLY on the provided device configurations.
CRITICAL: Output format must depend on the expected answer type:
- boolean: "true" or "false"
- numeric: Number only (e.g. 5)
- set/list: JSON array ["item1", "item2"]
- map/dict: JSON object {{"key": "value"}}
- text: Exact value string only, no description.

If information is missing, answer with:
- boolean: false
- numeric: 0
- set: []
- map: {{}}
- text: null
"""

        user_prompt = f"""
=== DEVICE CONFIGURATIONS ===
{configs}

=== QUESTION ===
{question}

=== EXPECTED ANSWER TYPE ===
{answer_type}

=== ANSWER ===
"""
        max_tokens = 2048
        # Truncate configs if too long (simple char limit for safety)
        if len(user_prompt) > 100000: 
             # Rough heuristic, OpenAI handles up to 128k context but good to be safe/cost-effective
             # Keep config parts that might satisfy the query? 
             # For now, just truncating head might lose context, but simple eval usually fits.
             pass

        try:
            response = self.client.chat.completions.create(
                model=self.model,
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_prompt}
                ],
                temperature=0.0, # Deterministic
                max_tokens=100
            )
            return response.choices[0].message.content.strip()
        except Exception as e:
            logger.error(f"API Error: {e}")
            return "API_ERROR"

    def run(self, csv_path: str, output_path: str, limit: int = None):
        logger.info(f"Loading dataset from {csv_path}")
        
        data = []
        with open(csv_path, 'r', encoding='utf-8') as f:
            reader = csv.DictReader(f)
            data = list(reader)
            
        logger.info(f"Loaded {len(data)} questions.")
        
        if limit:
            data = data[:limit]
            logger.info(f"Limiting evaluation to {limit} samples.")
            
        dataset_stats = {
            "total": 0,
            "correct": 0,
            "by_level": Counter(),
            "by_level_correct": Counter(),
            "by_type": Counter(),
            "by_type_correct": Counter(),
            "negative_testing_total": 0,
            "negative_testing_correct": 0,
            "false_positives": 0, # Should be null but listed
            "false_negatives": 0, # Should be val but null
        }
        
        logger.info("Starting evaluation...")
        
        start_time = time.time()
        
        for idx, row in enumerate(data):
            qid = row.get('question_id', str(idx))
            question = row['question']
            answer_type = row['answer_type']
            gold_answer = row['answer']
            answer_status = row.get('answer_status', 'OK') # OK, NOT_CONFIGURED, UNKNOWN
            level = row.get('level', 'L1')
            
            # Extract involved devices if possible (from question or metadata)
            # Simple heuristic: scan question for known hostnames in cache
            # Better strategy: Load ALL configs for the topology since we usually work with a lab
            # For this script, we'll pass ALL configs from the directory as context 
            # (Assuming small topology like the PE1/PE2/Leaf/Spine set we saw)
            # If topology is large, this needs to be smarter.
            
            # For now, get all cached configs as one block
            configs_content = self.config_manager.get_configs(list(self.config_manager._cache.keys()))
            
            pred_answer = self.generate_answer(question, answer_type, configs_content)
            
            # Score
            metrics = self.scorer.score(pred_answer, gold_answer, answer_type)
            score = metrics['score']
            
            # Update Stats
            dataset_stats["total"] += 1
            dataset_stats["by_level"][level] += 1
            dataset_stats["by_type"][answer_type] += 1
            
            if score == 1.0:
                dataset_stats["correct"] += 1
                dataset_stats["by_level_correct"][level] += 1
                dataset_stats["by_type_correct"][answer_type] += 1
            
            # Negative Testing Stats
            if answer_status == 'NOT_CONFIGURED':
                dataset_stats["negative_testing_total"] += 1
                if score == 1.0:
                    dataset_stats["negative_testing_correct"] += 1
                elif pred_answer not in ["null", "[]", "{}", "false", "0"]:
                    dataset_stats["false_positives"] += 1 # Hallucination
            
            result_entry = {
                "question_id": qid,
                "question": question,
                "gold": gold_answer,
                "pred": pred_answer,
                "score": score,
                "level": level,
                "type": answer_type,
                "status": answer_status
            }
            self.results.append(result_entry)
            
            if (idx + 1) % 5 == 0:
                logger.info(f"Processed {idx + 1}/{len(data)} samples.")
        
        duration = time.time() - start_time
        logger.info(f"Evaluation completed in {duration:.2f} seconds.")
        
        # Save results
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump({
                "meta": {
                    "model": self.model,
                    "date": str(datetime.datetime.now()),
                    "duration": duration
                },
                "stats": {
                    "accuracy": dataset_stats["correct"] / dataset_stats["total"] if dataset_stats["total"] else 0,
                    "level_accuracy": {k: dataset_stats["by_level_correct"][k]/dataset_stats["by_level"][k] for k in dataset_stats["by_level"]},
                    "type_accuracy": {k: dataset_stats["by_type_correct"][k]/dataset_stats["by_type"][k] for k in dataset_stats["by_type"]},
                },
                "results": self.results
            }, f, indent=2, ensure_ascii=False)
            
        logger.info(f"Results saved to {output_path}")

def main():
    parser = argparse.ArgumentParser(description="NetConfigQA Evaluation Script")
    parser.add_argument("--dataset", default=Config.DEFAULT_DATASET_PATH, help="Path to dataset CSV")
    parser.add_argument("--config_dir", default=Config.DEFAULT_CONFIG_DIR, help="Path to config directory")
    parser.add_argument("--model", default=Config.DEFAULT_MODEL, help="OpenAI Model name")
    parser.add_argument("--output", default="netconfigqa_results.json", help="Output JSON path")
    parser.add_argument("--sample", type=int, default=None, help="Number of samples to run (for testing)")
    
    args = parser.parse_args()
    
    api_key = os.getenv("OPENAI_API_KEY")
    if not api_key:
        # Fallback to hardcoded key if testing (NOT RECOMMENDED for prod)
        # Or ask user. For now, log error.
        logger.error("OPENAI_API_KEY environment variable is not set.")
        sys.exit(1)
        
    evaluator = Evaluator(api_key, args.model, args.config_dir)
    evaluator.run(args.dataset, args.output, args.sample)

if __name__ == "__main__":
    main()
