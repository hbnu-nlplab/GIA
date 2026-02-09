import sys
import os
import re
import json
import numpy as np
import evaluate
import pandas as pd
import time
from pathlib import Path
from typing import List, Dict, Any

# === 설정 및 경로 ===
BASE_DIR = Path(__file__).resolve().parents[1]
sys.path.append(str(BASE_DIR))

# 평가할 파일 경로
TARGET_FILE = BASE_DIR / "data" / "debate_results" / "full_w_context4" / "results_analyzed_20260107_141226.json"

class BaseParser:
    def parse(self, text: str) -> str:
        if not text or not isinstance(text, str):
            return ""
        return text.strip()

def load_metrics():
    print("⏳ Loading metrics: ROUGE, BERTScore, BLEU...")
    try:
        print("   - Loading ROUGE...", end=" ", flush=True)
        rouge = evaluate.load('rouge')
        print("✅")
        
        print("   - Loading BERTScore...", end=" ", flush=True)
        bertscore = evaluate.load('bertscore')
        print("✅")
        
        print("   - Loading BLEU...", end=" ", flush=True)
        bleu = evaluate.load('bleu')
        print("✅")
        
        return rouge, bertscore, bleu
    except Exception as e:
        print(f"\n❌ Metric loading failed: {e}")
        return None, None, None

def evaluate_custom_dataset(file_path, rouge, bert, bleu):
    if not os.path.exists(file_path):
        return {"Dataset": str(file_path), "Status": "File Not Found"}

    print(f"📂 Reading file: {file_path}")
    with open(file_path, 'r', encoding='utf-8') as f:
        data = json.load(f)

    # Handle the structure of the new dataset
    items = []
    if isinstance(data, dict) and "results" in data:
        items = data["results"]
    elif isinstance(data, list):
        items = data
    else:
        return {"Dataset": "Custom", "Status": "Unknown JSON structure"}

    print(f"   Found {len(items)} items.")

    preds, refs = [], []
    parser = BaseParser()

    for item in items:
        # User specified: gold is gold answer, pred is answer
        gold = item.get('gold', '')
        # Handle cases where gold might be wrapped in quotes or JSON-like strings if needed
        # In the sample shown: "gold": "\"p2\"", so it might be a JSON encoded string. 
        # But looking at the eval_answer.py, it mostly just strips. 
        # Let's clean it up slightly if it looks like a JSON string representation of a string.
        if isinstance(gold, str):
            gold = gold.strip()
            # If it looks like a quoted string like "\"p2\"", we might want to unquote it?
            # The original eval script didn't seem to unquote explicitly, but the user's sample shows keys like "gold": "\"p2\""
            # It's safest to treat it as the reference text directly, maybe stripping outer quotes if they are part of the value.
            # In the sample: "gold": "\"p2\"" -> the value is `"p2"`.
            # If I stick to simple strip, I should be fine for metrics like ROUGE/BERTScore.
            if gold.startswith('"') and gold.endswith('"') and len(gold) > 1:
                gold = gold[1:-1]
        elif isinstance(gold, list): 
            gold = str(gold[0]) if gold else ""
        elif isinstance(gold, dict): 
            gold = str(gold)
        
        pred = item.get('pred', '')
        if not pred:
            pred = item.get('raw_pred', '')
            
        parsed_pred = parser.parse(str(pred))
        
        preds.append(parsed_pred)
        refs.append(str(gold).strip())

    if not preds: 
        return {"Dataset": "Custom", "Status": "No Data"}

    result = {"Dataset": "Custom Dataset", "Count": len(preds)}

    # EM
    em = sum(1 for p, r in zip(preds, refs) if p.strip().lower() == r.strip().lower())
    result["EM"] = round((em / len(preds)), 6)
    
    # ROUGE
    rouge_res = rouge.compute(predictions=preds, references=refs)
    result["R-1"] = round(rouge_res['rouge1'], 4)
    result["R-2"] = round(rouge_res['rouge2'], 4)
    result["R-L"] = round(rouge_res['rougeL'], 4)
    
    # BERTScore
    try:
        bert_res = bert.compute(predictions=preds, references=refs, lang='en', model_type="distilbert-base-uncased")
        result["BERT_F1"] = round(np.mean(bert_res['f1']), 4)
    except Exception as e:
        print(f"⚠️ BERTScore failed: {e}")
        result["BERT_F1"] = 0.0
    
    # BLEU
    try:
        bleu_res = bleu.compute(predictions=preds, references=[[r] for r in refs])
        result["BLEU"] = round(bleu_res['bleu'], 4)
    except Exception as e:
        print(f"⚠️ BLEU failed: {e}")
        result["BLEU"] = 0.0
    
    result["Accuracy"] = "-"

    return result

def run_evaluation():
    rouge, bert, bleu = load_metrics()
    if rouge is None or bert is None or bleu is None: 
        print("❌ Failed to load metrics (None returned). Exiting.")
        return

    summary = []
    print("\n" + "=" * 100) 
    print(f"📊  Custom Dataset Evaluation Report ({time.strftime('%Y-%m-%d %H:%M')})")
    print("=" * 100)
    
    res = evaluate_custom_dataset(TARGET_FILE, rouge, bert, bleu)
    if "Status" in res and res["Status"] != "No Data":
        print(f"⚠️ {res['Status']}")
    else:
        summary.append(res)
        print("✅ Evaluation Complete")

    if summary:
        df = pd.DataFrame(summary)
        cols = ["Dataset", "Count", "Accuracy", "EM", "BERT_F1", "R-1", "R-2", "R-L", "BLEU"]
        
        pd.set_option('display.max_columns', None)
        pd.set_option('display.width', 1000)
        
        print("\n" + df[cols].to_string(index=False))
    
    print("=" * 100 + "\n")

if __name__ == "__main__":
    run_evaluation()
