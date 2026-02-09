import sys
import os
import re
import json
import numpy as np
import evaluate
import pandas as pd
import time
import string
import collections
from pathlib import Path
from typing import List, Dict, Any

# === 경로 설정 ===
current_dir = Path(__file__).resolve().parent
sys.path.append(str(current_dir))
BASE_DIR = current_dir.parent
sys.path.append(str(BASE_DIR))

try:
    from evaluation_utils import RobustCleaner, TypeAwareScorer, MetricsCalculator
except ImportError:
    try:
        from evaluation.evaluation_utils import RobustCleaner, TypeAwareScorer, MetricsCalculator
    except ImportError:
        print("[Error] evaluation_utils.py not found.")
        sys.exit(1)

# 평가할 파일 경로
DATA_FILES = {
    # "Telequad": BASE_DIR / "data" / "debate_results" / "full_w_context4" / "telequad_result.json",
    # "TeleQnA": BASE_DIR / "data" / "debate_results" / "full_w_context4" / "teleqna_result.json",
    # "NetBench": BASE_DIR / "data" / "debate_results" / "full_w_context4" / "netbench_result.json",
    "NetConfig": BASE_DIR / "data" / "debate_results" / "full_w_context4" / "netconfig_result2.json"
}

# === Token F1 Score 계산 함수 (SQuAD Style) ===
def compute_token_f1(prediction, truth):
    def normalize_answer(s):
        """소문자 변환, 문장부호 제거, 관사 제거 후 공백 정리"""
        def remove_articles(text):
            return re.sub(r'\b(a|an|the)\b', ' ', text)
        def white_space_fix(text):
            return ' '.join(text.split())
        def remove_punc(text):
            exclude = set(string.punctuation)
            return ''.join(ch for ch in text if ch not in exclude)
        def lower(text):
            return text.lower()
        return white_space_fix(remove_articles(remove_punc(lower(s))))

    # None 안전 처리
    if prediction is None: prediction = ""
    if truth is None: truth = ""

    pred_tokens = normalize_answer(str(prediction)).split()
    truth_tokens = normalize_answer(str(truth)).split()

    # 겹치는 토큰 개수 계산
    common = collections.Counter(pred_tokens) & collections.Counter(truth_tokens)
    num_same = sum(common.values())

    # 둘 다 빈 값인 경우 1.0, 하나만 빈 경우 0.0
    if len(pred_tokens) == 0 or len(truth_tokens) == 0:
        return int(pred_tokens == truth_tokens)

    if num_same == 0:
        return 0.0

    precision = 1.0 * num_same / len(pred_tokens)
    recall = 1.0 * num_same / len(truth_tokens)
    f1 = (2 * precision * recall) / (precision + recall)
    return f1

# === 기존 파서들 ===
class BaseParser:
    def parse(self, text: str) -> str:
        return text.strip() if text and isinstance(text, str) else ""

class TeleQnAParser(BaseParser):
    def parse(self, response: str) -> str:
        if not response or not isinstance(response, str): return ""
        response = response.strip()
        response = re.sub(r'<think>.*?</think>', '', response, flags=re.DOTALL).strip()
        for marker in ["assistant", "final", "Answer:", "Result:"]:
            if marker.lower() in response.lower():
                parts = re.split(re.escape(marker), response, flags=re.IGNORECASE)
                if len(parts) > 1: response = parts[-1].strip()
        response = re.sub(r'^(?:analysis|thought|reasoning)[:\s]*', '', response, flags=re.IGNORECASE).strip()
        patterns = [r'option\s*(\d+)', r'^[\s\*\-]*(\d+)[\s\.\)]*', r'(?:answer|correct)\s*(?:is)?\s*(?:option)?\s*(\d+)']
        for p in patterns:
            match = re.search(p, response, re.IGNORECASE)
            if match: return f"option {match.group(1)}"
        match = re.search(r'\(?\s*([A-F])\s*\)?', response)
        if match:
            num = ord(match.group(1).upper()) - ord('A') + 1
            return f"option {num}"
        return response[:100]

def load_metrics():
    print("⏳ Loading metrics...", end=" ", flush=True)
    try:
        rouge = evaluate.load('rouge')
        bertscore = evaluate.load('bertscore')
        bleu = evaluate.load('bleu')
        print("✅")
        return rouge, bertscore, bleu
    except Exception as e:
        print(f"\n❌ Metric loading failed: {e}")
        return None, None, None

def evaluate_netconfig(file_path, rouge, bert, bleu):
    if not os.path.exists(file_path):
        return {"Dataset": "NetConfig", "Status": "File Not Found"}

    with open(file_path, 'r', encoding='utf-8') as f:
        data = json.load(f)

    scorer = TypeAwareScorer()
    
    preds_clean = [] 
    refs_clean = []
    f1_scores = []
    
    type_stats = {} 
    wrong_cases = []
    
    for i, item in enumerate(data):
        raw_pred = item.get('debate2_answer', item.get('final_answer', ''))
        gold = item.get('gold_answer', '')
        atype = RobustCleaner.canonical_answer_type(item.get('answer_type', 'text'))
        
        # [CRITICAL FIX] None 타입 및 빈 문자열 방어 로직
        if raw_pred is None: raw_pred = ""
        else: raw_pred = str(raw_pred)
        
        if gold is None: gold = ""
        else: gold = str(gold)

        # Map/Set인데 비어있거나 null인 경우, scorer가 죽지 않도록 기본값 할당
        if atype == 'map':
            if not gold.strip() or gold.strip().lower() == 'null': gold = "{}"
            if not raw_pred.strip() or raw_pred.strip().lower() == 'null': raw_pred = "{}"
        elif atype == 'set':
            if not gold.strip() or gold.strip().lower() == 'null': gold = "[]"
            if not raw_pred.strip() or raw_pred.strip().lower() == 'null': raw_pred = "[]"

        # 1. Type-Aware Score (안전하게 호출)
        try:
            score = scorer.score(raw_pred, gold, atype)
        except Exception as e:
            # Scorer 내부 에러 발생 시 0점 처리하고 로그 출력
            # print(f"[Warning] Item {i} scorer failed: {e}. Pred: {raw_pred}, Gold: {gold}")
            score = 0.0
        
        # 2. 통계
        if atype not in type_stats: type_stats[atype] = {'sum': 0.0, 'count': 0}
        type_stats[atype]['sum'] += score
        type_stats[atype]['count'] += 1
        
        # 3. NLP Metrics용 정제
        clean_p = RobustCleaner.clean(raw_pred, atype)
        clean_g = RobustCleaner.clean(gold, atype)
        
        # Token F1 계산
        f1 = compute_token_f1(clean_p, clean_g)
        f1_scores.append(f1)

        preds_clean.append(clean_p if clean_p else " ")
        refs_clean.append(clean_g if clean_g else " ")

        if score < 1.0 and len(wrong_cases) < 5:
            wrong_cases.append({
                "Type": atype,
                "Gold": clean_g,
                "Pred": clean_p,
                "Raw": raw_pred[:50] + "..."
            })

    if not preds_clean:
        return {"Dataset": "NetConfig", "Status": "No Data"}

    print("\n" + "-"*60)
    print(f"📊 NetConfig Detailed Breakdown (Total: {len(preds_clean)})")
    print("-"*60)
    
    print(f"{'Type':<15} | {'Count':<8} | {'Accuracy':<10}")
    print("-" * 40)
    
    total_score_sum = 0
    for atype, stat in type_stats.items():
        avg = (stat['sum'] / stat['count']) * 100
        print(f"{atype:<15} | {stat['count']:<8} | {avg:.2f}%")
        total_score_sum += stat['sum']
    
    if wrong_cases:
        print("\n[❌ Wrong Cases Examples]")
        for i, wc in enumerate(wrong_cases):
            print(f"{i+1}. [{wc['Type']}] Gold: '{wc['Gold']}' vs Pred: '{wc['Pred']}'")
            print(f"   (Raw output: {wc['Raw']})")
    
    print("-" * 60 + "\n")

    result = {"Dataset": "NetConfig", "Count": len(preds_clean)}
    result["Type-Aware Acc"] = round((total_score_sum / len(preds_clean)) * 100, 2)
    
    em = sum(1 for p, r in zip(preds_clean, refs_clean) if p.strip() == r.strip())
    result["EM"] = round(em / len(preds_clean), 4)
    
    # Token F1 평균 저장
    result["Token_F1"] = round(sum(f1_scores) / len(f1_scores), 4)
    
    rouge_res = rouge.compute(predictions=preds_clean, references=refs_clean)
    result["R-1"] = round(rouge_res['rouge1'], 4)
    result["R-2"] = round(rouge_res['rouge2'], 4)
    result["R-L"] = round(rouge_res['rougeL'], 4)
    
    try:
        bert_res = bert.compute(predictions=preds_clean, references=refs_clean, lang='en', model_type="distilbert-base-uncased")
        result["BERT_F1"] = round(np.mean(bert_res['f1']), 4)
    except: result["BERT_F1"] = 0.0
        
    try:
        bleu_res = bleu.compute(predictions=preds_clean, references=[[r] for r in refs_clean])
        result["BLEU"] = round(bleu_res['bleu'], 4)
    except: result["BLEU"] = 0.0
        
    result["Accuracy"] = "-" 
    
    return result

def evaluate_other_dataset(name, file_path, rouge, bert, bleu):
    if not os.path.exists(file_path):
        return {"Dataset": name, "Status": "File Not Found"}

    if "teleqna" in name.lower(): parser = TeleQnAParser()
    else: parser = BaseParser()

    with open(file_path, 'r', encoding='utf-8') as f:
        data = json.load(f)

    preds, refs = [], []
    f1_scores = [] 

    for item in data:
        gold = str(item.get('gold_answer', ''))
        raw_pred = str(item.get('debate2_answer', item.get('final_answer', '')))
        
        parsed_pred = parser.parse(raw_pred)
        
        p_clean = parsed_pred if parsed_pred else " "
        g_clean = gold.strip() if gold.strip() else " "

        preds.append(p_clean)
        refs.append(g_clean)
        
        # Token F1 계산
        f1_scores.append(compute_token_f1(p_clean, g_clean))

    if not preds: return {"Dataset": name, "Status": "No Data"}

    result = {"Dataset": name, "Count": len(preds)}

    if "teleqna" in name.lower():
        correct = 0
        for p, r in zip(preds, refs):
            p_num = re.search(r'\d+', p)
            r_num = re.search(r'\d+', r)
            if p_num and r_num and p_num.group(0) == r_num.group(0):
                correct += 1
        result["Accuracy"] = round((correct / len(preds)) * 100, 2)
        result["Type-Aware Acc"] = "-"
        result["Token_F1"] = "-" 
    else:
        em = sum(1 for p, r in zip(preds, refs) if p.strip().lower() == r.strip().lower())
        result["EM"] = round(em / len(preds), 4)
        
        result["Token_F1"] = round(sum(f1_scores) / len(f1_scores), 4)

        rouge_res = rouge.compute(predictions=preds, references=refs)
        result["R-1"] = round(rouge_res['rouge1'], 4)
        result["R-2"] = round(rouge_res['rouge2'], 4)
        result["R-L"] = round(rouge_res['rougeL'], 4)
        try:
            bert_res = bert.compute(predictions=preds, references=refs, lang='en', model_type="distilbert-base-uncased")
            result["BERT_F1"] = round(np.mean(bert_res['f1']), 4)
        except: result["BERT_F1"] = 0.0
        try:
            bleu_res = bleu.compute(predictions=preds, references=[[r] for r in refs])
            result["BLEU"] = round(bleu_res['bleu'], 4)
        except: result["BLEU"] = 0.0
        result["Accuracy"] = "-"
        result["Type-Aware Acc"] = "-"

    return result

def run_evaluation_all():
    rouge, bert, bleu = load_metrics()
    if rouge is None: return

    summary = []
    print("\n" + "=" * 125) 
    print(f"📊  Multi-Agent Evaluation Report ({time.strftime('%Y-%m-%d %H:%M')})")
    print("=" * 125)
    
    for name, path in DATA_FILES.items():
        print(f"🔍 Evaluating {name}...")
        
        if "NetConfig" in name:
            res = evaluate_netconfig(path, rouge, bert, bleu)
        else:
            res = evaluate_other_dataset(name, path, rouge, bert, bleu)
            
        if "Status" in res:
            print(f"   ⚠️ {res['Status']}")
        else:
            summary.append(res)
            print("   ✅ Done")

    if summary:
        df = pd.DataFrame(summary)
        cols = ["Dataset", "Count", "Accuracy", "Type-Aware Acc", "EM", "Token_F1", "BERT_F1", "R-1", "R-2", "R-L", "BLEU"]
        for c in cols:
            if c not in df.columns: df[c] = "-"
        
        pd.set_option('display.max_columns', None)
        pd.set_option('display.width', 1000)
        df = df.fillna("-")
        print("\n" + df[cols].to_string(index=False))
    
    print("=" * 125 + "\n")

if __name__ == "__main__":
    run_evaluation_all()