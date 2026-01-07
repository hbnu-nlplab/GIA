"""
NetConfigQA Agent Result Analyzer
Based on the highly accurate NetConfigQA2 scoring logic.
"""

import json
import re
import os
import argparse
import csv
from pathlib import Path
from typing import Dict, List, Set, Any
from collections import defaultdict
from datetime import datetime


def canonical_answer_type(answer_type: str) -> str:
    """Normalize answer_type values to a canonical set used by the scorer/reports."""
    if answer_type is None:
        return 'text'
    atype = str(answer_type).strip().lower()
    aliases = {
        'numbers': 'number',
        'num': 'numeric',
        'int': 'number',
        'integer': 'number',
        'float': 'numeric',
        'list_str': 'set',
        'set_string': 'set',
        'dict': 'map',
    }
    return aliases.get(atype, atype)

# Traditional metrics
try:
    from rouge_score import rouge_scorer
    ROUGE_AVAILABLE = True
except ImportError:
    ROUGE_AVAILABLE = False

try:
    from bert_score import score as bert_score
    BERTSCORE_AVAILABLE = True
except ImportError:
    BERTSCORE_AVAILABLE = False

try:
    import nltk
    from nltk.translate.bleu_score import sentence_bleu, SmoothingFunction
    NLTK_AVAILABLE = True
except ImportError:
    NLTK_AVAILABLE = False


class TraditionalMetricsCalculator:
    def __init__(self):
        self.rouge_scorer = None
        if ROUGE_AVAILABLE:
            self.rouge_scorer = rouge_scorer.RougeScorer(['rouge1', 'rouge2', 'rougeL'], use_stemmer=True)
    
    def normalize_text(self, text: str) -> str:
        text = str(text).lower().strip()
        text = re.sub(r'\s+', ' ', text)
        return text
    
    def calculate_exact_match(self, pred: str, gold: str) -> float:
        return 1.0 if self.normalize_text(pred) == self.normalize_text(gold) else 0.0
    
    def calculate_token_f1(self, pred: str, gold: str) -> Dict[str, float]:
        pred_tokens = set(self.normalize_text(pred).split())
        gold_tokens = set(self.normalize_text(gold).split())
        if not gold_tokens and not pred_tokens: return {"token_f1": 1.0, "token_precision": 1.0, "token_recall": 1.0}
        if not gold_tokens or not pred_tokens: return {"token_f1": 0.0, "token_precision": 0.0, "token_recall": 0.0}
        common = pred_tokens & gold_tokens
        precision = len(common) / len(pred_tokens)
        recall = len(common) / len(gold_tokens)
        f1 = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0.0
        return {"token_f1": f1, "token_precision": precision, "token_recall": recall}
    
    def calculate_rouge(self, pred: str, gold: str) -> Dict[str, float]:
        if not ROUGE_AVAILABLE or not self.rouge_scorer: return {"rouge1": 0.0, "rouge2": 0.0, "rougeL": 0.0}
        try:
            scores = self.rouge_scorer.score(gold, pred)
            return {"rouge1": scores['rouge1'].fmeasure, "rouge2": scores['rouge2'].fmeasure, "rougeL": scores['rougeL'].fmeasure}
        except: return {"rouge1": 0.0, "rouge2": 0.0, "rougeL": 0.0}
    
    def calculate_bleu(self, pred: str, gold: str) -> float:
        if not NLTK_AVAILABLE: return 0.0
        p_tokens, g_tokens = self.normalize_text(pred).split(), [self.normalize_text(gold).split()]
        if not p_tokens or not g_tokens[0]: return 0.0
        try: return sentence_bleu(g_tokens, p_tokens, smoothing_function=SmoothingFunction().method1)
        except: return 0.0
    
    def calculate_all(self, pred: str, gold: str) -> Dict[str, float]:
        metrics = {'exact_match': self.calculate_exact_match(pred, gold)}
        metrics.update(self.calculate_token_f1(pred, gold))
        metrics.update(self.calculate_rouge(pred, gold))
        metrics['bleu'] = self.calculate_bleu(pred, gold)
        return metrics


class NetConfigQAScorer:
    def clean_prediction(self, pred: str, answer_type: str = None) -> str:
        if not pred: return ""
        answer_type = canonical_answer_type(answer_type)
        original_pred = str(pred)
        
        # 1. Handle Thinking / Agent labels
        if '</think>' in pred: pred = pred.split('</think>')[-1].strip()
        elif 'assistantfinal' in pred: pred = pred.split('assistantfinal')[-1].strip()
        elif 'Final Answer:' in pred: pred = pred.split('Final Answer:')[-1].strip()
        
        # 2. Extract structured content if pred is too long
        if len(pred) > 100:
            if answer_type in ['numeric', 'number']:
                num = self._extract_number(pred)
                if num is not None: pred = str(int(num))
            else:
                json_matches = list(re.finditer(r'\{[^{}]+:[^{}]+\}', pred))
                if json_matches: pred = json_matches[-1].group(0)
                else:
                    array_matches = list(re.finditer(r'\[[^\[\]]+\]', pred))
                    if array_matches: pred = array_matches[-1].group(0)

        # 3. Strip common prefixes
        pred = re.sub(r'^(analysis|answer|result|text|set|map):\s*', '', pred, flags=re.IGNORECASE).strip()
        pred = re.sub(r"```(json)?\s*|\s*```", "", pred, flags=re.DOTALL).strip()
        
        # 4. Unquote and Normalize
        if len(pred) >= 2 and ((pred.startswith('"') and pred.endswith('"')) or (pred.startswith("'") and pred.endswith("'"))):
            pred = pred[1:-1]
        
        # Cisco domain-specific
        pred = re.sub(r'^login\s+local$', 'local', pred, flags=re.IGNORECASE).strip()
        if pred.lower() in ['null', 'none', 'n/a', 'not configured', 'not found', '']: return ""
        return pred

    def clean_gold(self, gold: str) -> str:
        gold = str(gold).strip().strip('"\'')
        if gold.lower() in ['null', 'none', 'n/a', 'not configured', '']: return ""
        return gold

    def _extract_number(self, val: str) -> float:
        match = re.search(r'-?\d+(\.\d+)?', str(val))
        if match: return float(match.group())
        return None

    def _parse_set(self, val: str) -> Set[str]:
        val = str(val).strip()
        try:
            val_norm = val.replace("'", '"').replace('{', '[').replace('}', ']').replace('(', '[').replace(')', ']')
            if val_norm.startswith('[') and val_norm.endswith(']'):
                return set(str(i).strip().lower() for i in json.loads(val_norm))
        except: pass
        val_cleaned = val.strip('[]{}()"\' ').strip()
        if ',' in val_cleaned: return set(i.strip().lower() for i in val_cleaned.split(',') if i.strip())
        return {val_cleaned.lower()} if val_cleaned else set()

    def score(self, pred: str, gold: str, answer_type: str) -> Dict[str, float]:
        answer_type = canonical_answer_type(answer_type)
        p, g = self.clean_prediction(pred, answer_type), self.clean_gold(gold)
        try:
            if answer_type in ["numeric", "number"]:
                p_num, g_num = self._extract_number(p), self._extract_number(g)
                if p_num is not None and g_num is not None: return {"score": 1.0 if p_num == g_num else 0.0}
                return {"score": 1.0 if p.lower() == g.lower() else 0.0}
            elif answer_type in ["set", "list"]:
                p_set, g_set = self._parse_set(pred), self._parse_set(gold)
                if not g_set and not p_set: return {"score": 1.0}
                intersect = len(p_set & g_set)
                f1 = 2 * intersect / (len(p_set) + len(g_set)) if (len(p_set) + len(g_set)) > 0 else 0.0
                return {"score": f1}
            else:
                return {"score": 1.0 if p.lower() == g.lower() else 0.0}
        except: return {"score": 0.0}


def analyze_results(json_file: str):
    with open(json_file, 'r', encoding='utf-8') as f:
        data = json.load(f)
    
    scorer = NetConfigQAScorer()
    trad_calc = TraditionalMetricsCalculator()
    results = []
    
    grouped_by_type = defaultdict(list)
    print(f"Analyzing {len(data['results'])} agent results...")

    for row in data['results']:
        # Map agent field names to analyzer expectations
        raw_pred = row.get('pred', '')
        gold = row.get('gold', '')
        answer_type = row.get('answer_type', 'text')
        
        type_aware_metrics = scorer.score(raw_pred, gold, answer_type)
        score = type_aware_metrics['score']
        
        # Traditional metrics
        p_clean = scorer.clean_prediction(raw_pred, answer_type)
        g_clean = scorer.clean_gold(gold)
        trad_metrics = trad_calc.calculate_all(p_clean, g_clean)
        
        grouped_by_type[canonical_answer_type(answer_type)].append(score)
        
        results.append({
            "id": row.get('question_id', ''),
            "gold": gold,
            "pred": raw_pred,
            "score": score,
            "type": answer_type
        })

    total_acc = sum(sum(s) for s in grouped_by_type.values()) / len(data['results'])
    
    print("\n" + "="*50)
    print(f"AGENT EVALUATION RESULTS")
    print("="*50)
    print(f"Overall Accuracy: {total_acc:.2%}")
    for atype, scores in sorted(grouped_by_type.items()):
        print(f"   {atype:10s}: {sum(scores)/len(scores):.2%} (n={len(scores)})")
    print("="*50 + "\n")

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("json_file")
    args = parser.parse_args()
    analyze_results(args.json_file)

