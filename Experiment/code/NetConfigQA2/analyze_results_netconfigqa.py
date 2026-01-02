"""
NetConfigQA Result Analyzer (Scoring Only)

이 스크립트는 run_netconfigqa_eval_vllm.py의 raw 결과를 분석합니다:
- 예측 전처리 (think 태그 제거, 정규화)
- 점수 계산 (answer_type별)
- 통계 분석
- Markdown/JSON 채점표 생성

시각화는 별도로 Figure.py에서 수행합니다.
"""

import json
import re
import os
import argparse
import csv
from pathlib import Path
from typing import Dict, List, Set
from collections import defaultdict
from datetime import datetime

# Traditional metrics
try:
    from rouge_score import rouge_scorer
    ROUGE_AVAILABLE = True
except ImportError:
    ROUGE_AVAILABLE = False
    print("[WARNING] rouge-score not available. Install with: pip install rouge-score")

try:
    from bert_score import score as bert_score
    BERTSCORE_AVAILABLE = True
except ImportError:
    BERTSCORE_AVAILABLE = False
    print("[WARNING] bert-score not available. Install with: pip install bert-score")


# ==================== Traditional Metrics Calculator ====================

class TraditionalMetricsCalculator:
    """Calculate traditional NLP evaluation metrics."""
    
    def __init__(self):
        self.rouge_scorer = None
        if ROUGE_AVAILABLE:
            self.rouge_scorer = rouge_scorer.RougeScorer(
                ['rouge1', 'rouge2', 'rougeL'], 
                use_stemmer=True
            )
    
    def normalize_text(self, text: str) -> str:
        """Normalize text for fair comparison."""
        text = text.lower().strip()
        # Remove extra whitespace
        text = re.sub(r'\s+', ' ', text)
        return text
    
    def calculate_exact_match(self, pred: str, gold: str) -> float:
        """Exact Match: 1.0 if exactly same, 0.0 otherwise."""
        pred_norm = self.normalize_text(pred)
        gold_norm = self.normalize_text(gold)
        return 1.0 if pred_norm == gold_norm else 0.0
    
    def calculate_token_f1(self, pred: str, gold: str) -> Dict[str, float]:
        """Token-level F1 score."""
        pred_tokens = set(self.normalize_text(pred).split())
        gold_tokens = set(self.normalize_text(gold).split())
        
        if not gold_tokens and not pred_tokens:
            return {"token_f1": 1.0, "token_precision": 1.0, "token_recall": 1.0}
        if not gold_tokens or not pred_tokens:
            return {"token_f1": 0.0, "token_precision": 0.0, "token_recall": 0.0}
        
        common = pred_tokens & gold_tokens
        precision = len(common) / len(pred_tokens) if pred_tokens else 0.0
        recall = len(common) / len(gold_tokens) if gold_tokens else 0.0
        f1 = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0.0
        
        return {
            "token_f1": f1,
            "token_precision": precision,
            "token_recall": recall
        }
    
    def calculate_rouge(self, pred: str, gold: str) -> Dict[str, float]:
        """Calculate ROUGE-1, ROUGE-2, ROUGE-L scores."""
        if not ROUGE_AVAILABLE or not self.rouge_scorer:
            return {
                "rouge1": 0.0,
                "rouge2": 0.0,
                "rougeL": 0.0
            }
        
        try:
            scores = self.rouge_scorer.score(gold, pred)
            return {
                "rouge1": scores['rouge1'].fmeasure,
                "rouge2": scores['rouge2'].fmeasure,
                "rougeL": scores['rougeL'].fmeasure
            }
        except:
            return {"rouge1": 0.0, "rouge2": 0.0, "rougeL": 0.0}
    
    def calculate_all(self, pred: str, gold: str) -> Dict[str, float]:
        """Calculate all traditional metrics (except BERTScore which should be batched)."""
        metrics = {}
        
        # Exact Match
        metrics['exact_match'] = self.calculate_exact_match(pred, gold)
        
        # Token F1
        token_metrics = self.calculate_token_f1(pred, gold)
        metrics.update(token_metrics)
        
        # ROUGE
        rouge_metrics = self.calculate_rouge(pred, gold)
        metrics.update(rouge_metrics)
        
        return metrics


# ==================== Scorer ====================

class NetConfigQAScorer:
    """Handles scoring based on answer types."""
    
    def clean_prediction(self, pred: str, answer_type: str = None) -> str:
        """
        Clean model prediction by removing thinking tags and normalizing format.
        
        Handles:
        - Complete <think>...</think> blocks (takes text AFTER </think>)
        - Incomplete <think>... (takes text BEFORE <think>)
        - Multiple assistantfinal delimiters
        - Markdown code blocks
        - Quoted strings
        - Null values
        """
        if not pred:
            return ""
        
        original_pred = pred  # Keep original for fallback extraction
            
        # 1. Handle <think> tags and common delimiters
        # If </think> exists, we only care about what's AFTER it.
        if '</think>' in pred:
            pred = pred.split('</think>')[-1].strip()
        # GPT-OSS-20B specific delimiter
        elif 'assistantfinal' in pred:
            # Handle multiple assistantfinal delimiters - take the LAST one
            parts = pred.split('assistantfinal')
            pred = parts[-1].strip()
            
            # Handle 'assistantfinal think' pattern where think block appears after delimiter
            if pred.startswith('think'):
                # Check if there's a valid answer in the think block
                pred = pred[5:].strip()  # Remove 'think'
                
                # If pred is now a long explanation without structured answer,
                # fall back to extracting from original text
                if len(pred) > 80 and not any(pred.strip().startswith(c) for c in ['{', '[', '"']):
                    # Try to extract last valid JSON/set/map from original text
                    import re as re_local
                    
                    # For numeric/number types, try to extract numbers from text
                    if answer_type in ['numeric', 'number']:
                        num = self._extract_number(pred)
                        if num is not None:
                            pred = str(int(num))
                        else:
                            # Try to find number in original
                            num = self._extract_number(original_pred)
                            if num is not None:
                                pred = str(int(num))
                    else:
                        # Look for last JSON object
                        json_matches = list(re_local.finditer(r'\{[^{}]+:[^{}]+\}', original_pred))
                        if json_matches:
                            pred = json_matches[-1].group(0)
                        # Look for last JSON array
                        elif re_local.search(r'\[[^\[\]]+\]', original_pred):
                            array_matches = list(re_local.finditer(r'\[[^\[\]]+\]', original_pred))
                            pred = array_matches[-1].group(0)
                        # Look for numbers in the last sentence
                        elif len(pred) > 100:
                            sentences = pred.split('.')
                            if sentences:
                                last_sent = sentences[-1].strip()
                                num_match = re_local.search(r'\b(\d+)\b', last_sent)
                                if num_match:
                                    pred = num_match.group(1)
        # If only <think> exists (truncated), remove everything from <think> onwards
        elif '<think>' in pred:
            pred = pred.split('<think>')[0].strip()
        
        # 2. Strip common prefixes that might appear
        prefixes_to_remove = [
            r'^analysis\s*',
            r'^we need to\s*',
            r'^based on\s*',
            r'^the answer is\s*',
            r'^answer:\s*',
            r'^result:\s*',
            r'^\**answer\**:\s*',
            r'^json\s*',
            r'^set\s*',
            r'^map\s*',
            r'^text\s*',
        ]
        for prefix in prefixes_to_remove:
            pred = re.sub(prefix, '', pred, flags=re.IGNORECASE | re.MULTILINE).strip()

        # 3. Strip standard Markdown code blocks if present
        pred = re.sub(r"```.*?```", "", pred, flags=re.DOTALL).strip()
        pred = pred.replace("```json", "").replace("```", "").strip()

        # 4. Basic normalization
        pred = pred.strip('\n\r\t ')
        
        # Unquote (double or single quotes) - only if properly balanced
        if len(pred) >= 2 and ((pred.startswith('"') and pred.endswith('"')) or \
                               (pred.startswith("'") and pred.endswith("'"))):
            pred = pred[1:-1]
            
        # 5. Domain-specific cleaning (Cisco commands)
        # Handle common Cisco command patterns where model outputs full command instead of value
        cisco_patterns = [
            (r'^login\s+local$', 'local'),  # 'login local' -> 'local'
            (r'^login\s+(.+)$', r'\1'),      # 'login <method>' -> '<method>'
        ]
        for pattern, replacement in cisco_patterns:
            pred = re.sub(pattern, replacement, pred, flags=re.IGNORECASE).strip()
            
        # Handle nulls
        if pred.lower() in ['null', 'none', 'n/a', 'not configured', 'not found', '']:
            pred = ""
            
        return pred

    def clean_gold(self, gold: str) -> str:
        """Clean gold answer with same normalization as prediction."""
        gold = str(gold).strip()
        
        # Unquote gold
        if len(gold) >= 2 and ((gold.startswith('"') and gold.endswith('"')) or \
                               (gold.startswith("'") and gold.endswith("'"))):
            gold = gold[1:-1]
        
        if gold.lower() in ['null', 'none', 'n/a', 'not configured', '']:
            gold = ""
            
        return gold

    def score(self, pred: str, gold: str, answer_type: str) -> Dict[str, float]:
        """Score prediction against gold answer based on answer type."""
        # Clean prediction with answer_type context
        pred = self.clean_prediction(pred, answer_type)
        gold = self.clean_gold(gold)

        try:
            if answer_type in ["numeric", "scalar_int", "number"]:
                return self._score_numeric(pred, gold)
            elif answer_type in ["set", "set_str", "list"]:
                return self._score_set(pred, gold)
            elif answer_type in ["map", "map_str_str", "dictionary", "json"]:
                return self._score_map(pred, gold)
            else:  # text
                return self._score_text(pred, gold)
        except Exception as e:
            return {"score": 0.0, "error": str(e)}

    def _extract_number(self, val: str) -> float:
        """Extract number from string, including word-to-digit conversion."""
        try:
            # First try direct digit extraction
            match = re.search(r'-?\d+(\.\d+)?', val)
            if match:
                return float(match.group())
            
            # If no digit found, try to extract number words
            # Map of English number words to digits
            word_to_num = {
                'zero': 0, 'one': 1, 'two': 2, 'three': 3, 'four': 4,
                'five': 5, 'six': 6, 'seven': 7, 'eight': 8, 'nine': 9,
                'ten': 10, 'eleven': 11, 'twelve': 12, 'thirteen': 13,
                'fourteen': 14, 'fifteen': 15, 'sixteen': 16, 'seventeen': 17,
                'eighteen': 18, 'nineteen': 19, 'twenty': 20,
                'thirty': 30, 'forty': 40, 'fifty': 50,
                'sixty': 60, 'seventy': 70, 'eighty': 80, 'ninety': 90,
                'hundred': 100, 'thousand': 1000
            }
            
            val_lower = val.lower()
            
            # Look for patterns like "totaling five network interfaces"
            patterns = [
                r'totaling\s+(\w+)',
                r'lists\s+(\w+)',
                r'has\s+exactly\s+(\w+)',
                r'total\s+of\s+(\w+)',
                r'consists?\s+of\s+(\w+)',
            ]
            
            for pattern in patterns:
                match = re.search(pattern, val_lower)
                if match:
                    word = match.group(1)
                    if word in word_to_num:
                        return float(word_to_num[word])
            
            # Try to find any number word in the string
            for word, num in word_to_num.items():
                if re.search(r'\b' + word + r'\b', val_lower):
                    return float(num)
            
            return None
        except:
            return None

    def _score_numeric(self, pred: str, gold: str) -> Dict[str, float]:
        p_num = self._extract_number(pred)
        g_num = self._extract_number(gold)
        if p_num is None or g_num is None:
            return {"score": 1.0 if pred.lower() == gold.lower() else 0.0}
        return {"score": 1.0 if p_num == g_num else 0.0}

    def _parse_set(self, val: str) -> Set[str]:
        """
        Parse set from various formats:
        - JSON array: ["item1", "item2"]
        - Set notation: {"item1", "item2"}
        - Tuple: ("item1", "item2")
        - Comma-separated: item1, item2
        """
        val = val.strip()
        
        try:
            # 1. JSON 형식 파싱 시도 (대괄호, 중괄호, 소괄호 모두 지원)
            val_normalized = val.replace("'", '"')
            if (val_normalized.startswith('[') and val_normalized.endswith(']')) or \
               (val_normalized.startswith('{') and val_normalized.endswith('}')) or \
               (val_normalized.startswith('(') and val_normalized.endswith(')')):
                # 중괄호/소괄호를 대괄호로 변환 (JSON은 array만 지원)
                val_normalized = val_normalized.replace('{', '[').replace('}', ']')
                val_normalized = val_normalized.replace('(', '[').replace(')', ']')
                items = json.loads(val_normalized)
                return set(str(i).strip().lower() for i in items)
        except:
            pass
        
        # 2. Fallback: 쉼표 구분 파싱
        # 괄호 제거 후 쉼표로 split
        val_cleaned = val.strip('[]{}()"\' ').strip()
        if ',' in val_cleaned:
            return set(i.strip().lower() for i in val_cleaned.split(',') if i.strip())
        elif val_cleaned:
            return {val_cleaned.lower()}
        
        return set()

    def _score_set(self, pred: str, gold: str) -> Dict[str, float]:
        p_set = self._parse_set(pred)
        g_set = self._parse_set(gold)
        if not g_set and not p_set:
            return {"score": 1.0, "f1": 1.0}
        
        intersection = len(p_set & g_set)
        precision = intersection / len(p_set) if p_set else 0.0
        recall = intersection / len(g_set) if g_set else 0.0
        f1 = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0.0
        return {"score": f1, "f1": f1, "precision": precision, "recall": recall}

    def _normalize_ip_value(self, value: str) -> str:
        """
        Normalize IP address value for comparison.
        Removes CIDR notation if present.
        
        Examples:
        - "10.0.0.1/31" -> "10.0.0.1"
        - "10.0.0.1" -> "10.0.0.1"
        - "" -> ""
        """
        value = str(value).strip()
        # Remove CIDR notation (e.g., /31, /24, /32)
        if '/' in value:
            value = value.split('/')[0].strip()
        return value.lower()
    
    def _score_map(self, pred: str, gold: str) -> Dict[str, float]:
        try:
            p_obj = json.loads(pred.replace("'", '"'))
            g_obj = json.loads(gold.replace("'", '"'))
        except:
            return {"score": 1.0 if pred.lower() == gold.lower() else 0.0}
        
        if not isinstance(p_obj, dict) or not isinstance(g_obj, dict):
            return {"score": 1.0 if str(p_obj) == str(g_obj) else 0.0}
             
        common = set(p_obj.keys()) & set(g_obj.keys())
        all_k = set(p_obj.keys()) | set(g_obj.keys())
        if not all_k:
            return {"score": 1.0}
        
        # Compare values with IP normalization (removes CIDR notation)
        val_matches = 0
        for k in common:
            pred_val = self._normalize_ip_value(p_obj[k])
            gold_val = self._normalize_ip_value(g_obj[k])
            if pred_val == gold_val:
                val_matches += 1
        
        return {"score": (len(common)/len(all_k)*0.5) + (val_matches/len(common)*0.5 if common else 0)}

    def _normalize_for_comparison(self, text: str) -> str:
        """
        Normalize text for comparison:
        1. Extract numbers (remove Korean counters like 개, 대, 명)
        2. Map synonyms (diff -> 차이, etc.)
        """
        import re
        
        # 1. Korean/English synonym mapping
        synonyms = {
            'diff': '차이',
            'difference': '차이',
            'count': '개수',
            'total': '합계',
            'yes': '예',
            'no': '아니오',
            'true': '예',
            'false': '아니오',
        }
        
        text = text.lower().strip()
        
        # Apply synonym mapping
        for eng, kor in synonyms.items():
            text = text.replace(eng, kor)
        
        # 2. Normalize numbers: "0개" -> "0", "1대" -> "1"
        # Remove Korean counters after numbers
        text = re.sub(r'(\d+)\s*[개대명건번째]', r'\1', text)
        
        # 3. Normalize punctuation: remove extra spaces around colons/commas
        text = re.sub(r'\s*:\s*', ':', text)
        text = re.sub(r'\s*,\s*', ',', text)
        
        return text

    def _score_text(self, pred: str, gold: str) -> Dict[str, float]:
        """
        Score text answers using Type-Aware logic + Token F1 for robustness.
        Strategy:
        1. Exact Match (normalized): 1.0
        2. Token F1 with normalization: Partial match
        """
        # Handle 'false' or '0' which some models use for NOT_CONFIGURED text fields
        if pred.lower() in ['false', '0']:
            pred = ""
            
        # Apply normalization (number extraction + synonym mapping)
        pred_norm = self._normalize_for_comparison(pred)
        gold_norm = self._normalize_for_comparison(gold)
        
        # 1. Exact Match (Primary)
        if pred_norm == gold_norm:
            return {"score": 1.0}
            
        # 2. Token F1 (Secondary - Robustness)
        pred_tokens = set(pred_norm.split())
        gold_tokens = set(gold_norm.split())
        
        if not gold_tokens:
            return {"score": 1.0 if not pred_tokens else 0.0}
            
        common = pred_tokens & gold_tokens
        if common:
            precision = len(common) / len(pred_tokens) if pred_tokens else 0
            recall = len(common) / len(gold_tokens)
            f1 = 2 * (precision * recall) / (precision + recall)
            return {"score": f1}
            
        return {"score": 0.0}


# ==================== Markdown Report Generator ====================

class ScorecardGenerator:
    """Generates Markdown scorecard from analysis results."""
    
    def generate(self, stats: dict, meta: dict, error_samples: list = None) -> str:
        """Generate a comprehensive Markdown scorecard."""
        lines = []
        
        # Header
        model_name = meta.get("model", "Unknown Model")
        lines.append(f"# NetConfigQA Evaluation Scorecard\n")
        lines.append(f"> **Model**: `{model_name}`  ")
        lines.append(f"> **Date**: {meta.get('date', datetime.now().isoformat())}  ")
        lines.append(f"> **Dataset**: `{meta.get('dataset', 'Unknown')}`\n")
        
        
        # Overall Score with all metrics
        lines.append("## 📊 Overall Performance\n")
        lines.append("| Metric | Value |")
        lines.append("|--------|-------|")
        lines.append(f"| **Type-Aware Accuracy** | **{stats['accuracy']*100:.2f}%** |")
        
        trad_metrics = stats.get('traditional_metrics', {})
        lines.append(f"| Exact Match (EM) | {trad_metrics.get('exact_match', 0)*100:.2f}% |")
        lines.append(f"| Token F1 | {trad_metrics.get('token_f1', 0)*100:.2f}% |")
        lines.append(f"| BERTScore F1 | {trad_metrics.get('bertscore_f1', 0)*100:.2f}% |")
        lines.append(f"| ROUGE-L | {trad_metrics.get('rougeL', 0)*100:.2f}% |")
        lines.append(f"| ROUGE-1 | {trad_metrics.get('rouge1', 0)*100:.2f}% |")
        lines.append(f"| ROUGE-2 | {trad_metrics.get('rouge2', 0)*100:.2f}% |")
        lines.append(f"| Total Samples | {stats['total_samples']} |")
        lines.append(f"| Inference Time | {meta.get('duration', 0):.1f}s |")
        lines.append("")
        
        # Metric Comparison by Answer Type
        lines.append("## 📊 Metric Comparison by Answer Type\n")
        lines.append("| Metric | Number | Numeric | Set | Map | Text | **Overall** |")
        lines.append("|--------|--------|---------|-----|-----|------|-------------|")
        
        # Type-Aware row
        ta_row = "| **Type-Aware** |"
        for atype in ['number', 'numeric', 'set', 'map', 'text']:
            ta_row += f" {stats['by_type'].get(atype, 0)*100:.1f}% |"
        ta_row += f" **{stats['accuracy']*100:.1f}%** |"
        lines.append(ta_row)
        
        # Traditional metrics rows
        trad_by_type = stats.get('trad_by_type', {})
        for metric_name, metric_label in [
            ('exact_match', 'Exact Match'),
            ('token_f1', 'Token F1'),
            ('bertscore_f1', 'BERTScore F1'),
            ('rougeL', 'ROUGE-L')
        ]:
            row = f"| {metric_label} |"
            for atype in ['number', 'numeric', 'set', 'map', 'text']:
                val = trad_by_type.get(atype, {}).get(metric_name, 0) * 100
                row += f" {val:.1f}% |"
            overall_val = trad_metrics.get(metric_name, 0) * 100
            row += f" {overall_val:.1f}% |"
            lines.append(row)
        
        lines.append("")
        
        # By Level
        lines.append("## 📈 Type-Aware Accuracy by Difficulty Level\n")
        lines.append("| Level | Description | Accuracy | Status |")
        lines.append("|-------|-------------|----------|--------|")
        level_desc = {
            'L1': 'Single Device Extraction',
            'L2': 'Multi-Device Aggregation',
            'L3': 'Cross-Device Comparison',
            'L4': 'Reachability Analysis',
            'L5': 'What-If Analysis'
        }
        for level in ['L1', 'L2', 'L3', 'L4', 'L5']:
            acc = stats['by_level'].get(level, 0) * 100
            desc = level_desc.get(level, '')
            status = "✅" if acc >= 70 else "⚠️" if acc >= 40 else "❌"
            lines.append(f"| {level} | {desc} | {acc:.1f}% | {status} |")
        lines.append("")
        
        # By Answer Type
        lines.append("## 📝 Accuracy by Answer Type\n")
        lines.append("| Type | Accuracy |")
        lines.append("|------|----------|")
        for atype, acc in sorted(stats['by_type'].items(), key=lambda x: x[1], reverse=True):
            lines.append(f"| {atype} | {acc*100:.1f}% |")
        lines.append("")
        
        # By Status (Positive/Negative Testing)
        lines.append("## 🔬 Positive vs Negative Testing\n")
        lines.append("| Test Type | Accuracy |")
        lines.append("|-----------|----------|")
        for status, acc in sorted(stats['by_status'].items()):
            label = "Positive (OK)" if status == "OK" else "Negative (NOT_CONFIGURED)"
            lines.append(f"| {label} | {acc*100:.1f}% |")
        lines.append("")
        
        # Error Analysis (if provided)
        if error_samples:
            lines.append("## ❌ Sample Errors\n")
            lines.append("| ID | Type | Gold | Pred | Score |")
            lines.append("|----|------|------|------|-------|")
            for e in error_samples[:15]:
                gold_short = e['gold'][:25] + "..." if len(e['gold']) > 25 else e['gold']
                pred_short = e['pred'][:25] + "..." if len(e['pred']) > 25 else e['pred']
                lines.append(f"| {e['id']} | {e['type']} | `{gold_short}` | `{pred_short}` | {e['score']:.2f} |")
            lines.append("")
        
        # Footer
        lines.append("---")
        lines.append(f"*Generated by NetConfigQA Analyzer on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}*")
        
        return "\n".join(lines)


# ==================== Main Analyzer ====================

def analyze_results(json_file: str, verbose: bool = False):
    """메인 분석 함수"""
    
    with open(json_file, 'r', encoding='utf-8') as f:
        data = json.load(f)

    scorer = NetConfigQAScorer()
    trad_calc = TraditionalMetricsCalculator()
    results = []
    
    # 통계 수집용
    grouped_by_type = defaultdict(list)
    grouped_by_level = defaultdict(list)
    grouped_by_category = defaultdict(list)
    grouped_by_status = defaultdict(list)
    
    # Traditional metrics 통계
    trad_metrics_by_type = defaultdict(lambda: defaultdict(list))
    
    error_samples = []
    
    # BERTScore를 위한 배치 데이터
    all_preds = []
    all_golds = []
    
    print(f"Analyzing {len(data['results'])} results...")
    print(f"[Step 1/3] Calculating Type-Aware and Traditional metrics...")

    for row in data['results']:
        # 필드명 호환성 처리 (raw_pred vs pred, answer_type vs type, answer_status vs status)
        raw_pred = row.get('raw_pred', row.get('pred', ''))
        answer_type = row.get('answer_type', row.get('type', 'text'))
        status = row.get('answer_status', row.get('status', 'OK'))
        level = row.get('level', 'L1')
        category = row.get('category', 'General')
        
        # 전처리 (answer_type 전달)
        clean_pred = scorer.clean_prediction(raw_pred, answer_type)
        clean_gold = scorer.clean_gold(row['gold'])
        
        # Type-Aware 점수 계산
        type_aware_metrics = scorer.score(clean_pred, row['gold'], answer_type)
        type_aware_score = type_aware_metrics['score']
        
        # Traditional metrics 계산
        trad_metrics = trad_calc.calculate_all(clean_pred, clean_gold)
        
        # 결과 저장
        result = {
            "question_id": row.get('question_id', ''),
            "question": row['question'],
            "gold": row['gold'],
            "gold_cleaned": clean_gold,
            "raw_pred": raw_pred,
            "pred": clean_pred,
            "type_aware_score": type_aware_score,  # Renamed from 'score'
            "level": level,
            "category": category,
            "type": answer_type,
            "status": status,
        }
        
        # Type-Aware 추가 메트릭 (f1, precision, recall 등)
        result.update({f"type_aware_{k}": v for k, v in type_aware_metrics.items() if k != 'score'})
        
        # Traditional metrics 추가
        result.update(trad_metrics)
        
        results.append(result)
        
        # 그룹별 통계 (Type-Aware)
        grouped_by_type[answer_type].append(type_aware_score)
        grouped_by_level[level].append(type_aware_score)
        grouped_by_category[category].append(type_aware_score)
        grouped_by_status[status].append(type_aware_score)
        
        # Traditional metrics 통계
        for metric_name, metric_value in trad_metrics.items():
            trad_metrics_by_type[answer_type][metric_name].append(metric_value)
        
        # BERTScore 배치용 데이터
        all_preds.append(clean_pred if clean_pred else "[empty]")
        all_golds.append(clean_gold if clean_gold else "[empty]")
        
        # 오류 샘플 수집
        if type_aware_score < 0.99 and len(error_samples) < 20:
            error_samples.append({
                "id": row.get('question_id', '?'),
                "question": row['question'][:60] + "..." if len(row['question']) > 60 else row['question'],
                "gold": clean_gold[:40] if clean_gold else "(empty)",
                "pred": clean_pred[:40] if clean_pred else "(empty)",
                "type": answer_type,
                "score": type_aware_score
            })


    # BERTScore 계산 (배치 처리)
    print(f"[Step 2/3] Calculating BERTScore (batch processing)...")
    if BERTSCORE_AVAILABLE and all_preds and all_golds:
        try:
            P, R, F1 = bert_score(all_preds, all_golds, lang='en', verbose=False, device='cpu')
            for i, result in enumerate(results):
                result['bertscore_precision'] = P[i].item()
                result['bertscore_recall'] = R[i].item()
                result['bertscore_f1'] = F1[i].item()
                
                # BERTScore 통계에도 추가
                answer_type = result['type']
                trad_metrics_by_type[answer_type]['bertscore_f1'].append(F1[i].item())
            print(f"   [OK] BERTScore calculated for {len(results)} samples")
        except Exception as e:
            print(f"   [WARNING] BERTScore calculation failed: {e}")
            for result in results:
                result['bertscore_precision'] = 0.0
                result['bertscore_recall'] = 0.0
                result['bertscore_f1'] = 0.0
    else:
        if not BERTSCORE_AVAILABLE:
            print("   [WARNING] BERTScore not available (install with: pip install bert-score)")
        for result in results:
            result['bertscore_precision'] = 0.0
            result['bertscore_recall'] = 0.0
            result['bertscore_f1'] = 0.0

    n = len(results)
    total_score = sum(r['type_aware_score'] for r in results)
    avg_acc = total_score / n if n > 0 else 0
    
    # Traditional metrics의 overall 평균 계산
    overall_trad_metrics = {}
    for metric_name in ['exact_match', 'token_f1', 'rouge1', 'rouge2', 'rougeL', 'bertscore_f1']:
        all_values = [r.get(metric_name, 0.0) for r in results]
        overall_trad_metrics[metric_name] = sum(all_values) / len(all_values) if all_values else 0.0
    
    # 통계 빌드
    stats = {
        "accuracy": avg_acc,
        "total_samples": n,
        "by_type": {t: sum(s)/len(s) for t, s in grouped_by_type.items()},
        "by_level": {l: sum(s)/len(s) for l, s in grouped_by_level.items()},
        "by_category": {c: sum(s)/len(s) for c, s in grouped_by_category.items()},
        "by_status": {s: sum(sc)/len(sc) for s, sc in grouped_by_status.items()},
        "traditional_metrics": overall_trad_metrics,
        "trad_by_type": {
            atype: {
                metric: sum(vals)/len(vals) if vals else 0.0 
                for metric, vals in metrics_dict.items()
            }
            for atype, metrics_dict in trad_metrics_by_type.items()
        }
    }
    
    # 결과 출력
    print(f"[Step 3/3] Generating reports...")
    print("\n" + "="*80)
    print(" " * 25 + "ANALYSIS RESULTS")
    print("="*80)
    
    # Overall scores
    print(f"\n{'Metric':<25} {'Score':>10}")
    print("-" * 40)
    print(f"{'Type-Aware Accuracy':<25} {avg_acc:>9.2%}")
    print(f"{'Exact Match':<25} {overall_trad_metrics.get('exact_match', 0):>9.2%}")
    print(f"{'Token F1':<25} {overall_trad_metrics.get('token_f1', 0):>9.2%}")
    print(f"{'BERTScore F1':<25} {overall_trad_metrics.get('bertscore_f1', 0):>9.2%}")
    print(f"{'ROUGE-L':<25} {overall_trad_metrics.get('rougeL', 0):>9.2%}")
    print(f"{'ROUGE-1':<25} {overall_trad_metrics.get('rouge1', 0):>9.2%}")
    print(f"{'ROUGE-2':<25} {overall_trad_metrics.get('rouge2', 0):>9.2%}")
    
    print(f"\n[Type-Aware Score by Answer Type]")
    for t in sorted(grouped_by_type.keys()):
        scores = grouped_by_type[t]
        print(f"   {t:12s}: {sum(scores)/len(scores):.2%} (n={len(scores)})")
    
    print(f"\n[Type-Aware Score by Level]")
    for lvl in sorted(grouped_by_level.keys()):
        scores = grouped_by_level[lvl]
        print(f"   {lvl:5s}: {sum(scores)/len(scores):.2%} (n={len(scores)})")
    
    print(f"\n[Type-Aware Score by Status]")
    for status in sorted(grouped_by_status.keys()):
        scores = grouped_by_status[status]
        print(f"   {status:15s}: {sum(scores)/len(scores):.2%} (n={len(scores)})")
    
    if verbose and error_samples:
        print(f"\n[Sample Errors (first {len(error_samples)})]")
        for i, e in enumerate(error_samples[:10], 1):
            print(f"\n   [{i}] ID: {e['id']} | Type: {e['type']} | Score: {e['score']:.2f}")
            print(f"       Q: {e['question']}")
            print(f"       Gold: {e['gold']}")
            print(f"       Pred: {e['pred']}")

    # 결과 저장 (JSON)
    output_file = json_file.replace(".json", "_analyzed.json")
    if "_raw_" in json_file:
        output_file = json_file.replace("_raw_", "_analyzed_")
    
    meta = data.get("meta", {})
    output_data = {
        "meta": meta,
        "stats": stats,
        "results": results
    }
    
    with open(output_file, 'w', encoding='utf-8') as f:
        json.dump(output_data, f, indent=2, ensure_ascii=False)
    
    print(f"\n[OK] Saved analyzed results to: {output_file}")

    # 에러 결과만 따로 저장 (Manual verification용)
    error_results = [r for r in results if r['type_aware_score'] < 1.0]
    error_output_file = output_file.replace(".json", "_errors.json")
    error_output_data = {
        "meta": meta,
        "count": len(error_results),
        "results": error_results
    }
    with open(error_output_file, 'w', encoding='utf-8') as f:
        json.dump(error_output_data, f, indent=2, ensure_ascii=False)
    print(f"[OK] Saved error samples to: {error_output_file}")
    
    # CSV 파일 저장 (per-question detailed results)
    csv_file = output_file.replace(".json", "_detailed.csv")
    with open(csv_file, 'w', newline='', encoding='utf-8-sig') as csvf:
        if results:
            fieldnames = ['question_id', 'level', 'category', 'type', 'status', 
                         'question', 'gold', 'pred',
                         'type_aware_score', 'exact_match', 'token_f1', 
                         'bertscore_f1', 'rougeL', 'rouge1', 'rouge2']
            writer = csv.DictWriter(csvf, fieldnames=fieldnames, extrasaction='ignore')
            writer.writeheader()
            for r in results:
                writer.writerow(r)
    
    print(f"[OK] Saved detailed CSV to: {csv_file}")
    
    # Markdown 채점표 저장
    scorecard_file = output_file.replace(".json", "_scorecard.md")
    scorecard_gen = ScorecardGenerator()
    scorecard_md = scorecard_gen.generate(stats, meta, error_samples)
    
    with open(scorecard_file, 'w', encoding='utf-8') as f:
        f.write(scorecard_md)
    
    print(f"[OK] Saved scorecard to: {scorecard_file}")
    print(f"\n[TIP] Run 'python Figure.py \"{output_file}\"' to generate visualizations.")
    
    return stats, results


def main():
    parser = argparse.ArgumentParser(description="Analyze NetConfigQA evaluation results")
    parser.add_argument("json_file", help="Path to results json (raw or already analyzed)")
    parser.add_argument("--verbose", "-v", action="store_true", help="Show detailed error analysis")
    args = parser.parse_args()

    analyze_results(args.json_file, args.verbose)


if __name__ == "__main__":
    main()
