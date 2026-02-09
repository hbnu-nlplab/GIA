# evaluation_utils.py
import json
import re
import math
from collections import Counter
from typing import List, Dict, Any, Set, Union

# --- Optional Libraries (설치 안되어 있어도 기본 기능 동작하도록 처리) ---
try:
    from rouge_score import rouge_scorer
    ROUGE_AVAILABLE = True
except ImportError:
    ROUGE_AVAILABLE = False
    print("[Info] rouge-score not found. ROUGE metrics will be skipped.")

try:
    from bert_score import score as bert_score
    BERTSCORE_AVAILABLE = True
except ImportError:
    BERTSCORE_AVAILABLE = False
    print("[Info] bert-score not found. BERTScore will be skipped.")

try:
    import nltk
    from nltk.translate.bleu_score import sentence_bleu, SmoothingFunction
    NLTK_AVAILABLE = True
except ImportError:
    NLTK_AVAILABLE = False
    print("[Info] nltk not found. BLEU will be skipped.")


class RobustCleaner:
    """상대방 코드의 강력한 전처리 로직을 통합한 클래스"""
    
    @staticmethod
    def canonical_answer_type(answer_type: str) -> str:
        if answer_type is None: return 'text'
        atype = str(answer_type).strip().lower()
        aliases = {
            'numbers': 'number', 'num': 'numeric', 'int': 'number', 'integer': 'number', 'float': 'numeric',
            'list_str': 'set', 'set_string': 'set', 'list': 'set',
            'dict': 'map', 'dictionary': 'map', 'json': 'map'
        }
        return aliases.get(atype, atype)

    @staticmethod
    def extract_number(val: str) -> float:
        """텍스트에서 숫자를 강력하게 추출 (English word conversion 포함)"""
        try:
            # 1. 숫자 직접 추출
            match = re.search(r'-?\d+(\.\d+)?', val)
            if match: return float(match.group())
            
            # 2. 영단어 -> 숫자 변환
            word_to_num = {
                'zero': 0, 'one': 1, 'two': 2, 'three': 3, 'four': 4,
                'five': 5, 'six': 6, 'seven': 7, 'eight': 8, 'nine': 9,
                'ten': 10, 'eleven': 11, 'twelve': 12, 'twenty': 20,
                'thirty': 30, 'forty': 40, 'fifty': 50, 'hundred': 100
            }
            val_lower = val.lower()
            for word, num in word_to_num.items():
                if re.search(r'\b' + word + r'\b', val_lower):
                    return float(num)
            return None
        except:
            return None

    @classmethod
    def clean(cls, pred: str, answer_type: str = "text") -> str:
        """모델의 Raw Output을 정답 포맷으로 정제"""
        if not pred: return ""
        pred = str(pred)
        answer_type = cls.canonical_answer_type(answer_type)
        original_pred = pred

        # 1. <think> 태그 및 잡다한 구분자 처리
        if '</think>' in pred:
            pred = pred.split('</think>')[-1].strip()
        elif 'assistantfinal' in pred:
            parts = pred.split('assistantfinal')
            pred = parts[-1].strip()
            if pred.startswith('think'): pred = pred[5:].strip()
        elif '<think>' in pred: # 닫는 태그 없이 잘린 경우
            pred = pred.split('<think>')[0].strip()

        # 2. 불필요한 서술어 제거
        prefixes = [
            r'^analysis\s*', r'^the answer is\s*', r'^answer:\s*', 
            r'^result:\s*', r'^output:\s*', r'^based on.*[,:]\s*',
            r'^we need to\s*', r'^json\s*', r'^set\s*', r'^map\s*'
        ]
        for pat in prefixes:
            pred = re.sub(pat, '', pred, flags=re.IGNORECASE | re.MULTILINE).strip()

        # 3. Markdown 제거
        pred = re.sub(r"```.*?```", "", pred, flags=re.DOTALL).strip()
        pred = pred.replace("```json", "").replace("```", "").strip()
        
        # 4. 타입별 특화 처리
        # [Set/Map] JSON 파싱 시도
        if answer_type == "set":
        # JSON 배열 파싱 시도
        match = re.search(r'\[.*?\]', first_line)
        if match:
            try:
                parsed = json.loads(match.group(0))
                return json.dumps(parsed)
            except:
                pass
        return "[]"
    
        elif answer_type == "map":
            # JSON 객체 파싱 시도
            match = re.search(r'\{.*?\}', first_line)
            if match:
                try:
                    parsed = json.loads(match.group(0))
                    return json.dumps(parsed)
                except:
                    pass
            return "{}"
        
        elif answer_type in ["number", "numeric"]:
            # 숫자만 추출
            match = re.search(r'-?\d+\.?\d*', first_line)
            if match:
                return match.group(0)
            return "0"
        
        elif answer_type == "boolean":
            # true/false 추출
            lower = first_line.lower()
            if 'true' in lower or 'yes' in lower:
                return "true"
            elif 'false' in lower or 'no' in lower:
                return "false"
            return "false"
    
        else:  # text
            # 따옴표나 불필요한 문장 제거
            text = first_line.strip('"\'')
            # 문장 형태면 첫 단어/구문만 추출
            if len(text.split()) > 5:
                # 너무 긴 설명이면 첫 단어만
                text = text.split()[0]
            # Cisco-specific: 'login local' -> 'local'
            if text.lower() == 'login local':
                text = 'local'
    return text


import ast
import re

class TypeAwareScorer:
    def parse_structure(self, text, type_hint):
        """모델의 문자열 출력을 파이썬 객체(List, Dict)로 안전하게 변환"""
        text = text.strip()
        
        # 1. 전처리: Markdown 코드 블록 제거 등
        text = text.replace("```json", "").replace("```", "").strip()
        
        try:
            # 안전하게 파싱 시도 (ast.literal_eval 사용)
            parsed = ast.literal_eval(text)
            
            if type_hint == 'set' and isinstance(parsed, list):
                return set(str(x).lower().strip() for x in parsed) # 대소문자 무시
            elif type_hint == 'map' and isinstance(parsed, dict):
                # Key와 Value 모두 소문자 처리하여 정규화
                return {str(k).lower().strip(): str(v).lower().strip() for k, v in parsed.items()}
            return parsed
        except:
            # 파싱 실패 시, 정규표현식으로 억지 추출 (Fallback)
            if type_hint == 'set':
                # 따옴표 안의 내용이나 숫자 추출
                items = re.findall(r"['\"](.*?)['\"]|(\d+\.\d+\.\d+\.\d+)|(\w+)", text)
                flat_items = [item for group in items for item in group if item]
                return set(str(x).lower().strip() for x in flat_items)
            return None

    def compute_jaccard(self, pred_set, gold_set):
        """집합 간의 Jaccard 유사도 계산 (0.0 ~ 1.0)"""
        if not pred_set and not gold_set:
            return 1.0  # 둘 다 비어있으면 정답
        if not pred_set or not gold_set:
            return 0.0  # 둘 중 하나만 비어있으면 오답
            
        intersection = len(pred_set.intersection(gold_set))
        union = len(pred_set.union(gold_set))
        return intersection / union if union > 0 else 0.0

    def score(self, prediction, reference, answer_type):
        """타입별 맞춤 점수 계산"""
        if answer_type == 'numeric':
            # (기존 로직 유지: 숫자 추출 후 오차 범위 비교)
            try:
                p_num = float(re.search(r'-?\d+\.?\d*', str(prediction)).group())
                r_num = float(re.search(r'-?\d+\.?\d*', str(reference)).group())
                return 1.0 if abs(p_num - r_num) < 1e-6 else 0.0
            except:
                return 0.0

        elif answer_type == 'set':
            # [NEW] Set 전용 평가 (순서 무관, Jaccard Similarity)
            pred_obj = self.parse_structure(prediction, 'set')
            gold_obj = self.parse_structure(reference, 'set')
            
            if pred_obj is None: return 0.0
            return self.compute_jaccard(pred_obj, gold_obj)

        elif answer_type == 'map':
            # [NEW] Map 전용 평가 (Key-Value 쌍 비교)
            pred_obj = self.parse_structure(prediction, 'map')
            gold_obj = self.parse_structure(reference, 'map')
            
            if pred_obj is None or not isinstance(pred_obj, dict): return 0.0
            
            # Dict를 (Key, Value) 튜플의 집합으로 변환하여 Jaccard 계산
            pred_items = set(pred_obj.items())
            gold_items = set(gold_obj.items())
            
            return self.compute_jaccard(pred_items, gold_items)

        else:
            # Text, etc. (기존 F1/EM 사용 권장하지만 여기선 간단히 포함여부/EM)
            norm_p = str(prediction).lower().strip()
            norm_r = str(reference).lower().strip()
            return 1.0 if norm_p == norm_r else 0.0

class MetricsCalculator:
    """ROUGE, BLEU, EM 등 전통적 지표 계산"""
    def __init__(self):
        self.rouge = rouge_scorer.RougeScorer(['rouge1', 'rouge2', 'rougeL'], use_stemmer=True) if ROUGE_AVAILABLE else None

    def compute(self, pred: str, gold: str):
        pred = str(pred).lower().strip()
        gold = str(gold).lower().strip()
        
        res = {'exact_match': 1.0 if pred == gold else 0.0}
        
        # Token F1
        p_toks = pred.split()
        g_toks = gold.split()
        common = Counter(p_toks) & Counter(g_toks)
        num_same = sum(common.values())
        if len(p_toks) == 0 or len(g_toks) == 0:
            res['token_f1'] = 1.0 if len(p_toks) == len(g_toks) else 0.0
        else:
            prec = num_same / len(p_toks)
            rec = num_same / len(g_toks)
            res['token_f1'] = 2 * prec * rec / (prec + rec) if (prec + rec) > 0 else 0.0

        # ROUGE
        if self.rouge:
            scores = self.rouge.score(gold, pred)
            res['rouge1'] = scores['rouge1'].fmeasure
            res['rouge2'] = scores['rouge2'].fmeasure
            res['rougeL'] = scores['rougeL'].fmeasure
        
        # BLEU
        if NLTK_AVAILABLE:
            smooth = SmoothingFunction().method1
            try:
                res['bleu'] = sentence_bleu([g_toks], p_toks, smoothing_function=smooth)
            except:
                res['bleu'] = 0.0
                
        return res

def evaluate_results(results_list: List[Dict]):
    """
    최종 결과 리스트를 받아 종합 분석 리포트 생성
    results_list item 구조: {'question':..., 'gold':..., 'pred':..., 'answer_type':...}
    """
    scorer = TypeAwareScorer()
    metric_calc = MetricsCalculator()
    
    total_stats = {
        'count': 0, 'type_aware_acc': 0.0, 
        'em': 0.0, 'token_f1': 0.0, 'rougeL': 0.0, 'bleu': 0.0,
        'by_type': {}
    }
    
    analyzed_results = []
    
    for item in results_list:
        atype = RobustCleaner.canonical_answer_type(item.get('answer_type', 'text'))
        gold = str(item.get('gold', ''))
        pred = str(item.get('pred', ''))
        
        # Type-Aware Score
        ta_score = scorer.score(pred, gold, atype)
        
        # Traditional Metrics
        trad_scores = metric_calc.compute(pred, gold)
        
        # Aggregate
        total_stats['count'] += 1
        total_stats['type_aware_acc'] += ta_score
        total_stats['em'] += trad_scores.get('exact_match', 0)
        total_stats['token_f1'] += trad_scores.get('token_f1', 0)
        total_stats['rougeL'] += trad_scores.get('rougeL', 0)
        total_stats['bleu'] += trad_scores.get('bleu', 0)
        
        if atype not in total_stats['by_type']:
            total_stats['by_type'][atype] = {'sum': 0.0, 'count': 0}
        total_stats['by_type'][atype]['sum'] += ta_score
        total_stats['by_type'][atype]['count'] += 1
        
        analyzed_results.append({
            **item,
            'clean_pred': RobustCleaner.clean(pred, atype),
            'score': ta_score,
            'metrics': trad_scores
        })

    # Averages
    n = total_stats['count'] if total_stats['count'] > 0 else 1
    summary = {
        'total_samples': n,
        'Type-Aware Accuracy': total_stats['type_aware_acc'] / n,
        'Exact Match': total_stats['em'] / n,
        'Token F1': total_stats['token_f1'] / n,
        'ROUGE-L': total_stats['rougeL'] / n,
        'BLEU': total_stats['bleu'] / n,
        'By Type': {k: v['sum']/v['count'] for k, v in total_stats['by_type'].items()}
    }
    
    return summary, analyzed_results