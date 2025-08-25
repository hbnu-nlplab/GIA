"""
Multi-Modal Evaluation System for Network Configuration Q&A
EM, F1, BERT-Score, BLEU, ROUGE 지원
Short/Long Answer 구분 평가
"""

from __future__ import annotations
from typing import Dict, Any, List, Optional, Union, Tuple
from dataclasses import dataclass, asdict
from enum import Enum
import re
import json
import numpy as np
from collections import Counter
import string


class AnswerType(Enum):
    SHORT = "short"  # 단답형: 숫자, 짧은 텍스트, boolean
    LONG = "long"    # 서술형: 분석, 설명, 다단계 추론


@dataclass
class EvaluationResult:
    question_id: str
    answer_type: AnswerType
    predicted_answer: str
    ground_truth: str
    
    # 공통 메트릭
    exact_match: float
    f1_score: float
    
    # Short answer 메트릭
    token_accuracy: Optional[float] = None
    normalized_accuracy: Optional[float] = None
    
    # Long answer 메트릭
    bert_score: Optional[Dict[str, float]] = None
    bleu_score: Optional[float] = None
    rouge_scores: Optional[Dict[str, float]] = None
    
    # 구조적 메트릭 (JSON, XML 등)
    structural_accuracy: Optional[float] = None
    
    def overall_score(self) -> float:
        """전체 점수 계산 (가중평균)"""
        if self.answer_type == AnswerType.SHORT:
            return (self.exact_match * 0.4 + 
                   self.f1_score * 0.4 + 
                   (self.token_accuracy or 0) * 0.2)
        else:
            return (self.exact_match * 0.2 + 
                   self.f1_score * 0.3 + 
                   (self.bert_score.get('f1', 0) if self.bert_score else 0) * 0.3 +
                   (self.rouge_scores.get('rouge-l', {}).get('f', 0) if self.rouge_scores else 0) * 0.2)


class NetworkAnswerNormalizer:
    """네트워크 도메인 특화 답변 정규화"""
    
    def __init__(self):
        self.ip_pattern = re.compile(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b')
        self.as_pattern = re.compile(r'\bAS\s*(\d+)\b', re.IGNORECASE)
        self.interface_pattern = re.compile(r'\b(?:GigabitEthernet|FastEthernet|Ethernet|Loopback)[\d/\.]+\b', re.IGNORECASE)
        
    def normalize_answer(self, answer: str) -> str:
        """네트워크 답변 정규화"""
        if not isinstance(answer, str):
            answer = str(answer)
            
        # 1. 공백 및 특수문자 정리
        normalized = answer.strip().lower()
        
        # 2. 네트워크 엔티티 표준화
        # IP 주소 정규화 (선택적 서브넷 마스크 제거)
        normalized = re.sub(r'(\d+\.\d+\.\d+\.\d+)/\d+', r'\1', normalized)
        
        # AS 번호 정규화
        normalized = re.sub(r'as\s*(\d+)', r'as\1', normalized)
        
        # 인터페이스 이름 정규화
        normalized = re.sub(r'gigabitethernet', 'ge', normalized)
        normalized = re.sub(r'fastethernet', 'fe', normalized)
        
        # 3. Boolean 값 정규화
        bool_mappings = {
            'yes': 'true', 'no': 'false', '예': 'true', '아니오': 'false',
            'enabled': 'true', 'disabled': 'false', 'active': 'true', 'inactive': 'false',
            '활성': 'true', '비활성': 'false', '설정됨': 'true', '미설정': 'false'
        }
        for k, v in bool_mappings.items():
            normalized = normalized.replace(k, v)
            
        # 4. 숫자 표현 정규화
        normalized = re.sub(r'(\d+)개', r'\1', normalized)
        normalized = re.sub(r'(\d+)대', r'\1', normalized)
        
        return normalized.strip()
    
    def extract_entities(self, answer: str) -> Dict[str, List[str]]:
        """네트워크 엔티티 추출"""
        if not isinstance(answer, str):
            answer = str(answer)
        entities = {
            'ip_addresses': self.ip_pattern.findall(answer),
            'as_numbers': [m.group(1) for m in self.as_pattern.finditer(answer)],
            'interfaces': self.interface_pattern.findall(answer)
        }
        return entities
    
    def is_structured_answer(self, answer: str) -> bool:
        """구조화된 답변인지 판단 (JSON, XML, 리스트 등)"""
        # None 또는 원시 숫자 타입 보호
        if answer is None:
            return False
        # dict/list는 구조화된 것으로 간주
        if isinstance(answer, (dict, list)):
            return True
        try:
            s = answer.strip() if isinstance(answer, str) else str(answer).strip()
        except Exception:
            return False
        return (s.startswith('{') and s.endswith('}')) or \
               (s.startswith('[') and s.endswith(']')) or \
               (s.startswith('<') and s.endswith('>'))


class ExactMatchEvaluator:
    """Exact Match 평가기"""
    
    def __init__(self):
        self.normalizer = NetworkAnswerNormalizer()
    
    def evaluate(self, predicted: str, ground_truth: str) -> float:
        """정확한 일치 평가"""
        pred_norm = self.normalizer.normalize_answer(predicted)
        gt_norm = self.normalizer.normalize_answer(ground_truth)
        
        return 1.0 if pred_norm == gt_norm else 0.0
    
    def evaluate_fuzzy(self, predicted: str, ground_truth: str, threshold: float = 0.9) -> float:
        """유사도 기반 Fuzzy Exact Match"""
        pred_norm = self.normalizer.normalize_answer(predicted)
        gt_norm = self.normalizer.normalize_answer(ground_truth)
        
        if pred_norm == gt_norm:
            return 1.0
            
        # Levenshtein 유사도 계산
        similarity = self._levenshtein_similarity(pred_norm, gt_norm)
        return 1.0 if similarity >= threshold else 0.0
    
    def _levenshtein_similarity(self, s1: str, s2: str) -> float:
        """Levenshtein 거리 기반 유사도"""
        if len(s1) == 0:
            return 0.0 if len(s2) > 0 else 1.0
        if len(s2) == 0:
            return 0.0
            
        # 간단한 Levenshtein 거리 계산
        d = [[0] * (len(s2) + 1) for _ in range(len(s1) + 1)]
        
        for i in range(len(s1) + 1):
            d[i][0] = i
        for j in range(len(s2) + 1):
            d[0][j] = j
            
        for i in range(1, len(s1) + 1):
            for j in range(1, len(s2) + 1):
                cost = 0 if s1[i-1] == s2[j-1] else 1
                d[i][j] = min(
                    d[i-1][j] + 1,      # deletion
                    d[i][j-1] + 1,      # insertion
                    d[i-1][j-1] + cost  # substitution
                )
        
        max_len = max(len(s1), len(s2))
        return 1.0 - (d[len(s1)][len(s2)] / max_len)


class F1ScoreEvaluator:
    """F1 Score 평가기"""
    
    def __init__(self):
        self.normalizer = NetworkAnswerNormalizer()
    
    def evaluate(self, predicted: str, ground_truth: str) -> float:
        """토큰 기반 F1 Score"""
        pred_tokens = self._tokenize(predicted)
        gt_tokens = self._tokenize(ground_truth)
        
        if not gt_tokens:
            return 1.0 if not pred_tokens else 0.0
        if not pred_tokens:
            return 0.0
            
        pred_count = Counter(pred_tokens)
        gt_count = Counter(gt_tokens)
        
        # True Positives: 공통 토큰들
        overlap = pred_count & gt_count
        tp = sum(overlap.values())
        
        if tp == 0:
            return 0.0
            
        precision = tp / sum(pred_count.values())
        recall = tp / sum(gt_count.values())
        
        return 2 * precision * recall / (precision + recall)
    
    def evaluate_entity_f1(self, predicted: str, ground_truth: str) -> Dict[str, float]:
        """네트워크 엔티티별 F1 Score"""
        pred_entities = self.normalizer.extract_entities(predicted)
        gt_entities = self.normalizer.extract_entities(ground_truth)
        
        results = {}
        for entity_type in pred_entities.keys():
            pred_set = set(pred_entities[entity_type])
            gt_set = set(gt_entities[entity_type])
            
            if not gt_set:
                results[entity_type] = 1.0 if not pred_set else 0.0
                continue
            if not pred_set:
                results[entity_type] = 0.0
                continue
                
            tp = len(pred_set & gt_set)
            precision = tp / len(pred_set)
            recall = tp / len(gt_set)
            
            results[entity_type] = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0.0
            
        return results

    def _tokenize(self, text: str) -> List[str]:
        """네트워크 도메인 특화 토큰화 (개선된 버전)"""
        if not isinstance(text, str):
            text = str(text)
            
        normalized = self.normalizer.normalize_answer(text)
        
        # IP 주소와 같은 특수 엔티티를 먼저 플레이스홀더로 대체
        ip_addresses = self.normalizer.ip_pattern.findall(normalized)
        placeholders = {}
        for i, ip in enumerate(ip_addresses):
            placeholder = f" __IP{i}__ " # 양쪽에 공백 추가하여 단어 경계 보장
            placeholders[placeholder.strip()] = ip
            normalized = normalized.replace(ip, placeholder)

        # 공백 및 특수문자 기준으로 일반 토큰화
        tokens = re.findall(r'__IP\d+__|\w+', normalized)
        
        # 플레이스홀더를 원래 값으로 복원
        final_tokens = [placeholders.get(token, token) for token in tokens]
        
        return final_tokens


class BLEUEvaluator:
    """BLEU Score 평가기 (Long Answer용)"""
    
    def evaluate(self, predicted: str, ground_truth: str, max_n: int = 4) -> float:
        """BLEU Score 계산"""
        pred_tokens = self._tokenize(predicted)
        gt_tokens = self._tokenize(ground_truth)
        
        if not pred_tokens or not gt_tokens:
            return 0.0
        
        # Brevity Penalty
        bp = self._brevity_penalty(len(pred_tokens), len(gt_tokens))
        
        # N-gram precision scores
        precisions = []
        for n in range(1, max_n + 1):
            precision = self._ngram_precision(pred_tokens, gt_tokens, n)
            precisions.append(precision)
        
        # Geometric mean of precisions
        if all(p > 0 for p in precisions):
            geometric_mean = np.exp(np.mean(np.log(precisions)))
        else:
            geometric_mean = 0.0
            
        return bp * geometric_mean
    
    def _brevity_penalty(self, pred_len: int, ref_len: int) -> float:
        """Brevity Penalty 계산"""
        if pred_len >= ref_len:
            return 1.0
        else:
            return np.exp(1 - ref_len / pred_len)
    
    def _ngram_precision(self, pred_tokens: List[str], ref_tokens: List[str], n: int) -> float:
        """N-gram precision 계산"""
        pred_ngrams = self._get_ngrams(pred_tokens, n)
        ref_ngrams = self._get_ngrams(ref_tokens, n)
        
        if not pred_ngrams:
            return 0.0
            
        overlap = pred_ngrams & ref_ngrams
        return sum(overlap.values()) / sum(pred_ngrams.values())
    
    def _get_ngrams(self, tokens: List[str], n: int) -> Counter:
        """N-gram 추출"""
        ngrams = []
        for i in range(len(tokens) - n + 1):
            ngram = tuple(tokens[i:i+n])
            ngrams.append(ngram)
        return Counter(ngrams)
    
    def _tokenize(self, text: str) -> List[str]:
        """토큰화 (간단한 버전)"""
        if not isinstance(text, str):
            text = str(text)
        return text.lower().translate(str.maketrans('', '', string.punctuation)).split()


class ROUGEEvaluator:
    """ROUGE Score 평가기 (Long Answer용)"""
    
    def evaluate(self, predicted: str, ground_truth: str) -> Dict[str, Dict[str, float]]:
        """ROUGE-1, ROUGE-2, ROUGE-L 계산"""
        pred_tokens = self._tokenize(predicted)
        gt_tokens = self._tokenize(ground_truth)
        
        results = {}
        
        # ROUGE-1
        results['rouge-1'] = self._rouge_n(pred_tokens, gt_tokens, 1)
        
        # ROUGE-2
        results['rouge-2'] = self._rouge_n(pred_tokens, gt_tokens, 2)
        
        # ROUGE-L
        results['rouge-l'] = self._rouge_l(pred_tokens, gt_tokens)
        
        return results
    
    def _rouge_n(self, pred_tokens: List[str], ref_tokens: List[str], n: int) -> Dict[str, float]:
        """ROUGE-N 계산"""
        pred_ngrams = self._get_ngrams(pred_tokens, n)
        ref_ngrams = self._get_ngrams(ref_tokens, n)
        
        if not ref_ngrams:
            return {'precision': 0.0, 'recall': 0.0, 'f': 0.0}
        if not pred_ngrams:
            return {'precision': 0.0, 'recall': 0.0, 'f': 0.0}
            
        overlap = pred_ngrams & ref_ngrams
        overlap_count = sum(overlap.values())
        
        precision = overlap_count / sum(pred_ngrams.values())
        recall = overlap_count / sum(ref_ngrams.values())
        
        f_score = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0.0
        
        return {'precision': precision, 'recall': recall, 'f': f_score}
    
    def _rouge_l(self, pred_tokens: List[str], ref_tokens: List[str]) -> Dict[str, float]:
        """ROUGE-L (Longest Common Subsequence) 계산"""
        lcs_length = self._lcs_length(pred_tokens, ref_tokens)
        
        if len(ref_tokens) == 0:
            recall = 1.0 if len(pred_tokens) == 0 else 0.0
        else:
            recall = lcs_length / len(ref_tokens)
            
        if len(pred_tokens) == 0:
            precision = 1.0 if len(ref_tokens) == 0 else 0.0
        else:
            precision = lcs_length / len(pred_tokens)
        
        f_score = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0.0
        
        return {'precision': precision, 'recall': recall, 'f': f_score}
    
    def _lcs_length(self, seq1: List[str], seq2: List[str]) -> int:
        """Longest Common Subsequence 길이 계산"""
        m, n = len(seq1), len(seq2)
        dp = [[0] * (n + 1) for _ in range(m + 1)]
        
        for i in range(1, m + 1):
            for j in range(1, n + 1):
                if seq1[i-1] == seq2[j-1]:
                    dp[i][j] = dp[i-1][j-1] + 1
                else:
                    dp[i][j] = max(dp[i-1][j], dp[i][j-1])
        
        return dp[m][n]
    
    def _get_ngrams(self, tokens: List[str], n: int) -> Counter:
        """N-gram 추출"""
        ngrams = []
        for i in range(len(tokens) - n + 1):
            ngram = tuple(tokens[i:i+n])
            ngrams.append(ngram)
        return Counter(ngrams)
    
    def _tokenize(self, text: str) -> List[str]:
        """토큰화"""
        if not isinstance(text, str):
            text = str(text)
        return text.lower().translate(str.maketrans('', '', string.punctuation)).split()


class ComprehensiveEvaluator:
    """통합 평가 시스템"""
    
    def __init__(self):
        self.normalizer = NetworkAnswerNormalizer()
        self.em_evaluator = ExactMatchEvaluator()
        self.f1_evaluator = F1ScoreEvaluator()
        self.bleu_evaluator = BLEUEvaluator()
        self.rouge_evaluator = ROUGEEvaluator()
    
    def evaluate_single(
        self, 
        predicted: str, 
        ground_truth: str, 
        question_id: str,
        answer_type: str = "auto"
    ) -> EvaluationResult:
        """단일 답변 종합 평가"""
        
        # Answer Type 자동 감지
        if answer_type == "auto":
            detected_type = self._detect_answer_type(predicted, ground_truth)
        else:
            detected_type = AnswerType(answer_type)
        
        # 기본 메트릭 계산
        em_score = self.em_evaluator.evaluate(predicted, ground_truth)
        f1_score = self.f1_evaluator.evaluate(predicted, ground_truth)
        
        result = EvaluationResult(
            question_id=question_id,
            answer_type=detected_type,
            predicted_answer=predicted,
            ground_truth=ground_truth,
            exact_match=em_score,
            f1_score=f1_score
        )
        
        # Answer Type별 추가 메트릭
        if detected_type == AnswerType.SHORT:
            result.token_accuracy = self._calculate_token_accuracy(predicted, ground_truth)
            result.normalized_accuracy = self.em_evaluator.evaluate_fuzzy(predicted, ground_truth)
        else:
            # Long answer 메트릭
            result.bleu_score = self.bleu_evaluator.evaluate(predicted, ground_truth)
            result.rouge_scores = self.rouge_evaluator.evaluate(predicted, ground_truth)
            
        # 구조화된 답변 처리
        if self.normalizer.is_structured_answer(predicted) or self.normalizer.is_structured_answer(ground_truth):
            result.structural_accuracy = self._evaluate_structural_accuracy(predicted, ground_truth)
        
        return result
    
    def evaluate_batch(
        self,
        predictions: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """배치 평가 및 통계 계산"""
        results = []
        
        for pred_data in predictions:
            result = self.evaluate_single(
                pred_data['predicted'],
                pred_data['ground_truth'],
                pred_data['question_id'],
                pred_data.get('answer_type', 'auto')
            )
            results.append(result)
        
        # 통계 계산
        stats = self._calculate_batch_statistics(results)
        
        return {
            'individual_results': results,
            'overall_statistics': stats,
            'short_answer_stats': self._filter_stats(results, AnswerType.SHORT),
            'long_answer_stats': self._filter_stats(results, AnswerType.LONG)
        }

    def evaluate_dataset(
        self,
        predictions: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """데이터셋 전체 평가"""
        batch_result = self.evaluate_batch(predictions)

        processed: List[Dict[str, Any]] = []
        for res in batch_result['individual_results']:
            res_dict = asdict(res)
            res_dict['overall_score'] = res.overall_score()
            processed.append(res_dict)

        avg_score = float(np.mean([r['overall_score'] for r in processed])) if processed else 0.0
        batch_result['individual_results'] = processed
        batch_result['overall_statistics']['average_overall_score'] = avg_score

        return self._to_serializable(batch_result)
    
    def _detect_answer_type(self, predicted: str, ground_truth: str) -> AnswerType:
        """답변 타입 자동 감지"""
        texts = [predicted, ground_truth]
        
        for text in texts:
            if not isinstance(text, str):
                text = str(text)
                
            # 토큰 수 기반 판단
            tokens = text.split()
            if len(tokens) > 20:  # 20단어 이상이면 long
                return AnswerType.LONG
                
            # 구조화된 데이터면 일반적으로 short
            if self.normalizer.is_structured_answer(text):
                return AnswerType.SHORT
                
            # 문장 수 기반 판단
            sentences = re.split(r'[.!?]+', text)
            if len([s for s in sentences if s.strip()]) > 2:
                return AnswerType.LONG
        
        return AnswerType.SHORT
    
    def _calculate_token_accuracy(self, predicted: str, ground_truth: str) -> float:
        """토큰 수준 정확도"""
        pred_tokens = set(self.f1_evaluator._tokenize(predicted))
        gt_tokens = set(self.f1_evaluator._tokenize(ground_truth))
        
        if not gt_tokens:
            return 1.0 if not pred_tokens else 0.0
            
        return len(pred_tokens & gt_tokens) / len(gt_tokens)
    
    def _evaluate_structural_accuracy(self, predicted: str, ground_truth: Any) -> float:
        """구조화된 답변의 정확도 평가"""
        try:
            # 문자열 캐스팅 (필요 시)
            gt_is_str = isinstance(ground_truth, str)
            gt_str = ground_truth if gt_is_str else str(ground_truth)

            # JSON 객체 비교 준비
            pred_obj = None
            gt_obj = None
            if isinstance(predicted, dict):
                pred_obj = predicted
            elif isinstance(predicted, str):
                s = predicted.strip()
                if s.startswith('{') and s.endswith('}'):
                    pred_obj = json.loads(s)
            # ground truth
            if isinstance(ground_truth, dict):
                gt_obj = ground_truth
            elif gt_is_str:
                sgt = gt_str.strip()
                if sgt.startswith('{') and sgt.endswith('}'):
                    gt_obj = json.loads(sgt)
            if pred_obj is not None and gt_obj is not None:
                return self._compare_json_objects(pred_obj, gt_obj)

            # 리스트 비교 준비
            pred_list = None
            gt_list = None
            if isinstance(predicted, list):
                pred_list = predicted
            elif isinstance(predicted, str):
                s = predicted.strip()
                if s.startswith('[') and s.endswith(']'):
                    pred_list = json.loads(s)
            if isinstance(ground_truth, list):
                gt_list = ground_truth
            elif gt_is_str:
                sgt = gt_str.strip()
                if sgt.startswith('[') and sgt.endswith(']'):
                    gt_list = json.loads(sgt)
            if pred_list is not None and gt_list is not None:
                return self._compare_lists(pred_list, gt_list)
                
        except (json.JSONDecodeError, AttributeError, TypeError, ValueError):
            pass
        
        # 구조화 실패시 일반 문자열 비교
        return self.em_evaluator.evaluate(predicted, gt_str)
    
    def _compare_json_objects(self, pred: Dict, gt: Dict) -> float:
        """JSON 객체 비교"""
        if not isinstance(pred, dict) or not isinstance(gt, dict):
            return 0.0
            
        gt_keys = set(gt.keys())
        pred_keys = set(pred.keys())
        
        if not gt_keys:
            return 1.0 if not pred_keys else 0.0
            
        # 키 일치도
        key_accuracy = len(pred_keys & gt_keys) / len(gt_keys)
        
        # 값 일치도
        value_matches = 0
        for key in gt_keys:
            if key in pred:
                if pred[key] == gt[key]:
                    value_matches += 1
                    
        value_accuracy = value_matches / len(gt_keys)
        
        return (key_accuracy + value_accuracy) / 2
    
    def _compare_lists(self, pred: List, gt: List) -> float:
        """리스트 비교"""
        if not isinstance(pred, list) or not isinstance(gt, list):
            return 0.0
            
        if not gt:
            return 1.0 if not pred else 0.0
            
        # 순서 무관 집합 비교
        pred_set = set(str(item) for item in pred)
        gt_set = set(str(item) for item in gt)
        
        return len(pred_set & gt_set) / len(gt_set)

    def _calculate_batch_statistics(self, results: List[EvaluationResult]) -> Dict[str, float]:
        """배치 통계 계산"""
        if not results:
            return {}
            
        stats = {
            'total_questions': len(results),
            'exact_match_avg': np.mean([r.exact_match for r in results]),
            'f1_score_avg': np.mean([r.f1_score for r in results]),
            'overall_score_avg': np.mean([r.overall_score() for r in results])
        }
        
        # Short answer 통계
        short_results = [r for r in results if r.answer_type == AnswerType.SHORT]
        if short_results:
            stats['short_answer_count'] = len(short_results)
            stats['short_answer_em'] = np.mean([r.exact_match for r in short_results])
            stats['short_answer_f1'] = np.mean([r.f1_score for r in short_results])
        
        # Long answer 통계
        long_results = [r for r in results if r.answer_type == AnswerType.LONG]
        if long_results:
            stats['long_answer_count'] = len(long_results)
            stats['long_answer_em'] = np.mean([r.exact_match for r in long_results])
            stats['long_answer_f1'] = np.mean([r.f1_score for r in long_results])
            
            bleu_scores = [r.bleu_score for r in long_results if r.bleu_score is not None]
            if bleu_scores:
                stats['long_answer_bleu'] = np.mean(bleu_scores)
                
            rouge_l_scores = [r.rouge_scores['rouge-l']['f'] for r in long_results 
                            if r.rouge_scores and 'rouge-l' in r.rouge_scores]
            if rouge_l_scores:
                stats['long_answer_rouge_l'] = np.mean(rouge_l_scores)
        
        return stats
    
    def _filter_stats(self, results: List[EvaluationResult], answer_type: AnswerType) -> Dict[str, float]:
        """특정 답변 타입에 대한 통계"""
        filtered = [r for r in results if r.answer_type == answer_type]
        if not filtered:
            return {}
            
        return {
            'count': len(filtered),
            'exact_match': np.mean([r.exact_match for r in filtered]),
            'f1_score': np.mean([r.f1_score for r in filtered]),
            'overall_score': np.mean([r.overall_score() for r in filtered])
        }

    def _to_serializable(self, obj: Any) -> Any:
        """JSON 직렬화를 위한 기본 타입 변환"""
        if isinstance(obj, np.generic):
            return obj.item()
        if isinstance(obj, Enum):
            return obj.value
        if isinstance(obj, dict):
            return {k: self._to_serializable(v) for k, v in obj.items()}
        if isinstance(obj, list):
            return [self._to_serializable(v) for v in obj]
        return obj
