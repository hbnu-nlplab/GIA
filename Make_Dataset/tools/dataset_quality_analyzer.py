"""
Enhanced Dataset Ground Truth & Explanation Restructuring
LLM 평가를 위한 데이터셋 구조 개선
"""

from typing import Dict, Any, List, Union
import json
import re

class DatasetRestructurer:
    """
    Enhanced Dataset의 ground_truth와 explanation을 
    EM/F1 + BERT-score 평가에 적합하게 재구성
    """
    
    def __init__(self):
        self.metric_to_natural = {
            # 내부 메트릭명 → 자연스러운 답변으로 변환
            "bgp_local_as_numeric": "BGP Local AS 번호",
            "ibgp_fullmesh_ok": "iBGP Full-Mesh 구성 상태",
            "ssh_present_bool": "SSH 활성화 여부", 
            "aaa_present_bool": "AAA 인증 설정 여부",
            "vrf_without_rt_count": "Route Target 누락 VRF 개수",
            "l2vpn_unidir_count": "단방향 L2VPN 연결 개수",
            "neighbor_list_ibgp": "iBGP 이웃 목록",
            "ospf_area0_if_count": "OSPF Area 0 인터페이스 수"
        }
    
    def restructure_dataset(self, dataset_path: str, output_path: str) -> None:
        """데이터셋을 EM/F1 + BERT-score 평가에 적합하게 재구성"""
        
        with open(dataset_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
        
        restructured_data = []
        
        for item in data:
            restructured_item = self._restructure_single_item(item)
            if restructured_item:
                restructured_data.append(restructured_item)
        
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(restructured_data, f, ensure_ascii=False, indent=2)
        
        print(f"재구성 완료: {len(restructured_data)}개 항목")
    
    def _restructure_single_item(self, item: Dict[str, Any]) -> Dict[str, Any]:
        """개별 데이터 항목 재구성"""
        
        question = item.get("question", "")
        original_gt = item.get("ground_truth")
        original_exp = item.get("explanation", "")
        answer_type = item.get("answer_type", "long")
        
        # 1. Ground Truth 정규화
        normalized_gt = self._normalize_ground_truth(original_gt, question, answer_type)
        
        # 2. Explanation 정제 (BERT-score 평가용)
        refined_explanation = self._refine_explanation(original_exp, normalized_gt)
        
        # 3. 평가 불가능한 항목 필터링
        if not normalized_gt or not refined_explanation:
            return None
        
        return {
            **item,  # 기존 메타데이터 유지
            "ground_truth": normalized_gt,
            "explanation": refined_explanation,
            "evaluation_metrics": {
                "ground_truth_type": self._determine_gt_type(normalized_gt),
                "evaluation_method": "em_f1" if answer_type == "short" else "bert_score"
            }
        }
    
    def _normalize_ground_truth(self, gt: Any, question: str, answer_type: str) -> Union[str, List[str], None]:
        """Ground Truth를 평가 가능한 형태로 정규화"""
        
        if isinstance(gt, str):
            # 내부 메트릭명이 포함된 경우 자연스러운 용어로 변환
            if any(metric in gt for metric in self.metric_to_natural.keys()):
                return self._convert_metrics_to_natural(gt)
            return gt.strip()
        
        elif isinstance(gt, list):
            if not gt:
                return None
            
            # 내부 메트릭명 배열인 경우
            if all(isinstance(item, str) and item in self.metric_to_natural for item in gt):
                return [self.metric_to_natural[metric] for metric in gt]
            
            # 이미 자연스러운 용어인 경우
            return [str(item).strip() for item in gt if item]
        
        elif isinstance(gt, dict):
            # 복합 객체는 핵심 답변만 추출
            return self._extract_core_answer_from_dict(gt, question)
        
        elif isinstance(gt, (int, float, bool)):
            return str(gt)
        
        return None
    
    def _convert_metrics_to_natural(self, text: str) -> str:
        """내부 메트릭명을 자연스러운 용어로 변환"""
        result = text
        for metric, natural in self.metric_to_natural.items():
            result = result.replace(metric, natural)
        return result
    
    def _extract_core_answer_from_dict(self, gt_dict: Dict[str, Any], question: str) -> str:
        """복합 객체에서 핵심 답변 추출"""
        
        # 질문 유형에 따라 핵심 답변 추출
        if "영향" in question and "impact" in gt_dict:
            return gt_dict["impact"]
        elif "방법" in question or "조치" in question:
            if "preventive_measures" in gt_dict:
                return "; ".join(gt_dict["preventive_measures"])
            elif "methods" in gt_dict:
                return "; ".join(gt_dict["methods"])
        elif "단계" in question and "steps" in gt_dict:
            return " → ".join(gt_dict["steps"])
        
        # 기본적으로 첫 번째 값 반환
        values = list(gt_dict.values())
        if values:
            first_val = values[0]
            if isinstance(first_val, list):
                return "; ".join(str(v) for v in first_val)
            return str(first_val)
        
        return None
    
    def _refine_explanation(self, explanation: str, ground_truth: Any) -> str:
        """BERT-score 평가에 적합하게 Explanation 정제"""
        
        if not explanation:
            return ""
        
        # 1. 내부 메트릭명 제거/변환
        refined = explanation
        for metric, natural in self.metric_to_natural.items():
            refined = refined.replace(f"'{metric}'", f"'{natural}'")
            refined = refined.replace(f"`{metric}`", f"`{natural}`")
            refined = refined.replace(metric, natural)
        
        # 2. Ground Truth와 중복되는 내용 제거 (간단한 경우만)
        if isinstance(ground_truth, str) and len(ground_truth) < 100:
            # GT가 설명에 그대로 포함된 경우, 추가 설명 부분만 유지
            if ground_truth in refined:
                parts = refined.split(ground_truth)
                if len(parts) > 1 and len(parts[1].strip()) > 50:
                    refined = parts[1].strip()
        
        # 3. 설명의 품질 검증
        if len(refined) < 20:  # 너무 짧은 설명 제외
            return ""
        
        return refined.strip()
    
    def _determine_gt_type(self, gt: Any) -> str:
        """Ground Truth 타입 결정"""
        if isinstance(gt, list):
            return "list"
        elif isinstance(gt, str):
            if len(gt.split()) <= 5:
                return "short_answer"
            return "long_answer"
        return "other"

# 데이터셋 품질 분석 도구
class DatasetQualityAnalyzer:
    """데이터셋의 평가 적합성 분석"""
    
    def analyze_evaluation_suitability(self, dataset_path: str) -> Dict[str, Any]:
        """평가 적합성 분석"""
        
        with open(dataset_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
        
        analysis = {
            "total_items": len(data),
            "ground_truth_types": {},
            "problematic_items": [],
            "evaluation_recommendations": {}
        }
        
        for i, item in enumerate(data):
            gt = item.get("ground_truth")
            explanation = item.get("explanation", "")
            
            # GT 타입 분석
            gt_type = self._classify_gt_type(gt)
            analysis["ground_truth_types"][gt_type] = analysis["ground_truth_types"].get(gt_type, 0) + 1
            
            # 문제가 있는 항목 식별
            issues = self._identify_issues(item)
            if issues:
                analysis["problematic_items"].append({
                    "index": i,
                    "id": item.get("id"),
                    "issues": issues
                })
        
        # 평가 방법 권장사항
        analysis["evaluation_recommendations"] = self._generate_recommendations(analysis)
        
        return analysis
    
    def _classify_gt_type(self, gt: Any) -> str:
        """Ground Truth 타입 분류"""
        if isinstance(gt, list):
            if any(self._is_internal_metric(item) for item in gt if isinstance(item, str)):
                return "internal_metrics"
            return "list_answers"
        elif isinstance(gt, dict):
            return "complex_object"
        elif isinstance(gt, str):
            if self._is_internal_metric(gt):
                return "internal_metric"
            elif len(gt.split()) <= 5:
                return "short_text"
            return "long_text"
        return "other"
    
    def _is_internal_metric(self, text: str) -> bool:
        """내부 메트릭명 여부 판별"""
        metric_patterns = [
            r'.*_bool$', r'.*_count$', r'.*_list$', r'.*_map$', 
            r'.*_set$', r'.*_numeric$', r'.*_text$'
        ]
        return any(re.match(pattern, text) for pattern in metric_patterns)
    
    def _identify_issues(self, item: Dict[str, Any]) -> List[str]:
        """항목별 문제점 식별"""
        issues = []
        
        gt = item.get("ground_truth")
        explanation = item.get("explanation", "")
        
        # 내부 메트릭명 사용 문제
        if self._contains_internal_metrics(gt):
            issues.append("contains_internal_metrics")
        
        # Explanation 품질 문제
        if len(explanation) < 20:
            issues.append("explanation_too_short")
        
        # GT와 Explanation 중복 문제
        if isinstance(gt, str) and gt in explanation:
            issues.append("gt_explanation_overlap")
        
        return issues
    
    def _contains_internal_metrics(self, gt: Any) -> bool:
        """내부 메트릭명 포함 여부 확인"""
        if isinstance(gt, str):
            return self._is_internal_metric(gt)
        elif isinstance(gt, list):
            return any(self._is_internal_metric(str(item)) for item in gt)
        return False
    
    def _generate_recommendations(self, analysis: Dict[str, Any]) -> Dict[str, str]:
        """평가 방법 권장사항 생성"""
        recommendations = {}
        
        total = analysis["total_items"]
        gt_types = analysis["ground_truth_types"]
        
        # EM/F1 Score 적합성
        suitable_for_em_f1 = gt_types.get("short_text", 0) + gt_types.get("list_answers", 0)
        recommendations["em_f1_suitable"] = f"{suitable_for_em_f1}/{total} ({suitable_for_em_f1/total*100:.1f}%)"
        
        # BERT Score 적합성  
        suitable_for_bert = gt_types.get("long_text", 0) + suitable_for_em_f1
        recommendations["bert_score_suitable"] = f"{suitable_for_bert}/{total} ({suitable_for_bert/total*100:.1f}%)"
        
        # 개선 필요 항목
        problematic = len(analysis["problematic_items"])
        recommendations["needs_improvement"] = f"{problematic}/{total} ({problematic/total*100:.1f}%)"
        
        return recommendations

if __name__ == "__main__":
    # 사용 예시
    analyzer = DatasetQualityAnalyzer()
    analysis = analyzer.analyze_evaluation_suitability("enhanced_dataset.json")
    
    print("=== 데이터셋 평가 적합성 분석 ===")
    print(f"전체 항목 수: {analysis['total_items']}")
    print(f"Ground Truth 타입별 분포: {analysis['ground_truth_types']}")
    print(f"문제가 있는 항목 수: {len(analysis['problematic_items'])}")
    print(f"평가 방법 권장사항: {analysis['evaluation_recommendations']}")
    
    # 문제가 있는 항목들 상세 출력
    print("\n=== 문제가 있는 항목들 ===")
    for item in analysis['problematic_items'][:5]:  # 처음 5개만 출력
        print(f"ID: {item['id']}")
        print(f"문제점: {item['issues']}")
        print("---")
    
    # 타입별 예시 출력
    print("\n=== Ground Truth 타입별 예시 ===")
    with open("enhanced_dataset.json", 'r', encoding='utf-8') as f:
        data = json.load(f)
    
    type_examples = {}
    for item in data:
        gt = item.get("ground_truth")
        gt_type = analyzer._classify_gt_type(gt)
        if gt_type not in type_examples:
            type_examples[gt_type] = {
                "question": item.get("question", "")[:100] + "...",
                "ground_truth": gt,
                "explanation": item.get("explanation", "")[:150] + "..."
            }
    
    for gt_type, example in type_examples.items():
        print(f"\n[{gt_type}]")
        print(f"질문: {example['question']}")
        print(f"GT: {example['ground_truth']}")
        print(f"설명: {example['explanation']}")
        print("---")
