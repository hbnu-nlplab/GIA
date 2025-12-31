"""
NetConfigQA Dataset Validation Framework (Human Annotation Support)
===================================================================

데이터셋의 신뢰성을 검증하기 위한 프레임워크입니다.

검증 전략:
1. Automated Verification - 자동 검증 (기존 verify_dataset_v2.py)
2. Stratified Random Sampling - 층화 무작위 샘플링 (통계적 유의성)
3. Human Annotation - 팀원 3명의 독립 검증
4. Inter-Annotator Agreement (IAA) - Cohen's Kappa / Fleiss' Kappa

사용법:
    # Step 1: 검증용 샘플 추출
    python validate_dataset.py sample \\
        --csv Data/Pnetlab/.../dataset.csv \\
        --output validation_samples.csv \\
        --seed 42

    # Step 2: 각 팀원이 독립적으로 annotation_sheet를 작성
    # (generated annotation_annotatorX.csv 파일 배포)

    # Step 3: IAA 계산
    python validate_dataset.py iaa \\
        --files annotator1.csv annotator2.csv annotator3.csv

    # Step 4: 종합 리포트 생성
    python validate_dataset.py report \\
        --auto-results auto_verification.json \\
        --human-annotations annotator1.csv annotator2.csv annotator3.csv \\
        --output validation_report.md
"""

from __future__ import annotations

import argparse
import csv
import json
import math
import random
import hashlib
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
import ast


# ============================================================================
# Configuration
# ============================================================================

@dataclass
class SamplingConfig:
    """층화 샘플링 설정"""
    confidence_level: float = 0.95  # 신뢰수준 (95%)
    margin_of_error: float = 0.05   # 오차범위 (±5%)
    min_per_stratum: int = 5        # 계층당 최소 샘플 수
    seed: int = 42                  # 재현성을 위한 시드
    

# ============================================================================
# Statistical Sampling
# ============================================================================

def calculate_sample_size(
    population: int, 
    confidence: float = 0.95, 
    margin: float = 0.05
) -> int:
    """
    Cochran's formula를 사용한 샘플 크기 계산
    
    - Z-score: 신뢰수준에 따른 표준정규분포 값
    - p = 0.5: 최대 분산 가정 (보수적 추정)
    - 유한 모집단 보정 적용
    
    예시:
        population=1000, confidence=0.95, margin=0.05 → ~278개
        population=500, confidence=0.95, margin=0.05 → ~217개
    """
    z_scores = {0.90: 1.645, 0.95: 1.96, 0.99: 2.576}
    z = z_scores.get(confidence, 1.96)
    p = 0.5  # 최대 분산 가정
    
    # 무한 모집단 공식
    n0 = (z**2 * p * (1 - p)) / (margin**2)
    
    # 유한 모집단 보정 (Finite Population Correction)
    n = n0 / (1 + (n0 - 1) / population)
    
    return int(math.ceil(n))


def stratified_sample(
    rows: List[Dict[str, Any]], 
    config: SamplingConfig
) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
    """
    층화 무작위 샘플링 (Stratified Random Sampling)
    
    층화 기준: level + answer_type
    - 각 계층에서 비례 배분으로 샘플 추출
    - 최소 샘플 수 보장
    
    Returns:
        (샘플 리스트, 샘플링 통계 정보)
    """
    random.seed(config.seed)
    
    # 계층화: level × answer_type
    strata = defaultdict(list)
    for i, row in enumerate(rows):
        level = row.get('level', 'UNKNOWN')
        answer_type = row.get('answer_type', 'unknown')
        key = f"{level}_{answer_type}"
        strata[key].append((i, row))
    
    # 목표 샘플 크기 계산
    total_sample_size = calculate_sample_size(
        len(rows), 
        config.confidence_level, 
        config.margin_of_error
    )
    
    sampled = []
    sample_counts = {}
    
    for stratum_key, items in strata.items():
        # 비례 배분
        proportion = len(items) / len(rows)
        stratum_size = max(
            config.min_per_stratum,
            int(total_sample_size * proportion)
        )
        stratum_size = min(stratum_size, len(items))  # 계층 크기 초과 방지
        
        # 무작위 선택
        selected = random.sample(items, stratum_size)
        
        for original_idx, row in selected:
            row_copy = row.copy()
            row_copy['_sample_id'] = f"S{len(sampled)+1:04d}"
            row_copy['_original_idx'] = original_idx + 2  # CSV row number (1-indexed + header)
            row_copy['_stratum'] = stratum_key
            sampled.append(row_copy)
        
        sample_counts[stratum_key] = {
            "population": len(items),
            "sampled": stratum_size,
            "proportion": f"{proportion*100:.1f}%"
        }
    
    # 샘플 섞기 (편향 방지)
    random.shuffle(sampled)
    
    # 샘플 ID 재부여
    for i, s in enumerate(sampled, 1):
        s['_sample_id'] = f"S{i:04d}"
    
    stats = {
        "population": len(rows),
        "sample_size": len(sampled),
        "confidence_level": f"{config.confidence_level*100:.0f}%",
        "margin_of_error": f"±{config.margin_of_error*100:.0f}%",
        "seed": config.seed,
        "strata": sample_counts
    }
    
    return sampled, stats


# ============================================================================
# Annotation Sheet Generator
# ============================================================================

def generate_annotation_sheet(
    samples: List[Dict[str, Any]], 
    output_path: Path,
    annotator_name: str = "",
    include_answer: bool = True,  # True: 검증 모드, False: 블라인드 평가
    include_evidence: bool = True
) -> None:
    """
    Human Annotator용 검증 시트 생성
    
    검증 시트 구성:
    - sample_id: 샘플 고유 ID
    - original_row: 원본 CSV 행 번호
    - level, category, answer_type: 문항 메타정보
    - question: 질문
    - provided_answer: 파이프라인이 생성한 정답 (검증 모드시)
    - annotator_answer: 검증자가 작성 (선택적)
    - is_correct: Y / N / PARTIAL / UNCLEAR
    - error_type: 오류 유형 (오답일 경우)
    - confidence: 검증자 확신도 (1-5)
    - notes: 추가 메모
    """
    fieldnames = [
        "sample_id",
        "original_row", 
        "level",
        "category",
        "answer_type",
        "question",
    ]
    
    if include_answer:
        fieldnames.append("provided_answer")
    
    if include_evidence:
        fieldnames.append("evidence_summary")
    
    fieldnames.extend([
        "annotator_answer",  # 선택: 검증자가 직접 계산한 답
        "is_correct",        # 필수: Y / N / PARTIAL / UNCLEAR
        "error_type",        # 선택: wrong_value / wrong_format / incomplete / ambiguous / other
        "confidence",        # 필수: 1(불확실) ~ 5(확실)
        "notes"              # 선택: 추가 메모
    ])
    
    with output_path.open("w", encoding="utf-8-sig", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        
        for sample in samples:
            row = {
                "sample_id": sample.get('_sample_id', ''),
                "original_row": sample.get('_original_idx', ''),
                "level": sample.get('level', ''),
                "category": sample.get('category', ''),
                "answer_type": sample.get('answer_type', ''),
                "question": sample.get('question', ''),
                "annotator_answer": "",
                "is_correct": "",  # Y / N / PARTIAL / UNCLEAR
                "error_type": "",  # wrong_value / wrong_format / incomplete / ambiguous / other
                "confidence": "",  # 1-5
                "notes": ""
            }
            
            if include_answer:
                row["provided_answer"] = sample.get('answer', '')
            
            if include_evidence:
                # evidence에서 핵심 정보만 추출
                try:
                    evid = json.loads(sample.get('evidence', '{}'))
                    evidence_summary = f"metric: {evid.get('metric', 'N/A')}"
                except:
                    evidence_summary = sample.get('evidence', '')[:100]
                row["evidence_summary"] = evidence_summary
            
            writer.writerow(row)
    
    # 사용 가이드 생성
    guide_path = output_path.with_suffix('.guide.txt')
    guide_content = f"""
╔══════════════════════════════════════════════════════════════════════════════╗
║                    NetConfigQA 데이터셋 검증 가이드                           ║
╠══════════════════════════════════════════════════════════════════════════════╣
║ 검증자: {annotator_name or '미지정'}                                                               ║
║ 생성일: {datetime.now().strftime('%Y-%m-%d %H:%M')}                                         ║
║ 샘플수: {len(samples)}개                                                            ║
╚══════════════════════════════════════════════════════════════════════════════╝

[작성 방법]
────────────────────────────────────────────────────────────────────────────────

1. is_correct (필수) - 정답이 맞는지 판단
   ┌─────────┬────────────────────────────────────────────────────────────────┐
   │   값    │ 설명                                                           │
   ├─────────┼────────────────────────────────────────────────────────────────┤
   │    Y    │ 정답이 완전히 맞음                                             │
   │    N    │ 정답이 틀림                                                    │
   │ PARTIAL │ 부분적으로 맞음 (일부 요소 누락/추가)                          │
   │ UNCLEAR │ 질문이 모호하거나 판단 불가                                    │
   └─────────┴────────────────────────────────────────────────────────────────┘

2. error_type (is_correct가 N일 때 필수)
   - wrong_value   : 값 자체가 틀림
   - wrong_format  : 형식이 틀림 (예: set인데 list로 표기)
   - incomplete    : 일부 값 누락
   - ambiguous     : 질문/정답이 모호함
   - other         : 기타 (notes에 설명)

3. confidence (필수) - 판단 확신도
   1 = 매우 불확실 (추측)
   2 = 불확실
   3 = 보통
   4 = 확실
   5 = 매우 확실 (직접 확인함)

4. annotator_answer (선택)
   - 정답이 틀렸다고 판단할 경우, 올바른 답을 직접 작성

5. notes (선택)
   - 특이사항, 오류 원인 분석, 개선 제안 등


[검증 절차]
────────────────────────────────────────────────────────────────────────────────

1. question을 읽고 무엇을 묻는지 파악
2. provided_answer가 적절한지 판단
3. 필요시 원본 config 파일이나 facts.json 참조
4. is_correct, confidence 기입 (필수)
5. 오답일 경우 error_type, annotator_answer 기입


[주의사항]
────────────────────────────────────────────────────────────────────────────────

⚠️  다른 검증자와 상의하지 말고 독립적으로 검증하세요
⚠️  확실하지 않으면 confidence를 낮게, UNCLEAR로 표시
⚠️  모든 샘플을 검증해주세요 (빈칸 없이)


[답변 유형별 검증 포인트]
────────────────────────────────────────────────────────────────────────────────

• text    : 정확한 문자열 일치 (대소문자 무관)
• numeric : 숫자 값 일치
• set     : 순서 무관, 모든 요소 포함 여부
• map     : key-value 쌍 모두 일치

"""
    guide_path.write_text(guide_content.strip(), encoding="utf-8")
    
    print(f"✅ Annotation sheet: {output_path}")
    print(f"📖 Guide file: {guide_path}")


def generate_all_annotator_sheets(
    samples: List[Dict[str, Any]],
    output_dir: Path,
    annotator_names: List[str],
    **kwargs
) -> List[Path]:
    """모든 검증자용 시트 생성"""
    output_dir.mkdir(parents=True, exist_ok=True)
    paths = []
    
    for name in annotator_names:
        safe_name = name.replace(" ", "_").lower()
        output_path = output_dir / f"annotation_{safe_name}.csv"
        generate_annotation_sheet(
            samples, 
            output_path, 
            annotator_name=name,
            **kwargs
        )
        paths.append(output_path)
    
    return paths


# ============================================================================
# Inter-Annotator Agreement (IAA) Calculator
# ============================================================================

@dataclass
class IAAResult:
    """IAA 계산 결과"""
    num_annotators: int = 0
    num_samples: int = 0
    
    # Agreement metrics
    percent_agreement: float = 0.0
    cohen_kappa: float = 0.0          # 2명일 때
    fleiss_kappa: float = 0.0         # 3명 이상
    
    # Category-wise
    agreement_by_level: Dict[str, float] = field(default_factory=dict)
    agreement_by_type: Dict[str, float] = field(default_factory=dict)
    
    # Details
    confusion_matrix: Dict[str, Dict[str, int]] = field(default_factory=dict)
    disagreements: List[Dict] = field(default_factory=list)
    
    # Reliability
    krippendorff_alpha: float = 0.0


def load_annotation(filepath: Path) -> Dict[str, Dict[str, Any]]:
    """Annotation 파일 로드"""
    annotations = {}
    with filepath.open("r", encoding="utf-8-sig") as f:
        reader = csv.DictReader(f)
        for row in reader:
            sample_id = row.get('sample_id', '').strip()
            if sample_id:
                annotations[sample_id] = {
                    'is_correct': row.get('is_correct', '').strip().upper(),
                    'error_type': row.get('error_type', '').strip().lower(),
                    'confidence': row.get('confidence', '').strip(),
                    'level': row.get('level', ''),
                    'answer_type': row.get('answer_type', ''),
                    'notes': row.get('notes', '')
                }
    return annotations


def calculate_cohen_kappa(labels1: List[str], labels2: List[str]) -> float:
    """
    Cohen's Kappa 계산 (2명의 평가자)
    
    κ = (Po - Pe) / (1 - Pe)
    
    - Po: 관측 일치율 (observed agreement)
    - Pe: 우연 일치율 (expected agreement)
    
    해석:
        κ < 0.20: 매우 낮음 (poor)
        0.20 ≤ κ < 0.40: 낮음 (fair)
        0.40 ≤ κ < 0.60: 보통 (moderate)
        0.60 ≤ κ < 0.80: 상당함 (substantial)
        0.80 ≤ κ ≤ 1.00: 거의 완벽 (almost perfect)
    """
    if len(labels1) != len(labels2):
        raise ValueError("두 리스트의 길이가 같아야 합니다")
    
    n = len(labels1)
    if n == 0:
        return 0.0
    
    # 관측 일치율 (Po)
    agreements = sum(1 for a, b in zip(labels1, labels2) if a == b)
    po = agreements / n
    
    # 기대 일치율 (Pe) - 우연히 일치할 확률
    all_labels = set(labels1) | set(labels2)
    pe = 0.0
    for label in all_labels:
        p1 = sum(1 for x in labels1 if x == label) / n
        p2 = sum(1 for x in labels2 if x == label) / n
        pe += p1 * p2
    
    # Kappa 계산
    if pe == 1.0:
        return 1.0 if po == 1.0 else 0.0
    
    kappa = (po - pe) / (1 - pe)
    return kappa


def calculate_fleiss_kappa(ratings: List[List[str]]) -> float:
    """
    Fleiss' Kappa 계산 (3명 이상)
    
    ratings: [[annotator1_labels], [annotator2_labels], [annotator3_labels], ...]
    각 annotator_labels는 동일한 샘플들에 대한 라벨 리스트
    """
    n_annotators = len(ratings)
    if n_annotators < 2:
        return 0.0
    
    n_samples = len(ratings[0])
    if n_samples == 0:
        return 0.0
    
    # 모든 라벨 수집
    all_labels = set()
    for annotator_ratings in ratings:
        all_labels.update(annotator_ratings)
    labels = sorted(all_labels)
    k = len(labels)
    
    if k == 0:
        return 0.0
    
    # 각 샘플, 각 카테고리별 count 계산
    # n_ij = 샘플 i에서 카테고리 j를 선택한 평가자 수
    n_matrix = []
    for i in range(n_samples):
        row = []
        for label in labels:
            count = sum(1 for ann in ratings if ann[i] == label)
            row.append(count)
        n_matrix.append(row)
    
    # P_i 계산 (각 샘플의 일치도)
    N = n_annotators
    P_i_list = []
    for row in n_matrix:
        sum_sq = sum(n ** 2 for n in row)
        P_i = (sum_sq - N) / (N * (N - 1)) if N > 1 else 0
        P_i_list.append(P_i)
    
    # P_bar 계산 (평균 일치도)
    P_bar = sum(P_i_list) / n_samples if n_samples > 0 else 0
    
    # p_j 계산 (각 카테고리의 전체 비율)
    p_j_list = []
    total_ratings = n_samples * N
    for j, label in enumerate(labels):
        count_j = sum(row[j] for row in n_matrix)
        p_j = count_j / total_ratings if total_ratings > 0 else 0
        p_j_list.append(p_j)
    
    # P_e 계산 (우연 일치율)
    P_e = sum(p ** 2 for p in p_j_list)
    
    # Fleiss' Kappa
    if P_e == 1.0:
        return 1.0 if P_bar == 1.0 else 0.0
    
    kappa = (P_bar - P_e) / (1 - P_e)
    return kappa


def calculate_iaa(annotation_files: List[Path]) -> IAAResult:
    """
    여러 평가자의 IAA 계산
    
    Returns:
        IAAResult with all metrics
    """
    result = IAAResult()
    result.num_annotators = len(annotation_files)
    
    if len(annotation_files) < 2:
        raise ValueError("IAA 계산에는 최소 2명의 평가자가 필요합니다")
    
    # 모든 annotation 로드
    all_annotations = []
    for filepath in annotation_files:
        annotations = load_annotation(filepath)
        all_annotations.append(annotations)
    
    # 공통 샘플 ID 찾기
    common_ids = set(all_annotations[0].keys())
    for ann in all_annotations[1:]:
        common_ids &= set(ann.keys())
    
    common_ids = sorted(common_ids)
    result.num_samples = len(common_ids)
    
    if len(common_ids) == 0:
        print("⚠️ 공통 샘플이 없습니다. sample_id를 확인하세요.")
        return result
    
    # is_correct 라벨 추출
    ratings = []
    for ann in all_annotations:
        labels = [ann[sid]['is_correct'] for sid in common_ids]
        ratings.append(labels)
    
    # Percent Agreement (모든 평가자 일치)
    total_agree = 0
    for i, sid in enumerate(common_ids):
        labels_for_sample = [ratings[j][i] for j in range(len(ratings))]
        if len(set(labels_for_sample)) == 1:
            total_agree += 1
    result.percent_agreement = total_agree / len(common_ids) if common_ids else 0
    
    # Cohen's Kappa (2명일 때)
    if len(annotation_files) == 2:
        result.cohen_kappa = calculate_cohen_kappa(ratings[0], ratings[1])
    
    # Fleiss' Kappa (모든 경우)
    result.fleiss_kappa = calculate_fleiss_kappa(ratings)
    
    # 불일치 항목 기록
    for i, sid in enumerate(common_ids):
        labels_for_sample = [ratings[j][i] for j in range(len(ratings))]
        if len(set(labels_for_sample)) > 1:
            result.disagreements.append({
                'sample_id': sid,
                'annotations': labels_for_sample,
                'level': all_annotations[0][sid].get('level', ''),
                'answer_type': all_annotations[0][sid].get('answer_type', '')
            })
    
    # Level별 일치율
    level_agree = defaultdict(lambda: {'agree': 0, 'total': 0})
    for i, sid in enumerate(common_ids):
        level = all_annotations[0][sid].get('level', 'UNKNOWN')
        labels = [ratings[j][i] for j in range(len(ratings))]
        level_agree[level]['total'] += 1
        if len(set(labels)) == 1:
            level_agree[level]['agree'] += 1
    
    for level, counts in level_agree.items():
        if counts['total'] > 0:
            result.agreement_by_level[level] = counts['agree'] / counts['total']
    
    # Answer type별 일치율
    type_agree = defaultdict(lambda: {'agree': 0, 'total': 0})
    for i, sid in enumerate(common_ids):
        atype = all_annotations[0][sid].get('answer_type', 'unknown')
        labels = [ratings[j][i] for j in range(len(ratings))]
        type_agree[atype]['total'] += 1
        if len(set(labels)) == 1:
            type_agree[atype]['agree'] += 1
    
    for atype, counts in type_agree.items():
        if counts['total'] > 0:
            result.agreement_by_type[atype] = counts['agree'] / counts['total']
    
    return result


def interpret_kappa(kappa: float) -> str:
    """Kappa 해석"""
    if kappa < 0.20:
        return "매우 낮음 (poor)"
    elif kappa < 0.40:
        return "낮음 (fair)"
    elif kappa < 0.60:
        return "보통 (moderate)"
    elif kappa < 0.80:
        return "상당함 (substantial)"
    else:
        return "거의 완벽 (almost perfect)"


# ============================================================================
# Human Accuracy Calculator
# ============================================================================

def calculate_human_accuracy(
    annotation_files: List[Path],
    resolve_method: str = "majority"  # majority | unanimous | any
) -> Dict[str, Any]:
    """
    Human annotation 기반 정확도 계산
    
    resolve_method:
        - majority: 다수결 (과반수가 Y면 정답)
        - unanimous: 만장일치 (모두 Y여야 정답)
        - any: 최소 1명 이상 Y면 정답
    """
    all_annotations = []
    for filepath in annotation_files:
        annotations = load_annotation(filepath)
        all_annotations.append(annotations)
    
    common_ids = set(all_annotations[0].keys())
    for ann in all_annotations[1:]:
        common_ids &= set(ann.keys())
    
    common_ids = sorted(common_ids)
    
    results = {
        'total': len(common_ids),
        'correct': 0,
        'incorrect': 0,
        'partial': 0,
        'unclear': 0,
        'by_level': defaultdict(lambda: {'correct': 0, 'total': 0}),
        'by_type': defaultdict(lambda: {'correct': 0, 'total': 0}),
        'accuracy': 0.0
    }
    
    for sid in common_ids:
        votes = [ann[sid]['is_correct'] for ann in all_annotations]
        level = all_annotations[0][sid].get('level', '')
        atype = all_annotations[0][sid].get('answer_type', '')
        
        # Count votes
        y_count = sum(1 for v in votes if v == 'Y')
        n_count = sum(1 for v in votes if v == 'N')
        p_count = sum(1 for v in votes if v == 'PARTIAL')
        
        results['by_level'][level]['total'] += 1
        results['by_type'][atype]['total'] += 1
        
        # Resolve
        if resolve_method == "majority":
            is_correct = y_count > len(votes) / 2
        elif resolve_method == "unanimous":
            is_correct = y_count == len(votes)
        else:  # any
            is_correct = y_count > 0
        
        if is_correct:
            results['correct'] += 1
            results['by_level'][level]['correct'] += 1
            results['by_type'][atype]['correct'] += 1
        elif n_count > y_count:
            results['incorrect'] += 1
        elif p_count > 0:
            results['partial'] += 1
        else:
            results['unclear'] += 1
    
    # Calculate accuracy
    if results['total'] > 0:
        results['accuracy'] = results['correct'] / results['total']
    
    # Convert defaultdict to regular dict for JSON serialization
    results['by_level'] = dict(results['by_level'])
    results['by_type'] = dict(results['by_type'])
    
    return results


# ============================================================================
# Validation Report Generator
# ============================================================================

@dataclass
class ValidationReport:
    """종합 검증 리포트"""
    dataset_name: str
    total_rows: int
    
    # Automated verification results
    auto_total: int = 0
    auto_passed: int = 0
    auto_failed: int = 0
    auto_skipped: int = 0
    auto_pass_rate: float = 0.0
    
    # Human annotation results
    human_sample_size: int = 0
    human_accuracy: float = 0.0
    human_by_level: Dict[str, float] = field(default_factory=dict)
    
    # IAA results
    num_annotators: int = 0
    iaa_percent_agreement: float = 0.0
    iaa_kappa: float = 0.0
    iaa_interpretation: str = ""
    
    # Error analysis
    error_types: Counter = field(default_factory=Counter)
    
    # Metadata
    generated_at: str = ""
    sampling_confidence: str = "95%"
    sampling_margin: str = "±5%"


def generate_validation_report(
    report: ValidationReport,
    output_path: Path,
    iaa_result: Optional[IAAResult] = None,
    human_result: Optional[Dict[str, Any]] = None
) -> None:
    """학술 논문용 검증 리포트 생성"""
    
    md = []
    md.append("# NetConfigQA Dataset Validation Report")
    md.append("")
    md.append(f"> **Dataset**: {report.dataset_name}")
    md.append(f"> **Generated**: {report.generated_at or datetime.now().strftime('%Y-%m-%d %H:%M')}")
    md.append(f"> **Total Samples**: {report.total_rows:,}")
    md.append("")
    
    # ========== 1. Executive Summary ==========
    md.append("## 📊 Executive Summary")
    md.append("")
    md.append("| Validation Method | Result | Interpretation |")
    md.append("|-------------------|--------|----------------|")
    
    if report.auto_pass_rate > 0:
        auto_interp = "✅ 높음" if report.auto_pass_rate >= 0.95 else "⚠️ 검토 필요"
        md.append(f"| Automated Verification | {report.auto_pass_rate*100:.1f}% | {auto_interp} |")
    
    if report.human_accuracy > 0:
        human_interp = "✅ 높음" if report.human_accuracy >= 0.95 else "⚠️ 검토 필요"
        md.append(f"| Human Annotation (n={report.human_sample_size}) | {report.human_accuracy*100:.1f}% | {human_interp} |")
    
    if report.iaa_kappa > 0:
        md.append(f"| Inter-Annotator Agreement (κ) | {report.iaa_kappa:.3f} | {report.iaa_interpretation} |")
    
    md.append("")
    
    # ========== 2. Automated Verification ==========
    md.append("## 1️⃣ Automated Verification")
    md.append("")
    md.append("자동화된 검증을 통해 데이터셋의 정답을 독립적으로 재계산하여 비교했습니다.")
    md.append("")
    md.append("| Metric | Count | Rate |")
    md.append("|--------|------:|-----:|")
    md.append(f"| Total Verified | {report.auto_total - report.auto_skipped:,} | - |")
    md.append(f"| ✅ Passed | {report.auto_passed:,} | {report.auto_passed/max(report.auto_total-report.auto_skipped, 1)*100:.2f}% |")
    md.append(f"| ❌ Failed | {report.auto_failed:,} | {report.auto_failed/max(report.auto_total-report.auto_skipped, 1)*100:.2f}% |")
    md.append(f"| ⏭️ Skipped | {report.auto_skipped:,} | - |")
    md.append("")
    
    # ========== 3. Human Expert Verification ==========
    md.append("## 2️⃣ Human Expert Verification")
    md.append("")
    md.append(f"층화 무작위 샘플링으로 추출한 {report.human_sample_size}개 샘플에 대해")
    md.append(f"{report.num_annotators}명의 검증자가 독립적으로 정답의 정확성을 평가했습니다.")
    md.append("")
    md.append(f"- **Sample Size**: {report.human_sample_size}")
    md.append(f"- **Confidence Level**: {report.sampling_confidence}")
    md.append(f"- **Margin of Error**: {report.sampling_margin}")
    md.append(f"- **Accuracy**: **{report.human_accuracy*100:.2f}%**")
    md.append("")
    
    if report.human_by_level:
        md.append("### Level별 정확도")
        md.append("")
        md.append("| Level | Accuracy |")
        md.append("|-------|----------|")
        for level, acc in sorted(report.human_by_level.items()):
            md.append(f"| {level} | {acc*100:.1f}% |")
        md.append("")
    
    # ========== 4. Inter-Annotator Agreement ==========
    md.append("## 3️⃣ Inter-Annotator Agreement (IAA)")
    md.append("")
    md.append("검증자 간 일치도를 측정하여 평가의 신뢰성을 확인했습니다.")
    md.append("")
    md.append("| Metric | Value | Interpretation |")
    md.append("|--------|-------|----------------|")
    md.append(f"| Number of Annotators | {report.num_annotators} | - |")
    md.append(f"| Percent Agreement | {report.iaa_percent_agreement*100:.1f}% | - |")
    
    kappa_name = "Cohen's κ" if report.num_annotators == 2 else "Fleiss' κ"
    md.append(f"| {kappa_name} | {report.iaa_kappa:.3f} | {report.iaa_interpretation} |")
    md.append("")
    
    md.append("### Kappa 해석 기준")
    md.append("")
    md.append("| Range | Interpretation |")
    md.append("|-------|----------------|")
    md.append("| κ < 0.20 | Poor (매우 낮음) |")
    md.append("| 0.20 ≤ κ < 0.40 | Fair (낮음) |")
    md.append("| 0.40 ≤ κ < 0.60 | Moderate (보통) |")
    md.append("| 0.60 ≤ κ < 0.80 | Substantial (상당함) |")
    md.append("| 0.80 ≤ κ ≤ 1.00 | Almost Perfect (거의 완벽) |")
    md.append("")
    
    # ========== 5. Disagreement Analysis ==========
    if iaa_result and iaa_result.disagreements:
        md.append("## 4️⃣ Disagreement Analysis")
        md.append("")
        md.append(f"총 {len(iaa_result.disagreements)}개 샘플에서 검증자 간 의견 불일치가 발생했습니다.")
        md.append("")
        md.append("| Sample ID | Level | Type | Annotations |")
        md.append("|-----------|-------|------|-------------|")
        for d in iaa_result.disagreements[:10]:  # Top 10
            md.append(f"| {d['sample_id']} | {d['level']} | {d['answer_type']} | {d['annotations']} |")
        
        if len(iaa_result.disagreements) > 10:
            md.append(f"| ... | ... | ... | ({len(iaa_result.disagreements) - 10} more) |")
        md.append("")
    
    # ========== 6. Conclusion ==========
    md.append("## 5️⃣ Conclusion")
    md.append("")
    
    # 신뢰성 판단 로직
    confidence_statements = []
    
    if report.auto_pass_rate >= 0.98:
        confidence_statements.append(f"자동 검증에서 {report.auto_pass_rate*100:.1f}%의 높은 통과율을 보임")
    elif report.auto_pass_rate >= 0.95:
        confidence_statements.append(f"자동 검증 통과율 {report.auto_pass_rate*100:.1f}%")
    
    if report.human_accuracy >= 0.95:
        confidence_statements.append(f"전문가 검증 정확도 {report.human_accuracy*100:.1f}% (n={report.human_sample_size}, {report.sampling_confidence} CI)")
    
    if report.iaa_kappa >= 0.8:
        confidence_statements.append(f"평가자 간 일치도 κ={report.iaa_kappa:.3f} (거의 완벽)")
    elif report.iaa_kappa >= 0.6:
        confidence_statements.append(f"평가자 간 일치도 κ={report.iaa_kappa:.3f} (상당한 일치)")
    
    if confidence_statements:
        md.append("### ✅ 데이터셋 신뢰성 근거")
        md.append("")
        for stmt in confidence_statements:
            md.append(f"- {stmt}")
        md.append("")
    
    overall_confidence = "HIGH" if (report.auto_pass_rate >= 0.95 and report.human_accuracy >= 0.90 and report.iaa_kappa >= 0.6) else \
                         "MEDIUM" if (report.auto_pass_rate >= 0.90 and report.human_accuracy >= 0.85) else "LOW"
    
    md.append(f"**Overall Confidence Level: {overall_confidence}**")
    md.append("")
    
    # ========== References ==========
    md.append("---")
    md.append("")
    md.append("## References")
    md.append("")
    md.append("- Cohen, J. (1960). A coefficient of agreement for nominal scales. *Educational and Psychological Measurement*, 20(1), 37-46.")
    md.append("- Fleiss, J. L. (1971). Measuring nominal scale agreement among many raters. *Psychological Bulletin*, 76(5), 378-382.")
    md.append("- Landis, J. R., & Koch, G. G. (1977). The measurement of observer agreement for categorical data. *Biometrics*, 33(1), 159-174.")
    md.append("")
    
    output_path.write_text("\n".join(md), encoding="utf-8")
    print(f"📄 Validation report saved: {output_path}")


# ============================================================================
# CLI Commands
# ============================================================================

def cmd_sample(args):
    """샘플 추출 명령"""
    csv_path = Path(args.csv)
    
    # Load dataset
    with csv_path.open("r", encoding="utf-8-sig") as f:
        rows = list(csv.DictReader(f))
    
    print(f"\n📂 Dataset: {csv_path.name}")
    print(f"   Total rows: {len(rows)}")
    
    # Sampling config
    config = SamplingConfig(
        confidence_level=args.confidence,
        margin_of_error=args.margin,
        min_per_stratum=args.min_per_stratum,
        seed=args.seed
    )
    
    # Stratified sampling
    samples, stats = stratified_sample(rows, config)
    
    print(f"\n📊 Sampling Statistics:")
    print(f"   Confidence Level: {stats['confidence_level']}")
    print(f"   Margin of Error: {stats['margin_of_error']}")
    print(f"   Sample Size: {stats['sample_size']} / {stats['population']}")
    print(f"   Seed: {stats['seed']}")
    print(f"\n   By Stratum:")
    for stratum, info in sorted(stats['strata'].items()):
        print(f"     {stratum}: {info['sampled']} / {info['population']} ({info['proportion']})")
    
    # Save sampling stats
    output_dir = Path(args.output).parent
    output_dir.mkdir(parents=True, exist_ok=True)
    
    stats_path = output_dir / "sampling_stats.json"
    with stats_path.open("w", encoding="utf-8") as f:
        json.dump(stats, f, ensure_ascii=False, indent=2)
    print(f"\n💾 Sampling stats: {stats_path}")
    
    # Generate annotation sheets
    if args.annotators:
        annotator_names = [n.strip() for n in args.annotators.split(",")]
    else:
        annotator_names = ["Annotator1", "Annotator2", "Annotator3"]
    
    print(f"\n📝 Generating annotation sheets for: {annotator_names}")
    
    for name in annotator_names:
        safe_name = name.replace(" ", "_").lower()
        sheet_path = output_dir / f"annotation_{safe_name}.csv"
        generate_annotation_sheet(
            samples,
            sheet_path,
            annotator_name=name,
            include_answer=not args.blind
        )
    
    # Save samples with metadata
    samples_path = Path(args.output)
    with samples_path.open("w", encoding="utf-8-sig", newline="") as f:
        if samples:
            fieldnames = list(samples[0].keys())
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(samples)
    print(f"💾 Samples saved: {samples_path}")
    
    print(f"\n✅ Done! 각 검증자에게 annotation_*.csv 파일을 배포하세요.")


def cmd_iaa(args):
    """IAA 계산 명령"""
    files = [Path(f) for f in args.files]
    
    print(f"\n📊 Calculating Inter-Annotator Agreement")
    print(f"   Files: {[f.name for f in files]}")
    
    # Calculate IAA
    result = calculate_iaa(files)
    
    print(f"\n📏 IAA Results:")
    print(f"   Number of Annotators: {result.num_annotators}")
    print(f"   Number of Samples: {result.num_samples}")
    print(f"\n   Percent Agreement: {result.percent_agreement*100:.2f}%")
    
    if result.num_annotators == 2:
        print(f"   Cohen's Kappa: {result.cohen_kappa:.4f}")
        print(f"   Interpretation: {interpret_kappa(result.cohen_kappa)}")
    
    print(f"   Fleiss' Kappa: {result.fleiss_kappa:.4f}")
    print(f"   Interpretation: {interpret_kappa(result.fleiss_kappa)}")
    
    print(f"\n   Disagreements: {len(result.disagreements)} samples")
    
    if result.agreement_by_level:
        print(f"\n   Agreement by Level:")
        for level, agree in sorted(result.agreement_by_level.items()):
            print(f"     {level}: {agree*100:.1f}%")
    
    if result.agreement_by_type:
        print(f"\n   Agreement by Answer Type:")
        for atype, agree in sorted(result.agreement_by_type.items()):
            print(f"     {atype}: {agree*100:.1f}%")
    
    # Save disagreements
    if args.output_disagreements and result.disagreements:
        disagree_path = Path(args.output_disagreements)
        with disagree_path.open("w", encoding="utf-8-sig", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=['sample_id', 'level', 'answer_type', 'annotations'])
            writer.writeheader()
            for d in result.disagreements:
                d_copy = d.copy()
                d_copy['annotations'] = str(d['annotations'])
                writer.writerow(d_copy)
        print(f"\n💾 Disagreements saved: {disagree_path}")
    
    # Calculate human accuracy
    print(f"\n📈 Human Accuracy (majority vote):")
    accuracy_result = calculate_human_accuracy(files, resolve_method="majority")
    print(f"   Correct: {accuracy_result['correct']} / {accuracy_result['total']}")
    print(f"   Accuracy: {accuracy_result['accuracy']*100:.2f}%")
    
    return result, accuracy_result


def cmd_report(args):
    """종합 리포트 생성 명령"""
    print(f"\n📄 Generating Validation Report")
    
    # Load auto verification results
    auto_stats = {}
    if args.auto_results:
        auto_path = Path(args.auto_results)
        if auto_path.suffix == '.json':
            with auto_path.open("r", encoding="utf-8") as f:
                auto_stats = json.load(f)
        elif auto_path.suffix == '.md':
            # Parse from markdown (simplified)
            content = auto_path.read_text(encoding="utf-8")
            import re
            pass_match = re.search(r'PASS.*?(\d+)', content)
            fail_match = re.search(r'FAIL.*?(\d+)', content)
            skip_match = re.search(r'SKIP.*?(\d+)', content)
            total_match = re.search(r'Total.*?(\d+)', content)
            
            auto_stats = {
                'passed': int(pass_match.group(1)) if pass_match else 0,
                'failed': int(fail_match.group(1)) if fail_match else 0,
                'skipped': int(skip_match.group(1)) if skip_match else 0,
                'total': int(total_match.group(1)) if total_match else 0
            }
    
    # Load human annotations and calculate IAA
    iaa_result = None
    human_result = None
    if args.human_annotations:
        files = [Path(f) for f in args.human_annotations]
        iaa_result = calculate_iaa(files)
        human_result = calculate_human_accuracy(files, resolve_method="majority")
    
    # Build report
    report = ValidationReport(
        dataset_name=args.dataset_name or "NetConfigQA",
        total_rows=auto_stats.get('total', 0),
        auto_total=auto_stats.get('total', 0),
        auto_passed=auto_stats.get('passed', 0),
        auto_failed=auto_stats.get('failed', 0),
        auto_skipped=auto_stats.get('skipped', 0),
        generated_at=datetime.now().strftime('%Y-%m-%d %H:%M')
    )
    
    # Auto pass rate
    verified = report.auto_total - report.auto_skipped
    if verified > 0:
        report.auto_pass_rate = report.auto_passed / verified
    
    # Human results
    if human_result:
        report.human_sample_size = human_result['total']
        report.human_accuracy = human_result['accuracy']
        
        for level, data in human_result.get('by_level', {}).items():
            if data['total'] > 0:
                report.human_by_level[level] = data['correct'] / data['total']
    
    # IAA results
    if iaa_result:
        report.num_annotators = iaa_result.num_annotators
        report.iaa_percent_agreement = iaa_result.percent_agreement
        report.iaa_kappa = iaa_result.fleiss_kappa if iaa_result.num_annotators > 2 else iaa_result.cohen_kappa
        report.iaa_interpretation = interpret_kappa(report.iaa_kappa)
    
    # Generate report
    output_path = Path(args.output)
    generate_validation_report(report, output_path, iaa_result, human_result)
    
    print(f"\n✅ Report generated: {output_path}")


def main():
    parser = argparse.ArgumentParser(
        description="NetConfigQA Dataset Validation Framework",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Step 1: 검증용 샘플 추출
  python validate_dataset.py sample --csv dataset.csv --output validation/samples.csv --annotators "유진,팀원A,팀원B"
  
  # Step 2: 각 팀원이 annotation_*.csv 파일 작성
  
  # Step 3: IAA 계산
  python validate_dataset.py iaa --files validation/annotation_유진.csv validation/annotation_팀원a.csv validation/annotation_팀원b.csv
  
  # Step 4: 종합 리포트
  python validate_dataset.py report --auto-results verification.md --human-annotations annotation_*.csv --output validation_report.md
        """
    )
    
    subparsers = parser.add_subparsers(dest="command", help="Commands")
    
    # ===== sample command =====
    sample_parser = subparsers.add_parser("sample", help="검증용 샘플 추출 및 annotation sheet 생성")
    sample_parser.add_argument("--csv", required=True, help="데이터셋 CSV 경로")
    sample_parser.add_argument("--output", required=True, help="샘플 저장 경로")
    sample_parser.add_argument("--confidence", type=float, default=0.95, help="신뢰수준 (default: 0.95)")
    sample_parser.add_argument("--margin", type=float, default=0.05, help="오차범위 (default: 0.05)")
    sample_parser.add_argument("--min-per-stratum", type=int, default=5, help="계층당 최소 샘플 (default: 5)")
    sample_parser.add_argument("--seed", type=int, default=42, help="랜덤 시드 (default: 42)")
    sample_parser.add_argument("--annotators", help="검증자 이름 (쉼표로 구분, default: Annotator1,Annotator2,Annotator3)")
    sample_parser.add_argument("--blind", action="store_true", help="정답 숨김 (블라인드 평가)")
    
    # ===== iaa command =====
    iaa_parser = subparsers.add_parser("iaa", help="Inter-Annotator Agreement 계산")
    iaa_parser.add_argument("--files", nargs="+", required=True, help="annotation CSV 파일들")
    iaa_parser.add_argument("--output-disagreements", help="불일치 항목 저장 경로")
    
    # ===== report command =====
    report_parser = subparsers.add_parser("report", help="종합 검증 리포트 생성")
    report_parser.add_argument("--auto-results", help="자동 검증 결과 (JSON 또는 MD)")
    report_parser.add_argument("--human-annotations", nargs="+", help="Human annotation 파일들")
    report_parser.add_argument("--dataset-name", default="NetConfigQA", help="데이터셋 이름")
    report_parser.add_argument("--output", required=True, help="리포트 저장 경로")
    
    args = parser.parse_args()
    
    if args.command == "sample":
        cmd_sample(args)
    elif args.command == "iaa":
        cmd_iaa(args)
    elif args.command == "report":
        cmd_report(args)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
