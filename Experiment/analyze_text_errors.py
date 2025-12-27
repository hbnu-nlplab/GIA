"""
Text 타입 오답 분석 스크립트
"""
import json
from collections import defaultdict

# 결과 파일 로드
with open('Experiment/results/Qwen3-8B/results_analyzed_20251226_171545.json', 'r', encoding='utf-8') as f:
    data = json.load(f)

# Text 타입 필터링
all_text = [r for r in data['results'] if r['type'] == 'text']
text_errors = [r for r in all_text if r['type_aware_score'] == 0.0]
text_correct = [r for r in all_text if r['type_aware_score'] == 1.0]

print(f"=" * 80)
print(f"TEXT 타입 분석 리포트")
print(f"=" * 80)
print(f"\n전체 Text 문제: {len(all_text)}개")
print(f"정답: {len(text_correct)}개 ({len(text_correct)/len(all_text)*100:.1f}%)")
print(f"오답: {len(text_errors)}개 ({len(text_errors)/len(all_text)*100:.1f}%)")

# 카테고리별 분석
print(f"\n{'='*80}")
print(f"카테고리별 오답 분포")
print(f"{'='*80}")
error_by_category = defaultdict(list)
for err in text_errors:
    error_by_category[err['category']].append(err)

for category, errors in sorted(error_by_category.items(), key=lambda x: len(x[1]), reverse=True):
    print(f"\n{category}: {len(errors)}개")
    
# 오답 패턴 분석
print(f"\n{'='*80}")
print(f"오답 패턴 분석")
print(f"{'='*80}\n")

# 패턴 1: 포맷 차이
format_diff = []
# 패턴 2: 추가 텍스트
extra_text = []
# 패턴 3: 완전히 다른 답
completely_wrong = []
# 패턴 4: NOT_CONFIGURED 처리 실패
not_configured_fail = []

for err in text_errors:
    gold = err['gold_cleaned'].lower().strip()
    pred = err['pred'].lower().strip()
    
    if err['status'] == 'NOT_CONFIGURED' and pred:
        not_configured_fail.append(err)
    elif gold in pred or pred in gold:
        if len(pred) > len(gold) * 1.5:
            extra_text.append(err)
        else:
            format_diff.append(err)
    else:
        completely_wrong.append(err)

print(f"1. NOT_CONFIGURED 처리 실패: {len(not_configured_fail)}개")
print(f"2. 포맷 차이 (부분 일치): {len(format_diff)}개")
print(f"3. 추가 텍스트 포함: {len(extra_text)}개")
print(f"4. 완전히 틀린 답: {len(completely_wrong)}개")

# 샘플 출력
print(f"\n{'='*80}")
print(f"오답 샘플 (각 패턴별 3개)")
print(f"{'='*80}")

def print_sample(pattern_name, samples, max_samples=3):
    print(f"\n[{pattern_name}]")
    for i, err in enumerate(samples[:max_samples], 1):
        print(f"\n  {i}. Question: {err['question'][:70]}")
        print(f"     Level: {err['level']} | Category: {err['category']}")
        print(f"     Gold: '{err['gold_cleaned']}'")
        print(f"     Pred: '{err['pred']}'")
        if err.get('token_f1', 0) > 0:
            print(f"     Token F1: {err['token_f1']:.2f} (부분 일치 있음)")

print_sample("NOT_CONFIGURED 처리 실패", not_configured_fail)
print_sample("포맷 차이 (부분 일치)", format_diff)
print_sample("추가 텍스트 포함", extra_text)
print_sample("완전히 틀린 답", completely_wrong)

# L3 Comparison_Analysis 상세 분석
comparison_errors = [e for e in text_errors if e['category'] == 'Comparison_Analysis']
if comparison_errors:
    print(f"\n{'='*80}")
    print(f"Comparison_Analysis 상세 분석 ({len(comparison_errors)}개)")
    print(f"{'='*80}")
    
    for i, err in enumerate(comparison_errors[:5], 1):
        print(f"\n{i}. {err['question'][:80]}")
        print(f"   Gold: '{err['gold_cleaned']}'")
        print(f"   Pred: '{err['pred']}'")
        print(f"   Token F1: {err.get('token_f1', 0):.2f}")
        print(f"   ROUGE-L: {err.get('rougeL', 0):.2f}")

print(f"\n{'='*80}")
print(f"결론 및 제안")
print(f"{'='*80}\n")

print("주요 문제점:")
print("1. 정확한 텍스트 매칭만 인정 → 포맷 차이에 취약")
print("2. Comparison_Analysis에서 대량 오답")
print("3. 토큰 레벨에서는 부분 점수가 있지만 Type-Aware는 0점")
print("\n개선 방안:")
print("1. Text 타입에 Token F1 기반 부분 점수 도입")
print("2. 또는 Fuzzy Matching (유사도 임계값)")
print("3. Comparison_Analysis는 별도 평가 방식 고려")
