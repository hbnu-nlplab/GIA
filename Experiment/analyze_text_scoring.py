"""
Text 타입 채점 분석 (Token F1 적용 후)
"""
import json
from collections import defaultdict

# Load results
with open('Experiment/results/Qwen3-8B/results_analyzed_20251226_171545.json', 'r', encoding='utf-8') as f:
    data = json.load(f)

# Filter text type
all_text = [r for r in data['results'] if r['type'] == 'text']

# 점수 분포 분석
score_0 = [r for r in all_text if r['type_aware_score'] == 0.0]
score_partial = [r for r in all_text if 0 < r['type_aware_score'] < 1.0]
score_1 = [r for r in all_text if r['type_aware_score'] == 1.0]

print("=" * 70)
print("TEXT 타입 채점 분석 (Token F1 적용 후)")
print("=" * 70)
print(f"\n전체 Text 문제: {len(all_text)}개")
print(f"  - 완전 정답 (1.0): {len(score_1)}개 ({len(score_1)/len(all_text)*100:.1f}%)")
print(f"  - 부분 점수 (0<x<1): {len(score_partial)}개 ({len(score_partial)/len(all_text)*100:.1f}%)")
print(f"  - 완전 오답 (0.0): {len(score_0)}개 ({len(score_0)/len(all_text)*100:.1f}%)")

# 부분 점수 샘플
print("\n" + "=" * 70)
print("부분 점수 획득 샘플 (5개) - Token F1으로 구제됨")
print("=" * 70)
for i, r in enumerate(score_partial[:5], 1):
    print(f"\n{i}. Q: {r['question'][:60]}...")
    print(f"   Gold: '{r['gold_cleaned']}'")
    print(f"   Pred: '{r['pred']}'")
    print(f"   Type-Aware Score: {r['type_aware_score']:.2f} (Token F1으로 부분 점수)")
    print(f"   Traditional Token F1: {r.get('token_f1', 0):.2f}")

# 완전 오답 샘플
print("\n" + "=" * 70)
print("완전 오답 샘플 (5개) - 여전히 0점인 케이스")
print("=" * 70)
for i, r in enumerate(score_0[:5], 1):
    print(f"\n{i}. Q: {r['question'][:60]}...")
    print(f"   Gold: '{r['gold_cleaned']}'")
    print(f"   Pred: '{r['pred']}'")
    print(f"   Type-Aware Score: 0.0")
    print(f"   Category: {r['category']}")

# 카테고리별 분석
print("\n" + "=" * 70)
print("카테고리별 Text 평균 점수")
print("=" * 70)
by_cat = defaultdict(list)
for r in all_text:
    by_cat[r['category']].append(r['type_aware_score'])

for cat, scores in sorted(by_cat.items(), key=lambda x: sum(x[1])/len(x[1]) if x[1] else 0, reverse=True):
    avg = sum(scores) / len(scores) if scores else 0
    print(f"  {cat}: {avg*100:.1f}% (n={len(scores)})")

# 부분 점수 분포
print("\n" + "=" * 70)
print("부분 점수 분포 (0 < score < 1)")
print("=" * 70)
partial_scores = [r['type_aware_score'] for r in score_partial]
if partial_scores:
    bins = [(0, 0.2), (0.2, 0.4), (0.4, 0.6), (0.6, 0.8), (0.8, 1.0)]
    for low, high in bins:
        count = sum(1 for s in partial_scores if low < s <= high)
        print(f"  {low:.1f} < score <= {high:.1f}: {count}개")
