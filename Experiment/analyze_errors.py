import json

with open('Experiment/results/Qwen3-8B/results_analyzed_20251224_004016.json', 'r', encoding='utf-8') as f:
    data = json.load(f)

results = data['results']

# 475-516번 문제 분석 (L3, L4 레벨)
target_results = [r for r in results if 475 <= int(r.get('question_id', 0)) <= 516]

print(f'=== 분석 대상: {len(target_results)}개 문제 ===\n')

# 1. Truncation 분석
truncated = []
for r in target_results:
    raw = r.get('raw_pred', '')
    # <think> 태그가 있는데 </think>가 없으면 truncated
    if '<think>' in raw and '</think>' not in raw:
        truncated.append(r['question_id'])

print(f'1. Truncation (토큰 제한으로 잘림): {len(truncated)}개')
print(f'   - 비율: {len(truncated)/len(target_results)*100:.1f}%')

# 2. 빈 pred 분석
empty_pred = [r for r in target_results if r.get('pred', '') == '']
print(f'\n2. 빈 pred (답변 추출 실패): {len(empty_pred)}개')
print(f'   - 비율: {len(empty_pred)/len(target_results)*100:.1f}%')

# 3. 정답 vs 오답
correct = [r for r in target_results if r.get('score', 0) == 1.0]
wrong = [r for r in target_results if r.get('score', 0) == 0.0]
partial = [r for r in target_results if 0 < r.get('score', 0) < 1.0]

print(f'\n3. 점수 분포:')
print(f'   - 정답 (1.0): {len(correct)}개 ({len(correct)/len(target_results)*100:.1f}%)')
print(f'   - 오답 (0.0): {len(wrong)}개 ({len(wrong)/len(target_results)*100:.1f}%)')
print(f'   - 부분점수: {len(partial)}개')

# 4. 레벨별 분석
l3 = [r for r in target_results if r.get('level') == 'L3']
l4 = [r for r in target_results if r.get('level') == 'L4']

l3_correct = len([r for r in l3 if r.get('score', 0) == 1.0])
l4_correct = len([r for r in l4 if r.get('score', 0) == 1.0])

print(f'\n4. 레벨별 정확도:')
if l3:
    print(f'   - L3: {l3_correct}/{len(l3)} ({l3_correct/len(l3)*100:.1f}%)')
if l4:
    print(f'   - L4: {l4_correct}/{len(l4)} ({l4_correct/len(l4)*100:.1f}%)')

# 5. 오답 원인 분류
print(f'\n5. 오답 원인 상세 분석 (샘플 5개):')
print('='*80)

for r in wrong[:5]:
    qid = r['question_id']
    gold = r.get('gold_cleaned', '')[:60]
    pred = r.get('pred', '')[:60] if r.get('pred') else '[empty]'
    raw_pred = r.get('raw_pred', '')
    
    has_think = '<think>' in raw_pred
    has_close_think = '</think>' in raw_pred
    truncated_flag = has_think and not has_close_think
    
    # raw_pred의 마지막 50자
    raw_tail = raw_pred[-80:] if len(raw_pred) > 80 else raw_pred
    
    print(f'\nQ{qid} [{r.get("level")}] [{r.get("category")}]')
    print(f'  Gold: "{gold}"')
    print(f'  Pred: "{pred}"')
    print(f'  Truncated: {truncated_flag}')
    print(f'  Raw 끝부분: ...{raw_tail}')

# 6. 정답 케이스 분석
print(f'\n\n6. 정답 케이스 분석:')
print('='*80)
for r in correct[:3]:
    qid = r['question_id']
    gold = r.get('gold_cleaned', '')[:60]
    pred = r.get('pred', '')[:60]
    print(f'\nQ{qid} [{r.get("level")}]')
    print(f'  Gold: "{gold}"')
    print(f'  Pred: "{pred}"')
    print(f'  Score: {r.get("score")}')

# 7. Truncation vs 실제 오답 비율
print(f'\n\n7. 오답 원인 종합:')
truncated_wrong = len([r for r in wrong if '<think>' in r.get('raw_pred', '') and '</think>' not in r.get('raw_pred', '')])
format_wrong = len([r for r in wrong if r.get('pred') and '</think>' in r.get('raw_pred', '')])
print(f'   - Truncation으로 인한 오답: {truncated_wrong}개 ({truncated_wrong/len(wrong)*100:.1f}%)')
print(f'   - 답변은 있으나 형식/내용 오류: {format_wrong}개')


