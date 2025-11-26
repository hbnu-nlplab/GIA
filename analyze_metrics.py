import json

# 정책 파일에서 모든 메트릭 추출
with open('Make_Dataset/policies.json', 'r', encoding='utf-8') as f:
    policies = json.load(f)

policy_metrics = set()
policy_by_category = {}

# policies 배열에서 메트릭 추출
for policy in policies.get('policies', []):
    cat_name = policy.get('category', '')
    if cat_name not in policy_by_category:
        policy_by_category[cat_name] = set()
    
    levels = policy.get('levels', {})
    for level_name, level_items in levels.items():
        for item in level_items:
            metric = item.get('primary_metric', '')
            if metric:
                policy_metrics.add(metric)
                policy_by_category[cat_name].add(metric)

print(f'=== 정책 파일의 메트릭 수: {len(policy_metrics)} ===')

# 데이터셋에서 사용된 메트릭 추출
with open('output/logic_only_20251126_175853/dataset_logic_only_20251126_175853.json', 'r', encoding='utf-8') as f:
    dataset = json.load(f)

used_metrics = set()
# dataset이 train/validation/test 분할 구조인 경우
if isinstance(dataset, dict) and 'train' in dataset:
    items = dataset.get('train', []) + dataset.get('validation', []) + dataset.get('test', [])
elif isinstance(dataset, dict):
    items = dataset.get('questions', dataset.get('data', []))
else:
    items = dataset

for item in items:
    if isinstance(item, dict):
        # evidence_hint에서 메트릭 이름 추출
        hint = item.get('evidence_hint', {})
        if isinstance(hint, dict):
            metric = hint.get('metric', '')
            if metric:
                used_metrics.add(metric)

print(f'=== 데이터셋에서 사용된 메트릭 수: {len(used_metrics)} ===')

# 사용되지 않은 메트릭
unused = policy_metrics - used_metrics
print(f'\n=== 사용되지 않은 메트릭 ({len(unused)}개) ===')
for m in sorted(unused):
    print(f'  - {m}')

# 추가로 사용된 메트릭 (정책에 없는데 사용된 것)
extra = used_metrics - policy_metrics
if extra:
    print(f'\n=== 정책에 없는데 사용된 메트릭 ({len(extra)}개) ===')
    for m in sorted(extra):
        print(f'  - {m}')

# 카테고리별 분석
print('\n=== 카테고리별 메트릭 사용 현황 ===')
for cat_name, cat_metrics in policy_by_category.items():
    cat_used = cat_metrics & used_metrics
    cat_unused = cat_metrics - used_metrics
    print(f'\n[{cat_name}]')
    print(f'  정의됨: {len(cat_metrics)}개, 사용됨: {len(cat_used)}개, 미사용: {len(cat_unused)}개')
    if cat_unused:
        print(f'  미사용 목록: {sorted(cat_unused)}')

