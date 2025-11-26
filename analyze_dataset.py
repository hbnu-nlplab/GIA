import pandas as pd

df = pd.read_csv('output/logic_only_20251126_175853/dataset_logic_only_20251126_175853.csv')

print('=== 레벨별 문제 수 ===')
print(df['level'].value_counts().sort_index())
print()

print('=== 카테고리별 문제 수 ===')
print(df['category'].value_counts())
print()

# 장비 수 확인
devices = set()
for sf in df['source_files'].dropna():
    for f in sf.split(', '):
        devices.add(f.replace('.xml', ''))
print('=== 장비 목록 ===')
print(sorted(devices))
print(f'총 장비 수: {len(devices)}')
print()

# L1 분석
l1_df = df[df['level'] == 'L1']
print('=== L1 문제 분석 ===')
print(f'L1 문제 수: {len(l1_df)}')

# 메트릭별 문제 수
l1_metrics = l1_df['id'].str.extract(r'([A-Z_]+)_\d+')[0].value_counts()
print(f'\nL1 메트릭 종류: {len(l1_metrics)}개')
print(f'샘플링 전 예상 (8장비 x {len(l1_metrics)}메트릭): {len(l1_metrics) * 8}개')
print(f'현재 L1: {len(l1_df)}개')
print(f'샘플링 비율: {len(l1_df) / (len(l1_metrics) * 8):.1%}')

print('\n=== L3 비교 질문 분석 ===')
l3_df = df[df['level'] == 'L3']
compare_df = df[df['category'] == 'Comparison_Analysis']
print(f'L3 문제 수: {len(l3_df)}')
print(f'Comparison_Analysis: {len(compare_df)}')

# DEVICE_PAIR 조합 수 계산 (8C2 = 28)
print(f'\n장비 쌍 조합 (8C2): 28개')
print(f'비교 메트릭당 예상: 28개')

# 비교 메트릭별
compare_metrics = compare_df['id'].str.extract(r'([A-Z_]+)_\d+')[0].value_counts()
print(f'\n비교 메트릭별 문제 수:')
for m, c in compare_metrics.items():
    print(f'  {m}: {c}개')

print('\n=== 문제 수 요약 ===')
print(f'총 문제: {len(df)}개')
print(f'  L1: {len(l1_df)}개 ({len(l1_df)/len(df)*100:.1f}%)')
print(f'  L2: {len(df[df["level"]=="L2"])}개')
print(f'  L3: {len(l3_df)}개 ({len(l3_df)/len(df)*100:.1f}%)')

