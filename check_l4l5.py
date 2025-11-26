import pandas as pd

df = pd.read_csv('output/logic_only_20251126_163538/dataset_logic_only_20251126_163538.csv')

print("=== L4 문제 ===")
l4 = df[df['level'] == 'L4']
print(f"총 {len(l4)}개")
for _, row in l4.iterrows():
    print(f"  [{row['id']}] {row['question'][:80]}...")
    print(f"    Answer: {row['ground_truth'][:50]}...")
    print()

print("\n=== L5 문제 ===")
l5 = df[df['level'] == 'L5']
print(f"총 {len(l5)}개")
for _, row in l5.iterrows():
    print(f"  [{row['id']}] {row['question'][:80]}...")
    print(f"    Answer: {row['ground_truth'][:50]}...")
    print()

print("\n=== 레벨별 요약 ===")
print(df['level'].value_counts())

