import pandas as pd
import glob
import os

# Find latest csv
csv_files = glob.glob(r"C:\Users\Yujin\CodeSpace\GIA\Data\Pnetlab\L2VPN\Dataset\*.csv")
if not csv_files:
    print("No CSV found")
    exit(1)
latest_csv = max(csv_files, key=os.path.getctime)
print(f"Analyzing: {latest_csv}")

df = pd.read_csv(latest_csv, on_bad_lines='skip')
print("\n--- Category Counts ---")
print(df['level'].value_counts()) 

l5 = df[df['level'] == 'L5']
print("\n--- L5 (Level) Status Counts ---")
print(l5['answer_status'].value_counts())

# Print UNKNOWN details
unknowns = df[df['answer_status'] == 'UNKNOWN']
if not unknowns.empty:
    print(f"\n--- UNKNOWN Count: {len(unknowns)} ---")
    print(unknowns[['level', 'question', 'answer', 'unknown_reason']].head(5))

# Sampling NOT_CONFIGURED
nc = df[df['answer_status'] == 'NOT_CONFIGURED']
print(f"\n--- NOT_CONFIGURED Count: {len(nc)} ---")
if not nc.empty:
    sample_size = min(20, len(nc))
    print(f"Sampling {sample_size} examples:")
    sample = nc.sample(n=sample_size, random_state=42)
    for idx, row in sample.iterrows():
        print(f"[{row['level']}] {row['question']} -> {row['answer']} (Reason: {row['unknown_reason']})")
