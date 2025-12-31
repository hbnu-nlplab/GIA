import pandas as pd
import json

# Read the dataset
csv_path = r'c:\Users\Yujin\CodeSpace\GIA\Data\Pnetlab\Research_Institute_Internal_DC\Dataset\Research_Institute_Internal_DC_dataset_batfish_20251227_192048.csv'
df = pd.read_csv(csv_path)

print("=" * 80)
print("Dataset Verification Report")
print("=" * 80)

print(f"\n📊 Total Questions: {len(df)}")

print(f"\n📈 Answer Type Distribution:")
print(df['answer_type'].value_counts().to_string())

print(f"\n🔍 Boolean Count: {(df['answer_type'] == 'boolean').sum()}")
if (df['answer_type'] == 'boolean').sum() > 0:
    print("   ⚠️ WARNING: Boolean types still exist!")
    bool_questions = df[df['answer_type'] == 'boolean']
    print(f"   Boolean questions:")
    for idx, row in bool_questions.head(5).iterrows():
        print(f"     - {row['question'][:100]}")
else:
    print("   ✅ No boolean types found!")

print(f"\n📊 Level Distribution:")
print(df['level'].value_counts().sort_index().to_string())

print(f"\n🔍 L5 Answer Type Breakdown:")
l5_df = df[df['level'] == 'L5']
print(l5_df['answer_type'].value_counts().to_string())

# Check new metrics
print(f"\n✅ New Metric Samples:")

# AAA authentication method
aaa = df[df['question'].str.contains('AAA 인증 방식', na=False)]
if len(aaa) > 0:
    print(f"\n  📌 aaa_authentication_method ({len(aaa)} questions):")
    for idx, row in aaa.head(2).iterrows():
        print(f"     Q: {row['question'][:70]}...")
        print(f"     A: {row['answer']}")
        print(f"     Type: {row['answer_type']}")

# MPLS LDP Router-ID  
mpls = df[df['question'].str.contains('MPLS LDP Router-ID', na=False)]
if len(mpls) > 0:
    print(f"\n  📌 mpls_ldp_router_id ({len(mpls)} questions):")
    for idx, row in mpls.head(2).iterrows():
        print(f"     Q: {row['question'][:70]}...")
        print(f"     A: {row['answer']}")
        print(f"     Type: {row['answer_type']}")

# Blackhole
bh = df[df['question'].str.contains('블랙홀', na=False)]
if len(bh) > 0:
    print(f"\n  📌 blackhole_destination_list ({len(bh)} questions):")
    for idx, row in bh.head(2).iterrows():
        print(f"     Q: {row['question'][:70]}...")
        print(f"     A: {row['answer']}")
        print(f"     Type: {row['answer_type']}")

# Multi-link failure
mlf = df[df['question'].str.contains('동시에 다운되면', na=False)]
if len(mlf) > 0:
    print(f"\n  📌 multi_link_failure_reachability ({len(mlf)} questions):")
    for idx, row in mlf.head(2).iterrows():
        print(f"     Q: {row['question'][:70]}...")
        print(f"     A: {row['answer']}")
        print(f"     Type: {row['answer_type']}")

print("\n" + "=" * 80)
