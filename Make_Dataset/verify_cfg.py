"""
cfg 파일과 CSV 결과물 비교 검증 스크립트
"""
import pandas as pd
import json
import glob
import os

# 최신 CSV 찾기
csv_files = glob.glob(r"C:\Users\Yujin\CodeSpace\GIA\Data\Pnetlab\Research_Institute_Internal_DC\Dataset\*.csv")
latest_csv = max(csv_files, key=os.path.getctime)
print(f"📄 분석 파일: {latest_csv}")

df = pd.read_csv(latest_csv, on_bad_lines='skip')
print(f"\n📊 총 질문 수: {len(df)}")

# PE1 관련 질문 필터링
pe1_questions = df[df['question'].str.contains('PE1', case=False, na=False)]
print(f"\n🔍 PE1 관련 질문 수: {len(pe1_questions)}")

# 검증할 항목들 (PE1.cfg 기반)
expected_values = {
    "hostname": "PE1",
    "bgp_as": "65000",
    "vrf_count": 3,  # VRF_AI, VRF_BIO, VRF_HPC
    "ospf_area": "0",
    "ssh_enabled": True,
    "mpls_enabled": True,
}

print("\n" + "="*60)
print("🧪 PE1 설정 검증 결과")
print("="*60)

# 1. BGP AS 확인
bgp_as_q = pe1_questions[pe1_questions['question'].str.contains('Local AS', case=False, na=False)]
if not bgp_as_q.empty:
    answer = bgp_as_q.iloc[0]['answer']
    print(f"\n✅ BGP Local AS:")
    print(f"   cfg 기대값: {expected_values['bgp_as']}")
    print(f"   CSV 결과값: {answer}")
    if expected_values['bgp_as'] in str(answer):
        print(f"   → 일치 ✓")
    else:
        print(f"   → 불일치 ✗")

# 2. VRF 목록 확인
vrf_q = df[df['question'].str.contains('VRF.*PE1', case=False, na=False)]
if vrf_q.empty:
    vrf_q = df[df['question'].str.contains('PE1.*VRF', case=False, na=False)]
if not vrf_q.empty:
    answer = vrf_q.iloc[0]['answer']
    print(f"\n✅ VRF 목록:")
    print(f"   cfg 기대값: VRF_AI, VRF_BIO, VRF_HPC (3개)")
    print(f"   CSV 결과값: {answer}")

# 3. SSH 활성화 확인
ssh_q = pe1_questions[pe1_questions['question'].str.contains('SSH', case=False, na=False)]
if not ssh_q.empty:
    answer = ssh_q.iloc[0]['answer']
    print(f"\n✅ SSH 활성화:")
    print(f"   cfg 기대값: True (ip ssh version 2)")
    print(f"   CSV 결과값: {answer}")
    if str(answer).lower() == 'true':
        print(f"   → 일치 ✓")
    else:
        print(f"   → 불일치 ✗")

# 4. OSPF 영역 확인
ospf_q = pe1_questions[pe1_questions['question'].str.contains('OSPF', case=False, na=False)]
if not ospf_q.empty:
    for _, row in ospf_q.head(2).iterrows():
        print(f"\n✅ OSPF 관련:")
        print(f"   질문: {row['question'][:60]}...")
        print(f"   답변: {row['answer']}")

# 5. L4/L5 질문 확인
l4_l5 = df[df['level'].isin(['L4', 'L5'])]
print(f"\n" + "="*60)
print(f"📈 L4/L5 고급 분석 질문: {len(l4_l5)}개")
print("="*60)
for level in ['L4', 'L5']:
    level_qs = l4_l5[l4_l5['level'] == level]
    print(f"\n📌 {level} 질문 ({len(level_qs)}개):")
    for _, row in level_qs.head(2).iterrows():
        q = row['question'][:70] + "..." if len(row['question']) > 70 else row['question']
        print(f"   • {q}")
        print(f"     답변: {row['answer'][:50]}...")

print("\n✅ 검증 완료!")
