import pandas as pd
from pathlib import Path

# 파일 경로
csv_path = Path(r'c:\Users\Yujin\CodeSpace\GIA\Data\Pnetlab\Research_Institute_Internal_DC\Dataset\Research_Institute_Internal_DC_dataset_batfish_20251227_203825.csv')

# 데이터 로드
df = pd.read_csv(csv_path)
print(f"Total Rows: {len(df)}")

# 검증할 키워드 (ID에 포함된 것)
test_keywords = {
    "L1 New": ['BANNER_MOTD_CONTENT', 'LOOPBACK_INTERFACES_LIST', 'STATIC_ROUTE_COUNT', 'HARDWARE_INVENTORY'],
    "L4 Fixed": ['WAYPOINT', 'ISOLATION', 'ASYMMETRIC'],
    "L5 New": ['REDUNDANT', 'OSPF_AREA0']
}

print("\n=== 메트릭 생성 여부 확인 (ID 키워드 기준) ===")
for category, keywords in test_keywords.items():
    print(f"\n[{category}]")
    for k in keywords:
        count = df['id'].str.contains(k, na=False).sum()
        print(f"  - {k}: {count} questions")

# 전체 카테고리 확인
print("\n=== 카테고리별 개수 ===")
print(df['category'].value_counts())
