import pandas as pd

# 원본 CSV 경로
input_path = "/workspace/Yujin/GIA/data/Final/dataset_for_evaluation_fin.csv"
# 저장할 CSV 경로
output_path = "/workspace/Yujin/GIA/Network-Management-System-main/dataset/test_fin.csv"

# CSV 읽기
df = pd.read_csv(input_path)

# 필요한 컬럼만 추출
df_selected = df[["origin","question", "ground_truth", "explanation"]]

# 새 CSV로 저장
df_selected.to_csv(output_path, index=False, encoding="utf-8")

print(f"✅ Saved test.csv with {len(df_selected)} rows at {output_path}")
