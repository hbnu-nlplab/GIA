import json
import numpy as np
import evaluate
import pandas as pd
import sys
import os
from pathlib import Path
import time

# === 경로 설정 ===
BASE_DIR = Path(__file__).resolve().parents[1]
sys.path.append(str(BASE_DIR))

# 평가할 파일들의 경로 리스트
DATA_FILES = {
    "TeleQuAD": BASE_DIR / "data" / "passages" / "full" / "telequad_passage.json",
    "TeleQnA": BASE_DIR / "data" / "passages" / "full" / "teleqna_passage.json",
    "NetBench": BASE_DIR / "data" / "passages" / "full" / "netbench_passage.json",
    "NetConfig": BASE_DIR / "data" / "passages" / "full" / "netconfig_passage.json"
}

def load_metrics():
    print("Loading metrics models... (This may take a while)")
    rouge = evaluate.load('rouge')
    bertscore = evaluate.load('bertscore')
    return rouge, bertscore

def evaluate_single_file(file_path, dataset_name, rouge, bertscore):
    if not os.path.exists(file_path):
        print(f"⚠️ File not found: {dataset_name}")
        return None

    with open(file_path, 'r', encoding='utf-8') as f:
        data = json.load(f)

    refs = []
    preds = []
    
    for item in data:
        p = item.get('passage', '')
        g = item.get('gold_answer', '')

        # [Fix] gold_answer가 dict나 list일 경우 에러 방지 (문자열 변환)
        if isinstance(g, dict):
            # 만약 dict라면 문자열로 변환 (필요시 특정 키값만 추출 가능)
            g = str(g)
        elif isinstance(g, list):
            # 만약 정답이 리스트라면 첫 번째 요소를 쓰거나 문자열로 변환
            g = str(g[0]) if len(g) > 0 else ""
        elif g is None:
            g = ""
            
        # passage도 안전하게 문자열 변환
        if p is None:
            p = ""
        
        preds.append(str(p).lower())
        refs.append(str(g).lower())

    if not preds:
        return None

    # 지표 계산
    # 1. BERTScore (의미 유사도)
    bert_res = bertscore.compute(predictions=preds, references=refs, lang='en', model_type="distilbert-base-uncased")
    f1_mean = np.mean(bert_res['f1'])
    
    # 2. Substring Match (정답 포함 여부 - Recall 성격)
    inclusion_count = sum(1 for p, r in zip(preds, refs) if r in p)
    inclusion_rate = (inclusion_count / len(preds)) * 100
    
    # 3. 평균 길이
    avg_len = np.mean([len(p) for p in preds])

    return {
        "BERT_F1": round(f1_mean, 4),
        "Include_%": round(inclusion_rate, 2),
        "Avg_Len": round(avg_len, 1),
        "Count": len(preds)
    }

def run_evaluation_all():
    rouge_metric, bert_metric = load_metrics()
    
    # 최종 리포트용 딕셔너리
    report_row = {"Timestamp": time.strftime("%Y-%m-%d %H:%M")}
    
    total_bert = 0
    valid_datasets = 0

    print("-" * 50)
    print(f"🚀 Starting Batch Evaluation")
    print("-" * 50)

    for name, path in DATA_FILES.items():
        print(f"Processing {name}...")
        res = evaluate_single_file(path, name, rouge_metric, bert_metric)
        
        if res:
            # 데이터셋별 컬럼 추가 (예: NetConfig_BERT, NetConfig_Len)
            report_row[f"{name}_BERT"] = res["BERT_F1"]
            report_row[f"{name}_Inc%"] = res["Include_%"]
            report_row[f"{name}_Len"] = res["Avg_Len"]
            
            total_bert += res["BERT_F1"]
            valid_datasets += 1
            print(f"   -> BERT: {res['BERT_F1']}, Inc: {res['Include_%']}%, Len: {res['Avg_Len']}")
        else:
            print("   -> No data or file missing.")

    # 종합 점수 계산 (Average BERTScore)
    if valid_datasets > 0:
        report_row["Overall_Avg_BERT"] = round(total_bert / valid_datasets, 4)
    else:
        report_row["Overall_Avg_BERT"] = 0.0

    # 결과 DataFrame 생성 및 저장
    df = pd.DataFrame([report_row])
    
    # 누적 저장 (append mode)
    output_csv = BASE_DIR / "data" / "experiment_history.csv"
    
    if os.path.exists(output_csv):
        df.to_csv(output_csv, mode='a', header=False, index=False)
    else:
        df.to_csv(output_csv, mode='w', header=True, index=False)
        
    print("-" * 50)
    print(f"✅ Evaluation Complete. Saved to {output_csv}")
    print(df.T) # 결과를 세로로 보여줌

if __name__ == "__main__":
    run_evaluation_all()