import json
import csv
import sys
from pathlib import Path

sys.path.append(str(Path(__file__).resolve().parents[1] / "src"))

from integrated_pipeline import DatasetSample, assign_task_category

def convert_to_csv(json_paths: list[str], csv_path: str):
    """
    여러 데이터셋 JSON 파일을 읽어 하나의 평가용 CSV 파일로 변환합니다.
    """
    print(f"🚀 {', '.join(json_paths)} 파일을 CSV로 변환 시작...")
    
    # [수정] 헤더에 'origin' 추가 (rule-based vs llm-generated 구분용)
    header = [
        "id", "origin", "level", "task_category", "answer_type", 
        "complexity", "persona", "question", "ground_truth", 
        "explanation", "context", "source_files"
    ]
    all_samples = []

    # [수정] 여러 JSON 파일을 순회하며 데이터 로드
    for json_path in json_paths:
        path = Path(json_path)
        if not path.exists():
            print(f"⚠️ 경고: {json_path} 파일을 찾을 수 없습니다. 건너뜁니다.")
            continue
        
        with open(path, 'r', encoding='utf-8') as f:
            dataset = json.load(f)

        # JSON 데이터 구조에 따라 샘플 추출
        if isinstance(dataset, dict):
            for split in ["train", "validation", "test"]:
                if split in dataset and isinstance(dataset[split], list):
                    all_samples.extend(dataset[split])
        elif isinstance(dataset, list):
            all_samples.extend(dataset)

    rows = []
    for sample in all_samples:
        ds = DatasetSample(
            id=sample.get("id", ""),
            question=sample.get("question", ""),
            context=sample.get("context", ""),
            ground_truth=sample.get("ground_truth"),
            explanation=sample.get("explanation", ""),
            answer_type=sample.get("answer_type", ""),
            category=sample.get("category", ""),
            complexity=sample.get("complexity", ""),
            level=sample.get("level", 1),
            persona=sample.get("persona"),
            scenario=sample.get("scenario"),
            source_files=sample.get("source_files"),
            metadata=sample.get("metadata", {}),
        )

        task_category = ds.metadata.get("task_category") or assign_task_category(ds)
        origin = ds.metadata.get("origin", "unknown")
        
        # ground_truth가 리스트나 딕셔너리일 경우 JSON 문자열로 변환
        gt = ds.ground_truth
        if isinstance(gt, (dict, list)):
            gt_str = json.dumps(gt, ensure_ascii=False)
        else:
            gt_str = str(gt)

        rows.append({
            "id": ds.id,
            "origin": origin,
            "level": ds.level,
            "task_category": task_category,
            "answer_type": ds.answer_type,
            "complexity": ds.complexity,
            "persona": ds.persona,
            "question": ds.question,
            "ground_truth": gt_str,
            "explanation": ds.explanation,
            "context": ds.context,
            "source_files": ", ".join(ds.source_files or []),
        })

    output_path = Path(csv_path)
    output_path.parent.mkdir(exist_ok=True, parents=True)
    
    with open(output_path, 'w', newline='', encoding='utf-8-sig') as f:
        writer = csv.DictWriter(f, fieldnames=header)
        writer.writeheader()
        writer.writerows(rows)
    
    print(f"✅ CSV 변환 완료! {len(rows)}개 행이 {csv_path}에 저장되었습니다.")

if __name__ == '__main__':
    # [수정] basic과 enhanced JSON 파일을 모두 입력으로 전달
    convert_to_csv(
        json_paths=[
            "/workspace/Yujin/GIA/basic_dataset.json",
            
        ],
        csv_path="output/basic_dataset_many.csv"
    )