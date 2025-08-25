import json
import csv
from integrated_pipeline import DatasetSample, assign_task_category


def convert_to_csv(json_path="output_dataset/enhanced_dataset.json", csv_path="output_dataset/dataset_for_evaluation.csv"):
    """최종 데이터셋 JSON을 평가용 CSV 파일로 변환합니다."""
    with open(json_path, 'r', encoding='utf-8') as f:
        dataset = json.load(f)

    # rows의 키(id, level, context, question, ground_truth, explanation, answer_type, task_category, source_files)에 맞게 헤더 정렬
    header = [
        "id",
        "level",
        "context",
        "question",
        "ground_truth",
        "explanation",
        "answer_type",
        "task_category",
        "source_files",
    ]
    rows = []

    # 다양한 JSON 구조를 지원: {train/validation/test} 또는 리스트 형태
    samples = []
    if isinstance(dataset, dict):
        for split in ["train", "validation", "test"]:
            split_data = dataset.get(split)
            if isinstance(split_data, list):
                samples.extend(split_data)
        # 스플릿 키가 없고 data 키가 있는 경우 대응
        if not samples and isinstance(dataset.get("data"), list):
            samples = dataset["data"]
    elif isinstance(dataset, list):
        samples = dataset
    else:
        print("지원하지 않는 데이터 형식의 JSON입니다.")
        return

    for sample in samples:
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
            metadata=sample.get("metadata"),
        )

        task_category = ds.metadata.get("task_category") if ds.metadata and "task_category" in ds.metadata else assign_task_category(ds)
        referenced_files_str = ", ".join(ds.source_files or [])
        rows.append({
            "id": ds.id,
            "level": ds.level,
            "context": ds.context,
            "question": ds.question,
            "ground_truth": ds.ground_truth,
            "explanation": ds.explanation,
            "answer_type": ds.answer_type,
            "task_category": task_category,
            "source_files": referenced_files_str,
        })

    with open(csv_path, 'w', newline='', encoding='utf-8-sig') as f:
        writer = csv.DictWriter(f, fieldnames=header)
        writer.writeheader()
        writer.writerows(rows)

    print(f"✅ CSV 파일 생성 완료: {csv_path}")


if __name__ == "__main__":
    convert_to_csv()
