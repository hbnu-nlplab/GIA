import json
import csv
from integrated_pipeline import DatasetSample, assign_task_category


def convert_to_csv(json_path="demo_output/network_config_qa_dataset.json", csv_path="demo_output/dataset_for_evaluation.csv"):
    """최종 데이터셋 JSON을 평가용 CSV 파일로 변환합니다."""
    with open(json_path, 'r', encoding='utf-8') as f:
        dataset = json.load(f)

    header = ["입력 쿼리", "정답", "업무 분류", "참고 파일이름"]
    rows = []

    for split in ["train", "validation", "test"]:
        for sample in dataset.get(split, []):
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
                "입력 쿼리": ds.question,
                "정답": ds.ground_truth,
                "업무 분류": task_category,
                "참고 파일이름": referenced_files_str,
            })

    with open(csv_path, 'w', newline='', encoding='utf-8-sig') as f:
        writer = csv.DictWriter(f, fieldnames=header)
        writer.writeheader()
        writer.writerows(rows)

    print(f"✅ CSV 파일 생성 완료: {csv_path}")


if __name__ == "__main__":
    convert_to_csv()
