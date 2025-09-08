from __future__ import annotations

import os
from datetime import datetime
from pathlib import Path
import json
import pandas as pd
import sys
import argparse

# Ensure parent (pipeline_v2) is importable when running this module directly
CURRENT_DIR = Path(__file__).parent
PARENT_DIR = CURRENT_DIR.parent
if str(PARENT_DIR) not in sys.path:
    sys.path.insert(0, str(PARENT_DIR))

from rag_pipeline import NetworkEngineeringPipeline
from common.llm_utils import get_xml_query, ExperimentLogger, TrackedOpenAIClient  # LLM/로그
from config import CHROMADB_PATH, COLLECTION_NAME, XML_DIRECTORY


def recall_at_k(metadatas: list[dict], ground_truth_filenames_str: str, k: int) -> float:
    """정답 문서 목록 중 하나라도 top-k 검색 결과 안에 포함되면 1, 아니면 0"""
    if not metadatas:
        return 0.0
    # 쉼표로 구분된 정답 파일 목록을 set으로 변환 (공백 제거)
    ground_truth_set = set(x.strip() for x in str(ground_truth_filenames_str).split(',') if x.strip())
    if not ground_truth_set:
        return 0.0
    filenames_in_results = {str(meta.get('filename', '')).strip() for meta in metadatas[:k]}
    # 두 set의 교집합이 하나라도 있으면 성공
    return 1.0 if not ground_truth_set.isdisjoint(filenames_in_results) else 0.0


def reciprocal_rank(metadatas: list[dict], ground_truth_filenames_str: str) -> float:
    """정답 문서 목록 중 가장 먼저 등장하는 것의 Reciprocal Rank 계산"""
    if not metadatas:
        return 0.0
    ground_truth_set = set(x.strip() for x in str(ground_truth_filenames_str).split(',') if x.strip())
    if not ground_truth_set:
        return 0.0
    for idx, meta in enumerate(metadatas, start=1):
        if str(meta.get('filename', '')).strip() in ground_truth_set:
            return 1.0 / idx  # 가장 먼저 찾은 것의 점수 반환
    return 0.0


def evaluate_retrieval(pipeline, dataset: pd.DataFrame, query_fn, k_values: list[int]):
    """RAG 검색 성능 평가 (Heuristic/LLM Query + GPT ReRank)"""
    import numpy as np

    recall_scores = {k: [] for k in k_values}
    rr_scores = []
    max_k = max(k_values)
    for _, row in dataset.iterrows():
        question = row["question"]
        gt_filenames = row["ground_truth_filename"]  # 쉼표 구분 가능

        # 1) 쿼리 생성
        query = query_fn(question, "")

        # 2) 검색 + GPT ReRank
        documents, metadatas = pipeline.get_chromadb_content_for_eval(query, n_results=max_k)

        # 3) Recall@k
        for k in k_values:
            recall_scores[k].append(recall_at_k(metadatas, gt_filenames, k))

        # 4) MRR
        rr_scores.append(reciprocal_rank(metadatas, gt_filenames))

    recall_avg = {k: float(np.mean(v)) if v else 0.0 for k, v in recall_scores.items()}
    mrr = float(np.mean(rr_scores)) if rr_scores else 0.0
    return recall_avg, mrr

def main():
    print("🚀 Retrieval 성능 평가를 시작합니다...")

    parser = argparse.ArgumentParser(description="Run retrieval evaluation (Heuristic/LLM + GPT ReRank)")
    parser.add_argument(
        "--dataset",
        default=str(PARENT_DIR.parent / "dataset" / "retrieval_test.csv"),
        help="Retrieval 평가 CSV 경로 (columns: question, ground_truth_filename)",
    )
    parser.add_argument(
        "--k-values",
        default="1,5,10",
        help="Comma-separated K values for Recall@K (e.g., 1,5,10)",
    )
    args = parser.parse_args()

    # 공용 출력 디렉토리/로거 준비 (LLM 재정렬 로깅용)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    out_dir = PARENT_DIR / "experiment_results" / f"retrieval_{ts}"
    out_dir.mkdir(parents=True, exist_ok=True)
    logger = ExperimentLogger("retrieval_evaluation", str(out_dir))
    # rag_pipeline의 전역 LLM 핸들 주입 (GPT ReRank 사용)
    import rag_pipeline as rp
    rp.tracked_openai_client = TrackedOpenAIClient(logger)

    # 1. 평가할 파이프라인 초기화
    # NetworkEngineeringPipeline은 내부에 Embedder와 DB를 모두 포함하고 있음
    pipeline = NetworkEngineeringPipeline(
        chromadb_path=CHROMADB_PATH,
        collection_name=COLLECTION_NAME,
        max_iterations=0, # 평가 시에는 반복이 필요 없음
        xml_directory=XML_DIRECTORY,
    )

    # 2. 평가 데이터셋 로드 (필수 컬럼: question, ground_truth_filename)
    ds_path = Path(args.dataset)
    if not ds_path.exists():
        raise FileNotFoundError(
            f"❌ 평가 데이터셋이 없습니다: {ds_path}\n"
            f"필수 컬럼: question, ground_truth_filename (예: ce1.xml)"
        )
    dataset = pd.read_csv(ds_path)
    cols = set(dataset.columns)
    if "ground_truth_filename" not in cols and "source_files" in cols:
        # allow legacy column name
        dataset = dataset.rename(columns={"source_files": "ground_truth_filename"})
        cols = set(dataset.columns)
    if not {"question", "ground_truth_filename"}.issubset(cols):
        raise ValueError("❌ retrieval_test.csv에는 question, ground_truth_filename 컬럼이 필요합니다 (또는 source_files를 사용하면 자동 매핑)")
    print(f"📊 평가 데이터셋 로드 완료: {len(dataset)}개 질문 → {ds_path}")

    # 3. 평가 실행
    k_values = [int(x.strip()) for x in str(args.k_values).split(',') if x.strip()]

    # --- Heuristic Query + GPT ReRanking ---
    print("\nEvaluating: Heuristic Query + GPT ReRanking...")
    recall_h, mrr_h = evaluate_retrieval(
        pipeline,
        dataset,
        query_fn=lambda q, a: f"단순 조회, {q}",
        k_values=k_values
    )
    print(f"  - Recall Scores: {recall_h}")
    print(f"  - MRR Score: {mrr_h:.4f}")

    # --- LLM Query + GPT ReRanking ---
    print("\nEvaluating: LLM Query + GPT ReRanking...")
    recall_llm, mrr_llm = evaluate_retrieval(
        pipeline,
        dataset,
        query_fn=lambda q, a: get_xml_query(q, ""), # get_xml_query는 LLM 호출 함수
        k_values=k_values
    )
    print(f"  - Recall Scores: {recall_llm}")
    print(f"  - MRR Score: {mrr_llm:.4f}")

    # 4. 결과 저장 (Markdown/JSON)

    md_lines = []
    md_lines.append("## 표 4: Retrieval Performance (RAG만)")
    md_lines.append("| Method | Recall@1 | Recall@5 | Recall@10| Recall@20 | MRR |")
    md_lines.append("|--------|---------:|---------:|----------:|----------:|----:|")
    md_lines.append(
        f"| Heuristic + GPT ReRank | {recall_h.get(1,0):.4f} | {recall_h.get(5,0):.4f} | {recall_h.get(10,0):.4f} | {recall_h.get(20,0):.4f} | {mrr_h:.4f} |"
    )
    md_lines.append(
        f"| LLM Query + GPT ReRank | {recall_llm.get(1,0):.4f} | {recall_llm.get(5,0):.4f} | {recall_llm.get(10,0):.4f} | {recall_llm.get(20,0):.4f} | {mrr_llm:.4f} |"
    )
    md = "\n".join(md_lines)
    (out_dir / "retrieval_performance.md").write_text(md, encoding="utf-8")

    payload = {
        "k_values": k_values,
        "dataset_path": str(ds_path),
        "methods": {
            "heuristic+gpt_rerank": {
                "recall@1": float(f"{recall_h.get(1, 0):.3f}"),
                "recall@5": float(f"{recall_h.get(5, 0):.3f}"),
                "recall@10": float(f"{recall_h.get(10, 0):.3f}"),
                "recall@20": float(f"{recall_h.get(20, 0):.3f}"),
                "mrr": float(f"{mrr_h:.3f}"),
            },
            "llm+gpt_rerank": {
                "recall@1": float(f"{recall_llm.get(1, 0):.3f}"),
                "recall@5": float(f"{recall_llm.get(5, 0):.3f}"),
                "recall@10": float(f"{recall_llm.get(10, 0):.3f}"),
                "recall@20": float(f"{recall_llm.get(20, 0):.3f}"),
                "mrr": float(f"{mrr_llm:.3f}"),
            },
        },
        "timestamp": ts,
    }
    (out_dir / "retrieval_performance.json").write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")

    # 5. 콘솔 출력 요약
    print("\n" + "=" * 70)
    print("✅ Retrieval 성능 요약 (저장 완료)")
    print(md)
    print(f"📄 저장 위치: {out_dir}")
    print("=" * 70)

    # 마무리
    logger.finalize_experiment()


if __name__ == "__main__":
    main()
