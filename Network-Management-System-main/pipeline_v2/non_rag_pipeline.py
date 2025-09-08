#!/usr/bin/env python3
"""Non-RAG 파이프라인 전용 스크립트 (pipeline_v2)

모든 XML 원문을 그대로 제공하여 LLM이 직접 추출하도록 합니다.
"""

from __future__ import annotations

import argparse
import os
import time
import glob
from datetime import datetime
from typing import Dict, List

from common import (
    evaluate_predictions,
    TrackedOpenAIClient,
    ExperimentLogger,
    load_test_data,
    extract_and_preprocess,
    num_tokens_from_string,
)
from config import (
    OPENAI_API_KEY,
    EXPERIMENT_BASE_DIR,
    CSV_PATH,
    XML_DIRECTORY,
    NON_RAG_CHUNK_SIZE,
    NON_RAG_USE_EMBEDDING,
    LLM_MODEL,
    LLM_TEMPERATURE,
    LLM_TIMEOUT_SECONDS,
)


# 전역 LLM 핸들 (로깅 포함)
tracked_openai_client: TrackedOpenAIClient | None = None

# 시스템 프롬프트(간결화)
chatgpt_system_prompt = (
    "You are an expert network engineering assistant with deep knowledge of network "
    "configurations, troubleshooting, and security best practices."
)


def get_classification_result(question: str) -> str:
    """두 카테고리로 간단 분류: Simple Lookup Tasks | Other Tasks"""
    assert tracked_openai_client is not None
    classification_prompt = '''
    You are an excellent network engineering assistant. Classify the question into ONE of these categories:

    1. Simple Lookup Tasks
    2. Other Tasks

    IMPORTANT: Return ONLY the exact category name.
    '''
    response = tracked_openai_client.chat_completions_create(
        call_type="task_classification",
        model=LLM_MODEL,
        messages=[
            {"role": "system", "content": chatgpt_system_prompt},
            {"role": "user", "content": f"Question: {question}\n\nInstruction: {classification_prompt}"},
        ],
        temperature=LLM_TEMPERATURE,
    )
    return response.choices[0].message.content.strip()


class ImprovedNonRAGPipeline:
    """개선된 Non-RAG 파이프라인 - 모든 XML 원문 제공"""

    def __init__(self, xml_directory: str):
        self.xml_files = self._load_all_xml_files(xml_directory)
        if NON_RAG_USE_EMBEDDING:
            print("[INFO] NON_RAG_USE_EMBEDDING=True (not used in this simplified flow)")
        print(f"[INFO] Loaded {len(self.xml_files)} XML files for Non-RAG")

    def _load_all_xml_files(self, xml_directory: str) -> List[Dict]:
        files: List[Dict] = []
        for path in glob.glob(os.path.join(xml_directory, "*.xml")):
            content = None
            for enc in ["utf-8", "utf-8-sig", "latin-1", "cp1252"]:
                try:
                    with open(path, "r", encoding=enc) as f:
                        content = f.read()
                    break
                except UnicodeDecodeError:
                    continue
            if content is None:
                print(f"[WARNING] Failed to read: {path}")
                continue
            files.append(
                {
                    "filename": os.path.basename(path),
                    "filepath": path,
                    "content": content,
                    "size": len(content),
                    "tokens": num_tokens_from_string(content),
                }
            )
        return files

    def _get_all_xml_content(self, max_tokens: int = NON_RAG_CHUNK_SIZE) -> str:
        chunks: List[str] = []
        total = 0
        for x in self.xml_files:
            if total + x["tokens"] > max_tokens:
                print(f"[WARNING] Token limit reached → skip {x['filename']}")
                break
            header = f"=== {x['filename']} | Complete File | Size: {x['size']} chars ==="
            chunks.append(f"{header}\n{x['content']}")
            total += x["tokens"]
        print(f"[INFO] Provided ~{total} tokens from XML files")
        return "\n\n".join(chunks)

    def process_query(self, user_question: str) -> Dict:
        assert tracked_openai_client is not None
        start = time.time()
        print("=" * 70)
        print("NON-RAG PIPELINE (All XML Files)")
        print("=" * 70)
        print(f"Question: {user_question[:100]}...")

        # 1) 작업 분류
        task_type = get_classification_result(user_question)

        # 2) XML 전체 제공
        xml_blob = self._get_all_xml_content(max_tokens=NON_RAG_CHUNK_SIZE)

        # 3) 최종 답변 생성
        prompt = f"""
        You are a network engineering expert analyzing complete XML configuration files.

        COMPLETE XML Configuration Data:
        {xml_blob}

        User Question: {user_question}

        OUTPUT FORMAT:
        [GROUND_TRUTH]
        {{EXACT_VALUE_ONLY - no labels, no extra text, no descriptions}}

        [EXPLANATION]
        {{상세한 기술적 설명을 한국어로 제공}}

        CRITICAL FORMATTING RULES:
        - Device lists: Use device names only (CE1, CE2, sample10) - NEVER use IP addresses
        - Multiple items: Separate with comma and space: "item1, item2, item3"
        - Numbers: Just the number (0, 1, 5) - no "대", "개", "ea" etc.
        - IP addresses: Only when specifically asked for IPs: "1.1.1.1, 2.2.2.2"
        - Sort device names alphabetically: CE1, CE2, sample7, sample8, sample9, sample10

        EXAMPLES:
        - Device names: "CE1, CE2, sample10"  
        - Count: "0" or "5" (just numbers)
        - IP list: "1.1.1.1, 2.2.2.2, 3.3.3.3"
        """
        def _ask(prompt_text: str) -> str:
            r = tracked_openai_client.chat_completions_create(
                call_type="improved_non_rag_answer",
                model=LLM_MODEL,
                messages=[
                    {"role": "system", "content": chatgpt_system_prompt},
                    {"role": "user", "content": prompt_text},
                ],
                temperature=0.1,
            )
            return r.choices[0].message.content.strip()
        try:
            # simple timeout wrapper
            from multiprocessing import Process, Queue
            q = Queue()
            def _w(q, p):
                try:
                    q.put(_ask(p))
                except Exception as e:
                    print(f"[ERROR] LLM 호출 실패: {e}")
                    q.put("")
            p = Process(target=_w, args=(q, prompt))
            p.start(); p.join(LLM_TIMEOUT_SECONDS)
            if p.is_alive():
                print(f"[WARNING] LLM 호출 타임아웃 ({LLM_TIMEOUT_SECONDS}초)")
                p.terminate(); p.join()
                final_answer = ""
            else:
                final_answer = q.get() if not q.empty() else ""
                if not final_answer:
                    print("[WARNING] LLM 응답이 비어있습니다")
        except Exception as e:
            print(f"[WARNING] 타임아웃 래퍼 실패, 직접 호출 시도: {e}")
            try:
                final_answer = _ask(prompt)
            except Exception as e2:
                print(f"[ERROR] 직접 호출도 실패: {e2}")
                final_answer = ""
        elapsed = round(time.time() - start, 2)
        return {
            "question": user_question,
            "task_type": task_type,
            "final_answer": final_answer,
            "processing_time": elapsed,
            "method": "non_rag_all_xml",
            "xml_files_used": len(self.xml_files),
        }


def main():
    parser = argparse.ArgumentParser(description="Non-RAG Pipeline")
    parser.add_argument(
        "--output-dir",
        default=f"{EXPERIMENT_BASE_DIR}/non_rag_{datetime.now().strftime('%Y%m%d_%H%M%S')}",
        help="Output directory for results (will use this path directly)"
    )
    parser.add_argument("--max-questions", type=int, default=None)
    args = parser.parse_args()

    if OPENAI_API_KEY:
        os.environ["OPENAI_API_KEY"] = OPENAI_API_KEY

    # output-dir을 직접 사용 (추가 타임스탬프 폴더 생성하지 않음)
    logger = ExperimentLogger("non_rag_experiment", args.output_dir)
    global tracked_openai_client
    tracked_openai_client = TrackedOpenAIClient(logger)

    # 콘솔 캡처 시작
    logger.start_console_capture()
    try:
        # 데이터 로드
        test_data = load_test_data(CSV_PATH)
        if args.max_questions:
            test_data = test_data.head(args.max_questions)

        # 파이프라인 실행
        pipeline = ImprovedNonRAGPipeline(XML_DIRECTORY)
        results: List[Dict] = []
        for i, row in test_data.iterrows():
            print(f"Processing {i+1}/{len(test_data)}: {row['question'][:50]}...")
            # 질문 ID 설정 (1부터 시작)
            tracked_openai_client.logger.set_current_question_id(i + 1)
            results.append(pipeline.process_query(row["question"]))

        # 전처리: before/after CSV 및 증강 입력 CSV 저장
        import pandas as pd
        before_rows = []
        after_rows = []
        for i, res in enumerate(results):
            ans = res.get("final_answer", "")
            gt_raw, ex_raw, pre_gt, pre_ex = extract_and_preprocess(ans)
            before_rows.append(
                {
                    "question": test_data.iloc[i]["question"],
                    "ground_truth": test_data.iloc[i].get("ground_truth", ""),
                    "explanation": test_data.iloc[i].get("explanation", ""),
                    "final_answer": ans,
                    "raw_gt": gt_raw,
                    "raw_ex": ex_raw,
                }
            )
            after_rows.append(
                {
                    "question": test_data.iloc[i]["question"],
                    "ground_truth": test_data.iloc[i].get("ground_truth", ""),
                    "explanation": test_data.iloc[i].get("explanation", ""),
                    "pre_GT": pre_gt,
                    "pre_EX": pre_ex,
                }
            )
        pd.DataFrame(before_rows).to_csv(logger.results_dir / "non_rag_before.csv", index=False)
        pd.DataFrame(after_rows).to_csv(logger.results_dir / "non_rag_after.csv", index=False)

        aug_df = test_data.copy()
        aug_df["pre_GT"] = [r["pre_GT"] for r in after_rows]
        aug_df["pre_EX"] = [r["pre_EX"] for r in after_rows]
        aug_df.to_csv(logger.results_dir / "test_fin_with_predictions_non_rag.csv", index=False)

        # 평가 및 저장
        evaluation = evaluate_predictions(results, test_data)
        logger.save_results(
            {
                "results": results,
                "evaluation": evaluation,
                "config": {
                    "method": "non_rag",
                    "use_embedding": NON_RAG_USE_EMBEDDING,
                    "chunk_size": NON_RAG_CHUNK_SIZE,
                    "model": LLM_MODEL,
                },
            }
        )
        print(f"✅ Non-RAG 실험 완료! 결과: {args.output_dir}")
    except Exception as e:
        print(f"[ERROR] Non-RAG pipeline failed: {e}")
        raise
    finally:
        logger.finalize_experiment()


if __name__ == "__main__":
    main()
