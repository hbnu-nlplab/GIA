#!/usr/bin/env python3
"""RAG 파이프라인 전용 스크립트 (pipeline_v2)

ChromaDB에서 XML 관련 문서를 검색하고, LLM 재정렬을 통해 컨텍스트를 구성하여 답변합니다.
"""

from __future__ import annotations

import argparse
import os
import re
import time
from datetime import datetime
from typing import Dict, List, Optional

import chromadb
from langchain_huggingface import HuggingFaceEmbeddings
import torch

from common import (
    evaluate_predictions,
    ExperimentLogger,
    TrackedOpenAIClient,
    load_test_data,
    extract_and_preprocess,
    clean_ground_truth_text,
)
from config import (
    OPENAI_API_KEY,
    CHROMADB_PATH,
    XML_DIRECTORY,
    CSV_PATH,
    COLLECTION_NAME,
    MAX_ITERATIONS,
    EMBEDDING_MODEL,
    EMBEDDING_DEVICE,
    EMBEDDING_BATCH_SIZE,
    AUTO_EMBED_XML_ON_EMPTY,
    EXPERIMENT_BASE_DIR,
    LLM_MODEL,
    LLM_TEMPERATURE,
)


# 전역 LLM 핸들
tracked_openai_client: TrackedOpenAIClient | None = None

# 시스템 프롬프트
chatgpt_system_prompt = (
    "You are an expert network engineering assistant with deep knowledge of network "
    "configurations, troubleshooting, and security best practices."
)


class HuggingFaceEmbedder:
    """HuggingFace 임베더 (GPU 자동 선택 및 OOM 폴백)"""

    def __init__(self, model_name: str = EMBEDDING_MODEL, device: str = EMBEDDING_DEVICE, batch_size: int = EMBEDDING_BATCH_SIZE):
        self.model_name = model_name
        self.device = self._select_device(device)
        self.batch_size = self._scale_batch_size(batch_size)
        self.embedder = HuggingFaceEmbeddings(
            model_name=self.model_name,
            model_kwargs={"device": self.device} if self.device else {},
            encode_kwargs={"batch_size": self.batch_size},
        )
        print(f"[INFO] Embedding device={self.device or 'cpu/auto'}, batch_size={self.batch_size}")

    def _select_device(self, d: str | None) -> str | None:
        try:
            if not d:
                return None
            d = d.strip().lower()
            if d in ("cpu", "cuda:0", "cuda:1", "cuda:2", "cuda:3"):
                return d
            if d in ("cuda", "auto", "cuda:auto"):
                if torch.cuda.is_available() and torch.cuda.device_count() > 0:
                    best, best_free = 0, -1
                    for i in range(torch.cuda.device_count()):
                        try:
                            free, total = torch.cuda.mem_get_info(i)
                            if free > best_free:
                                best, best_free = i, free
                        except Exception:
                            continue
                    print(f"[INFO] Auto-selected cuda:{best}")
                    return f"cuda:{best}"
                return "cpu"
        except Exception:
            return d
        return d

    def _scale_batch_size(self, base: int) -> int:
        try:
            if torch.cuda.is_available():
                n = torch.cuda.device_count()
                if n >= 2:
                    return max(8, base * min(n, 2))
        except Exception:
            pass
        return base

    def embed(self, texts: List[str] | str) -> List[List[float]]:
        if isinstance(texts, str):
            texts = [texts]
        try:
            return self.embedder.embed_documents(texts)
        except torch.cuda.OutOfMemoryError:
            print("[WARNING] CUDA OOM during embedding. Falling back to CPU with smaller batch size.")
            # fallback to CPU with smaller batch size
            self.device = "cpu"
            self.batch_size = max(4, self.batch_size // 2)
            self.embedder = HuggingFaceEmbeddings(
                model_name=self.model_name,
                model_kwargs={"device": self.device},
                encode_kwargs={"batch_size": self.batch_size},
            )
            return self.embedder.embed_documents(texts)


class ChromaDB:
    def __init__(self, db_path: str, collection_name: str, embedder: object, xml_directory: str | None = None):
        self.db_path = db_path
        self.xml_directory = xml_directory
        self.client = chromadb.PersistentClient(path=db_path)
        self.embedder = embedder
        # Use existing collection if present; only auto-embed when explicitly enabled
        try:
            self.collection = self.client.get_collection(name=collection_name)
        except Exception:
            try:
                if hasattr(self.client, "get_or_create_collection"):
                    self.collection = self.client.get_or_create_collection(name=collection_name)
                else:
                    self.collection = self.client.create_collection(name=collection_name)
            except Exception:
                # race-safe: fetch again
                self.collection = self.client.get_collection(name=collection_name)
        print(f"[INFO] Using collection: {collection_name} (count={self.collection.count()})")
        if AUTO_EMBED_XML_ON_EMPTY and self.collection.count() == 0 and self.xml_directory:
            print("[INFO] AUTO_EMBED_XML_ON_EMPTY=True & empty collection → auto-embedding XML...")
            self._auto_embed_xml_files()

    def _auto_embed_xml_files(self) -> None:
        import glob
        if not self.xml_directory or not os.path.exists(self.xml_directory):
            print(f"[WARNING] XML directory not found: {self.xml_directory}")
            return
        files = [p for p in glob.glob(os.path.join(self.xml_directory, "**", "*.xml"), recursive=True)]
        if not files:
            print(f"[WARNING] No XML files found in: {self.xml_directory}")
            return
        print(f"[INFO] Auto-embedding {len(files)} XML files (batched)")
        batch = 5
        ids: List[str] = []
        docs: List[str] = []
        metas: List[Dict] = []
        for i, f in enumerate(files, 1):
            try:
                content = None
                for enc in ["utf-8", "utf-8-sig", "latin-1", "cp1252"]:
                    try:
                        with open(f, "r", encoding=enc) as fh:
                            content = fh.read()
                        break
                    except UnicodeDecodeError:
                        continue
                if not content:
                    continue
                docs.append(content)
                ids.append(f"doc_{i}")
                metas.append({"filename": os.path.basename(f), "file_path": f})
                if len(docs) >= batch:
                    embs = self.embedder.embed(docs)
                    self.collection.add(ids=ids, documents=docs, embeddings=embs, metadatas=metas)
                    ids, docs, metas = [], [], []
            except Exception as e:
                print(f"[WARNING] Failed to embed {os.path.basename(f)}: {e}")
        if docs:
            embs = self.embedder.embed(docs)
            self.collection.add(ids=ids, documents=docs, embeddings=embs, metadatas=metas)
        print(f"[INFO] Collection now has {self.collection.count()} documents")

    def query(self, text: str, n_results: int = 5) -> Dict:
        q_emb = self.embedder.embed(text)
        return self.collection.query(query_embeddings=q_emb, n_results=n_results)


def get_reranked_indices(question: str, documents: List[str], top_n: int = 5) -> List[int]:
    """LLM으로 1차 검색 결과 재정렬 → 상위 index 반환"""
    assert tracked_openai_client is not None
    if not documents:
        return []
    docs_str = "\n\n".join([f"Doc[{i+1}]:\n{d}" for i, d in enumerate(documents)])
    prompt = f"""
    You are an expert document analyst. Re-rank the documents by relevance to the user question.
    User Question: "{question}"
    Provided Documents:\n{docs_str}
    Instructions:
    - Output a comma-separated list of Doc[number] in descending order, up to {top_n}. No explanations.
    """
    resp = tracked_openai_client.chat_completions_create(
        call_type="document_reranking",
        model=LLM_MODEL,
        messages=[
            {"role": "system", "content": "You rank documents by relevance."},
            {"role": "user", "content": prompt},
        ],
        temperature=0.0,
    )
    text = resp.choices[0].message.content.strip()
    idx: List[int] = []
    for m in re.findall(r"Doc\[(\d+)\]", text):
        i = int(m) - 1
        if 0 <= i < len(documents):
            idx.append(i)
    if not idx:
        idx = list(range(min(top_n, len(documents))))
    return idx[:top_n]


def get_classification_result(question: str) -> str:
    assert tracked_openai_client is not None
    prompt = """
    Classify the question into ONE category:
    1) Simple Lookup Tasks
    2) Other Tasks
    Return only the category name.
    """
    resp = tracked_openai_client.chat_completions_create(
        call_type="task_classification",
        model=LLM_MODEL,
        messages=[
            {"role": "system", "content": chatgpt_system_prompt},
            {"role": "user", "content": f"Question: {question}\nInstruction: {prompt}"},
        ],
        temperature=LLM_TEMPERATURE,
    )
    return resp.choices[0].message.content.strip()


def get_draft(question: str, task_type: str, context: str = "") -> str:
    assert tracked_openai_client is not None
    
    # 컨텍스트가 있으면 포함, 없으면 기존 방식
    context_section = f"\n\nRelevant Configuration Data:\n{context}\n" if context else ""
    
    if task_type == "Simple Lookup Tasks":
        user = f"""
        Answer the following network engineering question with exact precision.
        
        Question: {question}{context_section}
        
        FORMAT REQUIREMENTS:
        [GROUND_TRUTH]
        {{EXACT_VALUE_ONLY - no labels, no extra text, no descriptions}}
        
        [EXPLANATION]
        {{Brief technical explanation in Korean}}
        
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
    else:
        user = f"""
        Provide a comprehensive answer to this network engineering question.
        
        Question: {question}{context_section}
        
        FORMAT REQUIREMENTS:
        [GROUND_TRUTH]
        {{Exact technical values only - no extra text}}
        
        [EXPLANATION]
        {{Detailed technical explanation in Korean}}
        
        For multiple values, use comma and space separation. Sort alphabetically when applicable.
        """
    
    # 메타데이터에 컨텍스트 정보 포함 (모든 값을 문자열로 변환)
    metadata = {
        "has_context": str(bool(context)),
        "context_length": str(len(context) if context else 0),
        "context_preview": (context[:200] + "..." if len(context) > 200 else context) if context else "No context"
    }
    
    resp = tracked_openai_client.chat_completions_create(
        call_type="initial_draft",
        model=LLM_MODEL,
        messages=[
            {"role": "system", "content": chatgpt_system_prompt},
            {"role": "user", "content": user},
        ],
        temperature=0.2,
        metadata=metadata,
    )
    return resp.choices[0].message.content


def determine_reference_source(task_type: str, iteration: int) -> str:
    # 인터넷 검색 비활성화 → 항상 chromadb
    return "chromadb"


def get_final_response(question: str, refined_answer: str, task_type: str) -> str:
    assert tracked_openai_client is not None
    final_prompt = f"""
    Optimize the answer for exact evaluation format. Follow these rules strictly:
    
    [GROUND_TRUTH] 
    - EXACT VALUES ONLY (no labels, no extra text)
    - Device lists: Use device names alphabetically (CE1, CE2, sample7, sample8, sample9, sample10)
    - Multiple items: comma-separated with spaces "item1, item2, item3"
    - Numbers: just the number "0" or "5" (no units like "대", "개")
    - IP addresses: "1.1.1.1, 2.2.2.2, 3.3.3.3"
    
    [EXPLANATION] Korean technical explanation
    
    Question: {question}
    Current Answer: {refined_answer}
    """
    resp = tracked_openai_client.chat_completions_create(
        call_type="final_optimization",
        model=LLM_MODEL,
        messages=[
            {"role": "system", "content": chatgpt_system_prompt},
            {"role": "user", "content": final_prompt},
        ],
        temperature=LLM_TEMPERATURE,
    )
    return resp.choices[0].message.content.strip()


def revise_with_reference(question: str, current_answer: str, reference_content: str, task_type: str) -> str:
    """LLM에 검색된 컨텍스트를 명시적으로 제공하여 답변을 보정"""
    assert tracked_openai_client is not None
    prompt = """
    You are a network engineering expert. Use ONLY the following reference content to revise the answer.

    STRICT FORMATTING RULES:
    [GROUND_TRUTH]: 
    - EXACT VALUES ONLY (no labels/extra text)
    - Device lists: Use device names alphabetically (CE1, CE2, sample7, sample8, sample9, sample10)
    - Multiple values: comma-separated with spaces (e.g., "CE1, CE2")
    - Numbers only: "0", "5" (no "대", "개", "ea")
    - IP addresses: "1.1.1.1, 2.2.2.2, 3.3.3.3"
    
    [EXPLANATION]: Korean technical explanation referencing the data
    
    Return the complete revised answer in the exact [GROUND_TRUTH]/[EXPLANATION] format.
    """
    resp = tracked_openai_client.chat_completions_create(
        call_type="answer_revision",
        model=LLM_MODEL,
        messages=[
            {"role": "system", "content": chatgpt_system_prompt},
            {
                "role": "user",
                "content": (
                    f"Reference Content:\n{reference_content}\n\n"
                    f"Question: {question}\n\n"
                    f"Original Answer: {current_answer}\n\n"
                    f"Instruction: {prompt}"
                ),
            },
        ],
        temperature=LLM_TEMPERATURE,
    )
    return resp.choices[0].message.content


class NetworkEngineeringPipeline:
    def __init__(self, chromadb_path: str, collection_name: str, max_iterations: int, xml_directory: str | None = None):
        self.db = ChromaDB(
            chromadb_path,
            collection_name,
            embedder=HuggingFaceEmbedder(),
            xml_directory=xml_directory,
        )
        self.max_iterations = max_iterations

    def get_chromadb_content(self, question: str, answer: str, top_n_after_rerank: int = 5) -> Optional[str]:
        candidate_multiplier = 3
        n_results = top_n_after_rerank * candidate_multiplier
        query = f"단순 조회, {question}"
        results = self.db.query(query, n_results=n_results)
        
        print(f"🔍 ChromaDB 검색 결과:")
        print(f"  - Query: {query}")
        print(f"  - 요청 문서 수: {n_results}")
        print(f"  - 검색된 문서 수: {len(results.get('documents', [[]])[0]) if results else 0}")
        
        if not (results and results.get("documents") and results["documents"][0]):
            print("  - ❌ 검색 결과 없음 → Fallback 재시도 (원문 질문)")
            # Fallback: 접두어 없이 원문 질문으로 재시도
            results = self.db.query(user_question := question, n_results=n_results)
            print(f"  - Fallback Query: {user_question}")
            print(f"  - 검색된 문서 수(재시도): {len(results.get('documents', [[]])[0]) if results else 0}")
            if not (results and results.get("documents") and results["documents"][0]):
                print("  - ❌ 재시도도 실패")
                return None
            
        documents = results["documents"][0]
        metadatas = results.get("metadatas", [None])[0]
        
        print(f"  - 초기 문서 수: {len(documents)}")
        
        if len(documents) > 1:
            ranked_idx = get_reranked_indices(question, documents, top_n=top_n_after_rerank)
            documents = [documents[i] for i in ranked_idx]
            if metadatas:
                metadatas = [metadatas[i] for i in ranked_idx]
                
        print(f"  - 최종 문서 수: {len(documents)}")
        if metadatas:
            device_names = [m.get('device_name', 'unknown') for m in metadatas]
            print(f"  - 관련 장비: {device_names}")
        
        # Join with metadata (excluding file paths)
        exclude_keys = {"file_path", "source", "filename", "source_directory"}
        if metadatas:
            combined = "\n\n".join(
                "[METADATA]\n"
                + "\n".join(f"{k}: {v}" for k, v in m.items() if k not in exclude_keys)
                + f"\n\n[CONTENT]\n{d}"
                for d, m in zip(documents, metadatas)
            )
        else:
            combined = "\n\n".join(documents)
            
        print(f"  - 컨텍스트 길이: {len(combined)} 문자")
        
        # context logging to file
        try:
            log_path = os.path.join("Network-Management-System-main", "pipeline_v2", "input_docs.log")
            with open(log_path, "a", encoding="utf-8") as f:
                f.write(f"\n[QUESTION]\n{question}\n")
                f.write(f"\n[COMBINED_CONTENT]\n{combined}\n")
                f.write("=" * 80 + "\n")
        except Exception:
            pass
        return combined

        # vvv 아래 메서드를 새로 추가 vvv
    def get_chromadb_content_for_eval(self, query: str, n_results: int) -> tuple[list[str], list[dict]]:
        """평가 전용: 검색 및 재정렬 후 문서와 메타데이터 리스트를 반환"""
        # 재정렬을 고려하여 3배수만큼 초기 검색
        initial_n_results = n_results * 3
        
        results = self.db.query(query, n_results=initial_n_results)
        if not (results and results.get("documents") and results["documents"][0]):
            return [], [] # 결과 없으면 빈 리스트 반환

        documents = results["documents"][0]
        metadatas = results.get("metadatas", [[]])[0] or [{}] * len(documents)
        
        # GPT ReRanking 수행
        if len(documents) > 1:
            ranked_idx = get_reranked_indices(query, documents, top_n=n_results)
            documents = [documents[i] for i in ranked_idx]
            metadatas = [metadatas[i] for i in ranked_idx]
            
        # 최종 k개만큼 잘라서 반환
        return documents[:n_results], metadatas[:n_results]

    def process_query(self, user_question: str, top_k_chroma: int) -> Dict:
        assert tracked_openai_client is not None
        start = time.time()
        log_data: List[Dict] = []
        task_type = get_classification_result(user_question)
        log_data.append({"step": "task_classification", "task_type": task_type})
        
        # 초기 답변 생성 전에 먼저 컨텍스트 검색
        initial_context = self.get_chromadb_content(user_question, "", top_n_after_rerank=top_k_chroma)
        current_answer = get_draft(user_question, task_type, initial_context)
        log_data.append({"step": "initial_draft", "content": current_answer})
        results: Dict = {
            "question": user_question,
            "task_type": task_type,
            "initial_draft": current_answer,
            "iterations": [],
            "total_revisions": 0,
        }
        last_reference_content = initial_context
        for it in range(self.max_iterations):
            ref_source = determine_reference_source(task_type, it)
            reference_content = None
            if ref_source == "chromadb":
                reference_content = self.get_chromadb_content(user_question, current_answer, top_n_after_rerank=top_k_chroma)
            if reference_content:
                # refine with explicit reference content
                last_reference_content = reference_content
                try:
                    revised = revise_with_reference(user_question, current_answer, reference_content, task_type)
                except Exception:
                    revised = None
                if revised and revised != current_answer:
                    current_answer = revised
                    results["total_revisions"] += 1
                    log_data.append({
                        "step": f"iteration_{it+1}",
                        "reference_found": True,
                        "answer_revised": True,
                    })
                    results["iterations"].append({
                        "iteration": it + 1,
                        "source": ref_source,
                        "reference_found": True,
                        "answer_revised": True,
                    })
                else:
                    log_data.append({
                        "step": f"iteration_{it+1}",
                        "reference_found": True,
                        "answer_revised": False,
                    })
                    results["iterations"].append({
                        "iteration": it + 1,
                        "source": ref_source,
                        "reference_found": True,
                        "answer_revised": False,
                    })
            else:
                log_data.append({
                    "step": f"iteration_{it+1}",
                    "reference_found": False,
                    "answer_revised": False,
                })
                results["iterations"].append({
                    "iteration": it + 1,
                    "source": ref_source,
                    "reference_found": False,
                    "answer_revised": False,
                })
        # final optimization (reuse last reference if available for stability)
        try:
            if last_reference_content:
                # One more light pass using reference to enforce strict format
                current_answer = revise_with_reference(user_question, current_answer, last_reference_content, task_type)
        except Exception:
            pass
        final_resp = get_final_response(user_question, current_answer, task_type)
        if final_resp and final_resp != current_answer:
            results["final_optimization"] = True
        else:
            final_resp = current_answer
            results["final_optimization"] = False
        results["final_answer"] = final_resp
        results["processing_time"] = round(time.time() - start, 2)
        log_data.append({"step": "final_answer", "content": final_resp})
        results["detailed_log"] = log_data
        return results


def main():
    parser = argparse.ArgumentParser(description="RAG Pipeline")
    parser.add_argument("--top-k", default="5,10,15", help="Comma-separated Top-K values")
    parser.add_argument("--max-iterations", type=int, default=MAX_ITERATIONS)
    parser.add_argument("--max-questions", type=int, help="Maximum number of questions to process")
    parser.add_argument(
        "--output-dir",
        default=f"{EXPERIMENT_BASE_DIR}/rag_{datetime.now().strftime('%Y%m%d_%H%M%S')}",
        help="Output directory for results (will use this path directly)"
    )
    args = parser.parse_args()

    if OPENAI_API_KEY:
        os.environ["OPENAI_API_KEY"] = OPENAI_API_KEY

    # output-dir을 직접 사용 (추가 타임스탬프 폴더 생성하지 않음)
    logger = ExperimentLogger("rag_experiment", args.output_dir)
    global tracked_openai_client
    tracked_openai_client = TrackedOpenAIClient(logger)
    # 콘솔 캡처 시작
    logger.start_console_capture()

    # load data
    test_data = load_test_data(CSV_PATH)
    if args.max_questions:
        test_data = test_data.head(args.max_questions)
        print(f"📊 처리할 질문 수 제한: {args.max_questions}")
    else:
        print(f"📊 모든 질문 처리: {len(test_data)}")
        
    pipeline = NetworkEngineeringPipeline(
        chromadb_path=CHROMADB_PATH,
        collection_name=COLLECTION_NAME,
        max_iterations=args.max_iterations,
        xml_directory=XML_DIRECTORY,
    )

    top_k_values = [int(x.strip()) for x in args.top_k.split(",") if x.strip()]
    all_results: Dict[str, Dict] = {}
    import pandas as pd
    merged_aug = None  # for final combined CSV with k-specific columns
    for top_k in top_k_values:
        print(f"\n🎯 RAG 실험 시작 (top_k={top_k})")
        results: List[Dict] = []
        for i, row in test_data.iterrows():
            print(f"Processing {i+1}/{len(test_data)} (k={top_k}): {row['question'][:50]}...")
            # 질문 ID 설정 (1부터 시작, top_k별로 구분)
            question_id = i + 1 + (top_k * 1000)  # top_k별로 다른 ID 범위 사용
            tracked_openai_client.logger.set_current_question_id(question_id)
            results.append(pipeline.process_query(row["question"], top_k_chroma=top_k))
        evaluation = evaluate_predictions(results, test_data)
        # relaxed scoring based on preprocessed GT (from after_rows built below)
        all_results[f"top_k_{top_k}"] = {"results": results, "evaluation": evaluation}
        logger.save_results({"top_k": top_k, "results": results, "evaluation": evaluation}, filename=f"rag_k{top_k}.json")
        print(
            f"✅ Top-K={top_k} 완료! EM: {evaluation['overall']['exact_match']:.4f} F1: {evaluation['overall']['f1_score']:.4f}"
        )

        # 전처리: before/after CSV 및 증강 입력 CSV(k별)
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
        import pandas as pd
        before_df = pd.DataFrame(before_rows)
        after_df = pd.DataFrame(after_rows)
        before_df.to_csv(logger.results_dir / f"rag_before_k{top_k}.csv", index=False)
        after_df.to_csv(logger.results_dir / f"rag_after_k{top_k}.csv", index=False)

        # compute relaxed EM/F1
        def _norm(s: str) -> str:
            return clean_ground_truth_text(str(s)).lower()
        preds_rel = [ _norm(r["pre_GT"]) for r in after_rows ]
        gts_rel = [ _norm(x) for x in test_data["ground_truth"].tolist() ]
        def _f1_rel(ps, gs):
            scores = []
            for p,g in zip(ps,gs):
                if ("," in g) or (";" in g) or ("," in p) or (";" in p):
                    ps_set = set([x.strip() for x in re.split(r"[;,]", p) if x.strip()])
                    gs_set = set([x.strip() for x in re.split(r"[;,]", g) if x.strip()])
                    inter = ps_set & gs_set
                    precision = len(inter)/len(ps_set) if ps_set else 0.0
                    recall = len(inter)/len(gs_set) if gs_set else 0.0
                    f1 = 0.0 if precision+recall==0 else 2*precision*recall/(precision+recall)
                    scores.append(f1)
                else:
                    pt, gtok = set(p.split()), set(g.split())
                    inter = pt & gtok
                    precision = len(inter)/len(pt) if pt else 0.0
                    recall = len(inter)/len(gtok) if gtok else 0.0
                    f1 = 0.0 if precision+recall==0 else 2*precision*recall/(precision+recall)
                    scores.append(f1)
            return sum(scores)/len(scores) if scores else 0.0
        em_rel = sum(1 for p,g in zip(preds_rel, gts_rel) if (
            (set([x.strip() for x in re.split(r"[;,]", p) if x.strip()]) == set([x.strip() for x in re.split(r"[;,]", g) if x.strip()])) if ("," in p or ";" in p or "," in g or ";" in g) else p==g
        )) / len(preds_rel) if preds_rel else 0.0
        f1_rel = _f1_rel(preds_rel, gts_rel)
        evaluation.setdefault("overall_relaxed", {})
        evaluation["overall_relaxed"].update({"exact_match": em_rel, "f1_score": f1_rel})

        # detailed logs aggregate per k
        all_logs = []
        for r in results:
            if isinstance(r, dict) and "detailed_log" in r:
                all_logs.extend(r["detailed_log"])
        if all_logs:
            logger.save_detailed_log(all_logs, filename=f"rag_k{top_k}_detailed.json")

        aug = test_data.copy()
        aug[f"pre_GT_k{top_k}"] = [r["pre_GT"] for r in after_rows]
        aug[f"pre_EX_k{top_k}"] = [r["pre_EX"] for r in after_rows]
        aug.to_csv(logger.results_dir / f"test_fin_with_predictions_rag_k{top_k}.csv", index=False)

        # merge per-k augmented to one combined (on index)
        merged_aug = aug if merged_aug is None else pd.concat([merged_aug, aug[[f"pre_GT_k{top_k}", f"pre_EX_k{top_k}"]]], axis=1)

    logger.save_results(
        {
            "experiments": all_results,
            "config": {
                "method": "rag",
                "top_k_values": top_k_values,
                "max_iterations": args.max_iterations,
                "embedding_model": EMBEDDING_MODEL,
            },
        },
        filename="rag_all_results.json",
    )
    # save combined augmented dataset across all k
    if merged_aug is not None:
        merged_aug.to_csv(logger.results_dir / "test_fin_with_predictions_rag.csv", index=False)
    print(f"✅ RAG 실험 모두 완료! 결과: {args.output_dir}")
    # 실험 마무리
    logger.finalize_experiment()


if __name__ == "__main__":
    main()
