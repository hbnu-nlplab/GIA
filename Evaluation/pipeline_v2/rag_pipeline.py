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
import pandas as pd

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


def _with_enhanced_origin_for_expl(df: pd.DataFrame) -> pd.DataFrame:
    """설명 점수 대상 행(origin='enhanced_llm_with_agent') 라벨링.
    - 기본 정책: explanation이 비어있지 않은 행만 enhanced로 지정
    - 기존 origin이 있으면 유지, 없으면 'general'로 초기화
    """
    out = df.copy()
    if "origin" not in out.columns:
        out["origin"] = "general"
    has_expl = out.get("explanation", pd.Series(
        [""] * len(out))).astype(str).str.strip() != ""
    out.loc[has_expl, "origin"] = "enhanced_llm_with_agent"
    return out


def get_plan(question: str) -> List[str]:
    """Generate a concise, actionable plan (RAT: Retrieval Augmented Thoughts)."""
    assert tracked_openai_client is not None
    import re as _re
    plan_prompt = f"""
    You are a world-class network engineer acting as a meticulous planner. Create a step-by-step execution plan
    to find the answer to the user's question from XML network configuration files.

    User Question: "{question}"

    CRITICAL INSTRUCTIONS:
    1) Decompose the problem into atomic, verifiable steps.
    2) Each step MUST start with an action verb (Search, Find, Extract, List, Compare, Calculate).
    3) The final step MUST be: "Synthesize all findings into a final answer in the required format."
    4) Output ONLY the numbered steps. No extra text.

    --- EXAMPLE ---
    1. Search for the BGP configuration of the device named 'sample7'.
    2. Extract all BGP neighbor IP addresses and their corresponding remote-as numbers.
    3. For each neighbor IP, search all documents to identify which device that IP belongs to.
    4. Synthesize all findings into a final answer in the required format.
    --- END EXAMPLE ---
    """
    resp = tracked_openai_client.chat_completions_create(
        call_type="get_plan",
        model=LLM_MODEL,
        messages=[
            {"role": "system", "content": chatgpt_system_prompt},
            {"role": "user", "content": plan_prompt},
        ],
        temperature=0.0,
    )
    plan_text = resp.choices[0].message.content.strip()
    steps = [s.strip() for s in _re.split(
        r"\n?\s*\d+\.\s+", plan_text) if s.strip()]
    if not steps or not any("Synthesize" in s or "final answer" in s for s in steps):
        steps.append(
            "Synthesize all findings into a final answer in the required format.")
    print("🧠 Generated Plan:")
    for s in steps:
        print(f"  - {s}")
    return steps


# =====================
# AB-Compatible Helpers
# =====================
def build_context_from_docs(docs: List[str], metas: List[dict]) -> str:
    """Build context string from docs/metas identical to C(RAT) formatting.

    - Mirrors the join logic in get_chromadb_content (metadata section + content)
    - Excludes file path related keys for cleanliness
    """
    exclude_keys = {"file_path", "source", "filename", "source_directory"}
    if metas:
        combined = "\n\n".join(
            "[METADATA]\n"
            + "\n".join(f"{k}: {v}" for k, v in m.items()
                        if k not in exclude_keys)
            + f"\n\n[CONTENT]\n{d}"
            for d, m in zip(docs, metas)
        )
    else:
        combined = "\n\n".join(docs)
    return combined


def generate_answer_brief(question: str, task_type: str, context: str) -> str:
    """Group A (1-pass): Short plain explanation (<=2 sentences) + strict GT.

    Returns full text in [GROUND_TRUTH]/[EXPLANATION] format.
    """
    assert tracked_openai_client is not None
    prompt = f"""
    Answer with the strict format below.

    Question: {question}

    Relevant Configuration Data:
    {context}

    FORMAT:
    [GROUND_TRUTH]
    {{EXACT VALUE(S) ONLY}}

    [EXPLANATION]
    {{Korean plain sentences, <=3 sentences, no lists, no inline citations}}

    RULES:
    - Device list: CE1, CE2, sample7, sample8, sample9, sample10 (alphabetical)
    - Multiple values: "item1, item2"
    - Numbers only; Boolean: True/False
    - At the very end, add one optional line: [CITATIONS] doc_1, doc_3 (use indices of the context order in this turn; leave empty if unsure)
    """
    resp = tracked_openai_client.chat_completions_create(
        call_type="ab_answer_brief",
        model=LLM_MODEL,
        messages=[
            {"role": "system", "content": chatgpt_system_prompt},
            {"role": "user", "content": prompt},
        ],
        temperature=LLM_TEMPERATURE,
        metadata={"task_type": task_type},
    )
    return resp.choices[0].message.content


def generate_explanation_only_plain(question: str, context: str) -> str:
    """Group B Pass1: Produce ONLY an explanation in Korean (3–5 sentences)."""
    assert tracked_openai_client is not None
    prompt = f"""
    Write ONLY an explanation (no final answer), in Korean, 3-5 sentences,
    plain narrative (no lists, no numbering, no inline citations).
    Base strictly on the reference below.

    Reference:
    {context}

    User Question: {question}
    """
    resp = tracked_openai_client.chat_completions_create(
        call_type="ab_expl_plain",
        model=LLM_MODEL,
        messages=[
            {"role": "system", "content": chatgpt_system_prompt},
            {"role": "user", "content": prompt},
        ],
        temperature=LLM_TEMPERATURE,
    )
    return resp.choices[0].message.content


def finalize_with_rationale(question: str, rationale: str, context: str) -> str:
    """Group B Pass2: Re-inject rationale + context and produce final GT/EX."""
    ref = f"[SELF_RATIONALE]\n{rationale}\n\n[CONTEXT]\n{context}"
    return revise_with_reference(
        question=question,
        current_answer="",
        reference_content=ref,
        task_type="Other Tasks",
    )


def run_experiment_ab(pipeline: "NetworkEngineeringPipeline", question: str, top_k: int) -> dict:
    """Run A/B-compatible flows sharing the same Top-K context.

    A: single pass brief answer; B: explanation-only then finalize with rationale.
    """
    task_type = get_classification_result(question)
    docs, metas = pipeline.get_chromadb_content_for_eval(
        question, n_results=top_k)
    context = build_context_from_docs(docs, metas)

    # A: 1-pass brief
    a_answer = generate_answer_brief(question, task_type, context)

    # B: Pass1 explanation only
    b_expl_plain = generate_explanation_only_plain(question, context)

    # B: Pass2 finalize
    b_answer = finalize_with_rationale(question, b_expl_plain, context)

    return {
        "A": {"question": question, "final_answer": a_answer, "context_used": top_k},
        "B": {"question": question, "final_answer": b_answer, "explanation_plain": b_expl_plain, "context_used": top_k},
        "retrieval_meta": metas,
    }


# =====================
# RAT Enhancements
# =====================
def compress_to_query_terms(step_result: str, rolling_answer: str) -> str:
    """Compress step result + current draft into a minimal query (Korean)."""
    assert tracked_openai_client is not None
    prompt = f"""
    From the following step result and current draft, extract a minimal Korean query focusing on key
    entities, protocols, identifiers, and device names. Output ONE line only; avoid punctuation except commas.

    [STEP_RESULT]
    {step_result}

    [CURRENT_DRAFT]
    {rolling_answer}
    """
    resp = tracked_openai_client.chat_completions_create(
        call_type="query_compression",
        model=LLM_MODEL,
        messages=[
            {"role": "system", "content": "You compress technical content into concise search queries."},
            {"role": "user", "content": prompt},
        ],
        temperature=0.0,
    )
    return resp.choices[0].message.content.strip()


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
            print(
                "[WARNING] CUDA OOM during embedding. Falling back to CPU with smaller batch size.")
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
                    self.collection = self.client.get_or_create_collection(
                        name=collection_name)
                else:
                    self.collection = self.client.create_collection(
                        name=collection_name)
            except Exception:
                # race-safe: fetch again
                self.collection = self.client.get_collection(
                    name=collection_name)
        print(f"[INFO] Using collection: {
              collection_name} (count={self.collection.count()})")
        if AUTO_EMBED_XML_ON_EMPTY and self.collection.count() == 0 and self.xml_directory:
            print(
                "[INFO] AUTO_EMBED_XML_ON_EMPTY=True & empty collection → auto-embedding XML...")
            self._auto_embed_xml_files()

    def _auto_embed_xml_files(self) -> None:
        import glob
        if not self.xml_directory or not os.path.exists(self.xml_directory):
            print(f"[WARNING] XML directory not found: {self.xml_directory}")
            return
        files = [p for p in glob.glob(os.path.join(
            self.xml_directory, "**", "*.xml"), recursive=True)]
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
                    self.collection.add(
                        ids=ids, documents=docs, embeddings=embs, metadatas=metas)
                    ids, docs, metas = [], [], []
            except Exception as e:
                print(f"[WARNING] Failed to embed {os.path.basename(f)}: {e}")
        if docs:
            embs = self.embedder.embed(docs)
            self.collection.add(ids=ids, documents=docs,
                                embeddings=embs, metadatas=metas)
        print(f"[INFO] Collection now has {self.collection.count()} documents")

    def query(self, text: str, n_results: int = 5) -> Dict:
        q_emb = self.embedder.embed(text)
        return self.collection.query(query_embeddings=q_emb, n_results=n_results)


def get_reranked_indices(question: str, documents: List[str], top_n: int = 5) -> List[int]:
    """LLM으로 1차 검색 결과 재정렬 → 상위 index 반환"""
    assert tracked_openai_client is not None
    if not documents:
        return []
    docs_str = "\n\n".join(
        [f"Doc[{i+1}]:\n{d}" for i, d in enumerate(documents)])
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
            {"role": "user", "content": f"Question: {
                question}\nInstruction: {prompt}"},
        ],
        temperature=LLM_TEMPERATURE,
    )
    return resp.choices[0].message.content.strip()


def get_draft(question: str, task_type: str, context: str = "") -> str:
    assert tracked_openai_client is not None

    # 컨텍스트가 있으면 포함, 없으면 기존 방식
    context_section = f"\n\nRelevant Configuration Data:\n{
        context}\n" if context else ""

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
        - Boolean: "True" or "False"
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
        temperature=LLM_TEMPERATURE,
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
    - Boolean: "True" or "False"

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


def _parse_citations(answer_text: str) -> List[str]:
    """[CITATIONS] 라인에서 인용을 추출 (쉼표 분리). 없으면 빈 리스트."""
    try:
        import re as _re
        m = _re.findall(r"\[CITATIONS\]\s*(.*)$", str(answer_text),
                        flags=_re.IGNORECASE | _re.MULTILINE)
        if not m:
            return []
        raw = m[-1]
        items = [x.strip() for x in raw.split(",") if x.strip()]
        return items
    except Exception:
        return []


def _compute_support_at_k(citations: List[str], metas: List[dict]) -> bool:
    """Compute Support@K via intersection between cited docs and retrieved top-K.
    - Supports filenames or 1-based indices (doc_1, 1, #2)
    """
    if not citations or not metas:
        return False
    try:
        import re as _re
        retrieved = set(str(m.get("filename", "")).strip().lower()
                        for m in metas if m)
        n = len(metas)
        for c in citations:
            s = str(c).strip().lower()
            if not s:
                continue
            if s in retrieved and s:
                return True
            m = _re.search(r"(?:doc[_\s-]?|#)?(\d+)", s)
            if m:
                idx = int(m.group(1)) - 1
                if 0 <= idx < n:
                    return True
        return False
    except Exception:
        return False


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
    - Boolean: "True" or "False"
    
    [EXPLANATION]: Korean technical explanation referencing the data

    At the very end, add one optional line: [CITATIONS] doc_i, doc_j (use indices of provided context in this turn or filenames if visible; leave empty if unsure).

    Return the complete revised answer in the exact [GROUND_TRUTH]/[EXPLANATION] format plus the optional [CITATIONS] line.
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
        print(
            f"  - 검색된 문서 수: {len(results.get('documents', [[]])[0]) if results else 0}")

        if not (results and results.get("documents") and results["documents"][0]):
            print("  - ❌ 검색 결과 없음 → Fallback 재시도 (원문 질문)")
            # Fallback: 접두어 없이 원문 질문으로 재시도
            results = self.db.query(
                user_question := question, n_results=n_results)
            print(f"  - Fallback Query: {user_question}")
            print(
                f"  - 검색된 문서 수(재시도): {len(results.get('documents', [[]])[0]) if results else 0}")
            if not (results and results.get("documents") and results["documents"][0]):
                print("  - ❌ 재시도도 실패")
                return None

        documents = results["documents"][0]
        metadatas = results.get("metadatas", [None])[0]

        print(f"  - 초기 문서 수: {len(documents)}")

        if len(documents) > 1:
            ranked_idx = get_reranked_indices(
                question, documents, top_n=top_n_after_rerank)
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
                + "\n".join(f"{k}: {v}" for k, v in m.items()
                            if k not in exclude_keys)
                + f"\n\n[CONTENT]\n{d}"
                for d, m in zip(documents, metadatas)
            )
        else:
            combined = "\n\n".join(documents)

        print(f"  - 컨텍스트 길이: {len(combined)} 문자")

        # context logging to file
        try:
            log_path = os.path.join(
                "Network-Management-System-main", "pipeline_v2", "input_docs.log")
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
            # 간단한 휴리스틱 접두어로 재시도 (RAT와 유사한 fallback)
            alt_query = f"단순 조회, {query}"
            results = self.db.query(alt_query, n_results=initial_n_results)
            if not (results and results.get("documents") and results["documents"][0]):
                return [], []  # 결과 없으면 빈 리스트 반환

        documents = results["documents"][0]
        metadatas = results.get("metadatas", [[]])[0] or [{}] * len(documents)

        # GPT ReRanking 수행
        if len(documents) > 1:
            ranked_idx = get_reranked_indices(
                query, documents, top_n=n_results)
            documents = [documents[i] for i in ranked_idx]
            metadatas = [metadatas[i] for i in ranked_idx]

        # 최종 k개만큼 잘라서 반환
        return documents[:n_results], metadatas[:n_results]

    def get_chromadb_content_with_meta(self, query: str, top_n_after_rerank: int = 5) -> tuple[Optional[str], list[dict]]:
        """RAT용: 컨텐츠 문자열과 메타데이터를 함께 반환 (fallback 포함)."""
        candidate_multiplier = 3
        n_results = top_n_after_rerank * candidate_multiplier
        # 1차 시도
        results = self.db.query(query, n_results=n_results)
        if not (results and results.get("documents") and results["documents"][0]):
            # Fallback: 접두어 "단순 조회," 시도
            alt_query = f"단순 조회, {query}"
            results = self.db.query(alt_query, n_results=n_results)
            if not (results and results.get("documents") and results["documents"][0]):
                return None, []

        documents = results["documents"][0]
        metadatas = results.get("metadatas", [[]])[0] or [{}] * len(documents)
        if len(documents) > 1:
            ranked_idx = get_reranked_indices(
                query, documents, top_n=top_n_after_rerank)
            documents = [documents[i] for i in ranked_idx]
            metadatas = [metadatas[i] for i in ranked_idx]

        exclude_keys = {"file_path", "source", "filename", "source_directory"}
        if metadatas:
            combined = "\n\n".join(
                "[METADATA]\n"
                + "\n".join(f"{k}: {v}" for k, v in m.items()
                            if k not in exclude_keys)
                + f"\n\n[CONTENT]\n{d}"
                for d, m in zip(documents, metadatas)
            )
        else:
            combined = "\n\n".join(documents)
        return combined, metadatas

    def process_query(self, user_question: str, top_k_chroma: int) -> Dict:
        """RAT-style pipeline (paper-style): Plan → Execute each step with retrieval →
        Rolling revision of draft with reference → Compressed next query → Final synthesis.
        """
        assert tracked_openai_client is not None
        start = time.time()

        # Keep task classification for downstream analyses (task-wise table)
        task_type = get_classification_result(user_question)

        # 1) Plan
        plan = get_plan(user_question)
        executed: List[Dict] = []
        context_for_next_step = "No context yet. This is the first step."
        # Initialize rolling draft (no context for initial draft)
        rolling_answer = get_draft(user_question, task_type)
        # Initialize search query with the user question
        next_search_query = user_question
        # Track last non-empty reference metadatas for Support@K
        last_ref_metas: List[dict] = []

        # 2) Execute each step with retrieval + focused LLM action
        for i, step in enumerate(plan, 1):
            print(f"\n▶️ Executing Plan Step {i}/{len(plan)}: {step}")
            # Build/retrieve reference content with metadata
            search_query = next_search_query or (
                f"Execute: {step}. Prior findings: {
                    context_for_next_step[:300]}"
            )
            reference_content, ref_metas = self.get_chromadb_content_with_meta(
                search_query, top_n_after_rerank=top_k_chroma)
            if ref_metas:
                last_ref_metas = ref_metas

            step_prompt = f"""
            You are an expert agent executing a single step in a larger plan. Your focus is absolute.

            Original Question (context only): "{user_question}"
            Full Plan (context only):\n{plan}

            CURRENT TASK: "{step}"
            Previous Findings:\n{context_for_next_step}
            Reference Content (USE ONLY THIS):\n{reference_content}

            CRITICAL INSTRUCTIONS:
            - Execute ONLY the current step. Do not jump ahead.
            - Base your work STRICTLY on the "Reference Content". No prior knowledge.
            - Output ONLY the direct result from this single step. Be concise and factual.
            - If reference content is insufficient, output exactly: INSUFFICIENT_CONTEXT_FOR_THIS_STEP
            """
            resp = tracked_openai_client.chat_completions_create(
                call_type=f"execute_plan_step_{i}",
                model=LLM_MODEL,
                messages=[
                    {"role": "system", "content": chatgpt_system_prompt},
                    {"role": "user", "content": step_prompt},
                ],
                temperature=0.0,
            )
            step_result = resp.choices[0].message.content.strip()
            print(f"  - Step Result: {step_result[:200]}...")
            executed.append({
                "step_index": i,
                "step": step,
                "reference_present": bool(reference_content),
                "result": step_result,
                "citations": [m.get("filename") for m in (ref_metas or []) if m],
            })
            # accumulate
            context_for_next_step = "\n\n".join(
                [f"Result[{e['step_index']}] {e['step']}:\n{
                    e['result']}" for e in executed]
            )

            # Rolling draft revision using reference
            if reference_content:
                rolling_answer = revise_with_reference(
                    question=user_question,
                    current_answer=rolling_answer or step_result,
                    reference_content=reference_content,
                    task_type=task_type,
                )

            # Build compressed query for next iteration
            try:
                next_search_query = compress_to_query_terms(
                    step_result, rolling_answer)
            except Exception:
                next_search_query = user_question

        # 3) Final synthesis into the strict output format
        synth_prompt = f"""
        You are a final rapporteur. Synthesize all step-by-step findings into the final answer.

        Original User Question: "{user_question}"

        Accumulated Findings:\n{context_for_next_step}

        Current Rolling Draft:\n{rolling_answer}

        CRITICAL FORMATTING RULES:
        - Output MUST contain BOTH [GROUND_TRUTH] and [EXPLANATION].
        - [GROUND_TRUTH]: ONLY the exact value(s). No labels/extra words. Multiple items → comma+space.
        - Sort device names alphabetically where relevant. Counts are numbers only.
        - [EXPLANATION]: Detailed Korean technical explanation based strictly on the findings.
        - At the very end, add one optional line: [CITATIONS] doc_i, doc_j (use filenames if available; leave empty if unsure).
        """
        final_obj = tracked_openai_client.chat_completions_create(
            call_type="final_synthesis",
            model=LLM_MODEL,
            messages=[
                {"role": "system", "content": chatgpt_system_prompt},
                {"role": "user", "content": synth_prompt},
            ],
            temperature=LLM_TEMPERATURE,
        )
        final_answer = final_obj.choices[0].message.content.strip()
        citations = _parse_citations(final_answer)
        support = _compute_support_at_k(citations, last_ref_metas)

        return {
            "question": user_question,
            "task_type": task_type,
            "plan": plan,
            "iterations": executed,
            "final_answer": final_answer,
            "citations": citations,
            "support_at_k": support,
            "final_context_metas": last_ref_metas,
            "processing_time": round(time.time() - start, 2),
            "method": "rag_rat",
        }


def main():
    parser = argparse.ArgumentParser(description="RAG Pipeline")
    parser.add_argument("--top-k", default="5,10,15",
                        help="Comma-separated Top-K values")
    parser.add_argument("--max-iterations", type=int, default=MAX_ITERATIONS)
    parser.add_argument("--max-questions", type=int,
                        help="Maximum number of questions to process")
    parser.add_argument(
        "--experiment", choices=["ab", "rat", "both"], default="ab", help="Which experiment path to run")
    parser.add_argument("--group", choices=["A", "B", "C"], default=None,
                        help="Run a single group (A/B/C) and tag results accordingly")
    parser.add_argument(
        "--output-dir",
        default=f"{
            EXPERIMENT_BASE_DIR}/rag_{datetime.now().strftime('%Y%m%d_%H%M%S')}",
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
        print(f"\n🎯 Experiments start (top_k={top_k})")

        # AB path (or single-group A/B override)
        if (args.experiment in ("ab", "both")) or (args.group in ("A", "B")):
            print("[AB] Running A and B compatible flows...")
            A_results: List[Dict] = []
            B_results: List[Dict] = []
            Bexp_results: List[Dict] = []
            for i, row in test_data.iterrows():
                print(f"[AB] Processing {
                      i+1}/{len(test_data)} (k={top_k}): {row['question'][:50]}...")
                # AB 오프셋: 1000 * k + i
                question_id = i + 1 + (top_k * 1000)
                tracked_openai_client.logger.set_current_question_id(
                    question_id)
                out = run_experiment_ab(pipeline, row["question"], top_k)
                if args.group in ("A", None):
                    a_ans = out["A"]["final_answer"]
                    a_cits = _parse_citations(a_ans)
                    a_sup = _compute_support_at_k(
                        a_cits, out.get("retrieval_meta", []))
                    A_results.append({
                        "question": row["question"],
                        "final_answer": a_ans,
                        "method": "rag_direct",
                        "citations": a_cits,
                        "support_at_k": a_sup,
                    })
                if args.group in ("B", None):
                    b_ans = out["B"]["final_answer"]
                    b_cits = _parse_citations(b_ans)
                    b_sup = _compute_support_at_k(
                        b_cits, out.get("retrieval_meta", []))
                    B_results.append({
                        "question": row["question"],
                        "final_answer": b_ans,
                        "method": "rag_rationale",
                        "citations": b_cits,
                        "support_at_k": b_sup,
                    })
                    # B Pass-1 explanation-only evaluation row
                    bexp_ans = f"[GROUND_TRUTH]\n\n[EXPLANATION]\n{
                        out['B'].get('explanation_plain', '')}"
                    Bexp_results.append({
                        "question": row["question"],
                        "final_answer": bexp_ans,
                        "method": "rag_rationale_pass1",
                    })

            if args.group == "A":
                test_data_expl = _with_enhanced_origin_for_expl(test_data)
                evalA = evaluate_predictions(A_results, test_data_expl)
                all_results[f"A_top_k_{top_k}"] = {
                    "results": A_results, "evaluation": evalA}
                logger.save_results({"top_k": top_k, "results": A_results,
                                    "evaluation": evalA}, filename=f"ragA_k{top_k}.json")
                print(f"[A] EM={evalA['overall']['exact_match']:.4f} F1={
                      evalA['overall']['f1_score']:.4f}")
            elif args.group == "B":
                test_data_expl = _with_enhanced_origin_for_expl(test_data)
                evalB = evaluate_predictions(B_results, test_data_expl)
                all_results[f"B_top_k_{top_k}"] = {
                    "results": B_results, "evaluation": evalB}
                logger.save_results({"top_k": top_k, "results": B_results,
                                    "evaluation": evalB}, filename=f"ragB_k{top_k}.json")
                print(f"[B] EM={evalB['overall']['exact_match']:.4f} F1={
                      evalB['overall']['f1_score']:.4f}")
                # Bexp: explanation-only evaluation storage
                if Bexp_results:
                    test_data_expl = _with_enhanced_origin_for_expl(test_data)
                    evalBexp = evaluate_predictions(
                        Bexp_results, test_data_expl)
                    all_results[f"Bexp_top_k_{top_k}"] = {
                        "results": Bexp_results, "evaluation": evalBexp}
                    logger.save_results({"top_k": top_k, "results": Bexp_results,
                                        "evaluation": evalBexp}, filename=f"ragBexp_k{top_k}.json")
            else:
                # default AB/both path
                test_data_expl = _with_enhanced_origin_for_expl(test_data)
                evalA = evaluate_predictions(A_results, test_data_expl)
                evalB = evaluate_predictions(B_results, test_data_expl)
                all_results[f"A_top_k_{top_k}"] = {
                    "results": A_results, "evaluation": evalA}
                all_results[f"B_top_k_{top_k}"] = {
                    "results": B_results, "evaluation": evalB}
                logger.save_results({"top_k": top_k, "results": A_results,
                                    "evaluation": evalA}, filename=f"ragA_k{top_k}.json")
                logger.save_results({"top_k": top_k, "results": B_results,
                                    "evaluation": evalB}, filename=f"ragB_k{top_k}.json")
                print(f"[A] EM={evalA['overall']['exact_match']:.4f} F1={
                      evalA['overall']['f1_score']:.4f}")
                print(f"[B] EM={evalB['overall']['exact_match']:.4f} F1={
                      evalB['overall']['f1_score']:.4f}")
                # Bexp for AB/both
                if Bexp_results:
                    test_data_expl = _with_enhanced_origin_for_expl(test_data)
                    evalBexp = evaluate_predictions(
                        Bexp_results, test_data_expl)
                    all_results[f"Bexp_top_k_{top_k}"] = {
                        "results": Bexp_results, "evaluation": evalBexp}
                    logger.save_results({"top_k": top_k, "results": Bexp_results,
                                        "evaluation": evalBexp}, filename=f"ragBexp_k{top_k}.json")

            # before/after CSVs for AB (no merged aug across k to keep scope minimal)
            def _write_before_after(tag: str, res_list: List[Dict]):
                before_rows, after_rows = [], []
                for i2, res in enumerate(res_list):
                    ans = res.get("final_answer", "")
                    gt_raw, ex_raw, pre_gt, pre_ex = extract_and_preprocess(
                        ans)
                    before_rows.append({
                        "question": test_data.iloc[i2]["question"],
                        "ground_truth": test_data.iloc[i2].get("ground_truth", ""),
                        "explanation": test_data.iloc[i2].get("explanation", ""),
                        "final_answer": ans,
                        "raw_gt": gt_raw,
                        "raw_ex": ex_raw,
                    })
                    after_rows.append({
                        "question": test_data.iloc[i2]["question"],
                        "ground_truth": test_data.iloc[i2].get("ground_truth", ""),
                        "explanation": test_data.iloc[i2].get("explanation", ""),
                        "pre_GT": pre_gt,
                        "pre_EX": pre_ex,
                    })
                bdf = pd.DataFrame(before_rows)
                adf = pd.DataFrame(after_rows)
                bdf.to_csv(logger.results_dir /
                           f"{tag}_before_k{top_k}.csv", index=False)
                adf.to_csv(logger.results_dir /
                           f"{tag}_after_k{top_k}.csv", index=False)
                # relaxed scoring

                def _norm(s: str) -> str:
                    return clean_ground_truth_text(str(s)).lower()
                preds_rel = [_norm(r["pre_GT"]) for r in after_rows]
                gts_rel = [_norm(x)
                           for x in test_data["ground_truth"].tolist()]

                def _f1_rel(ps, gs):
                    scores = []
                    for p, g in zip(ps, gs):
                        if ("," in g) or (";" in g) or ("," in p) or (";" in p):
                            ps_set = set(
                                [x.strip() for x in re.split(r"[;,]", p) if x.strip()])
                            gs_set = set(
                                [x.strip() for x in re.split(r"[;,]", g) if x.strip()])
                            inter = ps_set & gs_set
                            precision = len(inter) / \
                                len(ps_set) if ps_set else 0.0
                            recall = len(inter)/len(gs_set) if gs_set else 0.0
                            f1 = 0.0 if precision+recall == 0 else 2 * \
                                precision*recall/(precision+recall)
                            scores.append(f1)
                        else:
                            pt, gtok = set(p.split()), set(g.split())
                            inter = pt & gtok
                            precision = len(inter)/len(pt) if pt else 0.0
                            recall = len(inter)/len(gtok) if gtok else 0.0
                            f1 = 0.0 if precision+recall == 0 else 2 * \
                                precision*recall/(precision+recall)
                            scores.append(f1)
                    return sum(scores)/len(scores) if scores else 0.0
                em_rel = sum(1 for p, g in zip(preds_rel, gts_rel) if (
                    (set([x.strip() for x in re.split(r"[;,]", p) if x.strip()]) == set([x.strip() for x in re.split(
                        r"[;,]", g) if x.strip()])) if ("," in p or ";" in p or "," in g or ";" in g) else p == g
                )) / len(preds_rel) if preds_rel else 0.0
                f1_rel = _f1_rel(preds_rel, gts_rel)
                return {"em_rel": em_rel, "f1_rel": f1_rel}

            relA = _write_before_after("ragA", A_results)
            relB = _write_before_after("ragB", B_results)
            evalA.setdefault("overall_relaxed", {}).update(
                {"exact_match": relA["em_rel"], "f1_score": relA["f1_rel"]})
            evalB.setdefault("overall_relaxed", {}).update(
                {"exact_match": relB["em_rel"], "f1_score": relB["f1_rel"]})

        # RAT path
        if (args.experiment in ("rat", "both")) or (args.group == "C"):
            print("[C/RAT] Running RAT pipeline...")
            results: List[Dict] = []
            for i, row in test_data.iterrows():
                print(f"[RAT] Processing {
                      i+1}/{len(test_data)} (k={top_k}): {row['question'][:50]}...")
                # RAT 오프셋: 2000 * k + i
                question_id = i + 1 + (top_k * 2000)
                tracked_openai_client.logger.set_current_question_id(
                    question_id)
                results.append(pipeline.process_query(
                    row["question"], top_k_chroma=top_k))
            test_data_expl = _with_enhanced_origin_for_expl(test_data)
            evaluation = evaluate_predictions(results, test_data_expl)
            all_results[f"C_top_k_{top_k}"] = {
                "results": results, "evaluation": evaluation}
            logger.save_results({"top_k": top_k, "results": results,
                                "evaluation": evaluation}, filename=f"ragC_k{top_k}.json")
            print(
                f"[C] EM={evaluation['overall']['exact_match']:.4f} F1={
                    evaluation['overall']['f1_score']:.4f}"
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
            before_df = pd.DataFrame(before_rows)
            after_df = pd.DataFrame(after_rows)
            before_df.to_csv(logger.results_dir /
                             f"rag_before_k{top_k}.csv", index=False)
            after_df.to_csv(logger.results_dir /
                            f"rag_after_k{top_k}.csv", index=False)

            # compute relaxed EM/F1
            def _norm(s: str) -> str:
                return clean_ground_truth_text(str(s)).lower()
            preds_rel = [_norm(r["pre_GT"]) for r in after_rows]
            gts_rel = [_norm(x) for x in test_data["ground_truth"].tolist()]

            def _f1_rel(ps, gs):
                scores = []
                for p, g in zip(ps, gs):
                    if ("," in g) or (";" in g) or ("," in p) or (";" in p):
                        ps_set = set([x.strip()
                                     for x in re.split(r"[;,]", p) if x.strip()])
                        gs_set = set([x.strip()
                                     for x in re.split(r"[;,]", g) if x.strip()])
                        inter = ps_set & gs_set
                        precision = len(inter)/len(ps_set) if ps_set else 0.0
                        recall = len(inter)/len(gs_set) if gs_set else 0.0
                        f1 = 0.0 if precision+recall == 0 else 2 * \
                            precision*recall/(precision+recall)
                        scores.append(f1)
                    else:
                        pt, gtok = set(p.split()), set(g.split())
                        inter = pt & gtok
                        precision = len(inter)/len(pt) if pt else 0.0
                        recall = len(inter)/len(gtok) if gtok else 0.0
                        f1 = 0.0 if precision+recall == 0 else 2 * \
                            precision*recall/(precision+recall)
                        scores.append(f1)
                return sum(scores)/len(scores) if scores else 0.0
            em_rel = sum(1 for p, g in zip(preds_rel, gts_rel) if (
                (set([x.strip() for x in re.split(r"[;,]", p) if x.strip()]) == set([x.strip() for x in re.split(
                    r"[;,]", g) if x.strip()])) if ("," in p or ";" in p or "," in g or ";" in g) else p == g
            )) / len(preds_rel) if preds_rel else 0.0
            f1_rel = _f1_rel(preds_rel, gts_rel)
            evaluation.setdefault("overall_relaxed", {})
            evaluation["overall_relaxed"].update(
                {"exact_match": em_rel, "f1_score": f1_rel})

            # detailed logs aggregate per k
            all_logs = []
            for r in results:
                if isinstance(r, dict) and "detailed_log" in r:
                    all_logs.extend(r["detailed_log"])
            if all_logs:
                logger.save_detailed_log(all_logs, filename=f"rag_k{
                                         top_k}_detailed.json")

            aug = test_data.copy()
            aug[f"pre_GT_k{top_k}"] = [r["pre_GT"] for r in after_rows]
            aug[f"pre_EX_k{top_k}"] = [r["pre_EX"] for r in after_rows]
            aug.to_csv(logger.results_dir /
                       f"test_fin_with_predictions_rag_k{top_k}.csv", index=False)

            # merge per-k augmented to one combined (on index)
            merged_aug = aug if merged_aug is None else pd.concat(
                [merged_aug, aug[[f"pre_GT_k{top_k}", f"pre_EX_k{top_k}"]]], axis=1)

    logger.save_results(
        {
            "experiments": all_results,
            "config": {
                "method": args.experiment,
                "top_k_values": top_k_values,
                "max_iterations": args.max_iterations,
                "embedding_model": EMBEDDING_MODEL,
            },
        },
        filename="rag_all_results.json",
    )
    # save combined augmented dataset across all k
    if merged_aug is not None:
        merged_aug.to_csv(logger.results_dir /
                          "test_fin_with_predictions_rag.csv", index=False)
    print(f"✅ RAG 실험 모두 완료! 결과: {args.output_dir}")
    # 실험 마무리
    logger.finalize_experiment()


if __name__ == "__main__":
    main()
# origin 라벨링 유틸 (설명 점수 대상 지정)
