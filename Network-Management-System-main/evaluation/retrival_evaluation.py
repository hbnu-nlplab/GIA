# %% [markdown]
# # Extraction

# %%
import numpy as np
import pandas as pd
from openai import OpenAI
import chromadb
from typing import List, Dict, Optional, Tuple
from langchain_huggingface import HuggingFaceEmbeddings


chatgpt_system_prompt = """You are an expert network engineering assistant with deep knowledge of 
network configurations, troubleshooting, and security best practices. You have access to various 
network device configurations, XML schemas, and technical documentation."""

openai_client = OpenAI()  # 환경변수 OPENAI_API_KEY 필요


class HuggingFaceEmbedder:
    def __init__(self, model_name, device, batch_size):
        self.model_name = model_name
        self.device = device
        self.batch_size = batch_size
        
        self.embedder = HuggingFaceEmbeddings(
            model_name=model_name,
            model_kwargs={"device": device},
            encode_kwargs={"batch_size": batch_size}
        )

        self.model_name = model_name
        self.device = device
        self.batch_size = batch_size

    def embed(self, texts: list[str] | str) -> list[list[float]]:
        if isinstance(texts, str):
            texts = [texts]
        return self.embedder.embed_documents(texts)

class ChromaDB:
    """사전 임베딩된 XML 파일들을 위한 ChromaDB 인터페이스"""
    def __init__(self, db_path: str, collection_name: str, embedder: object):
        self.db_path = db_path
        self.client = chromadb.PersistentClient(path=db_path)
        self.embedder = embedder
        try:
            # 기존 컬렉션 로드 (사전 임베딩된 XML 데이터)
            self.collection = self.client.get_collection(name=collection_name)
            print(f"[INFO] Loaded existing collection: {collection_name}")
            print(f"[INFO] Total documents in collection: {self.collection.count()}")
        except:
            # 컬렉션이 없으면 새로 생성
            self.collection = self.client.create_collection(name=collection_name)
            print(f"[INFO] Created new collection: {collection_name}")

    def add_docs(self, ids: list[str], docs: list[str], metadatas: list[dict] | None = None):
        """새 문서 추가 (필요시)"""
        embeddings = self.embedder.embed(docs)
        self.collection.add(ids=ids, documents=docs, embeddings=embeddings, metadatas=metadatas)

    def query(self, text: str, n_results: int = 5) -> Dict:
        """벡터 유사도 검색"""
        q_emb = self.embedder.embed(text)
        return self.collection.query(query_embeddings=q_emb, n_results=n_results)


def get_xml_query(question: str, answer: str) -> str:
    """ChromaDB의 XML 파일 검색을 위한 쿼리 생성"""
    query_prompt = '''
        You are responsible for generating search queries in ChromaDB to find relevant XML network configuration files and related documents.

        CONTEXT:
            User Question: {question}
            Search History (information found or concluded so far): {answer}

        OBJECTIVE:
            Generate more effective search queries that expand beyond what has already been attempted or concluded in the history.

        OUTPUT INSTRUCTIONS:
            - Output ONLY the search query string.
            - Do not include explanations, reasoning, or extra text.
        '''
    
    response = openai_client.chat.completions.create(
        model="gpt-4o-mini",
        messages=[
            {"role": "system", "content": chatgpt_system_prompt},
            {"role": "user", "content": f"Question: {question}\n\nContent: {answer}\n\nInstruction: {query_prompt}"}
        ],
        temperature=0.05
    )
    
    return response.choices[0].message.content.strip()


def recall_at_k(results: list[str], ground_truth: str, k: int = 5) -> float:
    """정답 텍스트가 top-k 문서 안에 포함되면 1, 아니면 0"""
    return 1.0 if any(ground_truth in doc for doc in results[:k]) else 0.0

def reciprocal_rank(results: list[str], ground_truth: str) -> float:
    """정답이 몇 번째 문서에서 처음 등장하는지 Reciprocal Rank 계산"""
    for idx, doc in enumerate(results, start=1):
        if ground_truth in doc:
            return 1.0 / idx
    return 0.0

def evaluate_retrieval(db, dataset: pd.DataFrame, query_fn, k_values=[1,5,10,20,50]):
    """approximate retrieval 평가 (GT 텍스트 기반)"""
    recall_scores = {k: [] for k in k_values}
    rr_scores = []

    for _, row in dataset.iterrows():
        q, gt = row["question"], row["ground_truth"]

        # 쿼리 생성
        query = query_fn(q, row.get("answer",""))
        
        # 검색 실행
        results = db.query(query, n_results=max(k_values))
        docs = results["documents"][0] if results else []
        
        # Recall@k 계산
        for k in k_values:
            recall_scores[k].append(recall_at_k(docs, gt, k))
        
        # MRR 계산
        rr_scores.append(reciprocal_rank(docs, gt))
    
    # 평균 결과 리턴
    recall_avg = {k: np.mean(v) for k, v in recall_scores.items()}
    mrr = np.mean(rr_scores)
    return recall_avg, mrr

embedder = HuggingFaceEmbedder(
    model_name="Qwen/Qwen3-Embedding-8B",
    device="cuda:1",
    batch_size=32
)

CHROMADB_PATH = "/workspace/jke/chromadb_qwen"  # 사전 임베딩된 XML 파일들이 저장된 경로
COLLECTION_NAME = "network_devices"  # XML 설정 파일 컬렉션

# ChromaDB 초기화 (db_path는 chroma persist 디렉토리 경로, collection_name은 기존에 생성한 이름)
chroma_db = ChromaDB(
    db_path=CHROMADB_PATH,
    collection_name=COLLECTION_NAME,
    embedder=embedder
)

dataset = pd.read_csv("/workspace/jke/evaluation/test.csv")

# === 사용 예시 ===
# 휴리스틱 방식
recall_h, mrr_h = evaluate_retrieval(
    chroma_db, dataset,
    query_fn=lambda q, a: f"단순 조회, {q}"
)

# LLM 방식
recall_llm, mrr_llm = evaluate_retrieval(
    chroma_db, dataset,
    query_fn=lambda q, a: get_xml_query(q, "")
)

print("=== Heuristic Query ===")
print("Recall:", recall_h)
print("MRR:", mrr_h)

print("=== LLM Query ===")
print("Recall:", recall_llm)
print("MRR:", mrr_llm)


# %%
import numpy as np
import pandas as pd
from openai import OpenAI
import chromadb
from typing import List, Dict, Optional, Tuple
from langchain_huggingface import HuggingFaceEmbeddings
from sentence_transformers import CrossEncoder
import torch


chatgpt_system_prompt = """You are an expert network engineering assistant with deep knowledge of 
network configurations, troubleshooting, and security best practices. You have access to various 
network device configurations, XML schemas, and technical documentation."""

openai_client = OpenAI()  # 환경변수 OPENAI_API_KEY 필요


class HuggingFaceEmbedder:
    def __init__(self, model_name, device, batch_size):
        self.model_name = model_name
        self.device = device
        self.batch_size = batch_size
        
        self.embedder = HuggingFaceEmbeddings(
            model_name=model_name,
            model_kwargs={"device": device},
            encode_kwargs={"batch_size": batch_size}
        )

        self.model_name = model_name
        self.device = device
        self.batch_size = batch_size

    def embed(self, texts: list[str] | str) -> list[list[float]]:
        if isinstance(texts, str):
            texts = [texts]
        return self.embedder.embed_documents(texts)


class BERTReRanker:
    """BERT 기반 Cross-Encoder ReRanker"""
    def __init__(self, model_name: str = "cross-encoder/ms-marco-MiniLM-L-6-v2", device: str = "cuda"):
        """
        Args:
            model_name: Cross-encoder 모델명 (기본값: ms-marco-MiniLM-L-6-v2)
            device: 디바이스 설정
        """
        self.device = device
        self.model = CrossEncoder(model_name, device=device)
        print(f"[INFO] ReRanker initialized: {model_name} on {device}")
    
    def rerank(self, query: str, documents: List[str], top_k: int = None) -> List[Tuple[str, float]]:
        """
        문서들을 쿼리와의 관련성 점수로 재순위화
        
        Args:
            query: 검색 쿼리
            documents: 재순위화할 문서 리스트
            top_k: 상위 k개 문서만 반환 (None이면 모든 문서 반환)
            
        Returns:
            (문서, 점수) 튜플의 리스트, 점수 내림차순 정렬
        """
        if not documents:
            return []
            
        # 쿼리-문서 쌍 생성
        pairs = [[query, doc] for doc in documents]
        
        # Cross-encoder로 관련성 점수 계산
        scores = self.model.predict(pairs)
        
        # 문서와 점수를 함께 묶고 점수 내림차순 정렬
        doc_scores = list(zip(documents, scores))
        doc_scores.sort(key=lambda x: x[1], reverse=True)
        
        # top_k 개수만큼만 반환
        if top_k:
            doc_scores = doc_scores[:top_k]
            
        return doc_scores


class ChromaDB:
    """사전 임베딩된 XML 파일들을 위한 ChromaDB 인터페이스 (ReRanking 포함)"""
    def __init__(self, db_path: str, collection_name: str, embedder: object, use_reranking: bool = True, reranker_model: str = "cross-encoder/ms-marco-MiniLM-L-6-v2"):
        self.db_path = db_path
        self.client = chromadb.PersistentClient(path=db_path)
        self.embedder = embedder
        self.use_reranking = use_reranking
        
        # ReRanker 초기화
        if self.use_reranking:
            device = getattr(embedder, 'device', 'cuda')
            self.reranker = BERTReRanker(model_name=reranker_model, device=device)
        
        try:
            # 기존 컬렉션 로드 (사전 임베딩된 XML 데이터)
            self.collection = self.client.get_collection(name=collection_name)
            print(f"[INFO] Loaded existing collection: {collection_name}")
            print(f"[INFO] Total documents in collection: {self.collection.count()}")
        except:
            # 컬렉션이 없으면 새로 생성
            self.collection = self.client.create_collection(name=collection_name)
            print(f"[INFO] Created new collection: {collection_name}")

    def add_docs(self, ids: list[str], docs: list[str], metadatas: list[dict] | None = None):
        """새 문서 추가 (필요시)"""
        embeddings = self.embedder.embed(docs)
        self.collection.add(ids=ids, documents=docs, embeddings=embeddings, metadatas=metadatas)

    def query(self, text: str, n_results: int = 5, initial_retrieval_multiplier: int = 3) -> Dict:
        """벡터 유사도 검색 + BERT ReRanking"""
        
        if self.use_reranking:
            # ReRanking을 사용하는 경우: 더 많은 문서를 초기 검색
            initial_n_results = min(n_results * initial_retrieval_multiplier, self.collection.count())
        else:
            initial_n_results = n_results
        
        # 1단계: 벡터 유사도 검색
        q_emb = self.embedder.embed(text)
        initial_results = self.collection.query(query_embeddings=q_emb, n_results=initial_n_results)
        
        if not self.use_reranking:
            return initial_results
            
        # 2단계: BERT ReRanking
        if not initial_results['documents'] or not initial_results['documents'][0]:
            return initial_results
            
        documents = initial_results['documents'][0]
        ids = initial_results['ids'][0]
        metadatas = initial_results.get('metadatas', [[]])[0] if initial_results.get('metadatas') else [{}] * len(documents)
        distances = initial_results.get('distances', [[]])[0] if initial_results.get('distances') else [0.0] * len(documents)
        
        # ReRanking 수행
        reranked_results = self.reranker.rerank(text, documents, top_k=n_results)
        
        # 결과 재구성
        reranked_documents = []
        reranked_ids = []
        reranked_metadatas = []
        reranked_distances = []  # 이제 ReRanker 점수를 거리로 변환 (1 - score)
        
        for doc, score in reranked_results:
            doc_idx = documents.index(doc)
            reranked_documents.append(doc)
            reranked_ids.append(ids[doc_idx])
            reranked_metadatas.append(metadatas[doc_idx])
            reranked_distances.append(1.0 - score)  # 점수를 거리로 변환 (높은 점수 = 낮은 거리)
        
        return {
            'documents': [reranked_documents],
            'ids': [reranked_ids], 
            'metadatas': [reranked_metadatas] if any(reranked_metadatas) else None,
            'distances': [reranked_distances]
        }


def get_xml_query(question: str, answer: str) -> str:
    """ChromaDB의 XML 파일 검색을 위한 쿼리 생성"""
    query_prompt = '''
        You are responsible for generating search queries in ChromaDB to find relevant XML network configuration files and related documents.

        CONTEXT:
            User Question: {question}
            Search History (information found or concluded so far): {answer}

        OBJECTIVE:
            Generate more effective search queries that expand beyond what has already been attempted or concluded in the history.

        OUTPUT INSTRUCTIONS:
            - Output ONLY the search query string.
            - Do not include explanations, reasoning, or extra text.
        '''
    
    response = openai_client.chat.completions.create(
        model="gpt-4o-mini",
        messages=[
            {"role": "system", "content": chatgpt_system_prompt},
            {"role": "user", "content": f"Question: {question}\n\nContent: {answer}\n\nInstruction: {query_prompt}"}
        ],
        temperature=0.05
    )
    
    return response.choices[0].message.content.strip()


def recall_at_k(results: list[str], ground_truth: str, k: int = 5) -> float:
    """정답 텍스트가 top-k 문서 안에 포함되면 1, 아니면 0"""
    return 1.0 if any(ground_truth in doc for doc in results[:k]) else 0.0

def reciprocal_rank(results: list[str], ground_truth: str) -> float:
    """정답이 몇 번째 문서에서 처음 등장하는지 Reciprocal Rank 계산"""
    for idx, doc in enumerate(results, start=1):
        if ground_truth in doc:
            return 1.0 / idx
    return 0.0

def evaluate_retrieval(db, dataset: pd.DataFrame, query_fn, k_values=[1,5,10,20,50]):
    """approximate retrieval 평가 (GT 텍스트 기반)"""
    recall_scores = {k: [] for k in k_values}
    rr_scores = []

    for _, row in dataset.iterrows():
        q, gt = row["question"], row["ground_truth"]

        # 쿼리 생성
        query = query_fn(q, row.get("answer",""))
        
        # 검색 실행
        results = db.query(query, n_results=max(k_values))
        docs = results["documents"][0] if results else []
        
        # Recall@k 계산
        for k in k_values:
            recall_scores[k].append(recall_at_k(docs, gt, k))
        
        # MRR 계산
        rr_scores.append(reciprocal_rank(docs, gt))
    
    # 평균 결과 리턴
    recall_avg = {k: np.mean(v) for k, v in recall_scores.items()}
    mrr = np.mean(rr_scores)
    return recall_avg, mrr

# 임베딩 모델 초기화
embedder = HuggingFaceEmbedder(
    model_name="Qwen/Qwen3-Embedding-8B",
    device="cuda:1",
    batch_size=32
)

CHROMADB_PATH = "/workspace/jke/chromadb_qwen"  # 사전 임베딩된 XML 파일들이 저장된 경로
COLLECTION_NAME = "network_devices"  # XML 설정 파일 컬렉션

# ChromaDB 초기화 (ReRanking 사용)
chroma_db_with_rerank = ChromaDB(
    db_path=CHROMADB_PATH,
    collection_name=COLLECTION_NAME,
    embedder=embedder,
    use_reranking=True,
    reranker_model="cross-encoder/ms-marco-MiniLM-L-6-v2"  # BERT 기반 cross-encoder
)

# ChromaDB 초기화 (ReRanking 미사용 - 비교용)
chroma_db_no_rerank = ChromaDB(
    db_path=CHROMADB_PATH,
    collection_name=COLLECTION_NAME,
    embedder=embedder,
    use_reranking=False
)

dataset = pd.read_csv("/workspace/jke/evaluation/test.csv")

# === 평가 실행 ===
print("=== 평가 시작 ===")

# 1. 기본 휴리스틱 방식 (ReRanking 없음)
print("\n1. Heuristic Query (No ReRanking)")
recall_h, mrr_h = evaluate_retrieval(
    chroma_db_no_rerank, dataset,
    query_fn=lambda q, a: f"단순 조회, {q}"
)
print("Recall:", recall_h)
print("MRR:", mrr_h)

# 2. LLM 방식 (ReRanking 없음)
print("\n2. LLM Query (No ReRanking)")
recall_llm, mrr_llm = evaluate_retrieval(
    chroma_db_no_rerank, dataset,
    query_fn=lambda q, a: get_xml_query(q, "")
)
print("Recall:", recall_llm)
print("MRR:", mrr_llm)

# 3. 휴리스틱 방식 + BERT ReRanking
print("\n3. Heuristic Query + BERT ReRanking")
recall_h_rerank, mrr_h_rerank = evaluate_retrieval(
    chroma_db_with_rerank, dataset,
    query_fn=lambda q, a: f"단순 조회, {q}"
)
print("Recall:", recall_h_rerank)
print("MRR:", mrr_h_rerank)

# 4. LLM 방식 + BERT ReRanking
print("\n4. LLM Query + BERT ReRanking")
recall_llm_rerank, mrr_llm_rerank = evaluate_retrieval(
    chroma_db_with_rerank, dataset,
    query_fn=lambda q, a: get_xml_query(q, "")
)
print("Recall:", recall_llm_rerank)
print("MRR:", mrr_llm_rerank)

# === 성능 비교 출력 ===
print("\n" + "="*60)
print("성능 비교 요약")
print("="*60)

methods = [
    ("Heuristic (No ReRank)", recall_h, mrr_h),
    ("LLM (No ReRank)", recall_llm, mrr_llm), 
    ("Heuristic + BERT ReRank", recall_h_rerank, mrr_h_rerank),
    ("LLM + BERT ReRank", recall_llm_rerank, mrr_llm_rerank)
]

for method_name, recall_scores, mrr_score in methods:
    print(f"\n{method_name}:")
    print(f"  Recall@1: {recall_scores[1]:.4f}")
    print(f"  Recall@5: {recall_scores[5]:.4f}")
    print(f"  Recall@10: {recall_scores[10]:.4f}")
    print(f"  MRR: {mrr_score:.4f}")

# %%



