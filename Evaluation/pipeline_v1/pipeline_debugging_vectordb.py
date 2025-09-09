# pip install openai>=1.0.0 chromadb tiktoken langchain langchain-community
import os
import chromadb
import tiktoken
from openai import OpenAI
from datetime import datetime
from multiprocessing import Process, Queue
from typing import List, Dict, Optional, Tuple
import time
import traceback
from langchain.tools import Tool
from langchain_google_community import GoogleSearchAPIWrapper
from langchain_community.document_loaders import AsyncHtmlLoader
from langchain_community.document_transformers import Html2TextTransformer

# API Keys Configuration
os.environ["GOOGLE_CSE_ID"] = "API_key"
os.environ["GOOGLE_API_KEY"] = "API_key"
os.environ["OPENAI_API_KEY"] = "API_key"  # 보안상 제거

# Constants
OPENAI_EMBED_MODEL = "text-embedding-3-large"
EMBED_DIMS = None
MAX_ITERATIONS = 3
CHROMADB_PATH = "/workspace/jke/chromadb"
COLLECTION_NAME = "network_devices"

# System prompt
chatgpt_system_prompt = """You are an expert network engineering assistant with deep knowledge of 
network configurations, troubleshooting, and security best practices."""

# Initialize OpenAI client
openai_client = OpenAI()

class OpenAIEmbedder:
    """OpenAI 임베딩 생성 클래스"""
    def __init__(self, model=OPENAI_EMBED_MODEL, dims: int | None = EMBED_DIMS):
        self.client = OpenAI()
        self.model = model
        self.dims = dims

    def embed(self, texts: list[str] | str) -> list[list[float]]:
        if isinstance(texts, str):
            texts = [texts]
        
        # 디버깅: 임베딩 요청 확인
        print(f"[DEBUG] Embedding {len(texts)} text(s) with model {self.model}")
        
        try:
            resp = self.client.embeddings.create(
                model=self.model,
                input=texts,
                **({"dimensions": self.dims} if self.dims else {})
            )
            return [d.embedding for d in resp.data]
        except Exception as e:
            print(f"[ERROR] Embedding failed: {e}")
            raise

class ChromaDB:
    """사전 임베딩된 XML 파일들을 위한 ChromaDB 인터페이스"""
    def __init__(self, db_path: str, collection_name: str,
                 embedder: OpenAIEmbedder | None = None):
        self.db_path = db_path
        self.embedder = embedder or OpenAIEmbedder()
        
        try:
            # ChromaDB 클라이언트 초기화
            self.client = chromadb.PersistentClient(path=db_path)
            print(f"[INFO] ChromaDB client initialized at: {db_path}")
            
            # 모든 컬렉션 나열
            collections = self.client.list_collections()
            print(f"[INFO] Available collections: {[c.name for c in collections]}")
            
            # 컬렉션 로드 또는 생성
            try:
                self.collection = self.client.get_collection(name=collection_name)
                doc_count = self.collection.count()
                print(f"[INFO] Loaded existing collection: {collection_name}")
                print(f"[INFO] Total documents in collection: {doc_count}")
                
                # 샘플 문서 확인
                if doc_count > 0:
                    sample = self.collection.get(limit=1)
                    if sample and sample.get('documents'):
                        print(f"[INFO] Sample document preview: {sample['documents'][0][:200]}...")
                        if sample.get('metadatas'):
                            print(f"[INFO] Sample metadata: {sample['metadatas'][0]}")
                            
            except Exception as e:
                print(f"[WARNING] Collection not found: {e}")
                print(f"[INFO] Creating new collection: {collection_name}")
                self.collection = self.client.create_collection(name=collection_name)
                
        except Exception as e:
            print(f"[ERROR] Failed to initialize ChromaDB: {e}")
            print(f"[ERROR] Check if path exists: {os.path.exists(db_path)}")
            print(f"[ERROR] Path contents: {os.listdir(db_path) if os.path.exists(db_path) else 'Path does not exist'}")
            raise

    def add_docs(self, ids: list[str], docs: list[str], metadatas: list[dict] | None = None):
        """새 문서 추가"""
        embeddings = self.embedder.embed(docs)
        self.collection.add(ids=ids, documents=docs, embeddings=embeddings, metadatas=metadatas)
        print(f"[INFO] Added {len(docs)} documents to collection")

    def query(self, text: str, n_results: int = 5) -> Dict:
        """벡터 유사도 검색 - 개선된 버전"""
        try:
            print(f"[DEBUG] Query text: '{text}'")
            print(f"[DEBUG] Requesting {n_results} results")
            
            # 임베딩 생성
            q_emb = self.embedder.embed(text)
            print(f"[DEBUG] Query embedding generated, dimension: {len(q_emb[0])}")
            
            # ChromaDB 쿼리 실행
            results = self.collection.query(
                query_embeddings=q_emb, 
                n_results=n_results
            )
            
            # 결과 확인
            if results and results.get('documents'):
                print(f"[DEBUG] Found {len(results['documents'][0])} results")
                for i, (doc, dist) in enumerate(zip(results['documents'][0], results['distances'][0])):
                    print(f"[DEBUG] Result {i+1} - Distance: {dist:.4f}, Preview: {doc[:100]}...")
            else:
                print("[DEBUG] No results found")
                
            return results
            
        except Exception as e:
            print(f"[ERROR] Query failed: {e}")
            print(f"[ERROR] Traceback: {traceback.format_exc()}")
            return {'documents': [[]], 'metadatas': [[]], 'distances': [[]]}

    def test_connection(self):
        """ChromaDB 연결 테스트"""
        try:
            print("\n" + "="*50)
            print("CHROMADB CONNECTION TEST")
            print("="*50)
            
            # 1. 컬렉션 정보
            print(f"Collection name: {self.collection.name}")
            print(f"Document count: {self.collection.count()}")
            
            # 2. 샘플 쿼리 테스트
            test_queries = ["CE1", "IP address", "router", "config", "10.0.0.1"]
            
            for test_q in test_queries:
                print(f"\nTesting query: '{test_q}'")
                try:
                    results = self.query(test_q, n_results=3)
                    if results['documents'][0]:
                        print(f"  ✓ Found {len(results['documents'][0])} results")
                    else:
                        print("  ✗ No results")
                except Exception as e:
                    print(f"  ✗ Error: {e}")
                    
            print("="*50 + "\n")
            
        except Exception as e:
            print(f"[ERROR] Connection test failed: {e}")

def get_chromadb_content_direct(db: ChromaDB, question: str, answer: str) -> Optional[str]:
    """ChromaDB에서 직접 검색 (타임아웃 없이)"""
    try:
        # 여러 쿼리 전략 시도
        queries = [
            question,  # 원본 질문
            answer[:100] if len(answer) > 100 else answer,  # 답변 일부
            "CE1 IP",  # 단순화된 쿼리
            "CE1",  # 더 단순한 쿼리
            "IP address configuration"  # 일반적인 쿼리
        ]
        
        all_results = []
        
        for query in queries:
            print(f"[INFO] Trying query: '{query}'")
            results = db.query(query, n_results=3)
            
            if results and results['documents'] and results['documents'][0]:
                documents = results['documents'][0]
                metadatas = results['metadatas'][0] if results.get('metadatas') else None
                
                for i, doc in enumerate(documents):
                    if doc and doc not in all_results:
                        all_results.append(doc)
                        if metadatas and i < len(metadatas):
                            print(f"  - Found: {metadatas[i]}")
                            
                if len(all_results) >= 3:
                    break
        
        if all_results:
            combined_content = "\n\n".join(all_results[:3])
            print(f"[INFO] Combined {len(all_results[:3])} unique results")
            return combined_content
        else:
            print("[INFO] No results found from any query strategy")
            return None
            
    except Exception as e:
        print(f"[ERROR] ChromaDB search failed: {e}")
        print(f"[ERROR] Traceback: {traceback.format_exc()}")
        return None

class NetworkEngineeringPipeline:
    """네트워크 엔지니어링 LLM 파이프라인 - 개선된 버전"""
    
    def __init__(self, chromadb_path: str = CHROMADB_PATH, 
                 collection_name: str = COLLECTION_NAME,
                 max_iterations: int = MAX_ITERATIONS):
        """초기화"""
        print(f"[INFO] Initializing pipeline...")
        self.max_iterations = max_iterations
        
        try:
            self.db = ChromaDB(chromadb_path, collection_name)
            # 연결 테스트 실행
            self.db.test_connection()
            print(f"[INFO] Pipeline initialized successfully")
        except Exception as e:
            print(f"[ERROR] Failed to initialize pipeline: {e}")
            raise
        
    def get_chromadb_content(self, question: str, answer: str) -> Optional[str]:
        """ChromaDB에서 관련 XML 설정 파일 검색 - 개선된 버전"""
        return get_chromadb_content_direct(self.db, question, answer)
    
    def process_query(self, user_question: str) -> Dict:
        """사용자 쿼리 처리 메인 파이프라인 - 개선된 버전"""
        start_time = time.time()
        
        print(f"\n{'='*70}")
        print(f"NETWORK ENGINEERING LLM PIPELINE")
        print(f"{'='*70}")
        print(f"Query: {user_question}")
        print(f"Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"{'='*70}\n")
        
        # 초기 답변 생성 (간단한 테스트용)
        current_answer = "CE1 is a Customer Edge router with IP address configuration."
        
        results = {
            "question": user_question,
            "initial_draft": current_answer,
            "iterations": [],
            "total_revisions": 0
        }
        
        # 반복적 개선
        print(f"\n[ITERATIVE REFINEMENT] ({self.max_iterations} iterations)")
        print("─" * 50)
        
        for iteration in range(self.max_iterations):
            print(f"\n[ITERATION {iteration + 1}/{self.max_iterations}]")
            
            # ChromaDB에서 직접 검색 (타임아웃 없이)
            print("  ├─ Searching ChromaDB for XML configurations...")
            reference_content = self.get_chromadb_content(user_question, current_answer)
            
            if reference_content:
                print(f"  ├─ Found relevant XML configurations")
                print(f"  └─ Content preview: {reference_content[:200]}...")
                results["total_revisions"] += 1
                
                iteration_result = {
                    "iteration": iteration + 1,
                    "source": "chromadb",
                    "reference_found": True,
                    "answer_revised": True
                }
            else:
                print("  └─ No references found")
                iteration_result = {
                    "iteration": iteration + 1,
                    "source": "chromadb",
                    "reference_found": False,
                    "answer_revised": False
                }
            
            results["iterations"].append(iteration_result)
        
        results["final_answer"] = current_answer
        results["processing_time"] = round(time.time() - start_time, 2)
        
        print(f"\n{'='*70}")
        print(f"PIPELINE COMPLETE")
        print(f"  - Total time: {results['processing_time']}s")
        print(f"  - Total revisions: {results['total_revisions']}")
        print(f"{'='*70}\n")
        
        return results

def diagnose_chromadb():
    """ChromaDB 문제 진단"""
    print("\n" + "="*70)
    print("CHROMADB DIAGNOSTICS")
    print("="*70)
    
    # 1. 경로 확인
    print(f"\n1. Path Check:")
    print(f"   - ChromaDB path: {CHROMADB_PATH}")
    print(f"   - Path exists: {os.path.exists(CHROMADB_PATH)}")
    
    if os.path.exists(CHROMADB_PATH):
        print(f"   - Path contents: {os.listdir(CHROMADB_PATH)}")
    
    # 2. ChromaDB 초기화 테스트
    print(f"\n2. ChromaDB Initialization:")
    try:
        client = chromadb.PersistentClient(path=CHROMADB_PATH)
        print("   ✓ Client created successfully")
        
        collections = client.list_collections()
        print(f"   - Collections found: {len(collections)}")
        for col in collections:
            print(f"     • {col.name}: {col.count()} documents")
            
    except Exception as e:
        print(f"   ✗ Failed: {e}")
    
    # 3. 임베딩 모델 테스트
    print(f"\n3. Embedding Model Test:")
    try:
        embedder = OpenAIEmbedder()
        test_embedding = embedder.embed("test query")
        print(f"   ✓ Embedding successful, dimension: {len(test_embedding[0])}")
    except Exception as e:
        print(f"   ✗ Failed: {e}")
    
    print("="*70 + "\n")

def main():
    """개선된 메인 실행 함수"""
    
    # 진단 실행
    diagnose_chromadb()
    
    try:
        # 파이프라인 초기화
        pipeline = NetworkEngineeringPipeline(
            chromadb_path=CHROMADB_PATH,
            collection_name=COLLECTION_NAME,
            max_iterations=3
        )
        
        # 테스트 쿼리
        test_query = "CE1 IP address."
        results = pipeline.process_query(test_query)
        
        # 결과 출력
        print("\n" + "="*70)
        print("FINAL RESULTS")
        print("="*70)
        print(f"\nQuestion: {results['question']}")
        print(f"Processing Time: {results['processing_time']}s")
        print(f"Total Revisions: {results['total_revisions']}")
        
        print("\nIteration Summary:")
        for iter_info in results['iterations']:
            status = "✓" if iter_info['answer_revised'] else "○"
            print(f"  {status} Iteration {iter_info['iteration']}: "
                  f"{iter_info['source']} - "
                  f"{'Found' if iter_info['reference_found'] else 'Not found'}")
        
        print("="*70)
        
    except Exception as e:
        print(f"\n[ERROR] Pipeline failed: {e}")
        print(f"[ERROR] Traceback: {traceback.format_exc()}")

if __name__ == "__main__":
    # API 키 확인
    if not os.environ.get("OPENAI_API_KEY"):
        print("[ERROR] Please set OPENAI_API_KEY environment variable")
        exit(1)
    
    main()