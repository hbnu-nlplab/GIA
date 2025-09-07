# pip install openai>=1.0.0 chromadb tiktoken langchain langchain-community
import os
import chromadb
import tiktoken
import pandas as pd 
from openai import OpenAI
from datetime import datetime
from multiprocessing import Process, Queue
from typing import List, Dict, Optional, Tuple
import time
import torch
from langchain_core.tools import Tool
from langchain_google_community import GoogleSearchAPIWrapper
from langchain_community.document_loaders import AsyncHtmlLoader
from langchain_community.document_transformers import Html2TextTransformer
from langchain_huggingface import HuggingFaceEmbeddings


# API Keys Configuration
# wlsruddms@gmail.com
os.environ["GOOGLE_CSE_ID"] = "API_key"  # Your Google CSE ID
os.environ["GOOGLE_API_KEY"] = "API_key"  # Your Google API Key
os.environ["OPENAI_API_KEY"] = ""

# Constants
OPENAI_EMBED_MODEL = "text-embedding-3-large"
EMBED_DIMS = None

# System prompt for network engineering assistant
chatgpt_system_prompt = """You are an expert network engineering assistant with deep knowledge of 
network configurations, troubleshooting, and security best practices. You have access to various 
network device configurations, XML schemas, and technical documentation."""

# Initialize OpenAI client
openai_client = OpenAI()  # 환경변수 OPENAI_API_KEY 필요

class OpenAIEmbedder:
    """OpenAI 임베딩 생성 클래스"""
    def __init__(self, model, dims: int | None = EMBED_DIMS):
        self.client = OpenAI()
        self.model = model
        self.dims = dims

    def embed(self, texts: list[str] | str) -> list[list[float]]:
        if isinstance(texts, str):
            texts = [texts]
        resp = self.client.embeddings.create(
            model=self.model,
            input=texts,
            **({"dimensions": self.dims} if self.dims else {})
        )
        return [d.embedding for d in resp.data]
    
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
        self.embedder = embedder or OpenAIEmbedder()
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

def num_tokens_from_string(string: str, encoding_name: str = "cl100k_base") -> int:
    """텍스트의 토큰 수 계산"""
    encoding = tiktoken.get_encoding(encoding_name)
    return len(encoding.encode(string))

def chunk_texts(text: str, chunk_size: int = 1500) -> List[str]:
    """텍스트를 토큰 크기에 맞게 분할"""
    tokens = num_tokens_from_string(text)
    if tokens <= chunk_size:
        return [text]
    
    texts = []
    n = (tokens // chunk_size) + 1
    part_length = len(text) // n
    extra = len(text) % n
    
    parts = []
    start = 0
    for i in range(n):
        end = start + part_length + (1 if i < extra else 0)
        parts.append(text[start:end].replace('\n', " "))
        start = end
    
    return parts

def get_reranked_indices(question: str, documents: List[str], top_n: int = 5) -> List[int]:
    """LLM을 사용하여 1차 검색 문서들의 중요도를 재정렬하고 인덱스 리스트를 반환.

    Args:
        question: 사용자 질문
        documents: 1차 검색된 문서 텍스트 목록
        top_n: 최종 선택할 문서 수

    Returns:
        재정렬된 상위 문서의 0-based 인덱스 리스트
    """
    if not documents:
        return []

    # LLM에 전달할 문서 포맷팅
    docs_with_indices = [f"Doc[{i+1}]:\n{doc}" for i, doc in enumerate(documents)]
    docs_str = "\n\n".join(docs_with_indices)

    rerank_prompt = f"""
    You are an expert document analyst. Re-rank the documents by relevance to the user question.

    User Question: "{question}"

    Provided Documents:
    {docs_str}

    Instructions:
    1. Read the question and all documents carefully.
    2. Choose the MOST relevant documents that directly help answer the question.
    3. Output a comma-separated list of document numbers only (e.g., Doc[5],Doc[2],Doc[8]) in descending importance.
    4. Return up to {top_n} documents. No explanations.
    """

    try:
        response = openai_client.chat.completions.create(
            model="gpt-4o-mini",
            messages=[
                {"role": "system", "content": "You are a helpful assistant that ranks documents."},
                {"role": "user", "content": rerank_prompt}
            ],
            temperature=0.0
        )
        ranked_doc_indices_str = response.choices[0].message.content.strip()

        # 예: "Doc[5],Doc[2]" -> [4, 1]
        import re
        ranked_indices: List[int] = []
        matches = re.findall(r'Doc\[(\d+)\]', ranked_doc_indices_str)
        for m in matches:
            idx = int(m) - 1
            if 0 <= idx < len(documents):
                ranked_indices.append(idx)

        # 비어있거나 일부만 반환 시 보완
        if not ranked_indices:
            ranked_indices = list(range(min(top_n, len(documents))))

        return ranked_indices[:top_n]
    except Exception as e:
        print(f"[ERROR] Failed to re-rank documents: {e}")
        return list(range(min(top_n, len(documents))))

def get_reranked_documents(question: str, documents: List[str], top_n: int = 5) -> List[str]:
    """문서 목록을 LLM으로 재정렬하여 상위 top_n 문서를 반환."""
    idx = get_reranked_indices(question, documents, top_n=top_n)
    return [documents[i] for i in idx]

def get_classification_result(question: str) -> str:
    """사용자 입력을 2가지 작업 카테고리 중 하나로 분류"""
    classification_prompt = '''
    You are an excellent network engineering assistant. Classify the question into ONE of these categories:

    1. **Simple Lookup Tasks** 
        - Tasks that can be solved by referring to or retrieving information from network configuration XML files
        - Simple lookup tasks: Executing commands for the purpose of retrieving device status, routing tables, interfaces, sessions, logs, etc

    2. **Other Tasks** 
        - All other cases that do not rely on network configuration XML files
        - System control commands: performing configuration changes, applying policies, and executing device control commands
        - Technical errors: conducting fault analysis, identifying root causes, executing recovery procedures, and resolving issues based on logs
        - Configuration/Policy review and optimization: reviewing network configurations and optimizing routing/security policies
        - Security/Audit response: analyzing security events, performing compliance checks, and handling audit responses

    IMPORTANT:
    - Return ONLY the exact category name, nothing else.
    ex) Simple Lookup Tasks
    ex) Other Tasks
    '''
    
    response = openai_client.chat.completions.create(
        model="gpt-4o-mini",
        messages=[
            {"role": "system", "content": chatgpt_system_prompt},
            {"role": "user", "content": f"Question: {question}\n\nInstruction: {classification_prompt}"}
        ],
        temperature=0.05
    )
    
    task_type = response.choices[0].message.content.strip()
    print(f"[INFO] Task classified as: {task_type}")
    return task_type

def get_draft(question: str, task_type: str) -> str:
    """작업 유형에 따른 맞춤형 초안 생성"""

    if task_type == "Simple Lookup Tasks":
        prompt = '''
            This is a simple lookup query. Provide a direct answer based on your knowledge.

            Be extremely concise. No explanations needed.
        '''
    else:
        prompt = '''
            Provide a comprehensive technical answer following this structure:

            1. Direct Answer: State the solution clearly
            2. Technical Implementation: Provide specific steps or configurations
            3. Considerations: Note any important factors or best practices

            Use proper network engineering terminology and be specific with commands/configurations.
        '''
    # 초안은 Temperature 높게.
    response = openai_client.chat.completions.create(
        model="gpt-4o-mini",
        messages=[
            {"role": "system", "content": chatgpt_system_prompt},
            {"role": "user", "content": f"Question: {question}\n\n{prompt}"}
        ],
        temperature=0.3
    )
    
    return response.choices[0].message.content

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

def get_internet_query(question: str, answer: str) -> str:
    """인터넷 검색을 위한 쿼리 생성"""
    query_prompt = '''
        You are responsible for generating a Google search query to validate and reinforce the technical accuracy of the given network engineering answer.

        CONTEXT:
            User Question: {question}
            Proposed Answer: {answer}

        OBJECTIVE:
            - Find authoritative and reliable references that can support, confirm, or refine the proposed answer.
            - Prioritize high-trust sources such as:
                * Official vendor documentation (Cisco, Juniper, Arista, Huawei, etc.)
                * Standards bodies (IETF RFCs, IEEE standards)
                * Well-known security advisories (NVD, CERT, vendor advisories)
                * Recognized industry knowledge bases (Cisco Community, Juniper TechLibrary, etc.)
            - Ensure the query is precise, technical, and aimed at verifying correctness.
            - If possible, emphasize recency to capture the latest best practices, features, or advisories.

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
        temperature=0.1
    )
    
    return response.choices[0].message.content.strip()


def get_google_search(query: str = "", k: int = 3) -> Optional[List[Dict]]:
    """수정된 Google Search API 함수"""
    try:
        # 디버깅 정보 출력
        print(f"[DEBUG] Google search query: '{query}' (k={k})")
        
        # API 키 확인
        api_key = os.environ.get("GOOGLE_API_KEY")
        cse_id = os.environ.get("GOOGLE_CSE_ID")
        
        if not api_key:
            print("[ERROR] GOOGLE_API_KEY 환경변수가 설정되지 않았습니다.")
            return None
            
        if not cse_id:
            print("[ERROR] GOOGLE_CSE_ID 환경변수가 설정되지 않았습니다.")
            return None
        
        # GoogleSearchAPIWrapper 생성
        search = GoogleSearchAPIWrapper(
            k=k,
            google_api_key=api_key,
            google_cse_id=cse_id
        )
        
        # 검색 함수 정의
        def search_results(query):
            try:
                results = search.results(query, k)
                print(f"[DEBUG] Search results count: {len(results) if results else 0}")
                return results
            except Exception as e:
                print(f"[ERROR] search.results() 호출 중 오류: {e}")
                return None
        
        # Tool 생성
        tool = Tool(
            name="Google Search Snippets",
            description="Search Google for recent results.",
            func=search_results,
        )
        
        # 검색 실행
        ref_text = tool.run(query)
        
        if len(ref_text) > 0:
            # 결과 검증 - 첫 번째 항목이 딕셔너리인지 확인
            first_item = ref_text[0]
            if isinstance(first_item, dict):
                # 'Result' 키가 없으면 유효한 결과로 판단 (원래 조건 수정)
                if 'Result' not in first_item:
                    print(f"[SUCCESS] Valid search results found: {len(ref_text)} items")
                    return ref_text
                else:
                    print("[WARNING] Results contain 'Result' key - treating as invalid")
                    return None
            else:
                # 딕셔너리가 아니어도 결과가 있다면 반환
                print(f"[INFO] Non-dict results found: {len(ref_text)} items")
                return ref_text
        else:
            print("[INFO] No search results returned")
            return None
            
    except ImportError as e:
        print(f"[ERROR] 필요한 라이브러리 import 실패: {e}")
        print("다음 명령어로 설치하세요: pip install langchain-google-community")
        return None
    except Exception as e:
        print(f"[ERROR] Google search 실행 중 오류: {e}")
        import traceback
        traceback.print_exc()
        return None

def get_page_content(link: str) -> Optional[str]:
    """웹 페이지 내용 추출"""
    try:
        loader = AsyncHtmlLoader([link])
        docs = loader.load()
        html2text = Html2TextTransformer()
        docs_transformed = html2text.transform_documents(docs)
        if len(docs_transformed) > 0:
            return docs_transformed[0].page_content
        else:
            return None
    except Exception as e:
        print(f"[ERROR] Failed to fetch page content: {e}")
        return None
    
def get_internet_content(query: str) -> Optional[List[str]]:
    """Google 검색을 통해 인터넷 콘텐츠 가져오기"""
    search_results = get_google_search(query, k=3)
    
    if not search_results:
        print("[INFO] No Google search results found")
        return None
    
    all_content = []
    for result in search_results[:2]:  # 상위 2개 결과만 처리
        link = result.get('link')
        if link:
            print(f"[INFO] Fetching content from: {link}")
            page_content = get_page_content(link)
            if page_content:
                # 콘텐츠를 청크로 분할
                chunks = chunk_texts(page_content, 1500)
                all_content.extend(chunks[:2])  # 각 페이지에서 최대 2개 청크
    
    return all_content if all_content else None

def get_revise_answer(question: str, answer: str, content: str, task_type: str) -> str:
    """참조 자료를 바탕으로 답변 수정"""
    if task_type == "Simple Lookup Tasks":
        prompt = '''
            You are revising the given answer using the provided reference content.

            CONTEXT:
                User Question: {question}
                Trusted Answer: {answer}
                Reference Content: {content}

            INSTRUCTIONS:
                - Treat the given answer as reliable and relevant to the question.
                - Use the reference content only to confirm or slightly refine the answer.
                - Keep the revised answer short, direct, and concise.
                - Do not add extra explanations or unrelated details.
                - Output ONLY the revised answer text.
        '''
    else:
        prompt = '''
            Revise the answer using the reference content to ensure technical accuracy.

            Guidelines:
            - Verify all technical details against the reference
            - Add any missing critical information
            - Correct any errors or outdated practices
            - Maintain professional technical language
            - Focus on actionable information

            Output the revised answer directly without any meta-commentary.
        '''
        
    # # 분류 결과 없으면 Simple Lookup Tasks로    
    response = openai_client.chat.completions.create(
        model="gpt-4o-mini",
        messages=[
            {"role": "system", "content": chatgpt_system_prompt},
            {"role": "user", 
             "content": f"Reference Content: {content}\n\nQuestion: {question}\n\nOriginal Answer: {answer}\n\nInstruction: {prompt}"}
        ],
        temperature=0.1
    )
    
    return response.choices[0].message.content

def determine_reference_source(task_type: str, iteration: int) -> str:
    """작업 유형과 반복 횟수에 따라 참조 소스 결정"""
    if task_type == "Simple Lookup Tasks":
        # Simple Lookup은 주로 내부 XML DB 사용
        return "chromadb"
    else:
        return "chromadb" if iteration % 2 == 0 else "internet"

def run_with_timeout(func, timeout, *args, **kwargs):
    """타임아웃이 있는 함수 실행"""
    q = Queue()
    
    def wrapper(q, *args, **kwargs):
        try:
            result = func(*args, **kwargs)
            q.put(result)
        except Exception as e:
            print(f"[ERROR] Function execution failed: {e}")
            q.put(None)
    
    p = Process(target=wrapper, args=(q, *args), kwargs=kwargs)
    p.start()
    p.join(timeout)
    
    if p.is_alive():
        print(f"[WARNING] Function timed out after {timeout}s")
        p.terminate()
        p.join()
        return None
    else:
        return q.get() if not q.empty() else None

def get_final_response(question: str, refined_answer: str, task_type:str) -> str:
    """최종 응답 생성 - Exact Match 및 BERT-F1 Score 최적화"""
    if task_type == "Simple Lookup Tasks":
        final_prompt = """
            You are providing a final answer for a network lookup query.

            CRITICAL INSTRUCTIONS:
            1. Output ONLY the device names or values requested
            2. DO NOT include labels like "Final Answer:" or "Explanation:"
            3. Format as a simple comma-separated list or single value
            4. Be extremely concise and factual

            Example Input: "Which devices have SSH enabled?"
            Example Output: CE1, CE2, sample10

            Now provide the answer for the given question.
        """
    else:  # Other Tasks
        final_prompt = """
            You are providing a comprehensive network engineering solution.

            OUTPUT FORMAT (use exactly this structure):
            [ANSWER]
            {Your concise direct answer here}

            [TECHNICAL DETAILS]
            {Detailed technical explanation with:
            - Step-by-step instructions if applicable
            - Configuration commands if relevant
            - Security considerations
            - Best practices}

            IMPORTANT:
            - Start directly with [ANSWER] section
            - Keep the answer section brief and direct
            - Provide thorough technical details in the second section

            LANGUAEG:
            - 반드시 한국어로 답변해 주세요.
        """
    
    response = openai_client.chat.completions.create(
        model="gpt-4o-mini",
        messages=[
            {"role": "system", "content": chatgpt_system_prompt + "\n\nYou are optimizing responses for exact match and BERT-F1 evaluation metrics."},
            {"role": "user", 
             "content": f"Question: {question}\n\nRefined Answer: {refined_answer}\n\nInstruction: {final_prompt}"}
        ],
        temperature=0.1
    )
    
    return response.choices[0].message.content.strip()

class NetworkEngineeringPipeline:
    """네트워크 엔지니어링 LLM 파이프라인"""
    
    def __init__(self, chromadb_path: str, 
                 collection_name: str,
                 max_iterations: int):
        """
        초기화
        Args:
            chromadb_path: 사전 임베딩된 XML 파일이 있는 ChromaDB 경로
            collection_name: XML 설정 파일 컬렉션 이름
            max_iterations: 최대 반복 횟수
        """
        self.db = ChromaDB(chromadb_path, collection_name, 
            embedder=HuggingFaceEmbedder(
                model_name="Qwen/Qwen3-Embedding-8B",
                device="cuda:1",
                batch_size=8,
            )
        )
        self.max_iterations = max_iterations
        print(f"[INFO] Pipeline initialized with {max_iterations} max iterations")
        
    def get_chromadb_content(self, question: str, answer: str, n_results=5, top_n_after_rerank: int = 5) -> Optional[str]:
        """ChromaDB에서 관련 XML 설정 파일 검색, LLM으로 Re-ranking, 그리고 로깅

        Args:
            question: 사용자 질문
            answer: 현재까지의 초안/답변 (미사용 가능)
            n_results: 1차 후보군 개수 (벡터 검색 Top-K)
            top_n_after_rerank: Re-ranking 후 최종 컨텍스트로 사용할 문서 수
        """
        query = f"단순 조회, {question}"
        print(f"[INFO] ChromaDB query: {query}")
        
        results = self.db.query(query, n_results=n_results)
        
        if results and results['documents'] and results['documents'][0]:
            documents = results['documents'][0]
            metadatas = results['metadatas'][0] if results.get('metadatas') else None

            # Re-ranking 적용 (후보군이 충분히 클 때만)
            if len(documents) > 1:
                print(f"  ├─ Re-ranking {len(documents)} candidates → top {min(top_n_after_rerank, len(documents))}")
                ranked_indices = get_reranked_indices(question, documents, top_n=top_n_after_rerank)

                # 인덱스 기반으로 문서/메타데이터 정렬
                documents = [documents[i] for i in ranked_indices]
                if metadatas:
                    metadatas = [metadatas[i] for i in ranked_indices]
                print(f"  └─ ✓ Re-ranking complete. Selected {len(documents)} docs")
            
            # 메타데이터 정보 출력
            if metadatas:
                for i, meta in enumerate(metadatas):
                    print(f"  - Document {i+1}: {meta}")
            
            # 제외할 키
            exclude_keys = {"file_path", "source", "filename", "source_directory"}
            
            # 문서와 메타데이터를 함께 join
            if metadatas:
                combined_content = "\n\n".join(
                    f"[METADATA]\n" +
                    "\n".join(f"{k}: {v}" for k, v in meta.items() if k not in exclude_keys) +
                    f"\n\n[CONTENT]\n{doc}"
                    for doc, meta in zip(documents, metadatas)
                )
            else:
                combined_content = "\n\n".join(documents)
            
            # 디버깅 로그 저장
            log_path = "input_docs.log"
            with open(log_path, "a", encoding="utf-8") as f:
                f.write(f"\n[QUESTION]\n{question}\n")
                f.write(f"\n[COMBINED_CONTENT]\n{combined_content}\n")
                f.write("=" * 80 + "\n")
            
            return combined_content
        
        return None
    
    def process_query(self, user_question: str, top_k_chroma) -> Dict:
        """사용자 쿼리 처리 메인 파이프라인"""
        start_time = time.time()
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        
        # JSON 로깅을 위한 데이터 저장
        log_data = []
        
        print(f"\n{'='*70}")
        print(f"NETWORK ENGINEERING LLM PIPELINE")
        print(f"{'='*70}")
        print(f"Query: {user_question[:100]}...")
        print(f"Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"{'='*70}\n")
        
        # 1. 작업 분류
        print("[STEP 1/6] Classifying task type...")
        task_type = get_classification_result(user_question)
        print(f"  └─ Classified as: {task_type}")
        
        # JSON 로깅: 작업 분류
        log_data.append({
            "step": "task_classification",
            "content": task_type,
            "timestamp": timestamp
        })
        # 2. 초안 작성
        print("[WARNNING] Task Type : ", task_type)
        print("\n[STEP 2/6] Generating initial draft...")
            
        current_answer = get_draft(user_question, task_type)

        # JSON 로깅: 초안
        log_data.append({
            "step": "initial_draft",
            "content": current_answer,
            "timestamp": timestamp
        })
        
        # 결과 저장
        results = {
            "question": user_question,
            "task_type": task_type,
            "initial_draft": current_answer,
            "iterations": [],
            "total_revisions": 0
        }
        
        # 3-5. 반복적 개선
        print(f"\n[STEP 3-5/6] Iterative refinement ({self.max_iterations} iterations)")
        print("─" * 50)
        
        for iteration in range(self.max_iterations):
            print(f"\n[ITERATION {iteration + 1}/{self.max_iterations}]")
            
            # 참조 소스 결정
            ref_source = determine_reference_source(task_type, iteration)
            print(f"  ├─ Reference source: {ref_source.upper()}")
            
            reference_content = None
            source_details = {}
            
            if ref_source == "chromadb":
                # ChromaDB에서 XML 설정 파일 검색
                print("  ├─ Searching ChromaDB for XML configurations...")
                reference_content = self.get_chromadb_content(user_question, current_answer, n_results=top_k_chroma)
                
                
                if reference_content:
                    print(f"  ├─ Found relevant XML configurations")
                    source_details = {"type": "xml_config", "source": "chromadb"}
                else:
                    print("  ├─ No relevant XML found in ChromaDB")
                    
            else:  # internet
                # 인터넷에서 최신 정보 검색
                print("  ├─ Searching internet for latest information...")
                query = get_internet_query(user_question, current_answer)
                print(f"  ├─ Search query: {query}")
                
                content_list = get_internet_content(query)
                
                if content_list:
                    reference_content = "\n\n".join(content_list)
                    print(f"  ├─ Retrieved {len(content_list)} content chunks")
                    source_details = {"type": "web_content", "source": "google"}
                else:
                    print("  ├─ No relevant content found online")
            
            # 참조 자료가 있으면 답변 수정
            if reference_content:
                print("  ├─ Revising answer with references...")
                revised_answer = run_with_timeout(
                    get_revise_answer, 10, user_question, current_answer, 
                    reference_content, task_type  # 토큰 제한
                )
                
                if revised_answer and revised_answer != current_answer:
                    print("  └─ ✓ Answer improved")
                    current_answer = revised_answer
                    results["total_revisions"] += 1
                    
                    # JSON 로깅: 수정된 답변
                    log_data.append({
                        "step": f"iteration_{iteration + 1}_revised",
                        "content": current_answer,
                        "timestamp": timestamp
                    })
                    
                    iteration_result = {
                        "iteration": iteration + 1,
                        "source": ref_source,
                        "reference_found": True,
                        "answer_revised": True,
                        "source_details": source_details
                    }
                else:
                    print("  └─ ○ No changes needed")
                    iteration_result = {
                        "iteration": iteration + 1,
                        "source": ref_source,
                        "reference_found": True,
                        "answer_revised": False,
                        "source_details": source_details
                    }
            else:
                print("  └─ ○ No references found")
                iteration_result = {
                    "iteration": iteration + 1,
                    "source": ref_source,
                    "reference_found": False,
                    "answer_revised": False,
                    "source_details": {}
                }
            
            results["iterations"].append(iteration_result)
        
        # 6. 최종 응답 생성 (NEW STEP)
        print(f"\n[STEP 6/6] Generating final optimized response...")
        print("  ├─ Optimizing for Exact Match and BERT-F1 Score...")
        
        final_response = run_with_timeout(
            get_final_response, 10, user_question, current_answer, task_type
        )
        
        if final_response and final_response != current_answer:
            print("  └─ ✓ Final response optimized for evaluation metrics")
            results["final_optimization"] = True
        else:
            print("  └─ ○ Current answer already optimal")
            final_response = current_answer
            results["final_optimization"] = False
        
        # JSON 로깅: 최종 응답
        log_data.append({
            "step": "final_response",
            "content": final_response,
            "timestamp": timestamp
        })
        
        # JSON 파일로 저장
        import json
        import os
        
        # 로그 디렉토리 생성
        log_dir = "logs"
        if not os.path.exists(log_dir):
            os.makedirs(log_dir)
        
        # JSON 파일 경로
        json_filename = f"{log_dir}/pipeline_log_{timestamp}.json"
        
        # JSON 형태로 전체 로그 구성
        complete_log = {
            "question": user_question,
            "task_type": task_type,
            "timestamp": timestamp,
            "pipeline_steps": log_data
        }
        
        # JSON 파일 저장
        with open(json_filename, 'w', encoding='utf-8') as jsonfile:
            json.dump(complete_log, jsonfile, ensure_ascii=False, indent=2)
        
        print(f"  ├─ Logged to: {json_filename}")
        results["log_file"] = json_filename
        
        # 최종 결과
        results["final_answer"] = final_response
        results["processing_time"] = round(time.time() - start_time, 2)
        
        print(f"\n{'='*70}")
        print(f"PIPELINE COMPLETE")
        print(f"  - Total time: {results['processing_time']}s")
        print(f"  - Total revisions: {results['total_revisions']}")
        print(f"  - Final optimization: {'YES' if results['final_optimization'] else 'NO'}")
        print(f"  - Task type: {task_type}")
        print(f"{'='*70}\n")
        
        return results

# 메인 실행 함수
def main():
    """파이프라인 실행 예제"""
    
    CHROMADB_PATH = "/workspace/jke/chromadb_qwen"  # 사전 임베딩된 XML 파일들이 저장된 경로
    COLLECTION_NAME = "network_devices"  # XML 설정 파일 컬렉션
    MAX_ITERATIONS = 3  # 반복 횟수 설정

    # 파이프라인 초기화
    pipeline = NetworkEngineeringPipeline(
        chromadb_path=CHROMADB_PATH,  # 사전 임베딩된 XML DB 경로
        collection_name=COLLECTION_NAME,
        max_iterations=MAX_ITERATIONS
    )
    
    # 테스트 쿼리들
    # "CE1 IP address.",
    csv_path = "/workspace/Yujin/GIA/Network-Management-System-main/dataset/test_fin.csv"

    # question 컬럼만 읽어서 리스트로 변환  
    df = pd.read_csv(csv_path)
    test_queries = df["question"].dropna().tolist()
    
    top_k_chromas = [1, 5, 10, 20, 50]
    # 첫 번째 쿼리 실행
    for top_k_chroma in top_k_chromas:
        for query in test_queries:
            results = pipeline.process_query(query, top_k_chroma=top_k_chroma)
            
            # 결과 출력
            print("\n" + "="*70)
            print("FINAL RESULTS")
            print("="*70)
            print(f"\nQuestion: {results['question']}")
            print(f"Task Type: {results['task_type']}")
            print(f"Processing Time: {results['processing_time']}s")
            print(f"Total Revisions: {results['total_revisions']}")
            
            print("\nIteration Summary:")
            for iter_info in results['iterations']:
                status = "✓" if iter_info['answer_revised'] else "○"
                print(f"  {status} Iteration {iter_info['iteration']}: "
                    f"{iter_info['source']} - "
                    f"{'Found' if iter_info['reference_found'] else 'Not found'}")
            
            print(f"\n{'─'*70}")
            print("FINAL ANSWER:")
            print("─"*70)
            print(results['final_answer'])
            print("="*70)

            # 🔹 로그 파일 저장 추가
            with open(f"pipeline_results_qwen_final_exprement_{top_k_chroma}.log", "a", encoding="utf-8") as f:
                f.write("="*70 + "\n")
                f.write(f"Question: {results['question']}\n")
                f.write(f"Final Answer: {results['final_answer']}\n")
                f.write("="*70 + "\n\n")

    # for query in test_queries:
    #     results = pipeline.process_query(query, top_k_chroma=20)
        
    #     # 결과 출력
    #     print("\n" + "="*70)
    #     print("FINAL RESULTS")
    #     print("="*70)
    #     print(f"\nQuestion: {results['question']}")
    #     print(f"Task Type: {results['task_type']}")
    #     print(f"Processing Time: {results['processing_time']}s")
    #     print(f"Total Revisions: {results['total_revisions']}")
        
    #     print("\nIteration Summary:")
    #     for iter_info in results['iterations']:
    #         status = "✓" if iter_info['answer_revised'] else "○"
    #         print(f"  {status} Iteration {iter_info['iteration']}: "
    #             f"{iter_info['source']} - "
    #             f"{'Found' if iter_info['reference_found'] else 'Not found'}")
        
    #     print(f"\n{'─'*70}")
    #     print("FINAL ANSWER:")
    #     print("─"*70)
    #     print(results['final_answer'])
    #     print("="*70)

    #     # 🔹 로그 파일 저장 추가
    #     with open(f"pipeline_results_qwen_improved_prompt{20}.log", "a", encoding="utf-8") as f:
    #         f.write("="*70 + "\n")
    #         f.write(f"Question: {results['question']}\n")
    #         f.write(f"Final Answer: {results['final_answer']}\n")
    #         f.write("="*70 + "\n\n")

if __name__ == "__main__":
    # API 키 확인
    if not os.environ.get("OPENAI_API_KEY"):
        print("[ERROR] Please set OPENAI_API_KEY environment variable")
        exit(1)
    
    if not os.environ.get("GOOGLE_API_KEY") or not os.environ.get("GOOGLE_CSE_ID"):
        print("[WARNING] Google Search API keys not set. Internet search will be disabled.")
    
    main()
