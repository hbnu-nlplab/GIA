# pip install openai>=1.0.0 chromadb tiktoken langchain langchain-community
import os
import chromadb
import tiktoken
from openai import OpenAI
from datetime import datetime
from multiprocessing import Process, Queue
from typing import List, Dict, Optional, Tuple
import time
from langchain_core.tools import Tool
from langchain_google_community import GoogleSearchAPIWrapper
from langchain_community.document_loaders import AsyncHtmlLoader
from langchain_community.document_transformers import Html2TextTransformer

# API Keys Configuration
# wlsruddms@gmail.com
os.environ["GOOGLE_CSE_ID"] = "API_key"  # Your Google CSE ID
os.environ["GOOGLE_API_KEY"] = "API_key"  # Your Google API Key
os.environ["OPENAI_API_KEY"] = "API_key"

# Constants
OPENAI_EMBED_MODEL = "text-embedding-3-large"
EMBED_DIMS = None
MAX_ITERATIONS = 3  # 반복 횟수 설정
CHROMADB_PATH = "/workspace/jke/chromadb"  # 사전 임베딩된 XML 파일들이 저장된 경로
COLLECTION_NAME = "network_devices"  # XML 설정 파일 컬렉션

# System prompt for network engineering assistant
chatgpt_system_prompt = """You are an expert network engineering assistant with deep knowledge of 
network configurations, troubleshooting, and security best practices. You have access to various 
network device configurations, XML schemas, and technical documentation."""

# Initialize OpenAI client
openai_client = OpenAI()  # 환경변수 OPENAI_API_KEY 필요

# Task categories
TASK_CATEGORIES = {
    "SIMPLE_LOOKUP": "Simple Lookup Tasks",
    "SYSTEM_CONTROL": "System Control Commands", 
    "TECHNICAL_ERRORS": "Technical Errors",
    "CONFIG_OPTIMIZATION": "Configuration/Policy Review and Optimization",
    "SECURITY_AUDIT": "Security/Audit Response"
}

class OpenAIEmbedder:
    """OpenAI 임베딩 생성 클래스"""
    def __init__(self, model=OPENAI_EMBED_MODEL, dims: int | None = EMBED_DIMS):
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

class ChromaDB:
    """사전 임베딩된 XML 파일들을 위한 ChromaDB 인터페이스"""
    def __init__(self, db_path: str, collection_name: str,
                 embedder: OpenAIEmbedder | None = None):
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

def get_classification_result(question: str) -> str:
    """사용자 입력을 2가지 작업 카테고리 중 하나로 분류"""
    classification_prompt = '''
    You are an excellent network engineering assistant. Classify the question into ONE of these categories:

    1. **Simple Lookup Tasks** - Tasks that can be solved by referring to or retrieving information from network configuration XML files
    2. **Other Tasks** - All other cases that do not rely on network configuration XML files

    IMPORTANT:
    - Return ONLY the exact category name, nothing else.
    ex) Simple Lookup Tasks
    ex) Other Tasks
    '''
    
    response = openai_client.chat.completions.create(
        model="gpt-3.5-turbo",
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
    task_prompts = {
        "Simple Lookup Tasks": '''
        IMPORTANT:
        - Provide a direct, concise response focusing on retrieving the requested information
        - Include specific commands with their syntax
        - Respond directly without additional explanations unless asked
        ''',
        
        "Other Tasks" : '''
        IMPORTANT:
        - Generate a draft answer that provides step-by-step reasoning and recommended actions
        - Focus on configuration changes, troubleshooting, optimization, or security/audit responses
        - Include specific commands or configuration snippets with proper syntax when relevant
        - Use numbered or bulleted lists to structure solutions clearly
        - Provide a brief explanation for each step or command
        - Maintain a professional and technical tone suitable for network engineering
        - Respond directly without unnecessary disclaimers unless explicitly requested
        '''
    }
    
    # 분류 결과 없으면 Simple Lookup Tasks로
    prompt = task_prompts.get(task_type, task_prompts["Simple Lookup Tasks"])
    
    # 초안은 Temperature 높게.
    response = openai_client.chat.completions.create(
        model="gpt-3.5-turbo",
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
        Create a search query to find relevant XML configuration files and network documentation in ChromaDB.
            Focus on:
            - Network device types (router, switch, firewall)
            - Configuration elements (VLAN, BGP, OSPF, ACL, etc.)
            - Vendor-specific terms (Cisco IOS, Juniper, etc.)
            - Technical keywords from the question

        Output ONLY the query, no explanations.
        ex) CE1 ip address.
        ex) router config.
        '''
    
    response = openai_client.chat.completions.create(
        model="gpt-3.5-turbo",
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
        Create a Google search query to verify and enhance the technical accuracy of the network engineering answer.
            Focus on:
            - Recent best practices and standards
            - Vendor documentation and official guides
            - Common issues and solutions
            - Latest security advisories if relevant

        Make the query specific and technical.
        Output ONLY the query, no explanations.
        '''
    
    response = openai_client.chat.completions.create(
        model="gpt-3.5-turbo",
        messages=[
            {"role": "system", "content": chatgpt_system_prompt},
            {"role": "user", "content": f"Question: {question}\n\nContent: {answer}\n\nInstruction: {query_prompt}"}
        ],
        temperature=0.1
    )
    
    return response.choices[0].message.content.strip()


def get_google_search(query: str = "", k: int = 3) -> Optional[List[Dict]]:
    """완전히 수정된 Google Search API 함수 - Tool 없이 직접 호출"""
    try:
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
        
        tool = Tool(
            name="google_search",
            description="Search Google for recent results.",
            func=search.run,
        )

        results = tool.run(query)
        
        if results and isinstance(results, str) and len(results) > 0:
            print(f"[SUCCESS] Search results found: {len(results)} items")
            
            # 첫 번째 결과의 구조 확인 (디버깅용)
            if len(results) > 0 and isinstance(results[0], dict):
                print(f"[DEBUG] First result keys: {list(results[0].keys())}")
            
            return results
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

def get_revise_answer(question: str, answer: str, content: str, task_type: str) -> str:
    """참조 자료를 바탕으로 답변 수정"""
    revise_prompt = f'''
        I want to revise the answer according to retrieved related content.
        Task Type: {task_type}

        Guidelines:
        - Verify technical accuracy against the reference
        - Add missing critical details from the reference
        - Correct any errors or outdated information
        - Keep the response focused on the {task_type} requirements
        - If the answer is already accurate and complete, keep it as is
        - Always include the source of the reference(s) in the final answer

        IMPORTANT:
        Just output the revised answer directly. DO NOT add additional explanations or announcements.
        '''
    
    response = openai_client.chat.completions.create(
        model="gpt-3.5-turbo",
        messages=[
            {"role": "system", "content": chatgpt_system_prompt},
            {"role": "user", 
             "content": f"Reference Content: {content}\n\nQuestion: {question}\n\nOriginal Answer: {answer}\n\nInstruction: {revise_prompt}"}
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

def get_final_response(question: str, refined_answer: str) -> str:
    """최종 응답 생성 - Exact Match 및 BERT-F1 Score 최적화"""
    final_prompt = """
        You are a network engineering assistant.  

        Generate the final standardized response optimized for evaluation metrics.  

        ==================================================
        EXACT MATCH EVALUATION
        ==================================================
        GUIDELINES:
        - Output must match the expected ground truth precisely
        - Use concise and factual wording
        - Do not add extra explanations or stylistic elements
        - Maintain strict alignment with the given expected answer
        - Use \\n\\n to separate different sections if needed

        STRUCTURE:
        Final Answer  
        Explanation  
        Reference  

        IMPORTANT:
        - The "Final Answer" section must contain ONLY the exact string expected  
        - "Explanation" and "Reference" sections are allowed after the final answer  
        - **The Final Answer section will be evaluated using Exact Match**  

        ==================================================
        BERT-F1 EVALUATION
        ==================================================
        GUIDELINES:
        - Ensure semantic coverage of the ground truth
        - Use precise technical terminology
        - Include all essential details even if wording differs
        - Maintain logical and professional structure
        - Use \\n\\n to separate different sections

        STRUCTURE:
        Final Answer  
        Explanation  
        Reference  

        IMPORTANT:
        - "Final Answer" must capture all meaning in a clear and precise way
        - "Explanation" should summarize reasoning and clarify technical context
        - "Reference" must explicitly list the source(s) of information  
        - **The Explanation section will be evaluated using BERT-F1 Score**
        """
    
    response = openai_client.chat.completions.create(
        model="gpt-3.5-turbo",
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
    
    def __init__(self, chromadb_path: str = CHROMADB_PATH, 
                 collection_name: str = COLLECTION_NAME,
                 max_iterations: int = MAX_ITERATIONS):
        """
        초기화
        Args:
            chromadb_path: 사전 임베딩된 XML 파일이 있는 ChromaDB 경로
            collection_name: XML 설정 파일 컬렉션 이름
            max_iterations: 최대 반복 횟수
        """
        self.db = ChromaDB(chromadb_path, collection_name)
        self.max_iterations = max_iterations
        print(f"[INFO] Pipeline initialized with {max_iterations} max iterations")
        
    def get_chromadb_content(self, question: str, answer: str) -> Optional[str]:
        """ChromaDB에서 관련 XML 설정 파일 검색"""
        query = get_xml_query(question, answer)
        print(f"[INFO] ChromaDB query: {query}")
        
        results = self.db.query(query, n_results=30)
        
        if results and results['documents'] and results['documents'][0]:
            documents = results['documents'][0]
            metadatas = results['metadatas'][0] if results.get('metadatas') else None
            
            # 메타데이터 정보 출력
            if metadatas:
                for i, meta in enumerate(metadatas[:3]):
                    print(f"  - Document {i+1}: {meta}")
            
            # 상위 3개 문서 결합
            combined_content = "\n\n".join(documents[:3])
            return combined_content
        
        return None
    
    def process_query(self, user_question: str) -> Dict:
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
                reference_content = self.get_chromadb_content(user_question, current_answer)
                
                
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
                
                content_list = get_google_search(query)
                
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
            get_final_response, 10, user_question, current_answer
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
    
    CHROMADB_PATH = "/workspace/jke/chromadb"  # 사전 임베딩된 XML 파일들이 저장된 경로
    COLLECTION_NAME = "network_devices"  # XML 설정 파일 컬렉션

    # 파이프라인 초기화
    pipeline = NetworkEngineeringPipeline(
        chromadb_path=CHROMADB_PATH,  # 사전 임베딩된 XML DB 경로
        collection_name=COLLECTION_NAME,
        max_iterations=3
    )
    
    # 테스트 쿼리들

    test_queries = [
        "Review and optimize OSPF configuration for faster convergence",
    ]
    # dataset_for_evaluation_corrected.csv
    # 첫 번째 쿼리 실행
    for query in test_queries:
        results = pipeline.process_query(query)
        
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

if __name__ == "__main__":
    # API 키 확인
    if not os.environ.get("OPENAI_API_KEY"):
        print("[ERROR] Please set OPENAI_API_KEY environment variable")
        exit(1)
    
    if not os.environ.get("GOOGLE_API_KEY") or not os.environ.get("GOOGLE_CSE_ID"):
        print("[WARNING] Google Search API keys not set. Internet search will be disabled.")
    
    main()