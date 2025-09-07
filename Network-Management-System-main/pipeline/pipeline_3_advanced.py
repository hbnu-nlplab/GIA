# pip install openai>=1.0.0 chromadb tiktoken langchain langchain-community
"""
네트워크 엔지니어링 LLM 파이프라인 - 연구급 RAG vs Non-RAG 비교 실험
=====================================================

이 파이프라인은 네트워크 엔지니어링 질문에 대해 RAG와 Non-RAG 방식을 비교 평가합니다.
자동 임베딩 기능을 포함하여 사전 임베딩된 데이터가 없어도 바로 실험을 시작할 수 있습니다.
"""

# ============================================================================
# 설정 구성 - 여기서 모든 경로, API 키, 파라미터를 설정하세요
# ============================================================================

# 🔑 API 키 설정
GOOGLE_CSE_ID = "API_key"  # Google Custom Search Engine ID
GOOGLE_API_KEY = "API_key"  # Google API Key
OPENAI_API_KEY = ""  # OpenAI API Key

# 📂 파일 경로 설정
CHROMADB_PATH = "/workspace/jke/chromadb_qwen"  # ChromaDB 저장 경로 (자동 생성됨)
XML_DIRECTORY = "c:/Users/yujin/CodeSpace/GIA-Re/docs/xml_분석"  # XML 파일들이 있는 디렉토리
CSV_PATH = "c:/Users/yujin/CodeSpace/GIA-Re/Network-Management-System-main/dataset/test_fin.csv"  # 평가 데이터셋

# 🎛️ 실험 파라미터 설정
COLLECTION_NAME = "network_devices"  # ChromaDB 컬렉션 이름
MAX_ITERATIONS = 3  # RAG 파이프라인 최대 반복 횟수
TOP_K_VALUES = [5, 10, 20]  # RAG에서 테스트할 Top-K 값들

# 🤖 모델 설정
EMBEDDING_MODEL = "Qwen/Qwen3-Embedding-8B"  # 임베딩 모델
EMBEDDING_DEVICE = "cuda:1"  # 임베딩 모델 실행 디바이스
EMBEDDING_BATCH_SIZE = 8  # 임베딩 배치 크기
LLM_MODEL = "gpt-4o-mini"  # 메인 LLM 모델
LLM_TEMPERATURE = 0.05  # LLM Temperature

# 📊 Non-RAG 설정
NON_RAG_USE_EMBEDDING = True  # Non-RAG에서 임베딩 기반 문서 선택 사용 여부
NON_RAG_MAX_DOCS = 5  # Non-RAG에서 선택할 최대 문서 수
NON_RAG_CHUNK_SIZE = 1500  # 청크 크기 (토큰 단위)

# 🔧 기타 설정
OPENAI_EMBED_MODEL = "text-embedding-3-large"  # OpenAI 임베딩 모델 (사용 안함)
EMBED_DIMS = None  # 임베딩 차원 (None이면 모델 기본값)
EXPERIMENT_BASE_DIR = "experiment_results"  # 실험 결과 저장 디렉토리

# ============================================================================
# 필요한 라이브러리 Import
# ============================================================================

from openai import OpenAI
from datetime import datetime
from multiprocessing import Process, Queue
from typing import List, Dict, Optional, Tuple
from langchain_core.tools import Tool
from langchain_google_community import GoogleSearchAPIWrapper
from langchain_community.document_loaders import AsyncHtmlLoader
from langchain_community.document_transformers import Html2TextTransformer
from langchain_huggingface import HuggingFaceEmbeddings

# 평가를 위한 추가 라이브러리
from bert_score import score as bert_score
from rouge import Rouge
from pathlib import Path
import json
import os
import time
import sys
import traceback
import pandas as pd
import re
import glob
import tiktoken
import chromadb
from io import StringIO
import contextlib

# ============================================================================
# 환경 변수 설정 (위의 설정값들을 적용)
# ============================================================================

os.environ["GOOGLE_CSE_ID"] = GOOGLE_CSE_ID
os.environ["GOOGLE_API_KEY"] = GOOGLE_API_KEY  
os.environ["OPENAI_API_KEY"] = OPENAI_API_KEY

# ============================================================================
# 시스템 프롬프트 및 전역 변수
# ============================================================================

# System prompt for network engineering assistant
chatgpt_system_prompt = """You are an expert network engineering assistant with deep knowledge of 
network configurations, troubleshooting, and security best practices. You have access to various 
network device configurations, XML schemas, and technical documentation."""

# 전역 변수들
experiment_logger = None
tracked_openai_client = None

class ExperimentLogger:
    """실험 로그를 체계적으로 관리하는 클래스"""
    
    def __init__(self, experiment_name: str, base_dir: str = "experiment_results"):
        self.experiment_name = experiment_name
        self.timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        self.base_dir = Path(base_dir)
        
        # 실험별 디렉토리 구조 생성
        self.exp_dir = self.base_dir / f"{experiment_name}_{self.timestamp}"
        self.exp_dir.mkdir(parents=True, exist_ok=True)
        
        # 하위 디렉토리들
        self.logs_dir = self.exp_dir / "logs"
        self.results_dir = self.exp_dir / "results"
        self.llm_history_dir = self.exp_dir / "llm_history"
        self.console_dir = self.exp_dir / "console_output"
        
        for dir_path in [self.logs_dir, self.results_dir, self.llm_history_dir, self.console_dir]:
            dir_path.mkdir(exist_ok=True)
        
        # 콘솔 출력 캡처를 위한 설정
        self.console_buffer = StringIO()
        self.original_stdout = sys.stdout
        
        # LLM 호출 히스토리
        self.llm_calls = []
        
        print(f"[INFO] Experiment '{experiment_name}' initialized")
        print(f"[INFO] Results will be saved to: {self.exp_dir}")
    
    def start_console_capture(self):
        """콘솔 출력 캡처 시작"""
        sys.stdout = self.console_buffer
    
    def stop_console_capture(self):
        """콘솔 출력 캡처 종료 및 파일 저장"""
        sys.stdout = self.original_stdout
        console_content = self.console_buffer.getvalue()
        
        if console_content:
            console_file = self.console_dir / f"console_{self.timestamp}.txt"
            with open(console_file, 'w', encoding='utf-8') as f:
                f.write(console_content)
            print(f"[INFO] Console output saved to: {console_file}")
        
        self.console_buffer = StringIO()  # 버퍼 리셋
    
    def log_llm_call(self, call_type: str, prompt: str, response: str, model: str = "gpt-4o-mini", metadata: Dict = None):
        """LLM 호출 기록"""
        call_record = {
            "timestamp": datetime.now().isoformat(),
            "call_type": call_type,
            "model": model,
            "prompt": prompt,
            "response": response,
            "metadata": metadata or {}
        }
        self.llm_calls.append(call_record)
        
        # 개별 LLM 호출 파일로도 저장
        call_file = self.llm_history_dir / f"llm_call_{len(self.llm_calls):03d}_{call_type}.json"
        with open(call_file, 'w', encoding='utf-8') as f:
            json.dump(call_record, f, ensure_ascii=False, indent=2)
    
    def save_detailed_log(self, log_data: List[Dict], filename: str = None):
        """상세 로그 저장"""
        if filename is None:
            filename = f"detailed_log_{self.timestamp}.json"
        
        log_file = self.logs_dir / filename
        with open(log_file, 'w', encoding='utf-8') as f:
            json.dump(log_data, f, ensure_ascii=False, indent=2)
        
        print(f"[INFO] Detailed log saved to: {log_file}")
    
    def save_results(self, results: Dict, filename: str = None):
        """실험 결과 저장"""
        if filename is None:
            filename = f"results_{self.timestamp}.json"
        
        results_file = self.results_dir / filename
        with open(results_file, 'w', encoding='utf-8') as f:
            json.dump(results, f, ensure_ascii=False, indent=2)
        
        print(f"[INFO] Results saved to: {results_file}")
    
    def save_evaluation_report(self, evaluation_data: Dict, filename: str = None):
        """평가 결과 리포트 생성 및 저장"""
        if filename is None:
            filename = f"evaluation_report_{self.timestamp}.md"
        
        report_file = self.results_dir / filename
        
        # Markdown 형태의 리포트 생성
        report_content = self._generate_evaluation_markdown(evaluation_data)
        
        with open(report_file, 'w', encoding='utf-8') as f:
            f.write(report_content)
        
        print(f"[INFO] Evaluation report saved to: {report_file}")
        return report_file
    
    def _generate_evaluation_markdown(self, evaluation_data: Dict) -> str:
        """평가 결과를 Markdown 형태로 생성"""
        content = []
        content.append(f"# 실험 평가 리포트")
        content.append(f"**실험명**: {self.experiment_name}")
        content.append(f"**실행 시간**: {self.timestamp}")
        content.append(f"**생성 일시**: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        content.append("")
        
        # 실험 개요
        if 'experiment_overview' in evaluation_data:
            overview = evaluation_data['experiment_overview']
            content.append("## 📊 실험 개요")
            content.append(f"- **총 질문 수**: {overview.get('total_questions', 'N/A')}")
            content.append(f"- **실험 방법**: {overview.get('methods', 'N/A')}")
            content.append(f"- **평가 메트릭**: {overview.get('metrics', 'N/A')}")
            content.append("")
        
        # Non-RAG 결과
        if 'non_rag' in evaluation_data:
            content.append("## 🔍 Non-RAG 파이프라인 결과")
            non_rag = evaluation_data['non_rag']['evaluation']
            
            content.append("### 전체 성능")
            content.append(f"- **Exact Match**: {non_rag['overall']['exact_match']:.4f}")
            content.append(f"- **F1 Score**: {non_rag['overall']['f1_score']:.4f}")
            content.append(f"- **평균 처리 시간**: {evaluation_data['non_rag']['avg_processing_time']:.2f}초")
            content.append("")
            
            if non_rag['rule_based']['question_count'] > 0:
                content.append("### Rule-based 질문 성능")
                content.append(f"- **Exact Match**: {non_rag['rule_based']['exact_match']:.4f}")
                content.append(f"- **F1 Score**: {non_rag['rule_based']['f1_score']:.4f}")
                content.append(f"- **질문 수**: {non_rag['rule_based']['question_count']}")
                content.append("")
            
            if non_rag['enhanced_llm']['question_count'] > 0:
                content.append("### Enhanced LLM 질문 성능")
                content.append(f"- **Ground Truth EM**: {non_rag['enhanced_llm']['ground_truth']['exact_match']:.4f}")
                content.append(f"- **Ground Truth F1**: {non_rag['enhanced_llm']['ground_truth']['f1_score']:.4f}")
                if non_rag['enhanced_llm']['explanation']['valid_count'] > 0:
                    content.append(f"- **Explanation BERT F1**: {non_rag['enhanced_llm']['explanation']['bert_f1']:.4f}")
                    content.append(f"- **Explanation ROUGE-1**: {non_rag['enhanced_llm']['explanation']['rouge_1_f1']:.4f}")
                content.append(f"- **질문 수**: {non_rag['enhanced_llm']['question_count']}")
                content.append("")
        
        # RAG 결과
        if 'rag' in evaluation_data:
            content.append("## 🎯 RAG 파이프라인 결과")
            
            for top_k, data in evaluation_data['rag'].items():
                if 'top_k_' in top_k:
                    k_value = top_k.split('_')[-1]
                    rag_eval = data['evaluation']
                    
                    content.append(f"### Top-K = {k_value}")
                    content.append(f"- **전체 EM**: {rag_eval['overall']['exact_match']:.4f}")
                    content.append(f"- **전체 F1**: {rag_eval['overall']['f1_score']:.4f}")
                    content.append(f"- **평균 처리 시간**: {data['avg_processing_time']:.2f}초")
                    
                    if rag_eval['rule_based']['question_count'] > 0:
                        content.append(f"- **Rule-based EM**: {rag_eval['rule_based']['exact_match']:.4f}")
                        content.append(f"- **Rule-based F1**: {rag_eval['rule_based']['f1_score']:.4f}")
                    
                    if rag_eval['enhanced_llm']['question_count'] > 0:
                        content.append(f"- **Enhanced LLM GT EM**: {rag_eval['enhanced_llm']['ground_truth']['exact_match']:.4f}")
                        content.append(f"- **Enhanced LLM GT F1**: {rag_eval['enhanced_llm']['ground_truth']['f1_score']:.4f}")
                        if rag_eval['enhanced_llm']['explanation']['valid_count'] > 0:
                            content.append(f"- **Explanation BERT F1**: {rag_eval['enhanced_llm']['explanation']['bert_f1']:.4f}")
                    
                    content.append("")
        
        # 성능 비교 테이블
        content.append("## 📈 성능 비교 요약")
        content.append("| 방법 | 전체 EM | 전체 F1 | Rule-based EM | Enhanced LLM EM | 평균 처리시간 |")
        content.append("|------|---------|---------|---------------|-----------------|---------------|")
        
        # Non-RAG 행
        if 'non_rag' in evaluation_data:
            nr = evaluation_data['non_rag']['evaluation']
            content.append(f"| Non-RAG | {nr['overall']['exact_match']:.4f} | {nr['overall']['f1_score']:.4f} | {nr['rule_based']['exact_match']:.4f} | {nr['enhanced_llm']['ground_truth']['exact_match']:.4f} | {evaluation_data['non_rag']['avg_processing_time']:.2f}초 |")
        
        # RAG 행들
        if 'rag' in evaluation_data:
            for top_k, data in evaluation_data['rag'].items():
                if 'top_k_' in top_k:
                    k_value = top_k.split('_')[-1]
                    r = data['evaluation']
                    content.append(f"| RAG (k={k_value}) | {r['overall']['exact_match']:.4f} | {r['overall']['f1_score']:.4f} | {r['rule_based']['exact_match']:.4f} | {r['enhanced_llm']['ground_truth']['exact_match']:.4f} | {data['avg_processing_time']:.2f}초 |")
        
        content.append("")
        content.append("## 📋 분석 결과")
        content.append("### 주요 발견사항")
        content.append("- TODO: 자동 분석 결과 추가")
        content.append("")
        content.append("### 권장사항")
        content.append("- TODO: 성능 개선 권장사항 추가")
        content.append("")
        
        return "\n".join(content)
    
    def save_llm_history_summary(self):
        """LLM 호출 히스토리 요약 저장"""
        summary_file = self.llm_history_dir / f"llm_history_summary_{self.timestamp}.json"
        
        # 호출 유형별 통계
        call_stats = {}
        for call in self.llm_calls:
            call_type = call['call_type']
            if call_type not in call_stats:
                call_stats[call_type] = {
                    'count': 0,
                    'total_prompt_length': 0,
                    'total_response_length': 0
                }
            
            call_stats[call_type]['count'] += 1
            call_stats[call_type]['total_prompt_length'] += len(call['prompt'])
            call_stats[call_type]['total_response_length'] += len(call['response'])
        
        summary = {
            "total_calls": len(self.llm_calls),
            "call_types": list(call_stats.keys()),
            "statistics": call_stats,
            "first_call": self.llm_calls[0]['timestamp'] if self.llm_calls else None,
            "last_call": self.llm_calls[-1]['timestamp'] if self.llm_calls else None
        }
        
        with open(summary_file, 'w', encoding='utf-8') as f:
            json.dump(summary, f, ensure_ascii=False, indent=2)
        
        print(f"[INFO] LLM history summary saved to: {summary_file}")
    
    def finalize_experiment(self):
        """실험 종료 및 최종 정리"""
        self.stop_console_capture()
        self.save_llm_history_summary()
        
        # 실험 메타데이터 저장
        metadata = {
            "experiment_name": self.experiment_name,
            "timestamp": self.timestamp,
            "total_llm_calls": len(self.llm_calls),
            "experiment_duration": "TODO: 실험 시간 계산",
            "directories": {
                "base": str(self.exp_dir),
                "logs": str(self.logs_dir),
                "results": str(self.results_dir),
                "llm_history": str(self.llm_history_dir),
                "console": str(self.console_dir)
            }
        }
        
        metadata_file = self.exp_dir / "experiment_metadata.json"
        with open(metadata_file, 'w', encoding='utf-8') as f:
            json.dump(metadata, f, ensure_ascii=False, indent=2)
        
        print(f"\n{'='*70}")
        print(f"실험 '{self.experiment_name}' 완료!")
        print(f"결과 디렉토리: {self.exp_dir}")
        print(f"총 LLM 호출: {len(self.llm_calls)}회")
        print(f"{'='*70}")

class TrackedOpenAIClient:
    """LLM 호출을 추적하는 OpenAI 클라이언트 래퍼"""
    
    def __init__(self, logger: ExperimentLogger):
        self.client = OpenAI()
        self.logger = logger
    
    def chat_completions_create(self, call_type: str, **kwargs):
        """채팅 완성 호출 및 로깅"""
        # 프롬프트 추출
        messages = kwargs.get('messages', [])
        prompt = "\n".join([f"{msg['role']}: {msg['content']}" for msg in messages])
        
        # API 호출
        response = self.client.chat.completions.create(**kwargs)
        response_text = response.choices[0].message.content
        
        # 로깅
        metadata = {
            "model": kwargs.get('model', 'unknown'),
            "temperature": kwargs.get('temperature', 'unknown'),
            "prompt_tokens": len(prompt.split()) if prompt else 0,
            "response_tokens": len(response_text.split()) if response_text else 0
        }
        
        self.logger.log_llm_call(
            call_type=call_type,
            prompt=prompt,
            response=response_text,
            model=kwargs.get('model', 'unknown'),
            metadata=metadata
        )
        
        return response

# ============================================================================
# 실험 로깅 및 추적 클래스들
# ============================================================================

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
    def __init__(self, model_name=EMBEDDING_MODEL, device=EMBEDDING_DEVICE, batch_size=EMBEDDING_BATCH_SIZE):
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
    def __init__(self, db_path: str, collection_name: str, embedder: object, xml_directory: str = None):
        self.db_path = db_path
        self.xml_directory = xml_directory
        self.client = chromadb.PersistentClient(path=db_path)
        self.embedder = embedder or OpenAIEmbedder()
        
        try:
            # 기존 컬렉션 로드 (사전 임베딩된 XML 데이터)
            self.collection = self.client.get_collection(name=collection_name)
            print(f"[INFO] Loaded existing collection: {collection_name}")
            print(f"[INFO] Total documents in collection: {self.collection.count()}")
            
            # 컬렉션이 비어있다면 자동 임베딩 수행
            if self.collection.count() == 0 and self.xml_directory:
                print(f"[INFO] Collection is empty. Auto-embedding XML files from: {self.xml_directory}")
                self._auto_embed_xml_files()
                
        except:
            # 컬렉션이 없으면 새로 생성
            self.collection = self.client.create_collection(name=collection_name)
            print(f"[INFO] Created new collection: {collection_name}")
            
            # XML 디렉토리가 제공되었다면 자동 임베딩 수행
            if self.xml_directory:
                print(f"[INFO] Auto-embedding XML files from: {self.xml_directory}")
                self._auto_embed_xml_files()

    def add_docs(self, ids: list[str], docs: list[str], metadatas: list[dict] | None = None):
        """새 문서 추가 (필요시)"""
        embeddings = self.embedder.embed(docs)
        self.collection.add(ids=ids, documents=docs, embeddings=embeddings, metadatas=metadatas)

    def query(self, text: str, n_results: int = 5) -> Dict:
        """벡터 유사도 검색"""
        q_emb = self.embedder.embed(text)
        return self.collection.query(query_embeddings=q_emb, n_results=n_results)
    
    def _auto_embed_xml_files(self):
        """XML 디렉토리의 모든 XML 파일을 자동으로 임베딩"""
        if not self.xml_directory or not os.path.exists(self.xml_directory):
            print(f"[WARNING] XML directory not found: {self.xml_directory}")
            return
            
        xml_files = []
        for root, dirs, files in os.walk(self.xml_directory):
            for file in files:
                if file.lower().endswith('.xml'):
                    xml_files.append(os.path.join(root, file))
        
        if not xml_files:
            print(f"[WARNING] No XML files found in: {self.xml_directory}")
            return
            
        print(f"[INFO] Found {len(xml_files)} XML files. Starting auto-embedding...")
        print(f"[INFO] This may take several minutes depending on the number and size of files.")
        
        batch_size = 5  # 더 작은 배치 크기로 메모리 사용량 감소
        total_chunks = 0
        failed_files = []
        
        for i, xml_file in enumerate(xml_files):
            try:
                print(f"[INFO] Processing file {i+1}/{len(xml_files)}: {os.path.basename(xml_file)}")
                
                # XML 파일 읽기 (다양한 인코딩 시도)
                content = None
                for encoding in ['utf-8', 'utf-8-sig', 'latin-1', 'cp1252']:
                    try:
                        with open(xml_file, 'r', encoding=encoding) as f:
                            content = f.read()
                        break
                    except UnicodeDecodeError:
                        continue
                
                if content is None:
                    print(f"[ERROR] Could not read file {xml_file} with any encoding")
                    failed_files.append(xml_file)
                    continue
                
                # 텍스트를 청크로 분할
                chunks = chunk_texts(content, chunk_size=NON_RAG_CHUNK_SIZE)
                print(f"[INFO] Split into {len(chunks)} chunks")
                
                # 배치별로 처리
                for batch_start in range(0, len(chunks), batch_size):
                    batch_chunks = chunks[batch_start:batch_start + batch_size]
                    
                    # ID와 메타데이터 생성
                    batch_ids = []
                    batch_metadatas = []
                    
                    for j, chunk in enumerate(batch_chunks):
                        chunk_id = f"{os.path.basename(xml_file)}_chunk_{batch_start + j}"
                        batch_ids.append(chunk_id)
                        
                        metadata = {
                            "filename": os.path.basename(xml_file),
                            "file_path": xml_file,
                            "chunk_index": batch_start + j,
                            "total_chunks": len(chunks),
                            "source": "auto_embedded",
                            "source_directory": self.xml_directory
                        }
                        batch_metadatas.append(metadata)
                    
                    try:
                        # 임베딩 및 저장
                        self.add_docs(batch_ids, batch_chunks, batch_metadatas)
                        total_chunks += len(batch_chunks)
                        
                        if total_chunks % 25 == 0:  # 진행 상황 표시
                            print(f"[INFO] Embedded {total_chunks} chunks so far...")
                            
                    except Exception as e:
                        print(f"[ERROR] Failed to embed batch for {xml_file}: {e}")
                        continue
                        
            except Exception as e:
                print(f"[ERROR] Failed to process {xml_file}: {e}")
                failed_files.append(xml_file)
                continue
        
        print(f"[INFO] Auto-embedding complete!")
        print(f"[INFO] Successfully processed: {len(xml_files) - len(failed_files)}/{len(xml_files)} files")
        print(f"[INFO] Total chunks embedded: {total_chunks}")
        print(f"[INFO] Collection now contains: {self.collection.count()} documents")
        
        if failed_files:
            print(f"[WARNING] Failed to process {len(failed_files)} files:")
            for file in failed_files[:5]:  # 처음 5개만 표시
                print(f"  - {os.path.basename(file)}")
            if len(failed_files) > 5:
                print(f"  ... and {len(failed_files) - 5} more files")

def num_tokens_from_string(string: str, encoding_name: str = "cl100k_base") -> int:
    """텍스트의 토큰 수 계산"""
    encoding = tiktoken.get_encoding(encoding_name)
    return len(encoding.encode(string))

def chunk_texts(text: str, chunk_size: int = NON_RAG_CHUNK_SIZE) -> List[str]:
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
        response = tracked_openai_client.chat_completions_create(
            call_type="document_reranking",
            model=LLM_MODEL,
            messages=[
                {"role": "system", "content": "You are a helpful assistant that ranks documents."},
                {"role": "user", "content": rerank_prompt}
            ],
            temperature=0.0
        )
        ranked_doc_indices_str = response.choices[0].message.content.strip()

        # 예: "Doc[5],Doc[2]" -> [4, 1]
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
    
    response = tracked_openai_client.chat_completions_create(
        call_type="task_classification",
        model=LLM_MODEL,
        messages=[
            {"role": "system", "content": chatgpt_system_prompt},
            {"role": "user", "content": f"Question: {question}\n\nInstruction: {classification_prompt}"}
        ],
        temperature=LLM_TEMPERATURE
    )
    
    task_type = response.choices[0].message.content.strip()
    print(f"[INFO] Task classified as: {task_type}")
    return task_type

def get_draft(question: str, task_type: str) -> str:
    """작업 유형에 따른 맞춤형 초안 생성"""

    if task_type == "Simple Lookup Tasks":
        prompt = '''
            This is a simple lookup query. Provide a direct answer based on your knowledge.

            FORMAT REQUIREMENTS:
            [GROUND_TRUTH]
            {{EXACT_VALUE_ONLY - no labels or explanations}}

            [EXPLANATION]  
            {{Brief technical explanation in Korean}}

            EXAMPLES:
            - IP addresses: "192.168.1.1"
            - Device names: "CE1, sample7"
            - Port numbers: "22, 80, 443"
            - Boolean: "Yes" or "No"
        '''
    else:
        prompt = '''
            Provide a comprehensive technical answer following this structure:

            [GROUND_TRUTH]
            {{Exact technical values only}}

            [EXPLANATION]
            {{Detailed technical implementation in Korean}}
            1. Direct Answer: State the solution clearly
            2. Technical Implementation: Provide specific steps or configurations  
            3. Considerations: Note any important factors or best practices

            Use proper network engineering terminology and be specific with commands/configurations.
        '''
        
    response = tracked_openai_client.chat_completions_create(
        call_type="initial_draft",
        model=LLM_MODEL,
        messages=[
            {"role": "system", "content": chatgpt_system_prompt},
            {"role": "user", "content": f"Question: {question}\n\n{prompt}"}
        ],
        temperature=0.2
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
    
    response = tracked_openai_client.chat_completions_create(
        call_type="xml_query_generation",
        model=LLM_MODEL,
        messages=[
            {"role": "system", "content": chatgpt_system_prompt},
            {"role": "user", "content": f"Question: {question}\n\nContent: {answer}\n\nInstruction: {query_prompt}"}
        ],
        temperature=LLM_TEMPERATURE
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
    
    response = tracked_openai_client.chat_completions_create(
        call_type="internet_query_generation",
        model=LLM_MODEL,
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
                chunks = chunk_texts(page_content, NON_RAG_CHUNK_SIZE)
                all_content.extend(chunks[:2])  # 각 페이지에서 최대 2개 청크
    
    return all_content if all_content else None

def get_revise_answer(question: str, answer: str, content: str, task_type: str) -> str:
    """참조 자료를 바탕으로 답변 수정"""
    if task_type == "Simple Lookup Tasks":
        prompt = '''
            You are revising a network engineering answer using reference content.

            CONTEXT:
                User Question: {question}
                Current Answer: {answer}
                Reference Content: {content}

            INSTRUCTIONS:
                - Use reference content to verify and refine the answer
                - For ground_truth sections: Ensure EXACT values only (no labels)
                - For explanation sections: Add technical details from reference
                - Maintain the [GROUND_TRUTH] and [EXPLANATION] format
                - Be extremely precise with technical values
                - Extract exact device names, IPs, ports from reference content

            OUTPUT: Return the complete revised answer in the same format.
        '''
    else:
        prompt = '''
            Revise the network engineering answer using reference content for technical accuracy.

            Guidelines:
            - Verify all technical details against the reference
            - Ensure [GROUND_TRUTH] contains only exact values
            - Enhance [EXPLANATION] with comprehensive technical details
            - Correct any errors or outdated practices
            - Maintain precise technical formatting
            - Focus on actionable network configuration information

            OUTPUT: Return the complete revised answer maintaining the format.
        '''
        
    response = tracked_openai_client.chat_completions_create(
        call_type="answer_revision",
        model=LLM_MODEL,
        messages=[
            {"role": "system", "content": chatgpt_system_prompt},
            {"role": "user", 
             "content": f"Reference Content: {content}\n\nQuestion: {question}\n\nOriginal Answer: {answer}\n\nInstruction: {prompt}"}
        ],
        temperature=LLM_TEMPERATURE
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

def get_final_response(question: str, refined_answer: str, task_type: str) -> str:
    """최종 응답 생성 - CSV 형식에 맞춘 답변 강화"""
    final_prompt = f"""
    You are a network engineering expert. Analyze the question and provide a precise answer in the specified format.

    CRITICAL GROUND_TRUTH FORMATTING RULES:
    1. **Single Value Questions**: Return ONLY the exact value
       - IP addresses: "192.168.1.1" (no labels)
       - Device names: "CE1" or "sample7" (exact name only)
       - Port numbers: "22" or "443" (number only)
       - Boolean answers: "Yes" or "No"
       
    2. **Multiple Value Questions**: Use comma-separated format
       - Device lists: "CE1, CE2, sample10"
       - IP ranges: "192.168.1.1, 192.168.1.2"
       - Port lists: "22, 80, 443"
       
    3. **Configuration Values**: Return exact configuration strings
       - Interface names: "GigabitEthernet0/0"
       - Protocol names: "OSPF" or "BGP"
       - VLAN IDs: "100" or "200"

    EXAMPLES FROM CSV PATTERN:
    Q: "CE1의 IP 주소는 무엇입니까?"
    → Ground Truth: "192.168.1.100"
    
    Q: "SSH가 활성화된 장치들은?"
    → Ground Truth: "CE1, sample7, sample10"
    
    Q: "sample7에서 사용 중인 포트는?"
    → Ground Truth: "22, 80, 443"

    OUTPUT FORMAT:
    [GROUND_TRUTH]
    {{EXACT_VALUE_ONLY}}

    [EXPLANATION]
    {{상세한 기술적 설명을 한국어로 제공}}

    STRICT RULES:
    - Ground Truth: NO extra words, labels, or formatting
    - Explanation: Comprehensive Korean explanation
    - Be extremely precise with values
    - Match the exact format expected in evaluation
    """
    
    response = tracked_openai_client.chat_completions_create(
        call_type="final_optimization",
        model=LLM_MODEL,
        messages=[
            {"role": "system", "content": chatgpt_system_prompt},
            {"role": "user", 
             "content": f"Question: {question}\n\nCurrent Answer: {refined_answer}\n\nInstruction: {final_prompt}"}
        ],
        temperature=LLM_TEMPERATURE
    )
    
    return response.choices[0].message.content.strip()

class NetworkEngineeringPipeline:
    """네트워크 엔지니어링 LLM 파이프라인"""
    
    def __init__(self, chromadb_path: str, 
                 collection_name: str,
                 max_iterations: int,
                 xml_directory: str = None):
        """
        초기화
        Args:
            chromadb_path: 사전 임베딩된 XML 파일이 있는 ChromaDB 경로
            collection_name: XML 설정 파일 컬렉션
            max_iterations: 최대 반복 횟수
            xml_directory: XML 파일들이 있는 디렉토리 (자동 임베딩용)
        """
        self.db = ChromaDB(chromadb_path, collection_name, 
            embedder=HuggingFaceEmbedder(),  # 기본 설정값 사용
            xml_directory=xml_directory
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
        
        # experiment_logger를 통해 상세 로그 저장
        if experiment_logger:
            experiment_logger.save_detailed_log(log_data, f"pipeline_detailed_{timestamp}.json")
        
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
        log_dir = "logs2"
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

def main():
    """두 가지 실험을 위한 파이프라인 실행"""
    global experiment_logger, tracked_openai_client
    
    # 실험 로거 초기화
    experiment_logger = ExperimentLogger("network_pipeline_comparison", EXPERIMENT_BASE_DIR)
    tracked_openai_client = TrackedOpenAIClient(experiment_logger)
    
    # 콘솔 출력 캡처 시작
    experiment_logger.start_console_capture()
    
    try:
        # 설정값 출력 (확인용)
        print("="*80)
        print("실험 설정 확인")
        print("="*80)
        print(f"ChromaDB 경로: {CHROMADB_PATH}")
        print(f"XML 디렉토리: {XML_DIRECTORY}")
        print(f"CSV 데이터셋: {CSV_PATH}")
        print(f"임베딩 모델: {EMBEDDING_MODEL}")
        print(f"GPU 디바이스: {EMBEDDING_DEVICE}")
        print(f"최대 반복 횟수: {MAX_ITERATIONS}")
        print(f"Top-K 값들: {TOP_K_VALUES}")
        print("="*80)
        
        # 실험 개요 저장
        experiment_overview = {
            "total_questions": 0,
            "methods": ["Improved Non-RAG (Intelligent Chunking)", "RAG (ChromaDB with top_k variations)"],
            "metrics": ["Exact Match", "F1 Score", "BERT F1", "ROUGE-1", "Processing Time"],
            "chromadb_path": CHROMADB_PATH,
            "xml_directory": XML_DIRECTORY,
            "max_iterations": MAX_ITERATIONS,
            "top_k_values": TOP_K_VALUES,
            "embedding_model": EMBEDDING_MODEL
        }
        }
        
        # 테스트 데이터 로드
        print("Loading test data...")
        df = pd.read_csv(CSV_PATH)
        test_queries = df["question"].dropna().tolist()
        experiment_overview["total_questions"] = len(test_queries)
        print(f"Loaded {len(test_queries)} test queries")
        
        # ===============================
        # 실험 1: 개선된 Non-RAG (지능형 청킹)
        # ===============================
        print("\n" + "="*80)
        print("EXPERIMENT 1: IMPROVED NON-RAG PIPELINE (Intelligent XML Chunking)")
        print("="*80)
        
        # 기존 NonRAGPipeline 대신 ImprovedNonRAGPipeline 사용
        non_rag_pipeline = ImprovedNonRAGPipeline(XML_DIRECTORY)
        non_rag_results = []
        
        for i, query in enumerate(test_queries):
            print(f"\nProcessing query {i+1}/{len(test_queries)}: {query[:50]}...")
            result = non_rag_pipeline.process_query(query)
            non_rag_results.append(result)
        
        # 실험 1 결과 저장
        experiment_logger.save_results(non_rag_results, "improved_non_rag_results.json")
        
        # 실험 1 평가
        print("\n" + "="*80)
        print("EXPERIMENT 1 EVALUATION")
        print("="*80)
        non_rag_eval = evaluate_predictions(non_rag_results, df)
        
        # ===============================
        # 실험 2: RAG 적용
        # ===============================
        print("\n" + "="*80)
        print("EXPERIMENT 2: RAG PIPELINE (ChromaDB)")
        print("="*80)
        
        rag_pipeline = NetworkEngineeringPipeline(
            chromadb_path=CHROMADB_PATH,
            collection_name=COLLECTION_NAME,
            max_iterations=MAX_ITERATIONS,
            xml_directory=XML_DIRECTORY
        )
        
        # 다양한 top_k 값으로 실험
        top_k_values = TOP_K_VALUES
        rag_results_by_k = {}
        
        for top_k in top_k_values:
            print(f"\n--- Testing with top_k={top_k} ---")
            rag_results = []
            
            for i, query in enumerate(test_queries):
                print(f"\nProcessing query {i+1}/{len(test_queries)} (top_k={top_k}): {query[:50]}...")
                result = rag_pipeline.process_query(query, top_k_chroma=top_k)
                rag_results.append(result)
            
            rag_results_by_k[top_k] = rag_results
            
            # 각 top_k별 결과 저장
            experiment_logger.save_results(rag_results, f"rag_results_k{top_k}.json")
            
            # 실험 2 평가 (각 top_k별)
            print(f"\n--- EXPERIMENT 2 EVALUATION (top_k={top_k}) ---")
            rag_eval = evaluate_predictions(rag_results, df)
            rag_results_by_k[f"{top_k}_eval"] = rag_eval
        
        # ===============================
        # 종합 결과 비교
        # ===============================
        print("\n" + "="*80)
        print("COMPREHENSIVE COMPARISON")
        print("="*80)
        
        comparison_results = {
            "experiment_date": datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            "experiment_overview": experiment_overview,
            "test_queries_count": len(test_queries),
            "improved_non_rag": {
                "evaluation": non_rag_eval,
                "avg_processing_time": sum(r['processing_time'] for r in non_rag_results) / len(non_rag_results)
            },
            "rag": {}
        }
        
        print("\n[IMPROVED NON-RAG RESULTS (Intelligent Chunking)]")
        print(f"Overall - EM: {non_rag_eval['overall']['exact_match']:.4f}, F1: {non_rag_eval['overall']['f1_score']:.4f}")
        if 'origin' in df.columns:
            print(f"Rule-based - EM: {non_rag_eval['rule_based']['exact_match']:.4f}, F1: {non_rag_eval['rule_based']['f1_score']:.4f}")
            print(f"Enhanced LLM GT - EM: {non_rag_eval['enhanced_llm']['ground_truth']['exact_match']:.4f}, F1: {non_rag_eval['enhanced_llm']['ground_truth']['f1_score']:.4f}")
            if non_rag_eval['enhanced_llm']['explanation']['valid_count'] > 0:
                print(f"Enhanced LLM Exp - BERT F1: {non_rag_eval['enhanced_llm']['explanation']['bert_f1']:.4f}, ROUGE-1: {non_rag_eval['enhanced_llm']['explanation']['rouge_1_f1']:.4f}")
        
        for top_k in top_k_values:
            rag_eval = rag_results_by_k[f"{top_k}_eval"]
            rag_results = rag_results_by_k[top_k]
            
            comparison_results["rag"][f"top_k_{top_k}"] = {
                "evaluation": rag_eval,
                "avg_processing_time": sum(r['processing_time'] for r in rag_results) / len(rag_results)
            }
            
            print(f"\n[RAG RESULTS - top_k={top_k}]")
            print(f"Overall - EM: {rag_eval['overall']['exact_match']:.4f}, F1: {rag_eval['overall']['f1_score']:.4f}")
            if 'origin' in df.columns:
                print(f"Rule-based - EM: {rag_eval['rule_based']['exact_match']:.4f}, F1: {rag_eval['rule_based']['f1_score']:.4f}")
                print(f"Enhanced LLM GT - EM: {rag_eval['enhanced_llm']['ground_truth']['exact_match']:.4f}, F1: {rag_eval['enhanced_llm']['ground_truth']['f1_score']:.4f}")
                if rag_eval['enhanced_llm']['explanation']['valid_count'] > 0:
                    print(f"Enhanced LLM Exp - BERT F1: {rag_eval['enhanced_llm']['explanation']['bert_f1']:.4f}, ROUGE-1: {rag_eval['enhanced_llm']['explanation']['rouge_1_f1']:.4f}")
        
        # 종합 결과를 experiment_logger로 저장
        experiment_logger.save_results(comparison_results, "comprehensive_comparison_results.json")
        
        # 평가 리포트 생성
        experiment_logger.save_evaluation_report(comparison_results)
        
        print(f"\n실험이 완료되었습니다!")
        print(f"결과는 {experiment_logger.exp_dir}에 저장되었습니다.")
        print("="*80)
        
    except Exception as e:
        print(f"[ERROR] 실험 중 오류 발생: {e}")
        traceback.print_exc()
    finally:
        # 실험 종료 처리
        experiment_logger.finalize_experiment()

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

def calculate_exact_match(predictions: List[str], ground_truths: List[str]) -> float:
    """Exact Match 계산"""
    if len(predictions) != len(ground_truths):
        raise ValueError("Predictions and ground truths must have the same length")
    
    correct = 0
    for pred, gt in zip(predictions, ground_truths):
        if pred.strip().lower() == gt.strip().lower():
            correct += 1
    
    return correct / len(predictions)

def calculate_f1_score(predictions: List[str], ground_truths: List[str]) -> float:
    """F1 Score 계산 (토큰 기반)"""
    if len(predictions) != len(ground_truths):
        raise ValueError("Predictions and ground truths must have the same length")
    
    f1_scores = []
    for pred, gt in zip(predictions, ground_truths):
        pred_tokens = set(pred.strip().lower().split())
        gt_tokens = set(gt.strip().lower().split())
        
        if len(gt_tokens) == 0:
            f1_scores.append(1.0 if len(pred_tokens) == 0 else 0.0)
            continue
            
        intersection = pred_tokens.intersection(gt_tokens)
        precision = len(intersection) / len(pred_tokens) if len(pred_tokens) > 0 else 0
        recall = len(intersection) / len(gt_tokens)
        
        if precision + recall == 0:
            f1_scores.append(0.0)
        else:
            f1_scores.append(2 * precision * recall / (precision + recall))
    
    return sum(f1_scores) / len(f1_scores)

def calculate_bert_score(predictions: List[str], ground_truths: List[str]) -> Dict[str, float]:
    """BERT Score 계산"""
    if len(predictions) != len(ground_truths):
        raise ValueError("Predictions and ground truths must have the same length")
    
    # BERT Score 계산
    P, R, F1 = bert_score(predictions, ground_truths, lang="en", verbose=False)
    
    return {
        "precision": P.mean().item(),
        "recall": R.mean().item(), 
        "f1": F1.mean().item()
    }

def calculate_rouge_scores(predictions: List[str], ground_truths: List[str]) -> Dict[str, float]:
    """ROUGE Score 계산"""
    if len(predictions) != len(ground_truths):
        raise ValueError("Predictions and ground truths must have the same length")
    
    rouge = Rouge()
    scores = rouge.get_scores(predictions, ground_truths, avg=True)
    
    return {
        "rouge-1": scores['rouge-1']['f'],
        "rouge-2": scores['rouge-2']['f'],
        "rouge-l": scores['rouge-l']['f']
    }

def load_xml_files(xml_directory: str) -> str:
    """XML 파일들을 로드하여 하나의 문자열로 결합"""
    xml_files = glob.glob(os.path.join(xml_directory, "*.xml"))
    combined_xml = ""
    
    for xml_file in xml_files:
        try:
            with open(xml_file, 'r', encoding='utf-8') as f:
                content = f.read()
                combined_xml += f"\n\n=== {os.path.basename(xml_file)} ===\n{content}\n"
        except Exception as e:
            print(f"[WARNING] Failed to load {xml_file}: {e}")
    
    return combined_xml


class ImprovedNonRAGPipeline:
    """개선된 Non-RAG 파이프라인 - 지능형 XML 청킹 및 선택"""
    
    def __init__(self, xml_directory: str):
        """
        초기화
        Args:
            xml_directory: 원본 XML 파일들이 있는 디렉토리 경로
        """
        self.xml_files = self._load_xml_files_with_chunking(xml_directory)
        self.embedder = HuggingFaceEmbedder()  # 기본 설정값 사용
        print(f"[INFO] Loaded {len(self.xml_files)} XML files with intelligent chunking")
        total_chunks = sum(len(xml_file['chunks']) for xml_file in self.xml_files)
        print(f"[INFO] Total chunks created: {total_chunks}")
    
    def _load_xml_files_with_chunking(self, xml_directory: str) -> List[Dict]:
        """XML 파일들을 개별적으로 로드하여 지능형 청킹 적용"""
        xml_files = []
        
        for xml_file in glob.glob(os.path.join(xml_directory, "*.xml")):
            try:
                with open(xml_file, 'r', encoding='utf-8') as f:
                    content = f.read()
                    
                    # 의미 단위로 청킹 (XML 태그 기반)
                    chunks = self._intelligent_xml_chunking(content)
                    
                    xml_files.append({
                        "filename": os.path.basename(xml_file),
                        "original_content": content,
                        "chunks": chunks,
                        "chunk_count": len(chunks)
                    })
                    
                print(f"[INFO] Processed {os.path.basename(xml_file)}: {len(chunks)} chunks")
                    
            except Exception as e:
                print(f"[WARNING] Failed to load {xml_file}: {e}")
        
        return xml_files
    
    def _intelligent_xml_chunking(self, xml_content: str, max_chunk_size: int = 1500) -> List[Dict]:
        """XML 내용을 의미 단위로 지능형 청킹"""
        chunks = []
        
        # XML 구조를 고려한 분할 패턴들
        xml_patterns = [
            r'<device[^>]*>.*?</device>',  # 디바이스 단위
            r'<interface[^>]*>.*?</interface>',  # 인터페이스 단위
            r'<vlan[^>]*>.*?</vlan>',  # VLAN 단위
            r'<routing[^>]*>.*?</routing>',  # 라우팅 단위
            r'<security[^>]*>.*?</security>',  # 보안 단위
            r'<configuration[^>]*>.*?</configuration>',  # 설정 단위
        ]
        
        # 패턴별로 매칭된 청크들 수집
        matched_chunks = []
        remaining_content = xml_content
        
        for pattern in xml_patterns:
            matches = re.findall(pattern, xml_content, re.DOTALL | re.IGNORECASE)
            for match in matches:
                chunk_info = self._create_chunk_info(match, pattern)
                if chunk_info and chunk_info not in matched_chunks:
                    matched_chunks.append(chunk_info)
                    # 매칭된 부분을 제거
                    remaining_content = remaining_content.replace(match, '', 1)
        
        # 매칭되지 않은 나머지 내용도 청킹
        if remaining_content.strip():
            remaining_chunks = chunk_texts(remaining_content, max_chunk_size)
            for i, chunk_text in enumerate(remaining_chunks):
                if chunk_text.strip():
                    matched_chunks.append({
                        "content": chunk_text,
                        "type": "miscellaneous",
                        "chunk_id": f"misc_{i}",
                        "tokens": num_tokens_from_string(chunk_text)
                    })
        
        # 토큰 크기가 큰 청크들을 다시 분할
        final_chunks = []
        for chunk in matched_chunks:
            if chunk["tokens"] > max_chunk_size:
                sub_chunks = chunk_texts(chunk["content"], max_chunk_size)
                for j, sub_chunk in enumerate(sub_chunks):
                    final_chunks.append({
                        "content": sub_chunk,
                        "type": f"{chunk['type']}_sub",
                        "chunk_id": f"{chunk['chunk_id']}_{j}",
                        "tokens": num_tokens_from_string(sub_chunk)
                    })
            else:
                final_chunks.append(chunk)
        
        return final_chunks
    
    def _create_chunk_info(self, content: str, pattern: str) -> Dict:
        """청크 정보 생성"""
        # 패턴에서 타입 추출
        type_mapping = {
            'device': 'device_config',
            'interface': 'interface_config', 
            'vlan': 'vlan_config',
            'routing': 'routing_config',
            'security': 'security_config',
            'configuration': 'general_config'
        }
        
        chunk_type = 'unknown'
        for key, value in type_mapping.items():
            if key in pattern:
                chunk_type = value
                break
        
        return {
            "content": content,
            "type": chunk_type,
            "chunk_id": f"{chunk_type}_{hash(content) % 10000}",
            "tokens": num_tokens_from_string(content)
        }
    
    def _select_relevant_chunks_with_embedding(self, question: str, max_tokens: int = 15000) -> str:
        """임베딩 기반으로 질문과 관련된 XML 청크들을 지능적으로 선택"""
        
        print(f"[INFO] Selecting relevant chunks for question: {question[:50]}...")
        
        # 모든 청크들 수집
        all_chunks = []
        for xml_file in self.xml_files:
            for chunk in xml_file["chunks"]:
                chunk_with_metadata = chunk.copy()
                chunk_with_metadata["filename"] = xml_file["filename"]
                all_chunks.append(chunk_with_metadata)
        
        print(f"[INFO] Total chunks to analyze: {len(all_chunks)}")
        
        # 질문 임베딩
        question_embedding = self.embedder.embed([question])[0]
        
        # 청크들 임베딩 및 유사도 계산
        chunk_texts = [chunk["content"] for chunk in all_chunks]
        chunk_embeddings = self.embedder.embed(chunk_texts)
        
        # 코사인 유사도 계산
        similarities = []
        for i, chunk_emb in enumerate(chunk_embeddings):
            similarity = self._cosine_similarity(question_embedding, chunk_emb)
            similarities.append((similarity, i))
        
        # 유사도순으로 정렬
        similarities.sort(reverse=True)
        
        # 유사도 기반 + 다양성을 고려한 선택
        selected_chunks = []
        total_tokens = 0
        type_counts = {}
        
        for similarity, idx in similarities:
            chunk = all_chunks[idx]
            chunk_type = chunk["type"]
            
            # 토큰 제한 확인
            if total_tokens + chunk["tokens"] > max_tokens:
                continue
            
            # 타입 다양성 고려 (각 타입별 최대 제한)
            type_limit = max_tokens // 8  # 각 타입별 대략적 제한
            if type_counts.get(chunk_type, 0) * 500 > type_limit:  # 대략적 계산
                continue
            
            # 최소 유사도 임계값
            if similarity < 0.1:  # 너무 낮은 유사도는 제외
                break
            
            selected_chunks.append({
                "content": chunk["content"],
                "filename": chunk["filename"],
                "type": chunk["type"],
                "similarity": similarity,
                "tokens": chunk["tokens"]
            })
            
            total_tokens += chunk["tokens"]
            type_counts[chunk_type] = type_counts.get(chunk_type, 0) + 1
            
            # 충분한 정보가 모이면 종료
            if len(selected_chunks) >= 20 or total_tokens >= max_tokens * 0.9:
                break
        
        print(f"[INFO] Selected {len(selected_chunks)} relevant chunks ({total_tokens} tokens)")
        print(f"[INFO] Type distribution: {type_counts}")
        
        # 선택된 청크들을 포맷팅
        formatted_content = []
        for i, chunk in enumerate(selected_chunks):
            header = f"=== {chunk['filename']} | {chunk['type']} | Similarity: {chunk['similarity']:.3f} ==="
            formatted_content.append(f"{header}\n{chunk['content']}")
        
        return "\n\n".join(formatted_content)
    
    def _cosine_similarity(self, vec1: List[float], vec2: List[float]) -> float:
        """코사인 유사도 계산"""
        import numpy as np
        
        vec1 = np.array(vec1)
        vec2 = np.array(vec2)
        
        dot_product = np.dot(vec1, vec2)
        norm1 = np.linalg.norm(vec1)
        norm2 = np.linalg.norm(vec2)
        
        if norm1 == 0 or norm2 == 0:
            return 0.0
        
        return dot_product / (norm1 * norm2)
    
    def _fallback_keyword_selection(self, question: str, max_tokens: int = 15000) -> str:
        """임베딩 실패시 키워드 기반 폴백 선택"""
        print("[WARNING] Using fallback keyword-based selection")
        
        # 키워드 기반 관련성 점수 계산
        question_keywords = set(question.lower().split())
        scored_chunks = []
        
        for xml_file in self.xml_files:
            for chunk in xml_file["chunks"]:
                # 키워드 매칭 점수
                chunk_words = set(chunk["content"].lower().split())
                overlap = len(question_keywords.intersection(chunk_words))
                
                scored_chunks.append({
                    "content": chunk["content"],
                    "filename": xml_file["filename"],
                    "type": chunk["type"],
                    "score": overlap,
                    "tokens": chunk["tokens"]
                })
        
        # 점수순으로 정렬
        scored_chunks.sort(key=lambda x: x["score"], reverse=True)
        
        # 토큰 제한 내에서 상위 청크들 선택
        selected_content = []
        total_tokens = 0
        
        for chunk in scored_chunks:
            if total_tokens + chunk["tokens"] <= max_tokens and chunk["score"] > 0:
                header = f"=== {chunk['filename']} | {chunk['type']} | Score: {chunk['score']} ==="
                selected_content.append(f"{header}\n{chunk['content']}")
                total_tokens += chunk["tokens"]
            else:
                if total_tokens >= max_tokens:
                    break
        
        print(f"[INFO] Fallback selected {len(selected_content)} chunks ({total_tokens} tokens)")
        return "\n\n".join(selected_content)
    
    def process_query(self, user_question: str) -> Dict:
        """개선된 Non-RAG 쿼리 처리"""
        start_time = time.time()
        
        print(f"\n{'='*70}")
        print(f"IMPROVED NON-RAG PIPELINE (Intelligent Chunking)")
        print(f"{'='*70}")
        print(f"Query: {user_question[:100]}...")
        print(f"Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"{'='*70}\n")
        
        # 작업 분류
        print("[STEP 1/3] Classifying task type...")
        task_type = get_classification_result(user_question)
        print(f"  └─ Classified as: {task_type}")
        
        # 질문과 관련된 XML 청크들을 지능적으로 선택
        print("\n[STEP 2/3] Selecting relevant XML chunks...")
        
        if NON_RAG_USE_EMBEDDING:
            try:
                relevant_xml = self._select_relevant_chunks_with_embedding(user_question, max_tokens=15000)
                print(f"  └─ Using embedding-based selection")
            except Exception as e:
                print(f"[WARNING] Embedding-based selection failed: {e}")
                print(f"  └─ Falling back to keyword-based selection")
                relevant_xml = self._fallback_keyword_selection(user_question, max_tokens=15000)
        else:
            print(f"  └─ Using keyword-based selection (embedding disabled)")
            relevant_xml = self._fallback_keyword_selection(user_question, max_tokens=15000)
        
        # LLM으로 최종 답변 생성
        print("\n[STEP 3/3] Generating answer with selected XML chunks...")
        
        if task_type == "Simple Lookup Tasks":
            prompt_template = f"""
            You are a network engineering expert analyzing pre-selected relevant XML configuration chunks.

            RELEVANT XML Configuration Data (intelligently selected for this question):
            {relevant_xml}

            User Question: {user_question}

            CRITICAL GROUND_TRUTH FORMATTING RULES:
            1. **Single Value Questions**: Return ONLY the exact value
               - IP addresses: "192.168.1.1" (no labels)
               - Device names: "CE1" or "sample7" (exact name only)
               - Port numbers: "22" or "443" (number only)
               - Boolean answers: "Yes" or "No"
               
            2. **Multiple Value Questions**: Use comma-separated format
               - Device lists: "CE1, CE2, sample10"
               - IP ranges: "192.168.1.1, 192.168.1.2"
               - Port lists: "22, 80, 443"
               
            3. **Configuration Values**: Return exact configuration strings
               - Interface names: "GigabitEthernet0/0"
               - Protocol names: "OSPF" or "BGP"
               - VLAN IDs: "100" or "200"

            OUTPUT FORMAT:
            [GROUND_TRUTH]
            {{EXACT_VALUE_ONLY}}

            [EXPLANATION]
            {{상세한 기술적 설명을 한국어로 제공}}

            STRICT RULES:
            - Ground Truth: NO extra words, labels, or formatting
            - Explanation: Comprehensive Korean explanation
            - Be extremely precise with values
            - Match the exact format expected in evaluation
            """
        else:
            prompt_template = f"""
            You are a network engineering expert analyzing pre-selected relevant XML configuration chunks.

            RELEVANT XML Configuration Data (intelligently selected for this question):
            {relevant_xml}

            User Question: {user_question}

            INSTRUCTIONS:
            - Analyze the provided XML chunks thoroughly
            - Extract exact technical values for ground truth
            - Provide comprehensive technical explanation in Korean
            - Use specific device names, IPs, configurations from the XML data

            OUTPUT FORMAT:
            [GROUND_TRUTH]
            {{정확한 기술적 값만}}

            [EXPLANATION]
            {{상세한 한국어 기술 설명}}
            1. 직접적 답변: 질문에 대한 명확한 해답 제시
            2. 기술적 구현: 구체적인 설정 단계나 명령어 제공
            3. 고려사항: 중요한 요소나 모범 사례 언급
            """
        
        response = tracked_openai_client.chat_completions_create(
            call_type="improved_non_rag_answer",
            model=LLM_MODEL,
            messages=[
                {"role": "system", "content": chatgpt_system_prompt},
                {"role": "user", "content": prompt_template}
            ],
            temperature=0.1
        )
        
        final_answer = response.choices[0].message.content.strip()
        processing_time = round(time.time() - start_time, 2)
        
        print(f"\n{'='*70}")
        print(f"IMPROVED NON-RAG PIPELINE COMPLETE")
        print(f"  - Total time: {processing_time}s")
        print(f"  - Task type: {task_type}")
        print(f"  - XML chunks analyzed: {len(relevant_xml.split('===')) - 1}")
        print(f"{'='*70}\n")
        
        return {
            "question": user_question,
            "task_type": task_type,
            "final_answer": final_answer,
            "processing_time": processing_time,
            "method": "improved_non_rag_with_chunking",
            "xml_chunks_used": len(relevant_xml.split("===")) - 1
        }


def parse_answer_sections(answer: str) -> Tuple[str, str]:
    """답변에서 ground_truth와 explanation 섹션을 분리"""
    ground_truth = ""
    explanation = ""
    
    # [GROUND_TRUTH]와 [EXPLANATION] 섹션 찾기
    gt_match = re.search(r'\[GROUND_TRUTH\](.*?)(?:\[EXPLANATION\]|$)', answer, re.DOTALL | re.IGNORECASE)
    exp_match = re.search(r'\[EXPLANATION\](.*?)$', answer, re.DOTALL | re.IGNORECASE)
    
    if gt_match:
        ground_truth = gt_match.group(1).strip()
    
    if exp_match:
        explanation = exp_match.group(1).strip()
    
    # 섹션이 없으면 전체 답변을 explanation으로 사용
    if not ground_truth and not explanation:
        explanation = answer.strip()
        # 간단한 답변인 경우 ground_truth로도 사용
        if len(answer.strip().split()) <= 10:
            ground_truth = answer.strip()
    
    return ground_truth, explanation

def evaluate_predictions(predictions: List[Dict], test_data: pd.DataFrame) -> Dict:
    """예측 결과를 평가 - origin에 따라 다른 평가 적용"""
    print("\n" + "="*70)
    print("EVALUATION RESULTS")
    print("="*70)
    
    # 전체 데이터 준비
    pred_ground_truths = []
    pred_explanations = []
    gt_ground_truths = test_data['ground_truth'].tolist()
    gt_explanations = test_data['explanation'].tolist()
    
    # origin 컬럼이 있으면 사용, 없으면 빈 리스트로 처리
    if 'origin' in test_data.columns:
        origins = test_data['origin'].tolist()
    else:
        print("[INFO] No 'origin' column found. Treating all as general evaluation.")
        origins = ['general'] * len(predictions)
    
    for pred in predictions:
        gt, exp = parse_answer_sections(pred['final_answer'])
        pred_ground_truths.append(gt)
        pred_explanations.append(exp)
    
    # Origin별 데이터 분리
    if 'origin' in test_data.columns:
        rule_based_indices = [i for i, origin in enumerate(origins) if origin == 'rule-based']
        enhanced_llm_indices = [i for i, origin in enumerate(origins) if origin == 'enhanced_llm_with_agent']
    else:
        # origin 컬럼이 없으면 모든 데이터를 general로 처리
        rule_based_indices = []
        enhanced_llm_indices = []
        general_indices = list(range(len(predictions)))
    
    print(f"\n[DATA DISTRIBUTION]")
    if 'origin' in test_data.columns:
        print(f"  - Rule-based questions: {len(rule_based_indices)}")
        print(f"  - Enhanced LLM questions: {len(enhanced_llm_indices)}")
    else:
        print(f"  - General questions: {len(predictions)}")
    print(f"  - Total questions: {len(predictions)}")
    
    # 전체 Ground Truth 평가 (EM, F1)
    print("\n[OVERALL GROUND_TRUTH EVALUATION]")
    gt_em_overall = calculate_exact_match(pred_ground_truths, gt_ground_truths)
    gt_f1_overall = calculate_f1_score(pred_ground_truths, gt_ground_truths)
    
    print(f"  - Overall Exact Match: {gt_em_overall:.4f}")
    print(f"  - Overall F1 Score: {gt_f1_overall:.4f}")
    
    # Rule-based만 Ground Truth 평가
    if rule_based_indices:
        print("\n[RULE-BASED GROUND_TRUTH EVALUATION]")
        rule_pred_gt = [pred_ground_truths[i] for i in rule_based_indices]
        rule_true_gt = [gt_ground_truths[i] for i in rule_based_indices]
        
        rule_gt_em = calculate_exact_match(rule_pred_gt, rule_true_gt)
        rule_gt_f1 = calculate_f1_score(rule_pred_gt, rule_true_gt)
        
        print(f"  - Rule-based Exact Match: {rule_gt_em:.4f}")
        print(f"  - Rule-based F1 Score: {rule_gt_f1:.4f}")
    else:
        rule_gt_em = rule_gt_f1 = 0.0
        print("\n[WARNING] No rule-based questions found!")
    
    # Enhanced LLM Ground Truth + Explanation 평가
    explanation_results = {}
    if enhanced_llm_indices:
        print("\n[ENHANCED_LLM GROUND_TRUTH EVALUATION]")
        enhanced_pred_gt = [pred_ground_truths[i] for i in enhanced_llm_indices]
        enhanced_true_gt = [gt_ground_truths[i] for i in enhanced_llm_indices]
        
        enhanced_gt_em = calculate_exact_match(enhanced_pred_gt, enhanced_true_gt)
        enhanced_gt_f1 = calculate_f1_score(enhanced_pred_gt, enhanced_true_gt)
        
        print(f"  - Enhanced LLM Exact Match: {enhanced_gt_em:.4f}")
        print(f"  - Enhanced LLM F1 Score: {enhanced_gt_f1:.4f}")
        
        # Enhanced LLM Explanation 평가
        print("\n[ENHANCED_LLM EXPLANATION EVALUATION]")
        enhanced_pred_exp = [pred_explanations[i] for i in enhanced_llm_indices]
        enhanced_true_exp = [gt_explanations[i] for i in enhanced_llm_indices]
        
        # explanation이 비어있지 않은 경우만 평가
        valid_exp_indices = [i for i, exp in enumerate(enhanced_true_exp) if exp and str(exp).strip()]
        
        if valid_exp_indices:
            valid_pred_exp = [enhanced_pred_exp[i] for i in valid_exp_indices]
            valid_true_exp = [enhanced_true_exp[i] for i in valid_exp_indices]
            
            bert_scores = calculate_bert_score(valid_pred_exp, valid_true_exp)
            rouge_scores = calculate_rouge_scores(valid_pred_exp, valid_true_exp)
            
            print(f"  - BERT F1: {bert_scores['f1']:.4f}")
            print(f"  - ROUGE-1 F1: {rouge_scores['rouge-1']:.4f}")
            print(f"  - ROUGE-2 F1: {rouge_scores['rouge-2']:.4f}")
            print(f"  - ROUGE-L F1: {rouge_scores['rouge-l']:.4f}")
            print(f"  - Valid explanations evaluated: {len(valid_exp_indices)}/{len(enhanced_llm_indices)}")
            
            explanation_results = {
                "bert_f1": bert_scores['f1'],
                "bert_precision": bert_scores['precision'],
                "bert_recall": bert_scores['recall'],
                "rouge_1_f1": rouge_scores['rouge-1'],
                "rouge_2_f1": rouge_scores['rouge-2'],
                "rouge_l_f1": rouge_scores['rouge-l'],
                "valid_count": len(valid_exp_indices),
                "total_count": len(enhanced_llm_indices)
            }
        else:
            print("  - No valid explanations found for evaluation")
            explanation_results = {
                "bert_f1": 0.0, "bert_precision": 0.0, "bert_recall": 0.0,
                "rouge_1_f1": 0.0, "rouge_2_f1": 0.0, "rouge_l_f1": 0.0,
                "valid_count": 0, "total_count": len(enhanced_llm_indices)
            }
            print("  - No valid explanations found for evaluation!")
            explanation_results = {
                "bert_f1": 0.0, "bert_precision": 0.0, "bert_recall": 0.0,
                "rouge_1_f1": 0.0, "rouge_2_f1": 0.0, "rouge_l_f1": 0.0,
                "valid_count": 0, "total_count": len(enhanced_llm_indices)
            }
    else:
        enhanced_gt_em = enhanced_gt_f1 = 0.0
        explanation_results = {
            "bert_f1": 0.0, "bert_precision": 0.0, "bert_recall": 0.0,
            "rouge_1_f1": 0.0, "rouge_2_f1": 0.0, "rouge_l_f1": 0.0,
            "valid_count": 0, "total_count": 0
        }
        print("\n[WARNING] No enhanced LLM questions found!")
    
    return {
        "overall": {
            "exact_match": gt_em_overall,
            "f1_score": gt_f1_overall,
            "total_questions": len(predictions)
        },
        "rule_based": {
            "exact_match": rule_gt_em,
            "f1_score": rule_gt_f1,
            "question_count": len(rule_based_indices)
        },
        "enhanced_llm": {
            "ground_truth": {
                "exact_match": enhanced_gt_em,
                "f1_score": enhanced_gt_f1
            },
            "explanation": explanation_results,
            "question_count": len(enhanced_llm_indices)
        }
    }
