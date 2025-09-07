"""
Network LLM Benchmark Runner
다양한 LLM 모델의 네트워크 도메인 성능을 체계적으로 벤치마킹합니다.
"""

import os
import asyncio
import argparse
import json
import pandas as pd
from datetime import datetime
from typing import List, Dict, Any, Optional
import logging
from pathlib import Path

# 로컬 모듈
from enhanced_llm_manager import LLMManager, LLMResponse
from enhanced_experiment_logger import AdvancedExperimentLogger, ExperimentResult

# RAG 관련
import chromadb
from chromadb.config import Settings


class NetworkRAGSystem:
    """네트워크 도메인 특화 RAG 시스템"""
    
    def __init__(self, docs_path: str = "docs7_export", db_path: str = "chroma_network_db"):
        self.docs_path = docs_path
        self.db_path = db_path
        self.client = None
        self.collection = None
        self.setup_database()
    
    def setup_database(self):
        """ChromaDB 초기화"""
        try:
            self.client = chromadb.PersistentClient(path=self.db_path)
            
            # 기존 컬렉션 가져오기 또는 새로 생성
            try:
                self.collection = self.client.get_collection("network_docs")
                print(f"기존 네트워크 문서 컬렉션 로드: {self.collection.count()}개 문서")
            except:
                self.collection = self.client.create_collection("network_docs")
                self._load_documents()
                print(f"새 네트워크 문서 컬렉션 생성: {self.collection.count()}개 문서")
                
        except Exception as e:
            print(f"RAG 시스템 초기화 실패: {e}")
            self.collection = None
    
    def _load_documents(self):
        """문서 로딩 및 벡터화"""
        if not os.path.exists(self.docs_path):
            print(f"문서 경로를 찾을 수 없습니다: {self.docs_path}")
            return
        
        documents = []
        metadatas = []
        ids = []
        
        # 문서 파일들 읽기
        for root, dirs, files in os.walk(self.docs_path):
            for file in files:
                if file.endswith(('.txt', '.md', '.xml')):
                    file_path = os.path.join(root, file)
                    try:
                        with open(file_path, 'r', encoding='utf-8') as f:
                            content = f.read()
                            
                        documents.append(content)
                        metadatas.append({
                            'filename': file,
                            'filepath': file_path,
                            'type': file.split('.')[-1]
                        })
                        ids.append(f"doc_{len(documents)}")
                        
                    except Exception as e:
                        print(f"파일 읽기 실패 {file_path}: {e}")
        
        if documents:
            # 청크 단위로 나누어서 저장
            chunk_size = 100
            for i in range(0, len(documents), chunk_size):
                chunk_docs = documents[i:i+chunk_size]
                chunk_metas = metadatas[i:i+chunk_size]
                chunk_ids = ids[i:i+chunk_size]
                
                self.collection.add(
                    documents=chunk_docs,
                    metadatas=chunk_metas,
                    ids=chunk_ids
                )
    
    def retrieve_context(self, query: str, top_k: int = 5) -> List[str]:
        """질의에 관련된 컨텍스트 검색"""
        if not self.collection:
            return []
        
        try:
            results = self.collection.query(
                query_texts=[query],
                n_results=top_k
            )
            
            contexts = []
            if results['documents'] and results['documents'][0]:
                for doc, metadata in zip(results['documents'][0], results['metadatas'][0]):
                    context = f"[{metadata['filename']}]\n{doc[:500]}..."
                    contexts.append(context)
            
            return contexts
            
        except Exception as e:
            print(f"컨텍스트 검색 실패: {e}")
            return []


class NetworkBenchmarkRunner:
    """네트워크 LLM 벤치마크 실행기"""
    
    def __init__(self, config_path: str = "benchmark_config.json"):
        self.config = self._load_config(config_path)
        self.llm_manager = LLMManager(self.config.get('llm_config_path', 'llm_configs.json'))
        self.logger = AdvancedExperimentLogger(
            db_path=self.config.get('db_path', 'benchmark_experiments.db')
        )
        self.rag_system = None
        
        # RAG 시스템 초기화 (설정에 따라)
        if self.config.get('enable_rag', True):
            self.rag_system = NetworkRAGSystem(
                docs_path=self.config.get('docs_path', 'docs7_export')
            )
    
    def _load_config(self, config_path: str) -> Dict[str, Any]:
        """설정 파일 로드"""
        try:
            with open(config_path, 'r', encoding='utf-8') as f:
                existing_config = json.load(f)
            
            # 기존 설정을 새로운 형식으로 변환
            if "experiments" not in existing_config:
                # 기존 형식을 새로운 형식으로 변환
                converted_config = {
                    "llm_config_path": "enhanced_llm_configs.json",
                    "dataset_path": existing_config.get("dataset_path", "dataset/test_fin.csv"),
                    "docs_path": "docs7_export",
                    "db_path": "benchmark_experiments.db",
                    "enable_rag": existing_config.get("use_rag", True),
                    "max_concurrent": 3,
                    "system_prompt": """당신은 네트워크 엔지니어링 전문가입니다. 
네트워크 설정, BGP, OSPF, VLAN, 보안 등에 대한 정확하고 기술적인 답변을 제공해주세요.
제공된 문서나 컨텍스트가 있다면 이를 참고하여 답변하세요.""",
                    "experiments": {
                        "baseline": {
                            "description": "RAG 없이 순수 LLM 성능 측정",
                            "use_rag": False,
                            "max_iterations": 1
                        },
                        "rag": {
                            "description": "RAG 기반 성능 측정",
                            "use_rag": True,
                            "max_iterations": 1,
                            "top_k_contexts": existing_config.get("top_k_values", [5])[0] if isinstance(existing_config.get("top_k_values"), list) else 5
                        },
                        "rag_iterative": {
                            "description": "RAG + 반복 개선",
                            "use_rag": True,
                            "max_iterations": existing_config.get("max_iterations", 3),
                            "top_k_contexts": existing_config.get("top_k_values", [5])[0] if isinstance(existing_config.get("top_k_values"), list) else 5
                        }
                    }
                }
                
                # 변환된 설정을 파일에 저장
                with open(config_path, 'w', encoding='utf-8') as f:
                    json.dump(converted_config, f, indent=2, ensure_ascii=False)
                
                print(f"기존 설정 파일을 새로운 형식으로 변환: {config_path}")
                return converted_config
            else:
                return existing_config
                
        except FileNotFoundError:
            # 기본 설정 생성
            default_config = {
                "llm_config_path": "enhanced_llm_configs.json",
                "dataset_path": "dataset/test_fin.csv",
                "docs_path": "docs7_export",
                "db_path": "benchmark_experiments.db",
                "enable_rag": True,
                "max_concurrent": 3,
                "system_prompt": """당신은 네트워크 엔지니어링 전문가입니다. 
네트워크 설정, BGP, OSPF, VLAN, 보안 등에 대한 정확하고 기술적인 답변을 제공해주세요.
제공된 문서나 컨텍스트가 있다면 이를 참고하여 답변하세요.""",
                "experiments": {
                    "baseline": {
                        "description": "RAG 없이 순수 LLM 성능 측정",
                        "use_rag": False,
                        "max_iterations": 1
                    },
                    "rag": {
                        "description": "RAG 기반 성능 측정",
                        "use_rag": True,
                        "max_iterations": 1,
                        "top_k_contexts": 5
                    },
                    "rag_iterative": {
                        "description": "RAG + 반복 개선",
                        "use_rag": True,
                        "max_iterations": 3,
                        "top_k_contexts": 5
                    }
                }
            }
            
            with open(config_path, 'w', encoding='utf-8') as f:
                json.dump(default_config, f, indent=2, ensure_ascii=False)
            
            print(f"기본 설정 파일 생성: {config_path}")
            return default_config
    
    def load_dataset(self) -> pd.DataFrame:
        """벤치마크 데이터셋 로드"""
        dataset_path = self.config.get('dataset_path', 'dataset/test.csv')
        
        try:
            df = pd.read_csv(dataset_path, encoding='utf-8')
            print(f"데이터셋 로드 완료: {len(df)}개 질문")
            return df
        except Exception as e:
            print(f"데이터셋 로드 실패: {e}")
            return pd.DataFrame()
    
    async def run_single_experiment(
        self,
        experiment_name: str,
        model_ids: List[str],
        sample_size: Optional[int] = None
    ) -> str:
        """단일 실험 실행"""
        
        # 실험 설정
        exp_config = self.config['experiments'].get(experiment_name)
        if not exp_config:
            raise ValueError(f"알 수 없는 실험: {experiment_name}")
        
        # 데이터셋 로드
        dataset = self.load_dataset()
        if dataset.empty:
            raise ValueError("데이터셋을 로드할 수 없습니다.")
        
        # 샘플링
        if sample_size and sample_size < len(dataset):
            dataset = dataset.sample(n=sample_size, random_state=42)
            print(f"데이터셋 샘플링: {sample_size}개 질문")
        
        # 실험 ID 생성
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        if sample_size:
            experiment_id = f"{experiment_name}_sample_{sample_size}_{timestamp}"
        else:
            experiment_id = f"{experiment_name}_{timestamp}"
        
        # 실험 시작 로깅
        self.logger.log_experiment_start(
            experiment_id,
            exp_config['description'],
            {
                'experiment_name': experiment_name,
                'models': model_ids,
                'sample_size': len(dataset),
                'config': exp_config
            }
        )
        
        # 모델별 실행
        for model_id in model_ids:
            print(f"\n=== {model_id} 모델 실행 중... ===")
            
            await self._run_model_on_dataset(
                experiment_id,
                model_id,
                dataset,
                exp_config
            )
            
            # 메트릭 계산 및 저장
            try:
                metrics = self.logger.calculate_metrics(experiment_id, model_id)
                print(f"{model_id} 메트릭:")
                print(f"  - Exact Match: {metrics.exact_match:.3f}")
                print(f"  - BERT F1: {metrics.bert_f1:.3f}")
                print(f"  - ROUGE-L F1: {metrics.rougeL_f1:.3f}")
                print(f"  - 평균 지연시간: {metrics.average_latency:.2f}초")
                print(f"  - 총 비용: ${metrics.total_cost:.6f}")
            except Exception as e:
                print(f"메트릭 계산 실패: {e}")
        
        # 실험 종료
        self.logger.log_experiment_end(experiment_id)
        print(f"\n실험 완료: {experiment_id}")
        
        return experiment_id
    
    async def _run_model_on_dataset(
        self,
        experiment_id: str,
        model_id: str,
        dataset: pd.DataFrame,
        exp_config: Dict[str, Any]
    ):
        """특정 모델로 데이터셋 전체 실행"""
        
        # 동시 실행 제한
        semaphore = asyncio.Semaphore(self.config.get('max_concurrent', 3))
        
        async def process_question(row):
            async with semaphore:
                return await self._process_single_question(
                    experiment_id, model_id, row, exp_config
                )
        
        # 모든 질문을 비동기로 처리
        tasks = [process_question(row) for _, row in dataset.iterrows()]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # 결과 로깅
        successful = sum(1 for r in results if not isinstance(r, Exception))
        failed = len(results) - successful
        
        print(f"{model_id}: {successful}개 성공, {failed}개 실패")
    
    async def _process_single_question(
        self,
        experiment_id: str,
        model_id: str,
        question_row: pd.Series,
        exp_config: Dict[str, Any]
    ) -> Optional[ExperimentResult]:
        """단일 질문 처리"""
        
        question = question_row['question']
        ground_truth = question_row['ground_truth']
        question_id = str(question_row.name)
        
        try:
            # 시스템 프롬프트
            system_prompt = self.config.get('system_prompt', '')
            
            # RAG 컨텍스트 추가
            if exp_config.get('use_rag', False) and self.rag_system:
                contexts = self.rag_system.retrieve_context(
                    question, 
                    top_k=exp_config.get('top_k_contexts', 5)
                )
                
                if contexts:
                    context_text = "\n\n".join(contexts)
                    system_prompt += f"\n\n참고 문서:\n{context_text}"
            
            # LLM 실행
            response = await self.llm_manager.generate(
                model_id, 
                question, 
                system_prompt
            )
            
            # 반복 개선 (설정에 따라)
            max_iterations = exp_config.get('max_iterations', 1)
            if max_iterations > 1:
                response = await self._iterative_improvement(
                    model_id, question, response, max_iterations
                )
            
            # 결과 생성
            result = ExperimentResult(
                experiment_id=experiment_id,
                model_id=model_id,
                question_id=question_id,
                question=question,
                ground_truth=ground_truth,
                prediction=response.content,
                input_tokens=response.input_tokens,
                output_tokens=response.output_tokens,
                latency=response.latency,
                cost=response.cost,
                timestamp=datetime.now().isoformat(),
                metadata={
                    'experiment_config': exp_config,
                    'response_metadata': response.metadata
                }
            )
            
            # 로깅
            self.logger.log_result(result)
            
            return result
            
        except Exception as e:
            print(f"질문 처리 실패 {question_id}: {e}")
            return None
    
    async def _iterative_improvement(
        self,
        model_id: str,
        original_question: str,
        initial_response: LLMResponse,
        max_iterations: int
    ) -> LLMResponse:
        """반복적 답변 개선"""
        
        current_response = initial_response
        
        for iteration in range(1, max_iterations):
            improvement_prompt = f"""
이전 답변을 검토하고 개선해주세요.

원래 질문: {original_question}

이전 답변: {current_response.content}

더 정확하고 상세한 답변을 제공해주세요. 특히 네트워크 기술적 측면에서 누락된 부분이 있다면 보완해주세요.
"""
            
            try:
                improved_response = await self.llm_manager.generate(
                    model_id, 
                    improvement_prompt
                )
                
                # 토큰 및 비용 누적
                improved_response.input_tokens += current_response.input_tokens
                improved_response.output_tokens += current_response.output_tokens
                improved_response.latency += current_response.latency
                improved_response.cost += current_response.cost
                
                current_response = improved_response
                
            except Exception as e:
                print(f"반복 개선 실패 (iteration {iteration}): {e}")
                break
        
        return current_response
    
    async def run_batch_experiments(
        self,
        experiment_names: List[str],
        model_ids: List[str],
        sample_sizes: Optional[List[int]] = None
    ) -> List[str]:
        """배치 실험 실행"""
        
        experiment_ids = []
        
        for exp_name in experiment_names:
            print(f"\n{'='*50}")
            print(f"실험 시작: {exp_name}")
            print(f"{'='*50}")
            
            if sample_sizes:
                for sample_size in sample_sizes:
                    exp_id = await self.run_single_experiment(
                        exp_name,
                        model_ids,
                        sample_size
                    )
                    experiment_ids.append(exp_id)
            else:
                exp_id = await self.run_single_experiment(
                    exp_name,
                    model_ids
                )
                experiment_ids.append(exp_id)
        
        return experiment_ids
    
    def generate_report(self, experiment_ids: List[str], output_dir: str = "reports"):
        """실험 결과 리포트 생성"""
        print(f"\n리포트 생성 중... (출력 디렉토리: {output_dir})")
        
        # 디렉토리 생성
        os.makedirs(output_dir, exist_ok=True)
        
        # 비교 리포트 생성
        self.logger.generate_comparison_report(experiment_ids, output_dir)
        
        # 개별 실험 요약
        for exp_id in experiment_ids:
            summary = self.logger.get_experiment_summary(exp_id)
            
            with open(f"{output_dir}/experiment_{exp_id}_summary.json", 'w', encoding='utf-8') as f:
                json.dump(summary, f, indent=2, ensure_ascii=False)
        
        print(f"리포트 생성 완료: {output_dir}")


def main():
    """메인 실행 함수"""
    parser = argparse.ArgumentParser(description='Network LLM Benchmark Runner')
    
    parser.add_argument(
        '--models', 
        type=str, 
        default='gpt-4,claude-3-sonnet',
        help='테스트할 모델들 (쉼표로 구분)'
    )
    
    parser.add_argument(
        '--experiments', 
        type=str,
        default='baseline,rag',
        help='실행할 실험들 (쉼표로 구분)'
    )
    
    parser.add_argument(
        '--sample-sizes',
        type=str,
        default=None,
        help='샘플 크기들 (쉼표로 구분, 예: 10,50,100)'
    )
    
    parser.add_argument(
        '--config',
        type=str,
        default='benchmark_config.json',
        help='설정 파일 경로'
    )
    
    parser.add_argument(
        '--output-dir',
        type=str,
        default='reports',
        help='리포트 출력 디렉토리'
    )
    
    parser.add_argument(
        '--generate-report-only',
        action='store_true',
        help='실험 실행 없이 기존 결과로만 리포트 생성'
    )
    
    args = parser.parse_args()
    
    # 인자 파싱
    model_ids = [m.strip() for m in args.models.split(',')]
    experiment_names = [e.strip() for e in args.experiments.split(',')]
    sample_sizes = None
    if args.sample_sizes:
        sample_sizes = [int(s.strip()) for s in args.sample_sizes.split(',')]
    
    print("Network LLM Benchmark Runner")
    print(f"모델들: {model_ids}")
    print(f"실험들: {experiment_names}")
    if sample_sizes:
        print(f"샘플 크기들: {sample_sizes}")
    
    async def run_benchmark():
        # 벤치마크 러너 초기화
        runner = NetworkBenchmarkRunner(args.config)
        
        if args.generate_report_only:
            # 기존 실험 ID들을 찾아서 리포트만 생성
            # (실제 구현에서는 데이터베이스에서 최근 실험들을 조회)
            print("기존 실험 결과로 리포트 생성 중...")
            runner.generate_report([], args.output_dir)
        else:
            # 실험 실행
            experiment_ids = await runner.run_batch_experiments(
                experiment_names,
                model_ids,
                sample_sizes
            )
            
            # 리포트 생성
            runner.generate_report(experiment_ids, args.output_dir)
            
            print(f"\n모든 실험 완료!")
            print(f"실험 ID들: {experiment_ids}")
            print(f"리포트 위치: {args.output_dir}")
    
    # 실행
    asyncio.run(run_benchmark())


if __name__ == "__main__":
    main()
