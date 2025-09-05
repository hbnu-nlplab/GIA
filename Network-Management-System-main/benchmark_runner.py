"""
통합 벤치마크 실행 시스템
다양한 LLM 모델들을 통합 평가하는 메인 시스템
"""

import os
import json
import time
import pandas as pd
from typing import Dict, List, Any, Optional
from datetime import datetime
import argparse

# 로컬 모듈들
from llm_manager import LLMManager
from experiment_logger import ExperimentLogger, ExperimentResult, ExperimentVisualizer
from pipeline.pipeline_3_advanced import NetworkEngineeringPipeline

# 평가 메트릭
from bert_score import score as bert_score
from rouge_score import rouge_scorer
import re

class BenchmarkEvaluator:
    """벤치마크 평가 시스템"""
    
    def __init__(self):
        self.rouge_scorer = rouge_scorer.RougeScorer(['rougeL'], use_stemmer=True)
    
    def normalize_text(self, text: str) -> str:
        """텍스트 정규화"""
        text = re.sub(r'\s+', ' ', text.strip())
        return text.lower()
    
    def exact_match(self, prediction: str, ground_truth: str) -> float:
        """완전 일치 점수"""
        pred_norm = self.normalize_text(prediction)
        gt_norm = self.normalize_text(ground_truth)
        return 1.0 if pred_norm == gt_norm else 0.0
    
    def f1_score(self, prediction: str, ground_truth: str) -> float:
        """F1 점수 계산"""
        pred_tokens = set(self.normalize_text(prediction).split())
        gt_tokens = set(self.normalize_text(ground_truth).split())
        
        if not gt_tokens:
            return 1.0 if not pred_tokens else 0.0
        
        intersection = pred_tokens & gt_tokens
        if not intersection:
            return 0.0
        
        precision = len(intersection) / len(pred_tokens) if pred_tokens else 0.0
        recall = len(intersection) / len(gt_tokens)
        
        if precision + recall == 0:
            return 0.0
        
        return 2 * (precision * recall) / (precision + recall)
    
    def bert_score_single(self, prediction: str, ground_truth: str) -> float:
        """단일 BERT 점수 계산"""
        try:
            P, R, F1 = bert_score([prediction], [ground_truth], lang="en", verbose=False)
            return F1.item()
        except:
            return 0.0
    
    def rouge_l_score(self, prediction: str, ground_truth: str) -> float:
        """ROUGE-L 점수 계산"""
        try:
            scores = self.rouge_scorer.score(ground_truth, prediction)
            return scores['rougeL'].fmeasure
        except:
            return 0.0
    
    def evaluate_prediction(self, prediction: str, ground_truth: str) -> Dict[str, float]:
        """단일 예측에 대한 종합 평가"""
        return {
            'exact_match': self.exact_match(prediction, ground_truth),
            'f1_score': self.f1_score(prediction, ground_truth),
            'bert_score': self.bert_score_single(prediction, ground_truth),
            'rouge_l': self.rouge_l_score(prediction, ground_truth)
        }

class BenchmarkRunner:
    """벤치마크 실행기"""
    
    def __init__(self, config_file: str = "benchmark_config.json"):
        self.config_file = config_file
        self.config = self.load_config()
        
        # 컴포넌트 초기화
        self.llm_manager = LLMManager()
        self.logger = ExperimentLogger()
        self.evaluator = BenchmarkEvaluator()
        self.visualizer = ExperimentVisualizer(self.logger)
        
        # RAG 파이프라인 (필요시)
        self.rag_pipeline = None
        if self.config.get('use_rag', False):
            self.rag_pipeline = NetworkEngineeringPipeline(
                chromadb_path=self.config.get('chromadb_path', '/workspace/jke/chromadb_qwen'),
                collection_name=self.config.get('collection_name', 'network_devices'),
                max_iterations=self.config.get('max_iterations', 3)
            )
    
    def load_config(self) -> Dict[str, Any]:
        """설정 파일 로드"""
        if os.path.exists(self.config_file):
            with open(self.config_file, 'r') as f:
                return json.load(f)
        else:
            # 기본 설정 생성
            default_config = {
                "dataset_path": "dataset/test.csv",
                "models_to_test": ["gpt-4o-mini", "claude-3-haiku", "llama-3-8b", "qwen-2.5-7b"],
                "use_rag": True,
                "top_k_values": [1, 5, 10, 20, 50],
                "max_questions": 100,
                "chromadb_path": "/workspace/jke/chromadb_qwen",
                "collection_name": "network_devices",
                "max_iterations": 3,
                "output_dir": "benchmark_results"
            }
            
            with open(self.config_file, 'w') as f:
                json.dump(default_config, f, indent=2)
            
            return default_config
    
    def load_dataset(self) -> pd.DataFrame:
        """벤치마크 데이터셋 로드"""
        dataset_path = self.config['dataset_path']
        
        if not os.path.exists(dataset_path):
            raise FileNotFoundError(f"Dataset not found: {dataset_path}")
        
        df = pd.read_csv(dataset_path)
        
        # 필수 컬럼 확인
        required_columns = ['question', 'ground_truth']
        for col in required_columns:
            if col not in df.columns:
                raise ValueError(f"Missing required column: {col}")
        
        # 데이터 제한
        max_questions = self.config.get('max_questions', len(df))
        df = df.head(max_questions)
        
        return df
    
    def run_baseline_experiment(self, experiment_id: str, model_name: str, questions: List[str], ground_truths: List[str]):
        """Baseline 실험 (RAG 없음)"""
        print(f"\n🚀 Running Baseline Experiment: {model_name}")
        
        model = self.llm_manager.get_model(model_name)
        if not model or not model.is_available():
            print(f"❌ Model {model_name} not available")
            return
        
        results = []
        
        for i, (question, gt) in enumerate(zip(questions, ground_truths)):
            print(f"Processing {i+1}/{len(questions)}: {question[:50]}...")
            
            try:
                start_time = time.time()
                prediction = model.generate(question)
                end_time = time.time()
                
                # 평가
                metrics = self.evaluator.evaluate_prediction(prediction, gt)
                
                result = ExperimentResult(
                    experiment_id=experiment_id,
                    timestamp=datetime.now().isoformat(),
                    model_name=model_name,
                    question=question,
                    predicted_answer=prediction,
                    ground_truth=gt,
                    exact_match=metrics['exact_match'],
                    f1_score=metrics['f1_score'],
                    bert_score=metrics['bert_score'],
                    rouge_l=metrics['rouge_l'],
                    use_rag=False,
                    top_k=None,
                    temperature=model.config.temperature,
                    max_tokens=model.config.max_tokens,
                    response_time=end_time - start_time,
                    tokens_used=None,
                    cost_estimate=None,
                    retrieval_docs=None,
                    error_message=None,
                    success=True
                )
                
                self.logger.log_result(result)
                results.append(result)
                
            except Exception as e:
                print(f"❌ Error processing question {i+1}: {e}")
                
                error_result = ExperimentResult(
                    experiment_id=experiment_id,
                    timestamp=datetime.now().isoformat(),
                    model_name=model_name,
                    question=question,
                    predicted_answer="",
                    ground_truth=gt,
                    exact_match=0.0,
                    f1_score=0.0,
                    bert_score=0.0,
                    rouge_l=0.0,
                    use_rag=False,
                    top_k=None,
                    temperature=model.config.temperature,
                    max_tokens=model.config.max_tokens,
                    response_time=0.0,
                    tokens_used=None,
                    cost_estimate=None,
                    retrieval_docs=None,
                    error_message=str(e),
                    success=False
                )
                
                self.logger.log_result(error_result)
        
        print(f"✅ Baseline experiment completed: {len(results)} successful predictions")
        return results
    
    def run_rag_experiment(self, experiment_id: str, questions: List[str], ground_truths: List[str]):
        """RAG 실험"""
        if not self.rag_pipeline:
            print("❌ RAG pipeline not initialized")
            return
        
        print(f"\n🔍 Running RAG Experiment")
        
        for top_k in self.config['top_k_values']:
            print(f"\n📊 Testing Top-K = {top_k}")
            
            for i, (question, gt) in enumerate(zip(questions, ground_truths)):
                print(f"Processing {i+1}/{len(questions)}: {question[:50]}...")
                
                try:
                    start_time = time.time()
                    rag_result = self.rag_pipeline.process_query(question, top_k_chroma=top_k)
                    end_time = time.time()
                    
                    prediction = rag_result['final_answer']
                    
                    # 평가
                    metrics = self.evaluator.evaluate_prediction(prediction, gt)
                    
                    result = ExperimentResult(
                        experiment_id=experiment_id,
                        timestamp=datetime.now().isoformat(),
                        model_name="rag_pipeline",
                        question=question,
                        predicted_answer=prediction,
                        ground_truth=gt,
                        exact_match=metrics['exact_match'],
                        f1_score=metrics['f1_score'],
                        bert_score=metrics['bert_score'],
                        rouge_l=metrics['rouge_l'],
                        use_rag=True,
                        top_k=top_k,
                        temperature=0.1,
                        max_tokens=2000,
                        response_time=end_time - start_time,
                        tokens_used=None,
                        cost_estimate=None,
                        retrieval_docs=None,
                        error_message=None,
                        success=True
                    )
                    
                    self.logger.log_result(result)
                    
                except Exception as e:
                    print(f"❌ Error processing question {i+1}: {e}")
                    
                    error_result = ExperimentResult(
                        experiment_id=experiment_id,
                        timestamp=datetime.now().isoformat(),
                        model_name="rag_pipeline",
                        question=question,
                        predicted_answer="",
                        ground_truth=gt,
                        exact_match=0.0,
                        f1_score=0.0,
                        bert_score=0.0,
                        rouge_l=0.0,
                        use_rag=True,
                        top_k=top_k,
                        temperature=0.1,
                        max_tokens=2000,
                        response_time=0.0,
                        tokens_used=None,
                        cost_estimate=None,
                        retrieval_docs=None,
                        error_message=str(e),
                        success=False
                    )
                    
                    self.logger.log_result(error_result)
    
    def run_full_benchmark(self):
        """전체 벤치마크 실행"""
        experiment_id = f"benchmark_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        
        print(f"🎯 Starting Full Benchmark: {experiment_id}")
        
        # 데이터셋 로드
        df = self.load_dataset()
        questions = df['question'].tolist()
        ground_truths = df['ground_truth'].tolist()
        
        print(f"📊 Dataset loaded: {len(questions)} questions")
        
        # 실험 메타데이터 로깅
        self.logger.log_experiment_metadata(
            experiment_id=experiment_id,
            description="Full benchmark comparison of LLM models",
            config_file=self.config_file,
            dataset_path=self.config['dataset_path'],
            total_questions=len(questions)
        )
        
        # Baseline 실험들
        if self.config.get('run_baseline', True):
            for model_name in self.config['models_to_test']:
                if model_name in self.llm_manager.list_available_models():
                    self.run_baseline_experiment(experiment_id, model_name, questions, ground_truths)
                else:
                    print(f"⚠️ Model {model_name} not available for baseline")
        
        # RAG 실험
        if self.config.get('use_rag', False):
            self.run_rag_experiment(experiment_id, questions, ground_truths)
        
        # 실험 완료
        self.logger.update_experiment_status(experiment_id, "completed")
        
        # 결과 분석 및 시각화
        print("\n📈 Generating analysis and visualizations...")
        self.visualizer.plot_model_comparison(experiment_id)
        self.visualizer.plot_rag_impact()
        self.visualizer.plot_response_time_analysis()
        if self.config.get('use_rag', False):
            self.visualizer.plot_top_k_performance()
        
        # 리포트 생성
        report_path = self.visualizer.generate_experiment_report(experiment_id)
        
        print(f"\n🎉 Benchmark completed!")
        print(f"📋 Report: {report_path}")
        print(f"📊 Results: {self.logger.db_path}")
        
        return experiment_id

def main():
    parser = argparse.ArgumentParser(description='LLM Network Benchmark Runner')
    parser.add_argument('--config', default='benchmark_config.json', help='Config file path')
    parser.add_argument('--baseline-only', action='store_true', help='Run only baseline experiments')
    parser.add_argument('--rag-only', action='store_true', help='Run only RAG experiments')
    parser.add_argument('--models', nargs='+', help='Specific models to test')
    parser.add_argument('--max-questions', type=int, help='Maximum number of questions to test')
    
    args = parser.parse_args()
    
    # 벤치마크 러너 초기화
    runner = BenchmarkRunner(args.config)
    
    # 설정 오버라이드
    if args.baseline_only:
        runner.config['use_rag'] = False
    elif args.rag_only:
        runner.config['run_baseline'] = False
    
    if args.models:
        runner.config['models_to_test'] = args.models
    
    if args.max_questions:
        runner.config['max_questions'] = args.max_questions
    
    # 벤치마크 실행
    experiment_id = runner.run_full_benchmark()
    
    # 결과 요약
    summary = runner.logger.get_experiment_summary()
    print("\n📊 Final Results Summary:")
    print(summary.to_string(index=False))

if __name__ == "__main__":
    main()
