"""
평가 실행기
NIKA run_benchmark.py 참고
"""
import os
import json
import asyncio
import datetime
from typing import List, Dict, Any, Optional
from dataclasses import dataclass, asdict
from pathlib import Path

from agent.graph import create_graph, run_single_question
from eval.dataset_adapter import NetConfigQA2Adapter, Question
from eval.scorer import TypeAwareScorer


@dataclass
class EvalMetrics:
    """평가 메트릭"""
    question_id: str
    is_correct: bool
    latency_seconds: float
    step_count: int
    tool_calls: int
    token_count: int
    error: Optional[str] = None


class EvaluationRunner:
    """NetConfigQA2.0 평가 실행기"""
    
    def __init__(
        self,
        backend: str = "openai",
        model: str = None,
        output_dir: str = "results",
    ):
        """
        Args:
            backend: LLM 백엔드 ("openai", "vllm", "ollama")
            model: 모델 이름
            output_dir: 결과 저장 디렉토리
        """
        self.backend = backend
        self.model = model or self._get_default_model(backend)
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
        self.graph = create_graph(backend=backend, model=model)
        self.scorer = TypeAwareScorer()
        
        print(f"Initialized runner with {backend}/{self.model}")
    
    def _get_default_model(self, backend: str) -> str:
        """백엔드별 기본 모델"""
        defaults = {
            "openai": "gpt-4o-mini",
            "vllm": "gpt-oss-20b",
            "ollama": "qwen2.5:32b",
        }
        return defaults.get(backend, "gpt-4o-mini")
    
    async def run_single(self, question: Question) -> Dict[str, Any]:
        """단일 질문 평가
        
        Args:
            question: Question 객체
            
        Returns:
            평가 결과 딕셔너리
        """
        import time
        
        start_time = time.time()
        error = None
        pred = ""
        step_count = 0
        tool_calls = 0
        
        try:
            # 에이전트 실행
            initial_state = {
                "messages": [],
                "question": question.question,
                "answer_type": question.answer_type,
                "tool_calls": [],
                "tool_results": [],
                "evidence": "",
                "reasoning": "",
                "final_answer": "",
                "is_complete": False,
                "needs_more_info": False,
                "step_count": 0,
                "token_count": 0,
            }
            
            result = await self.graph.ainvoke(initial_state)
            pred = result.get("final_answer", "")
            step_count = result.get("step_count", 0)
            
        except Exception as e:
            error = str(e)
            pred = ""
        
        latency = time.time() - start_time
        
        # 채점
        score_result = self.scorer.score(
            pred=pred,
            gold=question.answer,
            answer_type=question.answer_type,
        )
        
        return {
            "question_id": question.question_id,
            "question": question.question,
            "answer_type": question.answer_type,
            "level": question.level,
            "category": question.category,
            "gold": question.answer,
            "pred": pred,
            "is_correct": score_result["is_correct"],
            "latency_seconds": latency,
            "step_count": step_count,
            "error": error,
        }
    
    async def run_batch(
        self,
        questions: List[Question],
        progress_callback=None,
    ) -> List[Dict[str, Any]]:
        """배치 평가
        
        Args:
            questions: 질문 목록
            progress_callback: 진행 콜백 함수
            
        Returns:
            평가 결과 목록
        """
        results = []
        total = len(questions)
        
        for i, q in enumerate(questions, 1):
            result = await self.run_single(q)
            results.append(result)
            
            if progress_callback:
                progress_callback(i, total, result)
            else:
                status = "✓" if result["is_correct"] else "✗"
                print(f"[{i}/{total}] {status} Q:{q.question_id} ({q.level})")
        
        return results
    
    def compute_metrics(self, results: List[Dict[str, Any]]) -> Dict[str, Any]:
        """메트릭 계산
        
        Args:
            results: 평가 결과 목록
            
        Returns:
            집계 메트릭
        """
        from collections import defaultdict
        
        total = len(results)
        correct = sum(1 for r in results if r["is_correct"])
        
        # Overall
        overall = {
            "total": total,
            "correct": correct,
            "accuracy": correct / total if total > 0 else 0,
            "avg_latency": sum(r["latency_seconds"] for r in results) / total if total > 0 else 0,
        }
        
        # By Level
        by_level = defaultdict(lambda: {"total": 0, "correct": 0})
        for r in results:
            level = r.get("level", "L1")
            by_level[level]["total"] += 1
            if r["is_correct"]:
                by_level[level]["correct"] += 1
        
        for level, stats in by_level.items():
            stats["accuracy"] = stats["correct"] / stats["total"] if stats["total"] > 0 else 0
        
        # By Answer Type
        by_type = defaultdict(lambda: {"total": 0, "correct": 0})
        for r in results:
            at = r.get("answer_type", "text")
            by_type[at]["total"] += 1
            if r["is_correct"]:
                by_type[at]["correct"] += 1
        
        for at, stats in by_type.items():
            stats["accuracy"] = stats["correct"] / stats["total"] if stats["total"] > 0 else 0
        
        return {
            "overall": overall,
            "by_level": dict(by_level),
            "by_answer_type": dict(by_type),
        }
    
    def save_results(
        self,
        results: List[Dict[str, Any]],
        metrics: Dict[str, Any],
        suffix: str = "",
    ) -> str:
        """결과 저장
        
        Args:
            results: 평가 결과
            metrics: 집계 메트릭
            suffix: 파일명 접미사
            
        Returns:
            저장된 파일 경로
        """
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"results_{self.backend}_{self.model}_{timestamp}{suffix}.json"
        filepath = self.output_dir / filename
        
        output = {
            "meta": {
                "backend": self.backend,
                "model": self.model,
                "timestamp": timestamp,
                "total_samples": len(results),
            },
            "metrics": metrics,
            "results": results,
        }
        
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(output, f, indent=2, ensure_ascii=False)
        
        print(f"Results saved to {filepath}")
        return str(filepath)


async def run_evaluation(
    dataset_path: str,
    backend: str = "openai",
    model: str = None,
    sample_n: int = None,
    levels: List[str] = None,
):
    """평가 실행 메인 함수
    
    Args:
        dataset_path: NetConfigQA2.csv 경로
        backend: LLM 백엔드
        model: 모델 이름
        sample_n: 샘플 수 (None이면 전체)
        levels: 평가할 레벨 목록
    """
    # 데이터셋 로드
    adapter = NetConfigQA2Adapter(dataset_path)
    questions = adapter.get_all()
    
    # 필터링
    if levels:
        questions = [q for q in questions if q.level in levels]
    
    if sample_n and sample_n < len(questions):
        questions = adapter.get_stratified_sample(sample_n)
    
    print(f"Evaluating {len(questions)} questions")
    print(adapter.summary())
    
    # 실행
    runner = EvaluationRunner(backend=backend, model=model)
    results = await runner.run_batch(questions)
    
    # 메트릭 계산
    metrics = runner.compute_metrics(results)
    
    # 저장
    runner.save_results(results, metrics)
    
    # 결과 출력
    print("\n" + "="*50)
    print("Evaluation Results")
    print("="*50)
    print(f"Overall Accuracy: {metrics['overall']['accuracy']:.2%}")
    print(f"Average Latency: {metrics['overall']['avg_latency']:.2f}s")
    print("\nBy Level:")
    for level, stats in sorted(metrics['by_level'].items()):
        print(f"  {level}: {stats['accuracy']:.2%} ({stats['correct']}/{stats['total']})")
    print("\nBy Answer Type:")
    for at, stats in sorted(metrics['by_answer_type'].items()):
        print(f"  {at}: {stats['accuracy']:.2%} ({stats['correct']}/{stats['total']})")


if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="LabMate Evaluation Runner")
    parser.add_argument("--dataset", required=True, help="Path to NetConfigQA2.csv")
    parser.add_argument("--backend", default="openai", choices=["openai", "vllm", "ollama"])
    parser.add_argument("--model", default=None, help="Model name")
    parser.add_argument("--sample", type=int, default=None, help="Number of samples")
    parser.add_argument("--levels", nargs="+", default=None, help="Levels to evaluate (e.g., L1 L2)")
    
    args = parser.parse_args()
    
    asyncio.run(run_evaluation(
        dataset_path=args.dataset,
        backend=args.backend,
        model=args.model,
        sample_n=args.sample,
        levels=args.levels,
    ))
