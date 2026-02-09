"""
NetConfigQA2.csv 데이터셋 어댑터
"""
import csv
import json
from pathlib import Path
from typing import List, Dict, Any, Optional
from dataclasses import dataclass


@dataclass
class Question:
    """질문 데이터 클래스"""
    question_id: str
    question: str
    answer: str
    answer_type: str
    answer_status: str
    level: str
    category: str
    evidence: Optional[str] = None


class NetConfigQA2Adapter:
    """NetConfigQA2.csv 데이터셋 로더
    
    CSV 형식의 NetConfigQA2.0 데이터셋을 로드하고
    에이전트 평가용 포맷으로 변환합니다.
    """
    
    def __init__(self, dataset_path: str):
        """
        Args:
            dataset_path: NetConfigQA2.csv 파일 경로
        """
        self.dataset_path = Path(dataset_path)
        self.questions: List[Question] = []
        self._load()
    
    def _load(self):
        """CSV 파일 로드"""
        if not self.dataset_path.exists():
            raise FileNotFoundError(f"Dataset not found: {self.dataset_path}")
        
        with open(self.dataset_path, 'r', encoding='utf-8') as f:
            reader = csv.DictReader(f)
            for row in reader:
                q = Question(
                    question_id=row.get('question_id', row.get('id', '')),
                    question=row['question'],
                    answer=row['answer'],
                    answer_type=row.get('answer_type', 'text'),
                    answer_status=row.get('answer_status', 'OK'),
                    level=row.get('level', 'L1'),
                    category=row.get('category', 'General'),
                    evidence=row.get('evidence'),
                )
                self.questions.append(q)
        
        print(f"Loaded {len(self.questions)} questions from {self.dataset_path}")
    
    def get_all(self) -> List[Question]:
        """전체 질문 반환"""
        return self.questions
    
    def get_by_level(self, level: str) -> List[Question]:
        """레벨별 질문 반환"""
        return [q for q in self.questions if q.level == level]
    
    def get_by_category(self, category: str) -> List[Question]:
        """카테고리별 질문 반환"""
        return [q for q in self.questions if q.category == category]
    
    def get_by_answer_type(self, answer_type: str) -> List[Question]:
        """답변 타입별 질문 반환"""
        return [q for q in self.questions if q.answer_type == answer_type]
    
    def get_stratified_sample(
        self,
        n: int,
        by: str = "level",
    ) -> List[Question]:
        """층화 샘플링
        
        Args:
            n: 총 샘플 수
            by: 층화 기준 ("level" 또는 "answer_type")
            
        Returns:
            샘플링된 질문 목록
        """
        import random
        from collections import defaultdict
        
        # 그룹별 분류
        groups = defaultdict(list)
        for q in self.questions:
            key = getattr(q, by)
            groups[key].append(q)
        
        # 각 그룹에서 균등 샘플링
        n_per_group = max(1, n // len(groups))
        samples = []
        
        for key in sorted(groups.keys()):
            qs = groups[key]
            if len(qs) <= n_per_group:
                samples.extend(qs)
            else:
                samples.extend(random.sample(qs, n_per_group))
        
        import random
        random.shuffle(samples)
        return samples[:n]
    
    def to_eval_format(self, questions: List[Question] = None) -> List[Dict[str, Any]]:
        """평가용 포맷으로 변환"""
        if questions is None:
            questions = self.questions
        
        return [
            {
                "question_id": q.question_id,
                "question": q.question,
                "answer_type": q.answer_type,
                "gold": q.answer,
                "level": q.level,
                "category": q.category,
            }
            for q in questions
        ]
    
    def summary(self) -> Dict[str, Any]:
        """데이터셋 요약"""
        from collections import Counter
        
        return {
            "total": len(self.questions),
            "by_level": dict(Counter(q.level for q in self.questions)),
            "by_answer_type": dict(Counter(q.answer_type for q in self.questions)),
            "by_category": dict(Counter(q.category for q in self.questions)),
            "by_status": dict(Counter(q.answer_status for q in self.questions)),
        }


if __name__ == "__main__":
    # 테스트
    import os
    
    # 데이터셋 경로 (예시)
    dataset_path = os.path.join(
        os.path.dirname(__file__), 
        "../../Data/Dataset/NetConfigQA2.csv"
    )
    
    if os.path.exists(dataset_path):
        adapter = NetConfigQA2Adapter(dataset_path)
        print(json.dumps(adapter.summary(), indent=2))
    else:
        print(f"Dataset not found: {dataset_path}")
