"""
데이터셋 베이스 클래스
- 모든 데이터셋이 구현해야 하는 인터페이스 정의
- 공통 메트릭 계산 로직
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional, Tuple
import re
import numpy as np


@dataclass
class SamplingConfig:
    """vLLM SamplingParams 설정"""
    temperature: float = 0.0          # 결정적 생성
    top_p: float = 1.0
    max_tokens: int = 64
    stop: List[str] = field(default_factory=list)
    # Structured Output (JSON mode)
    use_structured_output: bool = False
    response_schema: Optional[Dict] = None
    

@dataclass
class DataItem:
    """정규화된 데이터 아이템"""
    id: str
    question: str
    context: str
    gold: str
    metadata: Dict[str, Any] = field(default_factory=dict)


class BaseDataset(ABC):
    """데이터셋 베이스 클래스"""
    
    # === 기본 속성 (서브클래스에서 오버라이드) ===
    name: str = "base"
    description: str = "Base dataset"
    
    # 대표 메트릭 (결과 요약 시 사용)
    primary_metric: str = "F1"
    
    # 샘플링 설정
    sampling_config: SamplingConfig = SamplingConfig()
    
    def __init__(self):
        self._items: List[DataItem] = []
    
    # === 추상 메서드 (서브클래스에서 구현 필수) ===
    
    @abstractmethod
    def load(self, path: str) -> List[DataItem]:
        """데이터 로드 및 정규화"""
        pass
    
    @abstractmethod
    def get_system_prompt(self) -> str:
        """시스템 프롬프트 반환"""
        pass
    
    @abstractmethod
    def build_user_prompt(self, item: DataItem) -> str:
        """사용자 프롬프트 생성"""
        pass
    
    @abstractmethod
    def parse_response(self, response: str) -> str:
        """모델 응답 파싱"""
        pass
    
    # === 공통 메서드 ===
    
    def get_sampling_params(self) -> Dict[str, Any]:
        """vLLM SamplingParams용 딕셔너리 반환"""
        params = {
            "temperature": self.sampling_config.temperature,
            "top_p": self.sampling_config.top_p,
            "max_tokens": self.sampling_config.max_tokens,
            "stop": self.sampling_config.stop,
        }
        return params
    
    def get_guided_params(self) -> Optional[Dict[str, Any]]:
        """vLLM Guided Generation 파라미터 (structured output)"""
        if not self.sampling_config.use_structured_output:
            return None
        if self.sampling_config.response_schema:
            return {"json": self.sampling_config.response_schema}
        return None
    
    def truncate_context(self, context: str, max_chars: int) -> str:
        """컨텍스트 트렁케이션 (스킵 대신 자르기)"""
        if len(context) <= max_chars:
            return context
        # 문장 단위로 자르기 시도
        truncated = context[:max_chars]
        last_period = truncated.rfind('.')
        if last_period > max_chars * 0.5:
            return truncated[:last_period + 1] + " [truncated]"
        return truncated + "... [truncated]"
    
    def build_messages(self, item: DataItem) -> List[Dict[str, str]]:
        """채팅 메시지 형식 생성"""
        return [
            {"role": "system", "content": self.get_system_prompt()},
            {"role": "user", "content": self.build_user_prompt(item)}
        ]
    
    # === 메트릭 계산 (공통) ===
    
    @staticmethod
    def normalize_text(text: str) -> str:
        """텍스트 정규화 (EM/F1용)"""
        if not text or not isinstance(text, str):
            return ""
        text = text.lower().strip()
        # Remove articles
        text = re.sub(r'\b(a|an|the)\b', ' ', text)
        # Remove punctuation
        text = re.sub(r'[^\w\s]', '', text)
        # White space fix
        text = ' '.join(text.split())
        return text
    
    def compute_em(self, pred: str, gold: str) -> float:
        """Exact Match 계산"""
        return 1.0 if self.normalize_text(pred) == self.normalize_text(gold) else 0.0
    
    def compute_f1(self, pred: str, gold: str) -> float:
        """Token F1 계산"""
        pred_tokens = self.normalize_text(pred).split()
        gold_tokens = self.normalize_text(gold).split()
        
        if not pred_tokens or not gold_tokens:
            return 0.0
        
        common = set(pred_tokens) & set(gold_tokens)
        if not common:
            return 0.0
        
        num_common = sum(min(pred_tokens.count(t), gold_tokens.count(t)) for t in common)
        precision = num_common / len(pred_tokens)
        recall = num_common / len(gold_tokens)
        
        if precision + recall == 0:
            return 0.0
        return 2 * (precision * recall) / (precision + recall)
    
    def compute_all_metrics(self, predictions: List[str], references: List[str]) -> Dict[str, float]:
        """
        전체 메트릭 계산 (EM, F1)
        ROUGE, BLEU, BERTScore는 analyze.py에서 별도 계산
        """
        em_scores = []
        f1_scores = []
        
        for pred, ref in zip(predictions, references):
            em_scores.append(self.compute_em(pred, ref))
            f1_scores.append(self.compute_f1(pred, ref))
        
        return {
            "EM": np.mean(em_scores) * 100,
            "F1": np.mean(f1_scores) * 100,
            "Total": len(predictions),
        }
    
    @property
    def items(self) -> List[DataItem]:
        return self._items
    
    def __len__(self) -> int:
        return len(self._items)
    
    def __repr__(self) -> str:
        return f"{self.__class__.__name__}(name={self.name}, items={len(self)})"
