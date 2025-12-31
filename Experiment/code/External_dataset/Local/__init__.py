"""
데이터셋 모듈 패키지
- 각 데이터셋별 전용 설정/프롬프트/파서/메트릭
"""

from .base import BaseDataset, DataItem, SamplingConfig
from .teleqna import TeleQnADataset
from .telequad import TeleQuADDataset
from .netbench import NetBenchDataset

# 데이터셋 레지스트리
DATASET_REGISTRY = {
    "teleqna": TeleQnADataset,
    "telequad": TeleQuADDataset,
    "netbench": NetBenchDataset,
}

def get_dataset(name: str) -> BaseDataset:
    """데이터셋 이름으로 인스턴스 생성"""
    if name not in DATASET_REGISTRY:
        raise ValueError(f"Unknown dataset: {name}. Available: {list(DATASET_REGISTRY.keys())}")
    return DATASET_REGISTRY[name]()

__all__ = [
    "BaseDataset",
    "DataItem",
    "SamplingConfig",
    "TeleQnADataset", 
    "TeleQuADDataset",
    "NetBenchDataset",
    "DATASET_REGISTRY",
    "get_dataset",
]
