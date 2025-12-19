"""
core_batfish 패키지

리팩토링된 Batfish 분석 모듈:
- models: 데이터 클래스 (AnswerResult, FlowSpec 등)
- batfish_base: BatfishBase 클래스 (초기화, 스냅샷 관리)
- l4_analyzer: L4AnalyzerMixin (도달성 분석 메트릭)
- l5_analyzer: L5AnalyzerMixin (What-If 분석 메트릭)
- batfish_builder: BatfishBuilder (통합 Facade)
"""

from .batfish_builder import (
    BatfishBuilder,
    AnswerResult,
    FlowSpec,
    L4Result,
    L5Result,
    CanonicalizationError,
    BATFISH_AVAILABLE,
)

from .builder_core import BuilderCore

__all__ = [
    'BatfishBuilder',
    'BuilderCore',
    'AnswerResult',
    'FlowSpec',
    'L4Result',
    'L5Result',
    'CanonicalizationError',
    'BATFISH_AVAILABLE',
]
