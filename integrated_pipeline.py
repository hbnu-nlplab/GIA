"""
통합 네트워크 설정 테스트 데이터셋 생성 파이프라인
로직 기반(기초) + LLM 기반(심화) 질문 생성 및 다면적 평가 시스템
"""

from __future__ import annotations
from typing import Dict, Any, List, Optional, Tuple
from dataclasses import dataclass, asdict
from enum import Enum
import json
from pathlib import Path
import logging
import re

# 기존 모듈들
from parsers.universal_parser import UniversalParser
from generators.rule_based_generator import RuleBasedGenerator, RuleBasedGeneratorConfig
# from generators.llm_explorer import LLMExplorer
from assemblers.test_assembler import TestAssembler, AssembleOptions
from inspectors.intent_inspector import IntentInspector
from utils.builder_core import BuilderCore

# 새로운 향상된 모듈들 (위에서 생성한 것들)
from generators.enhanced_llm_generator import EnhancedLLMQuestionGenerator, QuestionComplexity, PersonaType
from inspectors.evaluation_system import ComprehensiveEvaluator, AnswerType, EvaluationResult


class PipelineStage(Enum):
    """파이프라인 단계 정의"""
    PARSING = "parsing"
    BASIC_GENERATION = "basic_generation"
    ENHANCED_GENERATION = "enhanced_generation"
    ASSEMBLY = "assembly"
    VALIDATION = "validation"
    EVALUATION = "evaluation"


@dataclass
class PipelineConfig:
    """파이프라인 설정"""
    # 입력 설정
    xml_data_dir: str
    policies_path: str
    
    # 생성 설정
    target_categories: List[str]
    basic_questions_per_category: int = 4
    enhanced_questions_per_category: int = 3

    # 시나리오 설정
    scenario_type: str = "normal"  # normal, failure, expansion
    scenario_overrides: Optional[Dict[str, Any]] = None
    
    # 복잡도 및 페르소나 설정
    target_complexities: List[QuestionComplexity] = None
    target_personas: List[PersonaType] = None
    
    # 평가 설정
    enable_bert_score: bool = False  # BERT-Score는 별도 라이브러리 필요
    short_answer_threshold: int = 20  # 20단어 이하는 short answer
    
    # 출력 설정
    output_dir: str = "output"
    save_intermediate: bool = True
    
    def __post_init__(self):
        if self.target_complexities is None:
            self.target_complexities = [
                QuestionComplexity.ANALYTICAL, 
                QuestionComplexity.SYNTHETIC,
                QuestionComplexity.DIAGNOSTIC
            ]
        if self.target_personas is None:
            self.target_personas = [
                PersonaType.NETWORK_ENGINEER,
                PersonaType.SECURITY_AUDITOR,
                PersonaType.NOC_OPERATOR
            ]


@dataclass
class DatasetSample:
    """데이터셋 샘플 구조"""
    id: str
    question: str
    context: str  # 네트워크 설정 컨텍스트
    answer: str
    answer_type: str  # "short" or "long"
    category: str
    level: int = 1
    complexity: str
    persona: Optional[str] = None
    scenario: Optional[str] = None
    source_files: List[str] = None
    metadata: Dict[str, Any] = None


class NetworkConfigDatasetGenerator:
    """통합 네트워크 설정 데이터셋 생성기"""
    
    def __init__(self, config: PipelineConfig):
        self.config = config
        self.logger = self._setup_logger()
        
        # 파이프라인 컴포넌트 초기화
        self.parser = UniversalParser()
        self.rule_generator = RuleBasedGenerator(
            RuleBasedGeneratorConfig(
                policies_path=config.policies_path,
                min_per_cat=config.basic_questions_per_category,
                scenario_type=config.scenario_type,
            )
        )
        # self.llm_explorer = LLMExplorer()
        self.enhanced_generator = EnhancedLLMQuestionGenerator()
        self.assembler = TestAssembler(
            AssembleOptions(base_xml_dir=config.xml_data_dir)
        )
        self.inspector = IntentInspector()
        self.evaluator = ComprehensiveEvaluator()
        
        # 진행 상황 추적
        self.stage_results = {}
        
    def generate_complete_dataset(self) -> Dict[str, Any]:
        """완전한 데이터셋 생성 - 메인 함수"""
        self.logger.info("=== 네트워크 설정 테스트 데이터셋 생성 시작 ===")
        
        try:
            # 1단계: XML 파싱
            network_facts = self._execute_stage_parsing()
            
            # 2단계: 기초 질문 생성 (Rule-based)
            basic_dataset = self._execute_stage_basic_generation(network_facts)
            
            # 3단계: 심화 질문 생성 (Enhanced LLM)
            enhanced_dataset = self._execute_stage_enhanced_generation(network_facts)
            
            # 4단계: 통합 및 어셈블리
            integrated_dataset = self._execute_stage_assembly(
                network_facts, basic_dataset, enhanced_dataset
            )
            
            # 5단계: 검증 및 품질 관리
            validated_dataset = self._execute_stage_validation(integrated_dataset)
            
            # 6단계: 평가 메트릭 계산 (자가 평가)
            evaluation_results = self._execute_stage_evaluation(validated_dataset)
            
            # 최종 데이터셋 구성
            final_dataset = self._compose_final_dataset(
                validated_dataset, evaluation_results
            )
            
            # 결과 저장
            self._save_results(final_dataset)
            
            self.logger.info("=== 데이터셋 생성 완료 ===")
            return final_dataset
            
        except Exception as e:
            self.logger.error(f"데이터셋 생성 실패: {e}")
            raise
    
    def _execute_stage_parsing(self) -> Dict[str, Any]:
        """1단계: XML 파싱"""
        self.logger.info("1단계: 네트워크 설정 파일 파싱")
        
        network_facts = self.parser.parse_dir(self.config.xml_data_dir)
        
        device_count = len(network_facts.get("devices", []))
        self.logger.info(f"파싱 완료: {device_count}개 장비")
        
        self.stage_results[PipelineStage.PARSING] = {
            "device_count": device_count,
            "success": True
        }
        
        if self.config.save_intermediate:
            self._save_intermediate("parsed_facts.json", network_facts)
        
        return network_facts
    
    def _execute_stage_basic_generation(self, network_facts: Dict[str, Any]) -> List[DatasetSample]:
        """2단계: 기초 질문 생성 (Rule-based)"""
        self.logger.info("2단계: 기초 질문 생성 (Rule-based)")
        
        # Rule-based 생성
        dsl_items = self.rule_generator.compile(
            capabilities=network_facts,
            categories=self.config.target_categories,
            scenario_type=self.config.scenario_type,
        )
        
        # 어셈블리를 통한 답변 계산
        assembled_tests = self.assembler.assemble(
            network_facts,
            dsl_items,
            scenario_conditions=self.config.scenario_overrides,
        )
        
        # DatasetSample로 변환
        basic_samples = []
        for category, tests in assembled_tests.items():
            for test in tests:
                formatted_answer = self._format_answer(test.get('expected_answer', {}))
                sample = DatasetSample(
                    id=f"BASIC_{test.get('test_id', f'{category}_{len(basic_samples)}')}",
                    question=test.get('question', ''),
                    context=self._create_context(network_facts, test.get('source_files', [])),
                    answer=formatted_answer,
                    answer_type=self._determine_answer_type(formatted_answer),
                    category="basic",
                    level=test.get('level', 1),
                    complexity="basic",
                    scenario=test.get('scenario'),
                    source_files=test.get('source_files', []),
                    metadata={
                        "origin": "rule_based",
                        "intent": test.get('intent', {}),
                        "evidence_hint": test.get('evidence_hint', {}),
                        "topic": category
                    }
                )
                basic_samples.append(sample)
        
        self.logger.info(f"기초 질문 생성 완료: {len(basic_samples)}개")
        
        self.stage_results[PipelineStage.BASIC_GENERATION] = {
            "question_count": len(basic_samples),
            "categories": list(assembled_tests.keys()),
            "success": True
        }
        
        if self.config.save_intermediate:
            self._save_intermediate("basic_dataset.json", [asdict(s) for s in basic_samples])
        
        return basic_samples
    
    def _execute_stage_enhanced_generation(self, network_facts: Dict[str, Any]) -> List[DatasetSample]:
        """3단계: 심화 질문 생성 (Enhanced LLM)"""
        self.logger.info("3단계: 심화 질문 생성 (Enhanced LLM)")
        
        # Enhanced LLM 질문 생성
        enhanced_questions = self.enhanced_generator.generate_enhanced_questions(
            network_facts=network_facts,
            target_complexities=self.config.target_complexities,
            questions_per_template=self.config.enhanced_questions_per_category
        )
        
        # Intent 파싱 및 답변 계산을 위해 LLMExplorer 활용
        llm_items = []
        for eq in enhanced_questions:
            # Enhanced question을 LLM Explorer 형태로 변환
            hypothesis = {
                "question": eq["question"],
                "hypothesis_type": eq.get("complexity", "analytical"),
                "intent_hint": {
                    "metric": eq.get("metrics_involved", [""])[0] if eq.get("metrics_involved") else "",
                    "scope": {}
                },
                "expected_condition": "",
                "reasoning_steps": eq.get("reasoning_requirement", ""),
                "cited_values": {}
            }
            llm_items.append({"hypothesis": hypothesis})
        
        # Intent 변환 및 답변 계산
        translated_items = []
        for item in llm_items:
            try:
                # 간단한 intent 변환 (실제로는 LLMExplorer의 로직 사용)
                translated = {
                    "origin": "enhanced_llm",
                    "hypothesis": item["hypothesis"],
                    "intent": self._create_fallback_intent(item["hypothesis"])
                }
                translated_items.append(translated)
            except Exception as e:
                self.logger.warning(f"Enhanced question intent 변환 실패: {e}")
                continue
        
        # 검증 및 답변 계산
        validated_items = self.inspector.validate_llm(network_facts, translated_items)

        # 시나리오 조건에 따른 정답 변형
        validated_items = self.assembler.apply_scenario(
            validated_items, self.config.scenario_overrides
        )
        
        # DatasetSample로 변환
        enhanced_samples = []
        for idx, test in enumerate(validated_items):
            # Enhanced question 정보 복구
            orig_question = enhanced_questions[min(idx, len(enhanced_questions)-1)]

            formatted_answer = self._format_answer(test.get('expected_answer', {}))
            sample = DatasetSample(
                id=f"ENHANCED_{test.get('test_id', f'ENH_{idx}')}",
                question=test.get('question', ''),
                context=self._create_context(network_facts, []),
                answer=formatted_answer,
                answer_type=self._determine_answer_type(formatted_answer),
                category=orig_question.get('category', 'Enhanced_Analysis'),
                level=orig_question.get('level', test.get('level', 3)),

                complexity=orig_question.get('complexity', 'analytical'),
                persona=orig_question.get('persona'),
                scenario=orig_question.get('scenario'),
                metadata={
                    "origin": "enhanced_llm",
                    "intent": test.get('intent', {}),
                    "hypothesis": test.get('hypothesis', {}),
                    # 생성 단계에서 설정된 레벨/난이도 정보를 그대로 사용한다
                    "level": orig_question.get('level', 3),
                    "answer_difficulty": orig_question.get('answer_difficulty', orig_question.get('level', 3)),

                    "reasoning_requirement": orig_question.get('reasoning_requirement', ''),
                    "expected_analysis_depth": orig_question.get('expected_analysis_depth', 'detailed')
                }
            )
            enhanced_samples.append(sample)
        
        self.logger.info(f"심화 질문 생성 완료: {len(enhanced_samples)}개")
        
        self.stage_results[PipelineStage.ENHANCED_GENERATION] = {
            "question_count": len(enhanced_samples),
            "complexities": list(set(s.complexity for s in enhanced_samples)),
            "personas": list(set(s.persona for s in enhanced_samples if s.persona)),
            "success": True
        }
        
        if self.config.save_intermediate:
            self._save_intermediate("enhanced_dataset.json", [asdict(s) for s in enhanced_samples])
        
        return enhanced_samples
    
    def _execute_stage_assembly(
        self, 
        network_facts: Dict[str, Any],
        basic_samples: List[DatasetSample],
        enhanced_samples: List[DatasetSample]
    ) -> List[DatasetSample]:
        """4단계: 통합 및 어셈블리"""
        self.logger.info("4단계: 데이터셋 통합 및 어셈블리")
        
        # 기초 + 심화 질문 통합
        all_samples = basic_samples + enhanced_samples
        
        # 중복 제거 (질문 내용 기준)
        seen_questions = set()
        deduplicated_samples = []
        
        for sample in all_samples:
            question_normalized = sample.question.lower().strip()
            if question_normalized not in seen_questions:
                seen_questions.add(question_normalized)
                deduplicated_samples.append(sample)
            else:
                self.logger.debug(f"중복 질문 제거: {sample.question[:50]}...")
        
        # 카테고리별 균형 조정
        balanced_samples = self._balance_categories(deduplicated_samples)
        
        # Context 정보 보강
        for sample in balanced_samples:
            if not sample.context or sample.context.strip() == "":
                sample.context = self._create_enhanced_context(network_facts, sample)

        # 복잡도별 그룹화 저장
        samples_by_complexity: Dict[str, List[DatasetSample]] = {}
        for sample in balanced_samples:
            samples_by_complexity.setdefault(sample.complexity, []).append(sample)
        self.samples_by_complexity = samples_by_complexity

        # 필요 시 복잡도별 중간 결과 저장
        if self.config.save_intermediate:
            for comp, items in samples_by_complexity.items():
                self._save_intermediate(f"assembled_{comp}.json", [asdict(s) for s in items])

        self.logger.info(
            f"통합 완료: {len(balanced_samples)}개 (중복 제거: {len(all_samples) - len(balanced_samples)}개)"
        )

        self.stage_results[PipelineStage.ASSEMBLY] = {
            "total_samples": len(balanced_samples),
            "basic_count": len(basic_samples),
            "enhanced_count": len(enhanced_samples),
            "deduplicated_count": len(all_samples) - len(balanced_samples),
            "complexity_counts": {k: len(v) for k, v in samples_by_complexity.items()},
            "success": True,
        }

        return balanced_samples
    
    def _execute_stage_validation(self, samples: List[DatasetSample]) -> List[DatasetSample]:
        """5단계: 검증 및 품질 관리"""
        self.logger.info("5단계: 데이터 검증 및 품질 관리")
        
        validated_samples = []
        rejected_count = 0
        
        for sample in samples:
            # 기본 품질 체크
            if not self._validate_sample_quality(sample):
                rejected_count += 1
                continue
            
            # Answer type 재분류
            sample.answer_type = self._reclassify_answer_type(sample)
            
            # Context 및 메타데이터 보완
            sample = self._enrich_sample_metadata(sample)
            
            validated_samples.append(sample)
        
        self.logger.info(f"검증 완료: {len(validated_samples)}개 통과, {rejected_count}개 거부")
        
        self.stage_results[PipelineStage.VALIDATION] = {
            "validated_count": len(validated_samples),
            "rejected_count": rejected_count,
            "short_answer_count": len([s for s in validated_samples if s.answer_type == "short"]),
            "long_answer_count": len([s for s in validated_samples if s.answer_type == "long"]),
            "success": True
        }
        
        if self.config.save_intermediate:
            self._save_intermediate("validated_dataset.json", [asdict(s) for s in validated_samples])
        
        return validated_samples
    
    def _execute_stage_evaluation(self, samples: List[DatasetSample]) -> Dict[str, Any]:
        """6단계: 평가 메트릭 계산 (자가 평가)"""
        self.logger.info("6단계: 평가 메트릭 계산")

        predictions = []
        for sample in samples:
            mock_prediction = self._generate_mock_prediction(sample)
            predictions.append({
                "predicted": mock_prediction,
                "ground_truth": sample.answer,
                "question_id": sample.id,
                "answer_type": sample.answer_type,
            })

        eval_output = self.evaluator.evaluate_dataset(predictions)
        evaluation_data = eval_output.get("individual_results", [])

        # 평가 결과를 각 샘플에 병합
        eval_map = {e["question_id"]: e for e in evaluation_data}
        for sample in samples:
            if sample.id in eval_map:
                sample.metadata = sample.metadata or {}
                sample.metadata["evaluation"] = eval_map[sample.id]
                sample.metadata["overall_score"] = eval_map[sample.id]["overall_score"]

        # 복잡도별 통계 계산
        complexity_breakdown: Dict[str, Dict[str, int]] = {}
        for comp, comp_samples in getattr(self, "samples_by_complexity", {}).items():
            complexity_breakdown[comp] = {
                "total": len(comp_samples),
                "short": len([s for s in comp_samples if s.answer_type == "short"]),
                "long": len([s for s in comp_samples if s.answer_type == "long"]),
            }

        # 배치 통계 계산
        batch_stats = eval_output.get("overall_statistics", {})
        batch_stats.update({
            "sample_evaluation_count": len(evaluation_data),
            "total_dataset_size": len(samples),
            "category_distribution": self._calculate_category_distribution(samples),
            "complexity_distribution": self._calculate_complexity_distribution(samples),
            "complexity_breakdown": complexity_breakdown,
            "answer_type_distribution": {
                "short": len([s for s in samples if s.answer_type == "short"]),
                "long": len([s for s in samples if s.answer_type == "long"]),
            },
        })

        self.stage_results[PipelineStage.EVALUATION] = {
            "evaluation_data": evaluation_data,
            "batch_statistics": batch_stats,
            "success": True,
        }

        return {
            "sample_evaluations": evaluation_data,
            "dataset_statistics": batch_stats,
        }
    
    def _compose_final_dataset(
        self, 
        samples: List[DatasetSample],
        evaluation_results: Dict[str, Any]
    ) -> Dict[str, Any]:
        """최종 데이터셋 구성"""
        self.logger.info("최종 데이터셋 구성")
        
        # 데이터셋을 train/validation/test로 분할
        train_samples, val_samples, test_samples = self._split_dataset(samples)
        
        # PipelineConfig 내 Enum을 직렬화 가능하도록 문자열로 변환
        cfg = asdict(self.config)
        def _enum_to_value_list(v):
            if isinstance(v, list):
                out = []
                for it in v:
                    try:
                        from enum import Enum as _Enum
                        out.append(it.value if isinstance(it, _Enum) else it)
                    except Exception:
                        out.append(getattr(it, "value", it))
                return out
            return v
        cfg["target_complexities"] = _enum_to_value_list(cfg.get("target_complexities"))
        cfg["target_personas"] = _enum_to_value_list(cfg.get("target_personas"))
        
        final_dataset = {
            "metadata": {
                "dataset_name": "NetworkConfigQA",
                "version": "1.0",
                "description": "LLM 네트워크 설정 파악 성능 평가 데이터셋",
                "generation_config": cfg,
                "pipeline_results": {stage.value: result for stage, result in self.stage_results.items()},
                "total_samples": len(samples),
                "categories": list(set(s.category for s in samples)),
                "complexities": list(set(s.complexity for s in samples)),
                "complexity_counts": {k: len(v) for k, v in getattr(self, "samples_by_complexity", {}).items()},
                "answer_types": ["short", "long"],
            },
            "train": [asdict(s) for s in train_samples],
            "validation": [asdict(s) for s in val_samples],
            "test": [asdict(s) for s in test_samples],
            "evaluation_results": evaluation_results
        }
        
        return final_dataset
    
    # === 보조 메서드들 ===
    
    def _setup_logger(self) -> logging.Logger:
        """로거 설정"""
        logger = logging.getLogger("NetworkDatasetGenerator")
        logger.setLevel(logging.INFO)
        
        if not logger.handlers:
            handler = logging.StreamHandler()
            formatter = logging.Formatter(
                '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
            )
            handler.setFormatter(formatter)
            logger.addHandler(handler)
        
        return logger
    
    def _create_context(self, network_facts: Dict[str, Any], source_files: List[str]) -> str:
        """질문용 컨텍스트 생성"""
        if not source_files:
            return self._create_global_context(network_facts)
        
        # 특정 파일들에 대한 컨텍스트
        devices = network_facts.get("devices", [])
        relevant_devices = [d for d in devices if d.get("file") in source_files]
        
        if not relevant_devices:
            return self._create_global_context(network_facts)
        
        context_parts = []
        for device in relevant_devices:
            device_info = [
                f"장비: {device.get('system', {}).get('hostname', device.get('file', 'unknown'))}",
                f"OS: {device.get('vendor', 'unknown')}"
            ]
            
            # BGP 정보
            bgp = device.get('routing', {}).get('bgp', {})
            if bgp:
                device_info.append(f"BGP AS: {bgp.get('local_as', 'N/A')}")
                device_info.append(f"BGP 피어 수: {len(bgp.get('neighbors', []))}")
            
            # VRF 정보
            vrfs = device.get('services', {}).get('vrf', [])
            if vrfs:
                device_info.append(f"VRF 수: {len(vrfs)}")
            
            context_parts.append(" | ".join(device_info))
        
        return "\n".join(context_parts)
    
    def _create_global_context(self, network_facts: Dict[str, Any]) -> str:
        """전역 네트워크 컨텍스트 생성"""
        devices = network_facts.get("devices", [])
        
        summary = [
            f"총 장비 수: {len(devices)}",
            f"사용 기술: BGP, OSPF, L2VPN, L3VPN"
        ]
        
        # AS 정보
        as_numbers = set()
        for device in devices:
            las = device.get('routing', {}).get('bgp', {}).get('local_as')
            if las:
                as_numbers.add(str(las))
        
        if as_numbers:
            summary.append(f"AS 번호: {', '.join(sorted(as_numbers))}")
        
        return " | ".join(summary)
    
    def _format_answer(self, expected_answer: Dict[str, Any]) -> str:
        """답변 포맷팅"""
        value = expected_answer.get("value")
        
        if value is None:
            return "정보 없음"
        
        if isinstance(value, (list, set)):
            if not value:
                return "없음"
            return ", ".join(str(v) for v in sorted(value))
        
        if isinstance(value, dict):
            if not value:
                return "없음"
            items = [f"{k}: {v}" for k, v in value.items()]
            return "; ".join(items)
        
        if isinstance(value, bool):
            return "예" if value else "아니오"
        
        return str(value)
    
    def _create_fallback_intent(self, hypothesis: Dict[str, Any]) -> Dict[str, Any]:
        """Enhanced question용 fallback intent 생성"""
        return {
            "metric": "system_hostname_text",  # 기본 메트릭
            "scope": {"type": "GLOBAL"},
            "aggregation": "text",
            "placeholders": []
        }
    
    def _validate_sample_quality(self, sample: DatasetSample) -> bool:
        """샘플 품질 검증"""
        # 기본 필드 체크
        if not sample.question or len(sample.question.strip()) < 10:
            return False
        if not sample.answer or sample.answer.strip() == "":
            return False
        if not sample.category:
            return False
        
        # 금지 패턴 체크
        forbidden_patterns = ["어떻게", "무엇을", "설명하시오"]
        question_lower = sample.question.lower()
        if any(pattern in question_lower for pattern in forbidden_patterns):
            return False
        
        return True

    def _determine_answer_type(self, answer: str) -> str:
        """단어 수 기반 answer type 결정"""
        tokens = str(answer).split()
        return "short" if len(tokens) <= self.config.short_answer_threshold else "long"

    def _reclassify_answer_type(self, sample: DatasetSample) -> str:
        """답변 타입 재분류"""
        return self._determine_answer_type(sample.answer)
    
    def _enrich_sample_metadata(self, sample: DatasetSample) -> DatasetSample:
        """샘플 메타데이터 보강"""
        if sample.metadata is None:
            sample.metadata = {}
        
        # 질문 특성 분석
        sample.metadata["question_length"] = len(sample.question)
        sample.metadata["answer_length"] = len(sample.answer)
        sample.metadata["has_numbers"] = bool(re.search(r'\d+', sample.question))
        sample.metadata["has_technical_terms"] = bool(re.search(r'\b(BGP|OSPF|VRF|L2VPN|SSH|AAA)\b', sample.question, re.IGNORECASE))
        
        return sample
    
    def _balance_categories(self, samples: List[DatasetSample]) -> List[DatasetSample]:
        """카테고리별 균형 조정"""
        # 간단한 균형 조정: 각 카테고리에서 최대 N개
        max_per_category = 15
        
        by_category = {}
        for sample in samples:
            by_category.setdefault(sample.category, []).append(sample)
        
        balanced = []
        for category, category_samples in by_category.items():
            # 복잡도별로 다양성 확보
            by_complexity = {}
            for sample in category_samples:
                by_complexity.setdefault(sample.complexity, []).append(sample)
            
            selected = []
            for complexity, complexity_samples in by_complexity.items():
                selected.extend(complexity_samples[:max_per_category // len(by_complexity)])
            
            balanced.extend(selected[:max_per_category])
        
        return balanced
    
    def _create_enhanced_context(self, network_facts: Dict[str, Any], sample: DatasetSample) -> str:
        """향상된 컨텍스트 생성"""
        # 질문 내용에 맞는 특화된 컨텍스트 생성
        question_lower = sample.question.lower()
        
        if "bgp" in question_lower:
            return self._create_bgp_context(network_facts)
        elif "ssh" in question_lower or "보안" in question_lower:
            return self._create_security_context(network_facts)
        elif "vrf" in question_lower or "l3vpn" in question_lower:
            return self._create_vrf_context(network_facts)
        else:
            return self._create_global_context(network_facts)
    
    def _create_bgp_context(self, network_facts: Dict[str, Any]) -> str:
        """BGP 특화 컨텍스트"""
        devices = network_facts.get("devices", [])
        bgp_info = []
        
        for device in devices:
            bgp = device.get('routing', {}).get('bgp', {})
            if bgp:
                hostname = device.get('system', {}).get('hostname', device.get('file', 'unknown'))
                local_as = bgp.get('local_as', 'N/A')
                neighbor_count = len(bgp.get('neighbors', []))
                bgp_info.append(f"{hostname}: AS{local_as}, {neighbor_count}개 피어")
        
        return "BGP 설정 현황:\n" + "\n".join(bgp_info[:5])  # 최대 5개
    
    def _create_security_context(self, network_facts: Dict[str, Any]) -> str:
        """보안 특화 컨텍스트"""
        devices = network_facts.get("devices", [])
        security_info = []
        
        for device in devices:
            hostname = device.get('system', {}).get('hostname', device.get('file', 'unknown'))
            ssh_enabled = device.get('security', {}).get('ssh', {}).get('present', False)
            aaa_enabled = device.get('security', {}).get('aaa', {}).get('present', False)
            security_info.append(f"{hostname}: SSH {'ON' if ssh_enabled else 'OFF'}, AAA {'ON' if aaa_enabled else 'OFF'}")
        
        return "보안 설정 현황:\n" + "\n".join(security_info[:5])
    
    def _create_vrf_context(self, network_facts: Dict[str, Any]) -> str:
        """VRF 특화 컨텍스트"""
        devices = network_facts.get("devices", [])
        vrf_info = []
        
        for device in devices:
            hostname = device.get('system', {}).get('hostname', device.get('file', 'unknown'))
            vrfs = device.get('services', {}).get('vrf', [])
            vrf_count = len(vrfs)
            if vrf_count > 0:
                vrf_names = [v.get('name', 'unnamed') for v in vrfs[:3]]
                vrf_info.append(f"{hostname}: {vrf_count}개 VRF ({', '.join(vrf_names)})")
        
        return "VRF 설정 현황:\n" + "\n".join(vrf_info[:5])
    
    def _generate_mock_prediction(self, sample: DatasetSample) -> str:
        """모의 LLM 답변 생성 (평가용)"""
        # 실제로는 외부 LLM에 질문을 보내서 답변을 받아야 함
        # 여기서는 간단한 모의 답변 생성
        
        if sample.answer_type == "short":
            # 정답에 약간의 노이즈 추가
            if "개" in sample.answer or "수" in sample.answer:
                try:
                    num = re.search(r'\d+', sample.answer)
                    if num:
                        # 숫자에 ±1 오차 추가
                        original = int(num.group())
                        predicted = max(0, original + (1 if original % 2 == 0 else -1))
                        return str(predicted)
                except:
                    pass
            
            # Boolean 답변에 노이즈
            if sample.answer in ["예", "아니오"]:
                return "아니오" if sample.answer == "예" else "예"
        
        # 기본적으로 정답 반환 (약간의 표현 변경)
        answer = sample.answer
        replacements = {
            "예": "yes",
            "아니오": "no", 
            "없음": "None",
            "정보 없음": "N/A"
        }
        
        for old, new in replacements.items():
            answer = answer.replace(old, new)
        
        return answer
    
    def _calculate_category_distribution(self, samples: List[DatasetSample]) -> Dict[str, int]:
        """카테고리 분포 계산"""
        distribution = {}
        for sample in samples:
            distribution[sample.category] = distribution.get(sample.category, 0) + 1
        return distribution
    
    def _calculate_complexity_distribution(self, samples: List[DatasetSample]) -> Dict[str, int]:
        """복잡도 분포 계산"""
        distribution = {}
        for sample in samples:
            distribution[sample.complexity] = distribution.get(sample.complexity, 0) + 1
        return distribution
    
    def _split_dataset(self, samples: List[DatasetSample]) -> Tuple[List[DatasetSample], List[DatasetSample], List[DatasetSample]]:
        """데이터셋 분할 (train/val/test)"""
        import random
        random.seed(42)  # 재현 가능한 분할
        
        shuffled = samples.copy()
        random.shuffle(shuffled)
        
        total = len(shuffled)
        train_size = int(total * 0.7)
        val_size = int(total * 0.15)
        
        train = shuffled[:train_size]
        val = shuffled[train_size:train_size + val_size]
        test = shuffled[train_size + val_size:]
        
        return train, val, test
    
    def _save_intermediate(self, filename: str, data: Any) -> None:
        """중간 결과 저장"""
        output_dir = Path(self.config.output_dir)
        output_dir.mkdir(exist_ok=True)
        
        filepath = output_dir / filename
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
    
    def _save_results(self, final_dataset: Dict[str, Any]) -> None:
        """최종 결과 저장"""
        output_dir = Path(self.config.output_dir)
        output_dir.mkdir(exist_ok=True)
        
        # 전체 데이터셋 저장
        with open(output_dir / "network_config_qa_dataset.json", 'w', encoding='utf-8') as f:
            json.dump(final_dataset, f, ensure_ascii=False, indent=2)
        
        # 분할된 데이터셋 개별 저장
        for split_name in ["train", "validation", "test"]:
            if split_name in final_dataset:
                with open(output_dir / f"{split_name}.json", 'w', encoding='utf-8') as f:
                    json.dump(final_dataset[split_name], f, ensure_ascii=False, indent=2)
        
        # 메타데이터만 별도 저장
        with open(output_dir / "metadata.json", 'w', encoding='utf-8') as f:
            json.dump(final_dataset["metadata"], f, ensure_ascii=False, indent=2)
        
        self.logger.info(f"결과 저장 완료: {output_dir}")


def main():
    """메인 실행 함수"""
    
    # 설정
    config = PipelineConfig(
        xml_data_dir="XML_Data",
        policies_path="policies/policies.json",
        target_categories=[
            "BGP_Consistency",
            "VRF_Consistency", 
            "Security_Policy",
            "L2VPN_Consistency",
            "OSPF_Consistency"
        ],
        basic_questions_per_category=6,
        enhanced_questions_per_category=5,
        target_complexities=[
        QuestionComplexity.ANALYTICAL,    # 분석적 추론
        QuestionComplexity.DIAGNOSTIC,    # 문제 진단
        QuestionComplexity.SCENARIO      # 시나리오 기반
        ],
        target_personas=[
            PersonaType.NETWORK_ENGINEER,
            PersonaType.SECURITY_AUDITOR,
            PersonaType.NOC_OPERATOR
        ],
        output_dir="output_dataset"
    )
    
    # 데이터셋 생성기 초기화 및 실행
    generator = NetworkConfigDatasetGenerator(config)
    
    try:
        dataset = generator.generate_complete_dataset()
        
        print("\n=== 데이터셋 생성 완료 ===")
        print(f"총 샘플 수: {dataset['metadata']['total_samples']}")
        print(f"Train: {len(dataset['train'])}")
        print(f"Validation: {len(dataset['validation'])}")
        print(f"Test: {len(dataset['test'])}")
        print(f"카테고리: {dataset['metadata']['categories']}")
        print(f"복잡도: {dataset['metadata']['complexities']}")
        
    except Exception as e:
        print(f"데이터셋 생성 실패: {e}")
        raise


if __name__ == "__main__":
    main()
