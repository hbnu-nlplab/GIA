"""
통합 네트워크 설정 테스트 데이터셋 생성 파이프라인
로직 기반(기초) + LLM 기반(심화) 질문 생성 및 다면적 평가 시스템
"""

from __future__ import annotations
from typing import Dict, Any, List, Optional, Tuple
from dataclasses import dataclass, asdict, field
from enum import Enum
import hashlib
import json
from pathlib import Path
import logging
import re
import logging




# 기존 모듈들
from parsers.universal_parser import UniversalParser
from generators.rule_based_generator import RuleBasedGenerator, RuleBasedGeneratorConfig
# from generators.llm_explorer import LLMExplorer
from assemblers.test_assembler import TestAssembler, AssembleOptions
from inspectors.intent_inspector import IntentInspector
from utils.builder_core import BuilderCore
from agents.answer_agent import AnswerAgent
from agents.command_agent import CommandAgent
# from agents.validation_agent import ValidationAgent
# from agents.feedback_loop import FeedbackLoop
from agents.hybrid_validation_system import HybridValidationSystem, ValidationMode
from agents.hybrid_feedback_loop import HybridFeedbackLoop
from utils.config_manager import get_settings

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
    basic_questions_per_category: int = field(
        default_factory=lambda: get_settings().generation.basic_questions_per_category
    )
    enhanced_questions_per_category: int = field(
        default_factory=lambda: get_settings().generation.enhanced_questions_per_category
    )

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

    # 균형/중복 설정
    balance_max_per_category: Optional[int] = None  # None이면 컷 비활성화
    balance_group_key: str = "topic"  # topic(메타) 우선, 없으면 category
    
    def __post_init__(self):
        if self.target_complexities is None:
            # 기본값: 모든 복잡도 사용
            self.target_complexities = [
                QuestionComplexity.BASIC,
                QuestionComplexity.ANALYTICAL, 
                QuestionComplexity.SYNTHETIC,
                QuestionComplexity.DIAGNOSTIC,
                QuestionComplexity.SCENARIO,
            ]
        if self.target_personas is None:
            self.target_personas = [
                PersonaType.NETWORK_ENGINEER,
                PersonaType.SECURITY_AUDITOR,
                PersonaType.NOC_OPERATOR,
                PersonaType.ARCHITECT,
                PersonaType.TROUBLESHOOTER,
                PersonaType.COMPLIANCE_OFFICER
            ]


@dataclass
class DatasetSample:
    """데이터셋 샘플 구조"""
    id: str
    question: str
    context: str  # 네트워크 설정 컨텍스트
    ground_truth: Any
    explanation: str
    answer_type: str  # "short" or "long"
    category: str
    complexity: str
    level: int = 1
    persona: Optional[str] = None
    scenario: Optional[str] = None
    source_files: Optional[List[str]] = None
    metadata: Optional[Dict[str, Any]] = None


def assign_task_category(sample: DatasetSample) -> str:
    """질문의 특성에 따라 업무 분류를 결정합니다."""
    question = sample.question.lower()
    persona = sample.persona
    complexity = sample.complexity

    if "명령어" in question or "cli" in question or persona == "automation_engineer":
        return "명령어 사용법/질의"

    if sample.metadata and (sample.metadata.get("topic") == "Security_Policy" or persona == "security_auditor"):
        return "보안 질의"

    if complexity == "diagnostic" or persona == "troubleshooter":
        return "기술적 오류 질의"

    if ("토폴로지" in question or "연결" in question or "구성" in question or (sample.source_files and len(sample.source_files) > 1)):
        if complexity in ["analytical", "synthetic"]:
            return "네트워크 토폴로지 구성 질의"

    if complexity == "basic":
        return "단순 조회 업무"

    return "네트워크 토폴로지 구성 질의"


class NetworkConfigDatasetGenerator:
    """통합 네트워크 설정 데이터셋 생성기"""
    
    def __init__(self, config: PipelineConfig):
        self.config = config
        Path(self.config.output_dir).mkdir(exist_ok=True)
        self.logger = self._setup_logger()
        
        # 파이프라인 컴포넌트 초기화
        self.parser = UniversalParser()
        self.rule_generator = RuleBasedGenerator(
            RuleBasedGeneratorConfig(
                policies_path=config.policies_path,
                min_per_cat=config.basic_questions_per_category * 2,  # 카테고리당 더 많은 질문
                scenario_type=config.scenario_type,
            )
        )
        self.evaluator = ComprehensiveEvaluator()
        # 하이브리드 검증 시스템 (나중에 초기화)
        self.hybrid_validator = None
        self.hybrid_feedback = None
        self.validation_mode = ValidationMode.HYBRID  # 기본값
        self.max_validation_iterations = 3


        # self.llm_explorer = LLMExplorer()
        self.enhanced_generator = EnhancedLLMQuestionGenerator()
        self.assembler = TestAssembler(
            AssembleOptions(base_xml_dir=config.xml_data_dir)
        )
        self.evaluator = ComprehensiveEvaluator()
        
        # 진행 상황 추적
        self.stage_results = {}
        
    def generate_complete_dataset(self) -> Dict[str, Any]:
        """완전한 데이터셋 생성 - 메인 함수"""
        self.logger.info("="*20 + " 데이터셋 생성 파이프라인 시작 " + "="*20)
        
        try:
            # 1단계: XML 파싱
            self.logger.info("🔄 1단계: XML 파싱 시작")
            network_facts = self._execute_stage_parsing()
            self.logger.info(f"✅ 1단계 완료: {network_facts.get('device_count', 0)}개 장비 파싱")
            
            # 2단계: 기초 질문 생성 (Rule-based)
            self.logger.info("🔄 2단계: 기초 질문 생성 시작")
            basic_dataset = self._execute_stage_basic_generation(network_facts)
            self.logger.info(f"✅ 2단계 완료: {len(basic_dataset)}개 기초 질문 생성")
            
            # 3단계: 심화 질문 생성 (Enhanced LLM)
            self.logger.info("🔄 3단계: 심화 질문 생성 시작")
            enhanced_dataset = self._execute_stage_enhanced_generation(network_facts)
            self.logger.info(f"✅ 3단계 완료: {len(enhanced_dataset)}개 심화 질문 생성")
            
            # 4단계: 통합 및 어셈블리
            self.logger.info("🔄 4단계: 통합 및 어셈블리 시작")
            self.logger.info(f"통합 전 총 개수: {len(basic_dataset) + len(enhanced_dataset)}")
            integrated_dataset = self._execute_stage_assembly(
                network_facts, basic_dataset, enhanced_dataset
            )
            self.logger.info(f"✅ 4단계 완료: {len(integrated_dataset)}개 최종 통합")
            
            # (신규) 프리‑밸리데이션: BASIC/Rule 기반 항목의 GT를 로직값으로 자동 검증/교정
            self.logger.info("🔄 프리 검증 시작")
            integrated_dataset = self._execute_pre_validation(network_facts, integrated_dataset)
            self.logger.info(f"✅ 프리 검증 완료: {len(integrated_dataset)}개 검증")

            # 6단계: 하이브리드 검증 루프 (새로운!)
            self.logger.info("🔄 하이브리드 검증 루프 시작")
            final_dataset, validation_report = self._execute_hybrid_validation_loop(
                integrated_dataset, network_facts)
            self.logger.info(f"✅ 하이브리드 검증 완료: {len(final_dataset)}개")

            # 6단계: 평가 메트릭 계산 (자가 평가)
            self.logger.info("🔄 평가 메트릭 계산 시작")
            evaluation_results = self._execute_stage_evaluation(final_dataset)
            self.stage_results[PipelineStage.EVALUATION] = evaluation_results
            self.logger.info("✅ 평가 메트릭 계산 완료")
            
            # 최종 데이터셋 구성
            self.logger.info("🔄 최종 데이터셋 구성 시작")
            final_dataset = self._compose_final_dataset(final_dataset, evaluation_results)
            self._save_results(final_dataset)
            self.logger.info("✅ 최종 데이터셋 구성 완료")
            
            self.logger.info("="*20 + " 데이터셋 생성 완료 " + "="*20)
            return final_dataset
            
        except Exception as e:
            self.logger.error(f"데이터셋 생성 실패: {e}")
            self.logger.error(f"오류 타입: {type(e).__name__}")
            import traceback
            self.logger.error(f"스택트레이스:\n{traceback.format_exc()}")
            raise

    

    # 새로운 메서드 추가
    def _execute_hybrid_validation_loop(
        self,
        dataset: List[DatasetSample],
        network_facts: Dict[str, Any]
    ) -> Tuple[List[DatasetSample], Dict[str, Any]]:
        """
        6단계: 하이브리드 검증 루프
        에이전트가 문제를 풀고, BuilderCore로 정답을 확인하는 이중 검증
        """
        
        self.logger.info("="*60)
        self.logger.info("6단계: 하이브리드 검증 루프 시작")
        self.logger.info("="*60)
        
        # 하이브리드 시스템 초기화
        if not self.hybrid_validator:
            self.hybrid_validator = HybridValidationSystem(
                network_facts=network_facts,
                mode=self.validation_mode,
                xml_base_dir=self.config.xml_data_dir
            )
            self.hybrid_feedback = HybridFeedbackLoop(network_facts)
        
        # 데이터셋 딕셔너리 변환
        dataset_dicts = [asdict(sample) for sample in dataset]
        
        iteration = 0
        validation_history = []
        total_improvements = 0
        
        while iteration < self.max_validation_iterations:
            self.logger.info(f"\n검증 반복 {iteration + 1}/{self.max_validation_iterations}")
            
            try:
                # Step 1: 하이브리드 검증 수행
                # 샘플 크기 제어: config.validation_sample_size(없거나 0이면 전체)
                initial_sample = getattr(self.config, "validation_sample_size", None)
                sample_size = (initial_sample if (iteration == 0) else None)
                if sample_size in (0, None):
                    sample_size = None

                validation_results, validation_stats = self.hybrid_validator.validate_dataset(
                    dataset_dicts,
                    sample_size=sample_size
                )
                
                validation_history.append(validation_stats)
                
                # 주요 지표 출력
                self.logger.info(
                    f"에이전트 정확도: {validation_stats['agent_performance']['accuracy']:.1%}"
                )
                self.logger.info(
                    f"Ground Truth 정확도: {validation_stats['ground_truth_quality']['accuracy']:.1%}"
                )
                
                # Step 2: 목표 달성 확인
                if validation_stats['ground_truth_quality']['accuracy'] >= 0.95:
                    self.logger.info("✅ 목표 정확도 95% 달성!")
                    break
                
                # Step 3: 피드백 루프 실행
                improved_dataset, improvement_report = self.hybrid_feedback.improve_dataset(
                    validation_results,
                    dataset_dicts
                )
                
                if improvement_report['total_improvements'] == 0:
                    self.logger.info("개선할 항목이 없습니다.")
                    break
                
                # Step 4: 개선된 데이터셋으로 업데이트
                dataset_dicts = improved_dataset
                total_improvements += improvement_report['total_improvements']
                
                self.logger.info(
                    f"이번 반복에서 {improvement_report['total_improvements']}개 개선"
                )
                
            except Exception as e:
                self.logger.error(f"검증 반복 {iteration + 1}에서 오류 발생: {e}")
                self.logger.error(f"오류 타입: {type(e).__name__}")
                import traceback
                self.logger.error(f"스택트레이스:\n{traceback.format_exc()}")
                
                # 오류가 발생해도 루프를 계속 진행
                self.logger.warning("오류 발생으로 이번 반복을 건너뜁니다.")
                
            iteration += 1
        
        # 최종 리포트 생성
        final_report = {
            "validation_mode": self.validation_mode.value,
            "iterations": iteration + 1,
            "total_improvements": total_improvements,
            "validation_history": validation_history,
            "final_stats": validation_history[-1] if validation_history else {}
        }
        
        self.logger.info("\n" + "="*60)
        self.logger.info("하이브리드 검증 완료!")
        self.logger.info(f"총 반복: {iteration + 1}회")
        self.logger.info(f"총 개선: {total_improvements}개")
        if validation_history:
            final_accuracy = validation_history[-1]['ground_truth_quality']['accuracy']
            self.logger.info(f"최종 Ground Truth 정확도: {final_accuracy:.1%}")
        self.logger.info("="*60)
        
        # DatasetSample로 변환
        final_samples = [
            self._dict_to_dataset_sample(d) for d in dataset_dicts
        ]
        
        return final_samples, final_report
    
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
        """2단계: 기초 질문 생성 (Rule-based) - 다중 시나리오 지원"""
        self.logger.info("2단계: 기초 질문 생성 (Rule-based) - 다중 시나리오")
        
        # 다중 시나리오로 더 많은 질문 생성
        scenarios = ["normal", "failure", "expansion"]
        all_dsl_items = []
        all_command_items = []
        
        for scenario in scenarios:
            self.logger.info(f"시나리오 '{scenario}' 질문 생성 중...")
            
            dsl_items = self.rule_generator.compile(
                capabilities=network_facts,
                categories=self.config.target_categories,
                scenario_type=scenario,
            )
            
            # 시나리오 정보 태깅
            for item in dsl_items:
                item["scenario"] = scenario
                
            command_items = [d for d in dsl_items if d.get("category") == "Command_Generation"]
            regular_items = [d for d in dsl_items if d.get("category") != "Command_Generation"]
            
            all_dsl_items.extend(regular_items)
            all_command_items.extend(command_items)
        
        self.logger.info(f"총 DSL 아이템: {len(all_dsl_items)}, 명령어 아이템: {len(all_command_items)}")
        
        # 어셈블리를 통한 답변 계산
        assembled_tests = self.assembler.assemble(
            network_facts,
            all_dsl_items,
            scenario_conditions=self.config.scenario_overrides,
        )

        command_agent = CommandAgent(network_facts)
        
        # DatasetSample로 변환
        basic_samples = []
        for category, tests in assembled_tests.items():
            for test in tests:
                gt, expl = self._format_answer(test.get('expected_answer', {}))
                sample = DatasetSample(
                    id=f"BASIC_{test.get('test_id', f'{category}_{len(basic_samples)}')}",
                    question=test.get('question', ''),
                    context=self._create_context(network_facts, test.get('source_files', [])),
                    ground_truth=gt,
                    explanation=expl,
                    answer_type=self._determine_answer_type(gt),
                    category="basic",
                    level=test.get('level', 1),
                    complexity="basic",
                    scenario=test.get('scenario', 'normal'),
                    source_files=test.get('source_files', []),
                    metadata={
                        "origin": "rule_based",
                        "intent": test.get('intent', {}),
                        "evidence_hint": test.get('evidence_hint', {}),
                        "topic": category
                    }
                )
                basic_samples.append(sample)

        # Command Generation 카테고리 전용 처리 (시나리오별 중복 방지)
        # rule_based_generator에서 _generate_command_questions로 생성된 명령어 질문들 처리
        command_questions = self.rule_generator._generate_command_questions(network_facts)
        
        for idx, item in enumerate(command_questions):
            intent = item.get('intent', {})
            metric = intent.get('metric', '')
            params = intent.get('params', {})
            
            # CommandAgent를 통해 실제 명령어 생성
            if metric.startswith('cmd_'):
                metric_name = metric[4:]  # 'cmd_' 접두사 제거
            else:
                metric_name = metric
                
            try:
                command = command_agent.generate(metric_name, params)
            except Exception as e:
                self.logger.error(f"Command generation failed for {metric_name}: {e}")
                # 대안으로 기본 명령어 패턴 사용
                command = f"show {metric_name}"
                
            gt, expl = self._format_answer({"ground_truth": command, "explanation": ""})
            sample = DatasetSample(
                id=f"BASIC_CMD_{idx}",
                question=item.get('question', ''),
                context=self._create_context(network_facts, item.get('source_files', [])),
                ground_truth=gt,
                explanation=expl,
                answer_type=self._determine_answer_type(gt),
                category="basic",
                level=item.get('level', 1),
                complexity="basic",
                scenario="normal",  # Command 질문은 기본적으로 normal 시나리오
                source_files=item.get('source_files', []),
                metadata={
                    "origin": "rule_based",
                    "intent": {"command": metric_name, "params": params},
                    "evidence_hint": {},
                    "topic": "Command_Generation",
                },
            )
            basic_samples.append(sample)
        
        self.logger.info(f"기초 질문 생성 완료: {len(basic_samples)}개")
        
        self.stage_results[PipelineStage.BASIC_GENERATION] = {
            "question_count": len(basic_samples),
            "categories": list(assembled_tests.keys()),
            "scenarios": scenarios,
            "success": True
        }
        
        if self.config.save_intermediate:
            self._save_intermediate("basic_dataset.json", [asdict(s) for s in basic_samples])
        
        return basic_samples
    
    def _execute_stage_enhanced_generation(self, network_facts: Dict[str, Any]) -> List[DatasetSample]:
        """3단계: 심화 질문 생성 및 'AnswerAgent'를 통한 정답 생성"""
        self.logger.info("3단계: 심화 질문 생성 (Enhanced LLM) 및 정답 생성 (AnswerAgent)")

        try:
            print(f"[Pipeline] target_complexities: {[c.value for c in self.config.target_complexities]}")
            print(f"[Pipeline] questions_per_template: {self.config.enhanced_questions_per_category}")
            
            enhanced_questions = self.enhanced_generator.generate_enhanced_questions(
                network_facts=network_facts,
                target_complexities=self.config.target_complexities,
                questions_per_template=self.config.enhanced_questions_per_category,
            )
            self.logger.info(f"LLM이 생성한 초기 질문 수: {len(enhanced_questions)}")
            
            reviewed_questions = self.enhanced_generator._review_generated_questions(enhanced_questions)
            self.logger.info(f"LLM 리뷰 후 유효한 질문 수: {len(reviewed_questions)}")

            answer_agent = AnswerAgent(network_facts)
            enhanced_samples: List[DatasetSample] = []

            for eq in reviewed_questions:
                if not isinstance(eq, dict):
                    self.logger.warning(f"Skipping non-dict entry: {type(eq)}")
                    continue

                question_text = eq.get("question")
                reasoning_plan = eq.get("reasoning_plan")
                if not question_text or not reasoning_plan:
                    self.logger.debug(f"질문 또는 추론 계획 누락: question={bool(question_text)}, plan={bool(reasoning_plan)}")
                    continue

                try:
                    result = answer_agent.execute_plan(question_text, reasoning_plan)
                    final_answer = result.get("ground_truth")
                    explanation = result.get("explanation", "")
                    if final_answer in (None, ""):
                        self.logger.warning(f"AnswerAgent가 질문에 대한 답을 생성하지 못했습니다: {question_text}")
                        continue

                    sample = DatasetSample(
                        id=f"ENHANCED_{eq.get('test_id', 'ENH')}",
                        question=question_text,
                        context="",
                        ground_truth=final_answer,
                        explanation=explanation,
                        answer_type=self._determine_answer_type(final_answer),
                        category=eq.get("category", "Enhanced_Analysis"),
                        complexity=eq.get("complexity", "analytical"),
                        level=eq.get("level", 3),
                        persona=eq.get("persona"),
                        scenario=eq.get("scenario"),
                        source_files=result.get("source_files"),
                        metadata={
                            "origin": "enhanced_llm_with_agent",
                            "reasoning_plan": reasoning_plan,
                            "reasoning_requirement": eq.get("reasoning_requirement", ""),
                            "expected_analysis_depth": eq.get("expected_analysis_depth", "detailed"),
                            "evidence": result.get("evidence", answer_agent.evidence),
                        },
                    )
                    sample.context = self._create_enhanced_context(network_facts, sample)
                    enhanced_samples.append(sample)
                    
                except Exception as e:
                    self.logger.error(f"AnswerAgent 실행 중 오류 발생: Q='{question_text}', Error: {e}")
                    continue

            self.logger.info(f"심화 질문 및 정답 생성 완료: {len(enhanced_samples)}개")

            self.stage_results[PipelineStage.ENHANCED_GENERATION] = {
                "question_count": len(enhanced_samples),
                "complexities": list(set(s.complexity for s in enhanced_samples)),
                "personas": list(set(s.persona for s in enhanced_samples if s.persona)),
                "success": True,
            }

            if self.config.save_intermediate:
                self._save_intermediate("enhanced_dataset.json", [asdict(s) for s in enhanced_samples])

            return enhanced_samples
            
        except Exception as e:
            self.logger.error(f"심화 질문 생성 단계에서 오류 발생: {e}")
            self.logger.error(f"오류 타입: {type(e).__name__}")
            import traceback
            self.logger.error(f"스택트레이스:\n{traceback.format_exc()}")
            
            # 오류가 발생해도 빈 리스트 반환하여 파이프라인 계속 진행
            self.stage_results[PipelineStage.ENHANCED_GENERATION] = {
                "question_count": 0,
                "complexities": [],
                "personas": [],
                "success": False,
                "error": str(e)
            }
            return []
    
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
        
        # 중복 제거 (질문+컨텍스트 해시+소스/시나리오/페르소나/복잡도 조합)
        seen_combinations = set()
        deduplicated_samples = []
        duplicate_details = []
        
        self.logger.info(f"중복 제거 시작: 전체 샘플 {len(all_samples)}개")
        
        for i, sample in enumerate(all_samples):
            # 질문 + 컨텍스트 해시 + 소스/시나리오/페르소나/복잡도 키로 고유성 판단
            question_normalized = (sample.question or "").lower().strip()
            ctx = sample.context or ""
            ctx_hash = hashlib.sha1(ctx.encode("utf-8")).hexdigest()[:12] if ctx else ""
            files = sample.source_files or []
            source_files_key = ",".join(sorted(map(str, files)))
            persona_key = sample.persona or ""
            scenario_key = sample.scenario or ""
            complexity_key = sample.complexity or ""
            combination_key = (
                question_normalized,
                ctx_hash,
                source_files_key,
                scenario_key,
                persona_key,
                complexity_key,
            )
            
            if combination_key not in seen_combinations:
                seen_combinations.add(combination_key)
                deduplicated_samples.append(sample)
                self.logger.debug(f"샘플 {i+1} 유지: {sample.question[:50]}...")
            else:
                duplicate_details.append({
                    "index": i+1,
                    "question": sample.question[:100],
                    "id": sample.id,
                    "combination_key": str(combination_key)[:100]
                })
                self.logger.debug(f"샘플 {i+1} 중복 제거: {sample.question[:50]}...")
        
        removed_count = len(all_samples) - len(deduplicated_samples)
        self.logger.info(f"중복 제거 완료: {len(all_samples)}개 → {len(deduplicated_samples)}개 (제거: {removed_count}개)")
        
        # 중복 제거 상세 정보 저장
        if self.config.save_intermediate and duplicate_details:
            self._save_intermediate("duplicate_removal_details.json", {
                "total_duplicates": len(duplicate_details),
                "duplicate_samples": duplicate_details[:20]  # 상위 20개만 저장
            })
        
        # 카테고리별 균형 조정 (기본 비활성화: config.balance_max_per_category=None)
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

        dedup_removed = len(all_samples) - len(deduplicated_samples)
        balance_trim = len(deduplicated_samples) - len(balanced_samples)
        self.logger.info(
            f"통합 완료: {len(balanced_samples)}개 (중복 제거: {dedup_removed}개, 균형 컷: {balance_trim}개)"
        )

        self.stage_results[PipelineStage.ASSEMBLY] = {
            "total_samples": len(balanced_samples),
            "basic_count": len(basic_samples),
            "enhanced_count": len(enhanced_samples),
            "dedup_removed": dedup_removed,
            "balance_trim": balance_trim,
            "complexity_counts": {k: len(v) for k, v in samples_by_complexity.items()},
            "success": True,
        }

        return balanced_samples
    
    def _execute_validation_and_feedback_loop(
        self, dataset: List[DatasetSample]
    ) -> Tuple[List[DatasetSample], Dict[str, Any]]:
        """(신규) 검증과 교정을 반복하여 데이터셋 품질을 점진적으로 향상시키는 루프"""
        self.logger.info("="*10 + " 5단계: 자율 검증 및 자동 교정 루프 시작 " + "="*10)
        
        dataset_dicts = [asdict(s) for s in dataset]
        max_iterations = 3
        target_accuracy = 0.98
        validation_history = []
        
        for i in range(max_iterations):
            self.logger.info(f"--- 검증 루프 Iteration {i+1}/{max_iterations} ---")
            
            validation_results, stats = self.validation_agent.validate_dataset(dataset_dicts)
            validation_history.append(stats)
            self.logger.info(f"검증 결과: 정확도 {stats['accuracy']:.2%}, 오류 {stats['incorrect']}개")
            self._save_intermediate(f"validation_results_iter_{i+1}.json", [asdict(r) for r in validation_results])

            if stats['accuracy'] >= target_accuracy or stats['incorrect'] == 0:
                self.logger.info(f"목표 정확도({target_accuracy:.0%}) 도달. 루프를 종료합니다.")
                break
            
            regenerated, regen_stats = self.feedback_loop.regenerate_failed_items(validation_results)
            self.logger.info(f"자동 교정 시도: {regen_stats['regenerated_and_corrected']}개 항목 수정됨")
            
            if regen_stats['regenerated_and_corrected'] == 0:
                self.logger.warning("더 이상 교정할 수 있는 항목이 없습니다. 루프를 종료합니다.")
                break
            
            # 교정된 항목으로 데이터셋 업데이트
            regen_map = {item['id']: item for item in regenerated}
            dataset_dicts = [regen_map.get(item['id'], item) for item in dataset_dicts]
            self._save_intermediate(f"corrected_dataset_iter_{i+1}.json", dataset_dicts)

        initial_stats = validation_history[0]
        final_stats = validation_history[-1]
        total_corrected = final_stats['total_items'] - final_stats['correct']

        # 최종 리포트용 통계 계산
        report_stats = {
            "initial_accuracy": initial_stats['accuracy'],
            "final_accuracy": final_stats['accuracy'],
            "total_iterations": len(validation_history),
            "total_corrected_items": initial_stats['incorrect'] - final_stats['incorrect'],
            "initial_errors": initial_stats['incorrect'],
            "final_errors": final_stats['incorrect'],
            "auto_correction_success_rate": ((initial_stats['incorrect'] - final_stats['incorrect']) / initial_stats['incorrect']) if initial_stats['incorrect'] > 0 else 1.0,
            "validation_history": validation_history
        }
        
        final_samples = [DatasetSample(**d) for d in dataset_dicts]
        return final_samples, report_stats
    
    def _execute_stage_validation(self, samples: List[DatasetSample]) -> List[DatasetSample]:
        """5단계: 검증 및 품질 관리"""
        self.logger.info("5단계: 데이터 검증 및 답변 형식 표준화")

        validated_samples = []
        rejected_count = 0

        for sample in samples:
            # 기본 품질 체크
            if not self._validate_sample_quality(sample):
                rejected_count += 1
                continue

            # Ground truth 표준화
            sample = self._standardize_ground_truth(sample)

            # Answer type 재분류
            sample.answer_type = self._reclassify_answer_type(sample)

            # Context 및 메타데이터 보완
            sample = self._enrich_sample_metadata(sample)
            # 업무 분류 태깅
            sample.metadata["task_category"] = assign_task_category(sample)

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

    def _standardize_ground_truth(self, sample: DatasetSample) -> DatasetSample:
        """Ground truth를 평가하기 쉬운 형식으로 표준화"""

        question_lower = sample.question.lower()
        gt = sample.ground_truth

        # 개수/숫자 질문 -> 숫자만
        if any(word in question_lower for word in ["수는", "개수", "몇 개"]):
            if isinstance(gt, (list, dict)):
                sample.ground_truth = str(len(gt))
            elif isinstance(gt, int):
                sample.ground_truth = str(gt)
            elif isinstance(gt, str) and gt.isdigit():
                sample.ground_truth = gt
            else:
                numbers = re.findall(r"\d+", str(gt))
                sample.ground_truth = numbers[0] if numbers else "0"

        # 명령어 질문 -> 개행 구분
        elif "명령어" in question_lower or "cli" in question_lower:
            if isinstance(gt, list):
                sample.ground_truth = "\n".join(gt)
            else:
                sample.ground_truth = str(gt).strip()

        # 목록 질문 -> 공백 구분 문자열
        elif any(word in question_lower for word in ["목록", "리스트", "장비들"]):
            if isinstance(gt, list):
                sample.ground_truth = " ".join(sorted(str(item).strip() for item in gt))
            elif isinstance(gt, str):
                items = re.split(r"[\s,\n]+", gt)
                sample.ground_truth = " ".join(sorted(item for item in items if item))

        # IP/장비명 등 단일 값
        elif any(word in question_lower for word in ["ip", "주소", "장비", "호스트"]):
            if isinstance(gt, list):
                if gt:  # 리스트가 비어있지 않은 경우
                    # 단일 값을 기대하므로 첫 번째 요소만 사용합니다.
                    sample.ground_truth = str(gt[0]).strip()
            else:
                # 문자열, 숫자 등 다른 타입은 문자열로 변환합니다.
                sample.ground_truth = str(gt).strip()

        # 상태/여부 질문 -> 정규화
        elif any(word in question_lower for word in ["상태", "여부", "적절", "정상"]):
            gt_str = str(gt).lower()
            if any(token in gt_str for token in ["정상", "ok", "true"]):
                sample.ground_truth = "정상"
            elif any(token in gt_str for token in ["비정상", "false", "문제"]):
                sample.ground_truth = "비정상"
            else:
                sample.ground_truth = "알 수 없음"

        # 복잡한 객체 -> 주요 정보만 추출
        elif isinstance(gt, dict):
            if "status" in gt:
                sample.ground_truth = gt["status"]
            elif "result" in gt:
                sample.ground_truth = gt["result"]
            elif len(gt) == 1:
                sample.ground_truth = next(iter(gt.values()))
            else:
                sample.ground_truth = "; ".join(f"{k}: {v}" for k, v in gt.items())
        return sample
    
    def _execute_stage_evaluation(self, samples: List[DatasetSample]) -> Dict[str, Any]:
        """6단계: 평가 메트릭 계산 (자가 평가)"""
        self.logger.info("6단계: 평가 메트릭 계산")

        predictions = []
        for sample in samples:
            mock_prediction = self._generate_mock_prediction(sample)
            predictions.append({
                "predicted": mock_prediction,
                "ground_truth": sample.ground_truth,
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
    
    def _make_serializable(self, obj):
        """Enum 등을 JSON 직렬화 가능한 형태로 변환"""
        if hasattr(obj, 'value'):  # Enum인 경우
            return obj.value
        elif isinstance(obj, dict):
            return {k: self._make_serializable(v) for k, v in obj.items()}
        elif isinstance(obj, list):
            return [self._make_serializable(item) for item in obj]
        elif hasattr(obj, '__dict__'):  # dataclass나 객체인 경우
            return {k: self._make_serializable(v) for k, v in obj.__dict__.items()}
        else:
            return obj

    def _save_intermediate(self, filename: str, data: Any):
        """중간 결과물을 output 디렉토리에 저장합니다."""
        if not self.config.save_intermediate:
            return
        output_path = Path(self.config.output_dir) / filename
        self.logger.info(f"중간 결과 저장 -> {output_path}")
        try:
            # JSON 직렬화 가능한 형태로 변환
            serializable_data = self._make_serializable(data)
            with open(output_path, 'w', encoding='utf-8') as f:
                json.dump(serializable_data, f, ensure_ascii=False, indent=2)
        except Exception as e:
            self.logger.error(f"'{filename}' 저장 실패: {e}")


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
    
    def _setup_logger(self):
        """파일 및 콘솔 로거를 설정합니다."""
        logger = logging.getLogger("DatasetGenerator")
        logger.setLevel(logging.DEBUG)  # DEBUG 레벨로 변경
        if logger.hasHandlers():
            logger.handlers.clear()
        
        log_file = Path(self.config.output_dir) / 'pipeline.log'
        file_handler = logging.FileHandler(log_file, mode='w', encoding='utf-8')
        file_handler.setLevel(logging.DEBUG)  # 파일에는 모든 로그 기록
        file_handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(funcName)s:%(lineno)d - %(message)s'))
        logger.addHandler(file_handler)
        
        console_handler = logging.StreamHandler()
        console_handler.setLevel(logging.INFO)  # 콘솔은 INFO 이상만
        console_handler.setFormatter(logging.Formatter('[%(levelname)s] %(message)s'))
        logger.addHandler(console_handler)
        
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
    
    def _format_answer(self, expected_answer: Dict[str, Any]) -> Tuple[Any, str]:
        """Extract ground truth and explanation from expected_answer."""
        if not expected_answer:
            return None, ""
        ground_truth = expected_answer.get("ground_truth")
        explanation = expected_answer.get("explanation", "")
        if ground_truth is None:
            ground_truth = expected_answer.get("value")
        return ground_truth, explanation
    
    def _validate_sample_quality(self, sample: DatasetSample) -> bool:
        """샘플 품질을 더욱 엄격하게 검증합니다."""
        if not all([sample.question, sample.ground_truth, sample.category]):
            self.logger.debug(f"품질 미달 (필수 필드 누락): {sample.id}")
            return False
        if len(sample.question.strip()) < 15:
            self.logger.debug(f"품질 미달 (너무 짧은 질문): {sample.question}")
            return False

        question_lower = sample.question.lower()

        generic_patterns = [
            "란 무엇인가",
            "무엇입니까",
            "설명하시오",
            "알려줘",
            "어떻게 생각해",
            "요약해줘",
        ]
        if any(pattern in question_lower for pattern in generic_patterns):
            self.logger.debug(f"품질 미달 (너무 일반적임): {sample.question}")
            return False

        gt_str = str(sample.ground_truth)
        if gt_str.isdigit():
            if not any(word in question_lower for word in ["몇 개", "수", "얼마나", "개수", "몇 명"]):
                self.logger.debug(
                    f"품질 미달 (답변<->질문 불일치): Q='{sample.question}', A='{gt_str}'"
                )
                return False

        if "상태는 어떤가" in question_lower:
            if gt_str not in ["정상", "비정상", "양호", "불량", "활성", "비활성"]:
                self.logger.debug(
                    f"품질 미달 (모호한 상태 질문): Q='{sample.question}', A='{gt_str}'"
                )
                return False

        return True

    def _determine_answer_type(self, answer: Any) -> str:
        """단어 수 기반 answer type 결정"""
        tokens = str(answer).split()
        return "short" if len(tokens) <= self.config.short_answer_threshold else "long"

    def _reclassify_answer_type(self, sample: DatasetSample) -> str:
        """답변 타입 재분류"""
        return self._determine_answer_type(sample.ground_truth)
    
    def _enrich_sample_metadata(self, sample: DatasetSample) -> DatasetSample:
        """샘플 메타데이터 보강"""
        if sample.metadata is None:
            sample.metadata = {}
        
        # 질문 특성 분석
        sample.metadata["question_length"] = len(sample.question)
        sample.metadata["answer_length"] = len(str(sample.ground_truth))
        sample.metadata["has_numbers"] = bool(re.search(r'\d+', sample.question))
        sample.metadata["has_technical_terms"] = bool(re.search(r'\b(BGP|OSPF|VRF|L2VPN|SSH|AAA)\b', sample.question, re.IGNORECASE))
        
        return sample
    
    def _balance_categories(self, samples: List[DatasetSample]) -> List[DatasetSample]:
        """카테고리별 균형 조정 (기본 비활성화). 
        - 그룹 키: metadata.topic 우선, 없으면 sample.category
        - 상한: config.balance_max_per_category(None이면 컷 없음)
        """
        max_per_category = getattr(self.config, "balance_max_per_category", None)
        # 컷 비활성화: 그대로 반환
        if max_per_category is None or max_per_category <= 0:
            return samples

        # 그룹핑: topic 우선
        group_key_pref = getattr(self.config, "balance_group_key", "topic")
        by_group: Dict[str, List[DatasetSample]] = {}
        for sample in samples:
            topic = None
            if group_key_pref == "topic":
                meta = sample.metadata or {}
                topic = meta.get("topic")
            key = topic or sample.category or "unknown"
            by_group.setdefault(key, []).append(sample)

        balanced: List[DatasetSample] = []
        for key, items in by_group.items():
            # 복잡도 다양성 유지: 균등 분배
            by_complexity: Dict[str, List[DatasetSample]] = {}
            for s in items:
                by_complexity.setdefault(s.complexity or "", []).append(s)
            share = max(1, max_per_category // max(1, len(by_complexity)))
            selected: List[DatasetSample] = []
            for comp, comp_items in by_complexity.items():
                selected.extend(comp_items[:share])
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
            answer_text = str(sample.ground_truth)
            if "개" in answer_text or "수" in answer_text:
                try:
                    num = re.search(r'\d+', answer_text)
                    if num:
                        original = int(num.group())
                        predicted = max(0, original + (1 if original % 2 == 0 else -1))
                        return str(predicted)
                except:
                    pass

            if answer_text in ["예", "아니오"]:
                return "아니오" if answer_text == "예" else "예"

        # 기본적으로 정답 반환 (약간의 표현 변경)
        answer = str(sample.ground_truth)
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

    def _execute_pre_validation(self, network_facts: Dict[str, Any], samples: List[DatasetSample]) -> List[DatasetSample]:
        """프리‑밸리데이션: BASIC/Rule 기반 항목에 대해 Logic vs GT 검증 및 자동 교정.
        - 대상: category=='basic' 또는 metadata.origin=='rule_based'
        - intent가 있는 항목만 처리
        """
        from utils.builder_core import BuilderCore

        builder = BuilderCore(network_facts.get("devices", []))

        def _cmp(a, b) -> bool:
            if a is None or b is None:
                return a == b
            # 숫자
            try:
                fa = float(a); fb = float(b)
                return abs(fa - fb) <= max(1.0, abs(fb) * 0.01)
            except Exception:
                pass
            # 불린 텍스트 동등성
            tmap = {"true": True, "false": False, "yes": True, "no": False, "활성": True, "비활성": False, "정상": True}
            def _t(x):
                xs = str(x).strip().lower();
                return tmap.get(xs, None)
            ta, tb = _t(a), _t(b)
            if ta is not None and tb is not None:
                return ta == tb
            # 리스트/집합
            if isinstance(a, list) and isinstance(b, list):
                return set(map(str, a)) == set(map(str, b))
            # 문자열 정규화 비교
            return str(a).strip().lower() == str(b).strip().lower()

        corrected = 0; checked = 0
        out: List[DatasetSample] = []
        for s in samples:
            out.append(s)
            if (s.category or "").lower() != "basic" and not ((s.metadata or {}).get("origin") == "rule_based"):
                continue
            intent = ((s.metadata or {}).get("intent")) or {}
            metric = intent.get("metric"); params = intent.get("params") or intent.get("scope") or {}
            if not metric:
                continue
            try:
                checked += 1
                logic_val, _files = builder.calculate_metric(metric, params)
                if not _cmp(s.ground_truth, logic_val):
                    s.metadata = s.metadata or {}
                    s.metadata["correction_log"] = {
                        "reason": "pre-validation logic vs GT mismatch",
                        "old_ground_truth": s.ground_truth,
                        "new_ground_truth": logic_val,
                        "metric": metric,
                        "params": params,
                    }
                    s.ground_truth = logic_val
                    corrected += 1
            except Exception:
                continue

        self.logger.info(f"프리‑밸리데이션: 검사 {checked}개, 자동 교정 {corrected}개")

        if self.config.save_intermediate:
            try:
                self._save_intermediate("prevalidation_corrections.json", [
                    {
                        "id": s.id,
                        "question": s.question,
                        "correction_log": (s.metadata or {}).get("correction_log")
                    }
                    for s in out if (s.metadata or {}).get("correction_log")
                ])
            except Exception:
                pass
        return out
    
    def _dict_to_dataset_sample(self, data: Dict[str, Any]) -> DatasetSample:
        """딕셔너리를 DatasetSample 객체로 변환"""
        return DatasetSample(
            id=data.get("id", ""),
            question=data.get("question", ""),
            context=data.get("context", ""),
            ground_truth=data.get("ground_truth"),
            explanation=data.get("explanation", ""),
            answer_type=data.get("answer_type", "short"),
            category=data.get("category", ""),
            complexity=data.get("complexity", "basic"),
            level=data.get("level", 1),
            persona=data.get("persona"),
            scenario=data.get("scenario"),
            source_files=data.get("source_files", []),
            metadata=data.get("metadata", {})
        )


def main():
    """메인 실행 함수"""
    
    # policies.json에서 모든 카테고리 자동 추출
    def get_all_categories(policies_path: str) -> List[str]:
        """policies.json에서 모든 카테고리 추출"""
        import json
        with open(policies_path, 'r', encoding='utf-8') as f:
            policies_data = json.load(f)
        
        categories = set()
        for policy in policies_data.get("policies", []):
            category = policy.get("category")
            if category:
                categories.add(category)
        
        return sorted(list(categories))
    
    # 설정
    policies_path = "policies.json"
    all_categories = get_all_categories(policies_path)

    config = PipelineConfig(
        xml_data_dir="data/raw/XML_Data",
        policies_path=policies_path,
        target_categories=all_categories,  # 모든 카테고리 자동 포함
        basic_questions_per_category=30,  # 대폭 증가: 카테고리당 30개
        enhanced_questions_per_category=50,  # 안정적인 수치: 카테고리당 20개
        target_complexities=[
            QuestionComplexity.BASIC,         # 기본
            QuestionComplexity.ANALYTICAL,    # 분석적 추론
            QuestionComplexity.DIAGNOSTIC,    # 문제 진단
            QuestionComplexity.SCENARIO,      # 시나리오 기반
            QuestionComplexity.SYNTHETIC      # 통합 분석
        ],
        target_personas=[
            PersonaType.NETWORK_ENGINEER,
            PersonaType.SECURITY_AUDITOR,
            PersonaType.NOC_OPERATOR,
            PersonaType.ARCHITECT,
            PersonaType.TROUBLESHOOTER,
            PersonaType.COMPLIANCE_OFFICER,
            # PersonaType.AUTOMATION_ENGINEER
        ],
        output_dir="output"
    )
    
    # 추출된 카테고리 로그 출력
    print(f"자동 추출된 카테고리: {all_categories}")
    
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
