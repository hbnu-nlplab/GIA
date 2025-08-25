"""
통합 네트워크 설정 테스트 데이터셋 생성 파이프라인
로직 기반(기초) + LLM 기반(심화) 질문 생성 및 다면적 평가 시스템
"""

from __future__ import annotations
from typing import Dict, Any, List, Optional, Tuple
from dataclasses import dataclass, asdict, field
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
from utils.builder_core import BuilderCore
from answer_agent import AnswerAgent
from command_agent import CommandAgent
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
        self.logger.info(f"Debug: categories = {self.config.target_categories}")
        self.logger.info(f"Debug: scenario_type = {self.config.scenario_type}")
        
        dsl_items = self.rule_generator.compile(
            capabilities=network_facts,
            categories=self.config.target_categories,
            scenario_type=self.config.scenario_type,
        )
        
        self.logger.info(f"Debug: dsl_items count = {len(dsl_items)}")
        if len(dsl_items) == 0:
            self.logger.warning("Debug: No DSL items generated. Checking policies...")
            # Check if policies are loaded
            self.logger.info(f"Debug: policies count = {len(self.rule_generator.policies)}")
            for i, pol in enumerate(self.rule_generator.policies[:3]):  # Show first 3
                self.logger.info(f"Debug: policy[{i}] category = {pol.get('category')}")

        command_items = [d for d in dsl_items if d.get("category") == "Command_Generation"]
        dsl_items = [d for d in dsl_items if d.get("category") != "Command_Generation"]
        
        # 어셈블리를 통한 답변 계산
        assembled_tests = self.assembler.assemble(
            network_facts,
            dsl_items,
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

        for idx, item in enumerate(command_items):
            # Check if this is from _generate_command_questions (has proper params) or DSL-style
            if 'intent' in item and 'params' in item['intent'] and item['intent']['params']:
                # This is from _generate_command_questions - has proper params
                intent = item.get('intent', {})
                metric = intent.get('metric', '')
                params = intent.get('params', {})
            else:
                # This is DSL-style - need to generate params from network facts
                intent = item.get('intent', {})
                metric = intent.get('metric', '')
                
                # Generate parameters similar to _generate_command_questions
                devices = network_facts.get("devices", [])
                first_device = devices[0] if devices else {}
                host = (
                    first_device.get("system", {}).get("hostname")
                    or first_device.get("name")
                    or first_device.get("file")
                    or "device1"
                )
                
                # Get interfaces and BGP info
                interfaces = first_device.get("interfaces") or [{}]
                interface = interfaces[0].get("name", "GigabitEthernet0/0")
                bgp = first_device.get("routing", {}).get("bgp", {})
                asn = bgp.get("local_as", 65000)
                neighbors = bgp.get("neighbors") or [{}]
                neighbor_ip = neighbors[0].get("id") or neighbors[0].get("ip") or "2.2.2.2"
                
                # Create comprehensive params based on metric type
                params_base = {
                    "host": host,
                    "interface": interface,
                    "asn": asn,
                    "neighbor_ip": neighbor_ip,
                    "user": "admin",
                    "prefix": "192.0.2.0",
                    "mask": "255.255.255.0",
                    "next_hop": "10.0.0.1",
                    "map_name": "RM_OUT",
                    "description": "Uplink to core",
                    "vrf_name": "CUSTOMER_A",
                    "process_id": 1,
                    "cost": 100,
                    "acl_name": "SSH_ONLY",
                    "new_hostname": f"{host}-NEW",
                    "jump_host": "jumphost",
                    "destination_host": host,
                }
                
                # Metric-specific parameter selection
                if metric == "cmd_ssh_direct_access":
                    params = {"user": params_base["user"], "host": host}
                elif metric == "cmd_set_static_route":
                    params = {
                        "host": host,
                        "prefix": params_base["prefix"],
                        "mask": params_base["mask"],
                        "next_hop": params_base["next_hop"],
                    }
                elif metric == "cmd_set_bgp_routemap":
                    params = {
                        "host": host,
                        "asn": asn,
                        "neighbor_ip": neighbor_ip,
                        "map_name": params_base["map_name"],
                    }
                elif metric == "cmd_set_interface_description":
                    params = {
                        "host": host,
                        "interface": interface,
                        "description": params_base["description"],
                    }
                elif metric == "cmd_create_vrf_and_assign":
                    params = {
                        "host": host,
                        "vrf_name": params_base["vrf_name"],
                        "interface": interface,
                    }
                elif metric == "cmd_ssh_proxy_jump":
                    hosts = [(
                        d.get("system", {}).get("hostname")
                        or d.get("name")
                        or d.get("file")
                        or host
                    ) for d in devices]
                    jump_host = hosts[1] if len(hosts) > 1 else "jumphost"
                    dest_host = hosts[2] if len(hosts) > 2 else host
                    params = {
                        "user": params_base["user"],
                        "jump_host": jump_host,
                        "destination_host": dest_host,
                    }
                else:
                    params = {"host": host}
            
            if metric.startswith('cmd_'):
                metric_name = metric[4:]
            else:
                metric_name = metric
                
            try:
                command = command_agent.generate(metric_name, params)
            except KeyError as e:
                self.logger.error(f"Missing parameter {e} for metric {metric_name}. Available params: {list(params.keys())}")
                continue
                
            gt, expl = self._format_answer({"ground_truth": command, "explanation": ""})
            sample = DatasetSample(
                id=f"BASIC_CMD_{idx}",
                question=item.get('question', ''),
                context=self._create_context(network_facts, []),
                ground_truth=gt,
                explanation=expl,
                answer_type=self._determine_answer_type(gt),
                category="basic",
                level=item.get('level', 1),
                complexity="basic",
                scenario=item.get('scenario'),
                source_files=[],
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
            "success": True
        }
        
        if self.config.save_intermediate:
            self._save_intermediate("basic_dataset.json", [asdict(s) for s in basic_samples])
        
        return basic_samples
    
    def _execute_stage_enhanced_generation(self, network_facts: Dict[str, Any]) -> List[DatasetSample]:
        """3단계: 심화 질문 생성 및 LLM 리뷰 후, AnswerAgent를 통한 정답 계산"""
        self.logger.info("3단계: 심화 질문 생성 (Enhanced LLM) 및 정답 생성 (AnswerAgent)")

        enhanced_questions = self.enhanced_generator.generate_enhanced_questions(
            network_facts=network_facts,
            target_complexities=self.config.target_complexities,
            questions_per_template=self.config.enhanced_questions_per_category,
        )
        self.logger.info(f"LLM이 생성한 초기 질문 수: {len(enhanced_questions)}")

        reviewed_questions = self.enhanced_generator._review_generated_questions(
            enhanced_questions
        )
        self.logger.info(f"LLM 리뷰 후 유효한 질문 수: {len(reviewed_questions)}")

        answer_agent = AnswerAgent(network_facts)
        command_agent = CommandAgent(network_facts)
        enhanced_samples: List[DatasetSample] = []

        # CommandAgent에서 지원하는 intent 목록
        valid_command_intents = {
            "show_bgp_summary", "show_ip_interface_brief", "show_ip_route_ospf",
            "show_processes_cpu", "show_l2vpn_vc", "show_ip_ospf_neighbor",
            "show_users", "show_logging", "ssh_direct_access", "set_static_route",
            "set_bgp_routemap", "set_interface_description", "create_vrf_and_assign",
            "set_ospf_cost", "set_vty_acl", "set_hostname", "ssh_proxy_jump",
            "ssh_multihop_jump", "check_connectivity", "show_bgp_neighbor_detail",
            "show_bgp_neighbors", "show_log_include", "show_interface_status",
            "show_vrf", "show_route_table", "show_ospf_database", "show_l2vpn_status"
        }

        def normalize_steps(steps: List[Dict[str, Any]]) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
            """Normalize reasoning steps by mapping intents or separating non-command steps."""
            command_steps: List[Dict[str, Any]] = []
            non_command_steps: List[Dict[str, Any]] = []

            keyword_intent_map = {
                "bgp neighbor detail": "show_bgp_neighbor_detail",
                "bgp neighbors": "show_bgp_neighbors",
                "bgp": "show_bgp_summary",
                "interface brief": "show_ip_interface_brief",
                "ospf neighbor": "show_ip_ospf_neighbor",
                "ospf database": "show_ospf_database",
                "ospf": "show_ip_route_ospf",
                "cpu": "show_processes_cpu",
                "l2vpn status": "show_l2vpn_status",
                "l2vpn": "show_l2vpn_vc",
                "users": "show_users",
                "logging": "show_logging",
                "static route": "set_static_route",
                "routemap": "set_bgp_routemap",
                "interface description": "set_interface_description",
                "create vrf": "create_vrf_and_assign",
                "ospf cost": "set_ospf_cost",
                "vty acl": "set_vty_acl",
                "hostname": "set_hostname",
                "ssh proxy": "ssh_proxy_jump",
                "ssh jump": "ssh_multihop_jump",
                "ssh": "ssh_direct_access",
                "connectivity": "check_connectivity",
                "log include": "show_log_include",
                "interface status": "show_interface_status",
                "vrf": "show_vrf",
                "route table": "show_route_table",
            }

            for step in steps:
                if not isinstance(step, dict):
                    non_command_steps.append(step)
                    continue

                intent = step.get("intent")
                if not intent:
                    text = f"{step.get('required_metric', '')} {step.get('description', '')}".lower()
                    for keyword, mapped_intent in keyword_intent_map.items():
                        if keyword in text:
                            intent = mapped_intent
                            step["intent"] = intent
                            break

                if intent in valid_command_intents:
                    command_steps.append(step)
                else:
                    non_command_steps.append(step)

            return command_steps, non_command_steps

        for eq in reviewed_questions:
            # Handle string entries (malformed LLM output)
            if isinstance(eq, str):
                self.logger.warning(f"Skipping malformed question entry: {eq[:100]}...")
                continue
                
            # Handle dict entries (normal case)
            if not isinstance(eq, dict):
                self.logger.warning(f"Skipping non-dict entry: {type(eq)}")
                continue
                
            question_text = eq.get("question")
            reasoning_plan = eq.get("reasoning_plan")
            if not question_text or not reasoning_plan:
                continue

            if isinstance(reasoning_plan, list):
                command_steps, non_command_steps = normalize_steps(reasoning_plan)
            else:
                command_steps, non_command_steps = [], []

            if command_steps and not non_command_steps:
                commands = []
                for step in command_steps:
                    try:
                        intent = step.get("intent")
                        params = step.get("params", {})
                        
                        # 누락된 필수 파라미터에 대한 기본값 제공
                        if intent == "set_bgp_routemap" and "asn" not in params:
                            params["asn"] = "65000"  # 기본 ASN
                        if intent == "ssh_direct_access" and "user" not in params:
                            params["user"] = "admin"  # 기본 사용자
                        if intent == "ssh_direct_access" and "host" not in params:
                            params["host"] = "192.168.1.1"  # 기본 호스트
                        
                        command = command_agent.generate(intent, params)
                        commands.append(command)
                    except Exception as e:
                        self.logger.warning(f"명령어 생성 실패 - intent: {intent}, params: {params}, error: {e}")
                        # 실패한 경우 기본 명령어 제공
                        commands.append(f"# ERROR: Failed to generate command for {intent}")
                        
                final_answer = "\n".join(commands)
                sample = DatasetSample(
                    id=f"ENHANCED_{eq.get('test_id', 'ENH')}",
                    question=question_text,
                    context="",
                    ground_truth=final_answer,
                    explanation="",
                    answer_type=eq.get("answer_type", "long"),
                    category=eq.get("category", "Enhanced_Analysis"),
                    complexity=eq.get("complexity", "analytical"),
                    level=eq.get("level", 3),
                    persona=eq.get("persona"),
                    scenario=eq.get("scenario"),
                    source_files=None,
                    metadata={
                        "origin": "enhanced_llm_with_agent",
                        "reasoning_plan": reasoning_plan,
                        "reasoning_requirement": eq.get("reasoning_requirement", ""),
                        "expected_analysis_depth": eq.get("expected_analysis_depth", "detailed"),
                        "evidence": {},
                    },
                )
            else:
                # AnswerAgent로 처리할 단계
                plan_for_answer = non_command_steps or reasoning_plan
                result = answer_agent.execute_plan(question_text, plan_for_answer)
                final_answer = result.get("ground_truth")
                explanation = result.get("explanation", "")

                if command_steps:
                    commands = []
                    for step in command_steps:
                        try:
                            intent = step.get("intent")
                            params = step.get("params", {})
                            if intent == "set_bgp_routemap" and "asn" not in params:
                                params["asn"] = "65000"
                            if intent == "ssh_direct_access" and "user" not in params:
                                params["user"] = "admin"
                            if intent == "ssh_direct_access" and "host" not in params:
                                params["host"] = "192.168.1.1"
                            command = command_agent.generate(intent, params)
                            commands.append(command)
                        except Exception as e:
                            self.logger.warning(
                                f"명령어 생성 실패 - intent: {intent}, params: {params}, error: {e}"
                            )
                            commands.append(f"# ERROR: Failed to generate command for {intent}")
                    if commands:
                        final_answer = "\n".join(commands + [str(final_answer)])

                sample = DatasetSample(
                    id=f"ENHANCED_{eq.get('test_id', 'ENH')}",
                    question=question_text,
                    context="",
                    ground_truth=final_answer,
                    explanation=explanation,
                    answer_type=eq.get("answer_type", "long"),
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
                        "evidence": answer_agent.evidence,
                    },
                )
            sample.context = self._create_enhanced_context(network_facts, sample)
            enhanced_samples.append(sample)

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
        
        # 중복 제거 (질문 + 장비/컨텍스트 조합 기준으로 완화)
        seen_combinations = set()
        deduplicated_samples = []
        
        for sample in all_samples:
            # 질문 + 주요 장비/컨텍스트 정보로 고유성 판단
            question_normalized = sample.question.lower().strip()
            context_key = sample.context[:100] if sample.context else ""
            source_files_key = str(sample.source_files) if sample.source_files else ""
            
            # 복합 키로 중복 판단 (장비가 다르면 같은 질문이어도 허용)
            combination_key = (
                question_normalized,
                context_key,
                source_files_key
            )
            
            if combination_key not in seen_combinations:
                seen_combinations.add(combination_key)
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
    policies_path = "policies/policies.json"
    all_categories = get_all_categories(policies_path)
    
    config = PipelineConfig(
        xml_data_dir="XML_Data",
        policies_path=policies_path,
        target_categories=all_categories,  # 모든 카테고리 자동 포함
        basic_questions_per_category=10,
        enhanced_questions_per_category=15,
        target_complexities=[
            QuestionComplexity.ANALYTICAL,    # 분석적 추론
            QuestionComplexity.DIAGNOSTIC,    # 문제 진단
            QuestionComplexity.SCENARIO      # 시나리오 기반
        ],
        target_personas=[
            PersonaType.NETWORK_ENGINEER,
            PersonaType.SECURITY_AUDITOR,
            PersonaType.NOC_OPERATOR,
            PersonaType.ARCHITECT,
            PersonaType.TROUBLESHOOTER,
            PersonaType.COMPLIANCE_OFFICER
        ],
        output_dir="output_dataset"
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
    