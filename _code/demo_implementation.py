"""
실제 사용 예시 및 데모 구현
교수님 요구사항을 반영한 구체적인 실행 예시
"""

import json
import os
from pathlib import Path
from typing import Dict, Any, List
import logging

# 설정 로깅
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


class NetworkDatasetDemo:
    """네트워크 데이터셋 생성 데모 클래스"""
    
    def __init__(self):
        self.setup_environment()
    
    def setup_environment(self):
        """환경 설정"""
        # 개발 단계에서는 LLM 사용을 제한적으로
        os.environ.setdefault("GIA_USE_INTENT_LLM", "0")
        os.environ.setdefault("GIA_ENABLE_LLM_REVIEW", "0")
        os.environ.setdefault("GIA_DISABLE_HYPO_REVIEW", "1")
        
        # 안정성을 위한 설정
        os.environ.setdefault("OPENAI_TIMEOUT_SEC", "30")
        os.environ.setdefault("OPENAI_MAX_RETRIES", "2")
    
    def demo_basic_pipeline(self):
        """기본 파이프라인 데모"""
        logger.info("=== 기본 파이프라인 데모 시작 ===")
        
        try:
            # 1. 설정
            from integrated_pipeline import NetworkConfigDatasetGenerator, PipelineConfig
            
            config = PipelineConfig(
                xml_data_dir="XML_Data",
                policies_path="policies/policies.json",
                target_categories=[
                    "BGP_Consistency",
                    "Security_Policy", 
                    "VRF_Consistency"
                ],
                basic_questions_per_category=4,
                enhanced_questions_per_category=2,  # 작게 시작
                output_dir="demo_output"
            )
            
            # 2. 생성기 초기화
            generator = NetworkConfigDatasetGenerator(config)
            
            # 3. 단계별 실행 (디버깅 용이)
            logger.info("1단계: XML 파싱")
            network_facts = generator._execute_stage_parsing()
            logger.info(f"파싱 완료: {len(network_facts.get('devices', []))}개 장비")
            
            logger.info("2단계: 기초 질문 생성")
            basic_samples = generator._execute_stage_basic_generation(network_facts)
            logger.info(f"기초 질문: {len(basic_samples)}개 생성")
            
            # 기초 질문 샘플 출력
            self._print_sample_questions(basic_samples[:3], "기초 질문")
            
            logger.info("3단계: 심화 질문 생성")
            enhanced_samples = generator._execute_stage_enhanced_generation(network_facts)
            logger.info(f"심화 질문: {len(enhanced_samples)}개 생성")
            
            # 심화 질문 샘플 출력
            self._print_sample_questions(enhanced_samples[:2], "심화 질문")
            
            logger.info("4-6단계: 통합, 검증, 평가")
            integrated = generator._execute_stage_assembly(network_facts, basic_samples, enhanced_samples)
            validated = generator._execute_stage_validation(integrated)
            evaluation = generator._execute_stage_evaluation(validated)
            
            # 최종 결과
            final_dataset = generator._compose_final_dataset(validated, evaluation)
            generator._save_results(final_dataset)
            
            logger.info("=== 기본 파이프라인 데모 완료 ===")
            self._print_dataset_summary(final_dataset)
            
            return final_dataset
            
        except Exception as e:
            logger.error(f"데모 실행 실패: {e}")
            raise
    
    def demo_incount_cases(self):
        """incount 확장 케이스 데모"""
        logger.info("=== incount 확장 케이스 데모 ===")
        
        from migration_guide import EnhancedDatasetConfigurator
        
        configurator = EnhancedDatasetConfigurator()
        
        # 기본 설정
        base_config = {
            "xml_data_dir": "XML_Data",
            "policies_path": "policies/policies.json",
            "target_categories": ["BGP_Consistency", "Security_Policy"],
            "basic_questions_per_category": 3,
            "enhanced_questions_per_category": 2
        }
        
        # 다양한 케이스 생성
        case_variants = configurator.create_incount_variants(base_config)
        
        logger.info(f"생성된 케이스 수: {len(case_variants)}")
        
        results = {}
        for case in case_variants:
            case_name = case.get("case_name", "unknown")
            logger.info(f"\n--- 케이스: {case_name} ---")
            logger.info(f"설명: {case.get('description', 'N/A')}")
            
            try:
                # 각 케이스별로 데이터셋 생성
                case_dataset = self._generate_case_dataset(case)
                results[case_name] = case_dataset
                
                logger.info(f"케이스 {case_name} 완료: {len(case_dataset.get('samples', []))}개 질문")
                
            except Exception as e:
                logger.warning(f"케이스 {case_name} 실패: {e}")
                continue
        
        # 케이스별 결과 저장
        output_dir = Path("demo_output/cases")
        output_dir.mkdir(parents=True, exist_ok=True)
        
        with open(output_dir / "all_cases.json", 'w', encoding='utf-8') as f:
            json.dump(results, f, ensure_ascii=False, indent=2)
        
        logger.info("=== incount 케이스 데모 완료 ===")
        return results
    
    def demo_evaluation_profiles(self):
        """평가 프로필 데모"""
        logger.info("=== 평가 프로필 데모 ===")
        
        from migration_guide import EnhancedDatasetConfigurator
        from evaluation_system import ComprehensiveEvaluator
        
        configurator = EnhancedDatasetConfigurator()
        evaluator = ComprehensiveEvaluator()
        
        # 평가 프로필들 생성
        profiles = configurator.create_evaluation_profiles()
        
        # 모의 평가 데이터
        mock_predictions = [
            {
                "question_id": "BGP_001",
                "predicted": "3개",
                "ground_truth": "3",
                "answer_type": "short"
            },
            {
                "question_id": "SEC_001", 
                "predicted": "SSH가 2대 장비에서 비활성화되어 있어 보안 위험이 있습니다. PE01과 CE02에서 SSH 설정을 확인하고 활성화해야 합니다.",
                "ground_truth": "SSH가 일부 장비에서 비활성화되어 보안 정책 위반이 있습니다. 총 2대 장비(PE01, CE02)에서 SSH 설정이 필요합니다.",
                "answer_type": "long"
            },
            {
                "question_id": "VRF_001",
                "predicted": "CUSTOMER_A, CUSTOMER_B",
                "ground_truth": "CUSTOMER_A, CUSTOMER_B, CUSTOMER_C",
                "answer_type": "short"
            }
        ]
        
        logger.info(f"평가 프로필 수: {len(profiles)}")
        
        for profile in profiles:
            profile_name = profile["profile_name"]
            logger.info(f"\n--- 평가 프로필: {profile_name} ---")
            logger.info(f"설명: {profile['description']}")
            logger.info(f"사용 메트릭: {profile['metrics']}")
            
            # 각 프로필별로 평가 수행
            profile_results = []
            for pred_data in mock_predictions:
                result = evaluator.evaluate_single(
                    predicted=pred_data["predicted"],
                    ground_truth=pred_data["ground_truth"],
                    question_id=pred_data["question_id"],
                    answer_type=pred_data["answer_type"]
                )
                profile_results.append(result)
            
            # 프로필별 통계
            batch_stats = evaluator._calculate_batch_statistics(profile_results)
            
            logger.info(f"프로필 결과:")
            logger.info(f"  - 전체 점수: {batch_stats.get('overall_score_avg', 0):.3f}")
            logger.info(f"  - EM 점수: {batch_stats.get('exact_match_avg', 0):.3f}")
            logger.info(f"  - F1 점수: {batch_stats.get('f1_score_avg', 0):.3f}")
            
            if 'short_answer_em' in batch_stats:
                logger.info(f"  - Short Answer EM: {batch_stats['short_answer_em']:.3f}")
            if 'long_answer_bleu' in batch_stats:
                logger.info(f"  - Long Answer BLEU: {batch_stats['long_answer_bleu']:.3f}")
        
        logger.info("=== 평가 프로필 데모 완료 ===")
        return profiles
    
    def demo_answer_type_classification(self):
        """Short/Long Answer 분류 데모"""
        logger.info("=== Answer Type 분류 데모 ===")
        
        from evaluation_system import ComprehensiveEvaluator
        
        evaluator = ComprehensiveEvaluator()
        
        # 테스트 케이스들
        test_cases = [
            # Short Answer 예시들
            {
                "question": "BGP 피어 수는?",
                "answer": "5개",
                "expected_type": "short"
            },
            {
                "question": "SSH가 활성화되어 있는가?",
                "answer": "예",
                "expected_type": "short"
            },
            {
                "question": "VRF 목록은?",
                "answer": "CUSTOMER_A, CUSTOMER_B, CUSTOMER_C",
                "expected_type": "short"
            },
            # Long Answer 예시들
            {
                "question": "AS 65001의 BGP 피어링 누락이 네트워크 수렴성에 미치는 영향을 분석하시오.",
                "answer": "AS 65001에서 PE01-PE02 간 iBGP 피어링이 누락되어 있어 다음과 같은 영향이 예상됩니다. 첫째, 라우트 수렴 시간이 지연될 수 있습니다. 둘째, 일부 고객 경로가 차선의 경로를 통해 전달될 가능성이 있습니다. 셋째, 링크 장애 시 복구 시간이 증가할 수 있습니다. 따라서 즉시 피어링 설정을 완료하고 BGP 모니터링을 강화해야 합니다.",
                "expected_type": "long"
            },
            {
                "question": "L2VPN 서비스에서 PW-ID 불일치가 발견된 회선들의 비즈니스 영향도를 평가하고 해결 방안을 제시하시오.",
                "answer": "PW-ID 불일치가 발견된 3개 회선(CUSTOMER_A-SITE1, CUSTOMER_B-SITE2, CUSTOMER_C-SITE1)의 영향도 분석 결과, CUSTOMER_A는 금융 서비스로 최고 우선순위이며 즉시 복구가 필요합니다. CUSTOMER_B는 일반 기업으로 업무시간 내 복구 계획을 수립하고, CUSTOMER_C는 테스트 환경으로 상대적으로 낮은 우선순위입니다. 해결 방안으로는 각 PE 라우터에서 PW-ID 설정을 표준화하고, 자동화된 검증 스크립트를 도입하여 향후 유사 문제를 방지해야 합니다.",
                "expected_type": "long"
            }
        ]
        
        logger.info(f"테스트 케이스 수: {len(test_cases)}")
        
        correct_classifications = 0
        for i, case in enumerate(test_cases):
            detected_type = evaluator._detect_answer_type(case["answer"], case["answer"])
            expected = case["expected_type"]
            is_correct = detected_type.value == expected
            
            logger.info(f"\n케이스 {i+1}:")
            logger.info(f"질문: {case['question'][:50]}...")
            logger.info(f"답변 길이: {len(case['answer'])} 문자")
            logger.info(f"예상: {expected}, 감지: {detected_type.value}, 정확: {is_correct}")
            
            if is_correct:
                correct_classifications += 1
        
        accuracy = correct_classifications / len(test_cases)
        logger.info(f"\n분류 정확도: {accuracy:.2%} ({correct_classifications}/{len(test_cases)})")
        
        logger.info("=== Answer Type 분류 데모 완료 ===")
        return accuracy
    
    def demo_network_domain_evaluation(self):
        """네트워크 도메인 특화 평가 데모"""
        logger.info("=== 네트워크 도메인 평가 데모 ===")
        
        from evaluation_system import ComprehensiveEvaluator
        
        evaluator = ComprehensiveEvaluator()
        
        # 네트워크 도메인 특화 테스트 케이스들
        network_test_cases = [
            {
                "question_id": "IP_TEST_001",
                "predicted": "192.168.1.1, 10.0.0.1, 172.16.0.1",
                "ground_truth": "192.168.1.1, 10.0.0.1, 172.16.0.1", 
                "description": "IP 주소 정확 매치"
            },
            {
                "question_id": "IP_TEST_002", 
                "predicted": "192.168.1.1/24, 10.0.0.1/8",
                "ground_truth": "192.168.1.1, 10.0.0.1",
                "description": "IP 주소 정규화 (서브넷 마스크 제거)"
            },
            {
                "question_id": "AS_TEST_001",
                "predicted": "AS65001, AS65002", 
                "ground_truth": "AS 65001, AS 65002",
                "description": "AS 번호 정규화"
            },
            {
                "question_id": "INTERFACE_TEST_001",
                "predicted": "GigabitEthernet0/0/0/0, FastEthernet0/1",
                "ground_truth": "GE0/0/0/0, FE0/1", 
                "description": "인터페이스 이름 정규화"
            },
            {
                "question_id": "BOOLEAN_TEST_001",
                "predicted": "활성화됨",
                "ground_truth": "예",
                "description": "불리언 의미 매핑"
            }
        ]
        
        logger.info("네트워크 특화 평가 수행:")
        
        total_score = 0
        for case in network_test_cases:
            # 기본 평가
            result = evaluator.evaluate_single(
                predicted=case["predicted"],
                ground_truth=case["ground_truth"], 
                question_id=case["question_id"],
                answer_type="short"
            )
            
            # 네트워크 엔티티 평가
            entity_f1_scores = evaluator.f1_evaluator.evaluate_entity_f1(
                case["predicted"], 
                case["ground_truth"]
            )
            
            logger.info(f"\n{case['description']}:")
            logger.info(f"  예측: {case['predicted']}")
            logger.info(f"  정답: {case['ground_truth']}")
            logger.info(f"  EM: {result.exact_match:.3f}")
            logger.info(f"  F1: {result.f1_score:.3f}")
            
            if entity_f1_scores:
                logger.info(f"  엔티티 F1: {entity_f1_scores}")
            
            total_score += result.overall_score()
        
        avg_score = total_score / len(network_test_cases)
        logger.info(f"\n네트워크 도메인 평균 점수: {avg_score:.3f}")
        
        logger.info("=== 네트워크 도메인 평가 데모 완료 ===")
        return avg_score
    
    def _generate_case_dataset(self, case_config: Dict[str, Any]) -> Dict[str, Any]:
        """케이스별 데이터셋 생성 (간소화 버전)"""
        
        case_name = case_config.get("case_name", "unknown")
        
        # 시뮬레이션 조건이 있는 경우 적용
        simulation_conditions = case_config.get("simulation_conditions", [])
        
        # 간단한 모의 데이터셋 생성
        samples = []
        
        if case_name == "bgp_peer_failure":
            samples = [
                {
                    "question": "BGP 피어 장애 상황에서 라우팅 수렴 시간은?",
                    "answer": "약 180초 (기본 BGP 타이머 기준)",
                    "answer_type": "short",
                    "simulation": simulation_conditions
                },
                {
                    "question": "BGP 피어 장애가 고객 서비스에 미치는 영향을 분석하시오.",
                    "answer": "Router1-Router2 간 iBGP 세션 중단으로 인해 해당 경로를 사용하는 CUSTOMER_A 서비스에 3분간 중단이 발생할 수 있습니다. 대체 경로로 Router3을 통한 우회가 가능하나 대역폭이 제한적입니다.",
                    "answer_type": "long",
                    "simulation": simulation_conditions
                }
            ]
        
        elif case_name == "interface_failure":
            samples = [
                {
                    "question": "인터페이스 장애로 영향받는 서비스 수는?",
                    "answer": "2개 서비스",
                    "answer_type": "short",
                    "simulation": simulation_conditions
                }
            ]
        
        elif case_name == "partial_ssh_failure":
            samples = [
                {
                    "question": "SSH 접근 불가 장비에서 설정 변경 방법은?",
                    "answer": "콘솔 포트를 통한 직접 접근 또는 대역외 관리 네트워크(OOBM)를 활용해야 합니다.",
                    "answer_type": "long",
                    "simulation": simulation_conditions
                }
            ]
        
        else:
            # 기본 케이스
            samples = [
                {
                    "question": "네트워크 상태가 정상인가?",
                    "answer": "예",
                    "answer_type": "short"
                }
            ]
        
        return {
            "case_name": case_name,
            "description": case_config.get("description", ""),
            "samples": samples,
            "simulation_conditions": simulation_conditions
        }
    
    def _print_sample_questions(self, samples: List[Any], title: str):
        """샘플 질문 출력"""
        logger.info(f"\n--- {title} 샘플 ---")
        for i, sample in enumerate(samples):
            if hasattr(sample, 'question'):
                q = sample.question
                a = sample.answer
                t = sample.answer_type
            else:
                q = sample.get('question', '')
                a = sample.get('answer', '')
                t = sample.get('answer_type', 'unknown')
            
            logger.info(f"{i+1}. Q: {q}")
            logger.info(f"   A: {a} ({t})")
    
    def _print_dataset_summary(self, dataset: Dict[str, Any]):
        """데이터셋 요약 출력"""
        metadata = dataset.get("metadata", {})
        
        logger.info("\n=== 최종 데이터셋 요약 ===")
        logger.info(f"총 샘플 수: {metadata.get('total_samples', 0)}")
        logger.info(f"Train: {len(dataset.get('train', []))}")
        logger.info(f"Validation: {len(dataset.get('validation', []))}")
        logger.info(f"Test: {len(dataset.get('test', []))}")
        logger.info(f"카테고리: {metadata.get('categories', [])}")
        logger.info(f"복잡도: {metadata.get('complexities', [])}")
        
        # 파이프라인 단계별 결과
        pipeline_results = metadata.get('pipeline_results', {})
        logger.info("\n파이프라인 단계별 결과:")
        for stage, result in pipeline_results.items():
            if isinstance(result, dict) and result.get('success'):
                logger.info(f"  {stage}: ✓")
            else:
                logger.info(f"  {stage}: ✗")


def main():
    """메인 데모 실행 함수"""
    demo = NetworkDatasetDemo()
    
    print("네트워크 설정 테스트 데이터셋 생성 파이프라인 데모")
    print("=" * 60)
    
    try:
        # 1. 기본 파이프라인 데모
        print("\n1. 기본 파이프라인 데모")
        basic_result = demo.demo_basic_pipeline()
        
        # 2. Answer Type 분류 데모
        print("\n2. Short/Long Answer 분류 데모")
        classification_accuracy = demo.demo_answer_type_classification()
        
        # 3. 네트워크 도메인 평가 데모
        print("\n3. 네트워크 도메인 특화 평가 데모")
        domain_score = demo.demo_network_domain_evaluation()
        
        # 4. 평가 프로필 데모
        print("\n4. 다중 평가 프로필 데모")
        evaluation_profiles = demo.demo_evaluation_profiles()
        
        # 5. incount 케이스 확장 데모
        print("\n5. incount 케이스 확장 데모")
        case_results = demo.demo_incount_cases()
        
        # 최종 요약
        print("\n" + "=" * 60)
        print("데모 완료 요약:")
        print(f"- 기본 데이터셋: {basic_result['metadata']['total_samples']}개 샘플")
        print(f"- Answer Type 분류 정확도: {classification_accuracy:.1%}")
        print(f"- 네트워크 도메인 평가 점수: {domain_score:.3f}")
        print(f"- 평가 프로필: {len(evaluation_profiles)}개")
        print(f"- 확장 케이스: {len(case_results)}개")
        print("\n모든 결과는 'demo_output' 디렉토리에 저장되었습니다.")
        
    except Exception as e:
        print(f"데모 실행 중 오류: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    main()
