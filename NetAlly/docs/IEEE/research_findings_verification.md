# 외부 벤치마크 검증 방법론 조사 결과 (Research Findings)

"다른 S급 논문들은 Ground Truth를 어떻게 검증했는가?"에 대한 조사 결과입니다.

> 이 문서는 **Ground Truth 검증 방법론 레퍼런스**를 정리한 자료입니다.  
> `run_dataset_pipeline.sh` 기반 데이터 품질 검증(스키마/ID/evidence)과는 목적이 다릅니다.

---

## 1. TeleQnA (2023)
> **분야**: 통신 도메인 지식 (3GPP 표준 등)  
> **검증 방식**: **Human Verification (전문가 검증)**

- **방법**: 
  - GPT-3.5/4로 10,000개 문제 자동 생성.
  - **통신 분야 전문가(박사급)**가 샘플을 직접 검수하여 정답 여부 확인.
  - "Automated generation followed by expert verification"이라고 명시.
- **시사점**: 
  - 자동 생성된 데이터라도 **"전문가가 직접 로직을 확인했다"**는 문장이 있으면 신뢰도를 얻음.
  - 우리의 **Method 2 (Metric-wise Manual Check)**의 강력한 레퍼런스.

---

## 2. NetConfEval (ACM CoNEXT 2024)
> **분야**: LLM 기반 네트워크 설정 자동 생성  
> **검증 방식**: **Batfish Oracle (시뮬레이션 검증)**

- **방법**:
  - LLM이 생성한 설정 파일을 **Batfish**에 넣어서 문법/동작 검증.
  - Batfish 결과를 **"Ground Truth Oracle"**로 간주함.
  - 별도의 실장비 검증(Physical Lab)은 수행하지 않음.
- **시사점**: 
  - **Batfish 자체가 이미 학계에서 "신뢰할 수 있는 검증 도구(Oracle)"로 인정받고 있음.**
  - 따라서 Batfish를 썼다는 것 자체는 공격 대상이 아님.
  - 다만 우리는 **"Batfish로 만들고 Batfish로 검증"**하는 순환 논리가 문제이므로, **"Batfish 안 쓰는 독립 파서(Method 1)"**가 필요한 것.

---

## 3. NIKA (ACM SIGCOMM NGNO 2025)
> **분야**: 네트워크 장애 진단/Troubleshooting  
> **검증 방식**: **Environment Telemetry (환경 진실)**

- **방법**:
  - "Incident Specification" (장애 명세서)에 따라 네트워크 환경을 구축.
  - **환경에서 발생하는 실제 Telemetry 정보**를 Ground Truth로 정의.
  - Agent가 추론한 결과와 실제 환경 상태(State)를 비교.
- **시사점**:
  - 가장 이상적이고 강력한 검증. "실제로 그렇게 동작하니까"라는 논리.
  - 우리의 **Method 3 (PNETLab Real-world Check)**가 이 접근법을 따름.

---

## 4. Code Generation Benchmarks (HumanEval 등)
> **분야**: 일반 코드 생성  
> **검증 방식**: **Execution-based (실행 검증)**

- **방법**:
  - 텍스트 매칭(BLEU score)을 버리고, 생성된 코드를 **실제 실행(Execute)**하여 테스트케이스 통과 여부 확인.
  - "코드는 실행되어야 의미가 있다"는 철학.
- **시사점**:
  - 우리의 **"Behavioral Inference"** (텍스트 비교가 아닌, 동작 결과 비교) 철학을 뒷받침하는 배경 이론.

---

## 🔑 결론: 우리의 Hybrid Strategy는 "Best of All Worlds"

우리의 전략은 위 3가지 연구의 장점을 모두 취했습니다.

1.  **독립 파서 (Method 1)**: NetConfEval의 Batfish 의존성을 극복 (Batfish 안 씀)
2.  **수동 로직 검증 (Method 2)**: TeleQnA의 전문가 검증 방식 차용 (로직 확인)
3.  **실환경 검증 (Method 3)**: NIKA의 환경 기반 검증 방식 계승 (Real-world Validity)

이 정도 레퍼런스와 논리면 리뷰어도 "검증에 진심이구나"라고 인정할 수밖에 없습니다.
