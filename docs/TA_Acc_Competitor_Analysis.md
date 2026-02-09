# Competitor Dataset Analysis (3 Slides)

## Slide 1: TeleQnA - Telecom Standards Knowledge Benchmark
### 1. Dataset Overview
- **데이터 출처**: 3GPP, IEEE 표준 문서 및 연구 논문 (Research Papers)
- **규모**: 10,000 Questions
- **형식**: Multiple Choice Questions (객관식 5지 선다)
- **평가 지표**: Accuracy (정답 선택 여부)

### 2. NetConfigQA2.0 vs TeleQnA
| Feature | TeleQnA (Competitor) | NetConfigQA2.0 (Ours) |
|:---|:---|:---|
| **지식의 성격** | **Theoretical Knowledge** (이론 지식) <br> "프로토콜의 정의가 무엇인가?" | **Operational Knowledge** (운영 지식) <br> "현재 라우팅 테이블에서 패킷은 어디로 가는가?" |
| **활용 데이터** | 텍스트 기반 표준 문서 (Text Corpus) | **실제 장비 설정 파일 (Running-Config)** |
| **검증 한계** | 이론은 알지만 실제 **설정 오류(Misconfiguration)**는 탐지 불가능 | 실제 장비의 **논리적 상태와 설정 오류**를 정확히 검증 가능 |

### 3. Key Takeaway
> "TeleQnA가 **네트워크 전공 필기 시험**이라면, NetConfigQA는 **실무 엔지니어의 실기 시험**입니다."

---

## Slide 2: TeleQuAD - RAG & Information Extraction
### 1. Dataset Overview
- **데이터 출처**: 3GPP Technical Specifications (TS 시리즈)
- **규모**: 약 4,500 QA Pairs
- **형식**: Extractive QA (SQuAD Style) - 지문에서 정답 구간 추출
- **평가 지표**: Exact Match (Text), F1 Score

### 2. NetConfigQA2.0 vs TeleQuAD
| Feature | TeleQuAD (Competitor) | NetConfigQA2.0 (Ours) |
|:---|:---|:---|
| **문제 해결 방식** | **독해 (Reading Comprehension)** <br> 문서 내 텍스트 찾기 | **추론 (Logical Reasoning)** <br> 여러 설정 간의 상호작용 계산 (Route + ACL + NAT) |
| **정답의 속성** | 정적 텍스트 (Static Text Span) | **동적 상태 값 (Dynamic State)** <br> "Result: Dropped by ACL 101" |
| **한계점** | 문서에 없는 **복합적인 장애 상황**에 대한 진단 불가 | 네트워크 **Topology와 Policy**를 이해해야만 풀 수 있는 문제 제공 |

### 3. Key Takeaway
> "TeleQuAD는 **매뉴얼 검색** 능력에 집중하지만, NetConfigQA는 **네트워크 문제 해결** 능력에 집중합니다."

---

## Slide 3: NetBench - Descriptive Scenario Analysis
### 1. Dataset Overview
- **데이터 출처**: 통신사/벤더 SME(전문가) 및 Digital Twin 시뮬레이션
- **규모**: 5,390 QA Pairs
- **형식**: Descriptive QA (서술형 답변) 및 Text Generation
- **평가 지표**: BERTScore, ROUGE (Text Similarity)

### 2. NetConfigQA2.0 vs NetBench
| Feature | NetBench (Competitor) | NetConfigQA2.0 (Ours) |
|:---|:---|:---|
| **평가 방식** | **Text Similarity** (유사도 평가) <br> "얼마나 그럴듯하게 설명했는가?" | **TA-Acc (Functional Correctness)** <br> "실제 결과값과 일치하는가?" |
| **할루시네이션** | 언어적 유사성만 높으면 **거짓 정보(Hallucination)**도 점수 획득 가능 | 잘못된 값(Value)이나 경로(Path)는 **0점 처리** (Strict Evaluation) |
| **자동화 여부** | 인간 전문가(SME)의 개입이 필수적 (Scalability 낮음) | **Batfish 시뮬레이션** 기반으로 데이터 무한 확장 및 자동 검증 가능 |

### 3. Key Takeaway
> "NetBench는 **설명 능력**을 평가하지만, TA-Acc는 **결과의 진실성(Ground Truth)**을 검증합니다."
