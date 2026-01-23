# NetConfigQA3: 대규모 네트워크를 위한 에이전트 시스템

> **발표 목적**: 랩미팅 발표용 핵심 요약  
> **날짜**: 2026-01-07  
> **대상**: SIGCOMM 제출

---

## 1. 문제 정의

### NetConfigQA2의 한계

**100대 규모에서 컨텍스트 폭발 발생**

| 문제                         | 영향           |
| ---------------------------- | -------------- |
| 모든 Facts를 프롬프트에 주입 | 토큰 한계 초과 |
| LLM이 전체 정보 기억 불가    | 정확도 저하    |
| 32개 API를 직접 노출         | 도구 선택 혼란 |

### 해결 방향

**Facts를 "프롬프트"에서 "질의 가능한 메모리"로 전환**

- **NetConfigQA2**: 전체 Facts를 LLM 프롬프트에 주입 (컨텍스트 폭발)
- **NetConfigQA3**: LLM이 필요할 때마다 Facts DB에 질의 (필요한 것만 가져옴)

---

## 2. 시스템 아키텍처

### 4-Layer 구조

**Layer 1: Agent Layer**

- **Reasoner**: 주어진 증거를 바탕으로 추론 및 판단 수행
- **Retriever**: 질문에 필요한 증거를 수집하고 Evidence Pack 구성
- 두 에이전트가 분리되어 협력하는 구조

**Layer 2: HITL (Human-in-the-Loop) Layer**

- **Approval Gate**: 위험한 작업(commit, rollback 등)에 대한 승인 게이트
- **Checkpoints**: 10단계 Runbook 중간에 사람이 개입할 수 있는 체크포인트
- **Alerts**: 실시간 알림 시스템

**Layer 3: Query Tools Layer**

- 5~8개의 통합 질의 인터페이스만 LLM에 노출
  - `facts.query()`: 정적 설정 정보 질의
  - `batfish.query()`: 네트워크 분석 수행
  - `batfish.diff()`: 변경 전후 비교
  - `nso.get()`: 장비 상태 조회
  - `nso.txn()`: 설정 변경 (승인 필요)
  - `logs.query()`, `metrics.query()`: 동적 관측 데이터 질의

**Layer 4: Data Layer**

- **Static Facts DB**: 설정 파일에서 추출한 정적 정보 (device, interface, vrf, bgp 등)
- **Dynamic Telemetry Store**: 로그 이벤트, 메트릭 윈도우, 플로우 요약 등 시간축 데이터

### 레이어별 역할 요약

| 레이어          | 구성요소                           | 역할                        |
| --------------- | ---------------------------------- | --------------------------- |
| **Agent**       | Reasoner, Retriever                | 추론과 증거 수집 분리       |
| **HITL**        | Approval Gate, Checkpoints, Alerts | 안전 장치 + 실시간 모니터링 |
| **Query Tools** | 5~8개 통합 인터페이스              | 도구 표면적 최소화          |
| **Data**        | Static Facts + Dynamic Telemetry   | 정적/동적 데이터 분리       |

---

## 3. 핵심 설계 원칙

### 원칙 1: 계층적 정보 제공 (지도 기반 탐색)

**Level 1: 네트워크 지도** (수십 줄, 상시 보유)

- 장비 수 및 역할 (PE/P/Leaf/Spine)
- VRF 목록, AS 번호
- 중요 서비스 목록
- 사용 가능한 도구 카탈로그

**Level 2: Evidence Pack** (수백~천 토큰, 선택적 가져옴)

- 질문에 직접 관련된 정보만 포함
- 예: "pe1의 VRF_AI RT는?"라는 질문에는 pe1의 VRF_AI 정보만 가져옴

**효과**: 평소엔 "지도"만 들고 다니다가, 질문 시 필요한 정보만 선택적으로 로드하여 **컨텍스트 절약**

### 원칙 2: 데이터 저장소 분리

**Static Facts DB**

- 설정 파일(CFG)에서 추출한 구조적 사실
- VRF, BGP neighbor, ACL, 인터페이스 주소 등
- 스냅샷 기반으로 관리

**Dynamic Telemetry Store**

- 시간축 데이터 (로그/메트릭/플로우)
- 계속 변하는 활성 데이터
- 시간 조건이 필수

**핵심**: 저장소는 분리하되, **Evidence Pack 출력 포맷은 통일**하여 Reasoner가 일관되게 소비할 수 있도록 함

### 원칙 3: 도구 표면적 최소화 (메가툴 패턴)

**LLM에게는 5~8개의 통합 도구만 노출**

- 내부적으로는 수십 개의 함수가 있지만 LLM은 소수의 메가툴만 봄
- 예: `batfish.query(name, params)` 하나로 수십 가지 Batfish 분석 수행 가능
- 내부 템플릿 레지스트리에서 `name`에 따라 적절한 분석 수행

**효과**: 도구 선택 오류 방지, 무한 확장 가능 (템플릿 추가만으로)

---

## 4. 멀티에이전트 구조

### Reasoner - Retriever 분리

**Reasoner Agent (추론자)**

- Evidence Pack만 보고 판단 및 검증
- 추가 질의 없이 주어진 증거로만 결론 도출
- 추론에만 집중

**Retriever Agent (사서)**

- 증거팩을 구성하는 역할
- Facts DB, Batfish, Telemetry Store에 질의
- Evidence Pack 상한 준수 (로그 30개, 메트릭 20개, Facts 40개)
- 캐시 우선 정책 적용
- 추가 질의 1회 제한 (무한 탐색 방지)

**협력 방식**

1. Reasoner가 Retriever에게 "증거 요청"
2. Retriever가 필요한 데이터를 수집하여 "Evidence Pack 반환"
3. Reasoner가 Evidence Pack 기반으로 결론 도출

---

## 5. Human-in-the-Loop (HITL)

### 10단계 Runbook + 체크포인트

**진행 흐름**

1. **[0] 목표 확정** → **[1] 범위 추정** → **[2] 증거 v1**
2. **[✓ 체크포인트 1]**: 초기 증거 검토
3. **[3] 가설 생성** → **[4] 증거 v2**
4. **[✓ 체크포인트 2]**: 가설 검증
5. **[5] 변경안 초안** → **[6] Dry-run**
6. **[✓ 체크포인트 3]**: ⭐ **가장 중요** - 변경 전 검증
7. **[7] Batfish Diff** → **[8] 최종 제안서**
8. **[⚠️ 승인 게이트]**: 사용자 승인 필요
9. **[9] Commit** (승인 후만 실행)
10. **[10] 사후 검증** (이상 시 롤백)

### 승인 게이트 제시 내용

- 변경 내용 (Diff)
- 위험도 (Risk Level)
- 영향 범위 (영향받는 장비 및 서비스)
- 롤백 방법 (Rollback ID)

### 승인 필요 작업 분류

| 분류                | 작업                                                    | 승인                      |
| ------------------- | ------------------------------------------------------- | ------------------------- |
| **High-Risk**       | commit, rollback, sync-to, 대량 변경 (N대 이상)         | ⚠️ 필수 승인              |
| **Critical (거부)** | any-any permit, 무단 default route 추가, 전체 BGP reset | ❌ 절대 불허              |
| **Low-Risk**        | Batfish 쿼리, Facts 읽기, 상태 조회                     | ✅ 자동 승인 (Rate-limit) |

### Rollback 시스템

- NSO가 변경 적용 시 자동으로 Rollback 파일 생성 (예: Rollback #12345)
- 문제 발생 시 Agent가 해당 Rollback ID로 즉시 복구
- Git (설계/코드 버전관리) vs NSO Rollback (운영 상태 복구) 역할 분담

---

## 6. 실험 설계

### 3축 프레임워크

**축 A: 정적 QA (텍스트 기반)**

- **A-1: NetConfigQA2**
  - Facts DB + Retriever 사용
  - Evidence Pack 구성
  - 컨텍스트 전략 효과 측정
- **A-2: 외부 벤치마크**
  - NetBench (5.4k 질문)
  - TeleQnA (10k 질문)
  - TeleQuAD (4.5k 질문)
  - Facts DB 없이 순수 MAS 추론 성능 측정

**축 B: 동적 트러블슈팅 (상호작용 환경)**

- **NIKA (Network Arena)**
  - 동적 네트워크 트러블슈팅 아레나
  - 평가 지표: 진단 성공률, TTR (Time To Resolve), 툴 호출 수, 위험 행동률

**축 C: 운영 실천성 (핵심 기여)** ⭐

- **NetConfigQA3 (Task 중심 벤치마크)**
  - 실행 기반 자동 채점 (Batfish Verifier)
  - Correctness / Safety / Efficiency 동시 측정
  - NetConfEval / NetPress 보완

### NetConfigQA2 → NetConfigQA3 전환

**NetConfigQA2: 질문 템플릿 방식**

- Question: "A에서 B로 통신 가능한가?"
- Answer: "Yes" 또는 "No"
- 평가: 텍스트 일치 (EM/F1)

**NetConfigQA3: Task 템플릿 방식**

- Task Spec 구성:
  - `initial_snapshot`: 초기 네트워크 상태 (S0)
  - `target_goal`: 달성해야 할 목표 (예: reachability(A→B)=True)
  - `hard_constraints`: 절대 위반하면 안 되는 제약 (예: 금지 트래픽 유지)
  - `oracle_checks`: 성공 여부를 자동 검증하는 Batfish 쿼리
  - `budget`: 제한 사항 (max_tool_calls: 20)
- 평가: 실행 결과 검증 (Verifier)

### 자동 데이터셋 생성 파이프라인

1. **베이스 스냅샷 풀**: pnetlab 랩 XML → CFG 변환
2. **태스크 샘플링**: 질문 템플릿 선택
3. **결함 주입 (Fault Injection)**:
   - ACL 추가/삭제
   - VRF RT 오류
   - BGP neighbor 오류
   - Interface shutdown
4. **Oracle Checks 자동 생성**: Batfish 쿼리로 "성공 조건" 정의
5. **Task Spec 완성**: goal + constraints + oracle_checks + budget

### 채점 시스템 (3축)

**1. Correctness (정확성)**

- Goal Checks: Batfish로 목표 달성 여부 검증
  - Reachability 확인
  - Blackhole 없음
  - Loop 없음
- 평가: 모든 goal 통과 시 1.0, 일부 통과 시 0.5

**2. Safety (안전성)**

- Invariant Checks: 불변 조건 위반 검사
  - 금지 트래픽 유지
  - VRF 격리 유지
  - any-any permit 금지
- 평가: 위반 시 감점 또는 즉시 fail

**3. Efficiency (효율성)**

- 측정 지표:
  - tool_calls: 도구 호출 횟수
  - tokens_in/out: 토큰 사용량
  - wall_clock: 소요 시간
  - cache_hit_rate: 캐시 히트율
- 평가: 효율 스코어 계산

**핵심**: LLM-as-a-judge 사용 안 함, 결정적 Verifier만 사용 → 재현성 + 공정성 확보

### Ablation Study 대상

| 구성요소           | 비교                    | 측정                     |
| ------------------ | ----------------------- | ------------------------ |
| Retriever          | 없음 vs 있음            | Context 효율, 정확도     |
| Cache              | 없음 vs 있음            | 툴 호출 수, 지연         |
| Mega-tool          | 개별 노출 vs 통합       | 도구 선택 오류율         |
| 승인 게이트        | on vs off               | 위험 행동률, Safety 점수 |
| Evidence Pack 상한 | 제한 없음 / 중간 / 엄격 | 토큰 대비 정확도         |

### Trade-off Curve 분석 목표

**핵심 메시지**:

- **"같은 성능을 더 싸게"**: MAS + Retriever + Cache 조합이 단일 에이전트 대비 적은 비용으로 같은 성공률 달성
- **"같은 비용에서 더 안전하게"**: 같은 툴 호출 수/토큰 예산 내에서 더 높은 안전 점수 달성

**비교 구성**:

- Single-agent (기본)
- MAS only
- MAS + Retriever
- MAS + Retriever + Cache (최고 성능)

---

## 7. 핵심 주장 (SIGCOMM)

### 주장 A (Task 벤치마크)

> **NetConfigQA3에서, 실행 기반 검증(Verifier) + 승인 게이트 + 롤백이 결합된 MAS가 Correctness / Safety / Efficiency를 동시에 달성한다.**

### 주장 B (효율성)

> **동적 관측(이벤트/집계)을 Evidence Pack으로 통제하면, 같은 성공률을 더 적은 툴 호출 / 토큰 / 시간으로 달성한다.**

---

## 8. 핵심 요약 (한눈에 보기)

### 설계 4대 원칙

| 원칙                 | 전략                                     | 효과                |
| -------------------- | ---------------------------------------- | ------------------- |
| **지도 기반 탐색**   | Level 1 (지도) + Level 2 (Evidence Pack) | 컨텍스트 절약       |
| **데이터 저장 분리** | Static Facts DB + Dynamic Telemetry      | 질의 효율화         |
| **도구 표면적 축소** | 5~8개 메가툴 + 템플릿 레지스트리         | 도구 선택 오류 방지 |
| **멀티에이전트**     | Reasoner + Retriever 분리                | 증거 수집 효율화    |

### HITL 4대 구성요소

| 구성요소           | 역할             | 핵심                   |
| ------------------ | ---------------- | ---------------------- |
| **승인 게이트**    | 파괴적 행동 차단 | commit 필수 승인       |
| **10단계 Runbook** | 중간 개입 지원   | 4개 체크포인트         |
| **실시간 알림**    | 이상 감지        | 노이즈 제거 파이프라인 |
| **Rollback**       | 안전한 되돌리기  | NSO rollback 파일      |

### 실험 3축

| 축                     | 벤치마크                                          | 평가                            |
| ---------------------- | ------------------------------------------------- | ------------------------------- |
| **A: 정적 QA**         | NetConfigQA2 + 외부 (NetBench, TeleQnA, TeleQuAD) | Accuracy, Context 효율          |
| **B: 동적 트러블슈팅** | NIKA                                              | TTR, 툴 호출, Safety            |
| **C: 운영 실천성** ⭐  | NetConfigQA3 (Task)                               | Correctness, Safety, Efficiency |

---

## References

- [SIGCOMM '26 CFP](https://conferences.sigcomm.org/sigcomm/2026/cfp/)
- [NIKA: Network Arena for AI Agents](https://arxiv.org/abs/2512.16381)
- [NetConfEval](https://dl.acm.org/doi/10.1145/3656296)
- [Batfish](https://www.usenix.org/system/files/conference/nsdi15/nsdi15-paper-fogel.pdf)
- [NSO Rollbacks](https://developer.cisco.com/docs/nso/guides/rollbacks/)
