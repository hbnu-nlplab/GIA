# NetAlly 데모 Agent Flow (PNETLab 내부 배포 기준)

## 목적
빠른 데모를 위해 **수동 Bootstrap + 자동 Refresh/Prepare + 에이전트 질의** 흐름을 정리한다.

---

## 전제 조건 (PNETLab 내부 배포)
- NetAlly는 **PNETLab Docker 노드**로 실행
- NetAlly 노드와 장비 노드는 **같은 OOB Cloud 네트워크**에 연결
- NSO는 PNETLab 내부 또는 접근 가능한 동일 네트워크에 위치
- Batfish 컨테이너는 NetAlly와 같은 네트워크에서 접근 가능

---

## 데모 흐름 요약

### 1) 수동 Bootstrap (권장)
1. Settings에서 **OOB 인터페이스** 수동 입력  
2. Refresh 버튼 클릭 → 신규 장비만 부트스트랩  
   - 내부적으로 `lab_bootstrap(action="refresh_onboard")`
   - `device_info.json` 없으면 PNETLab API로 자동 생성

### 2) Batfish 준비
Prepare 버튼 클릭 → Batfish 준비 상태 확인  
가능한 상태:
- `ready`: Batfish 준비 완료
- `loaded`: 스냅샷 로드 완료
- `initialized`: 새 스냅샷 생성 완료
- `not_ready`: 스냅샷 없음
- `unavailable`: Batfish 서비스 미사용

### 3) 에이전트 질의
Batfish 준비 후 Chat Panel에서 질의 실행
- NSO 기반: `network_query`
- Batfish 기반: `network_verify`

---

## 자동화 동작 (UI 버튼)

### Refresh 버튼
- 신규 장비만 자동 부트스트랩
- 결과는 Dashboard와 Evidence에 기록

### Prepare 버튼
- Batfish 상태 확인
- 결과는 Dashboard와 Evidence에 기록

---

## 에이전트 플로우 (Backend)

- `AUTO_PREPARE_ON_CHAT=true`일 때:
  - Chat 요청 시 Batfish 준비 상태 확인
  - 준비 실패 시 안내 메시지 반환 후 종료

---

## 에이전트 질의 처리 상세 (Query Lifecycle)

### 0) 요청 입력
- `/api/chat`로 질문 수신 (UI는 `{ message }`만 전송)
- `history`, `answer_type`는 API가 받지만 UI에서는 미사용  
  → 현재는 `answer_type` 기본값(`text`)로 동작
- 초기 state 구성:
  - `question`, `answer_type`, `messages`, `selected_skills`, `enabled_tools`, `step_count` 등

### 1) (선택) Batfish 준비 게이트
- `AUTO_PREPARE_ON_CHAT=true`이면 `ensure_batfish_ready()` 실행
- 상태가 `unavailable/not_ready`면 안내 메시지를 SSE로 반환하고 종료
- `AUTO_INIT_BATFISH=true`면 `lab_manage(action="init_batfish")`로 스냅샷 생성 시도

### 2) Orchestrator (Skill 선택)
- 스킬 카탈로그(`skills/*/SKILL.md`)를 기반으로 **JSON 형식**으로 `selected_skills` 결정
- Orchestrator 출력은 정규식으로 JSON 객체 1개만 파싱
  - 파싱 실패 시 `core`만 사용
  - `core` 스킬은 항상 포함

### 3) Tool Filter
- 선택된 스킬의 `requires_tools`를 합산 → `enabled_tools` 생성
- Executor용 skill prompt는 **SKILL 본문 전체**가 포함됨

### 4) Executor (Tool 호출 루프)
- 활성화된 도구만 바인딩하여 LLM 호출
- LLM이 `tool_calls`를 생성하면:
  - SSE `tool_call` 이벤트 전송
  - ToolNode에서 실제 도구 실행
  - SSE `tool_output` 전송
  - 다시 Executor로 복귀 (루프)
- 도구 호출이 없으면 최종 답변 생성 → SSE `answer`
- 최대 루프 횟수: 10 (`step_count` 기반)
- `step_count >= 10`이면 강제 종료 (완료 플래그 없이 종료될 수 있음)

### 5) SSE 이벤트 흐름
1. `planning` (오케스트레이터 결과)
2. `tool_call`
3. `tool_output`
4. `answer`
5. `complete`

### 6) UI 반영 (ChatPanel)
- `planning` → 시스템 메시지
- `tool_call` → 시스템 메시지
- `tool_output` → Evidence 카드 생성
- `answer` → 최종 응답 표시
- `error` 이벤트는 UI에서 별도 처리하지 않음 (현재 무시됨)

---

## 실패/보호 로직
- Orchestrator JSON 파싱 실패 시 `core`만 사용
- Tool 호출 실패 시 `tool_output`에 오류 문자열이 그대로 전달
- Batfish 준비 실패 시 즉시 안내 메시지 반환
- `history`는 전달되더라도 Executor에 반영되지 않음

---

## 디버깅 포인트
- `agent/graph.py`: orchestrator/executor prompt와 루프
- `agent/tools.py`: 도구 호출 결과 및 에러 메시지
- `main.py`: SSE 이벤트 변환 및 Batfish 준비 게이트
- `frontend/ChatPanel.tsx`: Evidence 카드 생성/요약 로직
- `agent/skill_loader.py`: 스킬 로딩과 `requires_tools` 매핑

---

## 주요 API

| Endpoint | Method | 설명 |
| --- | --- | --- |
| `/api/lab/refresh` | POST | 신규 장비 부트스트랩 |
| `/api/lab/prepare` | POST | Batfish 준비 상태 확인 |
| `/api/pnetlab/status` | GET | PNETLab 인증 상태 |
| `/api/pnetlab/auth` | POST | PNETLab 인증 설정 |
| `/api/chat` | POST | 에이전트 채팅 |

---

## 필수 환경 변수 (요약)

### PNETLab
- `PNETLAB_URL`
- `PNETLAB_COOKIES` **또는** `PNETLAB_AUTO_LOGIN=true` + 계정 정보
- `PNETLAB_DEVICE_INFO` (자동 생성 가능)

### NSO
- `NSO_BASE_URL` **또는** `PNETLAB_NSO_NODE`(자동 탐색)
- `NSO_USER`, `NSO_PASS`

### Batfish
- `BATFISH_HOST`
- `BATFISH_SNAPSHOT`

---

## 알려진 제한
- PNETLab API 인증은 **필수**
- OOB 인터페이스 자동 매핑은 **미지원(수동 입력 권장)**
- 변경 감지는 **NSO check-sync** 기반
- UI는 `answer_type`, `history`를 사용하지 않음
