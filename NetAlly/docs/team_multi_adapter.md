# Team Multi Adapter Guide

`team_multi_adapter`는 NetAlly 채팅 요청을 외부 `MultiAgent` 그래프로 전달하고, 결과를 NetAlly SSE 계약으로 변환하는 런타임이다.

---

## 1. 사용 목적

- NetAlly UI/백엔드 계약은 유지한 채로 팀 멀티에이전트 추론 경로를 붙이고 싶을 때 사용
- 프론트엔드는 기존처럼 `planning/tool_call/tool_output/answer`만 렌더하면 됨

---

## 2. 활성화 방법

### Settings API
`POST /api/settings`
```json
{
  "agent_backend": "team_multi_adapter"
}
```

### 환경 변수
```bash
export NETALLY_AGENT_BACKEND=team_multi_adapter
```

---

## 3. 주요 환경 변수

- `NETALLY_TEAM_MULTI_MODULE`
  - 기본: `agents.main_netconfig`
  - 설명: `MultiAgent` 루트 기준 Python 모듈 경로
- `NETALLY_TEAM_MULTI_DATASET_TYPE`
  - 기본: `netconfig`
  - 허용: `netconfig`, `descriptive`, `multiple_choice`, `short_answer`
- `NETALLY_TEAM_MULTI_ROOT`
  - 기본: `<repo>/MultiAgent`
  - 설명: 외부 MultiAgent 프로젝트 루트
- `NETALLY_TEAM_MULTI_CONTEXT_PATH`
  - 선택
  - 설명: 멀티에이전트 context로 주입할 텍스트 파일 경로
- `NETALLY_TEAM_MULTI_CONTEXT`
  - 선택
  - 설명: 인라인 context 문자열

---

## 4. 입출력 매핑

### NetAlly request -> MultiAgent state
- `message` -> `question`
- `answer_type` -> 질문 suffix (`[answer_type=...]`)
- `history` -> context fallback 생성에 사용

### context 결정 우선순위
1. 요청 본문의 `context`
2. `NETALLY_TEAM_MULTI_CONTEXT`
3. `NETALLY_TEAM_MULTI_CONTEXT_PATH`
4. `dataset_type=netconfig`면 `MultiAgent/data/original/netconfig/configs.txt`
5. history 변환 문자열
6. `[NONE]`

### MultiAgent result -> NetAlly answer
우선순위:
1. `final_answer`
2. `debate2_answer`
3. `answer`
4. `candidate_answer`

---

## 5. SSE 이벤트 예시

1. `planning`
```json
{
  "type": "planning",
  "mode": "team_multi_adapter",
  "agent_backend": "team_multi_adapter",
  "tool_backend": "team_multi",
  "module_name": "agents.main_netconfig",
  "dataset_type": "netconfig"
}
```

2. `tool_call`
```json
{
  "type": "tool_call",
  "tool": "team_multi_invoke",
  "input": {
    "module_name": "agents.main_netconfig",
    "dataset_type": "netconfig"
  }
}
```

3. `tool_output`
- adapter `ok/stage/error/meta` 요약 payload

4. `answer`
- 멀티에이전트 최종 답변 문자열

---

## 6. 의존성 주의사항

MultiAgent의 `USE_LOCAL=False`(기본 cloud/OpenRouter 경로)에서는 `torch/transformers`가 없어도 import 실패가 나지 않도록 보완되어 있다.  
로컬 모델 모드를 사용할 경우에는 별도 패키지(`torch`, `transformers`, `langchain_huggingface`) 설치가 필요하다.

---

## 7. 장애 대응

- 로딩 실패 시:
  - `answer`에 `team_multi_adapter 실행 실패(load): ...` 형태로 반환
- 실행 실패 시:
  - `answer`에 `team_multi_adapter 실행 실패(invoke): ...` 형태로 반환
- 즉시 롤백:
  - `agent_backend=single_executor` 또는 `agent_backend=legacy_graph`
