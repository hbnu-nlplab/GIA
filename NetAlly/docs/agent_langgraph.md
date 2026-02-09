# LabMate Agent (LangGraph) Spec (v1.0)

LabMate 에이전트의 핵심은 “모델 지식”이 아니라:
- 상태(State) 관리
- 도구 호출(Tools)
- 근거(Evidence) 구성
- 안전 게이트(Safety Gate)
다.

LangGraph는 노드/엣지로 워크플로우를 구성하고, 상태를 메시지 패싱으로 관리한다. :contentReference[oaicite:14]{index=14}

---

## 1) Agent Principles

1) Evidence-first: 모든 답변은 Evidence Pack 링크를 포함
2) Tool-driven: Batfish/Collector/Logs/NSO 도구 호출이 ‘정답 생성’의 기반
3) Safe execution: 변경 계열은 승인 없이 실행하지 않음
4) Model-agnostic: Local/API 교체 가능하도록 LLM 인터페이스 추상화

---

## 2) Graph State (권장 스키마)

State는 실행 동안 유지되며,
메시지 리스트는 reducer(`operator.add`)로 append하는 패턴이 권장된다. :contentReference[oaicite:15]{index=15}

예시 필드:
- `messages`: 대화 메시지 목록
- `lab_context`: lab_id, snapshot_id, mode(strict/compat)
- `selection`: selected_nodes, selected_link
- `plan`: tool-call 계획(DAG)
- `evidence`: evidence refs (run_id, cards[])
- `risk`: action 위험도(read/diagnose/change)
- `llm_route`: local/api/hybrid 결정 결과

---

## 3) Node Design (권장)

### N1. Intent Parser
입력을 분류:
- reachability / trace / policy / diff / troubleshoot / onboard

### N2. Planner
필요한 tool-call 순서를 생성.
- “정적 workflow”는 고정 DAG로,
- “진단”은 분기/루프(조건 엣지) 허용.

LangGraph는 분기/루프/워크플로우 패턴을 지원하며,
워크플로우 vs 에이전트 구분도 가이드한다. :contentReference[oaicite:16]{index=16}

### N3. Tool Executor
Tool Catalog 예:
- `snapshot.refresh(mode=UNL|ZIP)`
- `batfish.query(type, params)`
- `logs.search(pattern, range)` (옵션)
- `probe.ping/traceroute` (옵션)
- `nso.readonly.list_devices` (옵션)

### N4. Evidence Assembler
툴 결과를 표준 Evidence Card로 변환:
- title
- summary(1~2줄)
- key tables/paths
- supporting config lines
- rerun action params

### N5. Answer Writer
답변 템플릿 강제:
- 1줄 결론
- 근거 카드 Top3
- 다음 액션 버튼

### N6. Safety Gate
- `risk=change` 혹은 `nso.push` 등은 “승인 토큰” 없으면 중단
- Plan preview를 생성하고 UI에 전달

---

## 4) Tool-call Mapping (UI ↔ Agent)

UI 원클릭 액션은 Agent 노드를 직접 호출할 수 있다:
- 버튼 클릭 → `Intent=reachability` → Planner/Executor → Evidence → UI 카드 렌더
- 채팅은 “Explain last evidence”, “Suggest next step”로 이어짐

---

## 5) LLM Runtime Abstraction

단일 인터페이스 권장:
- `LLM.generate(task, evidence, constraints) -> response`

Hybrid일 경우:
- 민감도 스캐너가 payload를 분류(see `docs/security.md`)
- local/api route 결정 후 동일 인터페이스로 호출

---

## References
- LangGraph Graph API overview / state, nodes, edges :contentReference[oaicite:17]{index=17}
- LangGraph state reducer(operator.add) 패턴 :contentReference[oaicite:18]{index=18}
- LangGraph workflows vs agents :contentReference[oaicite:19]{index=19}
