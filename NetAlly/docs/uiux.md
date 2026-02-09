# LabMate UI/UX Spec (v1.0)

LabMate의 UI는 “챗봇”이 아니라 **조종석(Cockpit)** 이다.
채팅은 “해설/추천/다음 액션”을 담당하는 보조 패널로 설계한다.

---

## 1) Layout: Cockpit + Chat Drawer

### (A) Top Bar (Context Bar)
- Lab: 현재 랩 이름/ID
- Snapshot: timestamp + 모드(Strict/Compat)
- LLM Mode: Local / API / Hybrid
- Buttons:
  - Refresh Snapshot (Primary)
  - Run Health Check (Network/API)
  - Export Report (Markdown/PDF)

### (B) Left Panel: Topology Mini-map
- UNL 정밀 모드일 때:
  - 노드 좌표(x,y) 기반으로 “PnetLab과 유사한 배치” 표현
- Zip 호환 모드일 때:
  - 좌표는 없을 수 있으므로 “논리 토폴로지/리스트”로 대체

노드/링크 클릭 시:
- 우측 패널의 추천 액션이 컨텍스트를 자동 반영
- 채팅의 Context Chips도 자동 갱신

### (C) Right Panel: Action + Evidence Timeline
- 상단: One-click Actions (고정 5개)
- 하단: Evidence Timeline (실행 기록, 클릭하면 상세)

---

## 2) One-click Actions (v1 고정 세트)

1) Reachability (A → B)
2) Path Trace (Hop-by-hop)
3) Policy / ACL 영향 분석
4) Snapshot Diff (Before/After 영향)
5) (옵션) Onboard / Sync (NSO 연결이 켜졌을 때만)

각 액션 실행 결과는 Evidence Pack으로 저장되고,
Timeline에 카드로 누적된다.

---

## 3) Evidence Pack UI (핵심)

각 결과 카드는 다음 정보를 가진다:
- 결론(1줄)
- 근거(표/경로/규칙) “Top 3”
- 재현 버튼:
  - Re-run same query
  - Open related config lines
  - Compare with baseline

---

## 4) Chat Drawer Spec

채팅은 오른쪽 Drawer로 제공하고, 기본은 접혀있다.

### 4.1 Context Chips (항상 표시)
- Lab, Snapshot, Mode, Selected Nodes/Link

### 4.2 Attach Evidence (복붙 제거)
- “Attach Latest Evidence”
- “Attach Reachability Report”
- “Attach Diff Summary”
버튼 클릭으로 메시지에 요약/링크가 자동 첨부된다.

### 4.3 답변 템플릿(강제)
- 1) 한 줄 결론
- 2) 근거 카드 3개(클릭 가능)
- 3) 다음 액션 버튼 1~3개

### 4.4 Safety Gate (승인 UX)
- 조회/진단은 즉시 실행 가능
- 변경/푸시/등록은 승인(Confirm) 없이는 실행 금지
- 승인 UX:
  - “Plan Preview” → “Confirm Apply” → “Audit log 기록”

---

## 5) First Screen (처음 접속 시)

- Current Lab Status
  - 스냅샷 신선도(최근 업데이트)
  - 모드(Strict 가능/불가)
  - Port Name Mapper 상태(적용됨/추정/미완)
- Quick Start
  - Refresh Snapshot
  - Run Reachability
  - Open Chat (Explain last result)

---

## 6) UX Principles

- “질문하기 전에 클릭으로 상태 확보”를 유도
- 사용자가 가장 싫어하는 것:
  - 복붙
  - 근거 없는 답
  - ‘지금 뭘 기준으로 말하는지’ 불명확
- 따라서:
  - Context Bar/Chips로 기준을 항상 노출
  - Evidence Pack으로 “왜?”를 즉시 해결
  - 액션 버튼으로 “다음은?”을 즉시 해결

---

## References
- (UI 내부 원칙은 LabMate 설계 기준이며, 외부 표준 참고는 Architecture/Agent/Security 문서 참조)
