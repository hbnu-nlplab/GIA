# IEEE TNSM 논문 Figure 계획

> 총 6~7개 Figure. IEEE 2-column 포맷에서 각 Figure는 약 0.3~0.5 페이지.

## 제작 도구 결정

| 도구 | 용도 | 장점 | 단점 |
|---|---|---|---|
| **matplotlib + seaborn** | Bar chart, Line chart (Fig.4,5,6) | Python에서 바로 생성, 재현성 | 다이어그램은 불편 |
| **draw.io (diagrams.net)** | 아키텍처, 파이프라인 (Fig.1,2,3) | GUI, 벡터 PDF 출력, 무료 | 자동화 불가 |
| **Mermaid → SVG** | 간단한 흐름도 | 코드 기반, 버전 관리 | 복잡한 레이아웃 어려움 |
| **LaTeX tikz** | 최종 논문 내 직접 | IEEE 스타일 일관 | 학습 곡선 높음 |

**추천 워크플로우:**
- Fig.1,2,3 (다이어그램): **draw.io** → PDF 내보내기
- Fig.4,5,6 (차트): **matplotlib** → PDF 저장 (make_figure.py 활용)
- 최종 LaTeX에서: `\includegraphics[width=\columnwidth]{fig1.pdf}`

---

## Figure 상세 계획

### Fig. 1: 전체 프레임워크 개요
- **위치**: Section I or III 첫 페이지
- **내용**: 왼쪽(데이터셋 생성) → 오른쪽(평가) → 아래(3-way 비교)
- **도구**: draw.io
- **크기**: 2-column 전체 폭 (`\begin{figure*}`)
- **요소**:
  - .cfg files → Dual-Path Pipeline → Dataset (9,462 QA)
  - 6 LLMs → TA-Acc Evaluation
  - Single LLM / Pure MAS / NetAlly → 3-Way Comparison
- **색상**: 파스텔 톤, 색맹 안전 팔레트 (Okabe-Ito)

### Fig. 2: Dual-Path QA 생성 파이프라인
- **위치**: Section III.B
- **내용**: Path A (L1-L3, 규칙) + Path B (L4-L5, 시뮬레이션)
- **도구**: draw.io
- **크기**: 1-column
- **요소**:
  - .cfg → Batfish Parser → Static Facts
  - Path A: policies.json → Scope Expansion → L1-L3 QA
  - Path B: traceroute/fork_snapshot → L4-L5 QA
  - Dataset Assembler → CSV/JSON

### Fig. 3: NetAlly 3-Plane 아키텍처
- **위치**: Section IV.B
- **내용**: Orchestrator-Executor + 3 Planes + ReAct Loop
- **도구**: draw.io
- **크기**: 1-column
- **요소**:
  - User Query → Orchestrator (Skill Selection)
  - → Executor (ReAct Loop, max 10 steps)
  - 3 Planes: PNETLab / NSO / Batfish
  - Error Recovery 경로
  - MCP Server (외부 에이전트 연동)

### Fig. 4: 레벨별 TA-Acc — L4 절벽 (핵심!)
- **위치**: Section V.B
- **내용**: 6모델 × 5레벨 Grouped Bar Chart
- **도구**: matplotlib + seaborn
- **크기**: 1-column
- **스타일**:
  - X축: L1, L2, L3, L4, L5
  - Y축: TA-Acc (0.0 ~ 1.0)
  - 6가지 색상 (모델별)
  - L3-L4 사이 점선 + "Simulation Barrier" 라벨
  - 흑백 인쇄 대비: 해칭 패턴 추가
- **코드**: `make_figure.py`에서 생성

### Fig. 5: 3-Way 비교 — 구조 vs 도구
- **위치**: Section V.C
- **내용**: Single / Pure MAS / NetAlly × 5레벨
- **도구**: matplotlib
- **크기**: 1-column
- **스타일**:
  - 3그룹 × 5레벨 Grouped Bar
  - Δ(구조)와 Δ(도구) 화살표 표시
  - L4/L5에서 "Single ≈ Pure MAS << NetAlly" 패턴 강조

### Fig. 6: Scalability — 노드 수 vs TA-Acc
- **위치**: Section V.B 또는 VI.C
- **내용**: Best 모델의 레벨별 성능 × 4 Labs
- **도구**: matplotlib
- **크기**: 1-column
- **스타일**:
  - X축: 10, 20, 30, 40 (노드 수)
  - Y축: TA-Acc
  - 5개 선 (L1~L5)
  - L1은 평탄, L4/L5는 낮게 유지

### Fig. 7 (선택): 5단계 인지 난이도 시각화
- **위치**: Section III.C
- **내용**: L1→L5 계단식 + Simulation Barrier
- **도구**: draw.io
- **크기**: 1-column

---

## 제작 순서

1. 실험 결과 나오기 전: Fig.1, Fig.2, Fig.3 (다이어그램) — draw.io
2. 실험 결과 나온 후: Fig.4, Fig.5, Fig.6 (차트) — matplotlib
3. 시간 있으면: Fig.7 (난이도 시각화)

## 스타일 가이드

- **해상도**: 벡터 PDF (래스터 금지)
- **폰트**: 10pt 이상 (IEEE 2-column에서 읽히려면)
- **색상**: Okabe-Ito 색맹 안전 팔레트
  - #E69F00 (주황), #56B4E9 (하늘), #009E73 (초록)
  - #F0E442 (노랑), #0072B2 (파랑), #D55E00 (빨강)
  - #CC79A7 (핑크), #000000 (검정)
- **흑백 대비**: 해칭 패턴 (///, \\\\, xxx, ooo) 병행
- **캡션**: self-contained (본문 없이 이해 가능)
- **번호**: Fig. 1 ~ Fig. 6 (또는 7)
