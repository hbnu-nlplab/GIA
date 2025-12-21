아주 좋아. 지금까지 완성한 NetConfigQA 파이프라인을 **“처음 보는 사람도 바로 이해하고, 그대로 실행/해석/확장할 수 있게”** 문서 형태로 정리해줄게. (네가 말한 _철학·규칙·원칙·사용법·결과 보는 방법·이전과의 차이_ 전부 포함)

---

# NetConfigQA 벤치마크 파이프라인 사용 설명서 (8차 기준)

## 1) 이 파이프라인이 무엇을 하냐

NetConfigQA는 **네트워크 장비 설정(cfg)** 을 입력으로 받고, 그 설정에서 “정확히 검증 가능한 사실값”을 묻는 QA를 만들어서 **LLM이 설정을 얼마나 제대로 읽고 이해하는지** 평가하는 벤치마크야.

핵심은 “정답을 사람이 쓰는 게 아니라”
**L1-L3(정적)는 Rule-based로 속도/직관성 확보, L4-L5(동적)는 Batfish로 네트워크 동작/구성을 분석해 계산한 결과를 정답으로 쓴다**는 점이야. Batfish는 스냅샷(snapshot)에 있는 장비 설정으로 네트워크 모델을 만들고, traceroute/reachability 같은 질의로 경로/도달성 등을 분석할 수 있어. ([batfish.readthedocs.io][1])

---

## 2) 데이터셋 생성 철학(원칙 6개)

### 원칙 A. “있는 것만 묻지 않는다” (Negative Testing 포함)

- 설정이 **있는 경우(OK)** 뿐 아니라,
- 설정이 **없는 경우(NOT_CONFIGURED)** 도 “없다”고 정확히 답해야 한다.
- 이게 네가 말한 목표(‘없는 것도 알아야 함’)의 핵심이야.
- 즉, **“모르면 대충 채우기/환각”을 잡아내는** 벤치마크다.

### 원칙 B. “정답은 텍스트가 아니라 구조(타입)다”

정답을 `"a, b, c"` 같은 자연어로 저장하면 평가가 고통스러워져.
그래서 **정답은 JSON으로 파싱 가능한 값**으로 저장해.

- 리스트: `[]` 또는 `["p1","p2"]`
- 맵: `{}` 또는 `{"Gi0/0":"up"}`
- 불리언: `true/false`
- 경로: `["leaf1","p1","pe1"]`

### 원칙 C. “상태(status)와 값(value)을 분리한다”

정답의 의미는 두 층이야.

- `answer_status`: **이 질문이 성립하는가/설정이 존재하는가**
- `answer`: **실제 값(항상 타입 일관성 유지)**

이렇게 분리하면, “값이 없는 상황”을 텍스트(예: `정보없음`)로 때우지 않아도 돼.

### 원칙 D. “표현 차이로 점수가 흔들리면 안 된다” (Canonicalization)

순서 없는 집합/리스트는 정렬하고, edge_set 같은 건 무방향 통일을 해서
**항상 같은 정답은 항상 같은 형태로 저장**한다.
(모델이 맞췄는데 표기 순서 때문에 틀리는 황당한 사건 방지)

### 원칙 E. “스키마 검증은 품질보증(QC)이다”

JSON Schema로 “이 answer_type이면 이 형태여야 한다”를 검증한다.
JSON Schema는 JSON의 구조/타입/제약을 정의하고 검증할 수 있는 표준 스펙이야. ([json-schema.org][2])
파이썬에선 `jsonschema` 같은 검증기를 써서 스키마 준수 여부를 확인할 수 있어. ([jsonschema][3])

여기서 중요한 포인트:

- **생성 단계 스키마 검증**: 정답 라벨이 깨졌는지 잡는 “데이터셋 QC”
- **평가 단계 스키마 검증**: LLM 출력이 형식을 지켰는지 잡는 “모델 출력 검증”

### 원칙 F. “UNKNOWN은 모델 탓이 아니라 파이프라인 탓”

Batfish 질의 실패/파싱 실패/예외는 `UNKNOWN`으로 분리하고, 평가에선 보통 **분모에서 제외**한다.
대신 `unknown_reason`과 `evidence`로 디버깅이 가능해야 한다.

---

## 3) CSV 스키마(결과 파일) 읽는 법

네 최신 CSV는 대략 이런 컬럼 구조로 정리돼 있어:

- `id`: 문제(메트릭) ID (예: `TRACEROUTE_PATH`)
- `category`: 문제 카테고리 (Inventory/OSPF/BGP/What-if 등)
- `level`: L1~L5 난이도 레벨
- `question`: LLM에게 던질 질문
- `answer_status`: `OK / NOT_CONFIGURED / NOT_APPLICABLE / UNKNOWN`
- `answer_type`: 채점 방법을 결정하는 타입(예: `set_str`, `map_str_str`, `path`, `bool`…)
- `answer`: 정답(JSON string)
- `unknown_reason`: `SCHEMA_VIOLATION`, `BATFISH_QUERY_ERROR` 등
- `evidence`: Batfish query/params/snapshot 같은 재현 정보(디버깅용)
- `pipeline_version`: 생성 파이프라인 버전(커밋 해시)
- `files`: 관련 cfg 파일 목록

### answer_status 의미(가장 중요)

- **OK**: 설정/전제가 성립하고 값을 계산했다.
- **NOT_CONFIGURED**: 설정 자체가 없다(negative evidence).
- **NOT_APPLICABLE**: 질문의 전제가 성립하지 않는다(What-if에서 자주 등장).
- **UNKNOWN**: Batfish/파서/파이프라인 문제로 값이 확정 불가.

---

## 4) 질문 템플릿(모델에게 요구하는 출력 규칙)

질문은 “정답 문자열”을 요구하지 않고, **JSON 형태**를 요구한다.

예시:

- 리스트: `["VRF_A","VRF_B"]`, 없으면 `[]`
- 불리언: `true/false`
- 경로: `["R1","R2","R3"]`

이 규칙이 있으면 평가 단계에서:

1. JSON 파싱
2. 스키마 검증
3. 타입별 채점(EM/Set F1/Path match…)
   이 흐름이 자동화된다.

Batfish 쪽 질의(예: traceroute/reachability)로 만든 정답은 원래 구조화된 결과로 뽑기 쉬워서, 이 방식과 잘 맞는다. ([batfish.readthedocs.io][1])

---

## 5) “우리 방식이 뭐가 다른데?” (이전 연구 대비 차별점)

너의 이전 접근(또는 일반 QA 데이터셋)과 비교해 NetConfigQA 파이프라인이 강한 이유는 이거야:

1. **정답이 ‘LLM 생성’이 아니라 ‘Batfish 계산’**
   → 재현성/신뢰성 상승 ([Network to Code][4])
2. **Negative Testing이 구조적으로 포함됨**
   → “없는데 있다고 말하는 모델”을 잡아냄
3. **status/value/type 분리 + JSON Schema로 QC**
   → 평가 자동화가 쉬움 ([json-schema.org][2])
4. **L4/L5 What-if(장애/경로 영향)까지 포함**
   → 단순 설정조회가 아니라 “행동(behavior) 기반 질문”으로 확장 ([batfish.org][5])

---

## 6) 결과(quality report) 보는 방법

품질 리포트는 데이터셋이 “벤치마크로 쓸 수 있을 정도로 건강한지” 보는 대시보드야.

추천 해석 가이드:

- `UNKNOWN` 비율: **5% 이하 목표**(너희 기준). 높으면 파이프라인/스냅샷 문제.
- `NOT_APPLICABLE` 비율: What-if에 너무 많으면 질문 생성 로직이 과격할 수 있음.
- `NOT_CONFIGURED` 비율: 너무 높으면 “모두 비었다”만 평가, 너무 낮으면 negative testing이 약해짐.

---

## 7) 현재 CSV에서 아직 보이는 문제: “정보없음”

너희가 목표로 하는 최종 철학은 **레거시 문자열(예: `정보없음`) 제거**야.

지금도 CSV에 `정보없음` 같은 값이 남아 있다면, 그건 보통 의미가 이거야:

- 해당 메트릭이 아직 **AnswerResult(status/value)로 완전히 치환되지 않았거나**
- text 타입에서 “없음”을 `NOT_CONFIGURED + null`로 바꾸는 처리가 덜 들어간 것

### 권장 최종 규칙(문서에 못 박기)

- `정보없음`, `"Not found"` 같은 문자열을 **정답(answer)에 절대 넣지 않는다**
- 없다면:

  - `answer_status = NOT_CONFIGURED`
  - `answer = null` (text 계열) 또는 타입에 맞는 빈 값(`[]`, `{}`, `false`)

이걸 문서에 “금지 문자열”로 적어두면, 이후 새 메트릭 추가할 때도 팀원/코딩에이전트가 안 흔들린다.

---

## 8) 새 메트릭 추가(확장) 규칙: 딱 이 순서만 지키면 된다

1. **문제 의도 정의**: “설정 존재?”(configured) vs “값 조회” vs “행동 분석(what-if)”
2. **answer_type 선택**: set/map/path/bool/enum…
3. **Configured 판정 규칙 추가**(필요 시): `CONFIGURED_RULES`
4. **AnswerResult 반환**: status/value/type/evidence/unknown_reason
5. **\_canonicalize 적용**
6. **validate_answer 적용**
7. **템플릿에 JSON 출력 요구 명시**

---

## 9) 평가 단계(LLM 채점)는 어떻게 붙이나

평가 프레임워크는 Hugging Face `evaluate`를 써도 좋고, 자체 채점기를 만들어도 돼.
`evaluate`는 커스텀 metric을 만들어 공유하는 흐름도 공식 문서가 잘 되어 있어. ([Hugging Face][6])

NetConfigQA에선 보통 “타입별 채점”이 핵심이라:

- `set_str`: Set-F1
- `map_str_*`: key-wise match / value-wise score
- `path`: exact path match 또는 prefix match
- `bool/enum`: exact match
  이런 식으로 `answer_type`에 따라 metric을 고르면 된다.

---

# 한 줄 요약

**NetConfigQA는 “L1-L3(정적)는 Rule-based로 속도/직관성 확보, L4-L5(동적)는 Batfish로 로 계산한 구조화 정답 + status/value 분리 + schema QC”로,
LLM이 cfg를 ‘정확한 사실값’으로 이해하는지를 자동평가하는 네트워크 QA 벤치마크다.** ([batfish.org][7])
