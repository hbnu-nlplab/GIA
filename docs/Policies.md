# Policies & Metric Definitions Guide (SSOT)

`Make_Dataset/policies.json`은 NetConfigQA의 **Single Source of Truth (SSOT)**로서, 모든 메트릭의 정의, 질문 템플릿, 답변 형식, 검증 로직을 중앙에서 관리합니다.

## 1. 철학: Data-Driven Architecture

기존의 하드코딩된 규칙(Python 리스트/딕셔너리)을 제거하고, JSON 설정 파일만 수정하면 새로운 질문 유형을 추가할 수 있도록 설계되었습니다.

- **RuleBasedGenerator**: `policies.json`을 읽어 L1~L3 질문(설정 조회, 정합성 검사)을 생성
- **BatfishBuilder**: `policies.json`을 읽어 L4(Reachability), L5(What-If) 질문을 생성

## 2. 파일 구조 (`metrics_metadata`)

`metrics_metadata` 객체 안에 각 메트릭의 ID가 키(Key)로 정의됩니다.

```json
{
  "version": "3.0",
  "metrics_metadata": {
    "system_hostname_text": {
      "level": "L1",
      "category": "System_Inventory",
      "answer_type": "text",
      "template": "{host} 장비의 호스트네임은 무엇입니까?",
      "description": "장비 식별자(Hostname) 조회",
      "verification": "Config 파일 최상단의 'hostname <NAME>' 라인 확인",
      "logic_ref": "facts.devices[host].system.hostname"
    },
    "traceroute_path": {
      "level": "L4",
      "category": "Reachability_Analysis",
      "answer_type": "text",
      "template": "{src_node}에서 {dst_node}({dst_ip})로 가는 패킷의 네트워크 경로를 알려주세요.\n[답변 형식: 화살표(→)로 구분된 장비 목록]",
      "description": "경로 추적 (Traceroute)",
      "verification": "Batfish traceroute 결과와 비교",
      "logic_ref": "batfish.traceroute"
    }
  }
}
```

## 3. 항목별 상세 설명

| 필드           | 설명                                                   | 예시                                                   |
| -------------- | ------------------------------------------------------ | ------------------------------------------------------ |
| **Key**        | 고유 메트릭 ID (Python 코드 내 참조 키)                | `bgp_neighbor_count`, `link_failure_impact`            |
| `level`        | 질문 난이도 레벨 (L1~L5)                               | `L1` (단일장비), `L4` (Reachability)                   |
| `category`     | 질문 카테고리                                          | `Routing_Inventory`, `What_If_Analysis`                |
| `answer_type`  | 정답 데이터 타입 (스키마 검증용)                       | `text`, `numeric`, `boolean`, `set_str`, `map_str_int` |
| `template`     | 질문 생성 템플릿. 변수는 `{host}`, `{asn}` 등으로 표기 | `"{host}의 관리자 수는?"`                              |
| `description`  | 메트릭에 대한 간략한 설명 (사람용)                     | `"BGP Neighbor 개수 확인"`                             |
| `verification` | 정답 검증 가이드 (QC용)                                | `"show ip bgp summary 결과 비교"`                      |
| `logic_ref`    | 내부 로직 매핑 또는 구현 위치 힌트                     | `"facts.routing.bgp"`, `"batfish.loop_detection"`      |

### 지원되는 Template 변수

- **L1~L3**: `{host}`, `{asn}`, `{vrf}`, `{area}`, `{host1}`, `{host2}`
- **L4/L5**: `{src_ip}`, `{dst_ip}`, `{src_node}`, `{dst_node}`, `{link}`, `{policy_name}`

- **L4/L5**: `{src_ip}`, `{dst_ip}`, `{src_node}`, `{dst_node}`, `{link}`, `{policy_name}`

## 4. 검증 전략 매트릭스 (Verification Strategy Matrix)

모든 데이터셋(1,128건)은 **Hybrid Validation** 정책에 따라 검증됩니다.

| Level | Metrics | 검증 방법 | 구현 상세 |
|---|---|---|---|
| **L1** | `_text`, `_list`, `_count` | **(1) Independent Config Parser** | 정규식(Regex)으로 Config 파일 텍스트를 직접 파싱하여 비교 (90% 이상 커버) |
| **L2** | `_devices`, `_count` | **(1) Independent Config Parser** | 각 Config 파싱 결과를 파이썬으로 집계(`sum`, `len`)하여 검증 |
| **L3** | `compare_`, `ibgp_` | **(2) Metric-wise Manual Check** | 로직이 복잡한 경우, 샘플(Stratified)을 뽑아 엑셀 시트에서 사람(Expert)이 검증 |
| **L4** | `traceroute`, `reachability` | **(3) PNETLab Real-world** | 실제 라우터에서 `traceroute` 명령 실행 후 홉(Hop) 경로 비교 |
| **L5** | `link_failure`, `what_if` | **(3) PNETLab Real-world** | 인터페이스 Shutdown 후 라우팅 테이블 및 도달성 변화 실측 |

> **Note**: `logic_ref` 필드는 내부 구현 참고용이며, 실제 검증 시에는 위 전략을 따릅니다.

## 5. 메트릭 추가 방법 (Workflow)

새로운 메트릭을 추가하려면 다음 2단계만 수행하면 됩니다.

1. **`policies.json`에 메트릭 정의 추가**

   - 레벨, 카테고리, 템플릿, 답변 형식을 정의합니다.
   - 메트릭 이름(Key)은 유니크해야 합니다.

2. **메트릭 계산 로직 구현 (필요 시)**
   - **L1~L3**: `src/core_batfish/builder_core.py`의 `_answer_for_metric` 메서드에 계산 로직 추가
   - **L4/L5**: `src/core_batfish/batfish_builder.py` (또는 Mixin) 내에 해당 메트릭 메서드 구현 (`generate_l4_questions` 등에서 호출 확인)

## 5. Answer Type 정의

데이터 품질 관리를 위해 다음 타입들을 엄격하게 준수합니다.

- `text`: 일반 텍스트 (줄바꿈 포함 가능)
- `numeric`: 정수 또는 실수
- `boolean`: JSON `true` / `false`
- `set_str`: 중복 없는 문자열 리스트 (JSON Array)
- `map_str_int`: 키-값 쌍 (문자열: 숫자)
- `map_str_str`: 키-값 쌍 (문자열: 문자열)
- `json`: 복잡한 구조체 (What-If 분석 결과 등)

## 6. 주의사항

- **NOT_CONFIGURED**: 해당 장비에 기능이 설정되지 않은 경우, 값은 `null`이 되며 Status는 `NOT_CONFIGURED`가 됩니다. (코드 레벨 자동 처리)
- **템플릿 수정**: 질문 템플릿을 수정하면 즉시 생성되는 질문에 반영됩니다. 재컴파일이 필요 없습니다.
- **[답변 형식]**: 템플릿 끝에 `[답변 형식: ...]` 가이드를 포함하여 LLM이 답변 형식을 인지하도록 돕는 것을 권장합니다.
