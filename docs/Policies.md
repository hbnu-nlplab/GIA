# Policies & Metric Definitions Guide (SSOT)

`Make_Dataset/policies.json`은 NetConfigQA의 **Single Source of Truth (SSOT)**로서, 모든 메트릭의 정의, 질문 템플릿, 답변 형식, 검증 로직을 중앙에서 관리합니다.

## 1. 철학: Data-Driven Architecture

기존의 하드코딩된 규칙(Python 리스트/딕셔너리)을 제거하고, JSON 설정 파일만 수정하면 새로운 질문 유형을 추가할 수 있도록 설계되었습니다.

- **RuleBasedGenerator**: `policies.json`을 읽어 L1~L3 질문(설정 조회, 정합성 검사)을 생성
- **BatfishBuilder**: `policies.json`을 읽어 L4(Reachability), L5(What-If) 질문을 생성

## 2. 파일 구조 (`metrics_metadata`)

`metrics_metadata` 객체 안에 각 메트릭의 ID가 키(Key)로 정의됩니다. 각 메트릭은 한국어(`template`)와 영어(`template_en`) 이중언어 질문 템플릿을 포함합니다.

```json
{
  "version": "3.1",
  "metrics_metadata": {
    "system_hostname_text": {
      "level": "L1",
      "category": "System_Inventory",
      "answer_type": "text",
      "template": "{host} 장비의 호스트네임은 무엇입니까? [답변 형식: 정확한 값만]",
      "template_en": "What is the system hostname on {host}? [Answer format: plain string]",
      "description": "네트워크 장비의 고유 이름(Hostname)을 조회합니다.",
      "verification": "검증 방법: Config 파일 최상단의 'hostname <NAME>' 라인 확인",
      "logic_ref": "facts.devices[host].system.hostname"
    },
    "traceroute_path": {
      "level": "L4",
      "category": "Reachability_Analysis",
      "answer_type": "text",
      "template": "{src_ip}에서 {dst_ip}까지의 네트워크 경로를 나열해주세요. [답변 형식: 화살표(→)로 구분된 장비이름 목록]",
      "template_en": "What is the traceroute path from {src_ip} to {dst_ip}? [Answer format: plain string]",
      "description": "Batfish 시뮬레이션을 통해 패킷의 물리적/논리적 경로를 추적합니다.",
      "verification": "Batfish traceroute 결과와 비교",
      "logic_ref": "batfish.traceroute(src, dst)"
    }
  }
}
```

## 3. 항목별 상세 설명

| 필드             | 설명                                                   | 예시                                                   |
| ---------------- | ------------------------------------------------------ | ------------------------------------------------------ |
| **Key**          | 고유 메트릭 ID (Python 코드 내 참조 키)                | `bgp_neighbor_count`, `link_failure_impact`            |
| `level`          | 질문 난이도 레벨 (L1~L5)                               | `L1` (단일장비), `L4` (Reachability)                   |
| `category`       | 질문 카테고리                                          | `Routing_Inventory`, `What_If_Analysis`                |
| `answer_type`    | 정답 데이터 타입 (스키마 검증용)                       | `text`, `scalar_int`, `set_str`, `map_str_int`         |
| `template`       | 한국어 질문 템플릿. 변수는 `{host}`, `{asn}` 등       | `"{host} 장비의 BGP 피어는 총 몇 개입니까?"`           |
| `template_en`    | 영어 질문 템플릿. 동일 변수 사용                       | `"How many BGP neighbor entries are configured on {host}?"` |
| `description`    | 메트릭에 대한 상세 설명 (사람용)                       | `"BGP Neighbor 개수 확인"`                             |
| `verification`   | 정답 검증 가이드 (QC용)                                | `"show ip bgp summary 결과 비교"`                      |
| `logic_ref`      | 내부 로직 매핑 또는 구현 위치 힌트                     | `"facts.routing.bgp"`, `"batfish.loop_detection"`      |

### 지원되는 Template 변수

- **L1~L3**: `{host}`, `{asn}`, `{vrf}`, `{area}`, `{host1}`, `{host2}`
- **L4/L5**: `{src_ip}`, `{dst_ip}`, `{src_host}`, `{src_node}`, `{dst_node}`, `{link}`, `{policy_name}`, `{waypoint}`, `{protocol}`, `{dst_port}`

## 4. 이중언어 질문 템플릿 작성 가이드 (Bilingual Template Guide)

### 4.1 `template` (한국어) 작성 규칙

- 경어체(~입니까?, ~주세요) 사용
- `[답변 형식: ...]` 가이드를 템플릿 끝에 포함
- 예: `"{host} 장비의 BGP 피어는 총 몇 개입니까? [답변 형식: 숫자]"`

### 4.2 `template_en` (영어) 작성 규칙

- **자연스러운 영어 질문문**으로 작성 (메트릭 키를 그대로 나열하지 않음)
- `[Answer format: ...]` 가이드를 템플릿 끝에 포함
- **주어-동사 수 일치** 확인: 복수 대상은 복수형 사용
- 한국어 템플릿의 의미와 정확히 대응해야 함

**Answer format 매핑표:**

| `answer_type` | 한국어 `[답변 형식]` | 영어 `[Answer format]` |
|---|---|---|
| `text` | `정확한 값만` / `설정값 또는 null` | `plain string` |
| `scalar_int` / `number` | `숫자` | `integer` |
| `set_str` | `리스트` | `JSON array` |
| `map_str_str` / `map_str_int` | `{{'키': '값'}}` | `JSON object` |
| `json` | `JSON` | `JSON object` |
| `edge_set` | `['A<->B', ...]` | `JSON array` |

### 4.3 영어 템플릿 패턴별 예시

| 질문 유형 | Bad (자동생성) | Good (교정 후) |
|---|---|---|
| 목록 조회 | `Which NTP server are configured?` | `Which NTP servers are configured on {host}?` |
| 수량 조회 | `How many routing table entry entries are configured?` | `How many routing table entries exist on {host}?` |
| 값 조회 | `What is the all devices same AS?` | `What are the BGP AS numbers for all devices?` |
| 비교 | `What is the max interface device?` | `Which device has the most interfaces, and how many?` |
| 의미 불일치 | `How many BGP local AS entries are configured?` (count 아님) | `What is the BGP local AS number on {host}?` |
| 중복 표현 | `How many ACL configured entries are configured?` | `How many ACLs are defined on {host}?` |
| What-If | `How many node failure impact entries are configured?` | `How many traffic flows are disrupted if {host} goes down?` |

## 5. 검증 전략 매트릭스 (Verification Strategy Matrix)

모든 데이터셋(1,128건)은 **Hybrid Validation** 정책에 따라 검증됩니다.

| Level | Metrics | 검증 방법 | 구현 상세 |
|---|---|---|---|
| **L1** | `_text`, `_list`, `_count` | **(1) Independent Config Parser** | 정규식(Regex)으로 Config 파일 텍스트를 직접 파싱하여 비교 (90% 이상 커버) |
| **L2** | `_devices`, `_count` | **(1) Independent Config Parser** | 각 Config 파싱 결과를 파이썬으로 집계(`sum`, `len`)하여 검증 |
| **L3** | `compare_`, `ibgp_` | **(2) Metric-wise Manual Check** | 로직이 복잡한 경우, 샘플(Stratified)을 뽑아 엑셀 시트에서 사람(Expert)이 검증 |
| **L4** | `traceroute`, `reachability` | **(3) PNETLab Real-world** | 실제 라우터에서 `traceroute` 명령 실행 후 홉(Hop) 경로 비교 |
| **L5** | `link_failure`, `what_if` | **(3) PNETLab Real-world** | 인터페이스 Shutdown 후 라우팅 테이블 및 도달성 변화 실측 |

> **Note**: `logic_ref` 필드는 내부 구현 참고용이며, 실제 검증 시에는 위 전략을 따릅니다.

## 6. 메트릭 추가 방법 (Workflow)

새로운 메트릭을 추가하려면 다음 2단계만 수행하면 됩니다.

1. **`policies.json`에 메트릭 정의 추가**

   - 레벨, 카테고리, 한국어/영어 템플릿, 답변 형식을 정의합니다.
   - 메트릭 이름(Key)은 유니크해야 합니다.
   - `template`과 `template_en` 모두 작성합니다.

2. **메트릭 계산 로직 구현 (필요 시)**
   - **L1~L3**: `src/core_batfish/builder_core.py`의 `_answer_for_metric` 메서드에 계산 로직 추가
   - **L4/L5**: `src/core_batfish/batfish_builder.py` (또는 Mixin) 내에 해당 메트릭 메서드 구현 (`generate_l4_questions` 등에서 호출 확인)

## 7. Answer Type 정의

데이터 품질 관리를 위해 다음 타입들을 엄격하게 준수합니다.

- `text`: 일반 텍스트 (줄바꿈 포함 가능)
- `scalar_int`: 정수
- `number`: 정수 또는 실수
- `boolean`: JSON `true` / `false`
- `set_str`: 중복 없는 문자열 리스트 (JSON Array)
- `edge_set`: 양방향 쌍 리스트 (예: `["A<->B", "C<->D"]`)
- `map_str_int`: 키-값 쌍 (문자열: 숫자)
- `map_str_str`: 키-값 쌍 (문자열: 문자열)
- `json`: 복잡한 구조체 (What-If 분석 결과 등)

## 8. 주의사항

- **NOT_CONFIGURED**: 해당 장비에 기능이 설정되지 않은 경우, 값은 `null`이 되며 Status는 `NOT_CONFIGURED`가 됩니다. (코드 레벨 자동 처리)
- **템플릿 수정**: 질문 템플릿을 수정하면 즉시 생성되는 질문에 반영됩니다. 재컴파일이 필요 없습니다.
- **[답변 형식]**: 템플릿 끝에 `[답변 형식: ...]` / `[Answer format: ...]` 가이드를 포함하여 LLM이 답변 형식을 인지하도록 돕는 것을 권장합니다.
- **이중언어 일관성**: `template`과 `template_en`은 동일한 질문 의도를 가져야 합니다. 한쪽만 수정하고 다른 쪽을 빠뜨리지 않도록 주의합니다.
