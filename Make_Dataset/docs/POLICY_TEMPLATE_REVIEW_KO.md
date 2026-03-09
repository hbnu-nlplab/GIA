# policies.json 질문 템플릿 점검 메모

## 점검 범위

- 파일: `Make_Dataset/policies.json`
- 대상: `metrics_metadata` 내 127개 metric의 `template`, `template_en`

## 구조 점검 결과

자동 점검 기준으로는 아래 항목에서 구조적 오류가 없었다.

- `template` / `template_en` placeholder 집합 일치
- 누락된 템플릿 없음
- placeholder 이름 형식 이상 없음

즉 다음 종류의 오류는 현재 없다.

- `{host}`는 있는데 영어 템플릿에는 없는 경우
- 잘못된 `{host-name}` 같은 placeholder 문법
- 한국어/영어 템플릿 중 한쪽만 비어 있는 경우

## 실제 수정한 항목

아래 항목은 문장 의미가 평가 정책과 충돌하거나, 한영 범위가 어긋나 있어 수정했다.

### 1. `aaa_authentication_method`

기존:

- `local, tacacs+, radius 중 하나 또는 빈 값`

문제:

- 현재 평가 정책은 `NOT_CONFIGURED`를 명시적으로 사용하는 방향인데, `빈 값`은 모호하다.

수정:

- `local, tacacs+, radius 중 하나 또는 NOT_CONFIGURED`

### 2. `mpls_ldp_router_id`

기존:

- `IP 주소 ... 또는 빈 값`
- 영어 템플릿도 `empty string`

문제:

- `NOT_CONFIGURED` 정책과 충돌

수정:

- `IP 주소 ... 또는 NOT_CONFIGURED`
- 영어도 `IP address or NOT_CONFIGURED`

### 3. `configured_bgp_as_numbers`

기존:

- `BGP AS 번호는?`

문제:

- 실제 answer type은 리스트인데 문장이 단수형처럼 보인다.

수정:

- `BGP AS 번호 목록은 무엇입니까?`

### 4. `hsrp_groups_list`

기존:

- 한국어: `HSRP/VRRP 그룹 ID 목록`
- 영어: `Which HSRP groups are configured ...`

문제:

- 한국어는 `HSRP/VRRP`, 영어는 `HSRP only`

수정:

- 영어를 `HSRP/VRRP group IDs`로 정렬

## 현재 남아 있는 항목

구조적 오류는 없지만, 일부 레거시 metric은 문체가 조금 어색하다.

예:

- `... 활성화 상태는?`
- `... 목록은?`
- `... 개수는?`

이건 품질 개선 대상일 수는 있지만, 현재 기준으로는 기능 오류나 평가 오류를 직접 만들지는 않는다.

## 권장 원칙

앞으로 템플릿을 수정할 때는 아래를 유지하는 것이 좋다.

1. answer format은 `NOT_CONFIGURED` 정책과 충돌하지 않게 쓴다.
2. 한국어와 영어 템플릿의 범위는 동일해야 한다.
3. 리스트형 answer는 문장도 `목록`, `리스트`, `어떤 항목들`처럼 복수형으로 쓴다.
4. 숫자형 answer는 `몇 개`, `총 몇 개`처럼 count 질문으로 쓴다.
5. metric 의미가 바뀌는 템플릿 수정은 dataset 재생성을 동반해야 한다.
