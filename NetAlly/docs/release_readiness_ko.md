# NetAlly 릴리즈 체크리스트 (데모 OK / 운영 전 필수)

이 문서는 NetAlly를 **지금 데모 가능한 상태**로 판단하는 기준과,  
**운영(프로덕션) 반영 전에 반드시 끝내야 하는 작업**을 분리해서 제공합니다.

문서 허브: `docs/README_ko.md`

---

## 0. 사용법 (중요)

1. 아래 `A. 데모 OK 게이트`를 위에서 아래로 수행합니다.
2. 모든 `PASS 기준`을 만족하면 데모 진행 가능합니다.
3. 운영 반영 전에는 `B. 운영 전 필수 게이트`를 모두 완료해야 합니다.

권장 증적:
- 명령어 출력 스크린샷
- API 응답 JSON
- UI 동작 캡처

---

## A. 데모 OK 게이트 (바로 실행용)

기준:
- 한 항목이라도 실패하면 데모 진행 전 수정
- 실행 위치는 각 항목에 명시

### A-01. 코드/빌드 기본 무결성

- 실행 위치: 로컬 개발 PC

```bash
cd NetAlly
uv run pytest -q tests/test_settings_api_integration.py tests/test_onboarding_automation_paths.py tests/test_chat_sse_order.py
cd frontend && npm run build
```

PASS 기준:
- pytest 실패 0
- frontend build 성공

체크: `[ ]`

### A-02. 로컬 코드 변경분 재배포 (코드 수정한 경우만)

- 실행 위치: 로컬 개발 PC + PNETLab VM

```bash
cd /home/yujin/Desktop/Projects/GIA
docker build -f NetAlly/Dockerfile -t netally:latest .
docker save -o netally.tar netally:latest
scp netally.tar root@192.168.50.60:/root/
ssh root@192.168.50.60 'docker load -i /root/netally.tar'
```

PASS 기준:
- 이미지 빌드/전송/로드 성공
- PNETLab에서 NetAlly 노드 Stop/Start 완료

체크: `[ ]`

### A-03. 핵심 런타임 설정 점검

- 실행 위치: NetAlly 컨테이너 내부 또는 API 호출 가능 위치

```bash
curl -fsS http://127.0.0.1:8000/api/settings
```

PASS 기준:
- 아래 값 확인
- `tool_backend = "mcp"`
- `mcp_allow_mutations = true` (온보딩 테스트 시)
- `pnetlab_inventory_backend = "labfs_local"` (PNETLab 내부 실행 기준)
- `pnetlab_lab_name` 값이 실제 랩 이름과 일치
- `nso_base_url` 또는 `pnetlab_nso_node`가 실환경과 일치

체크: `[ ]`

### A-04. NetAlly 헬스 체크

- 실행 위치: NetAlly 접근 가능한 위치

```bash
curl -fsS http://127.0.0.1:8000/api/health
```

PASS 기준:
- `status = "ok"`
- `tool_backend`가 기대값(`mcp` 또는 `legacy`)과 일치

체크: `[ ]`

### A-05. NSO 접속 가능 확인

- 실행 위치: NetAlly 컨테이너

```bash
python - << 'PY'
import urllib.request
for u in [
    "http://192.168.1.1:8080/restconf",
    "http://10.10.10.100:8080/restconf",
]:
    try:
        r = urllib.request.urlopen(u, timeout=3)
        print(u, r.status)
    except Exception as e:
        print(u, "ERR", e)
PY
```

PASS 기준:
- 최소 1개 URL이 HTTP 응답 반환

체크: `[ ]`

### A-06. Batfish 준비 확인

- 실행 위치: NetAlly UI 또는 API

```bash
curl -fsS -X POST http://127.0.0.1:8000/api/lab/prepare \
  -H 'Content-Type: application/json' \
  -d '{"auto_init_batfish": true}'
```

PASS 기준:
- `status`가 `ready` 또는 `loaded` 또는 `initialized`

체크: `[ ]`

### A-07. Refresh 온보딩 동작 확인

- 실행 위치: NetAlly UI 또는 API

```bash
curl -fsS -X POST http://127.0.0.1:8000/api/lab/refresh \
  -H 'Content-Type: application/json' \
  -d '{}'
```

PASS 기준:
- 500 에러 없음
- 결과에 `missing`/`message` 등 정상 구조 반환
- `NSO`, `Docker`, `NetAlly`, `Admin` 노드가 온보딩 대상에서 제외됨

체크: `[ ]`

### A-08. 채팅 + SSE + 도구 호출 확인

- 실행 위치: NetAlly UI

테스트 입력:
- `show devices`

PASS 기준:
- planning → tool_call → tool_output → answer → complete 순서 표시
- 결과 텍스트 정상 출력

체크: `[ ]`

### A-09. 토폴로지 맵 시각화 확인

- 실행 위치: NetAlly UI

PASS 기준:
- Map View에서 노드/링크 렌더됨
- source 전환(`Lab`/`Batfish`) 시 깨짐 없음
- 채팅 질의 후 viz overlay(하이라이트) 반영 확인

체크: `[ ]`

### A-10. 데모 시작 승인

PASS 기준:
- A-01 ~ A-09 전체 체크 완료

체크: `[ ]`

---

## B. 운영 전 필수 게이트 (프로덕션 반영 전)

기준:
- 아래 항목은 "권장"이 아니라 운영 반영 전 "필수"

### B-01. 비밀정보 관리

PASS 기준:
- `.env`에 실키/비밀번호 평문 커밋 금지
- 비밀값은 배포 시크릿 저장소(또는 운영 환경변수)로 주입

체크: `[ ]`

### B-02. 설정 영속화 전략

PASS 기준:
- `/api/settings` 변경값의 영속 범위 명확화
- 컨테이너 재생성 후에도 필요한 값은 Docker Options/오케스트레이터 env에 반영

체크: `[ ]`

### B-03. 배포 자동화

PASS 기준:
- `build -> save -> transfer -> load -> restart`가 스크립트화되어 재현 가능
- 수동 절차 최소화

체크: `[ ]`

### B-04. 장애 복구 절차

PASS 기준:
- 이전 안정 이미지로 즉시 롤백 가능한 절차 문서화
- 롤백 검증(헬스/API/UI) 완료

체크: `[ ]`

### B-05. 관측성(Observability)

PASS 기준:
- 핵심 API(`/api/health`, `/api/lab/prepare`, `/api/lab/refresh`, `/api/chat`) 로그 추적 가능
- 오류 시 원인 파악 가능한 최소 로그/메트릭 확보

체크: `[ ]`

### B-06. E2E 회귀 검증

PASS 기준:
- 릴리즈 후보마다 핵심 경로 E2E를 자동 또는 반자동으로 반복 가능
- 최소: Prepare/Refresh/Chat/Map View 회귀 체크

체크: `[ ]`

---

## C. 최종 승인 기록

- 릴리즈 버전:
- 체크 수행 일시:
- 수행자:
- 데모 승인: `YES / NO`
- 운영 승인: `YES / NO`
- 이슈/메모:

---

## D. 관련 문서

- 실전 배선/운영: `docs/pnetlab_wiring_runbook_ko.md`
- E2E 구조: `docs/pipeline_end_to_end_ko.md`
- 테스트 실행: `docs/testing_runbook_ko.md`
- API 계약: `docs/backend_api.md`

---

## E. 다중 실험실 운영 체크 (랩 여러 개 동시 운영 시)

문제 포인트:
- 같은 NetAlly 인스턴스에서 랩을 자주 바꾸면 `PNETLAB_LAB_NAME`, `BATFISH_SNAPSHOT` 충돌로 결과 혼선 가능
- 설정 공유 시 실험실 A의 값이 실험실 B에 섞일 수 있음
- 포트/URL/토큰이 실험실별로 다르면 운영자 실수가 발생하기 쉬움

권장 운영 모델:
1. **실험실당 NetAlly 인스턴스 1개**를 권장
2. 각 인스턴스에 고유값 지정
   - `PNETLAB_LAB_NAME`
   - `BATFISH_SNAPSHOT`
   - `NETALLY_RUNTIME_SETTINGS_PATH`
3. 데모/운영 프로필 분리
   - Settings 프리셋(또는 배포 변수 파일)로 랩별 값 고정
4. 릴리즈 태그 고정
   - 실험실별로 동일 이미지 태그 사용해 환경 차이 최소화

최소 체크:
- [ ] 랩별 `PNETLAB_LAB_NAME` 고유
- [ ] 랩별 `BATFISH_SNAPSHOT` 고유
- [ ] 랩별 설정 파일 경로(`NETALLY_RUNTIME_SETTINGS_PATH`) 분리
- [ ] 랩별 NSO URL/계정 분리 확인
