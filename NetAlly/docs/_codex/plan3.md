Next Step: PNETLab Docker Node로 NetAlly “쿠키 없이(LabFS)” 실동작시키기
Summary
현재 코드 구현은 거의 끝났고, 다음 단계의 핵심은 PNETLab Docker Node가 띄우는 NetAlly 컨테이너에 /opt/unetlab을 read-only로 마운트해서 labfs_local이 실제로 동작하게 만드는 것입니다.
PNETLab UI에 별도 Volume 항목이 없어도, Docker Node의 docker_options 필드에 -v ...를 넣으면 해결됩니다(호스트 코드를 확인했음).

Important Interface Changes
외부 API 추가/변경 없음.
운영 설정(환경변수)만 확정:
PNETLAB_INVENTORY_BACKEND=labfs_local (권장)
PNETLAB_LAB_NAME은 “가능하면 자동(최신 .unl)”로 두고, 필요 시만 고정
Step 1) PNETLab Docker Node 설정(필수)
1. Docker Node의 docker_options에 마운트 추가
PNETLab 웹 UI에서 NetAlly Docker Node 편집 화면에서 docker_options를 아래처럼 설정:

최소(권장):

--privileged -v /opt/unetlab:/opt/unetlab:ro -e PNETLAB_INVENTORY_BACKEND=labfs_local
만약 랩 자동 선택이 엉키면(여러 .unl이 있고 최신 선택이 틀리면) 임시로 고정:

--privileged -v /opt/unetlab:/opt/unetlab:ro -e PNETLAB_INVENTORY_BACKEND=labfs_local -e PNETLAB_LAB_NAME=test_nso
2. NetAlly Docker Node 재시작
옵션 변경 후 노드 stop/start (또는 lab에서 노드 재시작)
Step 2) 실동작 검증(필수 체크리스트)
PNETLab 호스트(root)에서 확인(네가 해도 되고, 내가 SSH로 같이 봐도 됨):

컨테이너 이름 확인
t{{.Status}}' | head -n 30
컨테이너 내부에서 마운트 확인
docker exec -it <netally_container_name> sh -lc 'ls -la /opt/unetlab/labs | head; ls -la /opt/unetlab/tmp | head'
NetAlly API가 LabFS로 토폴로지 반환하는지 확인
curl -s http://127.0.0.1:8000/api/topology/pnetlab | head -c 400; echo
기대:
nodes/edges가 비어있지 않음
meta.backend가 labfs_local (또는 에러 없이 동작)
아이콘 프록시 확인(마운트가 되면 바로 됨)
Router.png'
기대: 200 또는 존재하지 않으면 404 (서버에 실제 아이콘 파일명에 따라 다름)
Step 3) “랩 이름 자동 인식”에 대한 현실적인 해석(결정 완료)
PNETLab API는 무인증 호출이 412 unauthorized로 막혀 있음(확인됨).
LabFS만으로 “내가 속한 정확한 lab path”를 100% 자동 매핑하는 건 환경 의존(버전/내부 상태 파일)이라,
기본은 **가장 최근 수정된 .unl 자동 선택(현재 구현)**로 운영한다.
데모 안정성이 필요하면 PNETLAB_LAB_NAME을 docker_options에 1줄로 고정한다(쿠키 없이도 충분히 간단).
Step 4) (선택) 아이콘 동기화는 당장 필수 아님
PNETLab VM 내부 컨테이너 운영에서는 /api/pnetlab/icon/<name>가 마운트 기반으로 잘 동작하므로,
“정적 아이콘을 레포에 박아넣기”는 로컬 개발/오프라인용 최적화로 남겨두고, 데모 우선은 프록시 fallback로 간다.
Test Cases / Acceptance Criteria
컨테이너에서 /opt/unetlab/labs가 보임
GET /api/topology/pnetlab가 에러 없이 nodes >= 1 반환
UI에서 PNETLab 토폴로지가 렌더되고(아이콘은 정적 또는 프록시 fallback), 기본 질문 1개에서 하이라이트가 보임
Assumptions / Defaults
NetAlly는 PNETLab Docker Node로 실행(호스트 docker에서 docker ps로 보이는 것이 정상)
docker_options로 -v/-e를 추가하는 방식을 표준으로 사용

---

Execution Log (2026-02-12)

완료 작업:
1. LLM viz 안정화 패치 적용
   - `ChatPanel.tsx`: SSE 버퍼 파싱으로 chunk 경계 JSON 유실 방지
   - `TopologyPanel.tsx`: fetch race(AbortController + seq guard), API error 노출, 부분 좌표 fallback 보강
   - `TopologyPanel.tsx`: reachability 스타일을 base 스타일과 분리(`__reachability`)해 overlay 복원성 보강
   - `TopologyPanel.tsx`: `net:*` 허브 노드 클릭 시 device detail 호출 방지

2. 검증 실행
```bash
cd NetAlly/frontend
npm run build
```

결과:
- build 성공
- 번들 크기 경고만 존재(기능/타입 오류 없음)

Execution Log Addendum (2026-02-12, UX)

완료 작업:
1. 답변 클릭 기반 viz 복원 기능 추가
   - assistant 메시지별 viz 스냅샷 보존
   - 이전 답변 클릭 시 해당 시점 overlay 재적용
2. 설명형 토폴로지 오버레이 추가
   - 질문 제목/질문 문맥 표시
   - node/edge 매칭률, 모드 이유(path/focus), 매칭 실패 힌트 표시
3. Chat UI 현대화
   - 헤더/버블/상태 표현 개선
   - 스트리밍 중 `[Thinking..]` 텍스트 명시

검증:
```bash
cd NetAlly/frontend
npm run build
```

결과:
- build 성공
- chunk size warning only

Execution Log Addendum (2026-02-12, Backend + Context UX)

완료 작업:
1. backend viz 힌트 품질 업그레이드
   - nested payload/path/edges 문자열까지 파싱하여 viz 노드/엣지 추출 강화
   - `query`를 viz payload에 주입
2. 장비 상세정보 API 정합성 개선
   - `/api/device/{id}` 응답을 UI 기대 스키마와 맞춤 (`name`, `config`, `routes[]`, `interfaces[]`)
   - NSO + Batfish 병합 및 장비명 대소문자 보정
3. 토폴로지 상호작용 UX 변경
   - 좌클릭: chat context 지정
   - 우클릭: context menu + Detail 버튼으로 사이드 패널 열기
4. 채팅 UX 확장
   - node context를 채팅 상단에 표시하고 요청 payload에 포함
   - 이미지 업로드/미리보기 지원
   - `/` quick picker로 장비 목록 검색/선택

검증:
```bash
cd NetAlly/frontend
npm run build

cd ../
uv run pytest -q tests/test_chat_sse_order.py tests/test_main_runtime_contract.py tests/test_runtime_single_executor.py
python -m py_compile main.py
```

결과:
- frontend build 성공
- targeted pytest 6 passed
- backend 문법 체크 성공

Execution Log Addendum (2026-02-12, Chat UX Hardening)

완료 작업:
1. 입력 안정성 보강
   - 한글 IME 조합 중 Enter 전송 방지(`isComposing`, `keyCode=229`)
2. 답변 렌더링 현대화
   - assistant 답변 Markdown + GFM 렌더링 지원
3. 스트리밍 체감 개선
   - `answer` 이벤트를 버블에 점진 표시(reveal)
   - `answer_delta`/`token` 이벤트 누적 처리 경로 추가
4. Slash 장비 선택 UX 개선
   - trailing slash token 기반으로 후보 노출
   - 장비 선택 시 기존 입력을 보존하고 context만 고정
   - listbox/option ARIA로 접근성 강화

검증:
```bash
cd NetAlly/frontend
npm run build
```

결과:
- build 성공
- chunk size warning only
