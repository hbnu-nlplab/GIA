---
type: devlog
date: 2026-01-21
project: LabMate
tags: [log, dev]
---
# 구현 로그 — 2026-01-21

## LabMate 범위 재정의: Hybrid Auto-Onboarding 아키텍처

### 요약
- LabMate의 데이터 수집 전략을 UNL 우선에서 **API-First + NSO 중심**으로 재정의
- **Hybrid Mode (옵션 3) 선택**: PNETLab API로 Discovery → NSO 자동 등록 → CDP/LLDP로 L1 토폴로지
- **모든 아키텍처 문서 업데이트** (`architecture.md`, `docker-compose.yml`)하여 NSO를 Single Source of Truth로 명시
- **UNL 파일 파싱은 v2로 연기**하여 v1 구현을 단순화하되, CDP/LLDP를 통한 L1 토폴로지 지원은 유지
- **"Design-to-Live Sync" 워크플로우 확립**: PNETLab에서 NSO로 자동 장비 등록

### 의사결정
1. **NSO vs UNL vs Hybrid** → NSO 우선 Hybrid 선택
   - 근거: 실제 운영자 경험, Self-Driving Network Onboarding 연구 가치
   - 트레이드오프: 순수 파일 기반보다 복잡하지만, SIGCOMM 2026 목표에 부합
   
2. **L1 토폴로지: CDP/LLDP vs UNL** → NSO에서 CDP/LLDP 추출
   - 근거: 실제 네트워크 상태 반영, 파일 마운트 복잡도 제거
   - 트레이드오프: 장비가 CDP/LLDP 지원 필요, "설계 의도" 캡처 불가
   
3. **Docker 네트워킹: Host vs Bridge** → Host 네트워크 모드
   - 근거: localhost의 PNETLab/NSO에 직접 접근, 복잡한 라우팅 불필요
   - 트레이드오프: 격리 수준 낮지만, 랩 환경에서는 허용 가능

### 수정한 파일
- `/home/kilab_pyj/codespace/GIA/LabMate/architecture.md` (완전 재작성)
- `/home/kilab_pyj/codespace/GIA/LabMate/docker-compose.yml` (간소화, `network_mode: host` 추가)
- `/home/kilab_pyj/.gemini/antigravity/brain/996c0d06-df28-45d6-a744-74fd7d4d547f/task.md`
- `/home/kilab_pyj/.gemini/antigravity/brain/996c0d06-df28-45d6-a744-74fd7d4d547f/implementation_plan.md`

### 핵심 흐름
1. 사용자가 "Docker 컨테이너에서 PNETLab API를 어떻게 쓰나?" 질문
2. 3가지 범위 옵션 제시: NSO 중심, 파일 중심, Hybrid
3. 사용자가 Auto-Onboarding 포함 Hybrid (옵션 3) 선택
4. L1 토폴로지 소스 명확화: CDP/LLDP > UNL (v2)
5. `architecture.md`의 Goals 섹션을 NSO 우선으로 업데이트
6. Section 3 (Data Ingestion) 점진적 수정 시도 → 여러 번 문자열 매칭 실패
7. 사용자가 전체 재작성 제안 → `architecture.md` 성공적으로 재작성
8. `docker-compose.yml`에 Batfish 서비스 추가 (처음에 빠뜨림)
9. PNETLab/NSO API 접근을 위해 `network_mode: host` 추가
10. `implementation_plan.md`에 Phase 3.5 계획 확정

### 가정 / 전제조건
- PNETLab과 NSO가 Docker와 동일한 호스트에서 실행 중
- PNETLab의 장비들이 CDP 또는 LLDP 지원
- NSO에 장비 유형별 적절한 NED 패키지 설치됨
- `.env` 파일에 유효한 NSO/PNETLab 인증 정보 포함

### 증거
- Phase 3 (MCP 도구 연동) 검증 완료: 도구 로드 성공, Batfish Available: True
- `architecture.md`가 이제 데이터 소스와 워크플로우를 명확히 정의
- `docker-compose.yml`에 Batfish 포함 및 host 네트워킹 사용

### 검증
- 미실행 (문서 업데이트만 수행)
- 다음: PNETLab API → NSO Auto-Onboarding 흐름 E2E 테스트

### Git
- 커밋 안 함 (작업 진행 중)

### 링크
- 상세 분석: [[docs/Log/2026-01-21/Deep_Dive|Deep_Dive]]
- 연구 노트: [[docs/Log/2026-01-21/AI_Research_Notes|AI_Research_Notes]]

### 질문
- CDP/LLDP를 지원하지 않는 장비는 어떻게 처리? (LLDP 전용 스위치, 레거시 장비)
- PNETLab→NSO 장비 매핑을 캐시해서 매 실행마다 재탐색을 피해야 하나?
- NSO에 접근 불가 시 실패 모드는? (Config Export 폴백은 정의되었지만, 얼마나 우아하게?)

### 다음 작업
- `agent/tools.py`에 `scan_and_sync` 도구 구현
- Docker 컨테이너에서 PNETLab API 연결 테스트
- `layer1_topology.json` 생성을 위한 CDP/LLDP 파싱 로직 구현
