# LabMate Security & Deployment Policy (v1.0)

기관 환경(KIST 등)을 고려해 LabMate는 기본적으로 “데이터 최소화 + 외부 유출 방지 + 감사 가능”을 목표로 한다.

---

## 1) Threat Model (요약)

### 주요 민감 자산
- 장비 설정(config 전문)
- 내부 IP/호스트명/토폴로지 상세
- 로그 원문(특히 인증/접속 흔적 포함 가능)
- API Key / SSH Key 등 비밀정보

### 주요 리스크
- 외부 LLM API로 민감 데이터 유출
- 컨테이너 이미지/로그에 키가 박혀서 노출
- 네트워크 프록시/SSL MITM 환경에서 예기치 않은 실패

---

## 2) Data Classification (권장)

- Level 2 (고민감): config 전문, 로그 원문, 계정/키, 장비 접속정보
  - **절대 외부 전송 금지**
  - Local LLM만 사용

- Level 1 (민감): 내부 IP/hostname, 정책/ACL 이름 일부
  - 기본 Local
  - 필요 시 마스킹/요약 후에만 API 가능

- Level 0 (안전): Batfish 결과 요약(테이블/결론), 익명화된 그래프/메트릭
  - 정책 허용 시 API 가능

---

## 3) Local / API / Hybrid Policy

### 기본 배포 권장: Local 모드
- 기관 보안정책에 가장 안전
- 네트워크/프록시 이슈 최소화

### 옵션: API 모드
- 개발/PoC 또는 기관 정책이 명확히 허용될 때만
- 외부로 나가는 payload는 Level 0~1로 제한


---

## 4) API Key / Secrets Handling

- API Key는 코드/이미지에 하드코딩 금지
- 환경변수 또는 secrets로 주입
- OpenAI는 키 보안 베스트 프랙티스를 안내한다. :contentReference[oaicite:8]{index=8}
- Docker Compose는 secrets를 `/run/secrets/<name>` 파일로 마운트하는 방법을 제공한다. :contentReference[oaicite:9]{index=9}

---

## 5) OpenAI API Data Handling (정책 설명용)

OpenAI 플랫폼 문서에 따르면,
API로 전송된 데이터는 기본적으로 모델 학습에 사용되지 않으며(옵트인 제외),
사용자가 데이터 사용을 제어할 수 있다는 점을 설명한다. :contentReference[oaicite:10]{index=10}

> 기관 정책에 따라 “외부 전송 자체 금지”일 수 있으므로,
> LabMate는 반드시 Local-only로도 완전 동작 가능해야 한다.

---

## 6) Network Egress / Proxy / TLS Checklist

기관 환경에서 “인터넷 된다”와 “컨테이너가 API 호출 된다”는 다를 수 있다.

권장 Health Check:
- DNS resolve 확인
- HTTPS(443) outbound 확인
- 프록시 환경변수(HTTP(S)_PROXY) 여부 확인
- TLS 인증서 체인 문제 감지(기관 SSL MITM 대비)

---

## 7) Logging & Audit

- 요청/응답 로그에 Level 2 데이터가 찍히지 않도록 기본 마스킹
- 모든 “변경/푸시/등록” 시도는:
  - Plan preview
  - 승인자/시간/스냅샷 ID
  - 실행 결과
  를 감사 로그로 남긴다.

---

## References
- OpenAI API key safety / production best practices :contentReference[oaicite:11]{index=11}
- OpenAI data controls (API 데이터 사용 제어) :contentReference[oaicite:12]{index=12}
- Docker Compose secrets docs :contentReference[oaicite:13]{index=13}
