# NSO Docker 명령어 업데이트 요약

**업데이트 날짜**: 2025년 11월 28일  
**목적**: NSO CLI 접속 명령어를 상대 경로(`~`)에서 절대 경로(`/root/`)로 변경하여 모든 환경에서 안정적으로 작동하도록 개선

---

## 🔄 주요 변경사항

### 문제점
- 상대 경로(`~`)를 사용한 명령어가 Debug 환경과 정상 컨테이너에서 다르게 동작
- `/nix/tmp/debug-tools/` 경로 충돌로 인한 경로 오류 발생

### 해결책
- **모든 NSO 관련 경로를 절대 경로(`/root/...`)로 통일**
- 호스트 PC 터미널에서 Docker 명령으로 실행하는 방식으로 통일

---

## 📝 수정된 문서

### 1️⃣ 문서: `2. Cisco NSO 6.6 Docker 설치 및 구성_정리.md`

**수정 항목:**

| 섹션 | 변경 전 | 변경 후 |
|------|--------|--------|
| 7.1 환경 접속 | 상대 경로 설명 | 절대 경로 사용 강조 |
| 7.2 NED 추출 | 컨테이너 내부 명령어 | Docker exec 명령어로 통일 |
| 7.3 인스턴스 생성 | 상대 경로 `~/ncs-instance` | 절대 경로 `/root/ncs-instance` |
| 7.4 서비스 시작 | 상대 경로 `~/ncs-instance` | Docker exec 백그라운드/포그라운드 옵션 |
| 7.5 패키지 로드 | 상대 경로 `~/nso-6.6` | 절대 경로 `/root/nso-6.6` |
| 6.3 상태 확인 | NSO 상태 확인 명령 없음 | `docker exec` 명령어 추가 |

**핵심 명령어 변경:**

```bash
# ❌ 변경 전
docker exec -it cisco-nso-dev bash -c "cd ~/ncs-instance && source ~/nso-6.6/ncsrc && ncs_cli -C -u admin"

# ✅ 변경 후
docker exec -it cisco-nso-dev bash -c "cd /root/ncs-instance && source /root/nso-6.6/ncsrc && ncs_cli -C -u admin"
```

---

### 2️⃣ 문서: `3. NSO-Pnetlab-Tailscale 연동_정리.md`

**수정 항목:**

| 섹션 | 변경 내용 |
|------|---------|
| VII-1 NSO CLI 접속 | 절대 경로 사용 + 경로 설명 추가 |

**추가된 설명:**

```
**중요**: `~` 상대 경로 대신 `/root/` 절대 경로를 사용해야 
Debug 환경과 정상 컨테이너 모두에서 작동합니다.
```

---

### 3️⃣ 문서: `5. 자동화 스크립트.md`

**수정 항목:**

| 섹션 | 변경 내용 |
|------|---------|
| 1.1 의존성 설치 | 실행 경로 수정 (Make_Dataset 폴더 진입 명시) |
| Automate_Setup.py | 상대 경로 → 절대 경로 변경 (코드 예제) |
| Config_Export_Batfish.py | 상대 경로 → 절대 경로 변경 (코드 예제) |
| 문제 해결 섹션 | NSO 상태 확인 명령어 추가 |

**주요 코드 변경:**

```python
# ❌ 변경 전
full_cmd = f'docker exec cisco-nso-dev bash -c "cd ~/ncs-instance && source ~/nso-6.6/ncsrc && ...'

# ✅ 변경 후
full_cmd = f'docker exec cisco-nso-dev bash -c "cd /root/ncs-instance && source /root/nso-6.6/ncsrc && ...'
```

---

## 🎯 올바른 사용 방법

### ✅ NSO CLI 접속 (권장)

```bash
# 호스트 PC 터미널에서 실행
docker exec -it cisco-nso-dev bash -c "cd /root/ncs-instance && source /root/nso-6.6/ncsrc && ncs_cli -C -u admin"
```

### ✅ NSO 상태 확인

```bash
# 호스트 PC 터미널에서 실행
docker exec cisco-nso-dev bash -c "cd /root/ncs-instance && source /root/nso-6.6/ncsrc && ncs --status"
```

### ✅ NED 패키지 확인

```bash
# 호스트 PC 터미널에서 실행
docker exec cisco-nso-dev bash -c "ls -la /root/nso-6.6/packages/neds/"
```

### ❌ 피해야 할 방법

```bash
# 상대 경로 사용 금지
docker exec -it cisco-nso-dev bash -c "cd ~/ncs-instance && ..."

# $HOME 변수 사용 금지
docker exec -it cisco-nso-dev bash -c "cd $HOME/ncs-instance && ..."
```

---

## 📋 검증 체크리스트

- [ ] NSO CLI 접속 명령어가 절대 경로를 사용하는가?
- [ ] 모든 `cd` 경로가 `/root/`로 시작하는가?
- [ ] `source` 경로가 `/root/nso-6.6/ncsrc`인가?
- [ ] Docker exec 명령어가 호스트 PC 터미널에서 실행되는가?
- [ ] 상대 경로(`~`, `./`)를 사용하는 부분이 없는가?

---

## 🔗 참고 명령어

| 작업 | 명령어 |
|------|--------|
| NSO CLI 진입 | `docker exec -it cisco-nso-dev bash -c "cd /root/ncs-instance && source /root/nso-6.6/ncsrc && ncs_cli -C -u admin"` |
| NSO 상태 확인 | `docker exec cisco-nso-dev bash -c "cd /root/ncs-instance && source /root/nso-6.6/ncsrc && ncs --status"` |
| NSO 버전 확인 | `docker exec cisco-nso-dev bash -c "source /root/nso-6.6/ncsrc && ncs --version"` |
| 컨테이너 bash 진입 | `docker exec -it cisco-nso-dev bash` |
| 컨테이너 로그 확인 | `docker logs cisco-nso-dev` |
| 컨테이너 실시간 로그 | `docker logs -f cisco-nso-dev` |

---

## 📌 주의사항

1. **절대 경로 필수**: 모든 NSO 관련 작업에서 절대 경로(`/root/...`)를 사용해야 합니다.
2. **호스트 PC 터미널**: Windows PowerShell이나 bash 등 호스트 PC의 터미널에서 `docker exec` 명령을 실행합니다.
3. **컨테이너 내부 접속**: 필요시 `docker exec -it cisco-nso-dev bash`로 컨테이너에 진입한 후 상대 경로 사용 가능합니다.


