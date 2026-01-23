# Docker 네트워크 설정 가이드

이 문서는 Cisco NSO와 Batfish를 Docker로 실행하고 Tailscale을 통한 외부 네트워크 접근을 설정하는 방법을 설명합니다.

## 📋 목차
- [포트 구성](#포트-구성)
- [NSO 설정](#nso-설정)
- [Batfish 설정](#batfish-설정)
- [외부 네트워크 접근 설정](#외부-네트워크-접근-설정)
- [Docker 명령어](#docker-명령어)
- [문제 해결](#문제-해결)

## 🔌 포트 구성

### NSO (Cisco Network Services Orchestrator)
| 서비스 | 컨테이너 포트 | 호스트 포트 | 설명 |
|-------|------------|----------|------|
| NSO CLI | 2022 | 2022 | NSO CLI 접근 |
| NSO SSH | 2024 | 2024 | NSO CLI over SSH |
| NSO Web UI | 8080 | 8080 | NSO 웹 인터페이스 |
| NSO REST API | 8888 | 8888 | NSO REST API |

### Batfish
| 서비스 | 컨테이너 포트 | 호스트 포트 | 설명 |
|-------|------------|----------|------|
| Batfish Service | 9996 | 9996 | Batfish 서비스 |
| Jupyter Notebook | 8888 | 8889 | Jupyter (포트 충돌 방지) |

> ⚠️ **포트 충돌 주의**: NSO와 Batfish 모두 8888 포트를 사용하기 때문에, Batfish의 Jupyter는 호스트의 8889 포트로 매핑했습니다.

## 🚀 NSO 설정

### 디렉토리 구조
```
cisco-nso-docker/
├── Dockerfile
├── docker-compose.yml
├── entrypoint.sh
├── nso-6.6.linux.x86_64.installer.bin
├── packages/
│   └── ncs-6.6-cisco-*
└── ncs-instance/  (자동 생성됨)
```

### Docker Compose 설정
파일 위치: `/home/kilab_pyj/codespace/cisco-nso-docker/docker-compose.yml`

주요 설정:
- **이미지**: `cisco-nso-dev:6.6` (로컬 빌드)
- **외부 접근**: 모든 포트가 `0.0.0.0`에 바인딩되어 Tailscale을 통한 외부 접근 가능
- **자동 재시작**: `restart: unless-stopped`
- **데이터 지속성**: `./ncs-instance` 볼륨 마운트

## 🦇 Batfish 설정

### 디렉토리 구조
```
Batfish/
├── allinone.dockerfile
├── docker-compose.yml
├── wrapper.sh
└── data/  (자동 생성됨)
```

### Docker Compose 설정
파일 위치: `/home/kilab_pyj/codespace/Batfish/docker-compose.yml`

주요 설정:
- **이미지**: `batfish-allinone:local` (로컬 빌드)
- **외부 접근**: 모든 포트가 `0.0.0.0`에 바인딩
- **Jupyter 포트**: 호스트 8889로 매핑 (NSO와 충돌 방지)
- **데이터 지속성**: `./data` 볼륨 마운트

## 🌐 외부 네트워크 접근 설정

### Tailscale 연결 확인
Tailscale이 이미 PC 간 연결되어 있다고 가정합니다.

1. **현재 PC의 Tailscale IP 확인**:
   ```bash
   tailscale ip -4
   ```

2. **방화벽 포트 열기** (필요시):
   ```bash
   # NSO 포트
   sudo ufw allow 2022/tcp
   sudo ufw allow 2024/tcp
   sudo ufw allow 8080/tcp
   sudo ufw allow 8888/tcp
   
   # Batfish 포트
   sudo ufw allow 9996/tcp
   sudo ufw allow 8889/tcp
   ```

### 외부 PC에서 접근하기

외부 PC에서 Tailscale IP를 통해 접근:

**NSO 접근**:
- Web UI: `http://<tailscale-ip>:8080`
- REST API: `http://<tailscale-ip>:8888`
- SSH CLI: `ssh -p 2024 admin@<tailscale-ip>`

**Batfish 접근**:
- Jupyter: `http://<tailscale-ip>:8889`
- Batfish API: `http://<tailscale-ip>:9996`

## 📝 Docker 명령어

### NSO

**빌드 (완료됨)**:
```bash
cd /home/kilab_pyj/codespace/cisco-nso-docker
docker compose build
```

**컨테이너 시작**:
```bash
docker compose up -d
```

**로그 확인**:
```bash
docker compose logs -f cisco-nso-dev
```

**컨테이너 접속**:
```bash
docker exec -it cisco-nso-dev bash
```

**컨테이너 중지**:
```bash
docker compose down
```

### Batfish

**빌드 및 시작**:
```bash
cd /home/kilab_pyj/codespace/Batfish
docker compose build
docker compose up -d
```

**로그 확인**:
```bash
docker compose logs -f batfish-allinone
```

**컨테이너 접속**:
```bash
docker exec -it batfish-allinone bash
```

**컨테이너 중지**:
```bash
docker compose down
```

### 모든 컨테이너 상태 확인
```bash
docker ps -a
```

### 이미지 확인
```bash
docker images | grep -E "cisco-nso|batfish"
```

## 🔧 문제 해결

### 포트가 이미 사용 중인 경우
```bash
# 포트 사용 확인
sudo lsof -i :<포트번호>

# 포트 사용 프로세스 종료
sudo kill -9 <PID>
```

### Docker 네트워크 충돌
```bash
# Docker 네트워크 목록 확인
docker network ls

# 사용하지 않는 네트워크 제거
docker network prune
```

### 컨테이너가 시작되지 않을 때
```bash
# 컨테이너 로그 확인
docker compose logs <서비스명>

# 컨테이너 상태 확인
docker inspect <컨테이너명>
```

### Tailscale 연결 문제
```bash
# Tailscale 상태 확인
tailscale status

# Tailscale 재시작
sudo systemctl restart tailscaled
```

## 🔐 보안 고려사항

1. **기본 자격증명 변경**: NSO의 기본 admin/admin 자격증명을 변경하세요.
2. **방화벽 규칙**: 필요한 포트만 열어두세요.
3. **HTTPS 설정**: 프로덕션 환경에서는 HTTPS를 설정하세요.
4. **Tailscale ACL**: Tailscale ACL을 설정하여 접근을 제한하세요.

## 📊 다음 단계

1. **NSO 초기 설정**: 컨테이너 시작 후 NSO 웹 UI에 접속하여 초기 설정
2. **Batfish 테스트**: Jupyter 노트북에 접속하여 예제 실행
3. **네트워크 구성 추가**: NSO에 네트워크 장비 추가
4. **Batfish 분석**: Batfish로 네트워크 구성 분석

## 💡 유용한 팁

- Docker 컨테이너는 `restart: unless-stopped` 정책으로 설정되어 있어 시스템 재부팅 시 자동으로 시작됩니다.
- `ncs-instance`와 `data` 디렉토리는 로컬에 마운트되어 있어 데이터가 영구 보존됩니다.
- 외부 접근 시 Tailscale IP는 고정되므로 북마크해두면 편리합니다.
