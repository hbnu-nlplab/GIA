# 🎉 Docker 네트워크 설정 완료! (업데이트됨)

Cisco NSO와 Batfish가 성공적으로 Docker 컨테이너로 실행되고 Tailscale을 통한 외부 네트워크 접근이 가능하도록 설정되었습니다.

## ✅ 현재 상태

### 실행 중인 컨테이너
- **cisco-nso-dev**: ✅ 정상 실행 중 (내부 포트 8888로 변경 완료)
- **batfish-allinone**: ✅ 정상 실행 중

### Tailscale IP
- **현재 PC의 Tailscale IP**: `100.67.63.77`

## 🔌 접근 정보

### NSO (Cisco Network Services Orchestrator)
| 서비스 | 로컬 접근 | 외부 접근 (Tailscale) | 설명 |
|-------|---------|---------------------|------|
| **NSO Web UI & REST** | `http://localhost:8888` | `http://100.67.63.77:8888` | **NSO 웹 인터페이스 및 RESTCONF** |
| NSO SSH | `localhost:2024` | `100.67.63.77:2024` | NSO CLI over SSH |
| NSO NETCONF | `localhost:2022` | `100.67.63.77:2022` | NSO NETCONF (SSH) |

**기본 자격증명**: `admin / admin`

### Batfish
| 서비스 | 로컬 접근 | 외부 접근 (Tailscale) | 설명 |
|-------|---------|---------------------|------|
| **Jupyter Notebook** | `http://localhost:8889` | `http://100.67.63.77:8889` | **Jupyter (토큰 필요)** |
| Batfish Service | `localhost:9996` | `100.67.63.77:9996` | Batfish 서비스 |

## 🚀 빠른 시작

### NSO RESTCONF 테스트
브라우저 또는 테스트 스크립트에서 다음 URL을 사용하세요:
```
http://100.67.63.77:8888/restconf
```

### NSO 웹 UI 접근
```
http://100.67.63.77:8888/
```

### Batfish Jupyter 접근
```bash
# Jupyter 토큰 확인
docker compose -f /home/kilab_pyj/codespace/Batfish/docker-compose.yml logs batfish-allinone | grep token

# URL: http://100.67.63.77:8889
```

## 🔧 문제 해결 요약
- **8888 포트 거부 문제**: NSO 내부 설정(`ncs.conf`)에서 WebUI/RESTCONF 포트를 8080에서 8888로 변경하여 해결했습니다.
- **포트 충돌 해결**: NSO(8888), Batfish Jupyter(8889)로 각각 분리하였습니다.

---
**🎉 이제 100.67.63.77:8888로 NSO와 RESTCONF에 정상적으로 접근하실 수 있습니다!**

## ✅ (추가) 외부 접속 문제 해결 완료 (2026-01-14)
NSO 보안 설정(`ncs.conf`)을 수정하여 Tailscale IP와 같은 외부 주소 접근 시 `400 Bad Request`가 발생하는 문제를 해결했습니다.
이제 브라우저나 스크립트에서 별도의 Host 헤더 조작 없이 바로 접속 가능합니다.

- **URL**: `http://100.67.63.77:8888/`
- **상태**: 정상 (로그인 창 또는 401 응답 확인)

### CVAT (Computer Vision Annotation Tool)
| 서비스 | 로컬 접근 | 외부 접근 (Tailscale) | 설명 |
|-------|---------|---------------------|------|
| **CVAT UI** | `http://localhost:9080` | `http://100.67.63.77:9080` | **CVAT 웹 인터페이스** |
| Traefik Dash | `http://localhost:9090` | `http://100.67.63.77:9090` | Traefik 대시보드 |

- **포트 설정**: NSO(8888) 및 Batfish(8889)와의 충돌을 피하기 위해 **9080** 포트를 사용하도록 설정했습니다.

## 🧩 통합 환경 변수 (Verified)
테스트를 통해 검증된 환경 변수 설정입니다. `.env` 파일이나 애플리케이션 설정에 사용하세요.

```properties
# NSO 설정
NSO_BASE_URL=http://100.67.63.77:8888/restconf
NSO_USER=admin
NSO_PASS=admin

# Batfish 설정
BATFISH_HOST=100.67.63.77
BATFISH_NETWORK=netconfig_qa  # 원하는 네트워크 이름으로 변경 가능
```
