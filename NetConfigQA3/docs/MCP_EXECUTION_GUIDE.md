# MCP 서버 실행 가이드

## 🚀 빠른 시작

NetConfigQA3 MCP 서버를 실행하는 방법을 안내합니다.

---

## 1️⃣ 개별 MCP 서버 실행

각 MCP 서버를 독립적으로 실행할 수 있습니다.

### NSO MCP Server

```bash
cd NetConfigQA3
python3 mcp_servers/nso_server.py
```

**기능**:
- `nso.get_devices`: 장비 목록 조회
- `nso.get_config`: 설정 조회
- `nso.export_batfish_configs`: 하이브리드 추출
- `nso.run_command`: CLI 명령 실행

**필수 환경변수** (`.env`):
```bash
NSO_BASE_URL=http://localhost:8080/restconf/data
NSO_USERNAME=admin
NSO_PASSWORD=admin
```

---

### Batfish MCP Server

```bash
cd NetConfigQA3
python3 mcp_servers/batfish_server.py
```

**기능**:
- `batfish.init_snapshot`: 스냅샷 초기화
- `batfish.check_reachability`: 도달성 검증
- `batfish.traceroute`: 경로 추적
- `batfish.get_bgp_sessions`: BGP 세션 상태

---

### PNETLab MCP Server

```bash
cd NetConfigQA3
python3 mcp_servers/pnetlab_server.py
```

**기능**:
- `pnetlab.show_inventory`: Lab 인벤토리
- `pnetlab.get_status`: 노드 상태
- `pnetlab.get_console_link`: 콘솔 링크

**필수 환경변수**:
```bash
PNETLAB_COOKIES="privacy=true; token=...; _session=...; XSRF-TOKEN=..."
PNETLAB_BASE_URL=https://100.66.240.82
```

---

## 2️⃣ FastMCP 통합 서버 실행 (권장)

모든 MCP 도구를 하나의 서버로 통합하여 실행합니다.

```bash
cd NetConfigQA3
python3 mcp_main.py
```

**노출되는 도구**:
```
- nso_get_devices
- nso_get_config
- nso_get_device_info
- nso_export_configs
- batfish_init
- batfish_verify_reachability
- pnetlab_inventory
- pnetlab_get_status
```

---

## 3️⃣ MCP Inspector로 테스트

MCP Inspector를 사용하여 서버를 테스트할 수 있습니다.

### 설치

```bash
npm install -g @modelcontextprotocol/inspector
```

### 실행

```bash
# 개별 서버 테스트
mcp-inspector python3 mcp_servers/nso_server.py

# 통합 서버 테스트
mcp-inspector python3 mcp_main.py
```

브라우저가 자동으로 열리며 도구를 테스트할 수 있습니다.

---

## 4️⃣ Cursor/Claude Desktop에서 사용

### Cursor 설정

`.cursor/mcp.json`:

```json
{
  "mcpServers": {
    "netconfigqa3": {
      "command": "python3",
      "args": [
        "/절대/경로/NetConfigQA3/mcp_main.py"
      ],
      "env": {
        "NSO_BASE_URL": "http://localhost:8080/restconf/data",
        "NSO_USERNAME": "admin",
        "NSO_PASSWORD": "admin"
      }
    }
  }
}
```

### Claude Desktop 설정

`~/Library/Application Support/Claude/claude_desktop_config.json` (Mac):

```json
{
  "mcpServers": {
    "netconfigqa3": {
      "command": "python3",
      "args": [
        "/absolute/path/to/NetConfigQA3/mcp_main.py"
      ]
    }
  }
}
```

---

## 5️⃣ 프로그래밍 방식으로 사용

### Python에서 직접 호출

```python
import asyncio
from mcp_servers.nso_server import NSOServer

async def main():
    server = NSOServer()
    
    # 장비 목록 조회
    devices = server.get_devices()
    print(f"장비: {devices}")
    
    # 설정 추출
    result = server.export_batfish_configs(
        devices=["CE01", "PE01"],
        output_dir="./snapshot",
        export_yang_json=True
    )
    print(f"추출 결과: {result}")

asyncio.run(main())
```

---

## 6️⃣ Unified Tools 사용 (통합 인터페이스)

LLM에 노출되는 7개 통합 도구를 직접 사용할 수 있습니다.

```python
from agent.unified_tools import (
    network_query,
    network_verify,
    lab_manage
)
from config.tool_config import get_preset, ToolProvider

# 프리셋 로드
config = get_preset("full")
provider = ToolProvider(config)
tools = provider.get_langchain_tools()

print(f"활성화된 도구: {len(tools)}개")
print(f"도구 이름: {provider.get_tool_names()}")

# 도구 사용 예시
result = network_query(
    category="device",
    device=None
)
print(result)
```

---

## 7️⃣ 테스트 스크립트

### MCP 런타임 테스트

```bash
cd NetConfigQA3
python3 test_mcp_runtime.py
```

이 스크립트는:
- NSO 서버 연결 확인
- 하이브리드 추출 테스트 (CFG + XML + YANG JSON)
- 결과 검증

---

## 🔧 문제 해결

### 1. MCP SDK 미설치

```bash
pip install "mcp>=1.0.0"
```

### 2. NSO Docker 컨테이너 미실행

```bash
docker ps | grep nso
# 없으면 NSO 컨테이너 시작
docker start cisco-nso-dev
```

### 3. 환경변수 누락

```bash
cp config/env_example.txt .env
# .env 파일 편집하여 실제 값 입력
```

### 4. Python 경로 문제

```bash
export PYTHONPATH="${PYTHONPATH}:/절대/경로/NetConfigQA3"
```

---

## 📊 성능 모니터링

### 로그 확인

```bash
# 실시간 로그
tail -f logs/mcp_server.log

# 에러만 필터링
grep ERROR logs/mcp_server.log
```

### 디버그 모드

```bash
# 환경변수로 로그 레벨 설정
export LOG_LEVEL=DEBUG
python3 mcp_main.py
```

---

## 🎯 다음 단계

MCP 서버가 정상 작동하면:

1. **Skills 시스템 활용**: `skills/` 디렉토리의 Skill 파일로 토큰 절감
2. **Ablation Study 실행**: `config/tool_config.py` 프리셋 전환
3. **LangGraph 에이전트 통합**: Phase 4 진행

---

**작성일**: 2026-01-14  
**버전**: 1.0.0
