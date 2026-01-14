# MCP Inspector 테스트 가이드

## 🐛 연결 문제 해결

MCP Inspector의 "Invalid origin" 에러는 CORS 정책 때문입니다.

### 해결 방법 1: 경로 지정 (권장)

```bash
cd NetConfigQA3
mcp-inspector python3 "$(pwd)/mcp_skills_server.py"
```

### 해결 방법 2: 절대 경로 사용

```bash
mcp-inspector python3 /mnt/c/Users/Yujin/My\ Drive/Workscpace/Projects/GIA/NetConfigQA3/mcp_skills_server.py
```

### 해결 방법 3: 환경 변수 설정

```bash
export DANGEROUSLY_OMIT_AUTH=true
mcp-inspector python3 mcp_skills_server.py
```

---

## 🚀 Skills-Controlled MCP 서버 테스트

### 1. MCP Inspector로 시작

```bash
cd /mnt/c/Users/Yujin/My\ Drive/Workscpace/Projects/GIA/NetConfigQA3
mcp-inspector python3 mcp_skills_server.py
```

브라우저가 자동으로 열립니다: `http://localhost:6274/`

---

### 2. 사용 가능한 도구 확인

브라우저에서 왼쪽 도구 목록을 확인하세요:

**초기 상태** (Skills 미로드):
- `load_skill` - Skill 로드
- `set_task_context` - Task 기반 자동 로드
- `list_available_skills` - Skills 목록
- `get_enabled_tools_status` - 활성화된 도구 확인

**이후 상태** (Skills 로드 후):
- NSO 도구들 (조건부)
- Batfish 도구들 (조건부)
- PNETLab 도구들 (조건부)

---

### 3. 테스트 시나리오

#### Scenario 1: Skills 목록 확인

**도구**: `list_available_skills`

**파라미터**: 없음

**예상 결과**:
```json
{
  "skills": [
    {
      "name": "core_policy",
      "description": "네트워크 운영 에이전트 핵심 정책 및 제약사항",
      "tags": ["core", "policy", "safety"],
      "requires_tools": []
    },
    {
      "name": "bgp_troubleshooting",
      "description": "BGP 세션 장애 진단 및 해결 절차",
      "tags": ["bgp", "routing", "troubleshooting", "domain"],
      "requires_tools": ["network_query", "network_verify"]
    }
  ]
}
```

---

#### Scenario 2: Task 기반 Skills 자동 로드

**도구**: `set_task_context`

**파라미터**:
```json
{
  "task": "PE1과 PE2 간 BGP 세션이 Down입니다"
}
```

**예상 결과**:
```json
{
  "success": true,
  "task": "PE1과 PE2 간 BGP 세션이 Down입니다",
  "loaded_skills": ["core_policy", "bgp_troubleshooting"],
  "enabled_tools": [
    "batfish_init",
    "batfish_verify_reachability",
    "nso_get_config",
    "nso_get_device_info",
    "nso_get_devices"
  ],
  "stats": {
    "loaded_skills": 2,
    "enabled_tools": 5,
    "disabled_tools": 3,
    "total_tools": 8,
    "reduction_rate": 37.5
  }
}
```

**효과**: BGP 관련 도구만 활성화되어 37.5% 도구 절감!

---

#### Scenario 3: 개별 Skill 로드

**도구**: `load_skill`

**파라미터**:
```json
{
  "skill_name": "bgp_troubleshooting"
}
```

**예상 결과**:
```json
{
  "success": true,
  "skill_name": "bgp_troubleshooting",
  "description": "BGP 세션 장애 진단 및 해결 절차",
  "enabled_tools": [
    "batfish_init",
    "batfish_verify_reachability",
    "nso_get_config"
  ],
  "content_preview": "# BGP Troubleshooting Skill..."
}
```

---

#### Scenario 4: 활성화된 도구 상태 확인

**도구**: `get_enabled_tools_status`

**파라미터**: 없음

**예상 결과**:
```json
{
  "enabled_tools": [
    "batfish_init",
    "batfish_verify_reachability",
    "nso_get_config",
    "nso_get_device_info",
    "nso_get_devices"
  ],
  "count": 5
}
```

---

#### Scenario 5: 비활성화된 도구 호출 시도

**Skills 로드 전 상태에서**:

**도구**: `nso_get_devices`

**파라미터**: 없음

**예상 결과**:
```json
{
  "error": "Tool not enabled. Load required skill first."
}
```

**Skills 로드 후 상태에서**:

같은 도구 호출 → 정상 작동!

---

## 📊 토큰 절감 확인

### Before (모든 도구 노출)

```
총 MCP 도구: 8개
- nso_get_devices
- nso_get_config
- nso_get_device_info
- nso_export_configs
- batfish_init
- batfish_verify_reachability
- pnetlab_inventory
- pnetlab_get_status
```

### After (BGP Task)

```
활성화된 도구: 5개 (37.5% 절감)
- nso_get_devices
- nso_get_config
- nso_get_device_info
- batfish_init
- batfish_verify_reachability

비활성화된 도구: 3개
- nso_export_configs
- pnetlab_inventory
- pnetlab_get_status
```

---

## 🎯 실제 워크플로우

### 1. LLM 에이전트 시작

```python
from langchain_openai import ChatOpenAI
from langchain.agents import create_mcp_agent

# Skills-Controlled MCP 서버 연결
mcp_client = MCPClient("http://localhost:6277")

# Task 설정
mcp_client.call_tool("set_task_context", {
    "task": "CE01에서 10.0.3.10으로 ping이 안 됩니다"
})

# 에이전트 생성
agent = create_mcp_agent(
    llm=ChatOpenAI(model="gpt-4o"),
    mcp_client=mcp_client
)

# 실행
result = agent.run("CE01에서 10.0.3.10으로 ping이 안 됩니다. 원인을 찾아주세요.")
```

### 2. 에이전트가 보는 도구

```
사용 가능한 도구 (Skills가 활성화한 것만):
- nso_get_config
- batfish_verify_reachability
- batfish_init
```

### 3. 에이전트 실행

```
1. batfish_init(snapshot_path="./snapshot")
   → 스냅샷 초기화

2. batfish_verify_reachability(src="CE01", dst="10.0.3.10")
   → 결과: Blocked by ACL

3. nso_get_config(device="PE1", config_path="ip/access-list")
   → ACL 확인

4. [해결 방안 제시]
```

---

## 🔧 트러블슈팅

### 1. "Invalid origin" 에러

**원인**: CORS 정책

**해결**:
```bash
export DANGEROUSLY_OMIT_AUTH=true
mcp-inspector python3 mcp_skills_server.py
```

### 2. "Tool not enabled" 에러

**원인**: Skills를 먼저 로드하지 않음

**해결**:
1. `list_available_skills` 호출
2. `load_skill` 또는 `set_task_context` 호출
3. 원하는 도구 사용

### 3. Python 경로 문제

**해결**:
```bash
cd /mnt/c/Users/Yujin/My\ Drive/Workscpace/Projects/GIA/NetConfigQA3
python3 -m mcp_skills_server
```

---

**작성일**: 2026-01-14  
**버전**: 1.0.0
