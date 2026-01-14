# Skills-Controlled NSO Agent 통합 가이드

기존 `NSO/agent.py`에 Skills 시스템을 통합하는 방법입니다.

---

## 🎯 통합 목표

**Before**: 11개 도구를 항상 모두 노출  
**After**: Task에 따라 필요한 도구만 동적으로 노출 (Skills 제어)

---

## 📝 수정 방법

### 1. Skills 시스템 Import 추가

`NSO/agent.py` 상단에 추가:

```python
# Skills 시스템 import
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

from agent.skill_loader import load_skills_for_task, SkillLoader
from agent.skill_controlled_mcp import SkillControlledMCPServer
```

### 2. 도구를 Skills와 매핑

현재 11개 도구를 Skills `requires_tools`와 매핑:

```python
# agent/skill_controlled_mcp.py에 추가할 매핑
TOOL_TO_MCP_MAPPING = {
    # 기존 매핑...
    
    # NSO Agent 도구 추가
    "network_discovery": [
        "scan_network_devices",
        "inspect_device_basic_info"
    ],
    "network_diagnosis": [
        "get_interfaces_status",
        "get_ip_address_map",
        "get_routing_status",
        "get_vrf_list"
    ],
    "network_analysis": [
        "compare_devices_configuration",
        "find_devices_by_query",
        "detect_network_anomalies"
    ],
    "network_verification": [
        "verify_reachability_ping",
        "trace_traffic_path"
    ]
}
```

### 3. Task 실행 시 Skills 로드

기존 Chat Loop 수정:

```python
while True:
    q = input("User (exit to quit): ")
    
    if q.lower() in ["exit", "quit"]:
        break
    
    # === Skills 기반 도구 필터링 ===
    print("🔍 Analyzing task and loading Skills...")
    task_skills = load_skills_for_task(q)
    skill_names = [s.name for s in task_skills]
    print(f"   Loaded Skills: {skill_names}")
    
    # Skills가 필요한 도구만 활성화
    server = SkillControlledMCPServer(task_skills)
    enabled_tool_names = server.get_enabled_tools()
    
    # 활성화된 도구만 필터링
    filtered_tools = [tool for tool in tools if tool.name in enabled_tool_names]
    
    print(f"   Enabled Tools: {len(filtered_tools)}/{len(tools)}")
    print(f"   Token Reduction: {server.get_stats()['reduction_rate']:.1f}%")
    
    # === 필터링된 도구로 에이전트 재생성 ===
    # 효율을 위해 동적으로 에이전트를 생성하거나,
    # 모든 도구를 등록하되 Skills가 없으면 "Tool not enabled" 반환
    
    # 방법 1: 동적 에이전트 생성 (권장)
    filtered_agent = create_react_agent(llm, filtered_tools, checkpointer=memory)
    
    # 에이전트 실행
    response = filtered_agent.invoke(
        {"messages": [("system", system_prompt), ("user", q)]},
        config=config
    )
    
    # 응답 출력...
```

---

## 🚀 빠른 통합 스크립트

전체 수정 버전을 자동으로 적용:

```bash
cd NetConfigQA3

# Skills-Controlled NSO Agent 실행
python3 NSO/agent_with_skills.py
```

---

## 💡 핵심 변경 사항

### Before
```python
tools = [
    scan_network_devices,
    inspect_device_basic_info,
    ...  # 11개 도구 항상 노출
]

agent_executor = create_react_agent(llm, tools, checkpointer=memory)
```

### After
```python
# Task 분석
task_skills = load_skills_for_task(user_query)
server = SkillControlledMCPServer(task_skills)
enabled_tools = [t for t in tools if t.name in server.get_enabled_tools()]

# 필터링된 도구로 에이전트 생성
agent_executor = create_react_agent(llm, enabled_tools, checkpointer=memory)
```

---

## 📊 예상 효과

| Task | 기존 도구 수 | Skills 제어 후 | 절감율 |
|------|-----------|------------|-------|
| "장비 목록 보여줘" | 11개 | 2개 | 82% |
| "IP 충돌 있어?" | 11개 | 5개 | 55% |
| "R1과 R2 BGP 네이버 수 비교" | 11개 | 7개 | 36% |

---

**작성일**: 2026-01-14  
**수정 파일**: `NSO/agent_with_skills.py` (새로 생성)
