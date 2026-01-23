# Skills 시스템

## 개요

Skills는 LLM 에이전트에게 주입되는 **도메인 지식 및 절차**를 모듈화한 것입니다. 각 Skill은 Markdown 파일로 작성되며, YAML frontmatter로 메타데이터를 정의합니다.

---

## 목적

1. **컨텍스트 효율화**: 필요한 Skill만 동적으로 로드하여 토큰 절감
2. **지식 모듈화**: 재사용 가능한 절차 및 정책 정의
3. **유지보수성**: 코드 변경 없이 Skill 업데이트 가능

---

## Skill 구조

```markdown
---
name: skill_name
description: 간단한 설명
priority: 1-10 (높을수록 우선)
tags: [network, bgp, troubleshooting]
enabled: true
---

# Skill 내용

구체적인 지침, 예시, 절차 등...
```

---

## Skill 카테고리

### 1. Core Skills (항상 로드)

- `core_policy.md`: 기본 정책 및 제약사항
- `tool_usage.md`: 도구 사용 가이드

### 2. Domain Skills (필요시 로드)

- `bgp_troubleshooting.md`: BGP 장애 진단
- `acl_verification.md`: ACL 검증
- `reachability_check.md`: 도달성 검사

### 3. Operational Runbooks (절차)

- `config_change_workflow.md`: 설정 변경 표준 절차
- `rollback_procedure.md`: Rollback 절차

---

## 사용 방법

### Skills Loader 사용

```python
from agent.skill_loader import SkillLoader

loader = SkillLoader(skills_dir="skills/")
skills = loader.load_enabled_skills()

# 특정 태그만 로드
bgp_skills = loader.load_by_tags(["bgp", "troubleshooting"])

# System Prompt 생성
system_prompt = loader.build_system_prompt(skills)
```

### ToolConfig와 통합

```python
from config.tool_config import get_preset

config = get_preset("no_runbook")
# config.enable_runbook_skills == False

# Loader가 자동으로 runbook 스킬 제외
loader = SkillLoader(config=config)
skills = loader.load_enabled_skills()
```

---

## 토큰 절감 효과

### Before (모든 Skill 로드)

```
System Prompt: 2,500 토큰
- core_policy.md: 500
- bgp_troubleshooting.md: 600
- acl_verification.md: 400
- reachability_check.md: 500
- config_change_workflow.md: 500
```

### After (선택적 로드)

```
Task: "CE01에서 10.0.3.10 도달 가능?"

필요 Skill만 로드:
- core_policy.md: 500
- reachability_check.md: 500

System Prompt: 1,000 토큰
절감: 60%
```

---

## 작성 가이드

### 1. YAML Frontmatter

```yaml
---
name: bgp_troubleshooting
description: BGP 세션 장애 진단 절차
priority: 7
tags: [bgp, routing, troubleshooting]
enabled: true
requires_tools: [network_query, network_verify]
---
```

### 2. 명확한 구조

```markdown
# BGP Troubleshooting Skill

## When to Use
BGP 세션이 Down 상태이거나 경로가 학습되지 않을 때

## Diagnosis Steps
1. `network_query("routing", device="PE1", params={"protocol": "bgp"})`
2. BGP neighbor 상태 확인
3. ...

## Common Issues
- Missing neighbor statement
- Wrong AS number
- ...
```

### 3. 도구 사용 예시 포함

```markdown
## Example Tool Calls

### 1. BGP 설정 조회
\`\`\`python
network_query(
    category="routing",
    device="PE1",
    params={"protocol": "bgp"}
)
\`\`\`
```

---

## 파일 구조

```
skills/
├── README.md                      # 이 파일
├── core/
│   ├── core_policy.md             # 기본 정책 (항상 로드)
│   └── tool_usage.md              # 도구 사용법
├── domain/
│   ├── bgp_troubleshooting.md
│   ├── acl_verification.md
│   └── reachability_check.md
└── runbooks/
    ├── config_change_workflow.md
    └── rollback_procedure.md
```

---

**다음**: `core/core_policy.md` 참조
