"""
LabMate Skill Loader (Simplified)

Skills 디렉토리에서 SKILL.md 파일을 로드하고
Orchestrator가 선택한 Skills에 따라 도구를 필터링합니다.
"""

import os
import re
from pathlib import Path
from typing import List, Dict, Any, Optional, Set
from dataclasses import dataclass
import yaml


@dataclass
class Skill:
    """Skill 메타데이터"""
    name: str
    description: str
    priority: int
    tags: List[str]
    enabled: bool
    requires_tools: List[str]
    content: str
    
    def token_estimate(self) -> int:
        """토큰 수 추정"""
        return len(self.content) // 4


class SkillLoader:
    """Skills 로더
    
    Usage:
        loader = SkillLoader()
        all_skills = loader.load_all()
        catalog = loader.get_catalog()  # Orchestrator용
    """
    
    def __init__(self, skills_dir: str = None):
        if skills_dir is None:
            skills_dir = Path(__file__).parent.parent / "skills"
        self.skills_dir = Path(skills_dir)
        self._cache: Dict[str, Skill] = {}
    
    def load_all(self) -> List[Skill]:
        """모든 Skill 로드"""
        skills = []
        
        if not self.skills_dir.exists():
            return skills
        
        for skill_dir in self.skills_dir.iterdir():
            if skill_dir.is_dir():
                skill_file = skill_dir / "SKILL.md"
                if skill_file.exists():
                    skill = self._parse_skill(skill_file)
                    if skill and skill.enabled:
                        skills.append(skill)
                        self._cache[skill.name] = skill
        
        # 우선순위 정렬
        skills.sort(key=lambda s: s.priority, reverse=True)
        return skills
    
    def load_by_names(self, names: List[str]) -> List[Skill]:
        """이름으로 Skill 로드"""
        if not self._cache:
            self.load_all()
        
        return [self._cache[name] for name in names if name in self._cache]
    
    def get_core_skills(self) -> List[Skill]:
        """Core Skill 로드 (항상 포함)"""
        all_skills = self.load_all()
        return [s for s in all_skills if "core" in s.tags]
    
    def get_catalog(self) -> str:
        """Orchestrator용 Skill 카탈로그 (간결)"""
        skills = self.load_all()
        lines = ["## Available Skills"]
        for s in skills:
            lines.append(f"- **{s.name}**: {s.description}")
        return "\n".join(lines)
    
    def get_required_tools(self, skills: List[Skill]) -> Set[str]:
        """Deprecated: tool access control is no longer managed by skills.

        MCP-lite mode keeps skills as prompt guidance only.
        """
        return set()
    
    def build_executor_prompt(self, skills: List[Skill]) -> str:
        """Executor용 Skill 프롬프트"""
        parts = []
        for skill in skills:
            parts.append(f"## Skill: {skill.name}")
            parts.append(skill.content)
            parts.append("")
        return "\n".join(parts)
    
    def _parse_skill(self, filepath: Path) -> Optional[Skill]:
        """SKILL.md 파싱"""
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                content = f.read()
            
            # YAML frontmatter
            match = re.match(r'^---\s*\n(.*?)\n---\s*\n(.*)', content, re.DOTALL)
            if not match:
                return None
            
            meta = yaml.safe_load(match.group(1))
            body = match.group(2).strip()
            
            return Skill(
                name=meta.get('name', filepath.parent.name),
                description=meta.get('description', ''),
                priority=meta.get('priority', 5),
                tags=meta.get('tags', []),
                enabled=meta.get('enabled', True),
                requires_tools=meta.get('requires_tools', []),
                content=body,
            )
        except Exception as e:
            print(f"Warning: Failed to parse {filepath}: {e}")
            return None


# 편의 함수
_loader = None

def get_loader() -> SkillLoader:
    global _loader
    if _loader is None:
        _loader = SkillLoader()
    return _loader


def get_skill_catalog() -> str:
    """Orchestrator용 카탈로그"""
    return get_loader().get_catalog()


def load_skills(names: List[str]) -> List[Skill]:
    """이름으로 Skills 로드"""
    loader = get_loader()
    core = loader.get_core_skills()
    selected = loader.load_by_names(names)
    
    # Core + Selected (중복 제거)
    seen = set()
    result = []
    for skill in core + selected:
        if skill.name not in seen:
            seen.add(skill.name)
            result.append(skill)
    
    return result


if __name__ == "__main__":
    loader = SkillLoader()
    
    print("=== All Skills ===")
    for skill in loader.load_all():
        print(f"- {skill.name} (priority={skill.priority}, tools={skill.requires_tools})")
    
    print("\n=== Catalog ===")
    print(loader.get_catalog())
