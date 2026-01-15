"""
Skill Loader

Skills 디렉토리에서 Markdown 파일을 읽어와 LLM System Prompt에 주입합니다.
동적 로딩으로 토큰 절감을 달성합니다.
"""

import os
import re
from pathlib import Path
from typing import List, Dict, Any, Optional
from dataclasses import dataclass
import yaml


@dataclass
class Skill:
    """Skill 메타데이터 및 내용"""
    name: str
    description: str
    priority: int
    tags: List[str]
    enabled: bool
    requires_tools: List[str]
    content: str
    filepath: str
    
    def __post_init__(self):
        """우선순위 기본값 설정"""
        if not isinstance(self.priority, int):
            self.priority = 5
    
    def matching_tags(self, tags: List[str]) -> bool:
        """태그 매칭 여부"""
        return any(tag in self.tags for tag in tags)
    
    def token_estimate(self) -> int:
        """토큰 수 추정 (간단한 휴리스틱)"""
        # 대략 4 characters = 1 token
        return len(self.content) // 4


class SkillLoader:
    """
    Skills 디렉토리에서 Skill 파일을 로드하는 클래스
    
    Usage:
        loader = SkillLoader(skills_dir="skills/")
        skills = loader.load_enabled_skills()
        prompt = loader.build_system_prompt(skills)
    """
    
    def __init__(
        self,
        skills_dir: str = "skills/",
        config: Optional[Any] = None
    ):
        """
        Args:
            skills_dir: Skills 디렉토리 경로
            config: ToolConfig 인스턴스 (선택적)
        """
        self.skills_dir = Path(skills_dir)
        self.config = config
        self._skills_cache: Dict[str, Skill] = {}
    
    def load_all_skills(self) -> List[Skill]:
        """
        모든 Skill 파일 로드
        
        표준 구조와 레거시 구조 모두 지원:
        - 표준: skills/skill-name/SKILL.md
        - 레거시: skills/*.md
        """
        skills = []
        
        if not self.skills_dir.exists():
            return skills
        
        # 1. 표준 구조: 폴더 내 SKILL.md 파일 찾기
        for skill_dir in self.skills_dir.iterdir():
            if skill_dir.is_dir():
                skill_file = skill_dir / "SKILL.md"
                if skill_file.exists():
                    skill = self._parse_skill_file(skill_file)
                    if skill:
                        skills.append(skill)
                        self._skills_cache[skill.name] = skill
                        continue
                
                # 폴더 내 다른 .md 파일도 확인 (레거시 호환)
                for md_file in skill_dir.glob("*.md"):
                    if md_file.name == "README.md":
                        continue
                    skill = self._parse_skill_file(md_file)
                    if skill:
                        skills.append(skill)
                        self._skills_cache[skill.name] = skill
        
        # 2. 레거시 구조: 루트의 .md 파일
        for md_file in self.skills_dir.glob("*.md"):
            if md_file.name == "README.md":
                continue
            
            skill = self._parse_skill_file(md_file)
            if skill and skill.name not in self._skills_cache:
                skills.append(skill)
                self._skills_cache[skill.name] = skill
        
        # 중복 제거 (이름 기준)
        seen = set()
        unique_skills = []
        for skill in skills:
            if skill.name not in seen:
                seen.add(skill.name)
                unique_skills.append(skill)
        
        # 우선순위 순으로 정렬
        unique_skills.sort(key=lambda s: s.priority, reverse=True)
        return unique_skills
    
    def load_enabled_skills(self) -> List[Skill]:
        """활성화된 Skill만 로드"""
        all_skills = self.load_all_skills()
        
        enabled = [s for s in all_skills if s.enabled]
        
        # ToolConfig가 제공되면 runbook 스킬 필터링
        if self.config and hasattr(self.config, 'enable_runbook_skills'):
            if not self.config.enable_runbook_skills:
                enabled = [s for s in enabled if 'runbook' not in s.tags]
        
        return enabled
    
    def load_by_tags(self, tags: List[str]) -> List[Skill]:
        """특정 태그를 가진 Skill만 로드"""
        all_skills = self.load_all_skills()
        return [s for s in all_skills if s.matching_tags(tags)]
    
    def load_by_names(self, names: List[str]) -> List[Skill]:
        """
        이름 목록으로 Skill 로드 (Planner가 선택한 스킬)
        
        Args:
            names: 스킬 이름 리스트 (예: ["core_policy", "device_lifecycle_playbook"])
            
        Returns:
            매칭된 Skill 리스트 (우선순위 순 정렬)
        """
        all_skills = self.load_all_skills()
        matched = [s for s in all_skills if s.name in names]
        matched.sort(key=lambda s: s.priority, reverse=True)
        return matched
    
    def load_core_skills(self) -> List[Skill]:
        """Core Skill만 로드 (항상 포함)"""
        return self.load_by_tags(["core"])
    
    def _parse_skill_file(self, filepath: Path) -> Optional[Skill]:
        """Skill 파일 파싱"""
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                content = f.read()
            
            # YAML frontmatter 추출
            match = re.match(r'^---\s*\n(.*?)\n---\s*\n(.*)', content, re.DOTALL)
            if not match:
                return None
            
            frontmatter_text = match.group(1)
            content_text = match.group(2)
            
            # YAML 파싱
            metadata = yaml.safe_load(frontmatter_text)
            
            return Skill(
                name=metadata.get('name', filepath.stem),
                description=metadata.get('description', ''),
                priority=metadata.get('priority', 5),
                tags=metadata.get('tags', []),
                enabled=metadata.get('enabled', True),
                requires_tools=metadata.get('requires_tools', []),
                content=content_text.strip(),
                filepath=str(filepath)
            )
        
        except Exception as e:
            print(f"Warning: Failed to parse {filepath}: {e}")
            return None
    
    def build_system_prompt(self, skills: List[Skill]) -> str:
        """
        Skill들을 System Prompt로 변환
        
        Returns:
            System Prompt 문자열
        """
        prompt_parts = []
        
        prompt_parts.append("# Network Operation Agent Skills\n")
        prompt_parts.append("You have access to the following skills and knowledge:\n")
        
        for skill in skills:
            prompt_parts.append(f"\n## Skill: {skill.name}\n")
            prompt_parts.append(f"**Description**: {skill.description}\n")
            prompt_parts.append(f"\n{skill.content}\n")
            prompt_parts.append("\n---\n")
        
        return "\n".join(prompt_parts)
    
    def get_skill_stats(self, skills: List[Skill]) -> Dict[str, Any]:
        """Skill 통계"""
        total_tokens = sum(s.token_estimate() for s in skills)
        
        return {
            "total_skills": len(skills),
            "skill_names": [s.name for s in skills],
            "estimated_tokens": total_tokens,
            "by_priority": {
                "high (8-10)": len([s for s in skills if s.priority >= 8]),
                "medium (5-7)": len([s for s in skills if 5 <= s.priority < 8]),
                "low (1-4)": len([s for s in skills if s.priority < 5]),
            },
            "by_tags": self._count_by_tags(skills)
        }
    
    def _count_by_tags(self, skills: List[Skill]) -> Dict[str, int]:
        """태그별 카운트"""
        tag_count = {}
        for skill in skills:
            for tag in skill.tags:
                tag_count[tag] = tag_count.get(tag, 0) + 1
        return tag_count


# 편의 함수
def load_core_skills() -> List[Skill]:
    """Core Skill만 로드"""
    loader = SkillLoader()
    return loader.load_core_skills()


def load_skills_for_task(task_description: str) -> List[Skill]:
    """
    Task 설명에서 관련 태그를 추출하여 Skill 로드
    
    Args:
        task_description: Task 설명
        
    Returns:
        관련 Skill 리스트
    """
    loader = SkillLoader()
    
    # 항상 Core Skill 포함
    skills = loader.load_core_skills()
    
    # Task 설명에서 키워드 추출
    task_lower = task_description.lower()
    
    # 태그 매핑
    tag_keywords = {
        # 네트워크 프로토콜
        "bgp": ["bgp", "border gateway"],
        "acl": ["acl", "access-list", "firewall"],
        
        # 장비 라이프사이클
        "lifecycle": ["생성", "삭제", "추가", "제거", "만들", "create", "delete", "add", "remove"],
        "device": ["장비", "라우터", "스위치", "노드", "router", "switch", "device", "node"],
        "creation": ["생성", "추가", "create", "add", "new"],
        "deletion": ["삭제", "제거", "delete", "remove"],
        
        # NSO 관련
        "registration": ["등록", "register", "nso", "sync"],
        
        # 연결 관련
        "connection": ["연결", "connect", "disconnect", "interface", "클라우드", "cloud"],
        
        # 문제 해결
        "troubleshooting": ["troubleshoot", "issue", "problem", "장애", "문제"],
        "reachability": ["ping", "reach", "도달", "통신"],
        
        # 분석
        "batfish": ["batfish", "분석", "검증", "verify", "reachability"],
        
        # 설정
        "configuration": ["설정", "config", "변경", "수정", "change", "modify"],
    }
    
    relevant_tags = []
    for tag, keywords in tag_keywords.items():
        if any(keyword in task_lower for keyword in keywords):
            relevant_tags.append(tag)
    
    # 관련 Skill 추가
    if relevant_tags:
        domain_skills = loader.load_by_tags(relevant_tags)
        skills.extend(domain_skills)
    
    # 중복 제거 (이름 기준)
    seen_names = set()
    unique_skills = []
    for skill in skills:
        if skill.name not in seen_names:
            seen_names.add(skill.name)
            unique_skills.append(skill)
    
    return unique_skills


if __name__ == "__main__":
    # 테스트
    loader = SkillLoader(skills_dir="skills/")
    
    print("=== ALL SKILLS ===")
    all_skills = loader.load_all_skills()
    for skill in all_skills:
        print(f"- {skill.name} (priority: {skill.priority}, tags: {skill.tags})")
    
    print("\n=== ENABLED SKILLS ===")
    enabled = loader.load_enabled_skills()
    stats = loader.get_skill_stats(enabled)
    print(f"Total: {stats['total_skills']} skills")
    print(f"Estimated tokens: {stats['estimated_tokens']}")
    
    print("\n=== CORE SKILLS ===")
    core = loader.load_core_skills()
    for skill in core:
        print(f"- {skill.name}")
    
    print("\n=== SYSTEM PROMPT PREVIEW ===")
    prompt = loader.build_system_prompt(core)
    print(prompt[:500] + "...\n")
