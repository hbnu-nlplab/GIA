from agent.skill_loader import SkillLoader


def test_required_tools_disabled_in_mcp_mode():
    loader = SkillLoader()
    skills = loader.load_all()
    assert isinstance(skills, list)
    assert loader.get_required_tools(skills) == set()
