from agent.onboarding import _ssh_state_from_output


def test_ssh_state_enabled_output():
    assert _ssh_state_from_output("SSH Enabled - version 2.0") is True


def test_ssh_state_disabled_output():
    assert _ssh_state_from_output("SSH Disabled - version 1.99") is False


def test_ssh_state_inconclusive_invalid_command():
    assert _ssh_state_from_output("% Invalid input detected at '^' marker.") is None


def test_ssh_state_enabled_from_version_line_without_disabled_token():
    output = "SSH Version 2.0\nAuthentication timeout: 120 secs"
    assert _ssh_state_from_output(output) is True


def test_ssh_state_none_for_empty_output():
    assert _ssh_state_from_output("") is None
