from agent.onboarding import _ssh_bootstrap_looks_ready, _ssh_state_from_output


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


def test_ssh_bootstrap_ready_when_show_reports_enabled():
    assert _ssh_bootstrap_looks_ready(
        show_state=True,
        transport_cfg="",
        login_cfg="",
        users_cfg="",
        username="admin",
    ) is True


def test_ssh_bootstrap_ready_when_running_config_has_transport_login_and_user():
    assert _ssh_bootstrap_looks_ready(
        show_state=None,
        transport_cfg="line vty 0 4\n transport input ssh",
        login_cfg="line vty 0 4\n login local",
        users_cfg="username netally privilege 15 secret 5 xxxxxx",
        username="netally",
    ) is True


def test_ssh_bootstrap_not_ready_when_login_local_missing():
    assert _ssh_bootstrap_looks_ready(
        show_state=None,
        transport_cfg="line vty 0 4\n transport input ssh",
        login_cfg="",
        users_cfg="username netally privilege 15 secret 5 xxxxxx",
        username="netally",
    ) is False
