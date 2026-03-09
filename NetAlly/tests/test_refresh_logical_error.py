import main


def test_refresh_logical_error_flags_nso_failed_list():
    payload = {
        "status": "completed",
        "nso": {"registered": [], "failed": ["R1"]},
    }
    assert main._refresh_logical_error(200, payload) is True


def test_refresh_logical_error_allows_clean_completed_payload():
    payload = {
        "status": "completed",
        "missing": [],
        "reconciled": [],
        "nso": {"registered": [], "failed": []},
        "skipped": [],
    }
    assert main._refresh_logical_error(200, payload) is False
