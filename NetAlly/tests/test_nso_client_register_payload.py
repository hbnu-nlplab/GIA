from agent.clients.nso import NSOClient


def _client() -> NSOClient:
    return NSOClient(
        base_url="http://127.0.0.1:18080/restconf",
        username="admin",
        password="admin",
    )


def test_normalize_ned_id_adds_identityref_prefix_when_missing():
    client = _client()
    assert client._normalize_ned_id("cisco-ios-cli-3.8") == "cisco-ios-cli-3.8:cisco-ios-cli-3.8"


def test_normalize_ned_id_keeps_prefixed_identityref():
    client = _client()
    value = "cisco-ios-cli-3.8:cisco-ios-cli-3.8"
    assert client._normalize_ned_id(value) == value


def test_register_device_uses_normalized_ned_id_payload():
    client = _client()
    captured = {}

    def fake_request(method: str, path: str, payload=None):
        captured["method"] = method
        captured["path"] = path
        captured["payload"] = payload
        return {"status": "success"}

    client._request = fake_request  # type: ignore[method-assign]

    ok = client.register_device(
        {
            "name": "CE01",
            "oob_ip": "192.168.50.60",
            "port": 30008,
            "authgroup": "default",
            "ned_id": "cisco-ios-cli-3.8",
            "protocol": "telnet",
        }
    )

    assert ok is True
    assert captured["method"] == "PUT"
    assert captured["path"] == "tailf-ncs:devices/device=CE01"
    payload = captured["payload"]
    assert payload["tailf-ncs:device"]["device-type"]["cli"]["ned-id"] == "cisco-ios-cli-3.8:cisco-ios-cli-3.8"


def test_register_device_falls_back_when_requested_ned_is_invalid():
    client = _client()
    put_neds = []

    def fake_request(method: str, path: str, payload=None):
        if method == "GET" and path.endswith("device?fields=device-type"):
            return {
                "device": [
                    {"device-type": {"cli": {"ned-id": "cisco-ios-cli-3.8:cisco-ios-cli-3.8"}}}
                ]
            }
        if method == "PUT":
            ned = payload["tailf-ncs:device"]["device-type"]["cli"]["ned-id"]
            put_neds.append(ned)
            if ned == "cisco-ios-cli-6.110:cisco-ios-cli-6.110":
                return {
                    "status": "error",
                    "message": 'invalid value for: ned-id: "cisco-ios-cli-6.110:cisco-ios-cli-6.110" is not a valid value.',
                }
            return {"status": "success"}
        return {"status": "error", "message": "unexpected call"}

    client._request = fake_request  # type: ignore[method-assign]

    ok = client.register_device(
        {
            "name": "CE02",
            "oob_ip": "192.168.50.60",
            "port": 30006,
            "authgroup": "default",
            "ned_id": "cisco-ios-cli-6.110",
            "protocol": "telnet",
        }
    )

    assert ok is True
    assert put_neds[0] == "cisco-ios-cli-6.110:cisco-ios-cli-6.110"
    assert put_neds[1] == "cisco-ios-cli-3.8:cisco-ios-cli-3.8"


def test_candidate_ned_ids_includes_installed_package_ned_ids():
    client = _client()

    def fake_request(method: str, path: str, payload=None):
        if method == "GET" and path == "tailf-ncs:packages":
            return {
                "packages": {
                    "package": [
                        {
                            "component": [
                                {
                                    "ned": {
                                        "cli": {
                                            "ned-id": "cisco-ios-cli-3.8:cisco-ios-cli-3.8"
                                        }
                                    }
                                }
                            ]
                        }
                    ]
                }
            }
        if method == "GET" and path.endswith("device?fields=device-type"):
            return {"device": []}
        return {"status": "error", "message": "unexpected call"}

    client._request = fake_request  # type: ignore[method-assign]

    candidates = client._candidate_ned_ids("cisco-ios-cli-6.110")
    assert "cisco-ios-cli-3.8:cisco-ios-cli-3.8" in candidates
    assert candidates[0] == "cisco-ios-cli-6.110:cisco-ios-cli-6.110"


def test_register_device_retries_without_ssh_algorithms_on_schema_error():
    client = _client()
    attempts = []

    def fake_request(method: str, path: str, payload=None):
        if method == "GET" and path in {
            "tailf-ncs:packages",
            "tailf-ncs:devices/device?fields=device-type",
        }:
            return {"packages": {"package": []}, "device": []}
        if method == "PUT":
            body = payload["tailf-ncs:device"]
            attempts.append(body)
            if "ssh-algorithms" in body:
                return {
                    "status": "error",
                    "message": "unknown element: ssh-algorithms",
                }
            return {"status": "success"}
        return {"status": "error", "message": "unexpected call"}

    client._request = fake_request  # type: ignore[method-assign]

    ok = client.register_device(
        {
            "name": "PE02",
            "oob_ip": "10.10.10.2",
            "port": 22,
            "authgroup": "default",
            "ned_id": "cisco-ios-cli-3.8",
            "protocol": "ssh",
        }
    )

    assert ok is True
    assert len(attempts) >= 2
    assert "ssh-algorithms" in attempts[0]
    assert "ssh-algorithms" not in attempts[1]
