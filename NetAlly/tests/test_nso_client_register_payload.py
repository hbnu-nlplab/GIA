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
