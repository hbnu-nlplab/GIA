import unittest

from Make_Dataset.src.l45_contracts import build_l45_contract


class FakeBuilder:
    snapshot_name = "baseline"
    node_ips = {
        "leaf1": ["10.0.0.1"],
        "pe1": ["10.0.0.2"],
        "dst": ["192.0.2.1"],
    }
    nodes = ["leaf1", "pe1", "p1"]


class L45ContractsTests(unittest.TestCase):
    def test_traceroute_contract_has_dst_ip(self):
        q = {
            "answer_type": "text",
            "evidence_hint": {"metric": "traceroute_path", "scope": {"type": "NODE_PAIR", "src": "leaf1", "dst": "dst"}},
        }
        c = build_l45_contract(q, FakeBuilder())
        self.assertEqual(c["query_contract"]["replay_method"], "traceroute_path")
        self.assertEqual(c["query_contract"]["params"]["dst_ip"], "192.0.2.1")
        self.assertEqual(c["verification_status"], "pending")

    def test_reachability_contract_parses_port_protocol(self):
        q = {
            "answer_type": "text",
            "question": "1.1.1.1에서 2.2.2.2(443/TCP)로의 트래픽 경로와 도달 여부를 알려주세요.",
            "evidence_hint": {"metric": "reachability_status", "scope": {"type": "FLOW", "src_ip": "1.1.1.1", "dst_ip": "2.2.2.2"}},
        }
        c = build_l45_contract(q, FakeBuilder())
        self.assertEqual(c["query_contract"]["params"]["dst_port"], 443)
        self.assertEqual(c["query_contract"]["params"]["protocol"], "TCP")

    def test_snapshot_diff_contract_carries_failure_node(self):
        q = {
            "answer_type": "text",
            "evidence_hint": {
                "metric": "config_change_impact",
                "scope": {
                    "type": "SNAPSHOT_DIFF",
                    "src": "leaf1",
                    "dst": "pe1",
                    "base_snapshot": "baseline",
                    "changed_snapshot": "cfg_change_p1",
                    "failure_node": "p1",
                },
            },
        }
        c = build_l45_contract(q, FakeBuilder())
        self.assertEqual(c["scenario"]["fork_ops"][0]["nodes"], ["p1"])
        self.assertEqual(c["query_contract"]["replay_method"], "config_change_impact")

    def test_missing_scope_quarantines(self):
        q = {
            "answer_type": "text",
            "evidence_hint": {"metric": "multi_link_failure_reachability", "scope": {"type": "MULTI_LINK_FAILURE", "link1": "a-b"}},
        }
        c = build_l45_contract(q, FakeBuilder())
        self.assertEqual(c["verification_status"], "quarantined")
        self.assertIn("missing_multi_link_scope", c["quarantine_reason"])


if __name__ == "__main__":
    unittest.main()
