import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
sys.path.insert(0, str(SRC))

from audit_ground_truth import audit
from core_batfish.batfish_parser import parse_text_config
from core_batfish.builder_core import BuilderCore
from ground_truth_contracts import build_metric_contract, normalize_scope_for_metric
from verification.independent_parser import CfgParser, TopologyFacts


class GroundTruthV2RegressionTests(unittest.TestCase):
    def test_scope_normalization_casts_asn(self):
        normalized = normalize_scope_for_metric("ibgp_under_peered_count", {"asn": "65000", "host": "PE1"})
        self.assertEqual(normalized["asn"], 65000)
        self.assertEqual(normalized["host"], "pe1")

    def test_batfish_text_parser_extracts_logging_snmp_and_banners(self):
        cfg = """hostname PE1
logging buffered 51200 warnings
logging host 10.0.0.10
snmp-server community public RO
banner motd ^
Authorized users only
^
banner login ^
Login banner
^
"""
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "PE1.cfg"
            path.write_text(cfg, encoding="utf-8")
            facts = parse_text_config(path)

        self.assertEqual(facts["logging"]["buffered_severity"], "warnings")
        self.assertEqual(sorted(facts["logging"]["hosts"]), ["10.0.0.10"])
        self.assertEqual(facts["snmp_communities"], ["public"])
        self.assertEqual(facts["banner_motd"], "Authorized users only")
        self.assertEqual(facts["banner_login"], "Login banner")

    def test_independent_parser_matches_builder_for_key_metrics(self):
        cfg_with_bgp = """hostname pe1
interface Loopback0
 ip address 1.1.1.1 255.255.255.255
router bgp 65000
 neighbor 2.2.2.2 remote-as 65000
logging buffered 51200 warnings
snmp-server community public RO
banner motd ^
Authorized users only
^
"""
        cfg_without_bgp = """hostname leaf1
interface Loopback0
 ip address 10.10.10.10 255.255.255.255
"""

        pe1 = CfgParser(cfg_with_bgp, "pe1.cfg").parse()
        leaf1 = CfgParser(cfg_without_bgp, "leaf1.cfg").parse()

        topo = TopologyFacts({"pe1": pe1, "leaf1": leaf1})
        builder = BuilderCore({"devices": [pe1, leaf1]})
        pre = builder._precompute()

        metrics = {
            "logging_buffered_severity_text": {"host": "PE1"},
            "snmp_community_list": {"host": "PE1"},
            "banner_motd_content": {"host": "PE1"},
            "all_devices_same_as": {"type": "GLOBAL"},
        }

        for metric, scope in metrics.items():
            with self.subTest(metric=metric):
                _, verifier_value = topo.compute_metric(metric, scope)
                _, builder_value = builder._answer_for_metric(metric, scope, pre)
                self.assertEqual(verifier_value, builder_value)

    def test_audit_report_has_contracts_and_coverage(self):
        report = audit(ROOT.parent)
        self.assertEqual(report["policy_metrics"], 127)
        self.assertIn("logging_buffered_severity_text", report["contracts"])
        self.assertIn("missing_count", report["builder_core"])
        self.assertIn("missing_count", report["independent_parser"])

    def test_contract_inference_for_l4_metric_prefers_batfish(self):
        metadata = {
            "level": "L4",
            "answer_type": "path",
            "logic_ref": "bf.q.traceroute(...)",
        }
        contract = build_metric_contract("traceroute_path", metadata)
        self.assertEqual(contract.oracle_source, "batfish")
        self.assertEqual(contract.canonical_answer_type, "path")


if __name__ == "__main__":
    unittest.main(verbosity=2)
