"""Module 6 - tests. Run from the project folder:  python -m unittest -v"""
import os
import unittest

from firewall_analyzer.loader import build_dataframe, load_rules
from firewall_analyzer.analyzer import analyze_all
from firewall_analyzer.scoring import score_groups, environment_score, rate
from firewall_analyzer.compliance import add_compliance

DATA = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                    "data", "firewall_rules.json")


def rule(i, port, source, protocol="tcp", group="test-sg"):
    return {"rule_id": i, "group": group, "protocol": protocol, "port": port, "source": source}


def severities(rule_list):
    return set(analyze_all(build_dataframe(rule_list))["severity"])


class TestChecks(unittest.TestCase):
    def test_ssh_open_to_world_is_high(self):
        self.assertIn("High", severities([rule(1, "22", "0.0.0.0/0")]))

    def test_ssh_from_one_ip_is_safe(self):
        self.assertEqual(severities([rule(1, "22", "203.0.113.5/32")]), {"Safe"})

    def test_allow_all_is_high(self):
        self.assertIn("High", severities([rule(1, "all", "0.0.0.0/0", protocol="all")]))

    def test_port_80_open_to_world_is_medium(self):
        self.assertEqual(severities([rule(1, "80", "0.0.0.0/0")]), {"Medium"})

    def test_wide_cidr_is_medium(self):
        self.assertEqual(severities([rule(1, "443", "10.0.0.0/8")]), {"Medium"})

    def test_duplicate_is_low(self):
        found = severities([rule(1, "22", "203.0.113.5/32"), rule(2, "22", "203.0.113.5/32")])
        self.assertIn("Low", found)

    def test_ipv6_open_to_world_is_high(self):
        self.assertIn("High", severities([rule(1, "3389", "::/0")]))


class TestValidation(unittest.TestCase):
    def test_invalid_cidr(self):
        self.assertEqual(severities([rule(1, "80", "999.1.1.1/24")]), {"Invalid"})

    def test_invalid_port(self):
        self.assertEqual(severities([rule(1, "70000", "192.168.1.0/24")]), {"Invalid"})

    def test_invalid_protocol(self):
        self.assertEqual(severities([rule(1, "80", "10.1.1.0/24", protocol="http")]), {"Invalid"})


class TestSampleData(unittest.TestCase):
    def setUp(self):
        self.report = add_compliance(analyze_all(load_rules(DATA)))

    def test_environment_score(self):
        self.assertEqual(environment_score(self.report), 21)

    def test_group_scores(self):
        groups = score_groups(self.report)
        self.assertEqual(dict(zip(groups["group"], groups["risk_score"])),
                         {"web-sg": 10, "db-sg": 5, "app-sg": 3, "admin-sg": 3})

    def test_rating_levels(self):
        self.assertEqual((rate(6), rate(3), rate(2)), ("HIGH RISK", "MEDIUM RISK", "LOW RISK"))

    def test_report_rows(self):
        self.assertEqual(len(self.report), 14)


if __name__ == "__main__":
    unittest.main()
