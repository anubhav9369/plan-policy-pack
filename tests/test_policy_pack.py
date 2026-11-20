"""Tests for plan-policy-pack. Standard library only."""
import json
import os
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import policy_pack
from policy_pack import PackError, check_plan, conformance, load_pack, load_plan

HERE = os.path.dirname(os.path.abspath(__file__))
DAY = os.path.dirname(HERE)


def load_example(name):
    with open(os.path.join(DAY, "examples", name), encoding="utf-8") as f:
        return json.load(f)


class PackValidationTests(unittest.TestCase):
    def _write_pack(self, pack):
        tmp = tempfile.NamedTemporaryFile(
            "w", suffix=".json", delete=False, encoding="utf-8")
        json.dump(pack, tmp)
        tmp.close()
        self.addCleanup(os.unlink, tmp.name)
        return tmp.name

    def _base_pack(self):
        return {
            "name": "test",
            "version": 1,
            "rules": [{
                "id": "SEC-01",
                "category": "security",
                "severity": "HIGH",
                "description": "No publishing.",
                "match": {"type": "forbid_action", "actions": ["publish"]},
            }],
        }

    def test_rejects_duplicate_rule_ids(self):
        pack = self._base_pack()
        pack["rules"].append(dict(pack["rules"][0]))
        with self.assertRaises(PackError) as ctx:
            load_pack(self._write_pack(pack))
        self.assertIn("duplicate rule id", str(ctx.exception))

    def test_rejects_unknown_category(self):
        pack = self._base_pack()
        pack["rules"][0]["category"] = "vibes"
        with self.assertRaises(PackError) as ctx:
            load_pack(self._write_pack(pack))
        self.assertIn("category", str(ctx.exception))

    def test_rejects_unknown_matcher_type(self):
        pack = self._base_pack()
        pack["rules"][0]["match"] = {"type": "forbid_thoughts"}
        with self.assertRaises(PackError) as ctx:
            load_pack(self._write_pack(pack))
        self.assertIn("unknown matcher type", str(ctx.exception))

    def test_rejects_bad_matcher_params(self):
        pack = self._base_pack()
        pack["rules"][0]["match"] = {"type": "forbid_action", "actions": []}
        with self.assertRaises(PackError):
            load_pack(self._write_pack(pack))
        pack = self._base_pack()
        pack["rules"][0]["match"] = {"type": "max_total_cost", "usd": -1}
        with self.assertRaises(PackError):
            load_pack(self._write_pack(pack))


class CheckTests(unittest.TestCase):
    def setUp(self):
        self.pack = load_pack(os.path.join(DAY, "examples",
                                           "default-pack.json"))
        self.clean = load_example("plan.json")
        self.risky = load_example("risky-plan.json")

    def test_clean_plan_passes(self):
        self.assertEqual(check_plan(self.clean, self.pack), [])

    def test_risky_plan_breaks_six_rules(self):
        found = sorted({v["rule_id"] for v in check_plan(self.risky,
                                                         self.pack)})
        self.assertEqual(found, ["ETH-01", "ORG-01", "PRV-01",
                                 "SEC-01", "SEC-02", "SEC-03"])

    def test_forbid_target_case_insensitive_and_skips_missing_target(self):
        plan = {"goal": "g", "steps": [
            {"id": "s1", "action": "Send it", "target": "PUBLIC-list"},
            {"id": "s2", "action": "Send it too"},
        ]}
        found = [v for v in check_plan(plan, self.pack)
                 if v["rule_id"] == "PRV-01"]
        self.assertEqual([v["step"] for v in found], ["s1"])

    def test_max_total_cost_ignores_unpriced_steps(self):
        plan = {"goal": "g", "steps": [
            {"id": "s1", "action": "Do it", "estimate": {"usd": 4.9}},
            {"id": "s2", "action": "Do more"},  # unknown, not zero
        ]}
        found = [v for v in check_plan(plan, self.pack)
                 if v["rule_id"] == "ORG-01"]
        self.assertEqual(found, [])


class ConformanceTests(unittest.TestCase):
    def test_default_pack_conformance_clean(self):
        pack = load_pack(os.path.join(DAY, "examples",
                                      "default-pack.json"))
        corpus = policy_pack.load_corpus(
            os.path.join(DAY, "examples", "conformance-corpus.json"))
        result = conformance(pack, corpus)
        self.assertEqual(result["cases_passed"], result["cases_total"])
        self.assertEqual(result["dead_rules"], [])
        self.assertEqual(result["false_positive_rules"], [])
        self.assertTrue(result["verdict"].startswith("CLEAN"))

    def test_strict_pack_flags_dead_scrape_rule(self):
        pack = load_pack(os.path.join(DAY, "examples",
                                      "strict-pack.json"))
        corpus = policy_pack.load_corpus(
            os.path.join(DAY, "examples", "conformance-corpus.json"))
        result = conformance(pack, corpus)
        self.assertEqual(result["cases_passed"], result["cases_total"])
        self.assertEqual(result["dead_rules"], ["SEC-04"])


class CliTests(unittest.TestCase):
    def _run(self, *args):
        proc = subprocess.run(
            [sys.executable, os.path.join(DAY, "policy_pack.py"), *args],
            capture_output=True, text=True, timeout=30)
        return proc.returncode, proc.stdout, proc.stderr

    def test_cli_exit_codes(self):
        pack = os.path.join(DAY, "examples", "default-pack.json")
        code, _, _ = self._run(pack, os.path.join(DAY, "examples",
                                                  "plan.json"))
        self.assertEqual(code, 0)
        code, _, _ = self._run(pack, os.path.join(DAY, "examples",
                                                  "risky-plan.json"))
        self.assertEqual(code, 2)
        code, _, err = self._run(pack, os.path.join(DAY, "examples",
                                                    "no-such-plan.json"))
        self.assertEqual(code, 1)
        self.assertIn("no such file", err)


if __name__ == "__main__":
    unittest.main()
