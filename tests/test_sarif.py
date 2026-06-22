"""Tests for SARIF 2.1.0 export and the new demo scenarios. Stdlib only."""

import json
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from licenselens import build_sarif, scan_project  # noqa: E402
from licenselens.cli import main  # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEMOS = os.path.join(ROOT, "demos")


def _req(name):
    return os.path.join(DEMOS, name, "requirements.txt")


class TestSarif(unittest.TestCase):
    def test_sarif_shape(self):
        result = scan_project(_req("01-basic"))
        log = build_sarif(result, "requirements.txt")
        self.assertEqual(log["version"], "2.1.0")
        self.assertTrue(log["$schema"].endswith("sarif-2.1.0.json"))
        run = log["runs"][0]
        self.assertEqual(run["tool"]["driver"]["name"], "licenselens")
        # Four rules are always advertised.
        self.assertEqual(len(run["tool"]["driver"]["rules"]), 4)

    def test_sarif_excludes_allow(self):
        # 01-basic has 5 allow + 1 forbid + 1 unknown; SARIF should emit only
        # the 2 non-compliant findings, none with an "allow" rule.
        result = scan_project(_req("01-basic"))
        log = build_sarif(result)
        results = log["runs"][0]["results"]
        self.assertEqual(len(results), 2)
        rule_ids = {r["ruleId"] for r in results}
        self.assertNotIn("LIC-ALLOW", rule_ids)
        self.assertEqual(rule_ids, {"LIC-FORBID", "LIC-UNKNOWN"})

    def test_sarif_levels(self):
        # 08-sarif-codescan spans warn/forbid/unknown.
        result = scan_project(_req("08-sarif-codescan"))
        log = build_sarif(result)
        by_rule = {r["ruleId"]: r["level"] for r in log["runs"][0]["results"]}
        self.assertEqual(by_rule["LIC-WARN"], "warning")
        self.assertEqual(by_rule["LIC-FORBID"], "error")
        self.assertEqual(by_rule["LIC-UNKNOWN"], "error")

    def test_sarif_is_valid_json_via_cli(self):
        # The CLI sarif format must emit parseable JSON and a failing exit code
        # for a failing gate.
        import io
        from contextlib import redirect_stdout

        buf = io.StringIO()
        with redirect_stdout(buf):
            rc = main(["--format", "sarif", "scan", _req("08-sarif-codescan")])
        self.assertEqual(rc, 1)
        doc = json.loads(buf.getvalue())
        self.assertEqual(doc["version"], "2.1.0")


class TestNewDemos(unittest.TestCase):
    def test_fastapi_passes_with_warn(self):
        r = scan_project(_req("04-fastapi-service"))
        self.assertTrue(r.passed)
        self.assertEqual(r.counts["warn"], 1)
        self.assertEqual(r.counts["forbid"], 0)

    def test_data_science_clean(self):
        r = scan_project(_req("05-data-science"))
        self.assertTrue(r.passed)
        self.assertEqual(r.counts["allow"], 9)

    def test_agpl_violation_fails(self):
        r = scan_project(_req("06-agpl-violation"))
        self.assertFalse(r.passed)
        self.assertEqual(r.counts["forbid"], 2)

    def test_unpinned_all_unknown(self):
        r = scan_project(_req("09-unpinned-unknowns"))
        self.assertFalse(r.passed)
        self.assertEqual(r.counts["unknown"], 4)

    def test_metadata_resolution(self):
        # Licenses must resolve from the .dist-info METADATA fixtures, so every
        # finding's source is "metadata", and the gate passes.
        r = scan_project(_req("10-policy-clean-release"))
        self.assertTrue(r.passed)
        sources = {f.source for f in r.findings}
        self.assertEqual(sources, {"metadata"})


if __name__ == "__main__":
    unittest.main()
