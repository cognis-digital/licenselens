"""Offline vulnerability-enrichment tests for LICENSELENS.

Every assertion runs against the bundled ~262k-record OSV corpus with no
network access. These prove real lookups resolve (log4j / CVE-2021-44228),
that namespace-tolerant matching works, and that the gate behaves correctly.
"""

import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from licenselens.cli import main  # noqa: E402
from licenselens.core import scan_project  # noqa: E402
from licenselens.vulndb_local import VulnDB  # noqa: E402
from licenselens.vulncheck import (  # noqa: E402
    PackageVulns,
    VulnReport,
    canonical_ecosystem,
    enrich_scan,
    lookup_cve,
    match_package,
    severity_bucket,
)

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _write_req(d, text):
    path = os.path.join(d, "requirements.txt")
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(text)
    return path


class TestBundledDb(unittest.TestCase):
    def test_db_loads_offline(self):
        self.assertGreaterEqual(VulnDB().count(), 100000)

    def test_db_is_large(self):
        # The shipped corpus is the documented ~262k OSV baseline.
        self.assertGreaterEqual(VulnDB().count(), 250000)

    def test_record_fields(self):
        r = next(iter(VulnDB()))
        for field in ("id", "aliases", "ecosystem", "summary", "severity", "packages"):
            self.assertIn(field, r)

    def test_count_helper_matches(self):
        from licenselens import vulndb_local

        self.assertEqual(vulndb_local.count(), VulnDB().count())

    def test_index_is_cached(self):
        db = VulnDB()
        db._index()
        self.assertIsNotNone(db._by_cve)
        self.assertIsNotNone(db._by_pkg)


class TestCveLookup(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.db = VulnDB()

    def test_log4shell_resolves(self):
        rows = lookup_cve("CVE-2021-44228", self.db)
        self.assertTrue(rows)
        self.assertTrue(any("CVE-2021-44228" in m.aliases for m in rows))

    def test_log4shell_summary_mentions_log4j(self):
        rows = lookup_cve("CVE-2021-44228", self.db)
        self.assertTrue(any("log4j" in m.summary.lower() for m in rows))

    def test_log4shell_is_maven(self):
        rows = lookup_cve("CVE-2021-44228", self.db)
        self.assertTrue(any(m.ecosystem == "Maven" for m in rows))

    def test_log4shell_affects_log4j_core(self):
        rows = lookup_cve("CVE-2021-44228", self.db)
        pkgs = {p.lower() for m in rows for p in m.packages}
        self.assertTrue(any("log4j-core" in p for p in pkgs))

    def test_case_insensitive_cve(self):
        a = lookup_cve("cve-2021-44228", self.db)
        b = lookup_cve("CVE-2021-44228", self.db)
        self.assertEqual(len(a), len(b))

    def test_unknown_cve_empty(self):
        self.assertEqual(lookup_cve("CVE-0000-00000", self.db), [])

    def test_blank_cve_empty(self):
        self.assertEqual(lookup_cve("", self.db), [])

    def test_ghsa_id_resolves(self):
        # Resolve a known Log4Shell GHSA id directly.
        rows = lookup_cve("GHSA-jfh8-c2jp-5v3q", self.db)
        self.assertTrue(rows)
        self.assertEqual(rows[0].id, "GHSA-jfh8-c2jp-5v3q")


class TestPackageMatch(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.db = VulnDB()

    def test_django_has_many_vulns(self):
        rows = match_package(self.db, "django", ecosystem="PyPI")
        self.assertGreater(len(rows), 5)

    def test_lodash_npm(self):
        rows = match_package(self.db, "lodash", ecosystem="npm")
        self.assertTrue(rows)
        self.assertTrue(all(m.ecosystem == "npm" for m in rows))

    def test_requests_pypi(self):
        rows = match_package(self.db, "requests", ecosystem="PyPI")
        self.assertTrue(rows)
        self.assertTrue(all(m.ecosystem == "PyPI" for m in rows))

    def test_ecosystem_filter_isolates(self):
        py = match_package(self.db, "requests", ecosystem="PyPI")
        mv = match_package(self.db, "requests", ecosystem="Maven")
        self.assertNotEqual(len(py), len(mv))

    def test_namespace_tolerant_maven(self):
        # bare name resolves the namespaced Maven record
        rows = match_package(self.db, "log4j-core", ecosystem="Maven")
        self.assertTrue(rows)

    def test_unknown_package_no_fabrication(self):
        rows = match_package(self.db, "definitely-not-a-real-pkg-xyz-123")
        self.assertEqual(rows, [])

    def test_results_sorted_by_severity(self):
        rows = match_package(self.db, "django", ecosystem="PyPI")
        ranks = [
            {"critical": 4, "high": 3, "moderate": 2, "low": 1, "unknown": 0}[m.severity_bucket]
            for m in rows
        ]
        self.assertEqual(ranks, sorted(ranks, reverse=True))

    def test_limit_respected(self):
        rows = match_package(self.db, "django", ecosystem="PyPI", limit=3)
        self.assertLessEqual(len(rows), 3)

    def test_no_duplicate_ids(self):
        rows = match_package(self.db, "django", ecosystem="PyPI")
        ids = [m.id for m in rows]
        self.assertEqual(len(ids), len(set(ids)))


class TestEcosystemNormalize(unittest.TestCase):
    def test_aliases(self):
        self.assertEqual(canonical_ecosystem("pypi"), "PyPI")
        self.assertEqual(canonical_ecosystem("python"), "PyPI")
        self.assertEqual(canonical_ecosystem("npm"), "npm")
        self.assertEqual(canonical_ecosystem("node"), "npm")
        self.assertEqual(canonical_ecosystem("cargo"), "crates.io")
        self.assertEqual(canonical_ecosystem("rust"), "crates.io")
        self.assertEqual(canonical_ecosystem("maven"), "Maven")
        self.assertEqual(canonical_ecosystem("java"), "Maven")
        self.assertEqual(canonical_ecosystem("gem"), "RubyGems")
        self.assertEqual(canonical_ecosystem("php"), "Packagist")

    def test_none(self):
        self.assertIsNone(canonical_ecosystem(None))
        self.assertIsNone(canonical_ecosystem(""))

    def test_passthrough_unknown(self):
        self.assertEqual(canonical_ecosystem("SwiftURL"), "SwiftURL")


class TestSeverityBucket(unittest.TestCase):
    def test_named(self):
        self.assertEqual(severity_bucket("CRITICAL"), "critical")
        self.assertEqual(severity_bucket("High"), "high")
        self.assertEqual(severity_bucket("moderate"), "moderate")
        self.assertEqual(severity_bucket("medium"), "moderate")
        self.assertEqual(severity_bucket("low"), "low")

    def test_empty_unknown(self):
        self.assertEqual(severity_bucket(""), "unknown")
        self.assertEqual(severity_bucket(None), "unknown")

    def test_cvss_score(self):
        self.assertEqual(severity_bucket("9.8"), "critical")
        self.assertEqual(severity_bucket("7.5"), "high")
        self.assertEqual(severity_bucket("5.0"), "moderate")
        self.assertEqual(severity_bucket("2.1"), "low")

    def test_cvss_vector_critical(self):
        # Network-exploitable, scope-change, high CIA = critical (Log4Shell-like).
        self.assertEqual(
            severity_bucket("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"),
            "critical",
        )

    def test_cvss_vector_high(self):
        self.assertEqual(
            severity_bucket("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"),
            "high",
        )

    def test_cvss_version_not_mistaken_for_score(self):
        # "3.1" is the spec version, not a base score; must not bucket as "low".
        self.assertNotEqual(
            severity_bucket("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"),
            "low",
        )


class TestLog4ShellSeverity(unittest.TestCase):
    def test_log4shell_is_critical(self):
        from licenselens.vulncheck import lookup_cve

        rows = lookup_cve("CVE-2021-44228")
        self.assertTrue(any(m.severity_bucket == "critical" for m in rows))


class TestEnrichScan(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.db = VulnDB()

    def _report(self, text, ecosystem="PyPI"):
        with tempfile.TemporaryDirectory() as d:
            path = _write_req(d, text)
            result = scan_project(path)
            return enrich_scan(result, db=self.db, ecosystem=ecosystem)

    def test_report_shape(self):
        rep = self._report("requests==2.20.0  # license: Apache-2.0\n")
        self.assertIsInstance(rep, VulnReport)
        self.assertEqual(rep.db_size, self.db.count())
        self.assertEqual(len(rep.packages), 1)

    def test_vulnerable_package_detected(self):
        rep = self._report("django==1.11  # license: BSD-3-Clause\n")
        self.assertGreaterEqual(rep.vulnerable_packages, 1)
        self.assertGreater(rep.total_vulns, 0)

    def test_clean_package_zero(self):
        rep = self._report("totally-made-up-pkg-zzz==1.0  # license: MIT\n")
        self.assertEqual(rep.total_vulns, 0)
        self.assertEqual(rep.vulnerable_packages, 0)

    def test_severity_counts_sum(self):
        rep = self._report("django==1.11  # license: BSD-3-Clause\n")
        sc = rep.severity_counts
        self.assertEqual(sum(sc.values()), rep.total_vulns)

    def test_carries_license_and_risk(self):
        rep = self._report("requests==2.20.0  # license: Apache-2.0\n")
        p = rep.packages[0]
        self.assertEqual(p.license, "Apache-2.0")
        self.assertEqual(p.risk, "allow")

    def test_sorted_most_vulnerable_first(self):
        rep = self._report(
            "django==1.11  # license: BSD-3-Clause\n"
            "totally-made-up-pkg-zzz==1.0  # license: MIT\n"
        )
        self.assertGreaterEqual(rep.packages[0].vuln_count, rep.packages[-1].vuln_count)

    def test_as_dict_roundtrips_json(self):
        rep = self._report("requests==2.20.0  # license: Apache-2.0\n")
        s = json.dumps(rep.as_dict())
        d = json.loads(s)
        self.assertIn("packages", d)
        self.assertIn("severity_counts", d)

    def test_max_severity_none_for_clean(self):
        pv = PackageVulns(name="x", version="1", ecosystem="PyPI", license="MIT", risk="allow")
        self.assertEqual(pv.max_severity, "none")
        self.assertEqual(pv.vuln_count, 0)


class TestVulncheckCli(unittest.TestCase):
    def _req(self, d, text):
        return _write_req(d, text)

    def test_cli_json_runs(self):
        with tempfile.TemporaryDirectory() as d:
            path = self._req(d, "requests==2.20.0  # license: Apache-2.0\n")
            rc = main(["--format", "json", "vulncheck", path])
            self.assertEqual(rc, 0)  # default --fail-on off

    def test_cli_table_runs(self):
        with tempfile.TemporaryDirectory() as d:
            path = self._req(d, "django==1.11  # license: BSD-3-Clause\n")
            rc = main(["vulncheck", path])
            self.assertEqual(rc, 0)

    def test_cli_fail_on_any_gate(self):
        with tempfile.TemporaryDirectory() as d:
            path = self._req(d, "django==1.11  # license: BSD-3-Clause\n")
            rc = main(["vulncheck", path, "--fail-on", "any"])
            self.assertEqual(rc, 1)  # django has real vulns -> gate fails

    def test_cli_fail_on_clean_passes(self):
        with tempfile.TemporaryDirectory() as d:
            path = self._req(d, "totally-made-up-pkg-zzz==1.0  # license: MIT\n")
            rc = main(["vulncheck", path, "--fail-on", "critical"])
            self.assertEqual(rc, 0)

    def test_cli_missing_file_exit_two(self):
        rc = main(["vulncheck", os.path.join(os.sep, "no", "such", "req.txt")])
        self.assertEqual(rc, 2)

    def test_cli_cve_command(self):
        rc = main(["cve", "CVE-2021-44228"])
        self.assertEqual(rc, 0)

    def test_cli_cve_json(self):
        rc = main(["--format", "json", "cve", "CVE-2021-44228"])
        self.assertEqual(rc, 0)

    def test_cli_cve_unknown_ok(self):
        rc = main(["cve", "CVE-0000-00000"])
        self.assertEqual(rc, 0)


if __name__ == "__main__":
    unittest.main()
