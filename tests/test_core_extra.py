"""Extended core coverage: normalization, classification, parsing, SBOM, gate.

Stdlib only, no network. Complements test_smoke.py with breadth across the
SPDX alias table, policy buckets, requirements edge cases, and SBOM/purl shape.
"""

import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from licenselens.core import (  # noqa: E402
    DEFAULT_POLICY,
    UNKNOWN,
    build_sarif,
    build_sbom,
    classify,
    normalize_license,
    parse_requirements,
    scan_project,
)


class TestNormalizeBreadth(unittest.TestCase):
    CASES = {
        "MIT": "MIT",
        "mit license": "MIT",
        "The MIT License": "MIT",
        "BSD": "BSD-3-Clause",
        "BSD-2-Clause": "BSD-2-Clause",
        "bsd-3": "BSD-3-Clause",
        "Apache 2.0": "Apache-2.0",
        "apache-2": "Apache-2.0",
        "Apache Software License": "Apache-2.0",
        "ISC License": "ISC",
        "MPL-2.0": "MPL-2.0",
        "Mozilla Public License 2.0": "MPL-2.0",
        "LGPL-2.1": "LGPL-2.1",
        "lgpl-3.0": "LGPL-3.0",
        "GPLv2": "GPL-2.0",
        "GPLv3": "GPL-3.0",
        "AGPLv3": "AGPL-3.0",
        "agpl-3.0": "AGPL-3.0",
        "Unlicense": "Unlicense",
        "public domain": "Unlicense",
        "PSF": "PSF-2.0",
        "proprietary": "Proprietary",
        "Commercial": "Proprietary",
    }

    def test_alias_table(self):
        for raw, expected in self.CASES.items():
            self.assertEqual(normalize_license(raw), expected, raw)

    def test_trove_classifier_forms(self):
        self.assertEqual(
            normalize_license("License :: OSI Approved :: Apache Software License"),
            "Apache-2.0",
        )
        self.assertEqual(
            normalize_license("License :: OSI Approved :: GNU General Public License v3 (GPLv3)"),
            "GPL-3.0",
        )

    def test_empty_and_none(self):
        self.assertEqual(normalize_license(None), UNKNOWN)
        self.assertEqual(normalize_license(""), UNKNOWN)
        self.assertEqual(normalize_license("   "), UNKNOWN)

    def test_bare_spdx_passthrough(self):
        self.assertEqual(normalize_license("BSD-3-Clause"), "BSD-3-Clause")
        self.assertEqual(normalize_license("Zlib"), "Zlib")

    def test_whitespace_tolerant(self):
        self.assertEqual(normalize_license("  MIT  "), "MIT")


class TestClassifyBuckets(unittest.TestCase):
    def test_allow(self):
        for spdx in ("MIT", "BSD-2-Clause", "BSD-3-Clause", "Apache-2.0", "ISC", "Unlicense", "PSF-2.0"):
            self.assertEqual(classify(spdx, DEFAULT_POLICY)[0], "allow", spdx)

    def test_warn(self):
        for spdx in ("MPL-2.0", "LGPL-2.1", "LGPL-3.0"):
            self.assertEqual(classify(spdx, DEFAULT_POLICY)[0], "warn", spdx)

    def test_forbid(self):
        for spdx in ("GPL-2.0", "GPL-3.0", "AGPL-3.0", "Proprietary"):
            self.assertEqual(classify(spdx, DEFAULT_POLICY)[0], "forbid", spdx)

    def test_unknown(self):
        self.assertEqual(classify(UNKNOWN, DEFAULT_POLICY)[0], "unknown")
        self.assertEqual(classify("Zlib", DEFAULT_POLICY)[0], "unknown")

    def test_reason_strings_present(self):
        for spdx in ("MIT", "MPL-2.0", "GPL-3.0", UNKNOWN):
            risk, reason = classify(spdx, DEFAULT_POLICY)
            self.assertTrue(reason)

    def test_custom_policy(self):
        policy = {"allow": ["GPL-3.0"], "warn": [], "forbid": ["MIT"]}
        self.assertEqual(classify("GPL-3.0", policy)[0], "allow")
        self.assertEqual(classify("MIT", policy)[0], "forbid")


class TestParseEdgeCases(unittest.TestCase):
    def test_operators(self):
        deps = parse_requirements("a==1\nb>=2\nc<=3\nd~=4\ne!=5\nf>6\ng<7\n")
        self.assertEqual([d.name for d in deps], list("abcdefg"))

    def test_no_version(self):
        deps = parse_requirements("bare\n")
        self.assertEqual(deps[0].name, "bare")
        self.assertEqual(deps[0].version, "*")

    def test_override_comment(self):
        deps = parse_requirements("x==1  # license: Apache-2.0\n")
        self.assertEqual(deps[0].declared_license, "Apache-2.0")

    def test_skip_comments_and_directives(self):
        deps = parse_requirements("# c\n-r other.txt\n--index-url u\n\nz==9\n")
        self.assertEqual([d.name for d in deps], ["z"])

    def test_extras_and_markers_name_only(self):
        deps = parse_requirements("pkg[extra]==1\n")
        self.assertEqual(deps[0].name, "pkg")

    def test_blank_lines_ignored(self):
        self.assertEqual(parse_requirements("\n\n   \n"), [])


class TestSbomAndSarifShape(unittest.TestCase):
    def _scan(self, text):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "requirements.txt")
            with open(path, "w", encoding="utf-8") as fh:
                fh.write(text)
            return scan_project(path)

    def test_sbom_cyclonedx(self):
        r = self._scan("a==1  # license: MIT\nb==2  # license: GPL-3.0\n")
        sbom = build_sbom(r)
        self.assertEqual(sbom["bomFormat"], "CycloneDX")
        self.assertEqual(sbom["specVersion"], "1.5")
        self.assertEqual(len(sbom["components"]), 2)

    def test_sbom_purls(self):
        r = self._scan("requests==2.31.0  # license: Apache-2.0\n")
        comp = build_sbom(r)["components"][0]
        self.assertEqual(comp["purl"], "pkg:pypi/requests@2.31.0")
        self.assertEqual(comp["licenses"][0]["license"]["id"], "Apache-2.0")

    def test_sarif_rules_count(self):
        r = self._scan("a==1  # license: GPL-3.0\n")
        log = build_sarif(r)
        self.assertEqual(len(log["runs"][0]["tool"]["driver"]["rules"]), 4)

    def test_sarif_no_allow_results(self):
        r = self._scan("a==1  # license: MIT\nb==2  # license: GPL-3.0\n")
        results = build_sarif(r)["runs"][0]["results"]
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["ruleId"], "LIC-FORBID")


class TestGate(unittest.TestCase):
    def _scan(self, text):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "requirements.txt")
            with open(path, "w", encoding="utf-8") as fh:
                fh.write(text)
            return scan_project(path)

    def test_pass_all_allow(self):
        r = self._scan("a==1  # license: MIT\nb==2  # license: Apache-2.0\n")
        self.assertTrue(r.passed)

    def test_warn_still_passes(self):
        r = self._scan("a==1  # license: MPL-2.0\n")
        self.assertTrue(r.passed)
        self.assertEqual(r.counts["warn"], 1)

    def test_forbid_fails(self):
        r = self._scan("a==1  # license: GPL-3.0\n")
        self.assertFalse(r.passed)

    def test_unknown_fails(self):
        r = self._scan("a==1\n")
        self.assertFalse(r.passed)
        self.assertEqual(r.counts["unknown"], 1)

    def test_counts_sum_to_findings(self):
        r = self._scan("a==1  # license: MIT\nb==2  # license: GPL-3.0\nc==3\n")
        self.assertEqual(sum(r.counts.values()), len(r.findings))

    def test_findings_sorted_severe_first(self):
        r = self._scan("a==1  # license: MIT\nz==2  # license: GPL-3.0\n")
        # forbid (z) must sort before allow (a)
        self.assertEqual(r.findings[0].risk, "forbid")


if __name__ == "__main__":
    unittest.main()
