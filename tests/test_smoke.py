"""Smoke tests for LICENSELENS. No network. Standard library only."""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from licenselens import (  # noqa: E402
    TOOL_NAME,
    TOOL_VERSION,
    build_sbom,
    classify,
    normalize_license,
    parse_requirements,
    scan_project,
)
from licenselens.cli import main  # noqa: E402

DEMO_REQ = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "demos",
    "01-basic",
    "requirements.txt",
)


class TestNormalize(unittest.TestCase):
    def test_aliases(self):
        self.assertEqual(normalize_license("MIT License"), "MIT")
        self.assertEqual(normalize_license("Apache Software License"), "Apache-2.0")
        self.assertEqual(normalize_license("GPLv3"), "GPL-3.0")

    def test_trove_classifier(self):
        self.assertEqual(
            normalize_license("License :: OSI Approved :: MIT License"), "MIT"
        )

    def test_unknown(self):
        self.assertEqual(normalize_license(None), "UNKNOWN")
        self.assertEqual(normalize_license(""), "UNKNOWN")

    def test_bare_spdx_passthrough(self):
        self.assertEqual(normalize_license("BSD-3-Clause"), "BSD-3-Clause")


class TestClassify(unittest.TestCase):
    def test_buckets(self):
        from licenselens import DEFAULT_POLICY

        self.assertEqual(classify("MIT", DEFAULT_POLICY)[0], "allow")
        self.assertEqual(classify("MPL-2.0", DEFAULT_POLICY)[0], "warn")
        self.assertEqual(classify("GPL-3.0", DEFAULT_POLICY)[0], "forbid")
        self.assertEqual(classify("UNKNOWN", DEFAULT_POLICY)[0], "unknown")


class TestParse(unittest.TestCase):
    def test_parse_with_override(self):
        deps = parse_requirements("foo==1.2.3  # license: MIT\nbar>=2.0\n# comment\n")
        self.assertEqual(len(deps), 2)
        self.assertEqual(deps[0].name, "foo")
        self.assertEqual(deps[0].version, "1.2.3")
        self.assertEqual(deps[0].declared_license, "MIT")
        self.assertEqual(deps[1].name, "bar")
        self.assertEqual(deps[1].version, "2.0")

    def test_skips_directives(self):
        deps = parse_requirements("-r other.txt\n--index-url http://x\npkg==1\n")
        self.assertEqual([d.name for d in deps], ["pkg"])


class TestScanAndGate(unittest.TestCase):
    def test_demo_gate_fails(self):
        result = scan_project(DEMO_REQ)
        self.assertFalse(result.passed)
        c = result.counts
        self.assertEqual(c["forbid"], 1)
        self.assertEqual(c["unknown"], 1)
        names = {f.name: f for f in result.findings}
        self.assertEqual(names["pycopyleft"].license, "GPL-3.0")
        self.assertEqual(names["pycopyleft"].risk, "forbid")
        self.assertEqual(names["mysterylib"].risk, "unknown")

    def test_clean_gate_passes(self):
        import tempfile

        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "requirements.txt")
            with open(path, "w", encoding="utf-8") as fh:
                fh.write("a==1  # license: MIT\nb==2  # license: Apache-2.0\n")
            result = scan_project(path)
            self.assertTrue(result.passed)
            self.assertEqual(result.counts["allow"], 2)


class TestSbom(unittest.TestCase):
    def test_sbom_shape(self):
        result = scan_project(DEMO_REQ)
        sbom = build_sbom(result)
        self.assertEqual(sbom["bomFormat"], "CycloneDX")
        self.assertEqual(len(sbom["components"]), len(result.findings))
        self.assertTrue(sbom["components"][0]["purl"].startswith("pkg:pypi/"))


class TestCli(unittest.TestCase):
    def test_scan_json_exit_one(self):
        rc = main(["--format", "json", "scan", DEMO_REQ])
        self.assertEqual(rc, 1)

    def test_sbom_exit_zero(self):
        rc = main(["--format", "json", "sbom", DEMO_REQ])
        self.assertEqual(rc, 0)

    def test_missing_file_exit_two(self):
        rc = main(["scan", os.path.join(os.sep, "no", "such", "file.txt")])
        self.assertEqual(rc, 2)

    def test_meta(self):
        self.assertEqual(TOOL_NAME, "licenselens")
        self.assertTrue(TOOL_VERSION)


if __name__ == "__main__":
    unittest.main()
