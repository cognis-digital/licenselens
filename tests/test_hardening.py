"""Hardening tests: edge cases, bad input, and error paths."""

from __future__ import annotations

import io
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from licenselens.cli import _render_scan_table, main  # noqa: E402
from licenselens.core import (  # noqa: E402
    ScanResult,
    build_sbom,
    parse_requirements,
    scan_project,
)


class TestEmptyRequirementsFile(unittest.TestCase):
    """scan_project on a file with no dependencies should succeed (gate passes)."""

    def test_scan_empty_file_gate_passes(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "requirements.txt")
            with open(path, "w", encoding="utf-8") as fh:
                fh.write("# nothing here\n")
            result = scan_project(path)
            self.assertTrue(result.passed)
            c = result.counts
            self.assertEqual(c["allow"] + c["warn"] + c["forbid"] + c["unknown"], 0)

    def test_scan_truly_empty_file(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "requirements.txt")
            open(path, "w").close()  # zero-byte file
            result = scan_project(path)
            self.assertTrue(result.passed)
            self.assertEqual(result.findings, [])


class TestRenderScanTableEmpty(unittest.TestCase):
    """_render_scan_table must not crash on an empty ScanResult."""

    def test_no_crash_empty(self):
        result = ScanResult(findings=[])
        output = _render_scan_table(result)
        self.assertIn("no dependencies", output)
        self.assertIn("gate: PASS", output)


class TestMissingFileExitCode(unittest.TestCase):
    """CLI must return exit code 2 and print to stderr for a missing file."""

    def test_scan_missing_file(self):
        rc = main(["scan", "/no/such/requirements.txt"])
        self.assertEqual(rc, 2)

    def test_sbom_missing_file(self):
        rc = main(["sbom", "/no/such/requirements.txt"])
        self.assertEqual(rc, 2)

    def test_missing_file_stderr_message(self):
        old_stderr = sys.stderr
        sys.stderr = buf = io.StringIO()
        try:
            rc = main(["scan", "/no/such/requirements.txt"])
        finally:
            sys.stderr = old_stderr
        self.assertEqual(rc, 2)
        msg = buf.getvalue()
        self.assertIn("error", msg.lower())


class TestScanProjectValidation(unittest.TestCase):
    """scan_project raises ValueError on empty path."""

    def test_empty_path_raises(self):
        with self.assertRaises(ValueError):
            scan_project("")

    def test_none_path_raises(self):
        with self.assertRaises((ValueError, TypeError)):
            scan_project(None)  # type: ignore[arg-type]


class TestParseRequirementsEdgeCases(unittest.TestCase):
    """parse_requirements handles comment-only and directive lines safely."""

    def test_only_comments(self):
        deps = parse_requirements("# just a comment\n# another\n")
        self.assertEqual(deps, [])

    def test_only_directives(self):
        deps = parse_requirements("-r base.txt\n--index-url http://x\n")
        self.assertEqual(deps, [])

    def test_blank_lines(self):
        deps = parse_requirements("\n\n\n")
        self.assertEqual(deps, [])

    def test_license_override_whitespace(self):
        """Inline license override with extra whitespace is stripped correctly."""
        deps = parse_requirements("pkg==1.0  # license:   MIT   \n")
        self.assertEqual(len(deps), 1)
        self.assertEqual(deps[0].declared_license, "MIT")


class TestBuildSbomEmpty(unittest.TestCase):
    """build_sbom must work when there are zero findings."""

    def test_empty_sbom(self):
        result = ScanResult(findings=[])
        sbom = build_sbom(result)
        self.assertEqual(sbom["bomFormat"], "CycloneDX")
        self.assertEqual(sbom["components"], [])

    def test_sbom_table_format_empty(self):
        """CLI sbom --format table must not crash on an empty requirements file."""
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "requirements.txt")
            with open(path, "w", encoding="utf-8") as fh:
                fh.write("# empty\n")
            rc = main(["--format", "table", "sbom", path])
            self.assertEqual(rc, 0)
