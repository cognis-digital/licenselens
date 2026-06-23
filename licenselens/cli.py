"""Command-line interface for LICENSELENS.

Subcommands:
  scan       Audit dependency licenses against a policy and gate the build.
  sbom       Emit a CycloneDX-style SBOM for the dependency set.
  vulncheck  Enrich the dependency set with known vulnerabilities, fully
             offline, against the bundled ~262k-record OSV corpus.
  cve        Resolve a single CVE / GHSA / OSV id from the bundled DB (offline).

Global flags: --version, --format {table,json,sarif}.
Exit codes:
  scan/vulncheck: 0 = gate passed, 1 = gate failed, 2 = usage/IO error.
  sbom/cve:       0 = ok, 2 = usage/IO error.

No network access is ever performed. ``vulncheck`` reads only the bundled,
offline vulnerability database.
"""

from __future__ import annotations

import argparse
import json
import sys
from typing import List, Optional

from . import TOOL_NAME, TOOL_VERSION
from .core import DEFAULT_POLICY, build_sarif, build_sbom, scan_project

_RISK_GLYPH = {"allow": "OK ", "warn": "WARN", "forbid": "FAIL", "unknown": "????"}

_SEV_GLYPH = {
    "critical": "CRIT",
    "high": "HIGH",
    "moderate": "MOD ",
    "low": "LOW ",
    "unknown": "??? ",
    "none": "----",
}


def _render_scan_table(result) -> str:
    lines = []
    name_w = max([len(f.name) for f in result.findings] + [4])
    ver_w = max([len(f.version) for f in result.findings] + [7])
    lic_w = max([len(f.license) for f in result.findings] + [7])
    header = f"{'RISK':<4}  {'NAME':<{name_w}}  {'VERSION':<{ver_w}}  {'LICENSE':<{lic_w}}  SOURCE"
    lines.append(header)
    lines.append("-" * len(header))
    for f in result.findings:
        lines.append(
            f"{_RISK_GLYPH.get(f.risk, '????'):<4}  "
            f"{f.name:<{name_w}}  {f.version:<{ver_w}}  {f.license:<{lic_w}}  {f.source}"
        )
    c = result.counts
    lines.append("")
    lines.append(
        f"summary: {c['allow']} allowed, {c['warn']} warn, "
        f"{c['forbid']} forbidden, {c['unknown']} unknown"
    )
    lines.append("gate: PASS" if result.passed else "gate: FAIL")
    return "\n".join(lines)


def _cmd_scan(args) -> int:
    try:
        result = scan_project(args.requirements, policy=DEFAULT_POLICY)
    except OSError as exc:
        print(f"error: cannot read {args.requirements}: {exc}", file=sys.stderr)
        return 2
    if args.format == "json":
        print(json.dumps(result.as_dict(), indent=2))
    elif args.format == "sarif":
        print(json.dumps(build_sarif(result, args.requirements), indent=2))
    else:
        print(_render_scan_table(result))
    return 0 if result.passed else 1


def _cmd_sbom(args) -> int:
    try:
        result = scan_project(args.requirements, policy=DEFAULT_POLICY)
    except OSError as exc:
        print(f"error: cannot read {args.requirements}: {exc}", file=sys.stderr)
        return 2
    sbom = build_sbom(result)
    if args.format == "table":
        # A SBOM is structured data; table mode prints a compact component list.
        lines = [f"CycloneDX {sbom['specVersion']} - {len(sbom['components'])} components"]
        for comp in sbom["components"]:
            lic = comp["licenses"][0]["license"]["id"]
            lines.append(f"  {comp['name']} {comp['version']}  ({lic})  {comp['purl']}")
        print("\n".join(lines))
    else:
        print(json.dumps(sbom, indent=2))
    return 0


def _render_vuln_table(report) -> str:
    lines = []
    name_w = max([len(p.name) for p in report.packages] + [4])
    lic_w = max([len(p.license) for p in report.packages] + [7])
    header = (
        f"{'SEV ':<4}  {'NAME':<{name_w}}  {'VULNS':>5}  "
        f"{'LICENSE':<{lic_w}}  TOP CVE / ADVISORY"
    )
    lines.append(header)
    lines.append("-" * len(header))
    for p in report.packages:
        top = ""
        if p.vulns:
            v = p.vulns[0]
            cve = next((a for a in v.aliases if a.upper().startswith("CVE-")), v.id)
            top = f"{cve}: {v.summary[:54]}"
        lines.append(
            f"{_SEV_GLYPH.get(p.max_severity, '??? '):<4}  "
            f"{p.name:<{name_w}}  {p.vuln_count:>5}  {p.license:<{lic_w}}  {top}"
        )
    sc = report.severity_counts
    lines.append("")
    lines.append(
        f"db: {report.db_size} records (offline) · "
        f"{report.vulnerable_packages} vulnerable package(s) · "
        f"{report.total_vulns} total vuln(s)"
    )
    lines.append(
        f"severity: {sc['critical']} critical, {sc['high']} high, "
        f"{sc['moderate']} moderate, {sc['low']} low, {sc['unknown']} unknown"
    )
    return "\n".join(lines)


def _cmd_vulncheck(args) -> int:
    from .core import scan_project as _scan
    from .vulncheck import enrich_scan

    try:
        result = _scan(args.requirements, policy=DEFAULT_POLICY)
    except OSError as exc:
        print(f"error: cannot read {args.requirements}: {exc}", file=sys.stderr)
        return 2
    report = enrich_scan(result, ecosystem=args.ecosystem)
    if args.format == "json":
        print(json.dumps(report.as_dict(), indent=2))
    else:
        print(_render_vuln_table(report))
    # Gate: fail when any real vulnerability at/above the chosen severity floor
    # is present. --fail-on off never fails (report-only).
    if args.fail_on == "off":
        return 0
    floor = {"any": 1, "low": 1, "moderate": 2, "high": 3, "critical": 4}[args.fail_on]
    from .vulncheck import _SEV_ORDER

    worst = 0
    for p in report.packages:
        for v in p.vulns:
            worst = max(worst, _SEV_ORDER.get(v.severity_bucket, 0))
    return 1 if (report.total_vulns and worst >= floor) else 0


def _cmd_cve(args) -> int:
    from .vulncheck import lookup_cve

    matches = lookup_cve(args.id)
    if args.format == "json":
        print(json.dumps([m.as_dict() for m in matches], indent=2))
    else:
        if not matches:
            print(f"no record for {args.id} in the bundled database")
        for m in matches:
            aliases = ", ".join(m.aliases) if m.aliases else "—"
            print(f"{m.id}  [{m.ecosystem}]  severity={m.severity_bucket}")
            print(f"  aliases: {aliases}")
            print(f"  packages: {', '.join(m.packages) or '—'}")
            print(f"  summary: {m.summary}")
            print(f"  published: {m.published}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog=TOOL_NAME,
        description="Dependency license + SBOM gate for CI (stdlib only, zero install).",
    )
    parser.add_argument(
        "--version", action="version", version=f"{TOOL_NAME} {TOOL_VERSION}"
    )
    parser.add_argument(
        "--format",
        choices=("table", "json", "sarif"),
        default="table",
        help="output format (default: table). 'sarif' applies to scan and "
        "emits a SARIF 2.1.0 log for code-scanning UIs.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p_scan = sub.add_parser("scan", help="audit licenses and gate the build")
    p_scan.add_argument(
        "requirements", help="path to a requirements.txt-style file"
    )
    p_scan.set_defaults(func=_cmd_scan)

    p_sbom = sub.add_parser("sbom", help="emit a CycloneDX-style SBOM")
    p_sbom.add_argument(
        "requirements", help="path to a requirements.txt-style file"
    )
    p_sbom.set_defaults(func=_cmd_sbom)

    p_vuln = sub.add_parser(
        "vulncheck",
        help="enrich the dependency set with known vulnerabilities (offline)",
    )
    p_vuln.add_argument(
        "requirements", help="path to a requirements.txt-style file"
    )
    p_vuln.add_argument(
        "--ecosystem",
        default="PyPI",
        help="package ecosystem for matching (default: PyPI). One of "
        "PyPI/npm/Go/Maven/RubyGems/crates.io/NuGet.",
    )
    p_vuln.add_argument(
        "--fail-on",
        choices=("off", "any", "low", "moderate", "high", "critical"),
        default="off",
        help="gate severity floor (default: off = report only). e.g. "
        "--fail-on high exits 1 when any high/critical vuln is found.",
    )
    p_vuln.set_defaults(func=_cmd_vulncheck)

    p_cve = sub.add_parser(
        "cve", help="resolve a CVE / GHSA / OSV id from the bundled DB (offline)"
    )
    p_cve.add_argument("id", help="e.g. CVE-2021-44228 or GHSA-xxxx-xxxx-xxxx")
    p_cve.set_defaults(func=_cmd_cve)
    return parser


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
