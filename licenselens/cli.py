"""Command-line interface for LICENSELENS.

Subcommands:
  scan   Audit dependency licenses against a policy and gate the build.
  sbom   Emit a CycloneDX-style SBOM for the dependency set.

Global flags: --version, --format {table,json}.
Exit codes: 0 = gate passed, 1 = gate failed (forbid/unknown), 2 = usage/IO error.
"""

from __future__ import annotations

import argparse
import json
import sys
from typing import List, Optional

from . import TOOL_NAME, TOOL_VERSION
from .core import DEFAULT_POLICY, build_sbom, scan_project

_RISK_GLYPH = {"allow": "OK ", "warn": "WARN", "forbid": "FAIL", "unknown": "????"}


def _render_scan_table(result) -> str:
    lines = []
    if not result.findings:
        lines.append("(no dependencies found)")
        lines.append("summary: 0 allowed, 0 warn, 0 forbidden, 0 unknown")
        lines.append("gate: PASS")
        return "\n".join(lines)
    name_w = max(len(f.name) for f in result.findings)
    name_w = max(name_w, 4)
    ver_w = max(len(f.version) for f in result.findings)
    ver_w = max(ver_w, 7)
    lic_w = max(len(f.license) for f in result.findings)
    lic_w = max(lic_w, 7)
    header = (
        f"{'RISK':<4}  {'NAME':<{name_w}}  "
        f"{'VERSION':<{ver_w}}  {'LICENSE':<{lic_w}}  SOURCE"
    )
    lines.append(header)
    lines.append("-" * len(header))
    for f in result.findings:
        lines.append(
            f"{_RISK_GLYPH.get(f.risk, '????'):<4}  "
            f"{f.name:<{name_w}}  "
            f"{f.version:<{ver_w}}  {f.license:<{lic_w}}  {f.source}"
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
        n = len(sbom.get("components", []))
        lines = [
            f"CycloneDX {sbom.get('specVersion', '?')} - {n} components"
        ]
        for comp in sbom.get("components", []):
            lics = comp.get("licenses") or []
            if lics:
                lic = (
                    lics[0].get("license", {}).get("id", "UNKNOWN")
                )
            else:
                lic = "UNKNOWN"
            lines.append(
                f"  {comp.get('name', '?')} "
                f"{comp.get('version', '?')}  ({lic})  "
                f"{comp.get('purl', '?')}"
            )
        print("\n".join(lines))
    else:
        print(json.dumps(sbom, indent=2))
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog=TOOL_NAME,
        description="Dependency license + SBOM gate for CI (stdlib only, zero install).",  # noqa: E501
    )
    parser.add_argument(
        "--version", action="version", version=f"{TOOL_NAME} {TOOL_VERSION}"
    )
    parser.add_argument(
        "--format",
        choices=("table", "json"),
        default="table",
        help="output format (default: table)",
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
    return parser


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    try:
        args = parser.parse_args(argv)
    except SystemExit:
        raise  # argparse already printed usage; propagate the exit code
    try:
        return args.func(args)
    except KeyboardInterrupt:
        print("\ninterrupted", file=sys.stderr)
        return 130
    except Exception as exc:  # noqa: BLE001
        print(f"error: unexpected failure: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
