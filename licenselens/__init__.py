"""LICENSELENS - Dependency license + SBOM gate for CI.

Developer-CLI-first license risk auditing. Scans a project's declared
dependencies, resolves each to a normalized SPDX license, classifies the
license risk against a configurable policy, emits a CycloneDX-style SBOM,
and fails the build (non-zero exit) when forbidden or unknown licenses are
found.

Standard library only. Zero install.
"""

from .core import (
    DEFAULT_POLICY,
    Dependency,
    Finding,
    ScanResult,
    build_sbom,
    classify,
    normalize_license,
    parse_requirements,
    scan_project,
)

TOOL_NAME = "licenselens"
TOOL_VERSION = "1.0.0"

__all__ = [
    "TOOL_NAME",
    "TOOL_VERSION",
    "DEFAULT_POLICY",
    "Dependency",
    "Finding",
    "ScanResult",
    "build_sbom",
    "classify",
    "normalize_license",
    "parse_requirements",
    "scan_project",
]
