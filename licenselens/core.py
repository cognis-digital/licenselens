"""Core engine for LICENSELENS.

Resolution order for a dependency's license:
  1. Explicit override in the requirements line (``# license: MIT``).
  2. Local installed package metadata (PEP 566 METADATA / PKG-INFO) found by
     walking ``site-packages`` style directories under the project.
  3. Marked ``UNKNOWN`` (which is itself a policy-driven risk).

No network access is ever performed.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field, asdict
from typing import Dict, List, Optional, Tuple

TOOL_NAME = "licenselens"
TOOL_VERSION = "0.1.0"

# --- License normalization -------------------------------------------------

# Map of messy real-world license strings -> canonical SPDX id.
_SPDX_ALIASES: Dict[str, str] = {
    "mit": "MIT",
    "mit license": "MIT",
    "the mit license": "MIT",
    "bsd": "BSD-3-Clause",
    "bsd license": "BSD-3-Clause",
    "bsd-2": "BSD-2-Clause",
    "bsd-2-clause": "BSD-2-Clause",
    "bsd-3": "BSD-3-Clause",
    "bsd-3-clause": "BSD-3-Clause",
    "apache": "Apache-2.0",
    "apache 2": "Apache-2.0",
    "apache 2.0": "Apache-2.0",
    "apache-2": "Apache-2.0",
    "apache-2.0": "Apache-2.0",
    "apache software license": "Apache-2.0",
    "isc": "ISC",
    "isc license": "ISC",
    "mpl": "MPL-2.0",
    "mpl-2.0": "MPL-2.0",
    "mozilla public license 2.0": "MPL-2.0",
    "lgpl": "LGPL-3.0",
    "lgpl-2.1": "LGPL-2.1",
    "lgpl-3.0": "LGPL-3.0",
    "gpl": "GPL-3.0",
    "gpl-2.0": "GPL-2.0",
    "gplv2": "GPL-2.0",
    "gpl-3.0": "GPL-3.0",
    "gplv3": "GPL-3.0",
    "agpl": "AGPL-3.0",
    "agpl-3.0": "AGPL-3.0",
    "agplv3": "AGPL-3.0",
    "unlicense": "Unlicense",
    "public domain": "Unlicense",
    "python software foundation license": "PSF-2.0",
    "psf": "PSF-2.0",
    "proprietary": "Proprietary",
    "commercial": "Proprietary",
}

UNKNOWN = "UNKNOWN"


def normalize_license(raw: Optional[str]) -> str:
    """Normalize a free-form license string to a canonical SPDX id."""
    if not raw:
        return UNKNOWN
    cleaned = raw.strip()
    if not cleaned:
        return UNKNOWN
    # Trove classifier form: "License :: OSI Approved :: MIT License"
    if "::" in cleaned:
        cleaned = cleaned.split("::")[-1].strip()
    key = cleaned.lower()
    if key in _SPDX_ALIASES:
        return _SPDX_ALIASES[key]
    # Try substring matching against known aliases (longest first).
    for alias in sorted(_SPDX_ALIASES, key=len, reverse=True):
        if alias in key:
            return _SPDX_ALIASES[alias]
    # Looks like a bare SPDX id already (e.g. "BSD-3-Clause").
    if re.fullmatch(r"[A-Za-z0-9.\-+]+", cleaned):
        return cleaned
    return UNKNOWN


# --- Policy ----------------------------------------------------------------

# Risk classification buckets. "allow" passes, "warn" is reported but does not
# fail the gate, "forbid" fails the gate. UNKNOWN is treated as forbid by
# default because an unaudited license is a real legal risk in CI.
DEFAULT_POLICY: Dict[str, List[str]] = {
    "allow": [
        "MIT",
        "BSD-2-Clause",
        "BSD-3-Clause",
        "Apache-2.0",
        "ISC",
        "Unlicense",
        "PSF-2.0",
    ],
    "warn": [
        "MPL-2.0",
        "LGPL-2.1",
        "LGPL-3.0",
    ],
    "forbid": [
        "GPL-2.0",
        "GPL-3.0",
        "AGPL-3.0",
        "Proprietary",
    ],
}

_SEVERITY_RANK = {"allow": 0, "warn": 1, "forbid": 2, "unknown": 2}


def classify(spdx: str, policy: Dict[str, List[str]]) -> Tuple[str, str]:
    """Return (risk, reason) for a normalized SPDX id under a policy.

    risk is one of: allow, warn, forbid, unknown.
    """
    if spdx == UNKNOWN:
        return "unknown", "license could not be determined"
    if spdx in policy.get("forbid", []):
        return "forbid", "license is on the forbid list"
    if spdx in policy.get("warn", []):
        return "warn", "copyleft / restricted license requires review"
    if spdx in policy.get("allow", []):
        return "allow", "license is on the allow list"
    return "unknown", "license not present in any policy bucket"


# --- Data models -----------------------------------------------------------


@dataclass
class Dependency:
    name: str
    version: str = "*"
    declared_license: Optional[str] = None  # from override comment


@dataclass
class Finding:
    name: str
    version: str
    license: str
    risk: str
    reason: str
    source: str  # how the license was resolved

    def as_dict(self) -> dict:
        return asdict(self)


@dataclass
class ScanResult:
    findings: List[Finding] = field(default_factory=list)
    policy: Dict[str, List[str]] = field(default_factory=dict)

    @property
    def counts(self) -> Dict[str, int]:
        out = {"allow": 0, "warn": 0, "forbid": 0, "unknown": 0}
        for f in self.findings:
            out[f.risk] = out.get(f.risk, 0) + 1
        return out

    @property
    def passed(self) -> bool:
        """Gate passes only when there are zero forbid/unknown findings."""
        c = self.counts
        return c["forbid"] == 0 and c["unknown"] == 0

    def as_dict(self) -> dict:
        return {
            "findings": [f.as_dict() for f in self.findings],
            "counts": self.counts,
            "passed": self.passed,
        }


# --- Parsing ---------------------------------------------------------------

_REQ_RE = re.compile(
    r"^\s*(?P<name>[A-Za-z0-9._\-]+)"
    r"\s*(?P<op>==|>=|<=|~=|!=|>|<)?\s*(?P<ver>[A-Za-z0-9._*\-]+)?"
)
_LICENSE_OVERRIDE_RE = re.compile(r"#\s*license:\s*(?P<lic>[^#\n]+)", re.IGNORECASE)


def parse_requirements(text: str) -> List[Dependency]:
    """Parse a requirements.txt-style file into Dependency objects.

    Supports an inline override comment to pin a license when metadata is not
    locally available:  ``coolpkg==1.2.3  # license: MIT``
    """
    deps: List[Dependency] = []
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or stripped.startswith("-"):
            continue
        override = None
        m_lic = _LICENSE_OVERRIDE_RE.search(line)
        if m_lic:
            override = m_lic.group("lic").strip()
        # Strip any trailing comment before matching name/version.
        code = line.split("#", 1)[0]
        m = _REQ_RE.match(code)
        if not m or not m.group("name"):
            continue
        version = m.group("ver") or "*"
        deps.append(
            Dependency(
                name=m.group("name"),
                version=version,
                declared_license=override,
            )
        )
    return deps


# --- Local metadata resolution ---------------------------------------------

_METADATA_LICENSE_RE = re.compile(r"^License:\s*(.+)$", re.IGNORECASE)
_METADATA_CLASSIFIER_RE = re.compile(
    r"^Classifier:\s*License\s*::\s*(.+)$", re.IGNORECASE
)


def _read_metadata_license(meta_path: str) -> Optional[str]:
    try:
        with open(meta_path, "r", encoding="utf-8", errors="replace") as fh:
            content = fh.read()
    except OSError:
        return None
    classifier_lic = None
    field_lic = None
    for line in content.splitlines():
        if line.startswith(" "):  # body of long description begins
            break
        mc = _METADATA_CLASSIFIER_RE.match(line)
        if mc:
            classifier_lic = mc.group(1).strip()
        mf = _METADATA_LICENSE_RE.match(line)
        if mf and mf.group(1).strip().upper() not in ("", "UNKNOWN"):
            field_lic = mf.group(1).strip()
    # Classifiers are more reliable than the free-form License field.
    return classifier_lic or field_lic


def _find_local_license(root: str, name: str) -> Optional[str]:
    """Search the project tree for installed metadata for ``name``."""
    norm = name.replace("-", "_").lower()
    norm_dash = name.replace("_", "-").lower()
    for dirpath, dirnames, filenames in os.walk(root):
        base = os.path.basename(dirpath).lower()
        is_dist = base.endswith(".dist-info") or base.endswith(".egg-info")
        if is_dist:
            pkg = base.split("-")[0].replace("_", "-")
            if pkg in (norm_dash, norm.replace("_", "-")):
                for meta in ("METADATA", "PKG-INFO"):
                    if meta in filenames:
                        lic = _read_metadata_license(os.path.join(dirpath, meta))
                        if lic:
                            return lic
    return None


# --- Top level scan --------------------------------------------------------


def scan_project(
    requirements_path: str,
    policy: Optional[Dict[str, List[str]]] = None,
    search_root: Optional[str] = None,
) -> ScanResult:
    """Scan a requirements file and classify every dependency's license.

    Raises:
        OSError: if the requirements file cannot be opened or read.
        ValueError: if ``requirements_path`` is empty/None.
    """
    if not requirements_path:
        raise ValueError("requirements_path must be a non-empty string")
    policy = policy or DEFAULT_POLICY
    # Raises OSError if path does not exist or is not readable.
    with open(requirements_path, "r", encoding="utf-8", errors="replace") as fh:
        text = fh.read()
    deps = parse_requirements(text)
    root = search_root or os.path.dirname(os.path.abspath(requirements_path))

    findings: List[Finding] = []
    for dep in deps:
        raw_license = dep.declared_license
        source = "override"
        if not raw_license:
            raw_license = _find_local_license(root, dep.name)
            source = "metadata" if raw_license else "unresolved"
        spdx = normalize_license(raw_license)
        risk, reason = classify(spdx, policy)
        findings.append(
            Finding(
                name=dep.name,
                version=dep.version,
                license=spdx,
                risk=risk,
                reason=reason,
                source=source,
            )
        )
    # Sort most-severe first, then by name, for stable, useful output.
    findings.sort(key=lambda f: (-_SEVERITY_RANK.get(f.risk, 2), f.name.lower()))
    return ScanResult(findings=findings, policy=policy)


# --- SBOM ------------------------------------------------------------------


def build_sbom(result: ScanResult) -> dict:
    """Build a minimal CycloneDX-1.5-style SBOM document from a scan."""
    from . import TOOL_NAME, TOOL_VERSION

    components = []
    for f in result.findings:
        components.append(
            {
                "type": "library",
                "name": f.name,
                "version": f.version,
                "purl": f"pkg:pypi/{f.name}@{f.version}",
                "licenses": [{"license": {"id": f.license}}],
            }
        )
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "version": 1,
        "metadata": {
            "tools": [  # noqa: E501
                {"vendor": "licenselens", "name": TOOL_NAME, "version": TOOL_VERSION}
            ]
        },
        "components": components,
    }
