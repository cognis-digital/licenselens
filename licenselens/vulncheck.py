"""Offline dependency-vulnerability enrichment for LICENSELENS.

LICENSELENS already resolves and gates the *licenses* of a dependency set. This
module adds the second half of a real supply-chain review — **known
vulnerabilities** — fully offline, against the bundled ``cognis_vulndb`` corpus
(``cognis_vulndb.jsonl.gz``, ~262k real OSV records spanning
PyPI/npm/Go/Maven/RubyGems/crates.io/NuGet).

No network access is ever performed by this module. The bundled DB is the
air-gap baseline; refresh/extend it with :mod:`licenselens.datafeeds` (OSV / NVD
/ GHSA) when you have connectivity, then sneakernet the cache to the edge.

Two surfaces:

* :func:`enrich_scan` — take a :class:`~licenselens.core.ScanResult` and attach,
  for every dependency, the real vulnerabilities affecting that package name
  (ecosystem-aware, namespace-tolerant). Produces a :class:`VulnReport`.
* :func:`lookup_cve` — resolve a single CVE / GHSA id to its real records.

Package-name matching is deliberately conservative and offline-honest:

* exact (case-insensitive) match on the bundled ``packages`` list, then
* a namespace-tolerant match so a bare ``log4j-core`` resolves the Maven
  ``org.apache.logging.log4j:log4j-core`` record without inventing data.

It never fabricates a CVE: a package with no real record reports zero vulns.
"""

from __future__ import annotations

from dataclasses import dataclass, field, asdict
from typing import Dict, List, Optional

from .vulndb_local import VulnDB

# Map our PyPI-centric purl ecosystem to the OSV ecosystem labels in the bundle.
# scan_project emits PyPI deps; ports/other manifests may pass an ecosystem.
_ECOSYSTEM_ALIASES = {
    "pypi": "PyPI",
    "python": "PyPI",
    "npm": "npm",
    "node": "npm",
    "go": "Go",
    "golang": "Go",
    "maven": "Maven",
    "java": "Maven",
    "rubygems": "RubyGems",
    "ruby": "RubyGems",
    "gem": "RubyGems",
    "crates.io": "crates.io",
    "cargo": "crates.io",
    "rust": "crates.io",
    "nuget": "NuGet",
    "packagist": "Packagist",
    "composer": "Packagist",
    "php": "Packagist",
}


def canonical_ecosystem(name: Optional[str]) -> Optional[str]:
    """Normalize a free-form ecosystem label to the OSV form used in the DB."""
    if not name:
        return None
    return _ECOSYSTEM_ALIASES.get(name.strip().lower(), name)


def _bare(pkg: str) -> str:
    """Strip a Maven group / npm scope namespace, lowercased.

    ``org.apache.logging.log4j:log4j-core`` -> ``log4j-core``
    ``@angular/core`` -> ``core`` (also kept as the full scoped name elsewhere)
    """
    p = (pkg or "").lower()
    if ":" in p:  # Maven group:artifact
        p = p.split(":")[-1]
    if p.startswith("@") and "/" in p:  # npm scope
        p = p.split("/", 1)[1]
    return p


# Severity ordering for sorting / "max severity" rollups. OSV severity strings
# are messy (CVSS vectors, bare CRITICAL/HIGH, or empty); we bucket coarsely.
_SEV_ORDER = {"critical": 4, "high": 3, "moderate": 2, "medium": 2, "low": 1, "": 0}


def _cvss_vector_bucket(vec: str) -> str:
    """Derive a coarse severity bucket from a raw CVSS v3/v4 vector string.

    OSV stores severity as a CVSS *vector* (e.g.
    ``CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H``) with no embedded base
    score, so we cannot just scan for a float (``3.1`` is the spec version, not
    the score). Instead we read the impact metrics: network-exploitable with
    high impact and scope-change is critical; high impact is high; etc. This is
    a deliberately conservative heuristic, never an invented CVSS score.
    """
    metrics = {}
    for part in vec.split("/"):
        if ":" in part:
            k, _, v = part.partition(":")
            metrics[k.upper()] = v.upper()
    impacts = [metrics.get(k, "N") for k in ("C", "I", "A")]
    high_impacts = sum(1 for x in impacts if x == "H")
    av = metrics.get("AV", "")
    scope = metrics.get("S", "")
    if high_impacts >= 2 and av == "N" and scope == "C":
        return "critical"
    if high_impacts >= 2 and av == "N":
        return "high"
    if high_impacts >= 1:
        return "moderate" if av != "N" else "high"
    if any(x in ("L", "H") for x in impacts):
        return "low"
    return "unknown"


def severity_bucket(raw: Optional[str]) -> str:
    """Coarse severity bucket from a raw OSV severity / CVSS-ish string."""
    s = (raw or "").strip()
    if not s:
        return "unknown"
    low = s.lower()
    for key in ("critical", "high", "moderate", "medium", "low"):
        if key in low:
            return "moderate" if key == "medium" else key
    # A CVSS vector string (no base score embedded): read impact metrics.
    if low.startswith("cvss:") or "/av:" in low or "/c:" in low:
        return _cvss_vector_bucket(s)
    # A bare numeric base score.
    import re

    m = re.fullmatch(r"\s*(\d+(?:\.\d+)?)\s*", s)
    if m:
        score = float(m.group(1))
        if score >= 9.0:
            return "critical"
        if score >= 7.0:
            return "high"
        if score >= 4.0:
            return "moderate"
        if score > 0:
            return "low"
    return "unknown"


def _sev_rank(raw: Optional[str]) -> int:
    return _SEV_ORDER.get(severity_bucket(raw), 0)


@dataclass
class VulnMatch:
    """A real vulnerability record matched to a dependency."""

    id: str
    aliases: List[str]
    ecosystem: str
    summary: str
    severity: str
    severity_bucket: str
    published: str
    modified: str
    packages: List[str]

    def as_dict(self) -> dict:
        return asdict(self)


@dataclass
class PackageVulns:
    name: str
    version: str
    ecosystem: str
    license: str
    risk: str
    vulns: List[VulnMatch] = field(default_factory=list)

    @property
    def vuln_count(self) -> int:
        return len(self.vulns)

    @property
    def max_severity(self) -> str:
        if not self.vulns:
            return "none"
        return max(self.vulns, key=lambda v: _SEV_ORDER.get(v.severity_bucket, 0)).severity_bucket

    def as_dict(self) -> dict:
        d = {
            "name": self.name,
            "version": self.version,
            "ecosystem": self.ecosystem,
            "license": self.license,
            "risk": self.risk,
            "vuln_count": self.vuln_count,
            "max_severity": self.max_severity,
            "vulns": [v.as_dict() for v in self.vulns],
        }
        return d


@dataclass
class VulnReport:
    packages: List[PackageVulns] = field(default_factory=list)
    db_size: int = 0

    @property
    def total_vulns(self) -> int:
        return sum(p.vuln_count for p in self.packages)

    @property
    def vulnerable_packages(self) -> int:
        return sum(1 for p in self.packages if p.vuln_count)

    @property
    def severity_counts(self) -> Dict[str, int]:
        out = {"critical": 0, "high": 0, "moderate": 0, "low": 0, "unknown": 0}
        for p in self.packages:
            for v in p.vulns:
                out[v.severity_bucket] = out.get(v.severity_bucket, 0) + 1
        return out

    def as_dict(self) -> dict:
        return {
            "db_size": self.db_size,
            "vulnerable_packages": self.vulnerable_packages,
            "total_vulns": self.total_vulns,
            "severity_counts": self.severity_counts,
            "packages": [p.as_dict() for p in self.packages],
        }


def _to_match(rec: dict) -> VulnMatch:
    return VulnMatch(
        id=rec.get("id", ""),
        aliases=list(rec.get("aliases") or []),
        ecosystem=rec.get("ecosystem", ""),
        summary=rec.get("summary", ""),
        severity=rec.get("severity", ""),
        severity_bucket=severity_bucket(rec.get("severity")),
        published=rec.get("published", ""),
        modified=rec.get("modified", ""),
        packages=list(rec.get("packages") or []),
    )


def match_package(
    db: VulnDB,
    name: str,
    ecosystem: Optional[str] = None,
    *,
    namespace_tolerant: bool = True,
    limit: int = 200,
) -> List[VulnMatch]:
    """Return real vulnerabilities affecting ``name`` from the bundled DB.

    Exact (case-insensitive) match first; if nothing hits and
    ``namespace_tolerant`` is on, also match records whose package list contains
    an entry whose bare (namespace-stripped) name equals ``name``. This resolves
    a bare ``log4j-core`` to the Maven ``org.apache.logging.log4j:log4j-core``
    record without fabricating anything.
    """
    eco = canonical_ecosystem(ecosystem)
    seen: set = set()
    out: List[VulnMatch] = []

    def _add(records: List[dict]) -> None:
        for r in records:
            if eco and r.get("ecosystem", "").lower() != eco.lower():
                continue
            rid = r.get("id", "")
            if rid in seen:
                continue
            seen.add(rid)
            out.append(_to_match(r))

    _add(db.by_package(name, ecosystem=eco))

    if namespace_tolerant and not out:
        target = _bare(name)
        # Walk the package index for any record whose bare package name matches.
        db._index()  # noqa: SLF001 — internal index is the documented fast path
        for key, records in db._by_pkg.items():  # noqa: SLF001
            if _bare(key) == target:
                _add(records)

    out.sort(key=lambda v: -_SEV_ORDER.get(v.severity_bucket, 0))
    return out[:limit]


def lookup_cve(cve: str, db: Optional[VulnDB] = None) -> List[VulnMatch]:
    """Resolve a CVE / GHSA / OSV id to its real records (offline)."""
    db = db or VulnDB()
    return [_to_match(r) for r in db.by_cve(cve)]


def enrich_scan(
    scan_result,
    db: Optional[VulnDB] = None,
    *,
    ecosystem: str = "PyPI",
    per_package_limit: int = 50,
) -> VulnReport:
    """Enrich a :class:`ScanResult` with offline vulnerability matches.

    Pairs each license finding with the real known vulnerabilities for that
    package. The result is a :class:`VulnReport` that renders as a table or
    JSON and is forwardable via cognis-connect.
    """
    db = db or VulnDB()
    report = VulnReport(db_size=db.count())
    for f in scan_result.findings:
        matches = match_package(
            db, f.name, ecosystem=ecosystem, limit=per_package_limit
        )
        report.packages.append(
            PackageVulns(
                name=f.name,
                version=f.version,
                ecosystem=canonical_ecosystem(ecosystem) or ecosystem,
                license=f.license,
                risk=f.risk,
                vulns=matches,
            )
        )
    # Most-vulnerable, most-severe first.
    report.packages.sort(
        key=lambda p: (
            -p.vuln_count,
            -_SEV_ORDER.get(p.max_severity, 0),
            p.name.lower(),
        )
    )
    return report
