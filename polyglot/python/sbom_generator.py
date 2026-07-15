"""
polyglot/python/sbom_generator.py

SPDX-compliant SBOM generator for Python projects.
Integrates with pip, poetry, and pip-tools ecosystems.
"""

import json
import os
import re
import subprocess
import sys
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


@dataclass
class _PackageInfo:
    name: str = ""
    version: str = ""
    license_id: str = "NOASSERTION"
    summary: str = ""
    homepage: str = ""
    source_url: str = ""
    dependencies: List[str] = field(default_factory=list)


class PyPIResolver:
    """Fetch package metadata from PyPI."""

    BASE_URL = "https://pypi.org/pypi/{name}/json"

    @classmethod
    def fetch_metadata(cls, name: str, version: Optional[str] = None) -> Dict[str, Any]:
        url = cls.BASE_URL.format(name=name)
        if version:
            url += f"/{version}"
        
        try:
            import urllib.request
            with urllib.request.urlopen(url, timeout=10) as resp:
                return json.loads(resp.read().decode())
        except Exception:
            return {"info": {}}

    @classmethod
    def get_license_id(cls, metadata: Dict[str, Any]) -> str:
        info = metadata.get("info", {})
        
        # Check for SPDX license identifier first
        if "license" in info:
            license_str = info["license"]
            
            # Try to extract SPDX ID from common formats
            spdx_ids = [
                re.search(r'(?:SPDXRef-)?([A-Za-z0-9._\-]+)', license_str),
                re.search(r'License::\s*([A-Za-z0-9._\-]+)', license_str),
            ]
            
            for match in spdx_ids:
                if match and match.group(1):
                    return match.group(1)
        
        # Fallback to common licenses
        fallback_map = {
            "MIT": "MIT",
            "Apache 2.0": "Apache-2.0",
            "BSD": "BSD-3-Clause",
            "GPL": "GPL-3.0-only",
            "LGPL": "LGPL-3.0-only",
        }
        
        for key, value in fallback_map.items():
            if key.lower() in license_str.lower():
                return value
        
        return "NOASSERTION"

    @classmethod
    def get_summary(cls, metadata: Dict[str, Any]) -> str:
        info = metadata.get("info", {})
        return info.get("summary") or ""

    @classmethod
    def get_homepage(cls, metadata: Dict[str, Any]) -> str:
        info = metadata.get("info", {})
        return info.get("home_page") or info.get("project_url") or ""

    @classmethod
    def get_source_url(cls, metadata: Dict[str, Any]) -> str:
        info = metadata.get("info", {})
        return info.get("bugtrack_url") or info.get("project_url") or ""


class DependencyResolver:
    """Resolve dependencies from various Python project formats."""

    @classmethod
    def from_requirements(cls, requirements_path: Path) -> List[_PackageInfo]:
        packages = []
        
        with open(requirements_path) as f:
            for line in f:
                line = line.strip()
                
                # Skip comments and empty lines
                if not line or line.startswith("#"):
                    continue
                
                # Parse package specifiers like "package==1.0" or "package>=1.0,<2.0"
                match = re.match(r'^([a-zA-Z0-9._\-]+)(.*)$', line)
                if match:
                    name, version_spec = match.groups()
                    
                    # Extract just the version for metadata lookup
                    pkg_version = None
                    if "==" in version_spec:
                        pkg_version = version_spec.split("==")[1].split(",")[0]
                    elif ">=" in version_spec or "<" in version_spec:
                        # Use a reasonable default for pinned versions
                        parts = version_spec.replace(">=", "").replace("<", "").replace(",", "").strip()
                        if parts and not parts.startswith("-"):
                            pkg_version = parts.split(",")[0]
                    
                    packages.append(_PackageInfo(
                        name=name.lower(),
                        version=pkg_version or "unknown"
                    ))
        
        return packages

    @classmethod
    def from_poetry(cls, pyproject_path: Path) -> List[_PackageInfo]:
        """Parse poetry.lock for exact versions."""
        if not pyproject_path.exists():
            return []
        
        packages = []
        
        try:
            with open(pyproject_path) as f:
                content = f.read()
                
                # Find the [[package]] sections
                pattern = r'\[\[package\]\](.*?)\n\n'
                matches = re.findall(pattern, content, re.DOTALL)
                
                for match in matches:
                    pkg_name = ""
                    pkg_version = ""
                    
                    name_match = re.search(r'name\s*=\s*"([^"]+)"', match)
                    if name_match:
                        pkg_name = name_match.group(1).lower()
                    
                    version_match = re.search(r'version\s*=\s*"([^"]+)"', match)
                    if version_match:
                        pkg_version = version_match.group(1)
                    
                    if pkg_name and not pkg_name.startswith("-"):
                        packages.append(_PackageInfo(
                            name=pkg_name,
                            version=pkg_version or "unknown"
                        ))
        except Exception:
            pass
        
        return packages

    @classmethod
    def from_pip_tools(cls, requirements_path: Path) -> List[_PackageInfo]:
        """Parse pip-compile output."""
        return cls.from_requirements(requirements_path)


class SBOMGenerator:
    """Generate SPDX 2.3 compliant SBOM for Python projects."""

    def __init__(self, project_root: Optional[Path] = None):
        self.project_root = project_root or Path.cwd()
        self.packages: List[_PackageInfo] = []
        self.metadata: Dict[str, Any] = {}

    def discover_project(self) -> Tuple[Optional[Path], Optional[Path]]:
        """Find pyproject.toml and poetry.lock files."""
        pyproject = self.project_root / "pyproject.toml"
        poetry_lock = self.project_root / "poetry.lock"
        
        return pyproject, poetry_lock

    def resolve_dependencies(self) -> None:
        """Resolve all dependencies from available sources."""
        pyproject, poetry_lock = self.discover_project()
        
        # Priority 1: Poetry lock file (most accurate versions)
        if poetry_lock.exists():
            self.packages.extend(DependencyResolver.from_poetry(poetry_lock))
        
        # Priority 2: pip-tools requirements.txt
        req_path = self.project_root / "requirements.txt"
        if req_path.exists() and not pyproject.exists():
            self.packages.extend(DependencyResolver.from_requirements(req_path))
        
        # Priority 3: Any requirements.txt found
        elif req_path.exists():
            self.packages.extend(DependencyResolver.from_requirements(req_path))

    def enrich_metadata(self) -> None:
        """Fetch PyPI metadata for all resolved packages."""
        batch_size = 50
        
        for i in range(0, len(self.packages), batch_size):
            batch = self.packages[i:i + batch_size]
            
            # Parallel fetch (simple sequential for portability)
            for pkg in batch:
                if not pkg.version or pkg.version == "unknown":
                    continue
                
                metadata = PyPIResolver.fetch_metadata(pkg.name, pkg.version)
                
                if metadata.get("info"):
                    info = metadata["info"]
                    
                    # Update package info with fetched data
                    pkg.license_id = PyPIResolver.get_license_id(metadata)
                    pkg.summary = PyPIResolver.get_summary(metadata)
                    pkg.homepage = PyPIResolver.get_homepage(metadata)
                    pkg.source_url = PyPIResolver.get_source_url(metadata)

    def generate_spdx_document(self, spdx_version: str = "2.3") -> Dict[str, Any]:
        """Generate SPDX 2.3 SBOM document."""
        
        # Document metadata
        doc_metadata = {
            "spdxVersion": spdx_version,
            "dataLicense": "CC0-1.0",
            "name": f"licenselens-{self.project_root.name}",
            "documentNamespace": f"https://example.org/sbom/{self.project_root.name}",
            "creationInfo": {
                "created": datetime.utcnow().isoformat() + "Z",
                "creators": [f"Tool: licenselens"],
            },
        }

        # Package list
        packages = []
        
        for pkg in self.packages:
            if not pkg.name or pkg.name.startswith("-"):
                continue
            
            package_doc = {
                "name": pkg.name,
                "versionInfo": pkg.version,
                "downloadLocation": f"https://pypi.org/pypi/{pkg.name}/json",
                "filesAnalyzed": False,
                "licenseConcluded": pkg.license_id if pkg.license_id else "NOASSERTION",
            }

            # Add optional fields if available
            if pkg.summary:
                package_doc["summary"] = pkg.summary
            
            if pkg.homepage:
                package_doc["homepage"] = pkg.homepage
            
            if pkg.source_url:
                package_doc["sourceInfo"] = pkg.source_url
            
            packages.append(package_doc)

        # Build final document
        sbom = {
            "spdxVersion": spdx_version,
            "dataLicense": "CC0-1.0",
            "name": f"licenselens-{self.project_root.name}",
            "documentNamespace": f"https://example.org/sbom/{self.project_root.name}",
            "creationInfo": {
                "created": datetime.utcnow().isoformat() + "Z",
                "creators": [f"Tool: licenselens"],
            },
            "packages": packages,
        }

        return sbom

    def save_sbom(self, output_path: Path, spdx_version: str = "2.3") -> None:
        """Save SBOM to file in JSON format."""
        document = self.generate_spdx_document(spdx_version)
        
        with open(output_path, 'w') as f:
            json.dump(document, f, indent=2)

    def print_summary(self) -> None:
        """Print a human-readable summary of the SBOM."""
        print(f"Project: {self.project_root.name}")
        print(f"Total packages: {len([p for p in self.packages if p.name])}")
        
        # License distribution
        licenses = defaultdict(int)
        for pkg in self.packages:
            if pkg.license_id != "NOASSERTION":
                licenses[pkg.license_id] += 1
        
        print("\nLicense Distribution:")
        for license_id, count in sorted(licenses.items()):
            print(f"  {license_id}: {count}")

    def check_license_policies(self, policies: Dict[str, List[str]]) -> Tuple[bool, List[str]]:
        """Check packages against license policy rules.
        
        Policies format: {"MIT": ["pkg1", "pkg2"], "GPL-3.0-only": []}
        Returns (all_passed, list_of_violations)
        """
        violations = []
        
        for pkg in self.packages:
            if not pkg.name or pkg.name.startswith("-"):
                continue
            
            allowed = policies.get(pkg.license_id, [])
            
            if allowed and pkg.name.lower() not in [p.lower() for p in allowed]:
                violations.append(
                    f"Package {pkg.name} (v{pkg.version}) has license "
                    f"{pkg.license_id}, which is not explicitly allowed."
                )

        return len(violations) == 0, violations


def main():
    """Entry point for CLI usage."""
    import argparse
    
    parser = argparse.ArgumentParser(
        description="Generate SPDX-compliant SBOM for Python projects"
    )
    
    parser.add_argument(
        "-p", "--project-root",
        default=None,
        help="Path to project root (default: current directory)"
    )
    
    parser.add_argument(
        "-o", "--output",
        default="sbom.json",
        help="Output file path for SBOM"
    )
    
    parser.add_argument(
        "--summary",
        action="store_true",
        help="Print summary after generation"
    )
    
    args = parser.parse_args()

    # Initialize generator
    root = Path(args.project_root) if args.project_root else None
    
    generator = SBOMGenerator(project_root=root)
    
    # Resolve dependencies
    print("Resolving dependencies...")
    generator.resolve_dependencies()
    
    # Enrich with PyPI metadata
    print("Fetching package metadata from PyPI...")
    generator.enrich_metadata()
    
    # Generate and save SBOM
    output_path = Path(args.output)
    if not output_path.is_absolute():
        output_path = root / output_path
    
    print(f"Saving SBOM to: {output_path}")
    generator.save_sbom(output_path)
    
    # Print summary if requested
    if args.summary:
        print("\n--- Summary ---")
        generator.print_summary()

    return 0


if __name__ == "__main__":
    sys.exit(main())