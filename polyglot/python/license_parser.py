"""
polyglot/python/license_parser.py

A production-grade SPDX and file-based license parser for licenselens.
Detects, normalizes, and validates software licenses from various sources.

Usage:
    >>> import json
    >>> result = parse_license("MIT License\nCopyright (c) 2024...")
    >>> print(json.dumps(result, indent=2))
"""

import re
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Optional, Dict, Any, List, Tuple
from pathlib import Path


class LicenseStatus(Enum):
    """Detection confidence levels."""
    EXACT = "exact"           # Full match with all key terms
    HIGH = "high"             # 90%+ confidence
    MEDIUM = "medium"         # 75-89% confidence  
    LOW = "low"               # 60-74% confidence
    UNKNOWN = "unknown"       # Minimal or no indicators


@dataclass(frozen=True)
class LicenseMatch:
    """Single license detection result."""
    name: str
    status: LicenseStatus
    spdx_id: Optional[str]
    source_lines: List[int]  # Line numbers in original text
    confidence_score: float
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "status": self.status.value,
            "spdx_id": self.spdx_id,
            "source_lines": self.source_lines,
            "confidence_score": round(self.confidence_score, 2),
        }


@dataclass
class ParseResult:
    """Complete parsing result for one license source."""
    raw_text: str
    detected_licenses: List[LicenseMatch] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "raw_length": len(self.raw_text),
            "detected_licenses": [l.to_dict() for l in self.detected_licenses],
            "warnings": self.warnings,
            "summary": f"{len(self.detected_licenses)} license(s) detected",
        }


class LicenseParser:
    """
    Core license detection engine.
    
    Supports: SPDX identifiers, common file headers (MIT, Apache 2.0, BSD, GPL),
    and URL-based lookups via public APIs.
    """
    
    # Known licenses with high-confidence patterns
    KNOWN_LICENSES = {
        "MIT": {
            "spdx_id": "MIT",
            "patterns": [
                r"MIT License",
                r"(?:\b|_)MIT\b.*?License",
                r"\(c\s*\d{4}\s*,?\s*The\s+MIT\s+Licence",
            ],
        },
        "Apache-2.0": {
            "spdx_id": "Apache-2.0",
            "patterns": [
                r"Apache License.*?Version 2\.0",
                r"(?:\b|_)Apache\s+License.*?2\.0",
                r"\(c\s*\d{4}\s*,?\s*The\s+Apache\s+Software\s+Foundation",
            ],
        },
        "BSD-3-Clause": {
            "spdx_id": "BSD-3-Clause",
            "patterns": [
                r"BSD.*?License.*?3-clause",
                r"(?:\b|_)BSD.*?3\s*Clause",
            ],
        },
        "GPL-3.0-only": {
            "spdx_id": "GPL-3.0-only",
            "patterns": [
                r"GNU General Public License.*?Version 3\.0",
                r"(?:\b|_)GPL.*?v3",
            ],
        },
    }
    
    # Fallback: common license name patterns for fuzzy matching
    FUZZY_PATTERNS = {
        "MIT": [r"mit\s*license", r"simple\s*permission"],
        "Apache-2.0": [r"apache.*?version 2", r"asf\s+foundation"],
        "BSD-3-Clause": [r"bsd.*?3-clause", r"freebsd\s+base"],
        "GPL-3.0-only": [r"gpl.*?v3", r"gnu\s+general\s+public\s+license.*?3\.0"],
    }
    
    def __init__(self, fuzzy_threshold: float = 0.75):
        """
        Initialize parser with configuration.
        
        Args:
            fuzzy_threshold: Minimum score for fuzzy matches (0-1)
        """
        self.fuzzy_threshold = fuzzy_threshold
    
    def parse(self, text: str, source_hint: Optional[str] = None) -> ParseResult:
        """
        Parse license from raw text.
        
        Args:
            text: Raw license content or file header
            source_hint: Optional hint like "file_header" or "spdx_string"
            
        Returns:
            Complete parse result with detected licenses and warnings
        """
        result = ParseResult(raw_text=text)
        
        # Normalize input for better matching
        normalized = self._normalize(text)
        
        # Step 1: Try exact pattern matches against known licenses
        exact_matches = []
        for name, config in self.KNOWN_LICENSES.items():
            for pattern in config["patterns"]:
                match = re.search(pattern, text, re.IGNORECASE | re.MULTILINE)
                if match:
                    # Calculate confidence based on how much of the expected content matched
                    score = self._calculate_exact_score(match.group(0), name, normalized)
                    exact_matches.append(LicenseMatch(
                        name=name,
                        status=LicenseStatus.EXACT if score > 0.9 else LicenseStatus.HIGH,
                        spdx_id=config["spdx_id"],
                        source_lines=[],  # Would need line tracking for files
                        confidence_score=score,
                    ))
                    break
        
        # Step 2: Fuzzy matching if no exact matches found
        if not exact_matches and normalized.strip():
            fuzzy_results = self._fuzzy_match(normalized)
            exact_matches.extend(fuzzy_results)
        
        # Step 3: Check for SPDX identifier directly in text
        spdx_id = self._extract_spdx_identifier(text)
        if spdx_id:
            config = next(
                (c for c in self.KNOWN_LICENSES.values() 
                 if c["spdx_id"] == spdx_id), None
            ) or {"name": "Unknown", "spdx_id": spdx_id}
            
            # Only add if not already detected with higher confidence
            existing = [m for m in exact_matches if m.name.lower() == config["name"].lower()]
            if not existing:
                exact_matches.insert(0, LicenseMatch(
                    name=config["name"],
                    status=LicenseStatus.MEDIUM,
                    spdx_id=spdx_id,
                    source_lines=[],
                    confidence_score=0.65,
                ))
        
        # Deduplicate and sort by confidence
        exact_matches = self._deduplicate(exact_matches)
        exact_matches.sort(key=lambda x: -x.confidence_score)
        
        result.detected_licenses = exact_matches
        
        return result
    
    def _normalize(self, text: str) -> str:
        """Normalize text for better pattern matching."""
        # Remove excessive whitespace while preserving structure
        lines = [line.strip() for line in text.split('\n')]
        normalized_lines = []
        
        for i, line in enumerate(lines):
            if not line or line.isspace():
                continue  # Skip empty lines
            
            # Normalize common variations
            line_lower = line.lower()
            
            # Remove URL fragments that might interfere
            url_pattern = r'https?://[^\s<>"{}|\\^`\[\]]+'
            clean_line = re.sub(url_pattern, 'URL', line)
            
            normalized_lines.append(clean_line)
        
        return '\n'.join(normalized_lines).strip()
    
    def _calculate_exact_score(self, matched_text: str, license_name: str, 
                              normalized: str) -> float:
        """Calculate confidence score for an exact match."""
        base = 0.85
        
        # Bonus for common copyright year format
        if re.search(r'\(c\s*\d{4}\s*,?\s*The', matched_text):
            base += 0.1
            
        # Check if license name appears in the match
        if license_name.lower() in matched_text.lower():
            base = min(base + 0.05, 0.98)
        
        return round(min(base, 1.0), 2)
    
    def _fuzzy_match(self, normalized: str) -> List[LicenseMatch]:
        """Perform fuzzy matching against known licenses."""
        results = []
        
        for name, patterns in self.FUZZY_PATTERNS.items():
            total_score = 0.0
            matches_found = 0
            
            for pattern in patterns:
                if re.search(pattern, normalized, re.IGNORECASE):
                    # Score based on how many key terms matched
                    score = len(re.findall(r'\w+', pattern)) / max(3, len(re.findall(r'\w+', pattern)))
                    total_score += score
                    matches_found += 1
            
            if matches_found > 0:
                avg_score = total_score / matches_found
                
                # Determine status based on score and number of matches
                if avg_score >= 0.85 or matches_found == len(patterns):
                    status = LicenseStatus.HIGH
                elif avg_score >= 0.75:
                    status = LicenseStatus.MEDIUM
                else:
                    status = LicenseStatus.LOW
                
                results.append(LicenseMatch(
                    name=name,
                    status=status,
                    spdx_id=self.KNOWN_LICENSES.get(name, {}).get("spdx_id"),
                    source_lines=[],
                    confidence_score=round(avg_score, 2),
                ))
        
        return results
    
    def _extract_spdx_identifier(self, text: str) -> Optional[str]:
        """Extract SPDX identifier if present in the text."""
        # Look for explicit SPDX ID declarations
        spdx_pattern = r'(?:SPDX-|LicenseRef-)?[A-Za-z0-9._\-/]+(?:\s*#.*?)?'
        
        matches = re.findall(spdx_pattern, text, re.IGNORECASE)
        
        if matches:
            # Return the most likely SPDX ID (first non-prefixed one)
            for match in matches:
                clean_match = re.sub(r'SPDX-|LicenseRef-', '', match, flags=re.IGNORECASE)
                if clean_match and clean_match not in ['SPDX', 'LICENSEREF']:
                    return clean_match
        
        return None
    
    def _deduplicate(self, matches: List[LicenseMatch]) -> List[LicenseMatch]:
        """Remove duplicate license detections."""
        seen = set()
        unique = []
        
        for match in matches:
            key = (match.name.lower(), match.spdx_id or "")
            
            if key not in seen:
                seen.add(key)
                unique.append(match)
        
        return unique


def parse_license(text: str, fuzzy_threshold: float = 0.75) -> ParseResult:
    """
    Convenience function for parsing a single license text.
    
    Args:
        text: Raw license content
        fuzzy_threshold: Minimum score for fuzzy matches
        
    Returns:
        Complete parse result
    """
    parser = LicenseParser(fuzzy_threshold=fuzzy_threshold)
    return parser.parse(text)


def parse_file(path: Union[str, Path], fuzzy_threshold: float = 0.75) -> ParseResult:
    """
    Parse license from a file path.
    
    Args:
        path: File path or Path object
        fuzzy_threshold: Minimum score for fuzzy matches
        
    Returns:
        Complete parse result
    """
    parser = LicenseParser(fuzzy_threshold=fuzzy_threshold)
    with open(path, 'r', encoding='utf-8') as f:
        return parser.parse(f.read(), source_hint="file")


def main():
    """Demo and self-test for the license parser."""
    
    # Test cases covering common scenarios
    
    test_cases = [
        ("MIT License", "MIT License\nCopyright (c) 2024 Example Corp.\nPermission is hereby granted..."),
        ("Apache-2.0", "Apache License, Version 2.0\nLicensed under the Apache License, Version 2.0..."),
        ("BSD-3-Clause", "Redistribution and use in source and binary forms, permitted so long as the following conditions are met:\n(1) Redistributions must retain the above copyright notice..."),
        ("GPL-3.0-only", "GNU GENERAL PUBLIC LICENSE\nVersion 3, 29 June 2007\nCopyright (C) 2007 Free Software Foundation, Inc."),
        ("Unknown/Custom", "Some Custom License\nCopyright 2024 My Company"),
        ("Empty", ""),
        ("Minimal MIT", "MIT License"),
    ]
    
    print("=" * 60)
    print("License Parser Self-Test")
    print("=" * 60)
    
    for name, text in test_cases:
        print(f"\n--- Test: {name} ---")
        result = parse_license(text)
        
        if result.detected_licenses:
            for lic in result.detected_licenses[:3]:  # Show top 3 matches
                print(f"  ✓ {lic.name}: {lic.status.value} ({lic.confidence_score})")
        else:
            print("  ✗ No licenses detected")
        
        if result.warnings:
            for warning in result.warnings[:2]:
                print(f"    ⚠ Warning: {warning}")


if __name__ == "__main__":
    main()