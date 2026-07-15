"""
Policy Engine for licenselens - Developer-First SBOM & License Gate

A complete, self-contained policy evaluation engine that:
- Loads and validates license policies (allow/block/audit)
- Evaluates dependencies against configured rules
- Generates detailed reports with decision rationale
- Supports graceful degradation when metadata is missing
"""

from __future__ import annotations
import json
import os
import sys
import re
from dataclasses import dataclass, field, asdict
from enum import Enum, auto
from typing import (
    Protocol, Optional, Callable, Any, List, Dict, Tuple, Set, 
    Iterator, TypeVar, Generic, Union
)
from contextlib import contextmanager
from functools import lru_cache
import hashlib
import urllib.parse
from datetime import datetime, timezone

# =============================================================================
# CONSTANTS & CONFIGURATION
# =============================================================================

DEFAULT_POLICY_PATH = "~/.licenselens/policy.json"
DEFAULT_LICENSE_DB_PATH = "~/.licenselens/license-db.json"
LOG_PREFIX = "[POLICY]"
MAX_RECURSION_DEPTH = 100
DEFAULT_TIMEOUT_SECONDS = 30


class PolicyAction(Enum):
    """Actions a policy can take on a license."""
    ALLOW = auto()
    BLOCK = auto()
    AUDIT = auto()
    WARN = auto()
    PROMPT = auto()


class DecisionType(Enum):
    """Types of decisions the engine makes."""
    PASS = auto()
    FAIL = auto()
    REVIEW = auto()
    WARNING = auto()
    INFO = auto()


# =============================================================================
# DATA MODELS
# =============================================================================

@dataclass(frozen=True)
class LicenseMetadata:
    """License metadata with resolution hints."""
    name: str
    spdx_id: Optional[str] = None
    url: Optional[str] = None
    text_url: Optional[str] = None
    is_fsf_free: bool = True
    is_osi_approved: bool = True
    copyleft: bool = False
    weak_copyleft: bool = False
    permissive: bool = True
    
    def __hash__(self):
        return hash((self.name, self.spdx_id))


@dataclass(frozen=True)
class DependencyContext:
    """Context for a single dependency."""
    name: str
    version: str
    scope: str  # "direct" or "transitive"
    license: Optional[str] = None
    resolved_license: Optional[LicenseMetadata] = None
    
    def __hash__(self):
        return hash((self.name, self.version))


@dataclass(frozen=True)
class PolicyRule:
    """A single policy rule for evaluation."""
    name: str
    action: PolicyAction
    licenses: List[str]  # SPDX IDs or names
    conditions: Dict[str, Any] = field(default_factory=dict)
    description: str = ""
    
    def matches_license(self, license_name: str) -> bool:
        """Check if this rule applies to a given license."""
        normalized = normalize_license(license_name)
        
        for pattern in self.licenses:
            # Try exact match first
            if pattern == normalized or pattern.lower() == normalized.lower():
                return True
            
            # Try regex patterns
            try:
                if re.match(pattern, normalized, re.IGNORECASE):
                    return True
            except re.error:
                pass
        
        return False


@dataclass(frozen=True)
class PolicySet:
    """Complete policy configuration."""
    name: str = "default"
    rules: List[PolicyRule] = field(default_factory=list)
    defaults: Dict[str, Any] = field(default_factory=dict)
    
    def get_rule_for_license(self, license_name: str) -> Optional[PolicyRule]:
        """Find the most specific matching rule."""
        matches = [r for r in self.rules if r.matches_license(license_name)]
        
        if not matches:
            return None
        
        # Sort by specificity (longer patterns first)
        def specificity_score(rule):
            pattern_str = str(rule.licenses[0]) if rule.licenses else ""
            regex_count = sum(1 for c in pattern_str if c in '.*[]{}()|\\^$+?')
            return -len(pattern_str) + 2 * regex_count
        
        matches.sort(key=specificity_score, reverse=True)
        return matches[0]


@dataclass(frozen=True)
class EvaluationResult:
    """Result of evaluating a single dependency."""
    context: DependencyContext
    action: PolicyAction
    decision: DecisionType
    message: str = ""
    matched_rule: Optional[PolicyRule] = None
    warnings: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict:
        return {
            "name": self.context.name,
            "version": self.context.version,
            "scope": self.context.scope,
            "license": self.context.license,
            "action": self.action.name,
            "decision": self.decision.name,
            "message": self.message,
            "matched_rule": asdict(self.matched_rule) if self.matched_rule else None,
            "warnings": self.warnings,
        }


@dataclass(frozen=True)
class EvaluationReport:
    """Complete evaluation report."""
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    policy_set: Optional[PolicySet] = None
    total_deps: int = 0
    passed: int = 0
    failed: int = 0
    reviewed: int = 0
    warnings: int = 0
    
    results: List[EvaluationResult] = field(default_factory=list)
    
    def to_dict(self) -> Dict:
        return {
            "timestamp": self.timestamp,
            "policy_set": asdict(self.policy_set) if self.policy_set else None,
            "summary": {
                "total_deps": self.total_deps,
                "passed": self.passed,
                "failed": self.failed,
                "reviewed": self.reviewed,
                "warnings": self.warnings,
            },
            "results": [r.to_dict() for r in self.results],
        }


# =============================================================================
# UTILITY FUNCTIONS
# =============================================================================

def normalize_license(license_name: str) -> str:
    """Normalize license name for comparison."""
    if not license_name:
        return ""
    
    # Remove common prefixes/suffixes
    normalized = license_name.strip().lower()
    normalized = re.sub(r'\s*\(.*?\)\s*', '', normalized)  # Remove parenthetical notes
    normalized = re.sub(r'^(spdx|license):? ', '', normalized, flags=re.IGNORECASE)
    
    return normalized


def load_json_file(path: str) -> Any:
    """Load JSON file with graceful error handling."""
    try:
        if path.startswith("~"):
            path = os.path.expanduser(path)
        
        with open(path, 'r', encoding='utf-8') as f:
            return json.load(f)
    except FileNotFoundError:
        return None
    except (json.JSONDecodeError, IOError):
        return {}


def load_license_database() -> Dict[str, LicenseMetadata]:
    """Load the license database."""
    db_path = os.path.expanduser(DEFAULT_LICENSE_DB_PATH)
    
    # Default embedded database for common licenses
    default_db: Dict[str, LicenseMetadata] = {
        "MIT": LicenseMetadata(
            name="MIT", spdx_id="MIT", url="https://opensource.org/licenses/MIT",
            is_fsf_free=True, is_osi_approved=True, permissive=True
        ),
        "Apache-2.0": LicenseMetadata(
            name="Apache-2.0", spdx_id="Apache-2.0", 
            url="https://www.apache.org/licenses/LICENSE-2.0",
            is_fsf_free=True, is_osi_approved=True, permissive=True
        ),
        "BSD-3-Clause": LicenseMetadata(
            name="BSD-3-Clause", spdx_id="BSD-3-Clause",
            url="https://opensource.org/licenses/BSD-3-Clause",
            is_fsf_free=True, is_osi_approved=True, permissive=True
        ),
        "GPL-3.0-only": LicenseMetadata(
            name="GPL-3.0-only", spdx_id="GPL-3.0-only",
            url="https://www.gnu.org/licenses/gpl-3.0.html",
            is_fsf_free=True, is_osi_approved=True, copyleft=True
        ),
        "LGPL-2.1-only": LicenseMetadata(
            name="LGPL-2.1-only", spdx_id="LGPL-2.1-only",
            url="https://www.gnu.org/licenses/lgpl-2.1.html",
            is_fsf_free=True, is_osi_approved=True, weak_copyleft=True
        ),
        "MPL-2.0": LicenseMetadata(
            name="MPL-2.0", spdx_id="MPL-2.0",
            url="https://www.mozilla.org/en-US/MPL/2.0/",
            is_fsf_free=True, is_osi_approved=True, weak_copyleft=True
        ),
    }
    
    # Try to load custom database
    if os.path.exists(db_path):
        data = load_json_file(db_path)
        for name, meta in (data.get("licenses") or {}).items():
            try:
                default_db[name] = LicenseMetadata(
                    name=meta.get("name", name),
                    spdx_id=meta.get("spdx_id"),
                    url=meta.get("url"),
                    text_url=meta.get("text_url"),
                    is_fsf_free=bool(meta.get("is_fsf_free")),
                    is_osi_approved=bool(meta.get("is_osi_approved")),
                    copyleft=bool(meta.get("copyleft")),
                    weak_copyleft=bool(meta.get("weak_copyleft")),
                    permissive=bool(meta.get("permissive", True)),
                )
            except (KeyError, TypeError):
                pass
    
    return default_db


def get_license_metadata(license_name: str) -> Optional[LicenseMetadata]:
    """Get metadata for a license name."""
    db = load_license_database()
    
    # Try exact match first
    if license_name in db:
        return db[license_name]
    
    # Try normalized match
    normalized = normalize_license(license_name)
    for meta in db.values():
        if normalize_license(meta.name) == normalized:
            return meta
    
    # Return generic metadata for unknown licenses
    return LicenseMetadata(
        name=license_name or "UNKNOWN",
        spdx_id="UNKNOWN",
        is_fsf_free=False,  # Unknown = potentially risky
        permissive=False,   # Unknown = assume restrictive until proven otherwise
    )


# =============================================================================
# POLICY ENGINE CORE
# =============================================================================

class PolicyEngine:
    """Main policy evaluation engine."""
    
    def __init__(self, 
                 policy_set: Optional[PolicySet] = None,
                 license_db: Optional[Dict[str, LicenseMetadata]] = None):
        self.policy_set = policy_set or PolicySet()
        self.license_db = license_db if license_db is not None else load_license_database()
    
    def set_policy(self, policy_set: PolicySet) -> None:
        """Update the active policy configuration."""
        self.policy_set = policy_set
    
    @contextmanager
    def temporary_policy(self, policy_set: PolicySet):
        """Use a temporary policy within a context block."""
        old = self.policy_set
        try:
            self.set_policy(policy_set)
            yield
        finally:
            self.set_policy(old)
    
    def evaluate_dependency(self, 
                          context: DependencyContext,
                          recursive: bool = True) -> EvaluationResult:
        """Evaluate a single dependency against the policy."""
        
        # Get metadata for this license
        resolved_meta = None
        if context.resolved_license:
            resolved_meta = self.license_db.get(context.resolved_license.name)
        
        # Determine action based on policy rules
        matched_rule = self.policy_set.get_rule_for_license(
            context.license or "UNKNOWN"
        )
        
        # Default action for unknown licenses
        if not matched_rule and not resolved_meta:
            default_action = self.policy_set.defaults.get("unknown_license", PolicyAction.AUDIT)
        elif resolved_meta:
            # Use metadata hints when available
            if resolved_meta.copyleft and not resolved_meta.is_fsf_free:
                default_action = PolicyAction.REVIEW
            else:
                default_action = PolicyAction.ALLOW
        else:
            default_action = PolicyAction.AUDIT
        
        # Override with matched rule if found
        if matched_rule:
            default_action = matched_rule.action
        
        # Check conditions
        conditions_met = self._check_conditions(matched_rule, context)
        
        # Determine final decision
        if not conditions_met and matched_rule:
            action = matched_rule.action
        else:
            action = default_action
        
        # Build message
        messages = []
        if matched_rule:
            messages.append(f"Matched rule: {matched_rule.name}")
        
        if resolved_meta:
            hints = []
            if not resolved_meta.is_fsf_free:
                hints.append("Not FSF Free")
            if not resolved_meta.is_osi_approved:
                hints.append("Not OSI Approved")
            if resolved_meta.copyleft:
                hints.append(f"{'Weak ' if resolved_meta.weak_copyleft else ''}Copyleft")
            
            if hints:
                messages.append(f"License hints: {', '.join(hints)}")
        
        # Create result
        result = EvaluationResult(
            context=context,
            action=action,
            decision=self._get_decision(action),
            message="; ".join(messages) if messages else "",
            matched_rule=matched_rule,
            warnings=[],
        )
        
        # Add warnings for known issues
        self._add_warnings(result, resolved_meta, context)
        
        return result
    
    def _check_conditions(self, rule: Optional[PolicyRule], 
                         context: DependencyContext) -> bool:
        """Check if rule conditions are met."""
        if not rule or not rule.conditions:
            return True
        
        # Check version constraints
        if "version" in rule.conditions:
            constraint = rule.conditions["version"]
            if isinstance(constraint, dict):
                op = constraint.get("operator", "==")
                ver = constraint.get("value")
                
                def compare_versions(v1: str, v2: str) -> int:
                    parts1 = [int(p) for p in v1.split('.')[:3]] + [0] * (4 - len([p for p in v1.split('.')[:3]]))
                    parts2 = [int(p) for p in v2.split('.')[:3]] + [0] * (4 - len([p for p in v2.split('.')[:3]]))
                    
                    # Handle pre-release suffixes
                    if v1.endswith(('a', 'b', 'rc')):
                        parts1[-1] -= 1
                    
                    return (parts1 > parts2) - (parts1 < parts2)
                
                result = compare_versions(context.version, ver)
                if op == "==" and result != 0:
                    return False
                elif op == ">=" and result < 0:
                    return False
                elif op == "<" and result >= 0:
                    return False
        
        # Check scope conditions
        if "scope" in rule.conditions:
            allowed_scopes = set(rule.conditions["scope"])
            if context.scope not in allowed_scopes:
                return False
        
        return True
    
    def _get_decision(self, action: PolicyAction) -> DecisionType:
        """Convert policy action to decision type."""
        mapping = {
            PolicyAction.ALLOW: DecisionType.PASS,
            PolicyAction.BLOCK: DecisionType.FAIL,
            PolicyAction.AUDIT: DecisionType.REVIEW,
            PolicyAction.WARN: DecisionType.WARNING,
            PolicyAction.PROMPT: DecisionType.REVIEW,
        }
        return mapping.get(action, DecisionType.INFO)
    
    def _add_warnings(self, result: EvaluationResult, 
                     meta: Optional[LicenseMetadata],
                     context: DependencyContext) -> None:
        """Add warnings for known issues."""
        
        if not meta:
            result.warnings.append("Unknown license metadata")
            return
        
        # Check for copyleft propagation risk
        if meta.copyleft and context.scope == "direct":
            result.warnings.append(
                f"Direct dependency with copyleft license ({meta.name}) may propagate to your project"
            )
        
        # Check for weak copyleft
        if meta.weak_copyleft:
            result.warnings.append(
                f"Weak copyleft license ({meta.name}) - check integration points"
            )
    
    def evaluate_batch(self, 
                      contexts: List[DependencyContext],
                      recursive: bool = True) -> EvaluationReport:
        """Evaluate multiple dependencies and generate report."""
        
        results: List[EvaluationResult] = []
        summary = {"passed": 0, "failed": 0, "reviewed": 0, "warnings": 0}
        
        for context in contexts:
            result = self.evaluate_dependency(context, recursive)
            results.append(result)