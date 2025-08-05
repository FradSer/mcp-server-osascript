"""
Security Profile System for MCP osascript Server

This module implements a configurable security framework that replaces
hard-coded blocking with flexible, user-controlled security policies.
"""

import logging
import re
from abc import ABC, abstractmethod
from dataclasses import dataclass
from enum import Enum
from typing import Dict, List, Any, Optional, Set
from datetime import datetime

logger = logging.getLogger(__name__)


class RiskLevel(Enum):
    """Risk levels for AppleScript operations."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class SecurityDecision(Enum):
    """Security decisions for script execution."""
    ALLOW = "allow"
    WARN = "warn"
    CONFIRM = "confirm"
    BLOCK = "block"


# Constants for risk scoring
RISK_SCORES = {
    RiskLevel.LOW: 10,
    RiskLevel.MEDIUM: 30,
    RiskLevel.HIGH: 70,
    RiskLevel.CRITICAL: 100
}

# Common patterns used across profiles
DANGEROUS_SYSTEM_PATTERNS = [
    r'\brm\s+-rf\b.*\/\*',      # rm -rf with wildcards
    r'\bformat\b.*\bdisk\b',    # format disk
    r'\bdiskutil\b.*\berase\b', # diskutil erase
    r'\bshutdown\b.*\bnow\b',   # immediate shutdown
]

# TCC trigger scripts for common applications
TCC_TRIGGER_SCRIPTS = {
    "System Events": 'tell application "System Events" to get name of first process',
    "Music": 'tell application "Music" to get player state',
    "Finder": 'tell application "Finder" to get name of desktop',
    "Safari": 'tell application "Safari" to get name of front window',
    "Google Chrome": 'tell application "Google Chrome" to get title of front window'
}


@dataclass
class SecurityResult:
    """Result of security analysis."""
    decision: SecurityDecision
    risk_level: RiskLevel
    risk_score: int  # 0-100
    issues: List[str]
    warnings: List[str]
    metadata: Dict[str, Any]


@dataclass
class SecurityPattern:
    """Security pattern definition."""
    pattern: str
    risk_level: RiskLevel
    description: str
    category: str
    remediation: Optional[str] = None


class PatternRegistry:
    """Centralized registry for security patterns to eliminate duplication."""
    
    @staticmethod
    def get_base_patterns() -> Dict[str, List[SecurityPattern]]:
        """Get the base security patterns used across profiles."""
        return {
            'shell_execution': [
                SecurityPattern(
                    r'\bdo\s+shell\s+script\b',
                    RiskLevel.CRITICAL,
                    "Shell script execution",
                    "shell_execution",
                    "Use AppleScript alternatives or switch to 'balanced' profile"
                ),
            ],
            'system_modification': [
                SecurityPattern(r'\bdelete\b.*\btrash\b', RiskLevel.CRITICAL, "File deletion to trash", "system_modification"),
                SecurityPattern(r'\bempty\s+trash\b', RiskLevel.CRITICAL, "Empty trash operation", "system_modification"),
                SecurityPattern(r'\brm\s+-rf\b', RiskLevel.CRITICAL, "Force file removal", "system_modification"),
                SecurityPattern(r'\bsudo\b', RiskLevel.CRITICAL, "Privileged command execution", "system_modification"),
                SecurityPattern(r'\bkillall\b', RiskLevel.CRITICAL, "Process termination", "system_modification"),
                SecurityPattern(r'\bshutdown\b', RiskLevel.CRITICAL, "System shutdown", "system_modification"),
                SecurityPattern(r'\brestart\b', RiskLevel.CRITICAL, "System restart", "system_modification"),
                SecurityPattern(r'\bformat\b', RiskLevel.CRITICAL, "Disk formatting", "system_modification"),
                SecurityPattern(r'\bfdisk\b', RiskLevel.CRITICAL, "Disk partitioning", "system_modification"),
                SecurityPattern(r'\bdiskutil\b.*\berase\b', RiskLevel.CRITICAL, "Disk erasure", "system_modification"),
            ],
            'ui_automation': [
                SecurityPattern(r'\bkeystroke\b', RiskLevel.HIGH, "Keystroke simulation", "ui_automation"),
                SecurityPattern(r'\bkey\s+code\b', RiskLevel.HIGH, "Key code simulation", "ui_automation"),
                SecurityPattern(r'\bmouse\b', RiskLevel.HIGH, "Mouse control", "ui_automation"),
                SecurityPattern(r'\bclick\b', RiskLevel.HIGH, "Mouse clicking", "ui_automation"),
                SecurityPattern(r'\bSystem\s+Events\b', RiskLevel.HIGH, "System Events access", "ui_automation"),
                SecurityPattern(r'\bUI\s+scripting\b', RiskLevel.HIGH, "UI scripting", "ui_automation"),
                SecurityPattern(r'\bGUI\s+scripting\b', RiskLevel.HIGH, "GUI scripting", "ui_automation"),
            ],
            'app_control': [
                SecurityPattern(r'\bquit\b', RiskLevel.MEDIUM, "Application termination", "app_control"),
                SecurityPattern(r'\blaunch\b', RiskLevel.MEDIUM, "Application launch", "app_control"),
                SecurityPattern(r'\bopen\b.*\bapplication\b', RiskLevel.MEDIUM, "Application opening", "app_control"),
            ]
        }


class SecurityProfile(ABC):
    """Base class for security profiles."""
    
    def __init__(self, name: str):
        self.name = name
        self.patterns = self._load_patterns()
        self._compiled_patterns = self._compile_patterns()
    
    @abstractmethod
    def _load_patterns(self) -> Dict[str, List[SecurityPattern]]:
        """Load security patterns for this profile."""
        pass
    
    def _compile_patterns(self) -> Dict[str, List[tuple]]:
        """Pre-compile regex patterns for better performance."""
        compiled = {}
        for category, patterns in self.patterns.items():
            compiled[category] = []
            for pattern in patterns:
                compiled_regex = re.compile(pattern.pattern, re.IGNORECASE)
                compiled[category].append((compiled_regex, pattern))
        return compiled
    
    @abstractmethod
    def evaluate(self, script: str) -> SecurityResult:
        """Evaluate script security and return decision."""
        pass
    
    def _analyze_patterns(self, script: str) -> Dict[str, Any]:
        """Analyze script against security patterns with optimized matching."""
        found_patterns = []
        risk_scores = []
        
        # Use pre-compiled patterns for better performance
        for category, compiled_patterns in self._compiled_patterns.items():
            for compiled_regex, pattern_obj in compiled_patterns:
                if compiled_regex.search(script):
                    pattern_info = {
                        'pattern': pattern_obj.pattern,
                        'risk_level': pattern_obj.risk_level,
                        'description': pattern_obj.description,
                        'category': category,
                        'remediation': pattern_obj.remediation
                    }
                    found_patterns.append(pattern_info)
                    risk_scores.append(RISK_SCORES[pattern_obj.risk_level])
        
        return {
            'found_patterns': found_patterns,
            'risk_score': max(risk_scores) if risk_scores else 0,
            'pattern_count': len(found_patterns),
            'patterns_by_category': self._group_patterns_by_category(found_patterns)
        }
    
    def _group_patterns_by_category(self, patterns: List[Dict[str, Any]]) -> Dict[str, List[Dict[str, Any]]]:
        """Group patterns by category for better organization."""
        grouped = {}
        for pattern in patterns:
            category = pattern['category']
            if category not in grouped:
                grouped[category] = []
            grouped[category].append(pattern)
        return grouped
    
    def _build_security_result(
        self, 
        decision: SecurityDecision, 
        risk_level: RiskLevel, 
        risk_score: int,
        issues: List[str] = None,
        warnings: List[str] = None,
        metadata: Dict[str, Any] = None
    ) -> SecurityResult:
        """Build a SecurityResult with consistent metadata."""
        return SecurityResult(
            decision=decision,
            risk_level=risk_level,
            risk_score=risk_score,
            issues=issues or [],
            warnings=warnings or [],
            metadata={
                'profile': self.name,
                **(metadata or {})
            }
        )


class StrictSecurityProfile(SecurityProfile):
    """Strict security profile - blocks dangerous operations (legacy behavior)."""
    
    def __init__(self):
        super().__init__("strict")
    
    def _load_patterns(self) -> Dict[str, List[SecurityPattern]]:
        return PatternRegistry.get_base_patterns()
    
    def evaluate(self, script: str) -> SecurityResult:
        analysis = self._analyze_patterns(script)
        patterns = analysis['found_patterns']
        
        # In strict mode, block critical patterns
        critical_patterns = [p for p in patterns if p['risk_level'] == RiskLevel.CRITICAL]
        if critical_patterns:
            return self._build_security_result(
                SecurityDecision.BLOCK,
                RiskLevel.CRITICAL,
                analysis['risk_score'],
                issues=[f"Blocked: {p['description']}" for p in critical_patterns],
                metadata={'patterns': patterns}
            )
        
        # High risk patterns require confirmation
        high_risk_patterns = [p for p in patterns if p['risk_level'] == RiskLevel.HIGH]
        if high_risk_patterns:
            return self._build_security_result(
                SecurityDecision.CONFIRM,
                RiskLevel.HIGH,
                analysis['risk_score'],
                warnings=[f"High risk: {p['description']}" for p in high_risk_patterns],
                metadata={'patterns': patterns}
            )
        
        # Allow with warnings for medium risk
        risk_level = RiskLevel.LOW if analysis['risk_score'] < 30 else RiskLevel.MEDIUM
        medium_patterns = [p for p in patterns if p['risk_level'] == RiskLevel.MEDIUM]
        
        return self._build_security_result(
            SecurityDecision.ALLOW,
            risk_level,
            analysis['risk_score'],
            warnings=[f"Medium risk: {p['description']}" for p in medium_patterns],
            metadata={'patterns': patterns}
        )


class BalancedSecurityProfile(SecurityProfile):
    """Balanced security profile - warns but allows shell execution (recommended)."""
    
    def __init__(self):
        super().__init__("balanced")
    
    def _load_patterns(self) -> Dict[str, List[SecurityPattern]]:
        return PatternRegistry.get_base_patterns()
    
    def evaluate(self, script: str) -> SecurityResult:
        analysis = self._analyze_patterns(script)
        patterns = analysis['found_patterns']
        
        # In balanced mode, only block the most dangerous operations
        for pattern in DANGEROUS_SYSTEM_PATTERNS:
            if re.search(pattern, script, re.IGNORECASE):
                return self._build_security_result(
                    SecurityDecision.BLOCK,
                    RiskLevel.CRITICAL,
                    100,
                    issues=[f"Extremely dangerous operation blocked: {pattern}"],
                    metadata={'blocked_pattern': pattern}
                )
        
        # High risk gets warning but is allowed
        if analysis['risk_score'] > 70:
            return self._build_security_result(
                SecurityDecision.WARN,
                RiskLevel.HIGH,
                analysis['risk_score'],
                warnings=[f"High risk operation: {p['description']}" for p in patterns],
                metadata={'patterns': patterns}
            )
        
        # Everything else is allowed with audit
        risk_level = RiskLevel.LOW if analysis['risk_score'] < 30 else RiskLevel.MEDIUM
        return self._build_security_result(
            SecurityDecision.ALLOW,
            risk_level,
            analysis['risk_score'],
            warnings=[f"Audit: {p['description']}" for p in patterns],
            metadata={'patterns': patterns}
        )


class PermissiveSecurityProfile(SecurityProfile):
    """Permissive security profile - audit only, minimal blocking."""
    
    def __init__(self):
        super().__init__("permissive")
    
    def _load_patterns(self) -> Dict[str, List[SecurityPattern]]:
        # Minimal pattern set for auditing
        return {
            'audit_only': [
                SecurityPattern(
                    r'\bdo\s+shell\s+script\b',
                    RiskLevel.MEDIUM,
                    "Shell script execution (audited)",
                    "audit_only"
                ),
                SecurityPattern(
                    r'\bsudo\b',
                    RiskLevel.HIGH,
                    "Privileged execution (audited)",
                    "audit_only"
                ),
            ]
        }
    
    def evaluate(self, script: str) -> SecurityResult:
        analysis = self._analyze_patterns(script)
        
        # Only block absolute disasters
        if re.search(r'\brm\s+-rf\s+/\s*$', script, re.IGNORECASE):
            return SecurityResult(
                decision=SecurityDecision.BLOCK,
                risk_level=RiskLevel.CRITICAL,
                risk_score=100,
                issues=["Prevented system-destroying command"],
                warnings=[],
                metadata={'profile': self.name, 'disaster_prevented': True}
            )
        
        # Everything else is allowed with audit
        return SecurityResult(
            decision=SecurityDecision.ALLOW,
            risk_level=RiskLevel.LOW,
            risk_score=analysis['risk_score'],
            issues=[],
            warnings=[],
            metadata={
                'profile': self.name, 
                'audit_log': [p['description'] for p in analysis['found_patterns']]
            }
        )


class SecurityProfileManager:
    """Manages security profiles and provides evaluation interface."""
    
    def __init__(self):
        self.profiles = {
            'strict': StrictSecurityProfile(),
            'balanced': BalancedSecurityProfile(),
            'permissive': PermissiveSecurityProfile(),
        }
        self.default_profile = 'balanced'  # Changed from strict for better UX
        self.audit_log = []
    
    def evaluate_script(
        self, 
        script: str, 
        profile_name: Optional[str] = None
    ) -> SecurityResult:
        """Evaluate script security using specified or default profile."""
        profile_name = profile_name or self.default_profile
        profile = self.profiles.get(profile_name)
        
        if not profile:
            # Fallback to strict if unknown profile
            profile = self.profiles['strict']
            logger.warning(f"Unknown security profile '{profile_name}', falling back to strict")
        
        result = profile.evaluate(script)
        
        # Log for audit trail
        self._log_evaluation(script, profile_name, result)
        
        return result
    
    def _log_evaluation(self, script: str, profile_name: str, result: SecurityResult):
        """Log security evaluation for audit trail."""
        log_entry = {
            'timestamp': datetime.now().isoformat(),
            'profile': profile_name,
            'decision': result.decision.value,
            'risk_level': result.risk_level.value,
            'risk_score': result.risk_score,
            'script_hash': hash(script),  # Don't log full script for privacy
            'issues_count': len(result.issues),
            'warnings_count': len(result.warnings)
        }
        
        self.audit_log.append(log_entry)
        
        # Keep audit log manageable
        if len(self.audit_log) > 1000:
            self.audit_log = self.audit_log[-500:]  # Keep last 500 entries
        
        logger.info(f"Security evaluation: {log_entry}")
    
    def get_profile_info(self, profile_name: str) -> Dict[str, Any]:
        """Get information about a security profile."""
        profile = self.profiles.get(profile_name)
        if not profile:
            return {'error': f'Unknown profile: {profile_name}'}
        
        pattern_summary = {}
        for category, patterns in profile.patterns.items():
            pattern_summary[category] = {
                'count': len(patterns),
                'risk_levels': [p.risk_level.value for p in patterns]
            }
        
        return {
            'name': profile.name,
            'pattern_categories': list(profile.patterns.keys()),
            'pattern_summary': pattern_summary,
            'total_patterns': sum(len(patterns) for patterns in profile.patterns.values())
        }
    
    def list_profiles(self) -> Dict[str, Any]:
        """List all available security profiles."""
        return {
            name: self.get_profile_info(name) 
            for name in self.profiles.keys()
        }