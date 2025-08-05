"""
Security Profile System for MCP osascript Server

This module implements a configurable security framework that replaces
hard-coded blocking with flexible, user-controlled security policies.
"""

import logging
import re
from dataclasses import dataclass
from enum import Enum
from typing import Dict, List, Any, Optional

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


# Risk scoring and patterns
RISK_SCORES = {RiskLevel.LOW: 10, RiskLevel.MEDIUM: 30, RiskLevel.HIGH: 70, RiskLevel.CRITICAL: 100}

CRITICAL_PATTERNS = [
    r'\brm\s+-rf\b.*\/\*', r'\bformat\b.*\bdisk\b', r'\bdiskutil\b.*\berase\b', 
    r'\bshutdown\b.*\bnow\b', r'\bdo\s+shell\s+script\b', r'\bsudo\b', r'\bkillall\b'
]

HIGH_RISK_PATTERNS = [
    r'\bkeystroke\b', r'\bkey\s+code\b', r'\bmouse\b', r'\bclick\b', r'\bSystem\s+Events\b'
]

MEDIUM_RISK_PATTERNS = [
    r'\bquit\b', r'\blaunch\b', r'\bopen\b.*\bapplication\b'
]


@dataclass
class SecurityResult:
    """Result of security analysis."""
    decision: SecurityDecision
    risk_level: RiskLevel
    risk_score: int  # 0-100
    issues: List[str]
    warnings: List[str]
    metadata: Dict[str, Any]


def analyze_script_patterns(script: str) -> Dict[str, Any]:
    """Analyze script against security patterns."""
    issues = []
    warnings = []
    risk_score = 0
    
    for pattern in CRITICAL_PATTERNS:
        if re.search(pattern, script, re.IGNORECASE):
            issues.append(f"Critical pattern detected: {pattern}")
            risk_score = max(risk_score, RISK_SCORES[RiskLevel.CRITICAL])
    
    for pattern in HIGH_RISK_PATTERNS:
        if re.search(pattern, script, re.IGNORECASE):
            warnings.append(f"High risk pattern detected: {pattern}")
            risk_score = max(risk_score, RISK_SCORES[RiskLevel.HIGH])
    
    for pattern in MEDIUM_RISK_PATTERNS:
        if re.search(pattern, script, re.IGNORECASE):
            warnings.append(f"Medium risk pattern detected: {pattern}")
            risk_score = max(risk_score, RISK_SCORES[RiskLevel.MEDIUM])
    
    return {'issues': issues, 'warnings': warnings, 'risk_score': risk_score}


class SecurityProfile:
    """Base security profile with simplified evaluation."""
    
    def __init__(self, name: str):
        self.name = name
    
    def evaluate(self, script: str) -> SecurityResult:
        """Evaluate script security and return decision."""
        analysis = analyze_script_patterns(script)
        return self._make_decision(analysis)
    
    def _make_decision(self, analysis: Dict[str, Any]) -> SecurityResult:
        """Make security decision based on analysis."""
        pass
    
    def _build_result(self, decision: SecurityDecision, risk_level: RiskLevel, 
                     issues: List[str], warnings: List[str], risk_score: int) -> SecurityResult:
        """Build security result."""
        return SecurityResult(
            decision=decision, risk_level=risk_level, risk_score=risk_score,
            issues=issues, warnings=warnings, metadata={'profile': self.name}
        )


class StrictSecurityProfile(SecurityProfile):
    """Strict security profile - blocks dangerous operations."""
    
    def __init__(self):
        super().__init__("strict")
    
    def _make_decision(self, analysis: Dict[str, Any]) -> SecurityResult:
        issues, warnings, risk_score = analysis['issues'], analysis['warnings'], analysis['risk_score']
        
        if issues:  # Critical patterns found
            return self._build_result(SecurityDecision.BLOCK, RiskLevel.CRITICAL, issues, warnings, risk_score)
        elif risk_score >= RISK_SCORES[RiskLevel.HIGH]:
            return self._build_result(SecurityDecision.CONFIRM, RiskLevel.HIGH, issues, warnings, risk_score)
        else:
            risk_level = RiskLevel.MEDIUM if risk_score >= RISK_SCORES[RiskLevel.MEDIUM] else RiskLevel.LOW
            return self._build_result(SecurityDecision.ALLOW, risk_level, issues, warnings, risk_score)


class BalancedSecurityProfile(SecurityProfile):
    """Balanced security profile - warns but allows most operations."""
    
    def __init__(self):
        super().__init__("balanced")
    
    def _make_decision(self, analysis: Dict[str, Any]) -> SecurityResult:
        issues, warnings, risk_score = analysis['issues'], analysis['warnings'], analysis['risk_score']
        
        if risk_score >= RISK_SCORES[RiskLevel.HIGH]:
            return self._build_result(SecurityDecision.WARN, RiskLevel.HIGH, issues, warnings, risk_score)
        else:
            risk_level = RiskLevel.MEDIUM if risk_score >= RISK_SCORES[RiskLevel.MEDIUM] else RiskLevel.LOW
            return self._build_result(SecurityDecision.ALLOW, risk_level, issues, warnings, risk_score)


class PermissiveSecurityProfile(SecurityProfile):
    """Permissive security profile - minimal blocking."""
    
    def __init__(self):
        super().__init__("permissive")
    
    def _make_decision(self, analysis: Dict[str, Any]) -> SecurityResult:
        # Everything is allowed in permissive mode
        return self._build_result(SecurityDecision.ALLOW, RiskLevel.LOW, [], [], 
                                analysis.get('risk_score', 0))


class SecurityProfileManager:
    """Simplified security profile manager."""
    
    def __init__(self):
        self.profiles = {
            'strict': StrictSecurityProfile(),
            'balanced': BalancedSecurityProfile(),
            'permissive': PermissiveSecurityProfile(),
        }
        self.default_profile = 'balanced'
    
    def evaluate_script(self, script: str, profile_name: Optional[str] = None) -> SecurityResult:
        """Evaluate script security using specified or default profile."""
        profile_name = profile_name or self.default_profile
        profile = self.profiles.get(profile_name, self.profiles['strict'])
        
        if profile_name not in self.profiles:
            logger.warning(f"Unknown security profile '{profile_name}', using strict")
        
        return profile.evaluate(script)
    
    def get_profile_info(self, profile_name: str) -> Dict[str, Any]:
        """Get basic profile information."""
        if profile_name not in self.profiles:
            return {'error': f'Unknown profile: {profile_name}'}
        return {'name': profile_name}
    
    def list_profiles(self) -> Dict[str, Any]:
        """List available profiles."""
        return {name: {'name': name} for name in self.profiles.keys()}