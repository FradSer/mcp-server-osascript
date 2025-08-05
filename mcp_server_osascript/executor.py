"""
Simplified execution engine for MCP osascript server.
"""

import logging
import subprocess
from datetime import datetime
from typing import Dict, Any

from .responses import ResponseBuilder
from .permissions import parse_tcc_error

logger = logging.getLogger(__name__)


class ScriptExecutor:
    """Simplified script executor."""
    
    def execute(self, script: str, timeout: int = 20) -> Dict[str, Any]:
        """Execute AppleScript with error handling."""
        try:
            result = subprocess.run(
                ['osascript', '-e', script],
                capture_output=True, text=True, timeout=timeout
            )
            return self._process_result(result)
        except subprocess.TimeoutExpired:
            return ResponseBuilder.error('TIMEOUT', f"Execution timed out after {timeout} seconds")
        except Exception as e:
            return ResponseBuilder.error('SYSTEM_ERROR', f"System error: {str(e)}")
    
    def _process_result(self, result: subprocess.CompletedProcess) -> Dict[str, Any]:
        """Process execution result."""
        if result.returncode == 0:
            return ResponseBuilder.success({'stdout': result.stdout, 'stderr': result.stderr})
        
        tcc_error = parse_tcc_error(result.stderr)
        if tcc_error:
            return ResponseBuilder.error('TCC_ERROR', 'Permission required', 
                                       details={'stdout': result.stdout, 'stderr': result.stderr})
        
        return ResponseBuilder.error('EXECUTION_FAILED', f"osascript failed with code {result.returncode}",
                                   details={'stdout': result.stdout, 'stderr': result.stderr})


class ExecutionManager:
    """Unified execution manager with security integration."""
    
    def __init__(self, security_manager, permission_handler=None):
        self.security_manager = security_manager
        self.permission_handler = permission_handler
        self.executor = ScriptExecutor()
    
    def execute_or_analyze(self, script: str, timeout: int = 30, security_profile: str = "balanced",
                          enable_auto_permissions: bool = True, dry_run: bool = False) -> Dict[str, Any]:
        """Execute script with security checks or analyze only."""
        if not script.strip():
            return ResponseBuilder.error('EMPTY_SCRIPT', 'Script cannot be empty')
        
        # Security evaluation
        security_result = self.security_manager.evaluate_script(script, security_profile)
        
        if dry_run:
            return self._build_analysis_response(security_result, len(script), security_profile)
        
        # Check security decision
        from .security import SecurityDecision
        if security_result.decision == SecurityDecision.BLOCK:
            return ResponseBuilder.error('SECURITY_POLICY_VIOLATION', 'Script blocked by security policy',
                                       details={'risk_level': security_result.risk_level.value,
                                               'issues': security_result.issues})
        
        # Execute script
        start_time = datetime.now()
        result = self.executor.execute(script, timeout)
        
        # Handle permissions if needed
        if (enable_auto_permissions and self.permission_handler and 
            result.get('status') == 'error'):
            result = self.permission_handler.auto_handle_permissions(result)
        
        # Add metadata to successful results
        if result.get('status') == 'success':
            result['execution_time'] = (datetime.now() - start_time).total_seconds()
            result['security'] = {
                'profile': security_profile,
                'risk_level': security_result.risk_level.value,
                'warnings': security_result.warnings
            }
        
        return result
    
    def _build_analysis_response(self, security_result, script_length: int, security_profile: str) -> Dict[str, Any]:
        """Build security analysis response."""
        data = {
            'risk_assessment': {
                'decision': security_result.decision.value,
                'risk_level': security_result.risk_level.value,
                'risk_score': security_result.risk_score
            },
            'security_findings': {
                'issues': security_result.issues,
                'warnings': security_result.warnings
            }
        }
        return ResponseBuilder.success(data=data, metadata={'security_profile_used': security_profile, 'dry_run': True})


