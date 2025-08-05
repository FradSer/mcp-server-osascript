"""
Script execution engine for MCP osascript server.

This module handles the actual execution of AppleScript and JavaScript
code through osascript, with comprehensive error handling and timeout management.
"""

import logging
import subprocess
from datetime import datetime
from typing import Dict, Any

from .responses import ExecutionResponseBuilder
from .permissions import parse_tcc_error

logger = logging.getLogger(__name__)


class ScriptExecutor:
    """Handles osascript execution with proper error handling and timeouts."""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
    
    def execute_direct(self, script: str, timeout: int = 20) -> Dict[str, Any]:
        """
        Execute AppleScript directly with comprehensive error handling.
        
        Args:
            script: The AppleScript code to execute
            timeout: Timeout in seconds
            
        Returns:
            Dictionary with execution results
        """
        try:
            cmd = ['osascript', '-e', script]
            self.logger.info(f"Executing osascript command: {' '.join(cmd[:2])}...")
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout
            )
            
            return self._process_execution_result(result)
            
        except subprocess.TimeoutExpired:
            self.logger.warning(f"Script execution timed out after {timeout} seconds")
            return ExecutionResponseBuilder.timeout_error(timeout)
            
        except Exception as e:
            self.logger.error(f"Unexpected error during script execution: {e}")
            return ExecutionResponseBuilder.system_error(str(e))
    
    def _process_execution_result(self, result: subprocess.CompletedProcess) -> Dict[str, Any]:
        """Process subprocess result and return appropriate response."""
        if result.returncode == 0:
            return self._build_success_response(result.stdout, result.stderr)
        
        # Handle TCC errors specially
        tcc_error = parse_tcc_error(result.stderr)
        if tcc_error:
            return self._build_tcc_error_response(tcc_error, result)
        
        # Handle general execution errors
        return ExecutionResponseBuilder.execution_error(
            'EXECUTION_FAILED',
            f"osascript exited with code {result.returncode}",
            stdout=result.stdout,
            stderr=result.stderr
        )
    
    def _build_success_response(self, stdout: str, stderr: str) -> Dict[str, Any]:
        """Build success response with output."""
        return {
            'status': 'success',
            'stdout': stdout,
            'stderr': stderr
        }
    
    def _build_tcc_error_response(
        self, 
        tcc_error: Dict[str, str], 
        result: subprocess.CompletedProcess
    ) -> Dict[str, Any]:
        """Build TCC error response with additional context."""
        return {
            'status': 'error',
            **tcc_error,
            'stdout': result.stdout,
            'stderr': result.stderr
        }


class SecurityAwareExecutor:
    """Executor that integrates security checks with script execution."""
    
    def __init__(self, security_manager, permission_handler=None):
        self.security_manager = security_manager
        self.permission_handler = permission_handler
        self.executor = ScriptExecutor()
        self.logger = logging.getLogger(__name__)
    
    def execute_with_security(
        self, 
        script: str, 
        timeout: int = 20, 
        security_profile: str = None
    ) -> Dict[str, Any]:
        """
        Execute script with security evaluation and permission handling.
        
        Args:
            script: The script to execute
            timeout: Execution timeout in seconds
            security_profile: Security profile to use
            
        Returns:
            Dictionary with execution results and security metadata
        """
        # Evaluate security first
        security_result = self.security_manager.evaluate_script(script, security_profile)
        
        # Handle security decisions
        security_decision = self._handle_security_decision(script, security_result)
        if security_decision:
            return security_decision
        
        # Execute the script
        self.logger.info(f"Executing AppleScript with {security_result.metadata.get('profile', 'default')} security profile")
        execution_result = self.executor.execute_direct(script, timeout)
        
        # Handle automatic permissions if enabled and handler available
        if self.permission_handler and self._should_handle_permissions(execution_result):
            execution_result = self.permission_handler.auto_handle_permissions(execution_result)
        
        # Add security metadata to successful results
        return self._add_security_metadata(execution_result, security_result)
    
    def _handle_security_decision(self, script: str, security_result) -> Dict[str, Any]:
        """Handle security decision (block/confirm), returns None if execution should proceed."""
        from .security import SecurityDecision
        from .ui import get_user_confirmation_enhanced
        
        if security_result.decision == SecurityDecision.BLOCK:
            return ExecutionResponseBuilder.security_block(
                security_result,
                'Script blocked by security policy'
            )
        
        elif security_result.decision == SecurityDecision.CONFIRM:
            if not get_user_confirmation_enhanced(script, security_result):
                return ExecutionResponseBuilder.security_block(
                    security_result,
                    'User cancelled risky operation'
                )
        
        return None  # Proceed with execution
    
    def _should_handle_permissions(self, execution_result: Dict[str, Any]) -> bool:
        """Check if automatic permission handling should be attempted."""
        return execution_result.get('status') == 'error'
    
    def _add_security_metadata(self, execution_result: Dict[str, Any], security_result) -> Dict[str, Any]:
        """Add security metadata to execution result."""
        if execution_result.get('status') == 'success':
            execution_result['security'] = {
                'profile': security_result.metadata.get('profile'),
                'risk_level': security_result.risk_level.value,
                'risk_score': security_result.risk_score,
                'warnings': security_result.warnings,
                'audit_patterns': [
                    p.get('description') for p in security_result.metadata.get('patterns', [])
                ]
            }
        return execution_result


class AnalysisEngine:
    """Engine for security analysis without execution (dry-run mode)."""
    
    def __init__(self, security_manager):
        self.security_manager = security_manager
        self.logger = logging.getLogger(__name__)
    
    def analyze_script(self, script: str, security_profile: str) -> Dict[str, Any]:
        """
        Perform comprehensive security analysis without execution.
        
        Args:
            script: Script to analyze
            security_profile: Security profile to use for analysis
            
        Returns:
            Detailed analysis response
        """
        if not script or not script.strip():
            from .responses import PermissionResponseBuilder
            return PermissionResponseBuilder.empty_script_error(script)
        
        try:
            security_result = self.security_manager.evaluate_script(script, security_profile)
            
            from .responses import SecurityResponseBuilder
            return SecurityResponseBuilder.analysis_response(
                security_result,
                len(script),
                security_profile
            )
            
        except Exception as e:
            self.logger.error(f"Error during security analysis: {e}")
            from .responses import StandardResponse
            return StandardResponse.error(
                'ANALYSIS_ERROR',
                'Failed to analyze script',
                details={'error_message': str(e)}
            )


class ExecutionManager:
    """High-level execution manager that coordinates all execution components."""
    
    def __init__(self, security_manager, permission_handler=None):
        self.security_executor = SecurityAwareExecutor(security_manager, permission_handler)
        self.analysis_engine = AnalysisEngine(security_manager)
        self.logger = logging.getLogger(__name__)
    
    def execute_or_analyze(
        self,
        script: str,
        timeout: int = 30,
        security_profile: str = "balanced",
        enable_auto_permissions: bool = True,
        dry_run: bool = False
    ) -> Dict[str, Any]:
        """
        Execute or analyze script based on parameters.
        
        Args:
            script: Script to execute or analyze
            timeout: Execution timeout (ignored for dry_run)
            security_profile: Security profile to use
            enable_auto_permissions: Whether to enable automatic permission handling
            dry_run: If True, only analyze without executing
            
        Returns:
            Execution or analysis results
        """
        start_time = datetime.now()
        
        try:
            if dry_run:
                self.logger.info(f"Analyzing AppleScript security with {security_profile} profile")
                return self.analysis_engine.analyze_script(script, security_profile)
            
            self.logger.info(f"Executing AppleScript with {security_profile} security profile")
            
            # Configure permission handling
            if not enable_auto_permissions:
                self.security_executor.permission_handler = None
            
            result = self.security_executor.execute_with_security(
                script, timeout, security_profile
            )
            
            # Enhance successful results with timing and metadata
            if result.get('status') == 'success':
                result = self._enhance_success_result(
                    result, start_time, security_profile, enable_auto_permissions, len(script)
                )
            
            return result
            
        except Exception as e:
            self.logger.error(f"Unexpected error during execution management: {e}")
            return ExecutionResponseBuilder.system_error(
                f"Unexpected system error during execution: {str(e)}",
                execution_time=(datetime.now() - start_time).total_seconds()
            )
    
    def _enhance_success_result(
        self,
        result: Dict[str, Any],
        start_time: datetime,
        security_profile: str,
        enable_auto_permissions: bool,
        script_length: int
    ) -> Dict[str, Any]:
        """Enhance successful execution result with additional metadata."""
        from .responses import ExecutionResponseBuilder
        
        return ExecutionResponseBuilder.success_with_output(
            stdout=result.get('stdout', ''),
            stderr=result.get('stderr', ''),
            execution_time=(datetime.now() - start_time).total_seconds(),
            security_info=result.get('security', {}),
            metadata={
                'security_profile': security_profile,
                'auto_permissions': enable_auto_permissions,
                'script_length': script_length,
                'execution_timestamp': start_time.isoformat()
            }
        )