"""
Simplified response handling for MCP osascript server.
"""

from datetime import datetime
from typing import Dict, Any, List, Optional


class ResponseBuilder:
    """Unified response builder for all API responses."""
    
    @staticmethod
    def _base_response(status: str, **kwargs) -> Dict[str, Any]:
        """Create base response with timestamp."""
        return {
            'status': status,
            'timestamp': datetime.now().isoformat(),
            **kwargs
        }
    
    @staticmethod
    def success(data: Dict[str, Any] = None, **kwargs) -> Dict[str, Any]:
        """Build success response."""
        result = ResponseBuilder._base_response('success', **kwargs)
        if data:
            result['data'] = data
        return result
    
    @staticmethod
    def error(error_type: str, message: str, details: Dict[str, Any] = None, **kwargs) -> Dict[str, Any]:
        """Build error response."""
        error_data = {'type': error_type, 'message': message}
        if details:
            error_data['details'] = details
        return ResponseBuilder._base_response('error', error=error_data, **kwargs)
    
    @staticmethod
    def warning(message: str, data: Dict[str, Any] = None, **kwargs) -> Dict[str, Any]:
        """Build warning response."""
        result = ResponseBuilder._base_response('warning', message=message, **kwargs)
        if data:
            result['data'] = data
        return result


    @staticmethod  
    def execution_success(stdout: str = "", stderr: str = "", execution_time: float = None,
                         security_info: Dict[str, Any] = None, **kwargs) -> Dict[str, Any]:
        """Build execution success response."""
        data = {'stdout': stdout, 'stderr': stderr}
        if execution_time is not None:
            data['execution_time'] = execution_time
        
        result = ResponseBuilder.success(data=data, **kwargs)
        if security_info:
            result['security'] = security_info
        return result
    
    @staticmethod
    def security_block(security_result, reason: str = "Script blocked by security policy") -> Dict[str, Any]:
        """Build security block response."""
        return ResponseBuilder.error(
            'SECURITY_POLICY_VIOLATION', reason,
            details={
                'risk_level': security_result.risk_level.value,
                'risk_score': security_result.risk_score,
                'issues': security_result.issues,
                'profile': security_result.metadata.get('profile')
            }
        )
    
    @staticmethod
    def execution_error(error_type: str, message: str, stdout: str = "", stderr: str = "", **kwargs) -> Dict[str, Any]:
        """Build execution error response."""
        return ResponseBuilder.error(error_type, message, 
                                   details={'stdout': stdout, 'stderr': stderr, **kwargs})
    
    @staticmethod
    def timeout_error(timeout: int) -> Dict[str, Any]:
        """Build timeout error response."""
        return ResponseBuilder.error('TIMEOUT', f"Script execution timed out after {timeout} seconds")
    
    @staticmethod
    def system_error(error_message: str, **kwargs) -> Dict[str, Any]:
        """Build system error response."""
        return ResponseBuilder.error('SYSTEM_ERROR', f"System error: {error_message}", details=kwargs)


    @staticmethod
    def analysis_response(security_result, script_length: int, security_profile: str) -> Dict[str, Any]:
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
            },
            'execution_guidance': {
                'safe_to_execute': security_result.decision.value in ['allow', 'warn'],
                'blocked': security_result.decision.value == 'block'
            }
        }
        
        return ResponseBuilder.success(
            data=data,
            metadata={
                'security_profile_used': security_profile,
                'script_length': script_length,
                'dry_run': True
            }
        )


    @staticmethod
    def profiles_list(profiles_info: Dict[str, Any]) -> Dict[str, Any]:
        """Build response for listing security profiles."""
        return ResponseBuilder.success(data={'available_profiles': profiles_info})
    
    @staticmethod
    def profile_changed(old_profile: str, new_profile: str) -> Dict[str, Any]:
        """Build response for profile change confirmation."""
        return ResponseBuilder.success(
            data={
                'message': f"Profile changed from '{old_profile}' to '{new_profile}'",
                'previous_profile': old_profile,
                'new_profile': new_profile
            }
        )
    
    @staticmethod
    def invalid_profile(provided_profile: str, available_profiles: List[str]) -> Dict[str, Any]:
        """Build response for invalid profile error."""
        return ResponseBuilder.error(
            'INVALID_PROFILE',
            f"Unknown security profile: {provided_profile}",
            details={'provided_profile': provided_profile, 'available_profiles': available_profiles}
        )
    
    @staticmethod
    def empty_script_error(provided_script: str) -> Dict[str, Any]:
        """Build error response for empty script."""
        return ResponseBuilder.error('EMPTY_SCRIPT', 'Script cannot be empty', 
                                   details={'provided_script': provided_script})