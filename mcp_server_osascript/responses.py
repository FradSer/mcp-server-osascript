"""
Standardized response handling module for MCP osascript server.

This module provides consistent response formatting and error handling
across all server operations, eliminating duplicated response building logic.
"""

from datetime import datetime
from typing import Dict, Any, List, Optional


class StandardResponse:
    """Standardized response builder for consistent API responses."""
    
    @staticmethod
    def success(data: Dict[str, Any] = None, **kwargs) -> Dict[str, Any]:
        """Build standardized success response."""
        result = {
            'status': 'success',
            'timestamp': datetime.now().isoformat()
        }
        if data:
            result['data'] = data
        result.update(kwargs)
        return result
    
    @staticmethod
    def error(error_type: str, message: str, details: Dict[str, Any] = None, **kwargs) -> Dict[str, Any]:
        """Build standardized error response."""
        result = {
            'status': 'error',
            'error': {
                'type': error_type,
                'message': message,
                'timestamp': datetime.now().isoformat()
            }
        }
        if details:
            result['error']['details'] = details
        result.update(kwargs)
        return result
    
    @staticmethod
    def warning(message: str, data: Dict[str, Any] = None, **kwargs) -> Dict[str, Any]:
        """Build standardized warning response."""
        result = {
            'status': 'warning',
            'message': message,
            'timestamp': datetime.now().isoformat()
        }
        if data:
            result['data'] = data
        result.update(kwargs)  
        return result


class ExecutionResponseBuilder:
    """Builder for execution-specific responses with security metadata."""
    
    @staticmethod
    def success_with_output(
        stdout: str = "", 
        stderr: str = "", 
        execution_time: float = None,
        security_info: Dict[str, Any] = None,
        **kwargs
    ) -> Dict[str, Any]:
        """Build success response with execution output."""
        data = {
            'stdout': stdout,
            'stderr': stderr
        }
        
        if execution_time is not None:
            data['execution_time'] = execution_time
            
        result = StandardResponse.success(data=data, **kwargs)
        
        if security_info:
            result['security'] = security_info
            
        return result
    
    @staticmethod
    def security_block(
        security_result, 
        reason: str = "Script blocked by security policy",
        suggestions: List[str] = None
    ) -> Dict[str, Any]:
        """Build security block response with detailed information."""
        return StandardResponse.error(
            'SECURITY_POLICY_VIOLATION',
            reason,
            details={
                'security_analysis': SecurityResponseBuilder.extract_security_info(security_result),
                'suggestions': suggestions or [],
                'alternative_security_profiles': SecurityResponseBuilder.get_alternative_profiles(security_result)
            }
        )
    
    @staticmethod
    def execution_error(
        error_type: str,
        message: str,
        stdout: str = "",
        stderr: str = "",
        **kwargs
    ) -> Dict[str, Any]:
        """Build execution error response with output."""
        return StandardResponse.error(
            error_type,
            message,
            details={
                'stdout': stdout,
                'stderr': stderr,
                **kwargs
            }
        )
    
    @staticmethod
    def timeout_error(timeout: int) -> Dict[str, Any]:
        """Build timeout error response."""
        return StandardResponse.error(
            'TIMEOUT',
            f"Script execution timed out after {timeout} seconds"
        )
    
    @staticmethod
    def system_error(error_message: str, **kwargs) -> Dict[str, Any]:
        """Build system error response."""
        return StandardResponse.error(
            'SYSTEM_ERROR',
            f"System error: {error_message}",
            details=kwargs
        )


class SecurityResponseBuilder:
    """Builder for security-related responses."""
    
    @staticmethod
    def extract_security_info(security_result) -> Dict[str, Any]:
        """Extract security information for response."""
        return {
            'profile': security_result.metadata.get('profile'),
            'risk_level': security_result.risk_level.value,
            'risk_score': security_result.risk_score,
            'issues': security_result.issues,
            'warnings': security_result.warnings,
            'decision': security_result.decision.value
        }
    
    @staticmethod
    def get_alternative_profiles(security_result) -> List[str]:
        """Get alternative security profiles based on current profile."""
        current_profile = security_result.metadata.get('profile')
        if current_profile == 'strict':
            return ['balanced', 'permissive']
        elif current_profile == 'balanced':
            return ['permissive']
        else:
            return []
    
    @staticmethod
    def analysis_response(
        security_result,
        script_length: int,
        security_profile: str
    ) -> Dict[str, Any]:
        """Build comprehensive security analysis response."""
        analysis_data = {
            'risk_assessment': {
                'decision': security_result.decision.value,
                'risk_level': security_result.risk_level.value,
                'risk_score': security_result.risk_score,
                'confidence': 'high' if security_result.risk_score > 50 else 'medium'
            },
            'security_findings': {
                'issues_found': len(security_result.issues),
                'warnings_found': len(security_result.warnings),
                'patterns_detected': len(security_result.metadata.get('patterns', [])),
                'critical_issues': security_result.issues,
                'warnings': security_result.warnings
            },
            'recommendations': SecurityResponseBuilder._get_security_recommendations(security_result),
            'execution_guidance': {
                'safe_to_execute': security_result.decision.value in ['allow', 'warn'],
                'requires_confirmation': security_result.decision.value == 'confirm',
                'blocked': security_result.decision.value == 'block',
                'suggested_security_profile': SecurityResponseBuilder._suggest_security_level(security_result)
            }
        }
        
        # Add educational information for high-risk scripts
        if security_result.risk_score > 70:
            analysis_data['educational_info'] = SecurityResponseBuilder._get_educational_info(security_result)
        
        return StandardResponse.success(
            data=analysis_data,
            metadata={
                'analysis_timestamp': datetime.now().isoformat(),
                'security_profile_used': security_profile,
                'script_length': script_length,
                'analysis_version': '2.0',
                'dry_run': True
            }
        )
    
    @staticmethod
    def _get_security_recommendations(security_result) -> List[str]:
        """Generate security recommendations based on analysis."""
        recommendations = []
        
        if security_result.risk_score > 70:
            recommendations.append("Consider reviewing the script carefully before execution")
        
        patterns = security_result.metadata.get('patterns', [])
        if any('shell' in pattern.get('category', '') for pattern in patterns):
            recommendations.append("Shell script execution detected - ensure commands are safe")
        
        if security_result.decision.value == 'block':
            recommendations.append("Switch to 'balanced' or 'permissive' profile if this script is legitimate")
        
        critical_patterns = [p for p in patterns if p.get('risk_level') == 'critical']
        if critical_patterns:
            recommendations.append("Critical security patterns detected - verify script source")
        
        return recommendations
    
    @staticmethod
    def _suggest_security_level(security_result) -> str:
        """Suggest appropriate security level based on risk analysis."""
        if security_result.risk_score >= 90:
            return "strict"
        elif security_result.risk_score >= 50:
            return "balanced"  
        else:
            return "permissive"
    
    @staticmethod
    def _get_educational_info(security_result) -> Dict[str, Any]:
        """Get educational information for high-risk scripts."""
        return {
            'why_risky': f"This script has a risk score of {security_result.risk_score}/100",
            'common_risks': [
                'May execute system commands',
                'Could modify files or system settings', 
                'Might access sensitive applications',
                'Could perform automation that affects other apps'
            ],
            'safety_tips': [
                'Review the script code carefully',
                'Ensure you trust the script source',  
                'Test with non-critical data first',
                'Consider using a more restrictive security profile'
            ]
        }


class ProfileResponseBuilder:
    """Builder for security profile management responses."""
    
    @staticmethod
    def profiles_list(profiles_info: Dict[str, Any], usage_stats: Dict[str, Any]) -> Dict[str, Any]:
        """Build response for listing security profiles."""
        return StandardResponse.success(
            data={
                'available_profiles': profiles_info,
                'usage_statistics': usage_stats,
                'recommendations': {
                    'strict': 'For maximum security with potentially dangerous scripts',
                    'balanced': 'Recommended default for most use cases', 
                    'permissive': 'For trusted scripts requiring full system access'
                }
            },
            metadata={
                'query_timestamp': datetime.now().isoformat(),
                'profiles_count': len(profiles_info)
            }
        )
    
    @staticmethod
    def profile_changed(old_profile: str, new_profile: str) -> Dict[str, Any]:
        """Build response for profile change confirmation."""
        return StandardResponse.success(
            data={
                'message': f"Default security profile changed from '{old_profile}' to '{new_profile}'",
                'previous_profile': old_profile,
                'new_profile': new_profile
            },
            metadata={
                'change_timestamp': datetime.now().isoformat(),
                'changed_by': 'user_request'
            }
        )
    
    @staticmethod
    def invalid_profile(provided_profile: str, available_profiles: List[str]) -> Dict[str, Any]:
        """Build response for invalid profile error."""
        return StandardResponse.error(
            'INVALID_PROFILE',
            f"Unknown security profile: {provided_profile}",
            details={
                'provided_profile': provided_profile,
                'available_profiles': available_profiles
            }
        )


class PermissionResponseBuilder:
    """Builder for permission-related responses."""
    
    @staticmethod
    def enhanced_error_with_permissions(
        original_error: Dict[str, Any],
        permission_info: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Enhance error response with permission guidance."""
        enhanced = original_error.copy()
        enhanced['permission_guidance'] = permission_info
        return enhanced
    
    @staticmethod
    def empty_script_error(provided_script: str) -> Dict[str, Any]:
        """Build error response for empty script."""
        return StandardResponse.error(
            'EMPTY_SCRIPT',
            'Script cannot be empty',
            details={'provided_script': provided_script}
        )