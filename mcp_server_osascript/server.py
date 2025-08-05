import logging
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Dict, Any, Optional, List
from datetime import datetime, timedelta

from mcp.server import FastMCP
from .security import SecurityProfileManager, SecurityDecision, RiskLevel

logger = logging.getLogger(__name__)

# Initialize global security manager
security_manager = SecurityProfileManager()

# TCC trigger scripts for automatic permission handling
TCC_TRIGGER_SCRIPTS = {
    "System Events": 'tell application "System Events" to get name of first process',
    "Music": 'tell application "Music" to get player state',
    "Finder": 'tell application "Finder" to get name of desktop',
    "Safari": 'tell application "Safari" to get name of front window',
    "Google Chrome": 'tell application "Google Chrome" to get title of front window'
}


class PermissionHandler:
    """
    Internal class to handle TCC permissions automatically.
    Hides macOS permission complexity from users.
    """
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
    
    def auto_handle_permissions(self, error_result: Dict[str, Any]) -> Dict[str, Any]:
        """
        Automatically attempt to resolve TCC permission issues.
        
        Args:
            error_result: Error result from script execution
            
        Returns:
            Enhanced error result with automatic permission handling
        """
        if not self._is_tcc_error(error_result):
            return error_result
        
        # Parse TCC error and attempt automatic resolution
        tcc_info = parse_tcc_error(error_result.get('stderr', ''))
        if not tcc_info:
            return error_result
        
        app_name = tcc_info.get('app_name', 'System Events')
        
        # Attempt to trigger permission dialog automatically
        permission_result = self._trigger_permission_dialog(app_name)
        
        # Enhance error message with actionable guidance
        enhanced_result = error_result.copy()
        enhanced_result.update({
            'permission_info': {
                'app_name': app_name,
                'auto_trigger_attempted': True,
                'auto_trigger_result': permission_result,
                'user_guidance': self._get_user_guidance(app_name),
                'next_steps': [
                    f"Check for permission dialog for '{app_name}'",
                    "If dialog appeared, click 'OK' to grant access",
                    "If no dialog, go to System Settings > Privacy & Security > Automation",
                    f"Enable automation permissions for your terminal/app to control '{app_name}'",
                    "Then retry your script"
                ]
            }
        })
        
        return enhanced_result
    
    def _is_tcc_error(self, error_result: Dict[str, Any]) -> bool:
        """Check if error is related to TCC permissions."""
        stderr = error_result.get('stderr', '').lower()
        return any(pattern in stderr for pattern in ['-1743', 'not authorized', 'permission'])
    
    def _trigger_permission_dialog(self, app_name: str) -> Dict[str, Any]:
        """
        Attempt to trigger TCC permission dialog for the specified app.
        
        Returns:
            Dictionary with trigger attempt results
        """
        trigger_script = TCC_TRIGGER_SCRIPTS.get(app_name, TCC_TRIGGER_SCRIPTS["System Events"])
        
        try:
            self.logger.info(f"Attempting to trigger TCC dialog for {app_name}")
            
            # Try direct execution first
            result = subprocess.run(
                ['osascript', '-e', trigger_script],
                capture_output=True,
                text=True,
                timeout=10
            )
            
            if result.returncode == 0:
                return {
                    'method': 'direct_execution',
                    'success': True,
                    'message': f'Successfully triggered permission request for {app_name}'
                }
            
            # If direct execution fails, try terminal method
            return self._trigger_via_terminal(trigger_script, app_name)
            
        except Exception as e:
            self.logger.warning(f"Failed to auto-trigger TCC dialog: {e}")
            return {
                'method': 'auto_trigger',
                'success': False,
                'message': f'Could not automatically trigger permission dialog: {str(e)}'
            }
    
    def _trigger_via_terminal(self, script: str, app_name: str) -> Dict[str, Any]:
        """Attempt to trigger permission dialog via Terminal."""
        try:
            # Create temporary script
            with tempfile.NamedTemporaryFile(mode='w', suffix='.command', delete=False) as f:
                f.write(f'#!/bin/bash\n')
                f.write(f'echo "Triggering TCC permission dialog for {app_name}..."\n')
                escaped_script = script.replace("'", "'\\''")
                f.write(f'osascript -e \'{escaped_script}\'\n')
                f.write(f'echo "Permission dialog should have appeared. Close this window."\n')
                f.write(f'read -p "Press Enter to continue..."\n')
                temp_script = f.name
            
            os.chmod(temp_script, 0o755)
            
            # Open in Terminal
            result = subprocess.run(
                ['open', '-a', 'Terminal', temp_script],
                capture_output=True,
                text=True,
                timeout=5
            )
            
            return {
                'method': 'terminal_trigger',
                'success': result.returncode == 0,
                'message': f'Opened Terminal to trigger {app_name} permission dialog',
                'temp_script': temp_script
            }
            
        except Exception as e:
            return {
                'method': 'terminal_trigger', 
                'success': False,
                'message': f'Terminal trigger failed: {str(e)}'
            }
    
    def _get_user_guidance(self, app_name: str) -> List[str]:
        """Get user-friendly guidance for resolving TCC permissions."""
        return [
            f"Your script needs permission to control '{app_name}'",
            "This is a normal macOS security feature",
            "Grant permission when the dialog appears, or manually in System Settings",
            "This only needs to be done once per application"
        ]


# Initialize global permission handler
permission_handler = PermissionHandler()


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

def get_user_confirmation(script: str) -> bool:
    """
    Get user confirmation for high-risk operations.
    
    Args:
        script: The AppleScript code to confirm
        
    Returns:
        True if user confirms, False otherwise
    """
    print("\n" + "="*60)
    print("HIGH-RISK APPLESCRIPT EXECUTION REQUEST")
    print("="*60)
    print("The following AppleScript contains potentially risky operations:")
    print("-" * 60)
    print(script)
    print("-" * 60)
    print("This script may:")
    print("- Control keyboard/mouse input")
    print("- Interact with system UI elements")
    print("- Control other applications")
    print("- Perform automation tasks")
    print("="*60)
    
    while True:
        response = input("Do you want to proceed? (yes/no): ").strip().lower()
        if response in ['yes', 'y']:
            return True
        elif response in ['no', 'n']:
            return False
        else:
            print("Please enter 'yes' or 'no'")


def parse_tcc_error(stderr: str) -> Optional[Dict[str, str]]:
    """
    Parse TCC permission errors from osascript stderr.
    
    Args:
        stderr: Error output from osascript
        
    Returns:
        Dictionary with error details or None if not a TCC error
    """
    stderr_lower = stderr.lower()
    
    # Check for various TCC permission error patterns
    tcc_patterns = [
        '-1743',
        'not authorized',
        'not authorised',
        'permission denied',
        'requires accessibility',
        'automation permission'
    ]
    
    if any(pattern in stderr_lower for pattern in tcc_patterns):
        app_match = re.search(r'application "([^"]+)"', stderr)
        app_name = app_match.group(1) if app_match else "the target application"
        
        # Detect if it's System Events or a specific app
        if 'system events' in stderr_lower:
            app_name = "System Events"
        elif 'finder' in stderr_lower:
            app_name = "Finder"
        elif 'music' in stderr_lower or 'itunes' in stderr_lower:
            app_name = "Music"
        elif 'safari' in stderr_lower:
            app_name = "Safari"
        elif 'chrome' in stderr_lower:
            app_name = "Google Chrome"
        
        return {
            'type': 'TCC_PERMISSION_DENIED',
            'app_name': app_name,
            'message': f"Permission denied to control {app_name}",
            'fix_suggestion': f"To fix this:\n1. Open System Settings > Privacy & Security > Automation\n2. Find your terminal/app in the list\n3. Enable the checkbox for '{app_name}'\n4. If no dialog appeared, run: sudo tccutil reset AppleEvents\n5. Try the script again - you should see a permission dialog",
            'manual_command': f"osascript -e 'tell application \"{app_name}\" to get name'"
        }
    
    return None


def _build_error_response(error_type: str, details: str, **kwargs) -> Dict[str, Any]:
    """Build standardized error response dictionary."""
    return {
        'status': 'error',
        'type': error_type,
        'details': details,
        **kwargs
    }


def _build_success_response(stdout: str = "", stderr: str = "", **kwargs) -> Dict[str, Any]:
    """Build standardized success response dictionary."""
    return {
        'status': 'success',
        'stdout': stdout,
        'stderr': stderr,
        **kwargs
    }


def execute_osascript_direct(script: str, timeout: int = 20) -> Dict[str, Any]:
    """
    Execute AppleScript directly with enhanced TCC dialog triggering.
    
    Uses synchronous execution to ensure TCC permission dialogs appear correctly.
    This is critical for client mode where async execution may prevent dialogs.
    
    Args:
        script: The AppleScript code to execute
        timeout: Timeout in seconds
        
    Returns:
        Dictionary with execution results
    """
    try:
        cmd = ['osascript', '-e', script]
        logger.info(f"Executing osascript command: {' '.join(cmd[:2])}...")
        
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout
        )
        
        if result.returncode == 0:
            return _build_success_response(result.stdout, result.stderr)
        
        # Handle TCC errors specially
        tcc_error = parse_tcc_error(result.stderr)
        if tcc_error:
            return {
                'status': 'error',
                **tcc_error,
                'stdout': result.stdout,
                'stderr': result.stderr
            }
        
        return _build_error_response(
            'EXECUTION_FAILED',
            f"osascript exited with code {result.returncode}",
            stdout=result.stdout,
            stderr=result.stderr
        )
            
    except subprocess.TimeoutExpired:
        return _build_error_response('TIMEOUT', f"Script execution timed out after {timeout} seconds")
    except Exception as e:
        return _build_error_response('SYSTEM_ERROR', f"System error: {str(e)}")

def _create_terminal_script(script: str, app_name: str = "application") -> str:
    """Create a temporary terminal script for TCC dialog triggering."""
    with tempfile.NamedTemporaryFile(mode='w', suffix='.command', delete=False) as f:
        escaped_script = script.replace("'", "'\\''")
        f.write(f'#!/bin/bash\n')
        f.write(f'echo "Triggering TCC permission dialog for {app_name}..."\n')
        f.write(f'echo "Script: {script[:50]}..."\n')
        f.write(f'echo ""\n')
        f.write(f'osascript -e \'{escaped_script}\'\n')
        f.write(f'echo ""\n')
        f.write(f'echo "If a permission dialog appeared, click OK to grant access."\n')
        f.write(f'echo "If no dialog appeared, check System Settings > Privacy & Security > Automation"\n')
        f.write(f'echo ""\n')
        f.write(f'echo "Press Enter to close this window..."\n')
        f.write(f'read\n')
        temp_script = f.name
    
    os.chmod(temp_script, 0o755)
    return temp_script


def trigger_tcc_via_terminal(script: str, app_name: str = "application") -> Dict[str, Any]:
    """
    Universal TCC dialog trigger by creating a Terminal script.
    
    Args:
        script: The AppleScript code to execute
        app_name: Name of the application for user messaging
        
    Returns:
        Result dictionary with instructions
    """
    try:
        temp_script = _create_terminal_script(script, app_name)
        logger.info(f"Created temporary script: {temp_script}")
        
        # Open script with Terminal
        result = subprocess.run(
            ['open', '-a', 'Terminal', temp_script],
            capture_output=True,
            text=True,
            timeout=10
        )
        
        if result.returncode == 0:
            return {
                'status': 'tcc_dialog_opened',
                'message': f'Terminal window opened to trigger TCC dialog for {app_name}',
                'instructions': [
                    'A Terminal window should have opened',
                    'The script will run automatically',
                    'If a permission dialog appears, click "OK"',
                    'If no dialog appears, permissions may already be granted',
                    'Check System Settings > Privacy & Security > Automation for manual setup'
                ],
                'cleanup_note': f'Temporary script created: {temp_script}'
            }
        else:
            return _build_error_response(
                'TERMINAL_OPEN_FAILED',
                'Failed to open Terminal script',
                fallback='Try running the script manually in Terminal'
            )
            
    except Exception as e:
        return _build_error_response(
            'TERMINAL_TRIGGER_FAILED',
            f'Failed to trigger TCC dialog: {str(e)}',
            fallback_instructions=[
                'Try running this command manually in Terminal:',
                f'osascript -e \'{script}\'',
                'Or check System Settings > Privacy & Security > Automation'
            ]
        )

def _build_security_error_response(security_result, error_type: str, details: str) -> Dict[str, Any]:
    """Build standardized security error response."""
    return {
        'status': 'error',
        'type': error_type,
        'details': details,
        'security': {
            'profile': security_result.metadata.get('profile'),
            'risk_level': security_result.risk_level.value,
            'risk_score': security_result.risk_score,
            'issues': security_result.issues,
            'warnings': security_result.warnings,
            'decision': security_result.decision.value
        }
    }


def _add_security_metadata(execution_result: Dict[str, Any], security_result) -> Dict[str, Any]:
    """Add security metadata to successful execution result."""
    if execution_result.get('status') == 'success':
        execution_result['security'] = {
            'profile': security_result.metadata.get('profile'),
            'risk_level': security_result.risk_level.value,
            'risk_score': security_result.risk_score,
            'warnings': security_result.warnings,
            'audit_patterns': [p.get('description') for p in security_result.metadata.get('patterns', [])]
        }
    return execution_result


def execute_osascript_with_security(
    script: str, 
    timeout: int = 20, 
    security_profile: Optional[str] = None
) -> Dict[str, Any]:
    """
    Execute AppleScript with configurable security checks.
    
    Args:
        script: The AppleScript code to execute
        timeout: Timeout in seconds
        security_profile: Security profile to use ('strict', 'balanced', 'permissive')
        
    Returns:
        Dictionary with execution results and security metadata
    """
    # Evaluate security
    security_result = security_manager.evaluate_script(script, security_profile)
    
    # Handle security decisions
    if security_result.decision == SecurityDecision.BLOCK:
        return _build_security_error_response(
            security_result, 'SECURITY_BLOCK', 'Script blocked by security policy'
        )
    
    elif security_result.decision == SecurityDecision.CONFIRM:
        if not get_user_confirmation_enhanced(script, security_result):
            return _build_security_error_response(
                security_result, 'USER_CANCELLED', 'User cancelled risky operation'
            )
    
    # Execute the script
    logger.info(f"Executing AppleScript with {security_result.metadata.get('profile', 'default')} security profile")
    execution_result = execute_osascript_direct(script, timeout)
    
    # Add security metadata to result
    return _add_security_metadata(execution_result, security_result)


def _display_security_header(security_result) -> None:
    """Display security review header information."""
    print("\n" + "="*70)
    print("SECURITY REVIEW REQUIRED")
    print("="*70)
    print(f"Risk Level: {security_result.risk_level.value.upper()}")
    print(f"Risk Score: {security_result.risk_score}/100")
    print(f"Security Profile: {security_result.metadata.get('profile', 'unknown')}")
    print("-" * 70)


def _display_security_warnings(security_result) -> None:
    """Display security warnings if present."""
    if security_result.warnings:
        print("Security Concerns:")
        for warning in security_result.warnings:
            print(f"  ⚠️  {warning}")
        print("-" * 70)


def _display_script_preview(script: str) -> None:
    """Display a preview of the script to be executed."""
    print("Script Preview:")
    script_lines = script.split('\n')[:5]  # Show first 5 lines
    for i, line in enumerate(script_lines, 1):
        print(f"  {i:2}: {line}")
    total_lines = len(script.split('\n'))
    if total_lines > 5:
        remaining_lines = total_lines - 5
        print(f"  ... ({remaining_lines} more lines)")
    print("-" * 70)


def _display_detected_patterns(security_result) -> None:
    """Display detected security patterns."""
    print("Patterns Detected:")
    patterns = security_result.metadata.get('patterns', [])
    if patterns:
        for pattern in patterns[:3]:  # Show first 3 patterns
            risk_level = pattern.get('risk_level', 'unknown')
            if hasattr(risk_level, 'value'):
                risk_level = risk_level.value
            print(f"  • {pattern.get('description', 'Unknown')} (Risk: {risk_level})")
        if len(patterns) > 3:
            print(f"  ... and {len(patterns) - 3} more")
    else:
        print("  No high-risk patterns detected")


def _display_detailed_analysis(security_result) -> None:
    """Display detailed security analysis."""
    print("\nDetailed Security Analysis:")
    print(f"Profile: {security_result.metadata.get('profile')}")
    for category, patterns_in_cat in security_result.metadata.get('patterns_by_category', {}).items():
        if patterns_in_cat:
            print(f"\n{category.replace('_', ' ').title()}:")
            for pattern in patterns_in_cat:
                print(f"  - {pattern.get('description')}")
                if pattern.get('remediation'):
                    print(f"    Suggestion: {pattern.get('remediation')}")
    print()


def get_user_confirmation_enhanced(script: str, security_result) -> bool:
    """
    Enhanced user confirmation with detailed security information.
    
    Args:
        script: The AppleScript code to confirm
        security_result: Security analysis result
        
    Returns:
        True if user confirms, False otherwise
    """
    _display_security_header(security_result)
    _display_security_warnings(security_result)
    _display_script_preview(script)
    _display_detected_patterns(security_result)
    print("="*70)
    
    while True:
        response = input("Do you want to proceed? (yes/no/details): ").strip().lower()
        if response in ['yes', 'y']:
            return True
        elif response in ['no', 'n']:
            return False
        elif response in ['details', 'd']:
            _display_detailed_analysis(security_result)
        else:
            print("Please enter 'yes', 'no', or 'details'")


def _get_security_recommendations(security_result) -> List[str]:
    """Generate security recommendations based on analysis."""
    recommendations = []
    
    if security_result.risk_score > 70:
        recommendations.append("Consider reviewing the script carefully before execution")
    
    if any('shell' in pattern.get('category', '') for pattern in security_result.metadata.get('patterns', [])):
        recommendations.append("Shell script execution detected - ensure commands are safe")
    
    if security_result.decision == SecurityDecision.BLOCK:
        recommendations.append("Switch to 'balanced' or 'permissive' profile if this script is legitimate")
    
    patterns = security_result.metadata.get('patterns', [])
    critical_patterns = [p for p in patterns if p.get('risk_level') == 'critical']
    if critical_patterns:
        recommendations.append("Critical security patterns detected - verify script source")
    
    return recommendations


def _suggest_security_level(security_result) -> str:
    """Suggest appropriate security level based on risk analysis."""
    if security_result.risk_score >= 90:
        return "strict"
    elif security_result.risk_score >= 50:
        return "balanced"  
    else:
        return "permissive"


# Keep old function for backward compatibility
def execute_osascript_safely(script: str, timeout: int = 20) -> Dict[str, Any]:
    """
    Legacy function for backward compatibility.
    Uses strict security profile to maintain old behavior.
    """
    return execute_osascript_with_security(script, timeout, 'strict')

def _perform_security_analysis(script: str, security_profile: str) -> Dict[str, Any]:
    """
    Internal function to perform security analysis without execution.
    This is the dry_run implementation for the execute_applescript tool.
    """
    if not script or not script.strip():
        return StandardResponse.error(
            'EMPTY_SCRIPT',
            'Cannot analyze empty script',
            details={'provided_script': script}
        )
    
    try:
        # Perform security analysis
        security_result = security_manager.evaluate_script(script, security_profile)
        
        # Build comprehensive analysis response
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
            'recommendations': _get_security_recommendations(security_result),
            'execution_guidance': {
                'safe_to_execute': security_result.decision in [SecurityDecision.ALLOW, SecurityDecision.WARN],
                'requires_confirmation': security_result.decision == SecurityDecision.CONFIRM,
                'blocked': security_result.decision == SecurityDecision.BLOCK,
                'suggested_security_profile': _suggest_security_level(security_result)
            }
        }
        
        # Add educational information for high-risk scripts
        if security_result.risk_score > 70:
            analysis_data['educational_info'] = {
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
        
        return StandardResponse.success(
            data=analysis_data,
            metadata={
                'analysis_timestamp': datetime.now().isoformat(),
                'security_profile_used': security_profile,
                'script_length': len(script),
                'analysis_version': '2.0',
                'dry_run': True
            }
        )
        
    except Exception as e:
        logger.error(f"Error during security analysis: {e}")
        return StandardResponse.error(
            'ANALYSIS_ERROR',
            'Failed to analyze script',
            details={'error_message': str(e)}
        )


def serve() -> FastMCP:
    """Create and configure the FastMCP server."""
    server = FastMCP("mcp-server-osascript")
    
    @server.tool()
    def execute_osascript(
        script: str, 
        execution_timeout: int = 30, 
        security_profile: str = "balanced",
        enable_auto_permissions: bool = True,
        dry_run: bool = False
    ) -> Dict[str, Any]:
        """
        Execute or analyze scripts using osascript with comprehensive functionality and automatic permission handling.
        
        This unified tool handles both AppleScript/JavaScript execution and security analysis with full osascript 
        capabilities including shell script execution and intelligent TCC permission management.
        
        Security Profiles:
        - "strict": Maximum security, blocks potentially dangerous operations
        - "balanced": Recommended default, warns about risks but allows execution 
        - "permissive": Minimal restrictions, full functionality with audit logging
        
        Features:
        - Complete osascript support for AppleScript and JavaScript
        - Shell script execution via "do shell script"
        - Automatic TCC permission dialog handling
        - Intelligent error recovery and user guidance
        - Security risk assessment and warnings
        - Comprehensive execution logging
        - Dry-run mode for analysis without execution
        
        Args:
            script: The script code to execute or analyze (AppleScript or JavaScript for osascript)
            execution_timeout: Maximum execution time in seconds (default: 30, ignored in dry_run)
            security_profile: Security mode ("strict", "balanced", "permissive") 
            enable_auto_permissions: Automatically handle macOS permission dialogs (default: True)
            dry_run: If True, only analyze security without executing (default: False)
            
        Returns:
            Standardized response with execution results, security analysis, and guidance
        """
        # Handle dry_run mode for analysis only
        if dry_run:
            logger.info(f"Analyzing AppleScript security with {security_profile} profile")
            return _perform_security_analysis(script, security_profile)
        
        logger.info(f"Executing AppleScript with {security_profile} security profile")
        
        # Validate input
        if not script or not script.strip():
            return StandardResponse.error(
                'EMPTY_SCRIPT', 
                'Script cannot be empty',
                details={'provided_script': script}
            )
        
        # Execute with timing
        start_time = datetime.now()
        try:
            # Run security analysis and execution
            result = execute_osascript_with_security(script, execution_timeout, security_profile)
            
            # Handle TCC permission errors automatically if enabled
            if enable_auto_permissions and result.get('status') == 'error':
                enhanced_result = permission_handler.auto_handle_permissions(result)
                if enhanced_result != result:
                    result = enhanced_result
                    logger.info("Applied automatic TCC permission handling")
            
            # Standardize successful responses
            if result.get('status') == 'success':
                return StandardResponse.success(
                    data={
                        'stdout': result.get('stdout', ''),
                        'stderr': result.get('stderr', ''),
                        'execution_time': (datetime.now() - start_time).total_seconds()
                    },
                    security=result.get('security', {}),
                    metadata={
                        'security_profile': security_profile,
                        'auto_permissions': enable_auto_permissions,
                        'script_length': len(script),
                        'execution_timestamp': start_time.isoformat()
                    }
                )
            
            # Handle security blocks with helpful guidance
            elif result.get('type') == 'SECURITY_BLOCK':
                return StandardResponse.error(
                    'SECURITY_POLICY_VIOLATION',
                    f"Script blocked by {security_profile} security policy",
                    details={
                        'security_analysis': result.get('security', {}),
                        'suggestions': [
                            f"Try using 'balanced' or 'permissive' security profile if this script is trusted",
                            "Review the security warnings and ensure script safety",
                            "Consider using dry_run=True to analyze risks first"
                        ],
                        'alternative_security_profiles': ['balanced', 'permissive'] if security_profile == 'strict' else ['permissive']
                    }
                )
            
            # Handle other errors with enhanced information
            else:
                error_type = result.get('type', 'EXECUTION_ERROR')
                error_details = result.get('details', 'Script execution failed')
                
                response = StandardResponse.error(error_type, error_details)
                
                # Add permission info if available
                if 'permission_info' in result:
                    response['permission_guidance'] = result['permission_info']
                
                return response
                
        except Exception as e:
            logger.error(f"Unexpected error during script execution: {e}")
            return StandardResponse.error(
                'SYSTEM_ERROR',
                'Unexpected system error during execution',
                details={
                    'error_message': str(e),
                    'execution_time': (datetime.now() - start_time).total_seconds()
                }
            )
    
    @server.tool()
    def get_security_profiles() -> Dict[str, Any]:
        """
        Get information about all available security profiles.
        
        Returns detailed information about each security profile including their
        patterns, risk levels, and usage recommendations.
        
        Returns:
            Dictionary with security profile information and current configuration
        """
        try:
            profiles_info = security_manager.list_profiles()
            
            usage_stats = {
                'total_evaluations': len(security_manager.audit_log),
                'recent_evaluations': len([
                    log for log in security_manager.audit_log[-100:]
                    if datetime.fromisoformat(log['timestamp']) > 
                       datetime.now() - timedelta(hours=24)
                ]) if security_manager.audit_log else 0
            }
            
            return StandardResponse.success(
                data={
                    'current_default_profile': security_manager.default_profile,
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
            
        except Exception as e:
            logger.error(f"Error getting security profiles: {e}")
            return StandardResponse.error(
                'CONFIGURATION_ERROR',
                'Failed to retrieve security profiles',
                details={'error_message': str(e)}
            )
    
    @server.tool()
    def set_security_profile(security_profile: str) -> Dict[str, Any]:
        """
        Set the default security profile for script execution.
        
        This sets the default security profile that will be used when no explicit
        profile is specified in execute_applescript calls.
        
        Args:
            security_profile: Security profile to set as default ("strict", "balanced", "permissive")
            
        Returns:
            Confirmation of the configuration change
        """
        try:
            if security_profile not in security_manager.profiles:
                return StandardResponse.error(
                    'INVALID_PROFILE',
                    f"Unknown security profile: {security_profile}",
                    details={
                        'provided_profile': security_profile,
                        'available_profiles': list(security_manager.profiles.keys())
                    }
                )
            
            old_profile = security_manager.default_profile
            security_manager.default_profile = security_profile
            
            return StandardResponse.success(
                data={
                    'message': f"Default security profile changed from '{old_profile}' to '{security_profile}'",
                    'previous_profile': old_profile,
                    'new_profile': security_profile
                },
                metadata={
                    'change_timestamp': datetime.now().isoformat(),
                    'changed_by': 'user_request'
                }
            )
            
        except Exception as e:
            logger.error(f"Error setting default security profile: {e}")
            return StandardResponse.error(
                'CONFIGURATION_ERROR',
                'Failed to set default security profile',
                details={'error_message': str(e)}
            )
    
    return server


def main():
    """Main entry point for the MCP server."""
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    )
    
    logger.info("Starting MCP osascript server...")
    
    try:
        server = serve()
        server.run()
    except KeyboardInterrupt:
        logger.info("Server stopped by user")
    except Exception as e:
        logger.error(f"Server error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
