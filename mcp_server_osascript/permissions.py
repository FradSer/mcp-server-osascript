"""
Permission and TCC handling module for MCP osascript server.

This module manages macOS Transparency, Consent, and Control (TCC) permissions
and provides automatic permission dialog handling for AppleScript execution.
"""

import logging
import os
import re
import subprocess
import tempfile
from typing import Dict, Any, Optional, List

logger = logging.getLogger(__name__)

# TCC trigger scripts for automatic permission handling
TCC_TRIGGER_SCRIPTS = {
    "System Events": 'tell application "System Events" to get name of first process',
    "Music": 'tell application "Music" to get player state',
    "Finder": 'tell application "Finder" to get name of desktop',
    "Safari": 'tell application "Safari" to get name of front window',
    "Google Chrome": 'tell application "Google Chrome" to get title of front window'
}


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
        '-1743', 'not authorized', 'not authorised',
        'permission denied', 'requires accessibility', 'automation permission'
    ]
    
    if not any(pattern in stderr_lower for pattern in tcc_patterns):
        return None
        
    app_name = _extract_app_name(stderr, stderr_lower)
    
    return {
        'type': 'TCC_PERMISSION_DENIED',
        'app_name': app_name,
        'message': f"Permission denied to control {app_name}",
        'fix_suggestion': _get_fix_suggestion(app_name),
        'manual_command': f"osascript -e 'tell application \"{app_name}\" to get name'"
    }


def _extract_app_name(stderr: str, stderr_lower: str) -> str:
    """Extract application name from TCC error message."""
    app_match = re.search(r'application "([^"]+)"', stderr)
    if app_match:
        return app_match.group(1)
    
    # Try to detect common applications from error message
    app_mappings = {
        'system events': 'System Events',
        'finder': 'Finder',
        'music': 'Music',
        'itunes': 'Music',
        'safari': 'Safari',
        'chrome': 'Google Chrome'
    }
    
    for pattern, app_name in app_mappings.items():
        if pattern in stderr_lower:
            return app_name
    
    return "the target application"


def _get_fix_suggestion(app_name: str) -> str:
    """Generate fix suggestion for TCC permission error."""
    return (
        f"To fix this:\n"
        f"1. Open System Settings > Privacy & Security > Automation\n"
        f"2. Find your terminal/app in the list\n"
        f"3. Enable the checkbox for '{app_name}'\n"
        f"4. If no dialog appeared, run: sudo tccutil reset AppleEvents\n"
        f"5. Try the script again - you should see a permission dialog"
    )


class PermissionHandler:
    """
    Handles TCC permissions automatically to simplify user experience.
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
        
        tcc_info = parse_tcc_error(error_result.get('stderr', ''))
        if not tcc_info:
            return error_result
        
        app_name = tcc_info.get('app_name', 'System Events')
        permission_result = self._trigger_permission_dialog(app_name)
        
        return self._enhance_error_result(error_result, app_name, permission_result)
    
    def _is_tcc_error(self, error_result: Dict[str, Any]) -> bool:
        """Check if error is related to TCC permissions."""
        stderr = error_result.get('stderr', '').lower()
        return any(pattern in stderr for pattern in ['-1743', 'not authorized', 'permission'])
    
    def _trigger_permission_dialog(self, app_name: str) -> Dict[str, Any]:
        """Attempt to trigger TCC permission dialog for the specified app."""
        trigger_script = TCC_TRIGGER_SCRIPTS.get(app_name, TCC_TRIGGER_SCRIPTS["System Events"])
        
        try:
            self.logger.info(f"Attempting to trigger TCC dialog for {app_name}")
            
            # Try direct execution first
            result = self._execute_trigger_script(trigger_script)
            if result['success']:
                return result
            
            # Fallback to terminal method
            return self._trigger_via_terminal(trigger_script, app_name)
            
        except Exception as e:
            self.logger.warning(f"Failed to auto-trigger TCC dialog: {e}")
            return {
                'method': 'auto_trigger',
                'success': False,
                'message': f'Could not automatically trigger permission dialog: {str(e)}'
            }
    
    def _execute_trigger_script(self, script: str) -> Dict[str, Any]:
        """Execute trigger script directly."""
        result = subprocess.run(
            ['osascript', '-e', script],
            capture_output=True,
            text=True,
            timeout=10
        )
        
        return {
            'method': 'direct_execution',
            'success': result.returncode == 0,
            'message': 'Successfully triggered permission request' if result.returncode == 0 
                      else 'Direct execution failed'
        }
    
    def _trigger_via_terminal(self, script: str, app_name: str) -> Dict[str, Any]:
        """Attempt to trigger permission dialog via Terminal."""
        try:
            temp_script = self._create_terminal_script(script, app_name)
            
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
    
    def _create_terminal_script(self, script: str, app_name: str) -> str:
        """Create a temporary terminal script for TCC dialog triggering."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.command', delete=False) as f:
            escaped_script = script.replace("'", "'\\''")
            f.write(f'#!/bin/bash\n')
            f.write(f'echo "Triggering TCC permission dialog for {app_name}..."\n')
            f.write(f'osascript -e \'{escaped_script}\'\n')
            f.write(f'echo "Permission dialog should have appeared. Close this window."\n')
            f.write(f'read -p "Press Enter to continue..."\n')
            temp_script = f.name
        
        os.chmod(temp_script, 0o755)
        return temp_script
    
    def _enhance_error_result(
        self, 
        error_result: Dict[str, Any], 
        app_name: str, 
        permission_result: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Enhance error result with permission handling information."""
        enhanced_result = error_result.copy()
        enhanced_result.update({
            'permission_info': {
                'app_name': app_name,
                'auto_trigger_attempted': True,
                'auto_trigger_result': permission_result,
                'user_guidance': self._get_user_guidance(app_name),
                'next_steps': self._get_next_steps(app_name)
            }
        })
        return enhanced_result
    
    def _get_user_guidance(self, app_name: str) -> List[str]:
        """Get user-friendly guidance for resolving TCC permissions."""
        return [
            f"Your script needs permission to control '{app_name}'",
            "This is a normal macOS security feature",
            "Grant permission when the dialog appears, or manually in System Settings",
            "This only needs to be done once per application"
        ]
    
    def _get_next_steps(self, app_name: str) -> List[str]:
        """Get specific next steps for resolving permissions."""
        return [
            f"Check for permission dialog for '{app_name}'",
            "If dialog appeared, click 'OK' to grant access",
            "If no dialog, go to System Settings > Privacy & Security > Automation",
            f"Enable automation permissions for your terminal/app to control '{app_name}'",
            "Then retry your script"
        ]


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
        temp_script = _create_enhanced_terminal_script(script, app_name)
        logger.info(f"Created temporary script: {temp_script}")
        
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
                'instructions': _get_terminal_instructions(),
                'cleanup_note': f'Temporary script created: {temp_script}'
            }
        else:
            return {
                'status': 'error',
                'type': 'TERMINAL_OPEN_FAILED',
                'details': 'Failed to open Terminal script',
                'fallback': 'Try running the script manually in Terminal'
            }
            
    except Exception as e:
        return {
            'status': 'error',
            'type': 'TERMINAL_TRIGGER_FAILED',
            'details': f'Failed to trigger TCC dialog: {str(e)}',
            'fallback_instructions': [
                'Try running this command manually in Terminal:',
                f'osascript -e \'{script}\'',
                'Or check System Settings > Privacy & Security > Automation'
            ]
        }


def _create_enhanced_terminal_script(script: str, app_name: str) -> str:
    """Create an enhanced terminal script with better user experience."""
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


def _get_terminal_instructions() -> List[str]:
    """Get instructions for Terminal-based TCC dialog triggering."""
    return [
        'A Terminal window should have opened',
        'The script will run automatically',
        'If a permission dialog appears, click "OK"',
        'If no dialog appears, permissions may already be granted',
        'Check System Settings > Privacy & Security > Automation for manual setup'
    ]