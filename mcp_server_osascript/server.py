import logging
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Dict, Any, Optional

from mcp.server import FastMCP

logger = logging.getLogger(__name__)

def lint_applescript(script: str) -> Dict[str, Any]:
    """
    Lint AppleScript for security issues and risk assessment.
    
    Args:
        script: The AppleScript code to lint
        
    Returns:
        Dictionary containing lint results with 'blocked', 'high_risk', and 'issues' keys
    """
    blocked_patterns = [
        r'\bdo\s+shell\s+script\b',
        r'\bdelete\b.*\btrash\b',
        r'\bempty\s+trash\b',
        r'\brm\s+-rf\b',
        r'\bsudo\b',
        r'\bkillall\b',
        r'\bshutdown\b',
        r'\brestart\b',
        r'\bformat\b',
        r'\bfdisk\b',
        r'\bdiskutil\b.*\berase\b',
    ]
    
    high_risk_patterns = [
        r'\bkeystroke\b',
        r'\bkey\s+code\b',
        r'\bmouse\b',
        r'\bclick\b',
        r'\bSystem\s+Events\b',
        r'\bUI\s+scripting\b',
        r'\bGUI\s+scripting\b',
        r'\bquit\b',
        r'\blaunch\b',
        r'\bopen\b.*\bapplication\b',
    ]
    
    issues = []
    
    for pattern in blocked_patterns:
        if re.search(pattern, script, re.IGNORECASE):
            issues.append(f"Blocked pattern detected: {pattern}")
    
    high_risk = False
    for pattern in high_risk_patterns:
        if re.search(pattern, script, re.IGNORECASE):
            high_risk = True
            issues.append(f"High-risk pattern detected: {pattern}")
    
    return {
        'blocked': len([issue for issue in issues if issue.startswith('Blocked')]) > 0,
        'high_risk': high_risk,
        'issues': issues
    }

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
        # Use synchronous execution to ensure TCC dialogs work properly
        cmd = ['osascript', '-e', script]
        
        logger.info(f"Executing osascript command: {' '.join(cmd[:2])}...")
        
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout
        )
        
        stdout_str = result.stdout
        stderr_str = result.stderr
        
        if result.returncode == 0:
            return {
                'status': 'success',
                'stdout': stdout_str,
                'stderr': stderr_str
            }
        else:
            tcc_error = parse_tcc_error(stderr_str)
            if tcc_error:
                return {
                    'status': 'error',
                    **tcc_error,
                    'stdout': stdout_str,
                    'stderr': stderr_str
                }
            
            return {
                'status': 'error',
                'type': 'EXECUTION_FAILED',
                'details': f"osascript exited with code {result.returncode}",
                'stdout': stdout_str,
                'stderr': stderr_str
            }
            
    except subprocess.TimeoutExpired:
        return {
            'status': 'error',
            'type': 'TIMEOUT',
            'details': f"Script execution timed out after {timeout} seconds"
        }
    except Exception as e:
        return {
            'status': 'error',
            'type': 'SYSTEM_ERROR',
            'details': f"System error: {str(e)}"
        }


def execute_osascript_safely(script: str, timeout: int = 20) -> Dict[str, Any]:
    """
    Execute AppleScript safely with security checks (no sandbox).
    
    Args:
        script: The AppleScript code to execute
        timeout: Timeout in seconds
        
    Returns:
        Dictionary with execution results
    """
    lint_result = lint_applescript(script)
    
    if lint_result['blocked']:
        return {
            'status': 'error',
            'type': 'SCRIPT_REJECTED_BY_LINTER',
            'details': 'Script contains blocked patterns',
            'issues': lint_result['issues']
        }
    
    if lint_result['high_risk']:
        if not get_user_confirmation(script):
            return {
                'status': 'error',
                'type': 'USER_CANCELLED',
                'details': 'User cancelled high-risk operation',
                'issues': lint_result['issues']
            }
    
    # Execute directly without sandbox to allow TCC dialogs
    logger.info("Executing AppleScript directly (no sandbox) to allow TCC permissions")
    return execute_osascript_direct(script, timeout)

def serve() -> FastMCP:
    """Create and configure the FastMCP server."""
    server = FastMCP("mcp-server-osascript")
    
    @server.tool()
    def execute_osascript(script: str, timeout: int = 20) -> Dict[str, Any]:
        """
        Execute AppleScript code safely with security checks (no sandbox).
        
        This tool provides secure execution of AppleScript code through multiple layers
        of security including script linting and user confirmation for high-risk operations.
        Scripts are executed directly without sandboxing to ensure TCC permission dialogs
        can be properly triggered.
        
        Security Features:
        - Pre-execution linting to block dangerous patterns
        - User confirmation for high-risk operations
        - TCC permission error handling with helpful guidance
        - Direct execution to allow macOS permission dialogs
        
        Args:
            script: The AppleScript code to execute
            timeout: Maximum execution time in seconds (default: 20)
            
        Returns:
            Dictionary containing:
            - status: "success" or "error"
            - stdout: Standard output (on success)
            - stderr: Standard error (on success)
            - type: Error type (on error)
            - details: Error details (on error)
            - issues: Security issues found (on linting errors)
            
        Blocked Patterns:
        - Shell script execution (do shell script)
        - File deletion operations
        - System administration commands
        - Potentially destructive operations
        
        High-Risk Patterns (require user confirmation):
        - Keyboard/mouse control
        - System Events usage
        - GUI scripting
        - Application control
        
        Common TCC Permission Errors:
        If you receive a TCC_PERMISSION_DENIED error, you need to grant
        automation permissions in System Settings > Privacy & Security > Automation.
        """
        logger.info(f"Executing AppleScript: {script[:100]}...")
        
        if not script or not script.strip():
            return {
                'status': 'error',
                'type': 'EMPTY_SCRIPT',
                'details': 'Script cannot be empty'
            }
        
        return execute_osascript_safely(script, timeout)
    
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