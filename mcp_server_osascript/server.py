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

def try_trigger_tcc_via_terminal(script: str, tcc_error: Dict[str, str]) -> Optional[Dict[str, Any]]:
    """
    Try to trigger TCC dialog by executing via terminal or other methods.
    
    Args:
        script: The AppleScript code
        tcc_error: The TCC error information
        
    Returns:
        Result dictionary if successful, None otherwise
    """
    try:
        # Method 1: Create a temporary script and open it in Terminal
        # This approach is more reliable for triggering TCC dialogs
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.command', delete=False) as f:
            f.write(f'#!/bin/bash\n')
            f.write(f'echo "Attempting to trigger TCC permission dialog..."\n')
            f.write(f'echo "Script: {script[:50]}..."\n')
            f.write(f'echo ""\n')
            escaped_script = script.replace("'", "'\\''")
            f.write(f'osascript -e \'{escaped_script}\'\n')
            f.write(f'echo ""\n')
            f.write(f'echo "If a permission dialog appeared, click OK to grant access."\n')
            f.write(f'echo "Then try running your script again in the MCP client."\n')
            f.write(f'echo "If no dialog appeared, check System Settings > Privacy & Security > Automation"\n')
            f.write(f'echo ""\n')
            f.write(f'echo "Press Enter to close this window..."\n')
            f.write(f'read\n')
            temp_script = f.name
        
        # Make it executable
        os.chmod(temp_script, 0o755)
        
        logger.info(f"Created temporary script: {temp_script}")
        
        # Try to open it with Terminal
        result = subprocess.run(
            ['open', '-a', 'Terminal', temp_script],
            capture_output=True,
            text=True,
            timeout=10
        )
        
        if result.returncode == 0:
            return {
                'status': 'tcc_dialog_trigger_attempted',
                'message': 'TCC dialog should appear in Terminal window',
                'instructions': [
                    'A Terminal window should have opened',
                    'If a permission dialog appears, click "OK" to grant access',
                    'Then try running your script again',
                    'If no dialog appears, check System Settings > Privacy & Security > Automation'
                ],
                'cleanup_note': f'Temporary script created: {temp_script}'
            }
        
    except Exception as e:
        logger.warning(f"Terminal script creation failed: {e}")
    
    # Method 2: Try to execute via AppleScript to Terminal
    try:
        escaped_script = script.replace("'", "'\\''")
        terminal_script = f'''
        tell application "Terminal"
            activate
            do script "osascript -e '{escaped_script}'"
        end tell
        '''
        
        logger.info("Attempting to trigger TCC dialog via Terminal.app")
        
        result = subprocess.run(
            ['osascript', '-e', terminal_script],
            capture_output=True,
            text=True,
            timeout=30
        )
        
        if result.returncode == 0:
            logger.info("Terminal execution successful")
            return {
                'status': 'success',
                'stdout': result.stdout,
                'stderr': result.stderr,
                'method': 'terminal_execution'
            }
        
    except Exception as e:
        logger.warning(f"Terminal execution failed: {e}")
    
    return None

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
    
    @server.tool()
    def force_tcc_dialog(app_name: str = "System Events") -> Dict[str, Any]:
        """
        Force trigger TCC permission dialog by opening Terminal.
        
        This tool creates a temporary Terminal session to run osascript directly,
        which should trigger the TCC permission dialog that doesn't appear when
        running from within other applications.
        
        Args:
            app_name: Name of the application to trigger permission for
            
        Returns:
            Dictionary with instructions and expected behavior
        """
        trigger_scripts = {
            "System Events": 'tell application "System Events" to get name of first process',
            "Music": 'tell application "Music" to get player state',
            "Finder": 'tell application "Finder" to get name of desktop',
            "Safari": 'tell application "Safari" to get name of front window',
            "Google Chrome": 'tell application "Google Chrome" to get title of front window'
        }
        
        script = trigger_scripts.get(app_name, f'tell application "{app_name}" to get name')
        
        try:
            # Create a temporary script file that will be opened in Terminal
            with tempfile.NamedTemporaryFile(mode='w', suffix='.command', delete=False) as f:
                f.write(f'#!/bin/bash\n')
                f.write(f'echo "Triggering TCC permission dialog for {app_name}..."\n')
                escaped_script = script.replace("'", "'\\''")
                f.write(f'osascript -e \'{escaped_script}\'\n')
                f.write(f'echo ""\n')
                f.write(f'echo "If a permission dialog appeared, click OK to grant access."\n')
                f.write(f'echo "If no dialog appeared, check System Settings > Privacy & Security > Automation"\n')
                f.write(f'echo ""\n')
                f.write(f'echo "Press Enter to close this window..."\n')
                f.write(f'read\n')
                temp_script = f.name
            
            # Make it executable
            os.chmod(temp_script, 0o755)
            
            # Open it with Terminal
            result = subprocess.run(
                ['open', '-a', 'Terminal', temp_script],
                capture_output=True,
                text=True,
                timeout=10
            )
            
            return {
                'status': 'tcc_dialog_opened',
                'message': f'Terminal window opened to trigger TCC dialog for {app_name}',
                'instructions': [
                    'A Terminal window should have opened',
                    'The script will run automatically',
                    'If a permission dialog appears, click "OK"',
                    'If no dialog appears, permissions may already be granted or denied',
                    'Check System Settings > Privacy & Security > Automation for manual setup'
                ],
                'next_steps': [
                    'After granting permission, try your original script again',
                    'The permission should now work for all scripts targeting this app'
                ],
                'cleanup_note': f'Temporary script created: {temp_script}'
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

    @server.tool()
    def trigger_tcc_permission(app_name: str = "Music") -> Dict[str, Any]:
        """
        Trigger TCC permission dialog for a specific application.
        
        This tool intentionally runs a simple AppleScript command to force macOS
        to show the permission dialog for controlling the specified application.
        
        Args:
            app_name: Name of the application to trigger permission for (default: "Music")
            
        Returns:
            Dictionary with instructions and expected behavior
        """
        trigger_scripts = {
            "Music": 'tell application "Music" to get player state',
            "System Events": 'tell application "System Events" to get name of first process',
            "Finder": 'tell application "Finder" to get name of desktop',
            "Safari": 'tell application "Safari" to get name of front window',
            "Google Chrome": 'tell application "Google Chrome" to get title of front window'
        }
        
        script = trigger_scripts.get(app_name, f'tell application "{app_name}" to get name')
        
        result = execute_osascript_safely(script, timeout=5)
        
        if result.get('type') == 'TCC_PERMISSION_DENIED':
            return {
                'status': 'permission_dialog_triggered',
                'message': f"TCC permission dialog should appear for {app_name}",
                'expected_behavior': [
                    f"A system dialog should appear asking to allow control of {app_name}",
                    "Click 'OK' to grant permission",
                    "If no dialog appears, use the reset commands below",
                    "Then try running this command again"
                ],
                'reset_commands': [
                    "sudo tccutil reset AppleEvents",
                    "sudo killall -9 tccd",
                    "Then run this tool again"
                ]
            }
        elif result.get('status') == 'success':
            return {
                'status': 'already_granted',
                'message': f"Permission already granted for {app_name}",
                'app_name': app_name
            }
        else:
            return {
                'status': 'unexpected_error',
                'message': result.get('details', 'Unknown error'),
                'type': result.get('type')
            }

    @server.tool()
    def reset_tcc_permissions() -> Dict[str, Any]:
        """
        Reset TCC permissions to allow new permission dialogs.
        
        This tool resets the TCC (Transparency, Consent, and Control) database
        to force macOS to show permission dialogs again. This is useful when
        permissions were denied and need to be re-requested.
        
        Returns:
            Dictionary with reset results and instructions
        """
        import getpass
        
        current_user = getpass.getuser()
        
        try:
            # Reset AppleEvents permissions
            cmd = ['sudo', 'tccutil', 'reset', 'AppleEvents']
            process = subprocess.run(
                cmd,
                capture_output=True,
                text=True
            )
            
            if process.returncode == 0:
                # Also try to restart the TCC daemon
                restart_cmd = ['sudo', 'killall', '-9', 'tccd']
                restart_process = subprocess.run(
                    restart_cmd,
                    capture_output=True,
                    text=True
                )
                
                return {
                    'status': 'success',
                    'message': 'TCC permissions reset successfully',
                    'next_steps': [
                        'Run your AppleScript again',
                        'You should now see permission dialogs',
                        'Click "OK" to grant permissions',
                        'If no dialogs appear, try running the script directly: osascript -e "your script"'
                    ]
                }
            else:
                stderr_str = process.stderr
                return {
                    'status': 'error',
                    'type': 'RESET_FAILED',
                    'details': f'Failed to reset TCC permissions: {stderr_str}',
                    'suggestion': 'Try running the reset command manually: sudo tccutil reset AppleEvents'
                }
                
        except Exception as e:
            return {
                'status': 'error',
                'type': 'SYSTEM_ERROR',
                'details': f'Error resetting TCC permissions: {str(e)}',
                'manual_commands': [
                    'sudo tccutil reset AppleEvents',
                    'sudo killall -9 tccd'
                ]
            }

    @server.tool()
    def check_tcc_permissions() -> Dict[str, Any]:
        """
        Check and guide through TCC permission issues for AppleScript automation.
        
        This tool helps diagnose and fix TCC (Transparency, Consent, and Control)
        permission problems when using AppleScript to control other applications.
        
        Returns:
            Dictionary with diagnostic information and step-by-step fix instructions
        """
        import getpass
        
        current_user = getpass.getuser()
        
        # Test script to trigger TCC for common applications
        test_scripts = {
            "Music": 'tell application "Music" to playpause',
            "System Events": 'tell application "System Events" to get name of first process',
            "Finder": 'tell application "Finder" to get name of front window'
        }
        
        results = {}
        
        for app_name, script in test_scripts.items():
            try:
                result = execute_osascript_safely(script, timeout=5)
                if result.get('status') == 'success':
                    results[app_name] = "✅ Granted"
                elif result.get('type') == 'TCC_PERMISSION_DENIED':
                    results[app_name] = "❌ Denied"
                else:
                    results[app_name] = f"⚠️ Other error: {result.get('type')}"
            except Exception as e:
                results[app_name] = f"⚠️ Error: {str(e)}"
        
        return {
            'status': 'diagnostic_complete',
            'user': current_user,
            'permissions': results,
            'fix_instructions': [
                "1. Open System Settings > Privacy & Security > Automation",
                "2. Look for your terminal app (Terminal, iTerm2, VS Code, etc.)",
                "3. Enable checkboxes for the apps you want to control",
                "4. If no dialog appeared, run: sudo tccutil reset AppleEvents",
                "5. Try the script again to trigger the permission dialog",
                "6. Still stuck? Run: sudo killall -9 tccd to refresh TCC cache"
            ],
            'reset_commands': [
                f"sudo tccutil reset AppleEvents",
                f"sudo tccutil reset All {current_user}",
                f"sudo killall -9 tccd"
            ]
        }

    @server.resource("applescript://example/{script_type}")
    def get_example_script(script_type: str) -> str:
        """
        Get example AppleScript snippets for common tasks.
        
        Args:
            script_type: Type of example script to retrieve
            
        Available examples:
        - browser_url: Get current browser URL
        - notification: Show system notification
        - clipboard: Get clipboard content
        - finder_path: Get current Finder path
        - music_play: Play/pause Music app
        - music_info: Get current track info
        """
        examples = {
            'browser_url': '''
tell application "Safari"
    if (count of windows) > 0 then
        return URL of current tab of front window
    else
        return "No Safari windows open"
    end if
end tell
'''.strip(),
            
            'notification': '''
display notification "Hello from AppleScript!" with title "MCP osascript"
'''.strip(),
            
            'clipboard': '''
return the clipboard
'''.strip(),
            
            'finder_path': '''
tell application "Finder"
    if (count of windows) > 0 then
        return POSIX path of (target of front window as alias)
    else
        return "No Finder windows open"
    end if
end tell
'''.strip(),
            
            'music_play': '''
tell application "Music" to playpause
'''.strip(),
            
            'music_info': '''
tell application "Music"
    if player state is playing then
        return (name of current track) & " by " & (artist of current track)
    else
        return "No music playing"
    end if
end tell
'''.strip()
        }
        
        return examples.get(script_type, f"Unknown example type: {script_type}")
    
    @server.prompt("safe_browser_url")
    def safe_browser_url_prompt() -> str:
        """
        Prompt for safely getting the current browser URL.
        
        This prompt guides the AI to use a safe, tested AppleScript
        to retrieve the current browser URL without triggering
        high-risk security warnings.
        """
        return """
You are about to execute an AppleScript to get the current browser URL.
This is a safe operation that only reads information and doesn't
perform any system modifications.

Here's a safe script you can use:

```applescript
tell application "Safari"
    if (count of windows) > 0 then
        return URL of current tab of front window
    else
        return "No Safari windows open"
    end if
end tell
```

You can also adapt this for other browsers by changing "Safari" to:
- "Google Chrome"
- "Firefox"
- "Microsoft Edge"

This script will not trigger security warnings and should execute
immediately without user confirmation.
"""
    
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