import logging
import sys
from datetime import datetime, timedelta
from typing import Dict, Any

from mcp.server import FastMCP
from .security import SecurityProfileManager
from .permissions import PermissionHandler
from .executor import ExecutionManager
from .responses import ResponseBuilder

logger = logging.getLogger(__name__)

# Initialize global components
security_manager = SecurityProfileManager()
permission_handler = PermissionHandler()
execution_manager = ExecutionManager(security_manager, permission_handler)











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
        return execution_manager.execute_or_analyze(
            script=script,
            timeout=execution_timeout,
            security_profile=security_profile,
            enable_auto_permissions=enable_auto_permissions,
            dry_run=dry_run
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
            return ResponseBuilder.success(data={'available_profiles': profiles_info})
        except Exception as e:
            logger.error(f"Error getting security profiles: {e}")
            return ResponseBuilder.error('CONFIGURATION_ERROR', 'Failed to retrieve security profiles',
                                       details={'error_message': str(e)})
    
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
                return ResponseBuilder.error('INVALID_PROFILE', f"Unknown security profile: {security_profile}",
                                           details={'available_profiles': list(security_manager.profiles.keys())})
            
            old_profile = security_manager.default_profile
            security_manager.default_profile = security_profile
            
            return ResponseBuilder.success(data={
                'message': f"Profile changed from '{old_profile}' to '{security_profile}'",
                'previous_profile': old_profile,
                'new_profile': security_profile
            })
            
        except Exception as e:
            logger.error(f"Error setting default security profile: {e}")
            return ResponseBuilder.error('CONFIGURATION_ERROR', 'Failed to set default security profile',
                                       details={'error_message': str(e)})
    
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
