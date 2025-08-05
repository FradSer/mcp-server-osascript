"""
User interface and interaction module for MCP osascript server.

This module handles all user-facing interactions including confirmation dialogs,
security warnings, and informational displays.
"""

from typing import List


def get_user_confirmation(script: str) -> bool:
    """
    Get basic user confirmation for script execution.
    
    Args:
        script: The AppleScript code to confirm
        
    Returns:
        True if user confirms, False otherwise
    """
    _display_basic_confirmation_header()
    _display_script_content(script)
    _display_basic_warnings()
    
    return _get_yes_no_input("Do you want to proceed? (yes/no): ")


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


def _display_basic_confirmation_header() -> None:
    """Display basic confirmation header."""
    print("\n" + "="*60)
    print("HIGH-RISK APPLESCRIPT EXECUTION REQUEST")
    print("="*60)
    print("The following AppleScript contains potentially risky operations:")
    print("-" * 60)


def _display_script_content(script: str) -> None:
    """Display script content for basic confirmation."""
    print(script)
    print("-" * 60)


def _display_basic_warnings() -> None:
    """Display basic warning information."""
    print("This script may:")
    print("- Control keyboard/mouse input")
    print("- Interact with system UI elements")
    print("- Control other applications")
    print("- Perform automation tasks")
    print("="*60)


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
    
    patterns_by_category = security_result.metadata.get('patterns_by_category', {})
    for category, patterns_in_cat in patterns_by_category.items():
        if patterns_in_cat:
            print(f"\n{category.replace('_', ' ').title()}:")
            for pattern in patterns_in_cat:
                print(f"  - {pattern.get('description')}")
                if pattern.get('remediation'):
                    print(f"    Suggestion: {pattern.get('remediation')}")
    print()


def _get_yes_no_input(prompt: str) -> bool:
    """Get yes/no input from user with validation."""
    while True:
        response = input(prompt).strip().lower()
        if response in ['yes', 'y']:
            return True
        elif response in ['no', 'n']:
            return False
        else:
            print("Please enter 'yes' or 'no'")


class UIFormatter:
    """Utility class for consistent UI formatting."""
    
    @staticmethod
    def format_header(title: str, width: int = 70) -> str:
        """Format a header with consistent styling."""
        return f"\n{'='*width}\n{title}\n{'='*width}"
    
    @staticmethod
    def format_section(title: str, width: int = 70) -> str:
        """Format a section divider."""
        return f"\n{title}\n{'-'*width}"
    
    @staticmethod
    def format_list_item(item: str, bullet: str = "•") -> str:
        """Format a list item with consistent indentation."""
        return f"  {bullet} {item}"
    
    @staticmethod
    def format_warning(message: str) -> str:
        """Format a warning message."""
        return f"  ⚠️  {message}"
    
    @staticmethod
    def format_info(message: str) -> str:
        """Format an informational message."""
        return f"  ℹ️  {message}"
    
    @staticmethod
    def format_code_line(line_num: int, content: str) -> str:
        """Format a code line with line number."""
        return f"  {line_num:2}: {content}"


class InteractiveDisplay:
    """Class for interactive displays with user input."""
    
    def __init__(self):
        self.formatter = UIFormatter()
    
    def show_security_review(self, script: str, security_result) -> bool:
        """Show interactive security review and get user decision."""
        self._show_security_info(security_result)
        self._show_script_info(script)
        self._show_pattern_info(security_result)
        
        return self._get_user_decision(security_result)
    
    def _show_security_info(self, security_result) -> None:
        """Display security information section."""
        print(self.formatter.format_header("SECURITY REVIEW REQUIRED"))
        print(f"Risk Level: {security_result.risk_level.value.upper()}")
        print(f"Risk Score: {security_result.risk_score}/100")
        print(f"Profile: {security_result.metadata.get('profile', 'unknown')}")
        
        if security_result.warnings:
            print(self.formatter.format_section("Security Concerns"))
            for warning in security_result.warnings:
                print(self.formatter.format_warning(warning))
    
    def _show_script_info(self, script: str) -> None:
        """Display script information section."""
        print(self.formatter.format_section("Script Preview"))
        lines = script.split('\n')[:5]
        for i, line in enumerate(lines, 1):
            print(self.formatter.format_code_line(i, line))
        
        if len(script.split('\n')) > 5:
            remaining = len(script.split('\n')) - 5
            print(f"  ... ({remaining} more lines)")
    
    def _show_pattern_info(self, security_result) -> None:
        """Display detected patterns section."""
        print(self.formatter.format_section("Detected Patterns"))
        patterns = security_result.metadata.get('patterns', [])
        
        if not patterns:
            print(self.formatter.format_info("No high-risk patterns detected"))
            return
        
        for pattern in patterns[:3]:
            risk_level = getattr(pattern.get('risk_level'), 'value', 'unknown')
            desc = pattern.get('description', 'Unknown')
            print(self.formatter.format_list_item(f"{desc} (Risk: {risk_level})"))
        
        if len(patterns) > 3:
            print(f"  ... and {len(patterns) - 3} more patterns")
    
    def _get_user_decision(self, security_result) -> bool:
        """Get user decision with option for detailed analysis."""
        print("="*70)
        
        while True:
            response = input("Proceed? (yes/no/details): ").strip().lower()
            if response in ['yes', 'y']:
                return True
            elif response in ['no', 'n']:
                return False
            elif response in ['details', 'd']:
                self._show_detailed_analysis(security_result)
            else:
                print("Please enter 'yes', 'no', or 'details'")
    
    def _show_detailed_analysis(self, security_result) -> None:
        """Show detailed security analysis."""
        print(self.formatter.format_section("Detailed Analysis"))
        print(f"Profile: {security_result.metadata.get('profile')}")
        
        patterns_by_category = security_result.metadata.get('patterns_by_category', {})
        for category, patterns in patterns_by_category.items():
            if patterns:
                category_title = category.replace('_', ' ').title()
                print(f"\n{category_title}:")
                for pattern in patterns:
                    print(f"  - {pattern.get('description')}")
                    if pattern.get('remediation'):
                        print(f"    💡 {pattern.get('remediation')}")
        print()