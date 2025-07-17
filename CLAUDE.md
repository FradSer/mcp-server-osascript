# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This is an MCP (Model Context Protocol) server that provides secure AppleScript execution capabilities to AI applications. The server acts as a bridge between AI models and macOS automation through osascript, implementing multiple layers of security including sandboxing, script linting, and user confirmation for high-risk operations.

Built using the FastMCP framework for simplified MCP server development.

## Development Environment

**Python Requirements:**
- Python 3.10+ (project specifies `>=3.10` in pyproject.toml)
- Virtual environment required (system Python is externally managed)

**Setup:**
```bash
python3 -m venv venv
source venv/bin/activate
pip install -e .
```

**Testing the Server:**
```bash
# Run the server directly
mcp-server-osascript

# Test with uvx (recommended)
uvx --from . mcp-server-osascript

# Install for development
pip install -e .
```

## Architecture

**FastMCP Implementation** (`mcp_server_osascript/server.py`):
- **FastMCP Framework**: Uses `@mcp.tool()` decorators for automatic tool registration
- **Security Layer**: Multi-stage security validation before script execution
- **Execution Engine**: Sandboxed osascript execution with comprehensive error handling
- **Tool Interface**: Single `execute_osascript` tool with structured input/output
- **Resource System**: Example AppleScript templates via `@mcp.resource()`

**Security Architecture (Defense in Depth):**
1. **Script Linting**: Pre-execution analysis blocking dangerous patterns (`do shell script`, `delete`, etc.)
2. **Risk Assessment**: High-risk operations flagged for user confirmation
3. **Sandbox Execution**: All scripts run via `sandbox-exec` with restrictive profile
4. **TCC Handling**: Intelligent parsing of macOS permission errors with user guidance

**Core Functions:**
- `lint_applescript()`: Security pattern matching and risk assessment
- `get_user_confirmation()`: Interactive confirmation for high-risk scripts
- `parse_tcc_error()`: TCC permission error analysis and user guidance
- `execute_osascript()`: Main tool decorated with `@mcp.tool()`
- `get_example_script()`: Resource decorated with `@mcp.resource()`

**Error Handling Strategy:**
- Structured dictionary responses with specific error types
- Clear user guidance for permission issues
- Timeout handling for long-running scripts
- Comprehensive subprocess error capture

## Key Implementation Details

**FastMCP Benefits**: Simplified decorator-based tool registration, automatic schema generation, and built-in stdio/transport handling.

**Sandbox Profile**: Creates temporary `.sb` files with restrictive permissions allowing only essential osascript operations while blocking filesystem writes and network access.

**Pattern Matching**: Uses regex patterns to identify blocked operations (shell scripts, system commands) and high-risk operations (keyboard/mouse control, System Events).

**Resource Templates**: Provides example AppleScript snippets via the `applescript://example/{script_type}` resource pattern.

**macOS-Specific**: Handles TCC (Transparency, Consent, and Control) permission system errors with error code -1743 detection and helpful user guidance.