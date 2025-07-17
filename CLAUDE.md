# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This is an MCP (Model Context Protocol) server that provides secure AppleScript execution capabilities to AI applications. The server acts as a bridge between AI models and macOS automation through osascript, implementing multiple layers of security including script linting, user confirmation for high-risk operations, and TCC permission handling.

Built using the MCP Python SDK's FastMCP framework for simplified server development.

## Development Environment

**Python Requirements:**
- Python 3.10+ (project specifies `>=3.10` in pyproject.toml)
- macOS (required for AppleScript execution)
- uv package manager (recommended)

**Setup:**
```bash
# Install dependencies
uv sync

# Development mode installation
uv pip install -e .
```

**Running the Server:**
```bash
# From project directory
uv run mcp-server-osascript

# From any directory
uv run --project /path/to/mcp-server-osascript mcp-server-osascript

# Alternative: Python module
uv run python -m mcp_server_osascript.server

# Test syntax
python3 -m py_compile mcp_server_osascript/server.py
```

## Architecture

**FastMCP Implementation** (`mcp_server_osascript/server.py`):
- **Import**: Uses `from mcp.server import FastMCP` (not standalone fastmcp package)
- **Tool Registration**: Single `@server.tool()` decorator for `execute_osascript`
- **Security Layer**: Multi-stage security validation before script execution
- **Execution Engine**: Direct osascript execution (no sandboxing) to allow TCC dialogs
- **Tool Interface**: Single focused tool with structured input/output

**Security Architecture (Defense in Depth):**
1. **Script Linting**: Pre-execution analysis blocking dangerous patterns (`do shell script`, `delete`, etc.)
2. **Risk Assessment**: High-risk operations flagged for user confirmation
3. **Direct Execution**: No sandboxing to ensure TCC permission dialogs can appear
4. **TCC Handling**: Intelligent parsing of macOS permission errors with user guidance

**Core Functions:**
- `lint_applescript()`: Security pattern matching and risk assessment
- `get_user_confirmation()`: Interactive confirmation for high-risk scripts
- `parse_tcc_error()`: TCC permission error analysis and user guidance
- `execute_osascript()`: Main tool decorated with `@server.tool()`
- `execute_osascript_safely()`: Wrapper with security checks
- `execute_osascript_direct()`: Direct osascript execution

**Error Handling Strategy:**
- Structured dictionary responses with specific error types
- Clear user guidance for permission issues
- Timeout handling for long-running scripts (default 20s)
- Comprehensive subprocess error capture

## Key Implementation Details

**MCP SDK Integration**: Uses `mcp>=1.0.0` which includes FastMCP. Import pattern is `from mcp.server import FastMCP`.

**Security Patterns**: Regex-based pattern matching to identify blocked operations (shell scripts, system commands) and high-risk operations (keyboard/mouse control, System Events).

**TCC Permission System**: Handles macOS TCC (Transparency, Consent, and Control) permission errors with error code -1743 detection and provides helpful user guidance including manual commands.

**No Sandboxing**: Removed sandbox execution to ensure TCC permission dialogs can be properly triggered in client applications.