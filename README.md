# MCP osascript Server

[中文版](README_CN.md)

Secure AppleScript execution for AI applications via Model Context Protocol with configurable security profiles and automatic TCC permission handling.

## Overview

This MCP server provides a bridge between AI models and macOS automation through secure AppleScript execution. It features a modular architecture with configurable security profiles, automatic permission management, and comprehensive error handling.

## Installation

### Development Setup
```bash
# Clone and setup dependencies
uv sync

# Optional: Development mode installation
uv pip install -e .
```

### Production Installation
```bash
# System-wide installation with uvx
uvx install /path/to/mcp-server-osascript

# From Git repository
uvx install git+https://github.com/your-username/mcp-server-osascript.git

# From PyPI (when published)
uvx install mcp-server-osascript
```

## Usage

### Production Usage
```bash
# After uvx installation (available system-wide)
mcp-server-osascript
```

### Development Usage
```bash
# From project directory
uv run mcp-server-osascript

# From any directory
uv run --project /path/to/mcp-server-osascript mcp-server-osascript

# Alternative: Direct module execution
uv run python -m mcp_server_osascript.server
```

## MCP Client Configuration

Add this configuration to your MCP client:

**Production Configuration:**
```json
{
  "mcpServers": {
    "osascript": {
      "command": "mcp-server-osascript",
      "args": []
    }
  }
}
```

**Development Configuration:**
```json
{
  "mcpServers": {
    "osascript": {
      "command": "uv",
      "args": ["run", "--project", "/path/to/mcp-server-osascript", "mcp-server-osascript"]
    }
  }
}
```

## Architecture

The server is built with a modular architecture consisting of six focused components:

- **Security System**: Configurable risk assessment with three security profiles
- **Execution Engine**: Direct osascript execution with timeout management
- **Permission Handler**: Automatic TCC permission dialog triggering
- **Response Builder**: Standardized API response formatting
- **User Interface**: Interactive confirmation dialogs
- **Server Core**: FastMCP integration and tool registration

## Features

### Configurable Security Profiles
- **Strict**: Maximum security with blocked dangerous operations
- **Balanced**: Recommended default with risk warnings (default)
- **Permissive**: Minimal restrictions with audit logging

### Advanced Permission Management
- Automatic TCC permission dialog triggering
- Intelligent error parsing and user guidance
- Support for common macOS applications
- Manual permission configuration instructions

### Comprehensive Tool Interface
- Single unified `execute_osascript` tool
- Dry-run mode for script analysis without execution
- Configurable execution timeouts
- Detailed success and error reporting

## Tool Reference

### `execute_osascript`

Execute or analyze AppleScript/JavaScript code with comprehensive security and permission handling.

**Parameters:**
- `script` (str): AppleScript or JavaScript code to execute
- `execution_timeout` (int): Timeout in seconds (default: 30)
- `security_profile` (str): Security level - "strict", "balanced", or "permissive" (default: "balanced")
- `enable_auto_permissions` (bool): Auto-trigger TCC permission dialogs (default: true)
- `dry_run` (bool): Analyze script without executing (default: false)

**Response Structure:**
```json
{
  "status": "success|error",
  "timestamp": "2024-01-01T12:00:00.000Z",
  "data": {
    "stdout": "execution output",
    "stderr": "error output",
    "execution_time": 1.23
  }
}
```

**Error Response:**
```json
{
  "status": "error",
  "timestamp": "2024-01-01T12:00:00.000Z",
  "error": {
    "type": "SECURITY_BLOCKED|TCC_PERMISSION_DENIED|EXECUTION_TIMEOUT|SYNTAX_ERROR",
    "message": "Human-readable error description",
    "details": "Additional error context and repair suggestions"
  }
}
```

## Security Features

### Script Analysis
- Pattern matching for dangerous operations
- Risk scoring and classification
- High-risk operation confirmation prompts
- Comprehensive audit logging

### Permission Management
- TCC error code detection (-1743)
- Application-specific permission guidance
- Automatic permission dialog triggering
- Manual configuration instructions

### Execution Safety
- Direct execution for proper TCC dialog display
- Configurable timeout protection
- Subprocess error handling
- Memory and resource management

## System Requirements

- **Operating System**: macOS (required for AppleScript runtime)
- **Python**: 3.10 or higher
- **Package Manager**: uv (recommended) or pip
- **Permissions**: User must grant necessary TCC permissions for target applications

## Development

### Testing
```bash
# Validate syntax for all modules
python3 -m py_compile mcp_server_osascript/*.py

# Test individual modules
python3 -c "from mcp_server_osascript.security import SecurityProfileManager; print('Security module OK')"
```

### Architecture Overview
The codebase follows a modular design with clear separation of concerns:
- Security assessment and policy enforcement
- Script execution and subprocess management  
- Permission handling and TCC error parsing
- Standardized response formatting
- User interface and confirmation dialogs

## License

MIT License