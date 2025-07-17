# MCP osascript Server

[🇨🇳 中文版](README_CN.md)

Secure AppleScript execution for AI via Model Context Protocol.

## Installation

### For Development
```bash
uv sync
```

### For Production Use
```bash
# Install directly from local directory
uvx install /path/to/mcp-server-osascript

# Or install from Git repository
uvx install git+https://github.com/your-username/mcp-server-osascript.git

# Or install from PyPI (when published)
uvx install mcp-server-osascript
```

## Usage

### After uvx installation
```bash
# Run the server directly (available system-wide)
mcp-server-osascript
```

### Development mode (from project directory)
```bash
# Run from project directory
uv run mcp-server-osascript

# Run from any directory
uv run --project /path/to/mcp-server-osascript mcp-server-osascript

# Alternative: Python module
uv run python -m mcp_server_osascript.server
```

## MCP Client Configuration

To use this server with an MCP client, add the following configuration:

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

Or for development:
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

## Features

- Secure AppleScript execution with security checks
- Multiple security layers including script linting
- TCC permission handling with helpful guidance
- MCP protocol support for AI integration
- Single focused tool: `execute_osascript`

## Security Features

### Script Security Checks
- Blocks dangerous operation patterns (shell script execution, file deletion, etc.)
- Identifies high-risk operations (keyboard/mouse control, system events, etc.)
- High-risk operations require user confirmation

### TCC Permission Handling
- Intelligent recognition of macOS TCC permission errors
- Provides detailed permission configuration guidance
- Supports common application permission settings

### Execution Environment
- Direct execution to ensure TCC permission dialogs display properly
- Configurable execution timeout
- Detailed error messages and repair suggestions

## Tool Description

### `execute_osascript`
Core tool for safely executing AppleScript code.

**Parameters:**
- `script` (str): The AppleScript code to execute
- `timeout` (int): Execution timeout in seconds, default 20

**Return Values:**
- `status`: Execution status ("success" or "error")
- `stdout`: Standard output (on success)
- `stderr`: Standard error (on success)
- `type`: Error type (on error)
- `details`: Error details (on error)

## System Requirements

- macOS (AppleScript runtime environment)
- Python 3.10+
- uv package manager

## License

MIT License