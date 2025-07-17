# MCP osascript Server

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