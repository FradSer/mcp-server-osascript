# MCP osascript 服务器

[🇺🇸 English](README.md)

通过模型上下文协议（Model Context Protocol）为AI提供安全的AppleScript执行能力。

## 安装

### 开发模式
```bash
uv sync
```

### 生产环境使用
```bash
# 从本地目录直接安装
uvx install /path/to/mcp-server-osascript

# 或从Git仓库安装
uvx install git+https://github.com/your-username/mcp-server-osascript.git

# 或从PyPI安装（发布后）
uvx install mcp-server-osascript
```

## 使用方法

### uvx安装后
```bash
# 直接运行服务器（全局可用）
mcp-server-osascript
```

### 开发模式（从项目目录）
```bash
# 从项目目录运行
uv run mcp-server-osascript

# 从任意目录运行
uv run --project /path/to/mcp-server-osascript mcp-server-osascript

# 替代方案：Python模块
uv run python -m mcp_server_osascript.server
```

## MCP客户端配置

要在MCP客户端中使用此服务器，请添加以下配置：

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

开发环境配置：
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

## 功能特性

- 安全的AppleScript执行与安全检查
- 多层安全防护，包括脚本静态分析
- TCC权限处理，提供有用的指导信息
- MCP协议支持，便于AI集成
- 专注的单一工具：`execute_osascript`

## 安全特性

### 脚本安全检查
- 阻止危险操作模式（如shell脚本执行、文件删除等）
- 识别高风险操作（键盘/鼠标控制、系统事件等）
- 高风险操作需要用户确认

### TCC权限处理
- 智能识别macOS TCC权限错误
- 提供详细的权限配置指导
- 支持常见应用程序的权限设置

### 执行环境
- 直接执行以确保TCC权限对话框正常显示
- 可配置执行超时时间
- 详细的错误信息和修复建议

## 工具说明

### `execute_osascript`
安全执行AppleScript代码的核心工具。

**参数：**
- `script` (str): 要执行的AppleScript代码
- `timeout` (int): 执行超时时间，默认20秒

**返回值：**
- `status`: 执行状态（"success" 或 "error"）
- `stdout`: 标准输出（成功时）
- `stderr`: 标准错误（成功时）
- `type`: 错误类型（出错时）
- `details`: 错误详情（出错时）

## 系统要求

- macOS（AppleScript运行环境）
- Python 3.10+
- uv包管理器

## 许可证

MIT License