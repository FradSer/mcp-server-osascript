# MCP osascript 服务器

[English](README.md)

通过模型上下文协议（Model Context Protocol）为AI应用提供安全的AppleScript执行能力，支持可配置安全策略和自动TCC权限处理。

## 概述

此MCP服务器为AI模型和macOS自动化之间提供安全的AppleScript执行桥梁。它采用模块化架构，具备可配置的安全策略、自动权限管理和全面的错误处理功能。

## 安装

### 开发环境设置
```bash
# 克隆并安装依赖
uv sync

# 可选：开发模式安装
uv pip install -e .
```

### 生产环境安装
```bash
# 使用uvx进行系统级安装
uvx install /path/to/mcp-server-osascript

# 从Git仓库安装
uvx install git+https://github.com/your-username/mcp-server-osascript.git

# 从PyPI安装（发布后）
uvx install mcp-server-osascript
```

## 使用方法

### 生产环境使用
```bash
# uvx安装后使用（全局可用）
mcp-server-osascript
```

### 开发环境使用
```bash
# 从项目目录运行
uv run mcp-server-osascript

# 从任意目录运行
uv run --project /path/to/mcp-server-osascript mcp-server-osascript

# 替代方案：直接模块执行
uv run python -m mcp_server_osascript.server
```

## MCP客户端配置

在您的MCP客户端中添加以下配置：

**生产环境配置：**
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

**开发环境配置：**
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

## 架构

服务器采用模块化架构，由六个专业组件构成：

- **安全系统**：具有三种安全策略的可配置风险评估
- **执行引擎**：带超时管理的直接osascript执行
- **权限处理器**：自动TCC权限对话框触发
- **响应构建器**：标准化API响应格式
- **用户界面**：交互式确认对话框
- **服务器核心**：FastMCP集成和工具注册

## 功能特性

### 可配置安全策略
- **严格模式**：最高安全级别，阻止危险操作
- **平衡模式**：推荐默认设置，提供风险警告（默认）
- **宽松模式**：最少限制，带审计日志

### 高级权限管理
- 自动TCC权限对话框触发
- 智能错误解析和用户指导
- 支持常见macOS应用程序
- 手动权限配置说明

### 全面工具接口
- 统一的`execute_osascript`工具
- 脚本分析的试运行模式
- 可配置执行超时
- 详细的成功和错误报告

## 工具参考

### `execute_osascript`

执行或分析AppleScript/JavaScript代码，具备全面的安全和权限处理功能。

**参数：**
- `script` (str): 要执行的AppleScript或JavaScript代码
- `execution_timeout` (int): 超时时间（秒，默认：30）
- `security_profile` (str): 安全级别 - "strict"、"balanced"或"permissive"（默认："balanced"）
- `enable_auto_permissions` (bool): 自动触发TCC权限对话框（默认：true）
- `dry_run` (bool): 仅分析脚本不执行（默认：false）

**响应结构：**
```json
{
  "status": "success|error",
  "timestamp": "2024-01-01T12:00:00.000Z",
  "data": {
    "stdout": "执行输出",
    "stderr": "错误输出",
    "execution_time": 1.23
  }
}
```

**错误响应：**
```json
{
  "status": "error",
  "timestamp": "2024-01-01T12:00:00.000Z",
  "error": {
    "type": "SECURITY_BLOCKED|TCC_PERMISSION_DENIED|EXECUTION_TIMEOUT|SYNTAX_ERROR",
    "message": "人类可读的错误描述",
    "details": "附加错误上下文和修复建议"
  }
}
```

## 安全特性

### 脚本分析
- 危险操作的模式匹配
- 风险评分和分类
- 高风险操作确认提示
- 全面审计日志

### 权限管理
- TCC错误代码检测（-1743）
- 应用程序特定的权限指导
- 自动权限对话框触发
- 手动配置说明

### 执行安全
- 直接执行以确保TCC对话框正常显示
- 可配置超时保护
- 子进程错误处理
- 内存和资源管理

## 系统要求

- **操作系统**：macOS（AppleScript运行环境必需）
- **Python**：3.10或更高版本
- **包管理器**：uv（推荐）或pip
- **权限**：用户必须为目标应用程序授予必要的TCC权限

## 开发

### 测试
```bash
# 验证所有模块语法
python3 -m py_compile mcp_server_osascript/*.py

# 测试单个模块
python3 -c "from mcp_server_osascript.security import SecurityProfileManager; print('安全模块正常')"
```

### 架构概述
代码库遵循模块化设计，职责清晰分离：
- 安全评估和策略执行
- 脚本执行和子进程管理
- 权限处理和TCC错误解析
- 标准化响应格式
- 用户界面和确认对话框

## 许可证

MIT License