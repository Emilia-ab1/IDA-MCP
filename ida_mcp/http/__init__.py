"""IDA MCP HTTP 代理模块。

提供通过 HTTP 访问多个 IDA 实例的 MCP 代理服务。

架构:
┌─────────────────────────────────────────────────┐
│              proxy/_server.server               │
│    (FastMCP 实例，唯一的工具定义源)              │
└───────────────┬─────────────────┬───────────────┘
                │                 │
        ┌───────▼───────┐ ┌───────▼───────┐
        │ stdio 传输    │ │ HTTP 传输     │
        │ server.run()  │ │ http_app()    │
        └───────────────┘ └───────────────┘
                │                 │
                └────────┬────────┘
                         ▼
                    协调器 (11337)
                         ▼
                IDA 实例 (10001, ...)

特点:
- 复用 proxy/_server.py 中的 FastMCP server
- 与 stdio 模式使用完全相同的工具定义
- 由协调器在 IDA 插件启动时自动启动
- 用户只需要在 MCP 客户端配置中填写 URL 即可连接

使用方式:
    MCP 客户端配置 (HTTP 模式):
    {
        "mcpServers": {
            "ida-mcp": {
                "url": "http://127.0.0.1:11338/mcp"
            }
        }
    }

配置:
    编辑 ida_mcp/config.conf 可自定义端口和地址:
    http_host = "127.0.0.1"  # 使用 0.0.0.0 允许远程访问
    http_port = 11338
    http_path = "/mcp"
"""
from __future__ import annotations

from .http_server import start_http_proxy, stop_http_proxy, is_http_proxy_running, get_http_url

__all__ = ['start_http_proxy', 'stop_http_proxy', 'is_http_proxy_running', 'get_http_url']
