"""IDA MCP 代理模块。

提供通过协调器访问多个 IDA 实例的 MCP 代理服务。

使用方式:
    python -m ida_mcp.proxy.ida_mcp_proxy

或导入:
    from ida_mcp.proxy import server
"""
from __future__ import annotations

from .ida_mcp_proxy import server

__all__ = ['server']

