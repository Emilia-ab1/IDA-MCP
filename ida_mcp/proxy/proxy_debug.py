"""调试器转发工具。"""
from __future__ import annotations

from typing import Optional, Any, Annotated

try:
    from pydantic import Field
except ImportError:
    Field = lambda **kwargs: None  # type: ignore

import sys
import os
_this_dir = os.path.dirname(os.path.abspath(__file__))
if _this_dir not in sys.path:
    sys.path.insert(0, _this_dir)

from _state import forward  # type: ignore


def register_tools(server: Any) -> None:
    """注册调试器工具到服务器。"""
    
    @server.tool(description="Start debugger process.")
    def dbg_start(
        port: Annotated[Optional[int], Field(description="Instance port override")] = None,
    ) -> Any:
        """启动调试器。"""
        return forward("dbg_start", {}, port)
    
    @server.tool(description="Exit/terminate debugger process.")
    def dbg_exit(
        port: Annotated[Optional[int], Field(description="Instance port override")] = None,
    ) -> Any:
        """退出调试器。"""
        return forward("dbg_exit", {}, port)
    
    @server.tool(description="Continue debugger execution.")
    def dbg_continue(
        port: Annotated[Optional[int], Field(description="Instance port override")] = None,
    ) -> Any:
        """继续执行。"""
        return forward("dbg_continue", {}, port)
    
    @server.tool(description="Step into next instruction.")
    def dbg_step_into(
        port: Annotated[Optional[int], Field(description="Instance port override")] = None,
    ) -> Any:
        """单步进入。"""
        return forward("dbg_step_into", {}, port)
    
    @server.tool(description="Step over next instruction.")
    def dbg_step_over(
        port: Annotated[Optional[int], Field(description="Instance port override")] = None,
    ) -> Any:
        """单步跳过。"""
        return forward("dbg_step_over", {}, port)
    
    @server.tool(description="Step into/over. into=True for step into, False for step over.")
    def dbg_step(
        into: Annotated[bool, Field(description="True=step into, False=step over")] = True,
        port: Annotated[Optional[int], Field(description="Instance port override")] = None,
    ) -> Any:
        """单步执行。"""
        tool = "dbg_step_into" if into else "dbg_step_over"
        return forward(tool, {}, port)
    
    @server.tool(description="Run to address.")
    def dbg_run_to(
        address: Annotated[str, Field(description="Target address")],
        port: Annotated[Optional[int], Field(description="Instance port override")] = None,
    ) -> Any:
        """运行到指定地址。"""
        return forward("dbg_run_to", {"addr": address}, port)
    
    @server.tool(description="Get all CPU registers.")
    def dbg_regs(
        port: Annotated[Optional[int], Field(description="Instance port override")] = None,
    ) -> Any:
        """获取寄存器。"""
        return forward("dbg_regs", {}, port)
    
    @server.tool(description="Get call stack.")
    def dbg_stack(
        port: Annotated[Optional[int], Field(description="Instance port override")] = None,
    ) -> Any:
        """获取调用栈。"""
        return forward("dbg_callstack", {}, port)
    
    @server.tool(description="List all breakpoints.")
    def dbg_list_breakpoints(
        port: Annotated[Optional[int], Field(description="Instance port override")] = None,
    ) -> Any:
        """列出断点。"""
        return forward("dbg_list_bps", {}, port)
    
    @server.tool(description="Set breakpoint at address.")
    def dbg_set_bp(
        address: Annotated[str, Field(description="Breakpoint address")],
        port: Annotated[Optional[int], Field(description="Instance port override")] = None,
    ) -> Any:
        """设置断点。"""
        return forward("dbg_add_bp", {"addr": address}, port)
    
    @server.tool(description="Delete breakpoint at address.")
    def dbg_del_bp(
        address: Annotated[str, Field(description="Breakpoint address")],
        port: Annotated[Optional[int], Field(description="Instance port override")] = None,
    ) -> Any:
        """删除断点。"""
        return forward("dbg_delete_bp", {"addr": address}, port)
    
    @server.tool(description="Enable or disable breakpoint.")
    def dbg_enable_bp(
        address: Annotated[str, Field(description="Breakpoint address")],
        enable: Annotated[bool, Field(description="True to enable, False to disable")] = True,
        port: Annotated[Optional[int], Field(description="Instance port override")] = None,
    ) -> Any:
        """启用/禁用断点。"""
        return forward("dbg_enable_bp", {
            "items": [{"address": address, "enable": enable}]
        }, port)
    
    @server.tool(description="Set or delete breakpoint. action='set' or 'delete'.")
    def dbg_breakpoint(
        address: Annotated[str, Field(description="Breakpoint address")],
        action: Annotated[str, Field(description="'set' or 'delete'")] = "set",
        port: Annotated[Optional[int], Field(description="Instance port override")] = None,
    ) -> Any:
        """管理断点。"""
        tool = "dbg_add_bp" if action == "set" else "dbg_delete_bp"
        return forward(tool, {"addr": address}, port)

