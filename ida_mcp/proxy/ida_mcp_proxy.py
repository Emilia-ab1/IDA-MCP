"""IDA MCP 代理 (协调器客户端) - 主程序入口

使用 stdio 传输的 MCP 服务器，通过协调器访问多个 IDA 实例。

架构
====================
proxy/
├── __init__.py           # 模块导出
├── ida_mcp_proxy.py      # 主程序入口 + 核心管理工具
├── _http.py              # HTTP 辅助函数
├── _state.py             # 状态管理和实例选择
├── proxy_core.py         # 核心工具: list_functions, metadata, strings
├── proxy_analysis.py     # 分析工具: decompile, disasm, xrefs
├── proxy_modify.py       # 修改工具: comment, rename
├── proxy_memory.py       # 内存工具: read_bytes, read_string
├── proxy_types.py        # 类型工具: set_func_type, declare_type
└── proxy_debug.py        # 调试工具: dbg_*

工具列表
====================
核心管理工具 (本文件定义):
    - check_connection    健康检查
    - list_instances      列出所有 IDA 实例
    - select_instance     选择默认实例

分类工具 (从各模块导入):
    - 核心: list_functions, metadata, strings, globals, local_types, entry_points
    - 分析: decompile, disasm, linear_disasm, xrefs_to, xrefs_from, lookup_function
    - 修改: comment, rename_function, rename_global, rename_local, rename
    - 内存: read_bytes, read_u32, read_u64, read_string, read_memory
    - 类型: set_func_type, set_local_type, set_global_type, declare_type
    - 调试: dbg_start, dbg_continue, dbg_step, dbg_regs, dbg_breakpoint, ...

使用方式
====================
直接运行: python ida_mcp_proxy.py
或模块运行: python -m ida_mcp.proxy.ida_mcp_proxy
"""
from __future__ import annotations

import sys
import os

from typing import Optional, Any, Annotated

try:
    from pydantic import Field
except ImportError:
    Field = lambda **kwargs: None  # type: ignore

from fastmcp import FastMCP

# 支持直接运行和作为包导入两种方式
_this_dir = os.path.dirname(os.path.abspath(__file__))
if _this_dir not in sys.path:
    sys.path.insert(0, _this_dir)

# 直接从当前目录导入 (无论是直接运行还是包导入都有效)
from _http import http_get, http_post  # type: ignore
from _state import (  # type: ignore
    get_instances, 
    is_valid_port, 
    get_current_port, 
    set_current_port,
)

# 导入工具注册函数
import proxy_core  # type: ignore
import proxy_analysis  # type: ignore
import proxy_modify  # type: ignore
import proxy_memory  # type: ignore
import proxy_types  # type: ignore
import proxy_debug  # type: ignore
import proxy_stack  # type: ignore


# ============================================================================
# FastMCP 服务器
# ============================================================================

server = FastMCP(
    name="IDA-MCP-Proxy",
    instructions="""IDA MCP 代理 - 通过协调器访问多个 IDA 实例。

核心管理:
- check_connection: 检查连接状态
- list_instances: 列出所有 IDA 实例
- select_instance: 选择要操作的实例

核心工具:
- list_functions, metadata, strings, globals, local_types, entry_points

分析工具:
- decompile, disasm, linear_disasm, xrefs_to, xrefs_from, lookup_function

修改工具:
- comment, rename_function, rename_global, rename_local

内存工具:
- read_bytes, read_u32, read_u64, read_string

类型工具:
- set_func_type, set_local_type, set_global_type, declare_type

调试工具:
- dbg_start, dbg_continue, dbg_step_into, dbg_step_over, dbg_regs
- dbg_set_bp, dbg_del_bp, dbg_list_breakpoints

栈帧工具:
- stack_frame, declare_stack, delete_stack

多实例时请先用 list_instances 查看可用实例，再用 select_instance 选择目标。
"""
)


# ============================================================================
# 核心管理工具
# ============================================================================

@server.tool(description="Health check. Returns {ok: bool, count: int} where count is number of registered IDA instances.")
def check_connection() -> dict:
    """检查协调器连接状态。"""
    data = http_get('/instances')
    if not isinstance(data, list):
        return {"ok": False, "count": 0}
    return {"ok": True, "count": len(data)}


@server.tool(description="List all registered IDA instances. Returns array of {id, port, pid, input_file, started, ...}.")
def list_instances() -> list:
    """列出所有已注册的 IDA 实例。"""
    return get_instances()


@server.tool(description="Select default IDA instance by port. If port omitted, auto-selects (prefer 8765). Returns {selected_port} or {error}.")
def select_instance(
    port: Annotated[Optional[int], Field(description="Target port; omit for auto-select")] = None
) -> dict:
    """选择默认目标实例。"""
    payload = {"port": port} if port is not None else {}
    res = http_post('/select_instance', payload)
    
    if isinstance(res, dict) and is_valid_port(res.get('selected_port')):
        set_current_port(int(res['selected_port']))
        return {"selected_port": get_current_port()}
    
    # 错误处理
    instances = get_instances()
    if not instances:
        return {"error": "No IDA instances available"}
    if port is not None and not any(i.get('port') == port for i in instances):
        return {"error": f"Port {port} not found in registered instances"}
    
    return {"error": "Failed to select instance"}


# ============================================================================
# 注册分类工具
# ============================================================================

proxy_core.register_tools(server)
proxy_analysis.register_tools(server)
proxy_modify.register_tools(server)
proxy_memory.register_tools(server)
proxy_types.register_tools(server)
proxy_debug.register_tools(server)
proxy_stack.register_tools(server)


# ============================================================================
# 入口
# ============================================================================

if __name__ == "__main__":
    import signal
    
    def _signal_handler(sig: int, frame: Any) -> None:
        """优雅退出。"""
        sys.exit(0)
    
    # 注册信号处理 (Windows 只支持 SIGINT)
    signal.signal(signal.SIGINT, _signal_handler)
    if hasattr(signal, 'SIGTERM'):
        signal.signal(signal.SIGTERM, _signal_handler)
    
    try:
        server.run()
    except KeyboardInterrupt:
        pass  # 静默退出
