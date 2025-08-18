"""IDA MCP 代理 (协调器客户端)

目的
====================
当外部 MCP 客户端 (如 IDE 插件 / LLM 工具) 只能通过“启动一个进程 + stdio/sse” 的形式接入时, 无法直接枚举多个 IDA 实例。本代理进程自身作为一个 FastMCP Server, 但内部并不执行逆向操作, 而是通过协调器 `/call` 将请求转发到目标 IDA 实例。

暴露工具
--------------------
    list_instances         – 获取当前所有已注册 IDA 实例 (由协调器返回)
    select_instance(port)  – 设置后续默认使用的实例端口 (若不指定自动选一个)
    check_connection       – 快速检测是否存在至少一个活跃实例
    ......

端口选择策略
--------------------
* 若未手动 select_instance, 自动优先选择 8765 (第一个常驻实例), 否则选择最早启动的实例。
* 切换实例只影响后续工具调用, 不影响协调器状态。

调用流程
--------------------
1. 客户端调用本代理的 tool (例如 list_functions)。
2. 代理确认/选择一个目标端口, 构造 body POST /call。
3. 协调器转发至对应 IDA 实例真正执行。
4. 返回的原始数据 (FunctionItem 列表等) 被协调器 JSON 化后再返回给客户端。

错误处理
--------------------
* 协调器不可达 / 超时: 返回 {"error": str(e)}。
* 没有实例: 返回 {"error": "No instances"}。
* 指定端口不存在: 返回 {"error": f"Port {port} not found"}。

可扩展点
--------------------
* 增加通用 forward(tool, params, port)
* 增加聚合/批量操作 (已根据需求删除 list_all_functions, 可随时恢复)
* 增加缓存/过滤/数据后处理

实现说明
--------------------
* 使用 urllib 标准库, 避免额外依赖。
* 超时严格 (GET 1 秒, CALL 5 秒) 防止阻塞。
* 内部维护 _current_port 作为默认目标。
"""
from __future__ import annotations
import json
import urllib.request
from typing import Optional, Dict, Any, List
from fastmcp import FastMCP

COORD_URL = "http://127.0.0.1:11337"
_current_port: Optional[int] = None

def _http_get(path: str) -> Any:
    try:
        with urllib.request.urlopen(COORD_URL + path, timeout=1) as r:  # type: ignore
            return json.loads(r.read().decode('utf-8') or 'null')
    except Exception:
        return None

def _http_post(path: str, obj: dict) -> Any:
    data = json.dumps(obj).encode('utf-8')
    req = urllib.request.Request(COORD_URL + path, data=data, method='POST', headers={'Content-Type': 'application/json'})
    try:
        with urllib.request.urlopen(req, timeout=5) as r:  # type: ignore
            return json.loads(r.read().decode('utf-8') or 'null')
    except Exception as e:
        return {"error": str(e)}

def _instances() -> List[Dict[str, Any]]:
    data = _http_get('/instances')
    return data if isinstance(data, list) else []

def _choose_default_port() -> Optional[int]:
    inst = _instances()
    if not inst:
        return None
    for e in inst:
        if e.get('port') == 8765:
            return 8765
    inst_sorted = sorted(inst, key=lambda x: x.get('started', 0))
    return inst_sorted[0].get('port')

def _ensure_port() -> Optional[int]:
    global _current_port
    if _current_port and any(e.get('port') == _current_port for e in _instances()):
        return _current_port
    _current_port = _choose_default_port()
    return _current_port

def _call(tool: str, params: dict | None = None, port: int | None = None) -> Any:
    body = {"tool": tool, "params": params or {}}
    if port is not None:
        body['port'] = port
    elif _ensure_port() is not None:
        body['port'] = _ensure_port()
    return _http_post('/call', body)

server = FastMCP(name="IDA-MCP-Proxy", instructions="Coordinator-based proxy forwarding tool calls via /call endpoint.")

@server.tool(description="Check if any IDA MCP instance is alive (ok/count).")
def check_connection() -> dict:  # type: ignore
    data = _http_get('/instances')
    if not isinstance(data, list):
        return {"ok": False, "count": 0}
    return {"ok": bool(data), "count": len(data)}

@server.tool(description="List registered IDA MCP instances (raw list, no filtering).")
def list_instances() -> list[dict]:  # type: ignore
    return _instances()

@server.tool(description="Select active backend instance port (auto-pick if omitted).")
def select_instance(port: int | None = None) -> dict:  # type: ignore
    global _current_port
    if port is None:
        port = _choose_default_port()
    if port is None:
        return {"error": "No instances"}
    if not any(e.get('port') == port for e in _instances()):
        return {"error": f"Port {port} not found"}
    _current_port = port
    return {"selected_port": port}

@server.tool(description="List functions via selected instance (forwarded through coordinator).")
def list_functions() -> Any:  # type: ignore
    p = _ensure_port()
    if p is None:
        return {"error": "No instances"}
    res = _call('list_functions', {}, port=p)
    return res.get('data') if isinstance(res, dict) else res

@server.tool(description="Get metadata via selected or specified instance (forwarded through coordinator).")
def get_metadata(port: int | None = None) -> Any:  # type: ignore
    """获取某个实例的元数据 (默认使用当前选中实例)。

    参数:
        port: 可选指定实例端口; 未提供则使用已选端口或自动选择。
    返回:
        get_metadata 工具返回的字典; 若实例不可用返回错误字典。
    """
    target = port if port is not None else _ensure_port()
    if target is None:
        return {"error": "No instances"}
    res = _call('get_metadata', {}, port=target)
    return res.get('data') if isinstance(res, dict) else res

@server.tool(description="Get cross references TO a given address (forwarded).")
def get_xrefs_to(address: int, port: int | None = None) -> Any:  # type: ignore
    if address is None:
        return {"error": "invalid address"}
    target = port if port is not None else _ensure_port()
    if target is None:
        return {"error": "No instances"}
    res = _call('get_xrefs_to', {"address": address}, port=target)
    return res.get('data') if isinstance(res, dict) else res

@server.tool(description="Heuristically find code references mentioning a struct field (forwarded).")
def get_xrefs_to_field(struct_name: str, field_name: str, port: int | None = None) -> Any:  # type: ignore
    if not struct_name or not field_name:
        return {"error": "empty struct_name or field_name"}
    target = port if port is not None else _ensure_port()
    if target is None:
        return {"error": "No instances"}
    res = _call('get_xrefs_to_field', {"struct_name": struct_name, "field_name": field_name}, port=target)
    return res.get('data') if isinstance(res, dict) else res

@server.tool(description="Set a comment for a given address (forwarded).")
def set_comment(address: int, comment: str, port: int | None = None) -> Any:  # type: ignore
    if address is None:
        return {"error": "invalid address"}
    if comment is None:
        return {"error": "comment is None"}
    target = port if port is not None else _ensure_port()
    if target is None:
        return {"error": "No instances"}
    res = _call('set_comment', {"address": address, "comment": comment}, port=target)
    return res.get('data') if isinstance(res, dict) else res

@server.tool(description="Rename a local variable in a function (forwarded, requires Hex-Rays).")
def rename_local_variable(function_address: int, old_name: str, new_name: str, port: int | None = None) -> Any:  # type: ignore
    if function_address is None:
        return {"error": "invalid function_address"}
    if not old_name:
        return {"error": "empty old_name"}
    if not new_name:
        return {"error": "empty new_name"}
    target = port if port is not None else _ensure_port()
    if target is None:
        return {"error": "No instances"}
    res = _call('rename_local_variable', {"function_address": function_address, "old_name": old_name, "new_name": new_name}, port=target)
    return res.get('data') if isinstance(res, dict) else res

@server.tool(description="Rename a global variable (forwarded).")
def rename_global_variable(old_name: str, new_name: str, port: int | None = None) -> Any:  # type: ignore
    if not old_name:
        return {"error": "empty old_name"}
    if not new_name:
        return {"error": "empty new_name"}
    target = port if port is not None else _ensure_port()
    if target is None:
        return {"error": "No instances"}
    res = _call('rename_global_variable', {"old_name": old_name, "new_name": new_name}, port=target)
    return res.get('data') if isinstance(res, dict) else res

@server.tool(description="Rename a function by address (forwarded).")
def rename_function(function_address: int, new_name: str, port: int | None = None) -> Any:  # type: ignore
    if function_address is None:
        return {"error": "invalid function_address"}
    if not new_name:
        return {"error": "empty new_name"}
    target = port if port is not None else _ensure_port()
    if target is None:
        return {"error": "No instances"}
    res = _call('rename_function', {"function_address": function_address, "new_name": new_name}, port=target)
    return res.get('data') if isinstance(res, dict) else res

@server.tool(description="Set a function prototype (forwarded).")
def set_function_prototype(function_address: int, prototype: str, port: int | None = None) -> Any:  # type: ignore
    if function_address is None:
        return {"error": "invalid function_address"}
    if not prototype:
        return {"error": "empty prototype"}
    target = port if port is not None else _ensure_port()
    if target is None:
        return {"error": "No instances"}
    res = _call('set_function_prototype', {"function_address": function_address, "prototype": prototype}, port=target)
    return res.get('data') if isinstance(res, dict) else res

@server.tool(description="Set the type of a local variable in a function (forwarded, requires Hex-Rays).")
def set_local_variable_type(function_address: int, variable_name: str, new_type: str, port: int | None = None) -> Any:  # type: ignore
    if function_address is None:
        return {"error": "invalid function_address"}
    if not variable_name:
        return {"error": "empty variable_name"}
    if not new_type:
        return {"error": "empty new_type"}
    target = port if port is not None else _ensure_port()
    if target is None:
        return {"error": "No instances"}
    res = _call('set_local_variable_type', {"function_address": function_address, "variable_name": variable_name, "new_type": new_type}, port=target)
    return res.get('data') if isinstance(res, dict) else res

@server.tool(description="Get a function by its name (forwarded through coordinator).")
def get_function_by_name(name: str, port: int | None = None) -> Any:  # type: ignore
    if not name:
        return {"error": "empty name"}
    target = port if port is not None else _ensure_port()
    if target is None:
        return {"error": "No instances"}
    res = _call('get_function_by_name', {"name": name}, port=target)
    return res.get('data') if isinstance(res, dict) else res

@server.tool(description="Get a function by its address (forwarded through coordinator).")
def get_function_by_address(address: int, port: int | None = None) -> Any:  # type: ignore
    if address is None:
        return {"error": "invalid address"}
    target = port if port is not None else _ensure_port()
    if target is None:
        return {"error": "No instances"}
    res = _call('get_function_by_address', {"address": address}, port=target)
    return res.get('data') if isinstance(res, dict) else res

@server.tool(description="Get the address currently selected by the user (forwarded through coordinator).")
def get_current_address(port: int | None = None) -> Any:  # type: ignore
    target = port if port is not None else _ensure_port()
    if target is None:
        return {"error": "No instances"}
    res = _call('get_current_address', {}, port=target)
    return res.get('data') if isinstance(res, dict) else res

@server.tool(description="Get the function currently selected by the user (forwarded through coordinator).")
def get_current_function(port: int | None = None) -> Any:  # type: ignore
    target = port if port is not None else _ensure_port()
    if target is None:
        return {"error": "No instances"}
    res = _call('get_current_function', {}, port=target)
    return res.get('data') if isinstance(res, dict) else res

@server.tool(description="Convert a number (decimal/hex/binary) into multiple representations (forwarded through coordinator).")
def convert_number(text: str, size: int, port: int | None = None) -> Any:  # type: ignore
    target = port if port is not None else _ensure_port()
    if target is None:
        return {"error": "No instances"}
    res = _call('convert_number', {"text": text, "size": size}, port=target)
    return res.get('data') if isinstance(res, dict) else res

@server.tool(description="List matching global symbols (non-function names) with pagination and optional substring filter (forwarded).")
def list_globals_filter(offset: int, count: int, filter: str | None = None, port: int | None = None) -> Any:  # type: ignore
    target = port if port is not None else _ensure_port()
    if target is None:
        return {"error": "No instances"}
    res = _call('list_globals_filter', {"offset": offset, "count": count, "filter": filter}, port=target)
    return res.get('data') if isinstance(res, dict) else res

@server.tool(description="List global symbols (non-function names) with pagination (forwarded).")
def list_globals(offset: int, count: int, port: int | None = None) -> Any:  # type: ignore
    target = port if port is not None else _ensure_port()
    if target is None:
        return {"error": "No instances"}
    res = _call('list_globals', {"offset": offset, "count": count}, port=target)
    return res.get('data') if isinstance(res, dict) else res

@server.tool(description="List matching strings with pagination and optional substring filter (forwarded).")
def list_strings_filter(offset: int, count: int, filter: str | None = None, port: int | None = None) -> Any:  # type: ignore
    target = port if port is not None else _ensure_port()
    if target is None:
        return {"error": "No instances"}
    res = _call('list_strings_filter', {"offset": offset, "count": count, "filter": filter}, port=target)
    return res.get('data') if isinstance(res, dict) else res

@server.tool(description="List strings with pagination (forwarded).")
def list_strings(offset: int, count: int, port: int | None = None) -> Any:  # type: ignore
    target = port if port is not None else _ensure_port()
    if target is None:
        return {"error": "No instances"}
    res = _call('list_strings', {"offset": offset, "count": count}, port=target)
    return res.get('data') if isinstance(res, dict) else res

@server.tool(description="List all local types defined in the IDB (forwarded).")
def list_local_types(port: int | None = None) -> Any:  # type: ignore
    target = port if port is not None else _ensure_port()
    if target is None:
        return {"error": "No instances"}
    res = _call('list_local_types', {}, port=target)
    return res.get('data') if isinstance(res, dict) else res

@server.tool(description="Decompile a function at the given address (forwarded, requires Hex-Rays).")
def decompile_function(address: int, port: int | None = None) -> Any:  # type: ignore
    if address is None:
        return {"error": "invalid address"}
    target = port if port is not None else _ensure_port()
    if target is None:
        return {"error": "No instances"}
    res = _call('decompile_function', {"address": address}, port=target)
    return res.get('data') if isinstance(res, dict) else res

@server.tool(description="Disassemble a function and return list of instructions (forwarded).")
def disassemble_function(start_address: int, port: int | None = None) -> Any:  # type: ignore
    if start_address is None:
        return {"error": "invalid address"}
    target = port if port is not None else _ensure_port()
    if target is None:
        return {"error": "No instances"}
    res = _call('disassemble_function', {"start_address": start_address}, port=target)
    return res.get('data') if isinstance(res, dict) else res

@server.tool(description="Get all entry points (forwarded).")
def get_entry_points(port: int | None = None) -> Any:  # type: ignore
    target = port if port is not None else _ensure_port()
    if target is None:
        return {"error": "No instances"}
    res = _call('get_entry_points', {}, port=target)
    return res.get('data') if isinstance(res, dict) else res

@server.tool(description="Set a global variable's type (forwarded).")
def set_global_variable_type(variable_name: str, new_type: str, port: int | None = None) -> Any:  # type: ignore
    if not variable_name:
        return {"error": "empty variable_name"}
    if not new_type:
        return {"error": "empty new_type"}
    target = port if port is not None else _ensure_port()
    if target is None:
        return {"error": "No instances"}
    res = _call('set_global_variable_type', {"variable_name": variable_name, "new_type": new_type}, port=target)
    return res.get('data') if isinstance(res, dict) else res

@server.tool(description="Declare or update a local type from a C declaration (forwarded).")
def declare_c_type(c_declaration: str, port: int | None = None) -> Any:  # type: ignore
    if not c_declaration:
        return {"error": "empty declaration"}
    target = port if port is not None else _ensure_port()
    if target is None:
        return {"error": "No instances"}
    res = _call('declare_c_type', {"c_declaration": c_declaration}, port=target)
    return res.get('data') if isinstance(res, dict) else res

@server.tool(description="Get all registers and their values when debugging (forwarded).")
def dbg_get_registers(port: int | None = None) -> Any:  # type: ignore
    target = port if port is not None else _ensure_port()
    if target is None:
        return {"error": "No instances"}
    res = _call('dbg_get_registers', {}, port=target)
    return res.get('data') if isinstance(res, dict) else res

@server.tool(description="Get the current call stack when debugging (forwarded).")
def dbg_get_call_stack(port: int | None = None) -> Any:  # type: ignore
    target = port if port is not None else _ensure_port()
    if target is None:
        return {"error": "No instances"}
    res = _call('dbg_get_call_stack', {}, port=target)
    return res.get('data') if isinstance(res, dict) else res

@server.tool(description="List all breakpoints (forwarded).")
def dbg_list_breakpoints(port: int | None = None) -> Any:  # type: ignore
    target = port if port is not None else _ensure_port()
    if target is None:
        return {"error": "No instances"}
    res = _call('dbg_list_breakpoints', {}, port=target)
    return res.get('data') if isinstance(res, dict) else res

@server.tool(description="Start the debugger (forwarded).")
def dbg_start_process(port: int | None = None) -> Any:  # type: ignore
    target = port if port is not None else _ensure_port()
    if target is None:
        return {"error": "No instances"}
    res = _call('dbg_start_process', {}, port=target)
    return res.get('data') if isinstance(res, dict) else res

@server.tool(description="Exit the debugger (forwarded).")
def dbg_exit_process(port: int | None = None) -> Any:  # type: ignore
    target = port if port is not None else _ensure_port()
    if target is None:
        return {"error": "No instances"}
    res = _call('dbg_exit_process', {}, port=target)
    return res.get('data') if isinstance(res, dict) else res

@server.tool(description="Continue the debugger (forwarded).")
def dbg_continue_process(port: int | None = None) -> Any:  # type: ignore
    target = port if port is not None else _ensure_port()
    if target is None:
        return {"error": "No instances"}
    res = _call('dbg_continue_process', {}, port=target)
    return res.get('data') if isinstance(res, dict) else res

@server.tool(description="Run to address (forwarded).")
def dbg_run_to(address: int, port: int | None = None) -> Any:  # type: ignore
    if address is None:
        return {"error": "invalid address"}
    target = port if port is not None else _ensure_port()
    if target is None:
        return {"error": "No instances"}
    res = _call('dbg_run_to', {"address": address}, port=target)
    return res.get('data') if isinstance(res, dict) else res

@server.tool(description="Set a breakpoint (forwarded).")
def dbg_set_breakpoint(address: int, port: int | None = None) -> Any:  # type: ignore
    if address is None:
        return {"error": "invalid address"}
    target = port if port is not None else _ensure_port()
    if target is None:
        return {"error": "No instances"}
    res = _call('dbg_set_breakpoint', {"address": address}, port=target)
    return res.get('data') if isinstance(res, dict) else res

@server.tool(description="Delete a breakpoint (forwarded).")
def dbg_delete_breakpoint(address: int, port: int | None = None) -> Any:  # type: ignore
    if address is None:
        return {"error": "invalid address"}
    target = port if port is not None else _ensure_port()
    if target is None:
        return {"error": "No instances"}
    res = _call('dbg_delete_breakpoint', {"address": address}, port=target)
    return res.get('data') if isinstance(res, dict) else res

@server.tool(description="Enable or disable a breakpoint (forwarded).")
def dbg_enable_breakpoint(address: int, enable: bool, port: int | None = None) -> Any:  # type: ignore
    if address is None:
        return {"error": "invalid address"}
    target = port if port is not None else _ensure_port()
    if target is None:
        return {"error": "No instances"}
    res = _call('dbg_enable_breakpoint', {"address": address, "enable": bool(enable)}, port=target)
    return res.get('data') if isinstance(res, dict) else res

if __name__ == "__main__":
    # 直接运行: fastmcp 会自动选择 stdio/sse 传输方式 (默认 stdio)
    server.run()
