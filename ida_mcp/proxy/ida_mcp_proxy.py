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
from typing import Optional, Dict, Any, List, Annotated
try:
    from pydantic import Field  # Pydantic v2
except Exception:  # pragma: no cover
    Field = lambda **kwargs: None  # type: ignore
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

@server.tool(description="Health check: no params. Queries coordinator /instances. Returns { ok:bool, count:int }. ok=true only if list retrieval succeeded (count may be 0). When multiple IDA instances are running, be sure to specify the correct port for your call to avoid invoking the wrong instance.")
def check_connection() -> dict:  # type: ignore
    data = _http_get('/instances')
    if not isinstance(data, list):
        return {"ok": False, "count": 0}
    return {"ok": bool(data), "count": len(data)}

@server.tool(description="List all registered backend instances (raw). No params. Returns array of instance dicts as provided by coordinator: [{ id,name,port,started,last_seen,meta?... }]. Empty array if none or fetch failed. When multiple IDA instances are running, be sure to specify the correct port for your call to avoid invoking the wrong instance.")
def list_instances() -> list[dict]:  # type: ignore
    return _instances()

@server.tool(description="Select default target instance. Param port(optional int). If omitted auto-picks: prefer 8765 else earliest started. Returns { selected_port } or { error }. Subsequent calls without explicit port use this. When multiple IDA instances are running, be sure to specify the correct port for your call to avoid invoking the wrong instance.")
def select_instance(
    port: Annotated[int | None, Field(description="Target instance port to select; if omitted auto-picks preferred (8765 or earliest)")] = None
) -> dict:  # type: ignore
    global _current_port
    if port is None:
        port = _choose_default_port()
    if port is None:
        return {"error": "No instances"}
    if not any(e.get('port') == port for e in _instances()):
        return {"error": f"Port {port} not found"}
    _current_port = port
    return {"selected_port": port}

@server.tool(description="List functions. No params. Forwards to selected instance list_functions; auto-selects instance if none chosen. Returns underlying tool data or { error } if no instances. When multiple IDA instances are running, be sure to specify the correct port for your call to avoid invoking the wrong instance.")
def list_functions() -> Any:  # type: ignore
    p = _ensure_port()
    if p is None:
        return {"error": "No instances"}
    res = _call('list_functions', {}, port=p)
    return res.get('data') if isinstance(res, dict) else res

@server.tool(description="Get IDB metadata. Param port(optional) overrides current selection. Returns underlying get_metadata dict { input_file,arch,bits,hash,... } or { error }. Auto-selects instance if needed. When multiple IDA instances are running, be sure to specify the correct port for your call to avoid invoking the wrong instance.")
def get_metadata(
    port: Annotated[int | None, Field(description="Override target instance port; defaults to selected/auto-chosen")]= None
) -> Any:  # type: ignore
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

@server.tool(description="Incoming xrefs: params address(int), port(optional). Returns underlying { address,total,xrefs } or { error }. Passes address through unchanged. When multiple IDA instances are running, be sure to specify the correct port for your call to avoid invoking the wrong instance.")
def get_xrefs_to(
    address: Annotated[int, Field(description="Target address inside backend IDB")],
    port: Annotated[int | None, Field(description="Optional instance port override")]= None
) -> Any:  # type: ignore
    if address is None:
        return {"error": "invalid address"}
    target = port if port is not None else _ensure_port()
    if target is None:
        return {"error": "No instances"}
    res = _call('get_xrefs_to', {"address": address}, port=target)
    return res.get('data') if isinstance(res, dict) else res

@server.tool(description="Heuristic struct field refs: params struct_name, field_name, port(optional). Returns underlying { struct,field,offset,matches,... } or { error }. Same limitations as backend (heuristic, truncated at 500). When multiple IDA instances are running, be sure to specify the correct port for your call to avoid invoking the wrong instance.")
def get_xrefs_to_field(
    struct_name: Annotated[str, Field(description="Struct name (as defined in Local Types)")],
    field_name: Annotated[str, Field(description="Exact field name within the struct")],
    port: Annotated[int | None, Field(description="Optional instance port override")]= None
) -> Any:  # type: ignore
    if not struct_name or not field_name:
        return {"error": "empty struct_name or field_name"}
    target = port if port is not None else _ensure_port()
    if target is None:
        return {"error": "No instances"}
    res = _call('get_xrefs_to_field', {"struct_name": struct_name, "field_name": field_name}, port=target)
    return res.get('data') if isinstance(res, dict) else res

@server.tool(description="Set/clear comment: params address(int|string), comment(str, empty => clear), port(optional). Accepts 0x / decimal / trailing h / underscores. Returns backend { address,old,new,changed } or { error }. Non-repeatable comment. When multiple IDA instances are running, be sure to specify the correct port for your call to avoid invoking the wrong instance.")
def set_comment(
    address: Annotated[int | str, Field(description="Target address (int or string: 0x..., 1234, 401000h, 0x40_10_00)")],
    comment: Annotated[str, Field(description="Comment text; empty string clears (max 1024 chars in backend)")],
    port: Annotated[int | None, Field(description="Optional instance port override")]= None
) -> Any:  # type: ignore
    if address is None:
        return {"error": "invalid address"}
    if comment is None:
        return {"error": "comment is None"}
    target = port if port is not None else _ensure_port()
    if target is None:
        return {"error": "No instances"}
    res = _call('set_comment', {"address": address, "comment": comment}, port=target)
    return res.get('data') if isinstance(res, dict) else res

@server.tool(description="Rename local variable (Hex-Rays): params function_address, old_name, new_name, port(optional). Returns backend { function,start_ea,old_name,new_name,changed } or { error }. Auto-select instance. When multiple IDA instances are running, be sure to specify the correct port for your call to avoid invoking the wrong instance.")
def rename_local_variable(
    function_address: Annotated[int, Field(description="Function start or any internal address")],
    old_name: Annotated[str, Field(description="Existing local variable name (exact match)")],
    new_name: Annotated[str, Field(description="New local variable name (valid C identifier)")],
    port: Annotated[int | None, Field(description="Optional instance port override")]= None
) -> Any:  # type: ignore
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

@server.tool(description="Rename global variable: params old_name,new_name, port(optional). Returns backend { ea,old_name,new_name,changed } or { error }. Rejects function starts. When multiple IDA instances are running, be sure to specify the correct port for your call to avoid invoking the wrong instance.")
def rename_global_variable(
    old_name: Annotated[str, Field(description="Existing global symbol name")],
    new_name: Annotated[str, Field(description="New symbol name (valid C identifier)")],
    port: Annotated[int | None, Field(description="Optional instance port override")]= None
) -> Any:  # type: ignore
    if not old_name:
        return {"error": "empty old_name"}
    if not new_name:
        return {"error": "empty new_name"}
    target = port if port is not None else _ensure_port()
    if target is None:
        return {"error": "No instances"}
    res = _call('rename_global_variable', {"old_name": old_name, "new_name": new_name}, port=target)
    return res.get('data') if isinstance(res, dict) else res

@server.tool(description="Rename function: params function_address(start or inside), new_name, port(optional). Returns backend { start_ea,old_name,new_name,changed } or { error }. When multiple IDA instances are running, be sure to specify the correct port for your call to avoid invoking the wrong instance.")
def rename_function(
    function_address: Annotated[int, Field(description="Function start or internal address")],
    new_name: Annotated[str, Field(description="New function name (valid C identifier)")],
    port: Annotated[int | None, Field(description="Optional instance port override")]= None
) -> Any:  # type: ignore
    if function_address is None:
        return {"error": "invalid function_address"}
    if not new_name:
        return {"error": "empty new_name"}
    target = port if port is not None else _ensure_port()
    if target is None:
        return {"error": "No instances"}
    res = _call('rename_function', {"function_address": function_address, "new_name": new_name}, port=target)
    return res.get('data') if isinstance(res, dict) else res

@server.tool(description="Set function prototype: params function_address, prototype(C decl), port(optional). Returns backend { start_ea,applied,old_type,new_type,parsed_name? } or { error }. When multiple IDA instances are running, be sure to specify the correct port for your call to avoid invoking the wrong instance.")
def set_function_prototype(
    function_address: Annotated[int, Field(description="Function start or internal address")],
    prototype: Annotated[str, Field(description="Full C function declaration text")],
    port: Annotated[int | None, Field(description="Optional instance port override")]= None
) -> Any:  # type: ignore
    if function_address is None:
        return {"error": "invalid function_address"}
    if not prototype:
        return {"error": "empty prototype"}
    target = port if port is not None else _ensure_port()
    if target is None:
        return {"error": "No instances"}
    res = _call('set_function_prototype', {"function_address": function_address, "prototype": prototype}, port=target)
    return res.get('data') if isinstance(res, dict) else res

@server.tool(description="Set local variable type (Hex-Rays): params function_address, variable_name, new_type(C fragment), port(optional). Returns backend { function,start_ea,variable_name,old_type,new_type,applied } or { error }. When multiple IDA instances are running, be sure to specify the correct port for your call to avoid invoking the wrong instance.")
def set_local_variable_type(
    function_address: Annotated[int, Field(description="Function start or internal address")],
    variable_name: Annotated[str, Field(description="Local variable name (exact match)")],
    new_type: Annotated[str, Field(description="C type fragment (e.g. int, MyStruct *)")],
    port: Annotated[int | None, Field(description="Optional instance port override")]= None
) -> Any:  # type: ignore
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

@server.tool(description="Get function by name: params name(str), port(optional). Returns backend { name,start_ea,end_ea } or { error }. Exact case-sensitive match. When multiple IDA instances are running, be sure to specify the correct port for your call to avoid invoking the wrong instance.")
def get_function_by_name(
    name: Annotated[str, Field(description="Exact function name (case-sensitive)")],
    port: Annotated[int | None, Field(description="Optional instance port override")]= None
) -> Any:  # type: ignore
    if not name:
        return {"error": "empty name"}
    target = port if port is not None else _ensure_port()
    if target is None:
        return {"error": "No instances"}
    res = _call('get_function_by_name', {"name": name}, port=target)
    return res.get('data') if isinstance(res, dict) else res

@server.tool(description="Get function by address: param address accepts INT or STRING (decimal or hex). Formats: 1234, 0x401000, 401000h, 0x40_10_00 (underscores). param port(optional). Forwards to backend get_function_by_address. Returns backend { name,start_ea,end_ea,input,address } or { error }. Inside-function addresses allowed. Parse/validation occurs in backend; proxy just forwards raw value. When multiple IDA instances are running, be sure to specify the correct port for your call to avoid invoking the wrong instance.")
def get_function_by_address(
    address: Annotated[int | str, Field(description="Function start or internal address (int or string: decimal/0x.../....h)")],
    port: Annotated[int | None, Field(description="Optional instance port override")]= None
) -> Any:  # type: ignore
    if address is None:
        return {"error": "invalid address"}
    target = port if port is not None else _ensure_port()
    if target is None:
        return {"error": "No instances"}
    res = _call('get_function_by_address', {"address": address}, port=target)
    return res.get('data') if isinstance(res, dict) else res

@server.tool(description="Get current cursor address: param port(optional). Returns backend { address } or { error }. Depends on GUI focus in target instance. When multiple IDA instances are running, be sure to specify the correct port for your call to avoid invoking the wrong instance.")
def get_current_address(
    port: Annotated[int | None, Field(description="Optional instance port override")]= None
) -> Any:  # type: ignore
    target = port if port is not None else _ensure_port()
    if target is None:
        return {"error": "No instances"}
    res = _call('get_current_address', {}, port=target)
    return res.get('data') if isinstance(res, dict) else res

@server.tool(description="Get current function at cursor: param port(optional). Returns backend { name,start_ea,end_ea } or { error }. Uses screen EA in target instance. When multiple IDA instances are running, be sure to specify the correct port for your call to avoid invoking the wrong instance.")
def get_current_function(
    port: Annotated[int | None, Field(description="Optional instance port override")]= None
) -> Any:  # type: ignore
    target = port if port is not None else _ensure_port()
    if target is None:
        return {"error": "No instances"}
    res = _call('get_current_function', {}, port=target)
    return res.get('data') if isinstance(res, dict) else res

@server.tool(description="Convert number representations: params text(str), size(8|16|32|64), port(optional). Returns backend multi-format dict or { error }. Supports 0x / 0b / trailing h / underscores / sign. When multiple IDA instances are running, be sure to specify the correct port for your call to avoid invoking the wrong instance.")
def convert_number(
    text: Annotated[str, Field(description="Numeric text to parse (decimal, 0x, 0b, trailing h, underscores, sign)")],
    size: Annotated[int, Field(description="Bit width: 8|16|32|64")],
    port: Annotated[int | None, Field(description="Optional instance port override")]= None
) -> Any:  # type: ignore
    target = port if port is not None else _ensure_port()
    if target is None:
        return {"error": "No instances"}
    res = _call('convert_number', {"text": text, "size": size}, port=target)
    return res.get('data') if isinstance(res, dict) else res

@server.tool(description="List global symbols (filtered): params offset>=0, count(1..1000), filter(optional substring), port(optional). Returns backend { total,offset,count,items }. Skips function starts. When multiple IDA instances are running, be sure to specify the correct port for your call to avoid invoking the wrong instance.")
def list_globals_filter(
    offset: Annotated[int, Field(description="Pagination start offset (>=0)")],
    count: Annotated[int, Field(description="Number of items to return (1..1000)")],
    filter: Annotated[str | None, Field(description="Optional case-insensitive name substring")]= None,
    port: Annotated[int | None, Field(description="Optional instance port override")]= None
) -> Any:  # type: ignore
    target = port if port is not None else _ensure_port()
    if target is None:
        return {"error": "No instances"}
    res = _call('list_globals_filter', {"offset": offset, "count": count, "filter": filter}, port=target)
    return res.get('data') if isinstance(res, dict) else res

@server.tool(description="List global symbols: params offset,count, port(optional). Returns backend { total,offset,count,items }. Unfiltered. When multiple IDA instances are running, be sure to specify the correct port for your call to avoid invoking the wrong instance.")
def list_globals(
    offset: Annotated[int, Field(description="Pagination start offset (>=0)")],
    count: Annotated[int, Field(description="Number of items to return (1..1000)")],
    port: Annotated[int | None, Field(description="Optional instance port override")]= None
) -> Any:  # type: ignore
    target = port if port is not None else _ensure_port()
    if target is None:
        return {"error": "No instances"}
    res = _call('list_globals', {"offset": offset, "count": count}, port=target)
    return res.get('data') if isinstance(res, dict) else res

@server.tool(description="List strings (filtered): params offset,count, filter(optional substring), port(optional). Returns backend { total,offset,count,items }. Auto-inits Strings. When multiple IDA instances are running, be sure to specify the correct port for your call to avoid invoking the wrong instance.")
def list_strings_filter(
    offset: Annotated[int, Field(description="Pagination start offset (>=0)")],
    count: Annotated[int, Field(description="Number of items to return (1..1000)")],
    filter: Annotated[str | None, Field(description="Optional case-insensitive substring")]= None,
    port: Annotated[int | None, Field(description="Optional instance port override")]= None
) -> Any:  # type: ignore
    target = port if port is not None else _ensure_port()
    if target is None:
        return {"error": "No instances"}
    res = _call('list_strings_filter', {"offset": offset, "count": count, "filter": filter}, port=target)
    return res.get('data') if isinstance(res, dict) else res

@server.tool(description="List strings: params offset,count, port(optional). Returns backend { total,offset,count,items }. No filtering. When multiple IDA instances are running, be sure to specify the correct port for your call to avoid invoking the wrong instance.")
def list_strings(
    offset: Annotated[int, Field(description="Pagination start offset (>=0)")],
    count: Annotated[int, Field(description="Number of items to return (1..1000)")],
    port: Annotated[int | None, Field(description="Optional instance port override")]= None
) -> Any:  # type: ignore
    target = port if port is not None else _ensure_port()
    if target is None:
        return {"error": "No instances"}
    res = _call('list_strings', {"offset": offset, "count": count}, port=target)
    return res.get('data') if isinstance(res, dict) else res

@server.tool(description="List local types: param port(optional). Returns backend { total,items:[{ ordinal,name,decl }] }. decl truncated per backend logic. When multiple IDA instances are running, be sure to specify the correct port for your call to avoid invoking the wrong instance.")
def list_local_types(
    port: Annotated[int | None, Field(description="Optional instance port override")]= None
) -> Any:  # type: ignore
    target = port if port is not None else _ensure_port()
    if target is None:
        return {"error": "No instances"}
    res = _call('list_local_types', {}, port=target)
    return res.get('data') if isinstance(res, dict) else res

@server.tool(description="Decompile function (Hex-Rays): params address(int), port(optional). Returns backend { name,start_ea,end_ea,address,decompiled } or { error }. Large text untruncated. When multiple IDA instances are running, be sure to specify the correct port for your call to avoid invoking the wrong instance.")
def decompile_function(
    address: Annotated[int, Field(description="Function start or internal address to decompile")],
    port: Annotated[int | None, Field(description="Optional instance port override")]= None
) -> Any:  # type: ignore
    if address is None:
        return {"error": "invalid address"}
    target = port if port is not None else _ensure_port()
    if target is None:
        return {"error": "No instances"}
    res = _call('decompile_function', {"address": address}, port=target)
    return res.get('data') if isinstance(res, dict) else res

@server.tool(description="Disassemble function: params start_address(int), port(optional). Returns backend { name,start_ea,end_ea,instructions:[...]} or { error }. Bytes truncated after 16 bytes. When multiple IDA instances are running, be sure to specify the correct port for your call to avoid invoking the wrong instance.")
def disassemble_function(
    start_address: Annotated[int, Field(description="Function start (internal address allowed)")],
    port: Annotated[int | None, Field(description="Optional instance port override")]= None
) -> Any:  # type: ignore
    if start_address is None:
        return {"error": "invalid address"}
    target = port if port is not None else _ensure_port()
    if target is None:
        return {"error": "No instances"}
    res = _call('disassemble_function', {"start_address": start_address}, port=target)
    return res.get('data') if isinstance(res, dict) else res

@server.tool(description="Linear disassemble: params start_address(int|string), count(1..64), port(optional). start_address accepts 0x / decimal / trailing h / underscores. Returns backend { start_address,count,instructions:[{ ea,bytes,text,comment,is_code,len }],truncated? } or { error }. Works outside functions. When multiple IDA instances are running, be sure to specify the correct port for your call to avoid invoking the wrong instance.")
def linear_disassemble(
    start_address: Annotated[int | str, Field(description="Starting linear address (int or string: 0x..., 1234, 401000h)")],
    count: Annotated[int, Field(description="Max instruction count (1..64)")],
    port: Annotated[int | None, Field(description="Optional instance port override")]= None
) -> Any:  # type: ignore
    """线性反汇编转发。

    参数:
        start_address: 起始线性地址 (可在函数外)。
        count: 需要的最大指令条数 (1..64)。
        port: 可选实例端口。
    返回 (后端原样):
        { start_address, count, instructions:[ { ea, bytes, text, comment, is_code, len } ... ], truncated? }
        或 { error }。
    说明:
        * 不做本地再解析, 直接转发给后端 IDA 实例。
        * 如果起点落在一条指令中间, 后端第一条可能 size=0 或 is_code=false。
    """
    if start_address is None:
        return {"error": "invalid start_address"}
    if count is None:
        return {"error": "invalid count"}
    target = port if port is not None else _ensure_port()
    if target is None:
        return {"error": "No instances"}
    res = _call('linear_disassemble', {"start_address": start_address, "count": count}, port=target)
    return res.get('data') if isinstance(res, dict) else res

@server.tool(description="List entry points: param port(optional). Returns backend { total,items:[{ ordinal,ea,name }] } or { error }. Name fallback logic done in backend. When multiple IDA instances are running, be sure to specify the correct port for your call to avoid invoking the wrong instance.")
def get_entry_points(
    port: Annotated[int | None, Field(description="Optional instance port override")]= None
) -> Any:  # type: ignore
    target = port if port is not None else _ensure_port()
    if target is None:
        return {"error": "No instances"}
    res = _call('get_entry_points', {}, port=target)
    return res.get('data') if isinstance(res, dict) else res

@server.tool(description="Set global variable type: params variable_name,new_type(C fragment), port(optional). Returns backend { ea,variable_name,old_type,new_type,applied } or { error }. Rejects function starts. When multiple IDA instances are running, be sure to specify the correct port for your call to avoid invoking the wrong instance.")
def set_global_variable_type(
    variable_name: Annotated[str, Field(description="Existing global variable name (not a function start)")],
    new_type: Annotated[str, Field(description="C type fragment (e.g. int, char *, MyStruct)")],
    port: Annotated[int | None, Field(description="Optional instance port override")]= None
) -> Any:  # type: ignore
    if not variable_name:
        return {"error": "empty variable_name"}
    if not new_type:
        return {"error": "empty new_type"}
    target = port if port is not None else _ensure_port()
    if target is None:
        return {"error": "No instances"}
    res = _call('set_global_variable_type', {"variable_name": variable_name, "new_type": new_type}, port=target)
    return res.get('data') if isinstance(res, dict) else res

@server.tool(description="Declare/update local type: params c_declaration(single struct/union/enum/typedef), port(optional). Returns backend { name,kind,replaced,success } or { error }. Replaces existing by name. When multiple IDA instances are running, be sure to specify the correct port for your call to avoid invoking the wrong instance.")
def declare_c_type(
    c_declaration: Annotated[str, Field(description="Single struct/union/enum/typedef declaration text")],
    port: Annotated[int | None, Field(description="Optional instance port override")]= None
) -> Any:  # type: ignore
    if not c_declaration:
        return {"error": "empty declaration"}
    target = port if port is not None else _ensure_port()
    if target is None:
        return {"error": "No instances"}
    res = _call('declare_c_type', {"c_declaration": c_declaration}, port=target)
    return res.get('data') if isinstance(res, dict) else res

@server.tool(description="Debugger registers: param port(optional). Returns backend { ok,registers:[{ name,value,int? }],note? } or { error }. ok=false if debugger inactive. When multiple IDA instances are running, be sure to specify the correct port for your call to avoid invoking the wrong instance.")
def dbg_get_registers(
    port: Annotated[int | None, Field(description="Optional instance port override")]= None
) -> Any:  # type: ignore
    target = port if port is not None else _ensure_port()
    if target is None:
        return {"error": "No instances"}
    res = _call('dbg_get_registers', {}, port=target)
    return res.get('data') if isinstance(res, dict) else res

@server.tool(description="Debugger call stack: param port(optional). Returns backend { ok,frames:[{ index,ea,func }],note? } or { error }. Inactive => ok=false. When multiple IDA instances are running, be sure to specify the correct port for your call to avoid invoking the wrong instance.")
def dbg_get_call_stack(
    port: Annotated[int | None, Field(description="Optional instance port override")]= None
) -> Any:  # type: ignore
    target = port if port is not None else _ensure_port()
    if target is None:
        return {"error": "No instances"}
    res = _call('dbg_get_call_stack', {}, port=target)
    return res.get('data') if isinstance(res, dict) else res

@server.tool(description="List breakpoints: param port(optional). Returns backend { ok,total,breakpoints:[...] } or { error }. ok=false if debugger inactive. When multiple IDA instances are running, be sure to specify the correct port for your call to avoid invoking the wrong instance.")
def dbg_list_breakpoints(
    port: Annotated[int | None, Field(description="Optional instance port override")]= None
) -> Any:  # type: ignore
    target = port if port is not None else _ensure_port()
    if target is None:
        return {"error": "No instances"}
    res = _call('dbg_list_breakpoints', {}, port=target)
    return res.get('data') if isinstance(res, dict) else res

@server.tool(description="Start debugger: param port(optional). Returns backend { ok,started,pid?,note? } or { error }. If already running started=false with note. When multiple IDA instances are running, be sure to specify the correct port for your call to avoid invoking the wrong instance.")
def dbg_start_process(
    port: Annotated[int | None, Field(description="Optional instance port override")]= None
) -> Any:  # type: ignore
    target = port if port is not None else _ensure_port()
    if target is None:
        return {"error": "No instances"}
    res = _call('dbg_start_process', {}, port=target)
    return res.get('data') if isinstance(res, dict) else res

@server.tool(description="Terminate debug process: param port(optional). Returns backend { ok,exited,note? } or { error }. Inactive => ok:false,exited:false. When multiple IDA instances are running, be sure to specify the correct port for your call to avoid invoking the wrong instance.")
def dbg_exit_process(
    port: Annotated[int | None, Field(description="Optional instance port override")]= None
) -> Any:  # type: ignore
    target = port if port is not None else _ensure_port()
    if target is None:
        return {"error": "No instances"}
    res = _call('dbg_exit_process', {}, port=target)
    return res.get('data') if isinstance(res, dict) else res

@server.tool(description="Continue execution: param port(optional). Returns backend { ok,continued,note? } or { error }. Inactive => ok:false. When multiple IDA instances are running, be sure to specify the correct port for your call to avoid invoking the wrong instance.")
def dbg_continue_process(
    port: Annotated[int | None, Field(description="Optional instance port override")]= None
) -> Any:  # type: ignore
    target = port if port is not None else _ensure_port()
    if target is None:
        return {"error": "No instances"}
    res = _call('dbg_continue_process', {}, port=target)
    return res.get('data') if isinstance(res, dict) else res

@server.tool(description="Run to address: params address,int port(optional). Returns backend { ok,requested,continued,used_temp_bpt,note? } or { error }. Non-blocking. When multiple IDA instances are running, be sure to specify the correct port for your call to avoid invoking the wrong instance.")
def dbg_run_to(
    address: Annotated[int, Field(description="Target address to run to")],
    port: Annotated[int | None, Field(description="Optional instance port override")]= None
) -> Any:  # type: ignore
    if address is None:
        return {"error": "invalid address"}
    target = port if port is not None else _ensure_port()
    if target is None:
        return {"error": "No instances"}
    res = _call('dbg_run_to', {"address": address}, port=target)
    return res.get('data') if isinstance(res, dict) else res

@server.tool(description="Set breakpoint: params address,int port(optional). Returns backend { ok,ea,existed,added,note? } or { error }. Can be used pre-debugger. When multiple IDA instances are running, be sure to specify the correct port for your call to avoid invoking the wrong instance.")
def dbg_set_breakpoint(
    address: Annotated[int, Field(description="Address where breakpoint should be set")],
    port: Annotated[int | None, Field(description="Optional instance port override")]= None
) -> Any:  # type: ignore
    if address is None:
        return {"error": "invalid address"}
    target = port if port is not None else _ensure_port()
    if target is None:
        return {"error": "No instances"}
    res = _call('dbg_set_breakpoint', {"address": address}, port=target)
    return res.get('data') if isinstance(res, dict) else res

@server.tool(description="Delete breakpoint: params address,int port(optional). Idempotent. Returns backend { ok,ea,existed,deleted,note? } or { error }. When multiple IDA instances are running, be sure to specify the correct port for your call to avoid invoking the wrong instance.")
def dbg_delete_breakpoint(
    address: Annotated[int, Field(description="Address of breakpoint to delete")],
    port: Annotated[int | None, Field(description="Optional instance port override")]= None
) -> Any:  # type: ignore
    if address is None:
        return {"error": "invalid address"}
    target = port if port is not None else _ensure_port()
    if target is None:
        return {"error": "No instances"}
    res = _call('dbg_delete_breakpoint', {"address": address}, port=target)
    return res.get('data') if isinstance(res, dict) else res

@server.tool(description="Enable/disable breakpoint: params address,int enable(bool), port(optional). Enabling creates if missing. Returns backend { ok,ea,existed,enabled,changed,note? } or { error }. When multiple IDA instances are running, be sure to specify the correct port for your call to avoid invoking the wrong instance.")
def dbg_enable_breakpoint(
    address: Annotated[int, Field(description="Breakpoint address")],
    enable: Annotated[bool, Field(description="True = enable (creates if missing), False = disable")],
    port: Annotated[int | None, Field(description="Optional instance port override")]= None
) -> Any:  # type: ignore
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
