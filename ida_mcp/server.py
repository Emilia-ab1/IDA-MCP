"""IDA FastMCP 服务器。

提供工具:
    * list_instances         – 通过协调器 (端口 11337) 获取所有已注册 IDA MCP 实例
    * check_connection       – 快速检测是否存在至少一个活跃实例
    ......

设计说明:
    * 运行于每个独立的 IDA 实例内部; SSE 端点由插件代码启动的 uvicorn 提供。
    * 所有 IDA API 调用通过 ida_kernwin.execute_sync 切换到 IDA 主线程, 避免线程不安全。
    * 保持极简; 需要更多逆向相关工具时可按需增量扩展。
"""
from __future__ import annotations

import os
import sys
import hashlib
from typing import Callable, Any, List

try:
    from pydantic import BaseModel
except Exception:  # pragma: no cover
    BaseModel = object  # type: ignore

from fastmcp import FastMCP
try:
    from ida_mcp import registry  # type: ignore
except Exception:  # pragma: no cover
    registry = None  # type: ignore

try:  # Only the IDA bits actually needed for list_functions
    import idaapi  # type: ignore
    import idautils  # type: ignore
    import ida_kernwin  # type: ignore
    import ida_funcs  # type: ignore
    try:
        import ida_bytes  # type: ignore
    except Exception:  # pragma: no cover
        ida_bytes = None  # type: ignore
    try:
        import ida_typeinf  # type: ignore
    except Exception:  # pragma: no cover
        ida_typeinf = None  # type: ignore
    try:
        import ida_hexrays  # type: ignore
    except Exception:  # pragma: no cover
        ida_hexrays = None  # type: ignore
    try:
        import ida_lines  # type: ignore
    except Exception:  # pragma: no cover
        ida_lines = None  # type: ignore
    try:
        import ida_struct  # type: ignore
    except Exception:  # pragma: no cover
        ida_struct = None  # type: ignore
    HAVE_IDA = True
except Exception:  # pragma: no cover
    HAVE_IDA = False

# Default TCP port exported for plugin entry (kept for compatibility)
DEFAULT_PORT = 8765


def _run_in_ida(fn: Callable[[], Any]) -> Any:
    """在 IDA 主线程执行回调并返回结果。若未处于 IDA 环境 (测试态) 则直接执行。"""
    if not HAVE_IDA:
        return fn()

    result_box: dict[str, Any] = {}

    def wrapper():  # type: ignore
        try:
            result_box["value"] = fn()
        except Exception as e:  # pragma: no cover
            result_box["error"] = repr(e)
        return 0

    ida_kernwin.execute_sync(wrapper, ida_kernwin.MFF_READ)  # type: ignore
    if "error" in result_box:
        raise RuntimeError(result_box["error"])
    return result_box.get("value")


class FunctionItem(BaseModel):  # type: ignore
    """函数条目结构 (显式声明避免出现通用 Root() 包装)。"""
    name: str  # type: ignore
    start_ea: int  # type: ignore
    end_ea: int  # type: ignore

def create_mcp_server() -> FastMCP:
    name = os.getenv("IDA_MCP_NAME", "IDA-MCP")
    mcp = FastMCP(name=name, instructions="通过 MCP 工具访问 IDA 反汇编/分析数据。")

    @mcp.tool(description="Check if IDA MCP plugin/coordinator connection is alive (returns ok/count).")
    def check_connection() -> dict:  # type: ignore
        if registry is None:
            return {"ok": False, "count": 0}
        try:
            return registry.check_connection()  # type: ignore
        except Exception:
            return {"ok": False, "count": 0}

    @mcp.tool(description="Get registered IDA MCP instances (raw list, no filtering).")
    def list_instances() -> list[dict]:  # type: ignore
        """获取所有已注册实例原始列表 (不进行任何过滤)。"""
        if registry is None:
            return []
        try:
            return registry.get_instances()  # type: ignore
        except Exception as e:  # pragma: no cover
            return [{"error": str(e)}]

    @mcp.tool(description="Get metadata about the current IDB.")
    def get_metadata() -> dict:  # type: ignore
        """返回当前 IDA 会话 / IDB 的基础元数据 (轻量查询)。

        字段示例:
            input_file: 输入二进制完整路径 (可能为空)
            arch:       处理器名称
            bits:       32 / 64 (无法判定则为 0)
            hash:       输入文件 SHA256 (若可访问; 否则为 None)
        """
        if not HAVE_IDA:
            return {
                "input_file": None,
                "arch": None,
                "bits": 0,
                "hash": None,
                "note": "Not running inside IDA"
            }

        def logic():
            try:
                input_file = idaapi.get_input_file_path()  # type: ignore
            except Exception:
                input_file = None
            # 不再返回 idb 路径
            # 获取架构 / 位宽
            arch = None
            bits = 0
            try:
                inf = idaapi.get_inf_structure()  # type: ignore
                # 兼容不同 IDA 版本的字段名
                arch = getattr(inf, 'procname', None) or getattr(inf, 'procName', None)
                if isinstance(arch, bytes):
                    arch = arch.decode(errors='ignore')
                is_64 = False
                try:
                    is_64 = inf.is_64bit()  # type: ignore
                except Exception:
                    # 回退: 通过 abits / lflags 判定
                    try:
                        is_64 = bool(getattr(inf, 'is_64bit', lambda: False)())
                    except Exception:
                        is_64 = False
                bits = 64 if is_64 else 32
            except Exception:
                pass
            # 计算输入文件 SHA256 (若可读取; 避免大文件阻塞, 使用流式读)
            file_hash: str | None = None
            if input_file and os.path.isfile(input_file):
                try:
                    h = hashlib.sha256()
                    with open(input_file, 'rb') as f:
                        for chunk in iter(lambda: f.read(1024 * 1024), b''):
                            h.update(chunk)
                    file_hash = h.hexdigest()
                except Exception:
                    file_hash = None
            return {
                "input_file": input_file,
                "arch": arch,
                "bits": bits,
                "hash": file_hash,
            }

        return _run_in_ida(logic)


    @mcp.tool(description="List functions (returns list of FunctionItem objects).")
    def list_functions() -> List[FunctionItem]:  # type: ignore
        def logic():
            out: list[FunctionItem] = []
            for ea in idautils.Functions():  # type: ignore
                f = ida_funcs.get_func(ea)  # type: ignore
                if not f:
                    continue
                name = idaapi.get_func_name(ea)  # type: ignore
                out.append(FunctionItem(name=name, start_ea=int(f.start_ea), end_ea=int(f.end_ea)))
            return out

        return _run_in_ida(logic)

    @mcp.tool(description="Get a function by its name.")
    def get_function_by_name(name: str) -> dict:  # type: ignore
        """按函数名称精确查找并返回函数的基本信息。

        参数:
            name: 函数精确名称 (区分大小写, 与 IDA 显示名称一致)。
        返回:
            { name, start_ea, end_ea } 若找到; 否则 { error: "not found" }。
        """
        if not name:
            return {"error": "empty name"}

        def logic():
            for ea in idautils.Functions():  # type: ignore
                try:
                    fn_name = idaapi.get_func_name(ea)  # type: ignore
                except Exception:
                    continue
                if fn_name == name:
                    f = ida_funcs.get_func(ea)  # type: ignore
                    if not f:
                        break
                    return {
                        "name": fn_name,
                        "start_ea": int(f.start_ea),
                        "end_ea": int(f.end_ea),
                    }
            return {"error": "not found"}

        return _run_in_ida(logic)

    @mcp.tool(description="Get a function by its address.")
    def get_function_by_address(address: int) -> dict:  # type: ignore
        """按地址获取函数信息。

        参数:
            address: 目标地址 (函数起始地址或函数内部任意地址)。
        返回:
            { name, start_ea, end_ea } 若找到; 否则 { error: "not found" }。
        注意:
            若地址位于函数内部也会返回该函数 (依赖 ida_funcs.get_func)。
        """
        if address is None:
            return {"error": "invalid address"}

        def logic():
            try:
                f = ida_funcs.get_func(address)  # type: ignore
            except Exception:
                f = None
            if not f:
                return {"error": "not found"}
            try:
                name = idaapi.get_func_name(f.start_ea)  # type: ignore
            except Exception:
                name = "?"
            return {
                "name": name,
                "start_ea": int(f.start_ea),
                "end_ea": int(f.end_ea),
            }

        return _run_in_ida(logic)

    @mcp.tool(description="Get the address currently selected by the user.")
    def get_current_address() -> dict:  # type: ignore
        """获取当前 IDA 界面上光标所在(或选中)的地址。

        返回:
            { address: int } 若成功;
            { error: "..." } 若未处于 IDA 或无法获取。
        说明:
            使用 ida_kernwin.get_screen_ea() / idaapi.get_screen_ea() (兼容不同版本)。
        """
        if not HAVE_IDA:
            return {"error": "not in IDA"}
        def logic():
            ea = None
            try:
                if hasattr(ida_kernwin, 'get_screen_ea'):
                    ea = ida_kernwin.get_screen_ea()  # type: ignore
                elif hasattr(idaapi, 'get_screen_ea'):
                    ea = idaapi.get_screen_ea()  # type: ignore
            except Exception:
                ea = None
            if ea is None or int(ea) == idaapi.BADADDR:  # type: ignore
                return {"error": "no valid address"}
            return {"address": int(ea)}
        return _run_in_ida(logic)

    @mcp.tool(description="Get the function currently selected by the user.")
    def get_current_function() -> dict:  # type: ignore
        """获取当前光标所在地址所属的函数信息。

        返回:
            { name, start_ea, end_ea } 若当前地址位于某个函数内;
            { error: "no function" } 若不在任何函数中;
            { error: "no valid address" } 若无法获取当前地址。
        说明:
            先获取 screen_ea, 再通过 ida_funcs.get_func(address) 判断所属函数。
        """
        if not HAVE_IDA:
            return {"error": "not in IDA"}

        def logic():
            ea = None
            try:
                if hasattr(ida_kernwin, 'get_screen_ea'):
                    ea = ida_kernwin.get_screen_ea()  # type: ignore
                elif hasattr(idaapi, 'get_screen_ea'):
                    ea = idaapi.get_screen_ea()  # type: ignore
            except Exception:
                ea = None
            if ea is None or int(ea) == idaapi.BADADDR:  # type: ignore
                return {"error": "no valid address"}
            try:
                f = ida_funcs.get_func(ea)  # type: ignore
            except Exception:
                f = None
            if not f:
                return {"error": "no function"}
            try:
                name = idaapi.get_func_name(f.start_ea)  # type: ignore
            except Exception:
                name = "?"
            return {
                "name": name,
                "start_ea": int(f.start_ea),
                "end_ea": int(f.end_ea),
            }

        return _run_in_ida(logic)

    @mcp.tool(description="Convert a number (decimal/hex/binary) into multiple representations for a given bit size.")
    def convert_number(text: str, size: int) -> dict:  # type: ignore
        """数字格式转换工具。

        参数:
            text: 可能的数字表示 (支持: 十进制, 0x 前缀十六进制, 0b 前缀二进制, 结尾 h 的十六进制, 可含下划线分隔, 可带符号)。
            size: 位宽, 仅允许 8/16/32/64 之一。
        返回:
            若成功: {
                input_text, size, parsed_raw (可能超范围), value (裁剪后无符号),
                hex, dec, unsigned, signed, bin, bytes_le, bytes_be
            }
            若失败: { error: "..." }
        说明:
            * 会按给定位宽进行掩码 (two's complement)。
            * signed 为裁剪后按 two's complement 解释的有符号值。
            * bytes_* 为每字节两位十六进制 (不含0x)。
        """
        allowed = {8, 16, 32, 64}
        if size not in allowed:
            return {"error": f"invalid size (must be one of {sorted(allowed)})"}
        if not isinstance(text, str) or not text.strip():
            return {"error": "empty text"}

        original = text
        s = text.strip().replace('_', '')
        negative = False
        try:
            if s.startswith(('+', '-')):
                negative = s.startswith('-')
            # 结尾 h 形式 (如 1234h / 0Fh)
            if s.lower().endswith('h') and len(s) > 1:
                core = s[:-1]
                # 允许前导 -
                sign = ''
                if core.startswith(('+', '-')):
                    sign = core[0]
                    core = core[1:]
                if core and all(c in '0123456789abcdefABCDEF' for c in core):
                    parsed_raw = int(sign + '0x' + core, 0)
                else:
                    raise ValueError("invalid trailing h hex")
            else:
                # 默认使用 base=0 解析 (支持 0x / 0b / 十进制)
                parsed_raw = int(s, 0)
        except Exception:
            return {"error": "parse failed"}

        mask = (1 << size) - 1
        value = parsed_raw & mask
        unsigned_val = value
        # two's complement signed
        if value & (1 << (size - 1)):
            signed_val = value - (1 << size)
        else:
            signed_val = value

        hex_width = size // 4
        hex_repr = f"0x{value:0{hex_width}X}"
        bin_repr = f"0b{value:0{size}b}"
        num_bytes = size // 8
        bytes_le = [f"{(value >> (8 * i)) & 0xFF:02X}" for i in range(num_bytes)]
        bytes_be = list(reversed(bytes_le))

        return {
            "input_text": original,
            "size": size,
            "parsed_raw": parsed_raw,
            "value": value,
            "hex": hex_repr,
            "dec": str(unsigned_val),
            "unsigned": unsigned_val,
            "signed": signed_val,
            "bin": bin_repr,
            "bytes_le": bytes_le,
            "bytes_be": bytes_be,
        }

    @mcp.tool(description="List matching global symbols (non-function names) with pagination and optional substring filter.")
    def list_globals_filter(offset: int, count: int, filter: str | None = None) -> dict:  # type: ignore
        """分页/过滤列出全局符号(非函数)。

        参数:
            offset: 起始偏移 (>=0)。
            count: 返回数量 (1..1000)。
            filter: 可选名称子串 (不区分大小写)。
        返回:
            {
              total: 符合条件的总数,
              offset: 请求的 offset,
              count: 实际返回数量,
              items: [ { name, ea, size? } ... ]
            } 或 { error: "..." }
        判定规则:
            * 使用 idautils.Names() 遍历所有命名地址。
            * 过滤掉属于任何函数 (ida_funcs.get_func(ea) 返回非空并且 f.start_ea == ea)。
            * 保留其余 (数据 / 外部引用 / 段标签等)。
        注意:
            * size 值来源 ida_bytes.get_item_size(ea), 失败则为 None。
            * 不执行昂贵的类型推断。
        """
        if offset < 0:
            return {"error": "offset < 0"}
        if count <= 0:
            return {"error": "count must be > 0"}
        if count > 1000:
            return {"error": "count too large (max 1000)"}

        pattern = (filter or '').lower()

        if not HAVE_IDA:
            return {"total": 0, "offset": offset, "count": 0, "items": [], "note": "not in IDA"}

        def logic():
            entries: list[dict] = []
            try:
                for ea, name in idautils.Names():  # type: ignore
                    if pattern and pattern not in name.lower():
                        continue
                    # 排除函数起始地址名称 (函数本身而非全局数据)
                    try:
                        f = ida_funcs.get_func(ea)  # type: ignore
                        if f and int(f.start_ea) == int(ea):
                            continue
                    except Exception:
                        pass
                    item_size = None
                    if 'ida_bytes' in globals() and ida_bytes:  # type: ignore
                        try:
                            item_size = ida_bytes.get_item_size(ea)  # type: ignore
                        except Exception:
                            item_size = None
                    entries.append({
                        "name": name,
                        "ea": int(ea),
                        "size": item_size,
                    })
            except Exception:
                # 即使部分迭代失败也尽量返回已收集数据
                pass
            # 按地址升序
            entries.sort(key=lambda x: x['ea'])
            total = len(entries)
            slice_items = entries[offset: offset + count]
            return {
                "total": total,
                "offset": offset,
                "count": len(slice_items),
                "items": slice_items,
            }

        return _run_in_ida(logic)

    @mcp.tool(description="List global symbols (non-function names) with pagination.")
    def list_globals(offset: int, count: int) -> dict:  # type: ignore
        """分页列出所有全局符号 (不区分名称, 不带过滤)。

        参数:
            offset: 起始偏移 (>=0)
            count: 数量 (1..1000)
        返回字段同 list_globals_filter (不含 filter 逻辑)。
        """
        if offset < 0:
            return {"error": "offset < 0"}
        if count <= 0:
            return {"error": "count must be > 0"}
        if count > 1000:
            return {"error": "count too large (max 1000)"}
        if not HAVE_IDA:
            return {"total": 0, "offset": offset, "count": 0, "items": [], "note": "not in IDA"}

        def logic():
            entries: list[dict] = []
            try:
                for ea, name in idautils.Names():  # type: ignore
                    # 排除函数起始地址
                    try:
                        f = ida_funcs.get_func(ea)  # type: ignore
                        if f and int(f.start_ea) == int(ea):
                            continue
                    except Exception:
                        pass
                    item_size = None
                    if 'ida_bytes' in globals() and ida_bytes:  # type: ignore
                        try:
                            item_size = ida_bytes.get_item_size(ea)  # type: ignore
                        except Exception:
                            item_size = None
                    entries.append({
                        "name": name,
                        "ea": int(ea),
                        "size": item_size,
                    })
            except Exception:
                pass
            entries.sort(key=lambda x: x['ea'])
            total = len(entries)
            slice_items = entries[offset: offset + count]
            return {
                "total": total,
                "offset": offset,
                "count": len(slice_items),
                "items": slice_items,
            }

        return _run_in_ida(logic)

    @mcp.tool(description="List matching strings with pagination and optional substring filter.")
    def list_strings_filter(offset: int, count: int, filter: str | None = None) -> dict:  # type: ignore
        """分页 / 过滤列出程序中提取到的字符串。

        参数:
            offset: 起始偏移 (>=0)
            count: 数量 (1..1000)
            filter: 名称/内容子串 (不区分大小写); 为空表示不过滤。
        返回:
            {
              total: 符合条件的字符串总数,
              offset, count,
              items: [ { ea, length, type, text } ... ]
            } 或 { error }。
        说明:
            * 使用 idautils.Strings() 列举; 若未初始化会自动 setup。
            * type 为字符串类型标记 (strtype 属性) 若可得; 否则 None。
        """
        if offset < 0:
            return {"error": "offset < 0"}
        if count <= 0:
            return {"error": "count must be > 0"}
        if count > 1000:
            return {"error": "count too large (max 1000)"}

        substr = (filter or '').lower()
        if not HAVE_IDA:
            return {"total": 0, "offset": offset, "count": 0, "items": [], "note": "not in IDA"}

        def logic():
            items: list[dict] = []
            try:
                strs = idautils.Strings()  # type: ignore
                try:
                    # 某些版本需要 setup 才能填充
                    _ = len(strs)  # 触发加载
                except Exception:
                    try:
                        strs.setup(strs.default_setup)  # type: ignore
                    except Exception:
                        pass
                for s in strs:  # type: ignore
                    try:
                        text = str(s)
                    except Exception:
                        continue
                    if substr and substr not in text.lower():
                        continue
                    ea = int(getattr(s, 'ea', 0))
                    length = int(getattr(s, 'length', 0))
                    stype = getattr(s, 'strtype', None)
                    items.append({
                        'ea': ea,
                        'length': length,
                        'type': stype,
                        'text': text,
                    })
            except Exception:
                pass
            items.sort(key=lambda x: x['ea'])
            total = len(items)
            slice_items = items[offset: offset + count]
            return {
                'total': total,
                'offset': offset,
                'count': len(slice_items),
                'items': slice_items,
            }

        return _run_in_ida(logic)

    @mcp.tool(description="List strings with pagination (no filtering).")
    def list_strings(offset: int, count: int) -> dict:  # type: ignore
        """分页列出所有已提取字符串 (不做内容过滤)。

        参数:
            offset: 起始偏移 (>=0)
            count: 数量 (1..1000)
        返回结构与 list_strings_filter 相同 (不含 filter)。
        """
        if offset < 0:
            return {"error": "offset < 0"}
        if count <= 0:
            return {"error": "count must be > 0"}
        if count > 1000:
            return {"error": "count too large (max 1000)"}
        if not HAVE_IDA:
            return {"total": 0, "offset": offset, "count": 0, "items": [], "note": "not in IDA"}

        def logic():
            items: list[dict] = []
            try:
                strs = idautils.Strings()  # type: ignore
                try:
                    _ = len(strs)
                except Exception:
                    try:
                        strs.setup(strs.default_setup)  # type: ignore
                    except Exception:
                        pass
                for s in strs:  # type: ignore
                    try:
                        text = str(s)
                    except Exception:
                        continue
                    ea = int(getattr(s, 'ea', 0))
                    length = int(getattr(s, 'length', 0))
                    stype = getattr(s, 'strtype', None)
                    items.append({
                        'ea': ea,
                        'length': length,
                        'type': stype,
                        'text': text,
                    })
            except Exception:
                pass
            items.sort(key=lambda x: x['ea'])
            total = len(items)
            slice_items = items[offset: offset + count]
            return {
                'total': total,
                'offset': offset,
                'count': len(slice_items),
                'items': slice_items,
            }

        return _run_in_ida(logic)

    @mcp.tool(description="List all local types (name + ordinal + short decl) defined in the IDB.")
    def list_local_types() -> dict:  # type: ignore
        """列出当前 IDB 中的所有 Local Types (本地类型定义)。

        返回:
            { total: N, items: [ { ordinal, name, decl } ... ] }
        说明:
            * 仅在 IDA 中有效; 测试环境返回空列表。
            * decl 可能很长, 进行截断 (默认 512 字符)。
            * 若 ida_typeinf 不可用则返回空。
        """
        if not HAVE_IDA or not ida_typeinf:  # type: ignore
            return {"total": 0, "items": [], "note": "not in IDA or no ida_typeinf"}

        def logic():
            items: list[dict] = []
            try:
                qty = ida_typeinf.get_ordinal_qty()  # type: ignore
            except Exception:
                qty = 0
            max_len = 512
            for ordinal in range(1, qty + 1):  # Ordinals start at 1
                try:
                    name = ida_typeinf.get_numbered_type_name(None, ordinal)  # type: ignore
                except Exception:
                    name = None
                if not name:
                    continue
                decl = None
                try:
                    tif = ida_typeinf.tinfo_t()  # type: ignore
                    fields = ida_typeinf.get_numbered_type(None, ordinal, tif, None, None)  # type: ignore
                    # fields may be a tuple (?). We'll fallback to print_type
                    try:
                        decl = ida_typeinf.print_tinfo('', 0, 0, ida_typeinf.PRTYPE_1LINE, tif, name, None)  # type: ignore
                    except Exception:
                        decl = None
                except Exception:
                    decl = None
                if decl is None:
                    decl = name
                if len(decl) > max_len:
                    decl = decl[:max_len] + '...'
                items.append({
                    'ordinal': ordinal,
                    'name': name,
                    'decl': decl,
                })
            return {"total": len(items), "items": items}

        return _run_in_ida(logic)

    @mcp.tool(description="Decompile a function at the given address (requires Hex-Rays).")
    def decompile_function(address: int) -> dict:  # type: ignore
        """反编译指定地址所在函数 (需要安装 Hex-Rays)。

        参数:
            address: 函数起始地址或函数内部任意地址。
        返回:
            { name, start_ea, end_ea, address, decompiled } 或 { error }。
        说明:
            * 若未加载 Hex-Rays / 无法初始化反编译器则返回 error。
            * 使用 ida_hexrays.decompile(ea)。
            * 结果字符串保持原样 (不截断)；客户端可自行截断。
        """
        if address is None:
            return {"error": "invalid address"}
        if not HAVE_IDA:
            return {"error": "not in IDA"}
        if not ida_hexrays:  # type: ignore
            return {"error": "hex-rays not available"}

        def logic():
            # 确保 Hex-Rays 已初始化
            try:
                if not ida_hexrays.init_hexrays_plugin():  # type: ignore
                    return {"error": "failed to init hex-rays"}
            except Exception:
                return {"error": "failed to init hex-rays"}
            try:
                f = ida_funcs.get_func(address)  # type: ignore
            except Exception:
                f = None
            if not f:
                return {"error": "function not found"}
            try:
                cfunc = ida_hexrays.decompile(f.start_ea)  # type: ignore
            except Exception as e:
                return {"error": f"decompile failed: {e}"}
            if not cfunc:
                return {"error": "decompile returned None"}
            try:
                name = idaapi.get_func_name(f.start_ea)  # type: ignore
            except Exception:
                name = "?"
            try:
                text = str(cfunc)  # type: ignore
            except Exception:
                text = "<print failed>"
            return {
                "address": int(address),
                "start_ea": int(f.start_ea),
                "end_ea": int(f.end_ea),
                "name": name,
                "decompiled": text,
            }

        return _run_in_ida(logic)

    @mcp.tool(description="Disassemble a function and return list of instructions (ea, bytes, text, comment).")
    def disassemble_function(start_address: int) -> dict:  # type: ignore
        """获取指定函数的反汇编指令列表。

        参数:
            start_address: 函数起始地址 (若指向函数内部, 会回退到所属函数起始)。
        返回:
            { name, start_ea, end_ea, instructions: [ { ea, bytes, text, comment } ... ] } 或 { error }。
        说明:
            * 仅收集指令 (heads 中可执行项); 数据项忽略。
            * bytes 为十六进制串 (大写, 无空格, 最长 16 字节截断标记 ...)。
            * comment 包含常规注释与 repeatable 注释 (若存在, 以 ' // ' 拼接)。
        """
        if start_address is None:
            return {"error": "invalid address"}
        if not HAVE_IDA:
            return {"error": "not in IDA"}

        def logic():
            try:
                f = ida_funcs.get_func(start_address)  # type: ignore
            except Exception:
                f = None
            if not f:
                return {"error": "function not found"}
            # 允许调用者传内部地址; 统一使用函数起始
            start = int(f.start_ea)
            end = int(f.end_ea)
            try:
                name = idaapi.get_func_name(f.start_ea)  # type: ignore
            except Exception:
                name = "?"
            out: list[dict] = []
            # 遍历指令 (逐条捕获异常, 避免整体失败)
            for ea in idautils.Heads(start, end):  # type: ignore
                try:
                    flags = idaapi.get_full_flags(ea)  # type: ignore
                    if not idaapi.is_code(flags):  # type: ignore
                        continue
                    insn_len = 0
                    try:
                        insn = idaapi.insn_t()  # type: ignore
                        if idaapi.decode_insn(insn, ea):  # type: ignore
                            insn_len = insn.size  # type: ignore
                    except Exception:
                        insn_len = 0
                    # 指令文本
                    text = None
                    try:
                        if ida_lines and hasattr(ida_lines, 'generate_disassembly_line'):  # type: ignore
                            text = ida_lines.generate_disassembly_line(ea, 0)  # type: ignore
                        if not text:
                            text = idaapi.generate_disasm_line(ea, 0)  # type: ignore
                    except Exception:
                        text = None
                    if text is None:
                        text = "?"
                    # 指令 bytes
                    b_hex = None
                    if insn_len and ida_bytes:  # type: ignore
                        try:
                            raw = ida_bytes.get_bytes(ea, insn_len)  # type: ignore
                            if raw:
                                b_hex = raw.hex().upper()
                                if len(b_hex) > 32:
                                    b_hex = b_hex[:32] + '...'
                        except Exception:
                            b_hex = None
                    # 注释
                    cmt_parts: list[str] = []
                    try:
                        c1 = idaapi.get_cmt(ea, 0)  # type: ignore
                        if c1:
                            cmt_parts.append(c1)
                    except Exception:
                        pass
                    try:
                        c2 = idaapi.get_cmt(ea, 1)  # type: ignore
                        if c2:
                            cmt_parts.append(c2)
                    except Exception:
                        pass
                    comment = ' // '.join(cmt_parts) if cmt_parts else None
                    out.append({
                        'ea': int(ea),
                        'bytes': b_hex,
                        'text': text,
                        'comment': comment,
                    })
                except Exception:
                    continue
            return {
                'name': name,
                'start_ea': start,
                'end_ea': end,
                'instructions': out,
            }

        return _run_in_ida(logic)

    @mcp.tool(description="Get cross references TO a given address (incoming xrefs).")
    def get_xrefs_to(address: int) -> dict:  # type: ignore
        """列出指向指定地址的所有交叉引用 (incoming xrefs)。

        参数:
            address: 目标地址 (指令或数据项)。
        返回:
            { address, total, xrefs: [ { frm, type, iscode } ... ] } 或 { error }。
        说明:
            * type 为 IDA xref_t 的 type (整数) 原始值。
            * iscode 标记该引用是否为代码引用。
            * 若地址无引用返回 total=0, xrefs=[]。
        """
        if address is None:
            return {"error": "invalid address"}
        if not HAVE_IDA:
            return {"error": "not in IDA"}

        def logic():
            out: list[dict] = []
            try:
                for xr in idautils.XrefsTo(address, 0):  # type: ignore
                    try:
                        frm = int(getattr(xr, 'frm', 0))
                        t = int(getattr(xr, 'type', 0))
                        iscode = False
                        try:
                            if hasattr(xr, 'iscode'):
                                iscode = bool(xr.iscode())  # type: ignore
                        except Exception:
                            iscode = False
                        out.append({'frm': frm, 'type': t, 'iscode': iscode})
                    except Exception:
                        continue
            except Exception as e:
                return {"error": f"xrefs failed: {e}"}
            return {"address": int(address), "total": len(out), "xrefs": out}

        return _run_in_ida(logic)

    @mcp.tool(description="Heuristically find code references mentioning a struct field (by name substring).")
    def get_xrefs_to_field(struct_name: str, field_name: str) -> dict:  # type: ignore
        """获取对结构体成员的 (启发式) 引用位置列表。

        说明 / 局限:
            * IDA 并未直接为“结构体字段”维护单独的 xref 列表; 此处实现通过:
                1. 定位结构 (ida_struct) 并找到字段偏移;
                2. 遍历所有函数指令, 生成反汇编行, 以字段名 (忽略大小写) 子串匹配;
                3. 同时检查指令操作数字面位移是否等于该字段偏移 (简单 decode, 可能不覆盖所有架构)。
            * 这是启发式, 可能产生误报/漏报, 特别是字段名很通用时。
            * 返回匹配上限 500 条, 超过会截断并设置 truncated 标记。
        返回:
            { struct, field, offset, matches: [ { ea, line } ... ], truncated?: bool, note? }
            或 { error }。
        """
        if not struct_name or not field_name:
            return {"error": "empty struct_name or field_name"}
        if not HAVE_IDA or not ida_struct:  # type: ignore
            return {"error": "not in IDA or ida_struct missing"}

        def logic():
            sid = ida_struct.get_struc_id(struct_name)  # type: ignore
            if sid == idaapi.BADADDR:  # type: ignore
                return {"error": "struct not found"}
            s = ida_struct.get_struc(sid)  # type: ignore
            if not s:
                return {"error": "struct not found"}
            # 查找成员
            target_off = None
            qty = ida_struct.get_struc_size(s)  # type: ignore
            # 遍历成员 (通过 first member / next offset)
            m = ida_struct.get_first_member(s)  # type: ignore
            while m is not None and m != idaapi.BADADDR:  # type: ignore
                try:
                    name = ida_struct.get_member_name(ida_struct.get_member_id(m))  # type: ignore
                except Exception:
                    name = None
                if name == field_name:
                    try:
                        target_off = ida_struct.get_member_offset(m)  # type: ignore
                    except Exception:
                        target_off = None
                    break
                try:
                    m = ida_struct.get_next_member(s, ida_struct.get_member_offset(m))  # type: ignore
                except Exception:
                    break
            if target_off is None:
                return {"error": "field not found"}
            # 启发式扫描
            fname_lower = field_name.lower()
            matches: list[dict] = []
            truncated = False
            MAX_MATCH = 500
            try:
                for fea in idautils.Functions():  # type: ignore
                    f = ida_funcs.get_func(fea)  # type: ignore
                    if not f:
                        continue
                    for ea in idautils.Heads(int(f.start_ea), int(f.end_ea)):  # type: ignore
                        try:
                            flags = idaapi.get_full_flags(ea)  # type: ignore
                            if not idaapi.is_code(flags):  # type: ignore
                                continue
                            line = None
                            try:
                                if ida_lines and hasattr(ida_lines, 'generate_disassembly_line'):  # type: ignore
                                    line = ida_lines.generate_disassembly_line(ea, 0)  # type: ignore
                                if not line:
                                    line = idaapi.generate_disasm_line(ea, 0)  # type: ignore
                            except Exception:
                                line = None
                            if not line:
                                continue
                            lcline = line.lower()
                            hit = fname_lower in lcline
                            # 简单位移匹配 (仅扫描十六进制立即数文本 0x... 与十进制)
                            if not hit:
                                pat_hex = f"0x{target_off:X}".lower()
                                if pat_hex in lcline or f"{target_off}" in lcline:
                                    hit = True
                            if hit:
                                matches.append({'ea': int(ea), 'line': line})
                                if len(matches) >= MAX_MATCH:
                                    truncated = True
                                    break
                        except Exception:
                            continue
                    if truncated:
                        break
            except Exception:
                pass
            result: dict = {
                'struct': struct_name,
                'field': field_name,
                'offset': int(target_off) if target_off is not None else None,
                'matches': matches,
            }
            if truncated:
                result['truncated'] = True
            if not matches:
                result['note'] = 'no heuristic matches (may be optimized code or indirect access)'
            return result

        return _run_in_ida(logic)

    @mcp.tool(description="Set a comment for a given address (non-repeatable); shown in disassembly & pseudocode.")
    def set_comment(address: int, comment: str) -> dict:  # type: ignore
        """为指定地址设置(或清除)普通注释。

        参数:
            address: 目标地址 (指令或数据项)。
            comment: 注释文本; 为空字符串则表示清除。
        行为:
            * 使用 idaapi.get_cmt / set_cmt(ea, text, 0) (非可重复)。
            * 超过 1024 字符将被截断。
            * 若地址无效或不在 IDA, 返回错误。
        返回:
            { address, old, new, changed: bool } 或 { error }。
        说明:
            Hex-Rays 伪代码通常会显示常规 (non-repeatable) 注释, 实现简单统一。
        """
        if address is None:
            return {"error": "invalid address"}
        if not HAVE_IDA:
            return {"error": "not in IDA"}
        if comment is None:
            return {"error": "comment is None"}

        def logic():
            try:
                old = idaapi.get_cmt(address, 0)  # type: ignore
            except Exception:
                old = None
            new_text = comment.strip()
            if len(new_text) > 1024:
                new_text = new_text[:1024]
            try:
                ok = idaapi.set_cmt(address, new_text if new_text else None, 0)  # type: ignore
            except Exception as e:
                return {"error": f"set failed: {e}"}
            return {
                "address": int(address),
                "old": old,
                "new": new_text if new_text else None,
                "changed": old != (new_text if new_text else None) and ok,
            }

        return _run_in_ida(logic)

    @mcp.tool(description="Rename a local variable in a function (requires Hex-Rays).")
    def rename_local_variable(function_address: int, old_name: str, new_name: str) -> dict:  # type: ignore
        """重命名函数中的本地变量 (依赖 Hex-Rays)。

        参数:
            function_address: 函数起始地址或内部任意地址。
            old_name: 旧变量名 (精确匹配)。
            new_name: 新变量名 (必须是有效的 C 标识符)。
        返回:
            { function: name, start_ea, old_name, new_name, changed } 或 { error }。
        说明:
            * 需要可用的 Hex-Rays 反编译支持。
            * 若存在多个同名本地变量, 修改第一个匹配项。
            * new_name 会截断到 255 字符; 若不合法 (非标识符) 返回错误。
        """
        if not HAVE_IDA:
            return {"error": "not in IDA"}
        if not ida_hexrays:  # type: ignore
            return {"error": "hex-rays not available"}
        if function_address is None:
            return {"error": "invalid function_address"}
        if not old_name:
            return {"error": "empty old_name"}
        if not new_name:
            return {"error": "empty new_name"}
        new_name_clean = new_name.strip()
        if len(new_name_clean) > 255:
            new_name_clean = new_name_clean[:255]
        # 简单标识符校验
        import re
        if not re.match(r'^[A-Za-z_][A-Za-z0-9_]*$', new_name_clean):
            return {"error": "new_name not a valid C identifier"}

        def logic():
            try:
                if not ida_hexrays.init_hexrays_plugin():  # type: ignore
                    return {"error": "failed to init hex-rays"}
            except Exception:
                return {"error": "failed to init hex-rays"}
            try:
                f = ida_funcs.get_func(function_address)  # type: ignore
            except Exception:
                f = None
            if not f:
                return {"error": "function not found"}
            try:
                cfunc = ida_hexrays.decompile(f.start_ea)  # type: ignore
            except Exception as e:
                return {"error": f"decompile failed: {e}"}
            if not cfunc:
                return {"error": "decompile returned None"}
            # 查找变量
            target = None
            try:
                for lv in cfunc.lvars:  # type: ignore
                    try:
                        if lv.name == old_name:  # type: ignore
                            target = lv
                            break
                    except Exception:
                        continue
            except Exception:
                return {"error": "iterate lvars failed"}
            if not target:
                return {"error": "local variable not found"}
            # 重命名
            try:
                ok = ida_hexrays.set_lvar_name(cfunc, target, new_name_clean)  # type: ignore
            except Exception as e:
                return {"error": f"set_lvar_name failed: {e}"}
            try:
                fname = idaapi.get_func_name(f.start_ea)  # type: ignore
            except Exception:
                fname = "?"
            return {
                "function": fname,
                "start_ea": int(f.start_ea),
                "old_name": old_name,
                "new_name": new_name_clean,
                "changed": bool(ok),
            }

        return _run_in_ida(logic)

    @mcp.tool(description="Rename a global variable (address-based name) in the IDB.")
    def rename_global_variable(old_name: str, new_name: str) -> dict:  # type: ignore
        """重命名全局变量。

        参数:
            old_name: 原有全局符号名称 (精确匹配)。
            new_name: 新名称 (有效 C 标识符)。
        返回:
            { ea, old_name, new_name, changed } 或 { error }。
        说明:
            * 通过 get_name_ea 查找地址; 若多个同名 (极少) 仅处理第一个。
            * 使用 idaapi.set_name(ea, new_name, SN_NOWARN)。
            * 仅处理非函数名 (若地址属于函数起始, 返回 error 提示用函数重命名工具)。
        """
        if not HAVE_IDA:
            return {"error": "not in IDA"}
        if not old_name:
            return {"error": "empty old_name"}
        if not new_name:
            return {"error": "empty new_name"}
        new_name_clean = new_name.strip()
        if len(new_name_clean) > 255:
            new_name_clean = new_name_clean[:255]
        import re
        if not re.match(r'^[A-Za-z_][A-Za-z0-9_]*$', new_name_clean):
            return {"error": "new_name not a valid C identifier"}

        def logic():
            try:
                ea = idaapi.get_name_ea(idaapi.BADADDR, old_name)  # type: ignore
            except Exception:
                ea = idaapi.BADADDR  # type: ignore
            if ea == idaapi.BADADDR:  # type: ignore
                return {"error": "global not found"}
            # 若是函数起始地址则拒绝
            try:
                f = ida_funcs.get_func(ea)  # type: ignore
                if f and int(f.start_ea) == int(ea):
                    return {"error": "target is a function start (use function rename)"}
            except Exception:
                pass
            try:
                ok = idaapi.set_name(ea, new_name_clean, idaapi.SN_NOWARN)  # type: ignore
            except Exception as e:
                return {"error": f"set_name failed: {e}"}
            return {
                "ea": int(ea),
                "old_name": old_name,
                "new_name": new_name_clean,
                "changed": bool(ok),
            }

        return _run_in_ida(logic)

    @mcp.tool(description="Rename a function by address.")
    def rename_function(function_address: int, new_name: str) -> dict:  # type: ignore
        """重命名函数。

        参数:
            function_address: 函数起始地址或函数内部地址。
            new_name: 新函数名 (有效 C 标识符)。
        返回:
            { start_ea, old_name, new_name, changed } 或 { error }。
        说明:
            * 若传入内部地址会先解析所属函数起始地址。
            * 使用 idaapi.set_name(ea, new_name, SN_NOWARN)。
        """
        if not HAVE_IDA:
            return {"error": "not in IDA"}
        if function_address is None:
            return {"error": "invalid function_address"}
        if not new_name:
            return {"error": "empty new_name"}
        new_name_clean = new_name.strip()
        if len(new_name_clean) > 255:
            new_name_clean = new_name_clean[:255]
        import re
        if not re.match(r'^[A-Za-z_][A-Za-z0-9_]*$', new_name_clean):
            return {"error": "new_name not a valid C identifier"}

        def logic():
            try:
                f = ida_funcs.get_func(function_address)  # type: ignore
            except Exception:
                f = None
            if not f:
                return {"error": "function not found"}
            start_ea = int(f.start_ea)
            try:
                old_name = idaapi.get_func_name(f.start_ea)  # type: ignore
            except Exception:
                old_name = None
            try:
                ok = idaapi.set_name(start_ea, new_name_clean, idaapi.SN_NOWARN)  # type: ignore
            except Exception as e:
                return {"error": f"set_name failed: {e}"}
            return {
                "start_ea": start_ea,
                "old_name": old_name,
                "new_name": new_name_clean,
                "changed": bool(ok) and old_name != new_name_clean,
            }

        return _run_in_ida(logic)

    @mcp.tool(description="Set a function prototype (apply type) at given address.")
    def set_function_prototype(function_address: int, prototype: str) -> dict:  # type: ignore
        """设置函数原型 (类型签名)。

        参数:
            function_address: 函数起始或内部地址。
            prototype: C 函数声明, 可包含函数名或使用占位名 (若含名可与当前不同)。
        返回:
            { start_ea, applied: bool, old_type, new_type, parsed_name? } 或 { error }。
        说明:
            * 尝试多种 parse_decl 调用方式以适配不同 IDA 版本。
            * 若声明中函数名与现有函数名不同, 不会自动重命名 (保持名称, 仅应用类型)。
            * 需要 ida_typeinf 支持; 不依赖 Hex-Rays。
        限制:
            * 原型必须是函数类型; 若解析为非函数返回错误。
            * 复杂 attribute / calling convention 解析失败会报错。
        """
        if not HAVE_IDA:
            return {"error": "not in IDA"}
        if not ida_typeinf:  # type: ignore
            return {"error": "ida_typeinf module missing"}
        if function_address is None:
            return {"error": "invalid function_address"}
        if not prototype or not prototype.strip():
            return {"error": "empty prototype"}
        proto_text = prototype.strip()

        def logic():
            try:
                f = ida_funcs.get_func(function_address)  # type: ignore
            except Exception:
                f = None
            if not f:
                return {"error": "function not found"}
            start_ea = int(f.start_ea)

            # 获取旧类型字符串
            old_decl = None
            try:
                old_t = ida_typeinf.tinfo_t()  # type: ignore
                if idaapi.get_tinfo(old_t, start_ea):  # type: ignore
                    try:
                        old_decl = ida_typeinf.print_tinfo('', 0, 0, ida_typeinf.PRTYPE_1LINE, old_t, '', None)  # type: ignore
                    except Exception:
                        old_decl = None
            except Exception:
                pass

            # 解析新类型
            tinfo = ida_typeinf.tinfo_t()  # type: ignore
            parsed_name = None
            parse_ok = False
            parse_errors: list[str] = []
            # 尝试不同 parse_decl 调用签名
            variants = [
                ("idaapi.parse_decl", lambda: idaapi.parse_decl(tinfo, None, proto_text, 0)),  # type: ignore
                ("ida_typeinf.parse_decl", lambda: ida_typeinf.parse_decl(tinfo, None, proto_text, 0)),  # type: ignore
            ]
            for label, fn in variants:
                try:
                    name = fn()
                    # 某些版本返回 (name, ) 或 str / None
                    if isinstance(name, (list, tuple)) and name:
                        name = name[0]
                    if isinstance(name, str) and name:
                        parsed_name = name
                    if tinfo and tinfo.is_func():  # type: ignore
                        parse_ok = True
                        break
                except Exception as e:  # pragma: no cover
                    parse_errors.append(f"{label}: {e}")
            if not parse_ok or not tinfo or not tinfo.is_func():  # type: ignore
                return {"error": "parse failed or not a function type", "details": parse_errors[:2]}

            # 应用类型
            try:
                applied = idaapi.apply_tinfo(start_ea, tinfo, idaapi.TINFO_DEFINITE)  # type: ignore
            except Exception:
                # 回退 API 名称
                try:
                    applied = idaapi.apply_tinfo2(start_ea, tinfo, idaapi.TINFO_DEFINITE)  # type: ignore
                except Exception as e:
                    return {"error": f"apply failed: {e}"}

            # 获取新类型字符串
            new_decl = None
            try:
                nt = ida_typeinf.tinfo_t()  # type: ignore
                if idaapi.get_tinfo(nt, start_ea):  # type: ignore
                    try:
                        new_decl = ida_typeinf.print_tinfo('', 0, 0, ida_typeinf.PRTYPE_1LINE, nt, '', None)  # type: ignore
                    except Exception:
                        new_decl = None
            except Exception:
                pass

            return {
                "start_ea": start_ea,
                "applied": bool(applied),
                "old_type": old_decl,
                "new_type": new_decl,
                "parsed_name": parsed_name,
            }

        return _run_in_ida(logic)

    @mcp.tool(description="Set the type of a local variable in a function (requires Hex-Rays).")
    def set_local_variable_type(function_address: int, variable_name: str, new_type: str) -> dict:  # type: ignore
        """为函数内局部变量设置类型。

        参数:
            function_address: 函数起始或内部地址。
            variable_name: 目标局部变量原名称 (精确匹配)。
            new_type: C 类型片段 (如 "int", "char *", "MyStruct *")。
        返回:
            { function, start_ea, variable_name, old_type, new_type, applied } 或 { error }。
        说明:
            * 需要 Hex-Rays + ida_typeinf。
            * 解析类型时会构造 "<new_type> tmp;" 形式喂给 parse_decl。
            * 若出现多个同名 (极少) 仅修改第一个匹配。
        限制:
            * 不自动刷新伪代码窗口 (调用者可手动刷新)。
        """
        if not HAVE_IDA:
            return {"error": "not in IDA"}
        if not ida_hexrays:  # type: ignore
            return {"error": "hex-rays not available"}
        if not ida_typeinf:  # type: ignore
            return {"error": "ida_typeinf module missing"}
        if function_address is None:
            return {"error": "invalid function_address"}
        if not variable_name:
            return {"error": "empty variable_name"}
        if not new_type or not new_type.strip():
            return {"error": "empty new_type"}
        type_text = new_type.strip()

        def logic():
            # 初始化 Hex-Rays
            try:
                if not ida_hexrays.init_hexrays_plugin():  # type: ignore
                    return {"error": "failed to init hex-rays"}
            except Exception:
                return {"error": "failed to init hex-rays"}
            # 定位函数
            try:
                f = ida_funcs.get_func(function_address)  # type: ignore
            except Exception:
                f = None
            if not f:
                return {"error": "function not found"}
            try:
                cfunc = ida_hexrays.decompile(f.start_ea)  # type: ignore
            except Exception as e:
                return {"error": f"decompile failed: {e}"}
            if not cfunc:
                return {"error": "decompile returned None"}
            # 查找局部变量
            target = None
            try:
                for lv in cfunc.lvars:  # type: ignore
                    try:
                        if lv.name == variable_name:  # type: ignore
                            target = lv
                            break
                    except Exception:
                        continue
            except Exception:
                return {"error": "iterate lvars failed"}
            if not target:
                return {"error": "local variable not found"}
            # 原类型字符串
            old_type_str = None
            try:
                old_t = target.type()  # type: ignore
                if old_t:
                    try:
                        old_type_str = ida_typeinf.print_tinfo('', 0, 0, ida_typeinf.PRTYPE_1LINE, old_t, '', None)  # type: ignore
                    except Exception:
                        old_type_str = None
            except Exception:
                pass
            # 解析新类型
            tinfo = ida_typeinf.tinfo_t()  # type: ignore
            parse_ok = False
            errors: list[str] = []
            candidate_decl = f"{type_text} tmp;"
            variants = [
                ("idaapi.parse_decl", lambda: idaapi.parse_decl(tinfo, None, candidate_decl, 0)),  # type: ignore
                ("ida_typeinf.parse_decl", lambda: ida_typeinf.parse_decl(tinfo, None, candidate_decl, 0)),  # type: ignore
            ]
            for label, fn in variants:
                try:
                    _ = fn()
                    if tinfo and not tinfo.empty():  # type: ignore
                        parse_ok = True
                        break
                except Exception as e:
                    errors.append(f"{label}: {e}")
            if not parse_ok:
                return {"error": "parse type failed", "details": errors[:2]}
            # 应用
            try:
                applied = ida_hexrays.set_lvar_type(cfunc, target, tinfo)  # type: ignore
            except Exception as e:
                return {"error": f"set_lvar_type failed: {e}"}
            # 新类型字符串
            new_type_str = None
            try:
                nt = target.type()  # type: ignore
                if nt:
                    try:
                        new_type_str = ida_typeinf.print_tinfo('', 0, 0, ida_typeinf.PRTYPE_1LINE, nt, '', None)  # type: ignore
                    except Exception:
                        new_type_str = None
            except Exception:
                pass
            try:
                fname = idaapi.get_func_name(f.start_ea)  # type: ignore
            except Exception:
                fname = "?"
            return {
                "function": fname,
                "start_ea": int(f.start_ea),
                "variable_name": variable_name,
                "old_type": old_type_str,
                "new_type": new_type_str,
                "applied": bool(applied),
            }

            
        return _run_in_ida(logic)

    @mcp.tool(description="Get all entry points (ordinal, ea, name) in the current database.")
    def get_entry_points() -> dict:  # type: ignore
        """获取全部入口点 (entry points)。

        返回:
            { total, items: [ { ordinal, ea, name } ... ] }
        说明:
            * 使用 idaapi.get_entry_qty / get_entry_ordinal / get_entry / get_entry_name。
            * name 解析失败时回退尝试通过函数名 (若指向函数起始)。
        """
        if not HAVE_IDA:
            return {"total": 0, "items": [], "note": "not in IDA"}

        def logic():
            out: list[dict] = []
            qty = 0
            try:
                qty = idaapi.get_entry_qty()  # type: ignore
            except Exception:
                qty = 0
            for i in range(qty):
                try:
                    ordv = idaapi.get_entry_ordinal(i)  # type: ignore
                    ea = idaapi.get_entry(ordv)  # type: ignore
                    name = None
                    try:
                        name = idaapi.get_entry_name(ordv)  # type: ignore
                    except Exception:
                        name = None
                    if not name:
                        try:
                            f = ida_funcs.get_func(ea)  # type: ignore
                            if f and int(f.start_ea) == int(ea):
                                name = idaapi.get_func_name(f.start_ea)  # type: ignore
                        except Exception:
                            name = None
                    out.append({
                        'ordinal': int(ordv),
                        'ea': int(ea),
                        'name': name,
                    })
                except Exception:
                    continue
            return {"total": len(out), "items": out}

        return _run_in_ida(logic)

    @mcp.tool(description="Set a global variable's type (apply tinfo).")
    def set_global_variable_type(variable_name: str, new_type: str) -> dict:  # type: ignore
        """设置全局变量类型。

        参数:
            variable_name: 全局符号名称 (必须已存在, 且不是函数起始)。
            new_type: C 类型片段 (如 "int", "char *", "MyStruct")。
        返回:
            { ea, variable_name, old_type, new_type, applied } 或 { error }。
        说明:
            * 需要 ida_typeinf。
            * 通过构造 "<type> __tmp_var;" 使用 parse_decl 解析。
            * 不修改变量名称, 仅应用类型。
        限制:
            * 若解析失败 / 非法类型返回错误。
        """
        if not HAVE_IDA:
            return {"error": "not in IDA"}
        if not ida_typeinf:  # type: ignore
            return {"error": "ida_typeinf module missing"}
        if not variable_name:
            return {"error": "empty variable_name"}
        if not new_type or not new_type.strip():
            return {"error": "empty new_type"}
        type_text = new_type.strip()

        def logic():
            try:
                ea = idaapi.get_name_ea(idaapi.BADADDR, variable_name)  # type: ignore
            except Exception:
                ea = idaapi.BADADDR  # type: ignore
            if ea == idaapi.BADADDR:  # type: ignore
                return {"error": "global not found"}
            # 拒绝函数起始
            try:
                f = ida_funcs.get_func(ea)  # type: ignore
                if f and int(f.start_ea) == int(ea):
                    return {"error": "target is function start"}
            except Exception:
                pass
            # 旧类型
            old_type_str = None
            try:
                ot = ida_typeinf.tinfo_t()  # type: ignore
                if idaapi.get_tinfo(ot, ea):  # type: ignore
                    try:
                        old_type_str = ida_typeinf.print_tinfo('', 0, 0, ida_typeinf.PRTYPE_1LINE, ot, '', None)  # type: ignore
                    except Exception:
                        old_type_str = None
            except Exception:
                pass
            # 解析新类型
            candidate = f"{type_text} __tmp_var;"
            tinfo = ida_typeinf.tinfo_t()  # type: ignore
            parse_ok = False
            errors: list[str] = []
            variants = [
                ("idaapi.parse_decl", lambda: idaapi.parse_decl(tinfo, None, candidate, 0)),  # type: ignore
                ("ida_typeinf.parse_decl", lambda: ida_typeinf.parse_decl(tinfo, None, candidate, 0)),  # type: ignore
            ]
            for label, fn in variants:
                try:
                    _ = fn()
                    if tinfo and not tinfo.empty():  # type: ignore
                        parse_ok = True
                        break
                except Exception as e:
                    errors.append(f"{label}: {e}")
            if not parse_ok:
                return {"error": "parse type failed", "details": errors[:2]}
            # 应用
            try:
                applied = idaapi.apply_tinfo(ea, tinfo, idaapi.TINFO_DEFINITE)  # type: ignore
            except Exception:
                try:
                    applied = idaapi.apply_tinfo2(ea, tinfo, idaapi.TINFO_DEFINITE)  # type: ignore
                except Exception as e:
                    return {"error": f"apply failed: {e}"}
            new_type_str = None
            try:
                nt = ida_typeinf.tinfo_t()  # type: ignore
                if idaapi.get_tinfo(nt, ea):  # type: ignore
                    try:
                        new_type_str = ida_typeinf.print_tinfo('', 0, 0, ida_typeinf.PRTYPE_1LINE, nt, '', None)  # type: ignore
                    except Exception:
                        new_type_str = None
            except Exception:
                pass
            return {
                "ea": int(ea),
                "variable_name": variable_name,
                "old_type": old_type_str,
                "new_type": new_type_str,
                "applied": bool(applied),
            }

        return _run_in_ida(logic)

    @mcp.tool(description="Declare or update a local type from a C declaration (struct/union/enum/typedef).")
    def declare_c_type(c_declaration: str) -> dict:  # type: ignore
        """创建或更新本地类型 (Local Types)。

        参数:
            c_declaration: 完整 C 声明, 如:
                "struct Foo { int a; char b; };" 或 "typedef int MYINT;"。
        返回:
            { name, kind, replaced, success } 或 { error }。
        说明:
            * 使用 parse_decl 解析, 获取 tinfo 与名称。
            * 通过 set_named_type 写入, 若已存在则替换 (NTF_REPLACE)。
            * kind 尝试根据 tinfo 判断 (struct/union/enum/typedef/other)。
        限制:
            * 不解析多个声明; 一次仅处理一个。
            * 若声明未含名称或无法推导名称则返回错误。
        """
        if not HAVE_IDA:
            return {"error": "not in IDA"}
        if not ida_typeinf:  # type: ignore
            return {"error": "ida_typeinf module missing"}
        if not c_declaration or not c_declaration.strip():
            return {"error": "empty declaration"}
        decl_text = c_declaration.strip()

        def logic():
            tinfo = ida_typeinf.tinfo_t()  # type: ignore
            name = None
            parse_errors: list[str] = []
            variants = [
                ("idaapi.parse_decl", lambda: idaapi.parse_decl(tinfo, None, decl_text, 0)),  # type: ignore
                ("ida_typeinf.parse_decl", lambda: ida_typeinf.parse_decl(tinfo, None, decl_text, 0)),  # type: ignore
            ]
            for label, fn in variants:
                try:
                    nm = fn()
                    if isinstance(nm, (list, tuple)) and nm:
                        nm = nm[0]
                    if isinstance(nm, str) and nm:
                        name = nm
                    if tinfo and not tinfo.empty():  # type: ignore
                        break
                except Exception as e:
                    parse_errors.append(f"{label}: {e}")
            if not name or not tinfo or tinfo.empty():  # type: ignore
                return {"error": "parse failed", "details": parse_errors[:2]}
            # 判断是否已有同名类型
            existed = False
            try:
                existed = bool(ida_typeinf.get_named_type(None, name))  # type: ignore
            except Exception:
                existed = False
            # 设置类型
            try:
                flags = ida_typeinf.NTF_REPLACE if existed else 0  # type: ignore
            except Exception:
                flags = 0
            try:
                ok = ida_typeinf.set_named_type(None, name, flags, tinfo, 0)  # type: ignore
            except Exception as e:
                return {"error": f"set_named_type failed: {e}"}
            kind = "other"
            try:
                if tinfo.is_struct():  # type: ignore
                    kind = "struct"
                elif tinfo.is_union():  # type: ignore
                    kind = "union"
                elif tinfo.is_enum():  # type: ignore
                    kind = "enum"
                elif tinfo.is_typedef():  # type: ignore
                    kind = "typedef"
            except Exception:
                pass
            return {
                "name": name,
                "kind": kind,
                "replaced": bool(existed),
                "success": bool(ok),
            }

        return _run_in_ida(logic)

    return mcp
