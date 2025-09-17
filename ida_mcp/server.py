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
import hashlib
from typing import Callable, Any, List, Annotated

try:
    from pydantic import BaseModel, Field
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
    try:
        import ida_dbg  # type: ignore
    except Exception:  # pragma: no cover
        ida_dbg = None  # type: ignore
    try:
        import ida_frame  # type: ignore
    except Exception:  # pragma: no cover
        ida_frame = None  # type: ignore
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

    # ------------------------------------------------------------------
    # 通用地址解析辅助: 允许工具参数接收 int 或字符串形式地址
    # 支持格式:
    #   1234                (十进制)
    #   0x401000 / 0X401000 (十六进制前缀)
    #   401000h / 401000H   (结尾 h/H 十六进制)
    #   0x40_10_00          (下划线分隔, 会被剔除)
    # 返回: (ok: bool, value: int | None, error: str | None)
    # 说明: 这里不接受负值, 解析失败或越界返回 False。
    def _parse_address(value):  # type: ignore
        import string as _s
        if isinstance(value, int):
            if value < 0:
                return False, None, "invalid address"
            return True, int(value), None
        if isinstance(value, str):
            txt = value.strip()
            if not txt:
                return False, None, "invalid address"
            txt = txt.replace('_', '')
            neg = False
            if txt.startswith(('+', '-')):
                if txt[0] == '-':
                    neg = True
                txt = txt[1:]
            try:
                val = None
                # trailing h 形式
                if txt.lower().endswith('h') and len(txt) > 1:
                    core = txt[:-1]
                    if all(c in _s.hexdigits for c in core):
                        val = int(core, 16)
                    else:
                        return False, None, "invalid address"
                else:
                    # base=0 支持 0x / 0o / 0b
                    val = int(txt, 0)
                if neg:
                    val = -val  # type: ignore
                if val is None or val < 0:  # type: ignore
                    return False, None, "invalid address"
                return True, int(val), None  # type: ignore
            except Exception:
                return False, None, "invalid address"
        return False, None, "invalid address type"

    @mcp.tool(description="Health check: no parameters. Returns { ok: bool, count: int }. ok indicates coordinator reachable; count is number of registered instances (may be 0). On failure returns { ok:false, count:0 }.")
    def check_connection() -> dict:  # type: ignore
        if registry is None:
            return {"ok": False, "count": 0}
        try:
            return registry.check_connection()  # type: ignore
        except Exception:
            return {"ok": False, "count": 0}

    @mcp.tool(description="List ALL instances registered in the coordinator (raw). No params. Returns array of { id, name, port, last_seen, meta?... }. No filtering/dedup; just forwards coordinator state. Returns [] if coordinator unavailable.")
    def list_instances() -> list[dict]:  # type: ignore
        """获取所有已注册实例原始列表 (不进行任何过滤)。"""
        if registry is None:
            return []
        try:
            return registry.get_instances()  # type: ignore
        except Exception as e:  # pragma: no cover
            return [{"error": str(e)}]

    @mcp.tool(description="Get current IDB metadata. No params. Returns { input_file, arch, arch_raw, arch_normalized, bits, endian, hash }.\narch_raw = value from IDA (procname / processor module); arch_normalized = heuristic normalized form (x86/x86_64/arm/arm64/mips/mips64/ppc/ppc64/...). endian = 'little' or 'big'. hash = SHA256 of input file if readable; may be None. If outside IDA returns note.")
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
            # 额外回退: 若 arch 仍为空, 尝试使用处理器模块名称 API
            if not arch:
                for fn_name in ('ph_get_idp_name', 'get_idp_name', 'ph_get_id', 'ph_get_idp_desc'):
                    try:
                        fn = getattr(idaapi, fn_name, None)  # type: ignore
                        if callable(fn):
                            cand = fn()
                            if isinstance(cand, bytes):
                                cand = cand.decode(errors='ignore')
                            if cand:
                                arch = cand
                                break
                    except Exception:
                        continue
            # 若 bits 仍未确定 (极端情况返回 0), 做简单启发
            if not bits:
                try:
                    # 尝试再次获取 inf 判定
                    inf2 = idaapi.get_inf_structure()  # type: ignore
                    try:
                        if hasattr(inf2, 'is_64bit') and inf2.is_64bit():  # type: ignore
                            bits = 64
                        elif hasattr(inf2, 'is_32bit') and inf2.is_32bit():  # type: ignore
                            bits = 32
                    except Exception:
                        pass
                except Exception:
                    pass
            # 仍未知则根据 Python 宏 (在某些版本 __EA64__) 做最终推断
            if not bits:
                try:
                    if getattr(idaapi, '__EA64__', False):  # type: ignore
                        bits = 64
                    else:
                        bits = 32  # 默认回退
                except Exception:
                    bits = 0
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
            # 归一化架构名称
            def _normalize_arch(raw: str | None, bits_val: int) -> str | None:
                if not raw:
                    return None
                r = raw.lower()
                # x86 family
                if r in ("pc", "metapc", "i386", "x86"):
                    return "x86_64" if bits_val == 64 else "x86"
                if r in ("amd64", "x86_64", "x64"):
                    return "x86_64"
                # ARM family
                if r in ("aarch64", "arm64") or r.startswith("arm64"):
                    return "arm64"
                if r.startswith("arm"):
                    return "arm"
                # MIPS
                if r in ("mips64", "mips64el"):
                    return "mips64"
                if r.startswith("mips"):
                    return "mips"
                # PowerPC
                if r in ("powerpc64", "ppc64") or r.startswith("ppc64"):
                    return "ppc64"
                if r.startswith("ppc") or r.startswith("powerpc"):
                    return "ppc"
                return raw

            arch_for_norm: str | None = arch if isinstance(arch, str) else None
            arch_normalized = _normalize_arch(arch_for_norm, bits)

            # 端序 (endianness)
            endian = None
            try:
                inf3 = idaapi.get_inf_structure()  # type: ignore
                try:
                    if hasattr(inf3, 'is_be') and inf3.is_be():  # type: ignore
                        endian = 'big'
                    else:
                        endian = 'little'
                except Exception:
                    endian = None
            except Exception:
                endian = None

            return {
                "input_file": input_file,
                "arch": arch_normalized or arch,  # 保持向后兼容 (arch 字段给出更友好值)
                "arch_raw": arch,
                "arch_normalized": arch_normalized,
                "bits": bits,
                "endian": endian,
                "hash": file_hash,
            }

        return _run_in_ida(logic)


    @mcp.tool(description="List all functions. No params. Returns [ { name, start_ea, end_ea } ]. Iterates idautils.Functions; no pagination (caller truncates if needed).")
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

    @mcp.tool(description="Get function by name: param name (str, exact case‑sensitive IDA display name). Returns { name,start_ea,end_ea } or { error }. If multiple (rare) returns first. No fuzzy search.")
    def get_function_by_name(
        name: Annotated[str, Field(description="Exact function name (case-sensitive, matches IDA display name)")]
    ) -> dict:  # type: ignore
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

    @mcp.tool(description="Get function by address: param address accepts INT or STRING (decimal or hex). Supported formats: 1234 (dec), 0x401000 / 0X401000, 401000h (trailing h), optional underscores (0x40_10_00). Address may be any EA inside the function. Returns { name,start_ea,end_ea,input,address } or { error }. Uses ida_funcs.get_func to resolve owning function. Errors: invalid address (parse failure), not found (no containing function).")
    def get_function_by_address(
        address: Annotated[int, Field(description="Function start or any address inside; also accepts decimal / 0x hex / trailing 'h' / underscores when passed as string")]
    ) -> dict:  # type: ignore
        """按地址获取函数信息 (兼容十进制 / 十六进制多种输入形式)。

        参数 address 支持:
            * 直接的整数 (JSON number) —— 视为十进制数值;
            * 字符串十进制: "123456";
            * 字符串十六进制: "0x401000" / "0X401000";
            * 末尾 h 形式: "401000h";
            * 允许下划线分隔: "0x40_10_00";
        若解析失败返回 { error: "invalid address" }。
        若地址处于某函数内部, 也返回该函数 (依赖 ida_funcs.get_func)。
        返回:
            { name, start_ea, end_ea, input, address } 或 { error }。
        """
        if address is None:
            return {"error": "invalid address"}

        original_input = address

        # 解析输入地址 (容忍字符串形式)
        if isinstance(address, str):
            txt = address.strip().replace('_', '')
            # trailing h hex (e.g., 401000h, -1Ah)
            try:
                if txt.lower().endswith('h') and len(txt) > 1:
                    core = txt[:-1]
                    sign = ''
                    if core.startswith(('+', '-')):
                        sign = core[0]
                        core = core[1:]
                    if core and all(c in '0123456789abcdefABCDEF' for c in core):
                        address = int(sign + '0x' + core, 0)
                    else:
                        return {"error": "invalid address"}
                else:
                    # int with base=0 supports 0x / 0X / 0b / decimal
                    address = int(txt, 0)
            except Exception:
                return {"error": "invalid address"}
        elif not isinstance(address, int):
            return {"error": "invalid address"}

        if address < 0:
            return {"error": "invalid address"}

        ea_int = int(address)

        def logic():
            try:
                f = ida_funcs.get_func(ea_int)  # type: ignore
            except Exception:
                f = None
            if not f:
                return {"error": "not found", "input": original_input}
            try:
                name = idaapi.get_func_name(f.start_ea)  # type: ignore
            except Exception:
                name = "?"
            return {
                "name": name,
                "start_ea": int(f.start_ea),
                "end_ea": int(f.end_ea),
                "input": original_input,
                "address": ea_int,
            }

        return _run_in_ida(logic)

    @mcp.tool(description="Get current caret address: no params. Returns { address } or { error }. Uses get_screen_ea; invalid view focus yields error.")
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

    @mcp.tool(description="Get function at caret: no params. If caret inside a function returns { name,start_ea,end_ea }; else { error }. Provides quick context discovery.")
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

    @mcp.tool(description="Numeric conversion: params text(str) & size(8|16|32|64). Supports 0x / 0b / trailing 'h' / sign / underscores. Returns multi‑representation { hex,dec,unsigned,signed,bin,bytes_le,bytes_be } or { error }.")
    def convert_number(
        text: Annotated[str, Field(description="Numeric text: supports decimal, 0x..., 0b..., trailing 'h' hex, underscores, optional +/- sign")],
        size: Annotated[int, Field(description="Bit width: one of 8,16,32,64")],
    ) -> dict:  # type: ignore
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

    @mcp.tool(description="List global (non‑function) symbols with optional substring filter: params offset>=0, count(1..1000), filter(optional case‑insensitive). Returns { total,offset,count,items:[{ name,ea,size }] }. Skips function start addresses. size from ida_bytes.get_item_size or None.")
    def list_globals_filter(
        offset: Annotated[int, Field(description="Pagination start offset (>=0)")],
        count: Annotated[int, Field(description="Number of items to return (1..1000)")],
        filter: Annotated[str | None, Field(description="Optional case-insensitive name substring filter")] = None,
    ) -> dict:  # type: ignore
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

    @mcp.tool(description="List all global (non‑function) symbols: params offset,count. Returns { total,offset,count,items }. Same as list_globals_filter without filtering.")
    def list_globals(
        offset: Annotated[int, Field(description="Pagination start offset (>=0)")],
        count: Annotated[int, Field(description="Number of items to return (1..1000)")],
    ) -> dict:  # type: ignore
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

    @mcp.tool(description="List extracted strings with optional filter: params offset,count,filter(optional substring, case‑insensitive). Returns { total,offset,count,items:[{ ea,length,type,text }] }. Auto‑initializes idautils.Strings if needed.")
    def list_strings_filter(
        offset: Annotated[int, Field(description="Pagination start offset (>=0)")],
        count: Annotated[int, Field(description="Number of items to return (1..1000)")],
        filter: Annotated[str | None, Field(description="Optional case-insensitive substring filter")]= None,
    ) -> dict:  # type: ignore
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

    @mcp.tool(description="List all extracted strings (no filter): params offset,count. Returns same structure as list_strings_filter minus filter handling.")
    def list_strings(
        offset: Annotated[int, Field(description="Pagination start offset (>=0)")],
        count: Annotated[int, Field(description="Number of items to return (1..1000)")],
    ) -> dict:  # type: ignore
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

    @mcp.tool(description="List local types: no params. Returns { total, items:[{ ordinal,name,decl }] }. decl is single‑line (<=512 chars). Requires ida_typeinf; returns empty with note otherwise.")
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

    @mcp.tool(description="Decompile function (Hex‑Rays): param address (function start or inside). Returns { name,start_ea,end_ea,address,decompiled } or { error }. Output untruncated; caller may truncate. Fails if Hex‑Rays unavailable/init fails.")
    def decompile_function(
        address: Annotated[int, Field(description="Function start address or any address inside it")]
    ) -> dict:  # type: ignore
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

    @mcp.tool(description="Disassemble function: param start_address (function start or inside). Returns { name,start_ea,end_ea,instructions:[{ ea,bytes,text,comment }] } or { error }. bytes truncated after 16 bytes (..). Code items only.")
    def disassemble_function(
        start_address: Annotated[int, Field(description="Function start (internal address auto-normalized)")]
    ) -> dict:  # type: ignore
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

    @mcp.tool(description="List incoming xrefs: param address(int). Returns { address,total,xrefs:[{ frm,type,iscode }] } or { error }. type is raw xref_t.type; iscode indicates code reference.")
    def get_xrefs_to(
        address: Annotated[int, Field(description="Target address (instruction or data item)")]
    ) -> dict:  # type: ignore
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

    @mcp.tool(description="Heuristic struct field reference search: params struct_name, field_name. Returns { struct,field,offset,matches:[{ ea,line }],truncated?,note? } or { error }. Uses name substring + offset literal match. Max 500 results; may contain false positives/negatives.")
    def get_xrefs_to_field(
        struct_name: Annotated[str, Field(description="Struct name (as in Local Types)")],
        field_name: Annotated[str, Field(description="Exact struct field name")],
    ) -> dict:  # type: ignore
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

    @mcp.tool(description="Set/clear non‑repeatable comment: params address(int|string), comment(str, empty => clear). Accepts 0x / decimal / trailing h / underscores. Returns { address,old,new,changed } or { error }. Non‑repeatable shows in pseudocode. Comment truncated to 1024 chars.")
    def set_comment(
        address: Annotated[int | str, Field(description="Target address (instruction or data item). Accepts int or string forms: 0x..., 1234, 401000h")],
        comment: Annotated[str, Field(description="Comment text; empty string clears (max 1024 chars)")],
    ) -> dict:  # type: ignore
        """为指定地址设置(或清除)普通注释 (支持字符串地址形式)。

        地址格式支持:
            * 十进制: 1234
            * 0x 前缀十六进制: 0x401000
            * 结尾 h: 401000h
            * 可含下划线: 0x40_10_00
        """
        if address is None:
            return {"error": "invalid address"}
        if not HAVE_IDA:
            return {"error": "not in IDA"}
        if comment is None:
            return {"error": "comment is None"}

        ok, addr_int, err = _parse_address(address)
        if not ok or addr_int is None:
            return {"error": err or "invalid address"}

        def logic():
            try:
                old = idaapi.get_cmt(addr_int, 0)  # type: ignore
            except Exception:
                old = None
            new_text = comment.strip()
            if len(new_text) > 1024:
                new_text = new_text[:1024]
            try:
                ok2 = idaapi.set_cmt(addr_int, new_text if new_text else None, 0)  # type: ignore
            except Exception as e:
                return {"error": f"set failed: {e}"}
            return {
                "address": int(addr_int),
                "old": old,
                "new": new_text if new_text else None,
                "changed": old != (new_text if new_text else None) and ok2,
            }

        return _run_in_ida(logic)

    @mcp.tool(description="Linear disassemble from arbitrary address: params start_address(int|string), count(1..64). Success: { start_address,count,instructions:[{ ea,bytes,text,is_code,len }], truncated? }. Errors: { error: 'no_segment' | 'decode_failed' | 'no_instructions' | 'invalid start_address' }. Stops early on decode failure or segment end.")
    def linear_disassemble(
        start_address: Annotated[int | str, Field(description="Starting address (int or string: 0x..., 1234, 401000h)")],
        count: Annotated[int, Field(description="Max number of instructions to decode (1..64)")],
    ) -> dict:  # type: ignore
        """从任意地址按线性方式反汇编若干条指令 (不要求属于函数)。

        参数:
            start_address: 起始线性地址 (必须在已映射段内)。
            count: 反汇编指令最大条数 (1..64)。
        返回:
            { start_address, count, instructions: [ { ea, bytes, text, is_code, len } ... ], truncated? }
            或 { error }。
        行为/说明:
            * 不借助 ida_funcs 边界; 逐条 decode_insn, 前进 insn.size 字节。
            * 第一条即无法定位到段 -> 返回 { error: 'no_segment' }。
            * 第一条 decode_insn 失败 -> 返回 { error: 'decode_failed' }。
            * bytes 最多 16 字节展示 (超过截断)。
            * 不收集注释; 仅返回最小必要指令信息。
            * 若过程中某条 decode 失败 (size=0) 且已有至少 1 条, 终止并返回已收集 (视为成功)。
            * 若最终收集 0 条 -> 返回 { error: 'no_instructions' }。
        """
        if start_address is None:
            return {"error": "invalid start_address"}
        if count < 1 or count > 64:
            return {"error": "count out of range (1..64)"}
        if not HAVE_IDA:
            return {"error": "not in IDA"}

        ok, addr_int, err = _parse_address(start_address)
        if not ok or addr_int is None:
            return {"error": err or "invalid start_address"}
        if addr_int < 0:
            return {"error": "invalid start_address"}

        def logic():
            ea = int(addr_int)
            # 首先确认段存在
            try:
                if hasattr(idaapi, 'getseg') and not idaapi.getseg(ea):  # type: ignore
                    return {'error': 'no_segment'}
            except Exception:
                # 若 getseg 本身异常, 继续尝试 decode (容忍老版本)
                pass
            collected: list[dict] = []
            for _ in range(count):
                try:
                    insn = idaapi.insn_t()  # type: ignore
                    size = 0
                    try:
                        if idaapi.decode_insn(insn, ea):  # type: ignore
                            size = insn.size  # type: ignore
                    except Exception:
                        size = 0
                    if size <= 0:
                        # 第一条失败 -> 报错
                        if not collected:
                            return {'error': 'decode_failed'}
                        # 后续某条失败 -> 结束, 视为成功
                        break
                    # 读取 flags 判定 is_code
                    is_code = False
                    try:
                        flags = idaapi.get_full_flags(ea)  # type: ignore
                        is_code = bool(idaapi.is_code(flags))  # type: ignore
                    except Exception:
                        pass
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
                        text = '?'
                    # bytes
                    b_hex = None
                    if ida_bytes:  # type: ignore
                        try:
                            raw = ida_bytes.get_bytes(ea, size)  # type: ignore
                            if raw:
                                b_hex = raw.hex().upper()
                                if len(b_hex) > 32:
                                    b_hex = b_hex[:32] + '...'
                        except Exception:
                            b_hex = None
                    collected.append({
                        'ea': int(ea),
                        'bytes': b_hex,
                        'text': text,
                        'is_code': is_code,
                        'len': size,
                    })
                    ea += size
                except Exception:
                    # 意外异常: 若尚无指令 -> decode 失败; 否则结束
                    if not collected:
                        return {'error': 'decode_failed'}
                    break
            if not collected:
                return {'error': 'no_instructions'}
            result: dict = {
                'start_address': int(addr_int),
                'count': count,
                'instructions': collected,
            }
            if len(collected) >= count:
                result['truncated'] = True
            return result

        return _run_in_ida(logic)

    @mcp.tool(description="Rename local variable (Hex‑Rays): params function_address, old_name, new_name(C identifier). Returns { function,start_ea,old_name,new_name,changed } or { error }. Only first matching lvar changed.")
    def rename_local_variable(
        function_address: Annotated[int, Field(description="Function start or internal address")],
        old_name: Annotated[str, Field(description="Old local variable name (exact match)")],
        new_name: Annotated[str, Field(description="New variable name (valid C identifier, <=255)")],
    ) -> dict:  # type: ignore
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

    @mcp.tool(description="Rename global variable: params old_name,new_name. Returns { ea,old_name,new_name,changed } or { error }. Rejects if address is function start (use function rename). New name must be C identifier.")
    def rename_global_variable(
        old_name: Annotated[str, Field(description="Existing global symbol name (exact match)")],
        new_name: Annotated[str, Field(description="New name (valid C identifier, <=255)")],
    ) -> dict:  # type: ignore
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

    @mcp.tool(description="Rename function: params function_address(start or inside), new_name(C identifier). Returns { start_ea,old_name,new_name,changed } or { error }. Internal address auto‑normalized to start.")
    def rename_function(
        function_address: Annotated[int, Field(description="Function start or internal address")],
        new_name: Annotated[str, Field(description="New function name (valid C identifier, <=255)")],
    ) -> dict:  # type: ignore
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

    @mcp.tool(description="Set function prototype: params function_address, prototype(full C decl, may include name). Returns { start_ea,applied,old_type,new_type,parsed_name? } or { error,details? }. Does NOT auto‑rename function.")
    def set_function_prototype(
        function_address: Annotated[int, Field(description="Function start or internal address")],
        prototype: Annotated[str, Field(description="Full C function declaration (may include name)")],
    ) -> dict:  # type: ignore
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

    @mcp.tool(description="Set local variable type (Hex‑Rays): params function_address, variable_name, new_type(C fragment). Returns { function,start_ea,variable_name,old_type,new_type,applied } or { error }. Parsing wrapper '<type> tmp;'.")
    def set_local_variable_type(
        function_address: Annotated[int, Field(description="Function start or internal address")],
        variable_name: Annotated[str, Field(description="Local variable original name (exact match)")],
        new_type: Annotated[str, Field(description="C type fragment (e.g. int, char *, MyStruct *)")],
    ) -> dict:  # type: ignore
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

    @mcp.tool(description="List all entry points: no params. Returns { total, items:[{ ordinal,ea,name }] }. If entry name missing, attempts function name fallback. Outside IDA returns note.")
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

    @mcp.tool(description="Set global variable type: params variable_name, new_type(C fragment). Returns { ea,variable_name,old_type,new_type,applied } or { error,details? }. Rejects function starts. Parsing wrapper '<type> __tmp_var;'.")
    def set_global_variable_type(
        variable_name: Annotated[str, Field(description="Global symbol name (must exist and not be a function start)")],
        new_type: Annotated[str, Field(description="C type fragment (e.g. int, char *, MyStruct)")],
    ) -> dict:  # type: ignore
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

    @mcp.tool(description="Declare / update a local type: param c_declaration(single struct/union/enum/typedef). Returns { name,kind,replaced,success } or { error,details? }. Existing name replaced (NTF_REPLACE). kind derived from tinfo.")
    def declare_c_type(
        c_declaration: Annotated[str, Field(description="Single struct/union/enum/typedef declaration (ending with semicolon)")]
    ) -> dict:  # type: ignore
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

    @mcp.tool(description="Debugger registers snapshot: no params. If active returns { ok:true,registers:[{ name,value,int? }] }; inactive returns { ok:false,registers:[],note }. Values hex‑formatted; failures skipped.")
    def dbg_get_registers() -> dict:  # type: ignore
        """获取所有调试寄存器及其值 (仅在调试器附加/运行时有效)。

        返回:
            { ok: bool, registers: [ { name, value } ... ], note? } 或 { error }。
        说明:
            * 需要 ida_dbg 模块可用且调试器已启动 (is_debugger_on)。
            * 通过 get_dbg_reg_names() 获取寄存器名列表, 再用 get_reg_val 读取。
            * 读取失败的寄存器跳过; 返回十六进制字符串形式 (根据位宽格式化)。
        限制:
            * 不包含浮点 / SIMD 拆分字段的结构化解析, 仅原始值。
        """
        if not HAVE_IDA:
            return {"error": "not in IDA"}
        if 'ida_dbg' not in globals() or ida_dbg is None:  # type: ignore
            return {"error": "ida_dbg module missing"}

        def logic():
            try:
                if not ida_dbg.is_debugger_on():  # type: ignore
                    return {"ok": False, "registers": [], "note": "debugger not active"}
            except Exception:
                return {"error": "cannot determine debugger state"}
            regs: list[dict] = []
            names: list[str] = []
            try:
                names = list(ida_dbg.get_dbg_reg_names())  # type: ignore
            except Exception:
                names = []
            for n in names:
                try:
                    v = ida_dbg.get_reg_val(n)  # type: ignore
                    # 尝试根据值大小格式化; IDA 可能返回 int 或 long
                    if isinstance(v, int):
                        # 选择最接近的宽度 (8/16/32/64) 用于零填充
                        bits = 8
                        if v > 0xFFFFFFFF:
                            bits = 64
                        elif v > 0xFFFF:
                            bits = 32
                        elif v > 0xFF:
                            bits = 16
                        width = bits // 4
                        regs.append({"name": n, "value": f"0x{v:0{width}X}", "int": int(v)})
                    else:
                        regs.append({"name": n, "value": repr(v)})
                except Exception:
                    continue
            return {"ok": True, "registers": regs}

        return _run_in_ida(logic)

    @mcp.tool(description="Get call stack: no params. Returns { ok,frames:[{ index,ea,func }],note? } or { error }. Prefers get_call_stack; falls back to walk_stack. Inactive debugger => ok:false.")
    def dbg_get_call_stack() -> dict:  # type: ignore
        """获取当前调用栈 (仅调试状态)。

        返回:
            { ok: bool, frames: [ { index, ea, func, name? } ... ], note? } 或 { error }。
        说明:
            * 使用 ida_dbg.get_current_thread / get_process_state + get_dbg_reg_val / get_frame ea 方式存在架构差异。
            * 这里采用 ida_dbg.get_call_stack / get_call_stack(invalidated) 不同版本兼容策略 (若可用)。
            * 回退: 尝试 ida_dbg.get_frame(ea) 不同 API 组合；若失败返回 ok=False。
        限制:
            * 不解析参数, 仅地址与函数名。
            * 某些架构或无调试符号时函数名可能为空。
        """
        if not HAVE_IDA:
            return {"error": "not in IDA"}
        if 'ida_dbg' not in globals() or ida_dbg is None:  # type: ignore
            return {"error": "ida_dbg module missing"}

        def logic():
            try:
                if not ida_dbg.is_debugger_on():  # type: ignore
                    return {"ok": False, "frames": [], "note": "debugger not active"}
            except Exception:
                return {"error": "cannot determine debugger state"}
            frames: list[dict] = []
            collected = False
            # 优先使用官方 call stack API (某些版本提供)
            try:
                if hasattr(ida_dbg, 'get_call_stack'):  # type: ignore
                    stk = ida_dbg.get_call_stack()  # type: ignore
                    # 可能返回 list[call_stack_item_t]
                    for idx, item in enumerate(stk or []):  # type: ignore
                        try:
                            ea = int(getattr(item, 'ea', 0))
                            func_name = None
                            try:
                                f = ida_funcs.get_func(ea)  # type: ignore
                                if f:
                                    func_name = idaapi.get_func_name(f.start_ea)  # type: ignore
                            except Exception:
                                func_name = None
                            frames.append({
                                'index': idx,
                                'ea': ea,
                                'func': func_name,
                            })
                        except Exception:
                            continue
                    if frames:
                        collected = True
            except Exception:
                pass
            # 回退: 尝试使用 ida_dbg.get_current_thread + walk_stack (有些版本)
            if not collected:
                try:
                    if hasattr(ida_dbg, 'walk_stack'):  # type: ignore
                        ws = []
                        def _cb(entry):  # type: ignore
                            try:
                                ea = int(getattr(entry, 'ea', 0))
                                func_name = None
                                try:
                                    f = ida_funcs.get_func(ea)  # type: ignore
                                    if f:
                                        func_name = idaapi.get_func_name(f.start_ea)  # type: ignore
                                except Exception:
                                    func_name = None
                                ws.append(ea)
                                frames.append({
                                    'index': len(frames),
                                    'ea': ea,
                                    'func': func_name,
                                })
                            except Exception:
                                return False
                            return True
                        ida_dbg.walk_stack(_cb)  # type: ignore
                        if frames:
                            collected = True
                except Exception:
                    pass
            if not collected:
                return {"ok": False, "frames": [], "note": "call stack API unavailable or empty"}
            return {"ok": True, "frames": frames}

        return _run_in_ida(logic)

    @mcp.tool(description="List breakpoints: no params. Active debugger => { ok:true,total,breakpoints:[{ ea,enabled?,size?,type?,cond?,pass_count? }] }; inactive => ok:false with note. Only available attrs returned.")
    def dbg_list_breakpoints() -> dict:  # type: ignore
        """列出程序中当前设置的所有断点 (仅调试状态)。

        返回:
            { ok: bool, total, breakpoints: [ { ea, enabled, size?, type?, cond?, pass_count?, hits? } ... ], note? } 或 { error }。
        说明:
            * 需要 ida_dbg 模块且调试器已启动。
            * 使用 get_bpt_qty / get_bpt_ea / get_bpt_attr 收集信息; 某些字段若 API 不存在或获取失败则跳过。
            * enabled 基于 flags & BPT_ENABLED。
        """
        if not HAVE_IDA:
            return {"error": "not in IDA"}
        if 'ida_dbg' not in globals() or ida_dbg is None:  # type: ignore
            return {"error": "ida_dbg module missing"}

        def logic():
            try:
                if not ida_dbg.is_debugger_on():  # type: ignore
                    return {"ok": False, "total": 0, "breakpoints": [], "note": "debugger not active"}
            except Exception:
                return {"error": "cannot determine debugger state"}
            bps: list[dict] = []
            qty = 0
            try:
                qty = ida_dbg.get_bpt_qty()  # type: ignore
            except Exception:
                qty = 0
            for i in range(qty):
                try:
                    ea = ida_dbg.get_bpt_ea(i)  # type: ignore
                except Exception:
                    continue
                if ea in (None, idaapi.BADADDR):  # type: ignore
                    continue
                info: dict = { 'ea': int(ea) }
                # flags / enabled
                flags = None
                try:
                    if hasattr(ida_dbg, 'get_bpt_attr'):  # type: ignore
                        flags = ida_dbg.get_bpt_attr(ea, ida_dbg.BPTATTR_FLAGS)  # type: ignore
                    elif hasattr(ida_dbg, 'get_bpt_flags'):  # type: ignore
                        flags = ida_dbg.get_bpt_flags(ea)  # type: ignore
                except Exception:
                    flags = None
                enabled = None
                try:
                    if flags is not None and hasattr(ida_dbg, 'BPT_ENABLED'):
                        enabled = bool(flags & ida_dbg.BPT_ENABLED)  # type: ignore
                except Exception:
                    enabled = None
                if enabled is not None:
                    info['enabled'] = enabled
                # size
                try:
                    if hasattr(ida_dbg, 'get_bpt_attr'):  # type: ignore
                        sz = ida_dbg.get_bpt_attr(ea, ida_dbg.BPTATTR_SIZE)  # type: ignore
                        if isinstance(sz, int) and sz > 0:
                            info['size'] = int(sz)
                except Exception:
                    pass
                # type
                try:
                    if hasattr(ida_dbg, 'get_bpt_attr'):  # type: ignore
                        tp = ida_dbg.get_bpt_attr(ea, ida_dbg.BPTATTR_TYPE)  # type: ignore
                        if isinstance(tp, int):
                            info['type'] = int(tp)
                except Exception:
                    pass
                # condition
                try:
                    if hasattr(ida_dbg, 'get_bpt_attr'):  # type: ignore
                        cond = ida_dbg.get_bpt_attr(ea, ida_dbg.BPTATTR_COND)  # type: ignore
                        if cond:
                            info['cond'] = cond
                except Exception:
                    pass
                # pass count
                try:
                    if hasattr(ida_dbg, 'get_bpt_attr'):  # type: ignore
                        pc = ida_dbg.get_bpt_attr(ea, ida_dbg.BPTATTR_PASSCNT)  # type: ignore
                        if isinstance(pc, int):
                            info['pass_count'] = int(pc)
                except Exception:
                    pass
                # hit count (IDA 有时无直接 API; 尝试 PASSCNT - remaining?)
                # 暂不推断 hits, 仅保留 pass_count
                bps.append(info)
            return {"ok": True, "total": len(bps), "breakpoints": bps}

        return _run_in_ida(logic)

    @mcp.tool(description="Start debugger: no params. If already running returns { ok:true,started:false,note }. Else attempts start_process with input file path; success returns pid. Some file types may fail to start.")
    def dbg_start_process() -> dict:  # type: ignore
        """启动调试会话 (若尚未启动)。

        行为:
            * 若调试器已激活, 返回 { ok: True, started: False, note: 'already running' }。
            * 否则尝试使用 idaapi.get_input_file_path() 作为可执行路径调用 ida_dbg.start_process。
        返回:
            { ok: bool, started: bool, pid?, note? } 或 { error }。
        限制:
            * 不设置自定义参数/工作目录/环境变量 (可后续扩展)。
            * 某些文件类型 (如纯对象文件) 可能无法直接启动调试。
        """
        if not HAVE_IDA:
            return {"error": "not in IDA"}
        if 'ida_dbg' not in globals() or ida_dbg is None:  # type: ignore
            return {"error": "ida_dbg module missing"}

        def logic():
            try:
                if ida_dbg.is_debugger_on():  # type: ignore
                    return {"ok": True, "started": False, "note": "debugger already running"}
            except Exception:
                pass
            # 取输入文件路径
            try:
                path = idaapi.get_input_file_path()  # type: ignore
            except Exception:
                path = None
            if not path:
                return {"error": "cannot determine input file path"}
            # 启动
            try:
                started = ida_dbg.start_process(path, '', None)  # type: ignore
            except Exception as e:
                return {"error": f"start_process failed: {e}"}
            ok = bool(started)
            pid = None
            if ok:
                try:
                    pid = ida_dbg.get_process_state().pid  # type: ignore
                except Exception:
                    pid = None
            return {"ok": ok, "started": ok, "pid": pid}

        return _run_in_ida(logic)

    @mcp.tool(description="Terminate debug process: no params. Inactive => { ok:false,exited:false,note }. Active => calls exit_process returning { ok:true,exited:true }. Non‑blocking.")
    def dbg_exit_process() -> dict:  # type: ignore
        """退出当前调试进程。

        行为:
            * 若调试器未激活 -> 返回 { ok: False, exited: False, note: 'debugger not active' }
            * 否则调用 ida_dbg.exit_process。
        返回:
            { ok: bool, exited: bool, note? } 或 { error }。
        限制:
            * 不做强制等待; 若 API 报错返回 error。
        """
        if not HAVE_IDA:
            return {"error": "not in IDA"}
        if 'ida_dbg' not in globals() or ida_dbg is None:  # type: ignore
            return {"error": "ida_dbg module missing"}

        def logic():
            try:
                if not ida_dbg.is_debugger_on():  # type: ignore
                    return {"ok": False, "exited": False, "note": "debugger not active"}
            except Exception:
                return {"error": "cannot determine debugger state"}
            try:
                ida_dbg.exit_process()  # type: ignore
            except Exception as e:
                return {"error": f"exit_process failed: {e}"}
            return {"ok": True, "exited": True}

        return _run_in_ida(logic)

    @mcp.tool(description="Continue execution: no params. Calls continue_process or continue_execution. Returns { ok,continued,note? } or { error }. Inactive => ok:false. Non‑blocking.")
    def dbg_continue_process() -> dict:  # type: ignore
        """继续 (resume) 调试进程执行。

        行为:
            * 若调试器未激活: 返回 ok=False, note。
            * 调用 ida_dbg.continue_process() (若存在) 或 ida_dbg.continue_execution() 兼容不同版本。
        返回:
            { ok: bool, continued: bool, note? } 或 { error }。
        限制:
            * 不等待执行结果; 仅发出继续请求。
        """
        if not HAVE_IDA:
            return {"error": "not in IDA"}
        if 'ida_dbg' not in globals() or ida_dbg is None:  # type: ignore
            return {"error": "ida_dbg module missing"}

        def logic():
            try:
                if not ida_dbg.is_debugger_on():  # type: ignore
                    return {"ok": False, "continued": False, "note": "debugger not active"}
            except Exception:
                return {"error": "cannot determine debugger state"}
            # Attempt continue
            cont_ok = False
            errors: list[str] = []
            tried = False
            try:
                if hasattr(ida_dbg, 'continue_process'):  # type: ignore
                    tried = True
                    cont_ok = bool(ida_dbg.continue_process())  # type: ignore
            except Exception as e:
                errors.append(f"continue_process: {e}")
            if not cont_ok:
                try:
                    if hasattr(ida_dbg, 'continue_execution'):  # type: ignore
                        tried = True
                        cont_ok = bool(ida_dbg.continue_execution())  # type: ignore
                except Exception as e:
                    errors.append(f"continue_execution: {e}")
            if not tried:
                return {"error": "no continue API available"}
            if not cont_ok and errors:
                return {"ok": False, "continued": False, "note": "; ".join(errors)[:200]}
            return {"ok": True, "continued": bool(cont_ok)}

        return _run_in_ida(logic)

    @mcp.tool(description="Run to address: param address. Prefers request_run_to; fallback creates temp breakpoint then continue. Returns { ok,requested,continued,used_temp_bpt,note? } or { error }. Non‑blocking (does not wait for hit).")
    def dbg_run_to(
        address: Annotated[int, Field(description="Target address to run to (may be inside a function)")]
    ) -> dict:  # type: ignore
        """运行到指定地址。

        参数:
            address: 目标地址 (需要在当前程序地址空间内)。
        行为:
            1. 确认调试器已激活。
            2. 优先调用 ida_dbg.request_run_to(address) (若可用)。
            3. 若 API 不可用或失败, 设置一个临时断点 (set_bpt) 并记录 used_temp_bpt=True。
            4. 继续执行 (continue_process / continue_execution)。
        返回:
            { ok, requested, continued, used_temp_bpt, note? } 或 { error }。
        限制:
            * 不等待实际到达; 只是发出请求。
            * 若地址无效 (BADADDR) 返回错误。
        """
        if not HAVE_IDA:
            return {"error": "not in IDA"}
        if 'ida_dbg' not in globals() or ida_dbg is None:  # type: ignore
            return {"error": "ida_dbg module missing"}
        if address is None:
            return {"error": "invalid address"}

        def logic():
            # 验证调试器状态
            try:
                if not ida_dbg.is_debugger_on():  # type: ignore
                    return {"error": "debugger not active"}
            except Exception:
                return {"error": "cannot determine debugger state"}
            if int(address) == idaapi.BADADDR:  # type: ignore
                return {"error": "BADADDR"}
            requested = False
            used_temp_bpt = False
            notes: list[str] = []
            # 尝试 request_run_to
            try:
                if hasattr(ida_dbg, 'request_run_to'):  # type: ignore
                    requested = bool(ida_dbg.request_run_to(address))  # type: ignore
                    if not requested:
                        notes.append('request_run_to returned False')
                else:
                    notes.append('request_run_to unavailable')
            except Exception as e:
                notes.append(f'request_run_to error: {e}')
            # 退回设置临时断点
            if not requested:
                try:
                    # 仅在不存在断点时设置, 避免重复
                    has_bp = False
                    try:
                        if hasattr(ida_dbg, 'get_bpt_flags'):  # type: ignore
                            has_bp = ida_dbg.get_bpt_flags(address) != -1  # type: ignore
                        elif hasattr(ida_dbg, 'get_bpt_attr'):  # type: ignore
                            # 试探读取 flags
                            _flags = ida_dbg.get_bpt_attr(address, ida_dbg.BPTATTR_FLAGS)  # type: ignore
                            has_bp = _flags is not None
                    except Exception:
                        has_bp = False
                    if not has_bp and hasattr(ida_dbg, 'add_bpt'):  # type: ignore
                        # 有的版本是 add_bpt(ea, size, type) 或 set_bpt(ea)
                        try:
                            added = False
                            if hasattr(ida_dbg, 'add_bpt'):  # type: ignore
                                # 尝试 add_bpt(ea, 0, BPT_DEFAULT) 若存在 BPT_DEFAULT
                                if hasattr(ida_dbg, 'BPT_DEFAULT'):
                                    added = bool(ida_dbg.add_bpt(address, 0, ida_dbg.BPT_DEFAULT))  # type: ignore
                                else:
                                    added = bool(ida_dbg.add_bpt(address, 0))  # type: ignore
                            if not added and hasattr(ida_dbg, 'add_bpt'):  # second try plain
                                added = bool(ida_dbg.add_bpt(address))  # type: ignore
                            if not added and hasattr(ida_dbg, 'set_bpt'):  # type: ignore
                                added = bool(ida_dbg.set_bpt(address))  # type: ignore
                            used_temp_bpt = bool(added)
                            if not added:
                                notes.append('failed to add temp breakpoint')
                        except Exception as e:
                            notes.append(f'add_bpt error: {e}')
                except Exception:
                    notes.append('temp breakpoint fallback failed')
            # 继续执行
            continued = False
            try:
                if hasattr(ida_dbg, 'continue_process'):  # type: ignore
                    continued = bool(ida_dbg.continue_process())  # type: ignore
                elif hasattr(ida_dbg, 'continue_execution'):  # type: ignore
                    continued = bool(ida_dbg.continue_execution())  # type: ignore
                else:
                    notes.append('no continue API')
            except Exception as e:
                notes.append(f'continue error: {e}')
            ok = requested or used_temp_bpt
            result: dict[str, object] = {
                'ok': ok,
                'requested': requested,
                'continued': continued,
                'used_temp_bpt': used_temp_bpt,
            }
            if notes:
                result['note'] = '; '.join(notes)[:300]
            return result

        return _run_in_ida(logic)

    @mcp.tool(description="Set / ensure breakpoint: param address. If already present returns existed=true. Tries add_bpt variants / set_bpt. Returns { ok,ea,existed,added,note? } or { error }. Can be used before debugger starts.")
    def dbg_set_breakpoint(
        address: Annotated[int, Field(description="Address where the breakpoint should be set")]
    ) -> dict:  # type: ignore
        """设置指定地址的断点 (若已存在则返回 existed=True)。

        参数:
            address: 目标地址 (指令地址)。
        返回:
            { ok, ea, existed, added, note? } 或 { error }。
        说明:
            * 允许在未启动调试器状态下预设断点。
            * 优先使用 add_bpt(ea, 0, BPT_DEFAULT) 变体; 回退 add_bpt(ea) / set_bpt(ea)。
            * existed 通过 get_bpt_flags / get_bpt_attr 判定。
        """
        if not HAVE_IDA:
            return {"error": "not in IDA"}
        if 'ida_dbg' not in globals() or ida_dbg is None:  # type: ignore
            return {"error": "ida_dbg module missing"}
        if address is None:
            return {"error": "invalid address"}

        def logic():
            if int(address) == idaapi.BADADDR:  # type: ignore
                return {"error": "BADADDR"}
            notes: list[str] = []
            existed = False
            # 检查是否存在断点
            try:
                if hasattr(ida_dbg, 'get_bpt_flags'):  # type: ignore
                    existed = ida_dbg.get_bpt_flags(address) != -1  # type: ignore
                elif hasattr(ida_dbg, 'get_bpt_attr'):  # type: ignore
                    _f = ida_dbg.get_bpt_attr(address, ida_dbg.BPTATTR_FLAGS)  # type: ignore
                    existed = _f is not None
            except Exception:
                existed = False
            added = False
            if not existed:
                try:
                    if hasattr(ida_dbg, 'add_bpt'):  # type: ignore
                        if hasattr(ida_dbg, 'BPT_DEFAULT'):
                            added = bool(ida_dbg.add_bpt(address, 0, ida_dbg.BPT_DEFAULT))  # type: ignore
                            if not added:
                                notes.append('add_bpt default failed')
                        if not added:
                            # try add_bpt(ea,0)
                            try:
                                added = bool(ida_dbg.add_bpt(address, 0))  # type: ignore
                            except Exception:
                                pass
                        if not added:
                            try:
                                added = bool(ida_dbg.add_bpt(address))  # type: ignore
                            except Exception:
                                pass
                    if not added and hasattr(ida_dbg, 'set_bpt'):  # type: ignore
                        try:
                            added = bool(ida_dbg.set_bpt(address))  # type: ignore
                        except Exception as e:
                            notes.append(f'set_bpt error: {e}')
                except Exception as e:
                    notes.append(f'add_bpt error: {e}')
                # 再次验证
                if added:
                    try:
                        if hasattr(ida_dbg, 'get_bpt_flags'):  # type: ignore
                            existed = ida_dbg.get_bpt_flags(address) != -1  # type: ignore
                        elif hasattr(ida_dbg, 'get_bpt_attr'):  # type: ignore
                            _f = ida_dbg.get_bpt_attr(address, ida_dbg.BPTATTR_FLAGS)  # type: ignore
                            existed = _f is not None
                    except Exception:
                        pass
            ok = existed or added
            result: dict[str, object] = {
                'ok': ok,
                'ea': int(address),
                'existed': bool(existed and not added),
                'added': bool(added),
            }
            if notes:
                result['note'] = '; '.join(notes)[:300]
            return result

        return _run_in_ida(logic)

    @mcp.tool(description="Delete breakpoint: param address. Idempotent (missing still ok). Returns { ok,ea,existed,deleted,note? } or { error }. Works pre‑debugger too.")
    def dbg_delete_breakpoint(
        address: Annotated[int, Field(description="Address of the breakpoint to delete")]
    ) -> dict:  # type: ignore
        """删除指定地址的断点。

        参数:
            address: 目标地址。
        返回:
            { ok, ea, existed, deleted, note? } 或 { error }。
        说明:
            * 若不存在断点返回 existed=False, deleted=False, ok=True (视为幂等)。
            * 支持在未启动调试会话状态下操作 (IDA 允许设置/删除预设断点)。
            * 使用 get_bpt_flags / get_bpt_attr 检测存在性; 删除使用 del_bpt / del_bpt(ea)。
        """
        if not HAVE_IDA:
            return {"error": "not in IDA"}
        if 'ida_dbg' not in globals() or ida_dbg is None:  # type: ignore
            return {"error": "ida_dbg module missing"}
        if address is None:
            return {"error": "invalid address"}

        def logic():
            if int(address) == idaapi.BADADDR:  # type: ignore
                return {"error": "BADADDR"}
            notes: list[str] = []
            existed = False
            try:
                if hasattr(ida_dbg, 'get_bpt_flags'):  # type: ignore
                    existed = ida_dbg.get_bpt_flags(address) != -1  # type: ignore
                elif hasattr(ida_dbg, 'get_bpt_attr'):  # type: ignore
                    _f = ida_dbg.get_bpt_attr(address, ida_dbg.BPTATTR_FLAGS)  # type: ignore
                    existed = _f is not None
            except Exception:
                existed = False
            deleted = False
            if existed:
                try:
                    if hasattr(ida_dbg, 'del_bpt'):  # type: ignore
                        deleted = bool(ida_dbg.del_bpt(address))  # type: ignore
                    elif hasattr(ida_dbg, 'del_breakpoint'):  # hypothetical fallback
                        deleted = bool(ida_dbg.del_breakpoint(address))  # type: ignore
                    else:
                        notes.append('no del_bpt API')
                except Exception as e:
                    notes.append(f'del_bpt error: {e}')
                if deleted:
                    # 再验证
                    try:
                        if hasattr(ida_dbg, 'get_bpt_flags'):  # type: ignore
                            existed2 = ida_dbg.get_bpt_flags(address) != -1  # type: ignore
                        elif hasattr(ida_dbg, 'get_bpt_attr'):  # type: ignore
                            _f2 = ida_dbg.get_bpt_attr(address, ida_dbg.BPTATTR_FLAGS)  # type: ignore
                            existed2 = _f2 is not None
                        else:
                            existed2 = False
                        if existed2:
                            notes.append('verification shows breakpoint still present')
                    except Exception:
                        pass
            # 幂等: 不存在也算成功
            ok = not existed or deleted or (existed and deleted)
            result: dict[str, object] = {
                'ok': ok,
                'ea': int(address),
                'existed': bool(existed),
                'deleted': bool(deleted),
            }
            if notes:
                result['note'] = '; '.join(notes)[:300]
            return result

        return _run_in_ida(logic)

    @mcp.tool(description="Enable/disable breakpoint: params address, enable(bool). Enabling a missing breakpoint attempts creation. Returns { ok,ea,existed,enabled,changed,note? } or { error }. changed indicates state/existence modified.")
    def dbg_enable_breakpoint(
        address: Annotated[int, Field(description="Breakpoint address")],
        enable: Annotated[bool, Field(description="True=enable, False=disable; enabling creates if absent")],
    ) -> dict:  # type: ignore
        """启用/禁用指定地址的断点 (若启用且不存在则自动创建)。

        参数:
            address: 目标地址。
            enable: True=启用 / False=禁用。
        返回:
            { ok, ea, existed, enabled, changed, note? } 或 { error }。
        说明:
            * existed 表示操作前是否存在断点。
            * enabled 表示操作后断点是否处于启用状态。
            * changed 表示本次调用是否修改了状态 (创建 / 状态翻转)。
            * 若禁用不存在的断点 => ok=True, existed=False, enabled=False, changed=False。
            * 启用不存在时尝试自动 add_bpt。
        """
        if not HAVE_IDA:
            return {"error": "not in IDA"}
        if 'ida_dbg' not in globals() or ida_dbg is None:  # type: ignore
            return {"error": "ida_dbg module missing"}
        if address is None:
            return {"error": "invalid address"}

        def logic():
            if int(address) == idaapi.BADADDR:  # type: ignore
                return {"error": "BADADDR"}
            notes: list[str] = []
            # 检查是否存在断点
            existed = False
            flags = None
            try:
                if hasattr(ida_dbg, 'get_bpt_flags'):  # type: ignore
                    flags = ida_dbg.get_bpt_flags(address)  # type: ignore
                    existed = flags != -1
                elif hasattr(ida_dbg, 'get_bpt_attr'):  # type: ignore
                    flags = ida_dbg.get_bpt_attr(address, ida_dbg.BPTATTR_FLAGS)  # type: ignore
                    existed = flags is not None
            except Exception:
                existed = False
            changed = False
            # 若需要启用且不存在 -> 创建
            if enable and not existed:
                try:
                    added = False
                    if hasattr(ida_dbg, 'add_bpt'):  # type: ignore
                        if hasattr(ida_dbg, 'BPT_DEFAULT'):
                            added = bool(ida_dbg.add_bpt(address, 0, ida_dbg.BPT_DEFAULT))  # type: ignore
                        if not added:
                            try:
                                added = bool(ida_dbg.add_bpt(address, 0))  # type: ignore
                            except Exception:
                                pass
                        if not added:
                            try:
                                added = bool(ida_dbg.add_bpt(address))  # type: ignore
                            except Exception:
                                pass
                    if not added and hasattr(ida_dbg, 'set_bpt'):  # type: ignore
                        try:
                            added = bool(ida_dbg.set_bpt(address))  # type: ignore
                        except Exception as e:
                            notes.append(f'set_bpt error: {e}')
                    if added:
                        existed = True
                        changed = True
                    else:
                        notes.append('failed to create breakpoint for enable')
                except Exception as e:
                    notes.append(f'add_bpt error: {e}')
            # 若存在 -> 切换启用状态
            if existed:
                # 获取当前 enabled 状态
                currently_enabled = None
                try:
                    if flags is None and hasattr(ida_dbg, 'get_bpt_flags'):  # type: ignore
                        flags = ida_dbg.get_bpt_flags(address)  # type: ignore
                    if flags is not None and hasattr(ida_dbg, 'BPT_ENABLED'):
                        currently_enabled = bool(flags & ida_dbg.BPT_ENABLED)  # type: ignore
                except Exception:
                    currently_enabled = None
                # 若需要改变
                desire = bool(enable)
                if currently_enabled is not None and currently_enabled != desire:
                    try:
                        if hasattr(ida_dbg, 'enable_bpt'):  # type: ignore
                            ok2 = ida_dbg.enable_bpt(address, desire)  # type: ignore
                        else:
                            # 回退: 修改 flags (若有 set_bpt_attr)
                            ok2 = False
                            if hasattr(ida_dbg, 'set_bpt_attr') and hasattr(ida_dbg, 'BPTATTR_FLAGS'):  # type: ignore
                                # 如果禁用, 清除 ENABLED 位; 启用则设置
                                new_flags = flags or 0
                                try:
                                    if desire:
                                        new_flags |= ida_dbg.BPT_ENABLED  # type: ignore
                                    else:
                                        new_flags &= ~ida_dbg.BPT_ENABLED  # type: ignore
                                except Exception:
                                    pass
                                try:
                                    ok2 = bool(ida_dbg.set_bpt_attr(address, ida_dbg.BPTATTR_FLAGS, new_flags))  # type: ignore
                                except Exception as e:
                                    notes.append(f'set_bpt_attr flags error: {e}')
                        if ok2:
                            changed = True
                        else:
                            notes.append('enable/disable operation failed')
                    except Exception as e:
                        notes.append(f'enable_bpt error: {e}')
                # 更新 enabled 状态再次读取
                try:
                    flags2 = None
                    if hasattr(ida_dbg, 'get_bpt_flags'):  # type: ignore
                        flags2 = ida_dbg.get_bpt_flags(address)  # type: ignore
                    elif hasattr(ida_dbg, 'get_bpt_attr'):  # type: ignore
                        flags2 = ida_dbg.get_bpt_attr(address, ida_dbg.BPTATTR_FLAGS)  # type: ignore
                    if flags2 is not None and hasattr(ida_dbg, 'BPT_ENABLED'):
                        enabled_now = bool(flags2 & ida_dbg.BPT_ENABLED)  # type: ignore
                    else:
                        # 如果无法获得, 依赖 desire 近似
                        enabled_now = desire
                except Exception:
                    enabled_now = desire
            else:
                enabled_now = False
            ok = (enable and existed) or (not enable and (not existed or existed)) or (enable and changed) or (not enable and existed)
            result: dict[str, object] = {
                'ok': bool(ok),
                'ea': int(address),
                'existed': bool(existed),
                'enabled': bool(enabled_now),
                'changed': bool(changed),
            }
            if notes:
                result['note'] = '; '.join(notes)[:300]
            return result

        return _run_in_ida(logic)

    return mcp
