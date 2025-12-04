"""修改 API - 注释、重命名等。

提供工具:
    - set_comment          设置注释 (批量)
    - rename_function      重命名函数
    - rename_local_variable 重命名局部变量
    - rename_global_variable 重命名全局变量
"""
from __future__ import annotations

import re
from typing import Annotated, Optional, List, Dict, Any, Union

from .rpc import tool
from .sync import idaread, idawrite
from .utils import parse_address, is_valid_c_identifier, normalize_list_input, hex_addr

# IDA 模块导入
import idaapi  # type: ignore
import ida_funcs  # type: ignore
import ida_hexrays  # type: ignore

@tool
@idawrite
def set_comment(
    items: Annotated[List[Dict[str, Any]], "List of {address, comment} objects"],
) -> List[dict]:
    """Set comments at address(es). Each item: {address, comment}."""
    results = []
    for item in items:
        address = item.get("address")
        comment = item.get("comment", "")
        
        if address is None:
            results.append({"error": "invalid address", "address": address})
            continue
        
        parsed = parse_address(address)
        if not parsed["ok"] or parsed["value"] is None:
            results.append({"error": "invalid address", "address": address})
            continue
        
        addr_int = parsed["value"]
        
        try:
            old = idaapi.get_cmt(addr_int, False)
        except Exception:
            old = None
        
        new_text = str(comment).strip() if comment else ""
        if len(new_text) > 1024:
            new_text = new_text[:1024]
        
        try:
            ok = idaapi.set_cmt(addr_int, new_text or '', False)
        except Exception as e:
            results.append({"error": f"set failed: {e}", "address": hex_addr(addr_int)})
            continue
        
        results.append({
            "address": hex_addr(addr_int),
            "old": old,
            "new": new_text if new_text else None,
            "changed": old != (new_text if new_text else None) and ok,
            "error": None,
        })
    
    return results




# ============================================================================
# 重命名
# ============================================================================

@tool
@idawrite
def rename_function(
    function_address: Annotated[Union[int, str], "Function name or address (hex/decimal)"],
    new_name: Annotated[str, "New function name (valid C identifier)"],
) -> dict:
    """Rename function. Accepts function name or address."""
    if function_address is None:
        return {"error": "invalid function_address"}
    if not new_name:
        return {"error": "empty new_name"}
    
    new_name_clean = new_name.strip()
    if len(new_name_clean) > 255:
        new_name_clean = new_name_clean[:255]
    
    if not is_valid_c_identifier(new_name_clean):
        return {"error": "new_name not a valid C identifier"}
    
    f = None
    addr = None
    
    # 方法 1: 尝试作为函数名查找
    if isinstance(function_address, str):
        try:
            ea = idaapi.get_name_ea(idaapi.BADADDR, function_address)
            if ea != idaapi.BADADDR:
                f = ida_funcs.get_func(ea)
                if f:
                    addr = ea
        except Exception:
            pass
    
    # 方法 2: 尝试作为地址解析
    if not f:
        parsed = parse_address(str(function_address))
        if parsed["ok"] and parsed["value"] is not None:
            addr = parsed["value"]
            try:
                f = ida_funcs.get_func(addr)
            except Exception:
                pass
    
    if not f:
        return {
            "error": "function not found",
            "query": str(function_address),
            "parsed_addr": hex_addr(addr) if addr is not None else None,
        }
    
    start_ea = int(f.start_ea)
    
    try:
        old_name = idaapi.get_func_name(f.start_ea)
    except Exception:
        old_name = None
    
    try:
        ok = idaapi.set_name(start_ea, new_name_clean, idaapi.SN_NOWARN)
    except Exception as e:
        return {"error": f"set_name failed: {e}"}
    
    return {
        "start_ea": hex_addr(start_ea),
        "old_name": old_name,
        "new_name": new_name_clean,
        "changed": bool(ok) and old_name != new_name_clean,
    }


@tool
@idawrite
def rename_local_variable(
    function_address: Annotated[Union[int, str], "Function start or internal address (hex or decimal)"],
    old_name: Annotated[str, "Old local variable name (exact match)"],
    new_name: Annotated[str, "New variable name (valid C identifier)"],
) -> dict:
    """Rename local variable (Hex-Rays)."""
    if function_address is None:
        return {"error": "invalid function_address"}
    if not old_name:
        return {"error": "empty old_name"}
    if not new_name:
        return {"error": "empty new_name"}
    
    parsed = parse_address(str(function_address))
    if not parsed["ok"] or parsed["value"] is None:
        return {"error": "invalid function_address"}
    
    addr = parsed["value"]
    
    new_name_clean = new_name.strip()
    if len(new_name_clean) > 255:
        new_name_clean = new_name_clean[:255]
    
    if not is_valid_c_identifier(new_name_clean):
        return {"error": "new_name not a valid C identifier"}
    
    # 初始化 Hex-Rays
    try:
        if not ida_hexrays.init_hexrays_plugin():
            return {"error": "failed to init hex-rays"}
    except Exception:
        return {"error": "failed to init hex-rays"}
    
    try:
        f = ida_funcs.get_func(addr)
    except Exception:
        f = None
    if not f:
        return {"error": "function not found"}
    
    try:
        cfunc = ida_hexrays.decompile(f.start_ea)
    except Exception as e:
        return {"error": f"decompile failed: {e}"}
    if not cfunc:
        return {"error": "decompile returned None"}
    
    # 查找变量
    target = None
    try:
        for lv in cfunc.lvars:  # type: ignore
            try:
                if lv.name == old_name:
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
        fname = idaapi.get_func_name(f.start_ea)
    except Exception:
        fname = "?"
    
    return {
        "function": fname,
        "start_ea": hex_addr(f.start_ea),
        "old_name": old_name,
        "new_name": new_name_clean,
        "changed": bool(ok),
    }


@tool
@idawrite
def rename_global_variable(
    old_name: Annotated[str, "Existing global symbol name (exact match)"],
    new_name: Annotated[str, "New name (valid C identifier)"],
) -> dict:
    """Rename global variable."""
    if not old_name:
        return {"error": "empty old_name"}
    if not new_name:
        return {"error": "empty new_name"}
    
    new_name_clean = new_name.strip()
    if len(new_name_clean) > 255:
        new_name_clean = new_name_clean[:255]
    
    if not is_valid_c_identifier(new_name_clean):
        return {"error": "new_name not a valid C identifier"}
    
    try:
        ea = idaapi.get_name_ea(idaapi.BADADDR, old_name)
    except Exception:
        ea = idaapi.BADADDR
    
    if ea == idaapi.BADADDR:
        return {"error": "global not found"}
    
    # 若是函数起始地址则拒绝
    try:
        f = ida_funcs.get_func(ea)
        if f and int(f.start_ea) == int(ea):
            return {"error": "target is a function start (use function rename)"}
    except Exception:
        pass
    
    try:
        ok = idaapi.set_name(ea, new_name_clean, idaapi.SN_NOWARN)
    except Exception as e:
        return {"error": f"set_name failed: {e}"}
    
    return {
        "ea": hex_addr(ea),
        "old_name": old_name,
        "new_name": new_name_clean,
        "changed": bool(ok),
    }


