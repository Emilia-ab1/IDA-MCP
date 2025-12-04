"""类型转发工具 - 类型声明、应用。"""
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
    """注册类型工具到服务器。"""
    
    @server.tool(description="Set function prototype/signature.")
    def set_func_type(
        address: Annotated[str, Field(description="Function address")],
        prototype: Annotated[str, Field(description="C-style function prototype")],
        port: Annotated[Optional[int], Field(description="Instance port override")] = None,
    ) -> Any:
        """设置函数原型。"""
        return forward("set_function_prototype", {
            "function_address": address,
            "prototype": prototype
        }, port)
    
    @server.tool(description="Set type of a local variable.")
    def set_local_type(
        function_address: Annotated[str, Field(description="Function containing the variable")],
        variable_name: Annotated[str, Field(description="Variable name")],
        new_type: Annotated[str, Field(description="C-style type declaration")],
        port: Annotated[Optional[int], Field(description="Instance port override")] = None,
    ) -> Any:
        """设置局部变量类型。"""
        return forward("set_local_variable_type", {
            "function_address": function_address,
            "variable_name": variable_name,
            "new_type": new_type
        }, port)
    
    @server.tool(description="Set type of a global variable.")
    def set_global_type(
        variable_name: Annotated[str, Field(description="Global variable name")],
        new_type: Annotated[str, Field(description="C-style type declaration")],
        port: Annotated[Optional[int], Field(description="Instance port override")] = None,
    ) -> Any:
        """设置全局变量类型。"""
        return forward("set_global_variable_type", {
            "variable_name": variable_name,
            "new_type": new_type
        }, port)
    
    @server.tool(description="Declare a new C type (struct, enum, typedef).")
    def declare_type(
        decl: Annotated[str, Field(description="C-style type declaration")],
        port: Annotated[Optional[int], Field(description="Instance port override")] = None,
    ) -> Any:
        """声明新类型。"""
        return forward("declare_type", {"decl": decl}, port)

