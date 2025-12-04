"""内存转发工具 - 内存读取。"""
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
    """注册内存工具到服务器。"""
    
    @server.tool(description="Read memory bytes. Returns hex dump and byte array.")
    def read_bytes(
        address: Annotated[str, Field(description="Memory address")],
        size: Annotated[int, Field(description="Bytes to read (1-4096)")] = 64,
        port: Annotated[Optional[int], Field(description="Instance port override")] = None,
    ) -> Any:
        """读取内存字节。"""
        return forward("get_bytes", {"addr": address, "size": size}, port)
    
    @server.tool(description="Read 32-bit unsigned integer from address.")
    def read_u32(
        address: Annotated[str, Field(description="Memory address")],
        port: Annotated[Optional[int], Field(description="Instance port override")] = None,
    ) -> Any:
        """读取 32 位无符号整数。"""
        return forward("get_u32", {"addr": address}, port)
    
    @server.tool(description="Read 64-bit unsigned integer from address.")
    def read_u64(
        address: Annotated[str, Field(description="Memory address")],
        port: Annotated[Optional[int], Field(description="Instance port override")] = None,
    ) -> Any:
        """读取 64 位无符号整数。"""
        return forward("get_u64", {"addr": address}, port)
    
    @server.tool(description="Read null-terminated string from address.")
    def read_string(
        address: Annotated[str, Field(description="Memory address")],
        max_len: Annotated[int, Field(description="Maximum length")] = 256,
        port: Annotated[Optional[int], Field(description="Instance port override")] = None,
    ) -> Any:
        """读取字符串。"""
        return forward("get_string", {"addr": address, "max_len": max_len}, port)
    
    @server.tool(description="Batch read memory regions.")
    def read_memory(
        address: Annotated[str, Field(description="Memory address")],
        size: Annotated[int, Field(description="Bytes to read")] = 64,
        port: Annotated[Optional[int], Field(description="Instance port override")] = None,
    ) -> Any:
        """批量读取内存。"""
        return forward("read_memory_bytes", {
            "regions": [{"address": address, "size": size}]
        }, port)

