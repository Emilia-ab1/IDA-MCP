"""IDA-MCP 包初始化模块。

职责概述
====================
* 对外导出 `create_mcp_server` 供插件入口 (`ida_mcp.py`) 创建 FastMCP 服务。
* 统一记录子包结构，方便后续扩展时查阅。

子模块说明
--------------------
* `server.py`    : 定义最小版 FastMCP 工具 (list_functions / list_instances / check_connection)。
* `registry.py`  : 多实例协调器的内存实现 (11337 端口 + /register /instances /call 转发)。
* `proxy/`       : 进程型代理所在子目录 ( `proxy/ida_mcp_proxy.py` )，为外部 MCP 客户端提供统一入口。

设计提示
--------------------
1. 仅在 IDA 内部调用 IDA API 的逻辑应放在 `server.py` 并通过 `execute_sync` 切换主线程。
2. 与实例发现/转发相关逻辑集中在 `registry.py`，保持无磁盘状态，方便多开与清理。
3. 代理属于可选组件，可独立运行，不依赖 IDA 进程；其扩展（例如新增工具转发、批量调用）建议置于 `proxy/` 目录。
4. 新增更多工具时优先保持“纯读取”属性，写操作（patch/重命名等）应考虑权限与安全策略再加入。

扩展占位
--------------------
如需新增公共导出 (例如统一的版本号 `__version__`) 可在此增加变量；目前刻意保持最小。"""

from .server import create_mcp_server  # noqa: F401
__version__ = "0.1.0"
