# 使用指南

本页说明如何部署、启动与调用 IDA-MCP 多实例插件与代理。

## 前置要求

- 已安装 IDA Pro（支持 IDAPython）。
- Python 环境具备 fastmcp (requirements.txt 已列出)。

## 安装步骤

1. 将整个 `IDA-MCP/` 目录复制到 IDA 的 `plugins/` 目录。
2. 启动 IDA，打开一个二进制文件，等待自动分析结束。
3. 在菜单 `Edit -> Plugins` 中点击 `IDA-MCP` 以启动（再次点击可停止）。

## 启动多个实例

- 打开第二个 IDA，重复点击插件；端口会自动避开冲突（8765 起向上）。
- 第一实例自动成为协调器（占用 11337）。

## 查看实例列表

通过任一已启动实例调用 MCP 工具 `instances` 或通过代理调用 `list_instances`。

## 代理模式

若外部客户端不便管理多个端口，可使用 `ida_mcp_proxy.py`：

1. 启动至少一个实例（已注册协调器）。
2. 启动代理（由 MCP 客户端基于 mcp.json command/args 自动运行）。
3. 使用工具：`check_connection`, `list_instances`, `select_instance`, `list_functions`, `search_instances`。

## JSON-RPC 调用

直接对某个实例端点（示例端口 8765）：

```bash
curl -X POST http://127.0.0.1:8765/mcp/ \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":"1","method":"tools/call","params":{"name":"list_functions","arguments":{}}}'
```

通过协调器转发（无需知道实例端口，指定 port 参数）：

```bash
curl -X POST http://127.0.0.1:11337/call \
  -H "Content-Type: application/json" \
  -d '{"tool":"list_functions","params":{"port":8765}}'
```

## Python 客户端示例

```python
import asyncio
from fastmcp import Client

async def main():
    async with Client("http://127.0.0.1:8765/mcp/") as c:
        r = await c.call_tool("list_functions", {})
        print("Total functions:", len(r.data))
        for i in r.data[:5]:
            print(i)

asyncio.run(main())
```

## 搜索实例

```bash
curl -X POST http://127.0.0.1:11337/call \
  -H "Content-Type: application/json" \
  -d '{"tool":"search_instances","params":{"keyword":"openssl"}}'
```

## 停止

- 再次点击插件（每实例独立）。
- 关闭 IDA 时若插件运行会自动尝试注销。

返回首页: [Home](Home.md)
