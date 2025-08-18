# 开发与调试

本页面向二次开发者，说明如何本地快速迭代、调试与验证改动。

## 快速迭代流程

1. 修改 `ida_mcp/server.py` 或 `registry.py` / `ida_mcp_proxy.py`。
2. 在 IDA 中停止插件（再次点击）并重新启动以加载新代码。
3. 使用脚本或 `curl`/MCP 客户端调用验证。

## 分离运行（可选）

- 可在非 IDA 环境下运行 `python ida_mcp.py` 启动最小 SSE（list_functions 会返回空或报缺失）。
- 代理可独立运行：`python ida_mcp_proxy.py`。

## 日志与调试

- 调整 `ida_mcp.py` 中 uvicorn `log_level="info"` 查看请求过程。
- 在 `registry.py` 的 /call 分支中临时打印 payload 追踪转发。
- 使用 `curl http://127.0.0.1:11337/instances` 直接查看原始 JSON。

## 常见调试脚本模板

```python
import asyncio
from fastmcp import Client

async def test(tool, args):
    async with Client("http://127.0.0.1:8765/mcp/") as c:
        r = await c.call_tool(tool, args)
        print(r.data)

asyncio.run(test("list_functions", {}))
```

## 结构调整注意点

| 改动 | 注意 |
|------|------|
| 新增工具 | 确保工具描述(description)用英文；返回内容可被 JSON 序列化 |
| 注册表字段 | 修改后记得调整 README / wiki 文档示例 |
| 转发逻辑 | 保留异常捕获，避免代理端崩溃 |
| 端口策略 | 避免硬编码除 11337 协调器外的特定端口 |

## 回归检查清单

- 单实例启动/停止是否正常清理。
- 多实例是否都能出现在 `instances` 列表。
- 代理是否能调用 `list_functions`。
- search_instances 关键字过滤是否大小写无关。
- check_connection 返回是否符合预期结构。

返回首页: [Home](Home.md)
