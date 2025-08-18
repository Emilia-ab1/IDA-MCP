# 扩展与定制

本页指导如何在现有最小核心上添加更多工具、增强安全、接入聚合逻辑或实现高级功能。

## 添加新工具

1. 打开 `ida_mcp/server.py`。
2. 在 `create_mcp_server()` 内新增：

```python
@mcp.tool(description="Your English description here.")
def new_tool(param1: int, flag: bool = False) -> dict:
    # 所有 IDA API 访问封装到 _run_in_ida 内部
    def logic():
        # 访问 idaapi / idautils / ida_funcs 等
        return {"ok": True, "p": param1, "flag": flag}
    return _run_in_ida(logic)
```

1. 外部客户端通过 `call_tool("new_tool", {"param1": 1, "flag": True})` 调用。

## 线程安全

- 所有访问 IDA 数据的逻辑应通过 `_run_in_ida()` 以 `execute_sync` 调度到 IDA 主线程执行，避免崩溃或数据竞争。
- 长耗时工具建议拆分或加入超时策略（目前未实现取消）。

## 聚合/跨实例操作

- 代理模式下可在 `ida_mcp_proxy.py` 增加遍历所有端口的逻辑（当前移除了 list_all_functions，可恢复）。
- 或在协调器中扩展 /call 支持 `targets=[...]` 批量调用（需并发聚合，这里未实现）。

## 安全增强选项

| 目标 | 思路 |
|------|------|
| 防止外部进程访问 | 保持 127.0.0.1 绑定（已做） |
| 简易认证 | 在 /call 请求头加入固定 token，协调器校验 |
| 工具白名单 | 在 registry 转发前检查工具名是否允许 |
| 只读模式 | 屏蔽写操作相关工具（后续添加 patch/注入类能力时） |

## 心跳与过期清理

- 当前设计依赖正常退出调用 `deregister`。
- 可扩展：实例周期性 POST /register 刷新 `last_seen` 字段；协调器定期剔除超过阈值未刷新条目。

## 性能注意事项

| 场景 | 风险 | 建议 |
|------|------|------|
| 超大函数数量 | list_functions JSON 过大 | 引入分页参数 limit/offset |
| 高频 /call | 注册表锁竞争 | 读多写少，可改为 RWLock 或无锁快照 |
| 反编译/复杂分析 | 阻塞主线程 | 考虑拆分异步任务 + 进度事件流 |

## 调试技巧

- 在 `ida_mcp.py` 中将 uvicorn log_level 调为 `info` 观察请求。
- 在 `registry.py` 手动打印转发参数定位问题。
- 使用 `curl` 直接调试 `/call` 观察原始返回结构。

## 版本兼容

- fastmcp 升级可能改变 JSON-RPC 响应结构；在代理层做最小依赖（只取 `data`）。
- IDA 版本差异：某些 API 可能在低版本不可用，需 try/except 包裹。

## 未来可考虑的高级特性

- 反编译缓存 / 预取
- 交叉引用图谱导出 (graph JSON)
- 按模式搜索 (字符串 / 字节 / 指令序列)
- Patch 编辑与回滚
- 结构体/类型信息访问、重命名广播

返回首页: [Home](Home.md)
