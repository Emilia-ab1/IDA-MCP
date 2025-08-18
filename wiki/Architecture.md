# 体系结构概览

本页面详细说明 IDA-MCP 的整体结构、组件边界与交互流程。

## 组件概述

| 组件 | 角色 | 主要职责 | 进程/线程 | 关键端口 |
|------|------|----------|-----------|----------|
| 插件实例 (ida_mcp.py + server.py) | 每个打开的 IDA | 暴露 FastMCP 工具（list_functions 等），注册到协调器 | IDA 进程内守护线程运行 uvicorn | 动态 (8765 起向上) |
| 协调器 (registry.py) | 第一个实例内存启动 | 维护实例列表，提供 /instances /register /deregister /call | IDA 进程内守护线程 | 固定 11337 |
| 代理 (ida_mcp_proxy.py) | 可选外部接入点 | 对外单一 MCP 服务，内部经协调器 /call 转发 | 独立 Python 进程 | (FastMCP 选择) |

## 启动流程

1. 用户在某 IDA 实例中点击插件：
   - 选择空闲端口 (默认 8765 起扫描)
   - 启动 uvicorn + FastMCP SSE (`/mcp`)
   - 调用 `init_and_register` -> 若 11337 空闲成为协调器，否则仅注册
2. 后续 IDA 实例重复上述动作，直接向已有协调器注册。
3. 可选启动代理进程，为外部 MCP 客户端提供统一入口。

## 多实例注册与转发

```text
客户端(代理/直接) --> 协调器(11337) --> 目标实例 /mcp -> 执行工具 -> 返回数据
```

- /register: {pid, port, input_file, idb, started, python}
- /instances: 返回当前内存中的所有条目
- /call: {pid|port, tool, params} -> fastmcp.Client -> 结果 JSON 化

## 数据结构

示例实例条目：

```json
{
  "pid": 1234,
  "port": 8765,
  "input_file": "C:/bin/a.exe",
  "idb": "C:/bin/a.i64",
  "started": 1730000000.12,
  "python": "3.11.9"
}
```

## 线程模型

- 每个实例：1 个 uvicorn 守护线程
- 协调器：HTTPServer 守护线程
- 代理：独立进程 (FastMCP server)
- IDA API 调用：通过 `execute_sync` 进入主线程，保证线程安全

## 设计取舍

| 关注点 | 取舍 | 说明 |
|--------|------|------|
| 持久化 | 放弃 | 内存注册，减少文件竞争与清理负担 |
| 安全 | 本地信任 | 仅监听 127.0.0.1，不做认证（可后续扩展） |
| 一致性 | 客户端无感 | 统一用 /call 转发，客户端无需逐实例管理 |
| 扩展性 | 最小核 -> 叠加 | 新工具只需在 server.py 注册即可被转发 |
| 可靠性 | 简单优先 | 暂无心跳；依赖退出时注销（可加 TTL 清理） |

## 典型调用序列 (代理模式)

```text
Client -> (MCP) ida_mcp_proxy.list_functions
  -> proxy _call('list_functions')
    -> POST http://127.0.0.1:11337/call {port, tool, params}
      -> 协调器内部 fastmcp.Client 调用 http://127.0.0.1:<实例>/mcp tools/call
        -> 实例执行 list_functions (IDA 主线程)
      <- 函数列表 JSON
    <- 转发结果
<- 返回给客户端
```

## 搜索与筛选

`search_instances(keyword)` 在内存实例列表上按 basename 做不区分大小写子串匹配。

## 扩展挂点

- 新工具: `server.py` 中 `@mcp.tool`
- 更复杂聚合: 代理新增工具转发多个实例结果
- 健康检查: registry 添加心跳字段 + 定期清理
- 安全: /call 参数过滤 + token 验证

---

返回首页: [Home](Home.md)
