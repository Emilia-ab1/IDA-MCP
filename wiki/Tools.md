# 内置工具说明

详细列出当前版本提供的 MCP 工具（实例侧与代理侧）。

## 实例侧 (server.py)

| 名称 | 描述 | 参数 | 返回 |
|------|------|------|------|
| list_functions | List all functions (name, start_ea, end_ea). | 无 | FunctionItem 列表 |
| instances | Get all registered IDA MCP instances (via coordinator if available). | 无 | 实例信息列表 |
| search_instances | Search registered instances by input file or IDB name (case-insensitive substring). | keyword(str) | 匹配实例列表 |
| check_connection | Check if IDA MCP plugin/coordinator connection is alive (returns ok/count). | 无 | {ok,count} |

## 代理侧 (ida_mcp_proxy.py)

| 名称 | 描述 | 参数 | 返回 |
|------|------|------|------|
| check_connection | Check if any IDA MCP instance is alive (ok/count). | 无 | {ok,count} |
| list_instances | List currently registered IDA MCP instances (coordinator view) | 无 | 实例信息列表 |
| select_instance | Select active backend instance port (auto-pick if omitted). | port(int?) | {selected_port} 或 {error} |
| list_functions | List functions via selected instance (forwarded through coordinator). | 无 | 函数信息列表 |
| search_instances | Search instances by input file or IDB name (case-insensitive substring). | keyword(str) | 匹配实例列表 |

## 返回数据结构示例

FunctionItem:

```json
{
  "name": "sub_401000",
  "start_ea": 4198400,
  "end_ea": 4198464
}
```

实例信息：

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

## 行为与限制

- list_functions 不做分页；大型程序可能返回较大 JSON（可后续加 limit/offset）。
- search_instances 只匹配 basename，不解析路径目录。
- check_connection 纯探活，不抛异常；协调器失联时返回 {ok:false,count:0}。

返回首页: [Home](Home.md)
