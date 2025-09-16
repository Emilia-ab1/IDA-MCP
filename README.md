# IDA-MCP

[readme-en](README-EN.md)

[wiki](https://github.com/jelasin/IDA-MCP/wiki)

[deepwiki](https://deepwiki.com/jelasin/IDA-MCP)

## IDA-MCP (FastMCP + 多实例协调器)

* 每个 IDA 实例启动一个 **FastMCP** 服务器 (`/mcp`)
* 第一个实例占用 `127.0.0.1:11337` 作为 **协调器(coordinator)**，维持内存注册表并支持工具转发
* 后续实例自动注册到协调器；无需共享文件或手工配置端口
* 通过一个进程型 **代理 `ida_mcp_proxy.py`**（MCP 客户端可用 command/args 启动）统一访问 / 聚合各实例工具

## 当前工具

### 插件内置 (`server.py`)

#### reverse-tools (server)

* `check_connection` – 快速检测插件与协调器健康 (ok/count)
* `list_instances` – 返回已注册实例原始列表
* `list_functions` – 返回当前 IDA 数据库中全部函数 (name, start_ea, end_ea)
* `get_function_by_name(name)` – 精确按名称获取单个函数的起止地址
* `get_function_by_address(address)` – 通过地址(起始或内部)获取函数信息
* `get_current_address()` – 获取当前界面光标地址
* `get_current_function()` – 获取当前光标所在函数 (若存在)
* `convert_number(text, size)` – 数字转换 (十进制/十六进制/二进制 ↔ 多种表示, 指定位宽)
* `list_globals_filter(offset, count, filter?)` – 分页 + 模糊(子串)过滤的全局符号列表 (排除函数)
* `list_globals(offset, count)` – 分页列出所有全局符号 (排除函数)
* `list_strings_filter(offset, count, filter?)` – 分页 + 模糊过滤字符串列表
* `list_strings(offset, count)` – 分页列出所有字符串
* `list_local_types()` – 列出所有 Local Types (ordinal + decl 截断)
* `decompile_function(address)` – 反编译函数 (需要 Hex-Rays)
* `disassemble_function(start_address)` – 输出函数反汇编 (指令/注释)
* `get_xrefs_to(address)` – 获取指向某地址的交叉引用
* `get_xrefs_to_field(struct_name, field_name)` – 启发式获取引用结构体字段的指令位置
* `set_comment(address, comment)` – 设置/清除地址注释 (同步到伪代码)
* `rename_local_variable(function_address, old_name, new_name)` – 重命名函数本地变量 (Hex-Rays)
* `rename_global_variable(old_name, new_name)` – 重命名全局变量
* `set_global_variable_type(variable_name, new_type)` – 设置全局变量类型
* `rename_function(function_address, new_name)` – 重命名函数
* `set_function_prototype(function_address, prototype)` – 设置函数原型
* `set_local_variable_type(function_address, variable_name, new_type)` – 设置局部变量类型 (Hex-Rays)
* `declare_c_type(c_declaration)` – 解析并声明/更新一个本地类型 (struct/union/enum/typedef)
* `get_entry_points()` – 获取所有入口点 (ordinal + 地址 + 名称)
* `get_metadata` - 获取指定或当前实例基础元数据（hash/arch/bits 等）

#### dbg-tools (server)

* `dbg_get_registers()` – 获取所有寄存器当前值
* `dbg_get_call_stack()` – 获取当前调用栈
* `dbg_list_breakpoints()` – 列出所有断点
* `dbg_start_process()` – 启动调试 (若尚未启动)
* `dbg_exit_process()` – 结束调试进程
* `dbg_continue_process()` – 继续运行 (Resume)
* `dbg_run_to(address)` – 运行到指定地址
* `dbg_set_breakpoint(address)` – 设置断点
* `dbg_delete_breakpoint(address)` – 删除断点 (幂等)
* `dbg_enable_breakpoint(address, enable)` – 启用/禁用断点 (不存在且启用则创建)

### 代理 (`ida_mcp_proxy.py`)

* `select_instance(port?)` - 选择要使用的 IDA 实例

#### reverse-tools (proxy)

* `check_connection` - 检测是否存在活跃实例
* `list_instances` - 返回原始实例列表
* `list_functions` - 针对选中或自动选中实例；经协调器转发
* `get_function_by_name(name, port?)` - 转发按名称查询函数
* `get_function_by_address(address, port?)` - 转发按地址查询函数
* `get_current_address(port?)` - 转发获取当前界面光标地址
* `get_current_function(port?)` - 转发获取当前光标所在函数 (若存在)
* `convert_number(text, size, port?)` - 转发数字转换
* `list_globals_filter(offset, count, filter?, port?)` - 转发分页全局符号查询
* `list_globals(offset, count, port?)` - 转发分页全局符号查询 (不含过滤)
* `list_strings_filter(offset, count, filter?, port?)` - 转发分页字符串查询
* `list_strings(offset, count, port?)` - 转发分页字符串查询 (不含过滤)
* `list_local_types(port?)` - 转发列出 Local Types
* `decompile_function(address, port?)` - 转发反编译函数 (需要 Hex-Rays)
* `disassemble_function(start_address, port?)` - 转发函数反汇编
* `get_metadata(port?)` - 获取指定或当前实例基础元数据（hash/arch/bits 等）
* `get_xrefs_to(address, port?)` - 转发获取指向某地址的交叉引用
* `get_xrefs_to_field(struct_name, field_name, port?)` - 转发启发式字段引用搜索
* `set_comment(address, comment, port?)` - 转发设置地址注释
* `rename_local_variable(function_address, old_name, new_name, port?)` - 转发重命名本地变量
* `rename_global_variable(old_name, new_name, port?)` - 转发重命名全局变量
* `set_global_variable_type(variable_name, new_type, port?)` - 转发设置全局变量类型
* `rename_function(function_address, new_name, port?)` - 转发重命名函数
* `set_function_prototype(function_address, prototype, port?)` - 转发设置函数原型
* `set_local_variable_type(function_address, variable_name, new_type, port?)` - 转发设置局部变量类型
* `declare_c_type(c_declaration, port?)` - 转发声明/更新本地类型
* `get_entry_points(port?)` - 转发获取入口点列表

#### dbg-tools (proxy)

* `dbg_get_registers(port?)` - 转发获取寄存器当前值
* `dbg_get_call_stack(port?)` - 转发获取当前调用栈
* `dbg_list_breakpoints(port?)` - 转发列出所有断点
* `dbg_start_process(port?)` - 转发启动调试
* `dbg_exit_process(port?)` - 转发结束调试进程
* `dbg_continue_process(port?)` - 转发继续运行
* `dbg_run_to(address, port?)` - 转发运行到指定地址
* `dbg_set_breakpoint(address, port?)` - 转发设置断点
* `dbg_delete_breakpoint(address, port?)` - 转发删除断点
* `dbg_enable_breakpoint(address, enable, port?)` - 转发启用/禁用断点

## 目录结构

```text
IDA-MCP/
  ida_mcp.py              # 插件入口：启动/停止 SSE server + 注册协调器
  ida_mcp/
    server.py             # FastMCP server 定义
    registry.py           # 协调器实现 / 多实例注册 & /call 转发
    __init__.py           # 包初始化, 导出 create_mcp_server 并说明子模块结构
    proxy/
      ida_mcp_proxy.py    # 进程型代理（附加 MCP server, 通过协调器 /call 转发）
  mcp.json                # MCP 客户端配置 (含 proxy / sse)
  README.md
  requirements.txt        # fastmcp 依赖（若外部环境需要）
```

## 启动步骤

1. 复制 `ida_mcp.py` + `ida_mcp` 文件夹到 IDA 的 `plugins/` 。
2. 打开目标二进制，等待分析完成。
3. 菜单 / 快捷方式触发插件：首次启动会：
   * 选择空闲端口（从 8765 起）运行 SSE 服务 `http://127.0.0.1:<port>/mcp/`
   * 若 11337 空闲 → 启动协调器；否则向现有协调器注册
4. 再次触发插件 = 停止并注销实例。

## 代理使用

在 `mcp.json` 中替换 `command` 和 `args`，然后将其复制到 claude 客户端的 mcp 工具配置文件或者其他 MCP 客户端的配置文件中。

**claude / cherry studio / cursor 客户端示例：**

```json
{
  "mcpServers": {
    "ida-mcp-proxy": {
      "command": "path of python",
      "args": ["path of ida_mcp_proxy.py"],
      "env": {},
      "description": "Process MCP proxy that forwards to running IDA SSE server."
    }
  }
}
```

claude 直接在安装目录里面的 `claude_desktop_config.json` 文件中添加上述配置。

cherry studio 支持快速创建 mcp 工具，直接从 json 导入，然后粘贴上述配置示例。

cursor 直接在模型工具导入即可（不推荐使用cursor）。

**vscode mcp 配置示例：**

```json
{
  "servers": {
    "ida-mcp-proxy": {
      "command": "path of python",
      "args": ["path of ida_mcp_proxy.py"]
    }
  }
}
```

1. 永久添加：
将 copilot 设置为 Agent 模式，点击配置工具 -> 配置工具集 -> 输入工具集名称 -> 输入工具集文件名 -> 确定 -> 然后将上述配置示例直接粘贴进去即可。

2. 临时添加：
项目目录建立 `.vscode` 文件夹，并在其中创建 `mcp.json` 文件，将上述配置文件粘贴进去。

3. copilot 也会扫描 claude 客户端的配置文件和 cursor 的配置文件。

## 依赖

```bash
python -m pip install -r requirements.txt
```
