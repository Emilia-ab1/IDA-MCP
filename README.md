# IDA-MCP

![logo](ida-mcp.png)

[wiki](https://github.com/jelasin/IDA-MCP/wiki)

[deepwiki](https://deepwiki.com/jelasin/IDA-MCP)

## IDA-MCP (FastMCP + Multi-instance Coordinator)

* Each IDA instance starts a **FastMCP** server (`/mcp`)
* The first instance occupies `127.0.0.1:11337` as the **coordinator**, maintaining a memory registry and supporting tool forwarding
* Subsequent instances automatically register with the coordinator; no need to share files or manually configure ports
* Unified access / aggregation of instance tools via a process-based **proxy `ida_mcp_proxy.py`** (MCP clients can start it via command/args)

## Current Tools

### Plugin Built-in (`server.py`)

#### reverse-tools (server)

* `check_connection` – Quick health check of plugin and coordinator (ok/count)
* `list_instances` – Returns raw list of registered instances
* `list_functions` – Returns all functions in current IDA database (name, start_ea, end_ea)
* `get_function_by_name(name)` – Get start/end address of a single function by exact name match
* `get_function_by_address(address)` – Get function information via address (start or internal)
* `get_current_address()` – Get current cursor address in UI
* `get_current_function()` – Get function at current cursor position (if exists)
* `convert_number(text, size)` – Number conversion (decimal/hex/binary ↔ multiple representations, specified bit width)
* `list_globals_filter(offset, count, filter?)` – Paginated + fuzzy (substring) filtered global symbols list (excluding functions)
* `list_globals(offset, count)` – Paginated list of all global symbols (excluding functions)
* `list_strings_filter(offset, count, filter?)` – Paginated + fuzzy filtered strings list
* `list_strings(offset, count)` – Paginated list of all strings
* `list_local_types()` – List all Local Types (ordinal + truncated decl)
* `decompile_function(address)` – Decompile function (requires Hex-Rays)
* `disassemble_function(start_address)` – Output function disassembly (instructions/comments)
* `get_xrefs_to(address)` – Get cross-references to an address
* `get_xrefs_to_field(struct_name, field_name)` – Heuristically get instruction locations referencing struct fields
* `set_comment(address, comment)` – Set/clear address comment (syncs to pseudocode)
* `rename_local_variable(function_address, old_name, new_name)` – Rename function local variable (Hex-Rays)
* `rename_global_variable(old_name, new_name)` – Rename global variable
* `set_global_variable_type(variable_name, new_type)` – Set global variable type
* `rename_function(function_address, new_name)` – Rename function
* `set_function_prototype(function_address, prototype)` – Set function prototype
* `set_local_variable_type(function_address, variable_name, new_type)` – Set local variable type (Hex-Rays)
* `declare_c_type(c_declaration)` – Parse and declare/update a local type (struct/union/enum/typedef)
* `get_entry_points()` – Get all entry points (ordinal + address + name)
* `get_metadata` - Get basic metadata of specified or current instance (hash/arch/bits etc.)
* `linear_disassemble(start_address, size)` - Linear disassembly of size instructions from specified address

#### dbg-tools (server)

* `dbg_get_registers()` – Get current values of all registers
* `dbg_get_call_stack()` – Get current call stack
* `dbg_list_breakpoints()` – List all breakpoints
* `dbg_start_process()` – Start debugging (if not already started)
* `dbg_exit_process()` – Terminate debug process
* `dbg_continue_process()` – Continue execution (Resume)
* `dbg_run_to(address)` – Run to specified address
* `dbg_set_breakpoint(address)` – Set breakpoint
* `dbg_delete_breakpoint(address)` – Delete breakpoint (idempotent)
* `dbg_enable_breakpoint(address, enable)` – Enable/disable breakpoint (creates if doesn't exist and enabling)

### Proxy (`ida_mcp_proxy.py`)

* `select_instance(port?)` - Select IDA instance to use

#### reverse-tools (proxy)

* `check_connection` - Check if active instances exist
* `list_instances` - Return raw instance list
* `list_functions` - For selected or auto-selected instance; forwarded via coordinator
* `get_function_by_name(name, port?)` - Forward function query by name
* `get_function_by_address(address, port?)` - Forward function query by address
* `get_current_address(port?)` - Forward get current UI cursor address
* `get_current_function(port?)` - Forward get function at current cursor (if exists)
* `convert_number(text, size, port?)` - Forward number conversion
* `list_globals_filter(offset, count, filter?, port?)` - Forward paginated global symbols query
* `list_globals(offset, count, port?)` - Forward paginated global symbols query (no filter)
* `list_strings_filter(offset, count, filter?, port?)` - Forward paginated strings query
* `list_strings(offset, count, port?)` - Forward paginated strings query (no filter)
* `list_local_types(port?)` - Forward list Local Types
* `decompile_function(address, port?)` - Forward decompile function (requires Hex-Rays)
* `disassemble_function(start_address, port?)` - Forward function disassembly
* `get_metadata(port?)` - Get basic metadata of specified or current instance (hash/arch/bits etc.)
* `get_xrefs_to(address, port?)` - Forward get cross-references to address
* `get_xrefs_to_field(struct_name, field_name, port?)` - Forward heuristic field reference search
* `set_comment(address, comment, port?)` - Forward set address comment
* `rename_local_variable(function_address, old_name, new_name, port?)` - Forward rename local variable
* `rename_global_variable(old_name, new_name, port?)` - Forward rename global variable
* `set_global_variable_type(variable_name, new_type, port?)` - Forward set global variable type
* `rename_function(function_address, new_name, port?)` - Forward rename function
* `set_function_prototype(function_address, prototype, port?)` - Forward set function prototype
* `set_local_variable_type(function_address, variable_name, new_type, port?)` - Forward set local variable type
* `declare_c_type(c_declaration, port?)` - Forward declare/update local type
* `get_entry_points(port?)` - Forward get entry points list
* `linear_disassemble(start_address, size, port?)` - Forward linear disassembly

#### dbg-tools (proxy)

* `dbg_get_registers(port?)` - Forward get current register values
* `dbg_get_call_stack(port?)` - Forward get current call stack
* `dbg_list_breakpoints(port?)` - Forward list all breakpoints
* `dbg_start_process(port?)` - Forward start debugging
* `dbg_exit_process(port?)` - Forward terminate debug process
* `dbg_continue_process(port?)` - Forward continue execution
* `dbg_run_to(address, port?)` - Forward run to specified address
* `dbg_set_breakpoint(address, port?)` - Forward set breakpoint
* `dbg_delete_breakpoint(address, port?)` - Forward delete breakpoint
* `dbg_enable_breakpoint(address, enable, port?)` - Forward enable/disable breakpoint

## Directory Structure

```text
IDA-MCP/
  ida_mcp.py              # Plugin entry: start/stop SSE server + register coordinator
  ida_mcp/
    server.py             # FastMCP server definition
    registry.py           # Coordinator implementation / multi-instance registration & /call forwarding
    __init__.py           # Package initialization, exports create_mcp_server and explains submodule structure
    proxy/
      ida_mcp_proxy.py    # Process proxy (attaches MCP server, forwards /call via coordinator)
  mcp.json                # MCP client configuration (includes proxy / sse)
  README.md
  requirements.txt        # fastmcp dependencies (if needed for external environment)
```

## Startup Steps

1. Copy `ida_mcp.py` + `ida_mcp` folder to IDA's `plugins/`.
2. Open target binary, wait for analysis to complete.
3. Trigger plugin via menu / shortcut: First launch will:
   * Select free port (starting from 8765) to run SSE service `http://127.0.0.1:<port>/mcp/`
   * If 11337 is free → start coordinator; otherwise register with existing coordinator
4. Trigger plugin again = stop and unregister instance.

## Proxy Usage

Replace `command` and `args` in `mcp.json`, then copy it to claude client's mcp tool configuration file or other MCP client configuration files.

**claude / cherry studio / cursor client example:**

```json
{
  "mcpServers": {
    "ida-mcp-proxy": {
      "command": "path of python（IDA's python）",
      "args": ["path of ida_mcp_proxy.py"],
      "env": {},
      "description": "Process MCP proxy that forwards to running IDA SSE server."
    }
  }
}
```

For claude, directly add the above configuration to the `claude_desktop_config.json` file in the installation directory.

cherry studio supports quick creation of mcp tools, import directly from json, then paste the above configuration example.

For cursor, simply import via model tools.

**vscode mcp configuration example:**

```json
{
  "servers": {
    "ida-mcp-proxy": {
      "command": "path of python（IDA's python）",
      "args": ["path of ida_mcp_proxy.py"]
    }
  }
}
```

1. Permanent addition:
Set copilot to Agent mode, click Configure Tools -> Configure Toolset -> Enter toolset name -> Enter toolset filename -> OK -> Then directly paste the above configuration example.

2. Temporary addition:
Create `.vscode` folder in project directory, create `mcp.json` file inside it, paste the above configuration file.

3. copilot also scans claude client configuration files and cursor configuration files.

## Dependencies

Need to install using IDA's Python environment:

```bash
python -m pip install -r requirements.txt
```

## Future Plans

Add UI interface, support internal model calls, add multi-agent A2A automated reverse engineering functionality after langchain officially updates to 1.0.0.
