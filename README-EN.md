# IDA-MCP (FastMCP SSE + Multi-Instance Coordinator)

Light‑weight Model Context Protocol (MCP) integration for IDA Pro enabling:

* One embedded FastMCP **SSE server** per IDA instance (`/mcp` endpoint).
* The first instance that can bind `127.0.0.1:11337` becomes the **coordinator** (in‑memory registry + request forwarding via `/call`).
* Later IDA instances auto‑register themselves (no shared files, no manual port bookkeeping).
* An optional standalone **proxy process** (`ida_mcp/proxy/ida_mcp_proxy.py`) exposes a consolidated MCP tool surface to external clients that only support spawning a single process.

This gives MCP / LLM clients a uniform way to query multiple concurrent reverse‑engineering sessions (functions, xrefs, types, debug info, …) while keeping plugin code minimal and thread‑safe.

---

## Features

* Zero persistent state: coordinator registry lives only in memory.
* Auto port selection (starting at 8765 for per‑instance SSE; 11337 reserved for coordinator when available).
* Tool forwarding with minimal overhead (thin JSON POST `/call`).
* Function, global symbol, string, local type, and Hex‑Rays helpers.
* Debugger helpers (registers, stack, breakpoints, run‑to, continue, etc.).
* Consistent parameter documentation via Pydantic v2 `Annotated[...] + Field(description=...)` (both server and proxy).
* Safe IDA API usage: every operation marshalled back to the IDA main thread (`ida_kernwin.execute_sync`).

---

## Architecture Overview

```text
IDA Instance A                IDA Instance B               Proxy Process (optional)
---------------               ---------------               -----------------------
FastMCP SSE server            FastMCP SSE server           FastMCP server
 | /mcp tools                 | /mcp tools                 | proxy tools
 | register ->                | register ->                | calls /call (coordinator)
          In‑Memory Coordinator (port 11337 if first instance)
                       | /instances  | /call -> forward to target instance
```

Coordinator responsibilities:

* Maintain current live instance list (port, name, last_seen, metadata).
* Provide `/instances` and `/call` endpoints.
* Forward tool invocations and serialize results.

Proxy responsibilities:

* Expose unified tool set (auto‑select or user‑select active instance).
* Remain process‑only (no direct IDA API) – pure HTTP forwarding.

---

## Repository Layout

```text
IDA-MCP/
  ida_mcp.py              # IDA plugin entry: start/stop SSE server & (maybe) coordinator
  ida_mcp/
    server.py             # Core FastMCP tool implementations inside IDA
    registry.py           # Coordinator (instance registry + /call forwarding)
    __init__.py           # Package init / exports
    proxy/
      ida_mcp_proxy.py    # Standalone proxy FastMCP server (forwarder)
  mcp.json                # Example MCP client configuration
  README.md               # Chinese README (original)
  README-EN.md            # This English README
  requirements.txt        # Python deps (fastmcp, pydantic, ...)
```

---

## Installation (IDA Plugin)

1. Copy `ida_mcp.py` and the `ida_mcp/` package directory into your IDA `plugins/` folder.
2. Open a target binary in IDA and let auto‑analysis finish (recommended for richer results).
3. Trigger the plugin (menu / hotkey). First activation:
   * Chooses a free SSE port (starting at 8765) and serves `http://127.0.0.1:<port>/mcp/`.
   * If port 11337 is free: starts coordinator. Else: registers with existing coordinator.
4. Trigger again to stop & unregister this instance.

> Multiple IDA windows can now coexist; each runs its own SSE server and shares the coordinator.

---

## Proxy Usage (Optional Consolidated Endpoint)

If your MCP client can spawn only one process (e.g. simple IDE integration), use the proxy.

Example `mcp.json` fragment:

```jsonc
{
  "mcpServers": {
    "ida-mcp-proxy": {
      "command": "python",
      "args": ["/absolute/path/to/ida_mcp/proxy/ida_mcp_proxy.py"],
      "description": "IDA MCP proxy forwarding to coordinator /call"
    }
  },
  "version": "1.0.0",
  "description": "IDA-MCP multi-instance configuration"
}
```

The proxy automatically picks an instance (prefers port 8765, else earliest start) unless you call `select_instance(port)`. Most proxy tools accept an optional `port` parameter to override.

---

## Available Tools (Server Inside IDA)

Category | Tools (summary)
---------|-----------------
Core / Metadata | `check_connection`, `list_instances`, `get_metadata`
Functions | `list_functions`, `get_function_by_name`, `get_function_by_address`, `get_current_function`, `get_current_address`, `decompile_function` (Hex‑Rays), `disassemble_function`, `get_entry_points`
Symbols / Data | `list_globals`, `list_globals_filter`, `list_strings`, `list_strings_filter`, `list_local_types`, `get_xrefs_to`, `get_xrefs_to_field`
Editing / Types | `set_comment`, `rename_function`, `rename_global_variable`, `rename_local_variable`, `set_function_prototype`, `set_global_variable_type`, `set_local_variable_type`, `declare_c_type`
Utilities | `convert_number`
Debugger | `dbg_get_registers`, `dbg_get_call_stack`, `dbg_list_breakpoints`, `dbg_start_process`, `dbg_exit_process`, `dbg_continue_process`, `dbg_run_to`, `dbg_set_breakpoint`, `dbg_delete_breakpoint`, `dbg_enable_breakpoint`

All parameter schemas now include per‑argument descriptions (Pydantic v2 `Annotated` + `Field`) enabling richer auto‑generated tool metadata for MCP clients.

---

## Available Tools (Proxy)

The proxy mirrors most server tools, adding:

* `select_instance(port?)` – set or auto‑select default backend instance.
* Every mirrored tool optionally accepts `port` to temporarily override selection.

Forwarded categories match the server (functions, symbols, types, debugger, etc.). Logic: validate minimal inputs → determine target port → POST `/call` to coordinator → unwrap `data` field.

---

## Parameter Documentation Strategy

* Server (`server.py`) and proxy (`ida_mcp_proxy.py`) use:

```python
from typing import Annotated
from pydantic import Field

def example(arg: Annotated[int, Field(description="Meaningful explanation")]):
    ...
```

* FastMCP produces JSON Schema with each argument's description for LLM / client introspection.

---

## Thread Safety

IDA is not thread‑safe for most APIs. All heavy or state‑touching calls are re‑routed to the main thread via `ida_kernwin.execute_sync` (`_run_in_ida` wrapper). This prevents deadlocks and sporadic crashes seen in naive multi‑threaded plugin code.

---

## Development & Dependencies

Install Python requirements (outside or inside the environment you use to run the proxy):

```bash
python -m pip install -r requirements.txt
```

The plugin inside IDA does not need extra installation beyond copying the files (it will import bundled modules). The proxy process requires the same dependencies as defined above.

---

## Troubleshooting

Symptom | Cause | Action
--------|-------|-------
`list_instances` empty in proxy | No IDA instance started or coordinator port blocked | Start at least one IDA instance; ensure 11337 not firewalled
Calls time out | Target instance busy (analysis, heavy decompilation) | Wait for analysis or restart the instance
`call failed` errors | Instance was closed without deregistration | Toggle plugin (stop/start) to refresh registry
Missing Hex‑Rays functions | Hex‑Rays not installed / not initialized | Install / license Hex‑Rays; open a function to force init
`invalid address` errors | Parameter formatting mismatch | Ensure decimal or 0x... / trailing h forms; underscores allowed

---

## Roadmap / Ideas

* Heartbeat & stale instance pruning in coordinator.
* Generic `forward(tool, params, port)` proxy tool (meta‑call).
* Streaming / progress (MCP resources & streaming events).
* Additional analysis tools: pattern search, data patching, structure diffs.
* Optional auth / allow‑list for hardened deployments.

Contributions & incremental extensions welcome.

---

## License

Add your chosen license (e.g. MIT) here if distributing publicly.

---

## Quick Summary

IDA-MCP provides a minimal, multi‑instance aware MCP surface over IDA Pro with rich parameter metadata and optional proxy consolidation — enabling automated reverse‑engineering assistant workflows without complex setup.
