"""pytest 配置和共享 fixtures。

测试框架设计：
1. coordinator_available - 检查 coordinator 是否运行
2. instance_port - 获取可用 IDA 实例端口
3. tool_caller - 工具调用函数
4. 前置信息 fixtures（session 级别缓存）:
   - first_function - 获取第一个函数信息
   - first_string - 获取第一个字符串信息
   - first_global - 获取第一个全局变量信息
   - metadata - 获取 IDB 元数据
5. API 调用日志 - 保存所有请求参数和返回值到 test_api_log.json
"""
import pytest
import urllib.request
import urllib.error
import json
import os
from datetime import datetime
from typing import Any, Optional, Dict, List, Union


# ============================================================================
# API 调用日志
# ============================================================================

# 全局日志列表，记录所有 API 调用
_api_call_log: List[Dict[str, Any]] = []

# 日志目录路径
_LOG_DIR = os.path.join(os.path.dirname(__file__), "api_logs")

# API 分类映射
_API_CATEGORIES = {
    # Core
    "check_connection": "core",
    "list_instances": "core",
    "get_metadata": "core",
    "list_functions": "core",
    "get_function": "core",
    "list_globals": "core",
    "list_strings": "core",
    "list_local_types": "core",
    "get_entry_points": "core",
    "convert_number": "core",
    
    # Analysis
    "decompile": "analysis",
    "disasm": "analysis",
    "linear_disassemble": "analysis",
    "xrefs_to": "analysis",
    "xrefs_from": "analysis",
    "xrefs_to_field": "analysis",
    
    # Memory
    "get_bytes": "memory",
    "get_u8": "memory",
    "get_u16": "memory",
    "get_u32": "memory",
    "get_u64": "memory",
    "get_string": "memory",
    
    # Modify
    "set_comment": "modify",
    "rename_function": "modify",
    "rename_local_variable": "modify",
    "rename_global_variable": "modify",
    
    # Types
    "declare_type": "types",
    "set_function_prototype": "types",
    "set_local_variable_type": "types",
    "set_global_variable_type": "types",
    
    # Stack
    "stack_frame": "stack",
    "declare_stack": "stack",
    "delete_stack": "stack",
    
    # Debug
    "dbg_regs": "debug",
    "dbg_get_registers": "debug",
    "dbg_callstack": "debug",
    "dbg_get_call_stack": "debug",
    "dbg_list_bps": "debug",
    "dbg_list_breakpoints": "debug",
    "dbg_start": "debug",
    "dbg_start_process": "debug",
    "dbg_exit": "debug",
    "dbg_exit_process": "debug",
    "dbg_continue": "debug",
    "dbg_continue_process": "debug",
    "dbg_run_to": "debug",
    "dbg_add_bp": "debug",
    "dbg_set_breakpoint": "debug",
    "dbg_delete_bp": "debug",
    "dbg_delete_breakpoint": "debug",
    "dbg_enable_bp": "debug",
    "dbg_enable_breakpoint": "debug",
    "dbg_step_into": "debug",
    "dbg_step_over": "debug",
    "dbg_read_mem": "debug",
    "dbg_write_mem": "debug",
}


def _get_api_category(tool_name: str) -> str:
    """获取 API 分类。"""
    return _API_CATEGORIES.get(tool_name, "other")


def _log_api_call(tool_name: str, params: dict, port: Optional[int], result: Any, duration_ms: float) -> None:
    """记录 API 调用。"""
    _api_call_log.append({
        "timestamp": datetime.now().isoformat(),
        "category": _get_api_category(tool_name),
        "tool": tool_name,
        "params": params,
        "port": port,
        "result": result,
        "duration_ms": round(duration_ms, 2),
    })


def _save_api_log() -> None:
    """保存 API 日志到多个文件（按分类）。"""
    if not _api_call_log:
        return
    
    # 按分类组织
    categorized: Dict[str, List[Dict[str, Any]]] = {}
    for call in _api_call_log:
        category = call.get("category", "other")
        if category not in categorized:
            categorized[category] = []
        categorized[category].append(call)
    
    # 统计信息
    stats = {cat: len(calls) for cat, calls in categorized.items()}
    
    try:
        # 创建日志目录
        os.makedirs(_LOG_DIR, exist_ok=True)
        
        # 保存各分类文件
        for category, calls in categorized.items():
            log_file = os.path.join(_LOG_DIR, f"{category}.json")
            with open(log_file, "w", encoding="utf-8") as f:
                json.dump({
                    "category": category,
                    "generated_at": datetime.now().isoformat(),
                    "total_calls": len(calls),
                    "calls": calls,
                }, f, indent=2, ensure_ascii=False, default=str)
        
        # 保存汇总文件
        summary_file = os.path.join(_LOG_DIR, "_summary.json")
        with open(summary_file, "w", encoding="utf-8") as f:
            json.dump({
                "generated_at": datetime.now().isoformat(),
                "total_calls": len(_api_call_log),
                "stats_by_category": stats,
                "files": [f"{cat}.json" for cat in sorted(categorized.keys())],
            }, f, indent=2, ensure_ascii=False, default=str)
        
        print(f"\n[API Log] Saved {len(_api_call_log)} calls to {_LOG_DIR}/")
        print(f"[API Log] Files: {', '.join(f'{cat}.json ({cnt})' for cat, cnt in sorted(stats.items()))}")
    except Exception as e:
        print(f"\n[API Log] Failed to save: {e}")


# ============================================================================
# 地址解析辅助函数
# ============================================================================

def parse_addr(addr: Union[str, int]) -> int:
    """将地址转换为整数（支持 hex string 或 int）。"""
    if isinstance(addr, str):
        return int(addr, 16)
    return addr

# Coordinator 地址
COORDINATOR_HOST = "127.0.0.1"
COORDINATOR_PORT = 11337


# ============================================================================
# HTTP 工具函数
# ============================================================================

def http_get(url: str, timeout: float = 5.0) -> Any:
    """发送 GET 请求。"""
    try:
        req = urllib.request.Request(url)
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read().decode('utf-8'))
    except Exception as e:
        return {"error": str(e)}


def http_post(url: str, data: dict, timeout: float = 10.0) -> Any:
    """发送 POST 请求。"""
    try:
        body = json.dumps(data).encode('utf-8')
        req = urllib.request.Request(
            url,
            data=body,
            headers={"Content-Type": "application/json"},
            method="POST"
        )
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read().decode('utf-8'))
    except Exception as e:
        return {"error": str(e)}


def call_tool(tool_name: str, params: dict, port: Optional[int] = None) -> Any:
    """调用 IDA 工具。"""
    import time
    start_time = time.perf_counter()
    
    url = f"http://{COORDINATOR_HOST}:{COORDINATOR_PORT}/call"
    payload = {
        "tool": tool_name,
        "params": params,
    }
    if port:
        payload["port"] = port
    result = http_post(url, payload)
    
    duration_ms = (time.perf_counter() - start_time) * 1000
    
    # 协调器返回 {"tool": ..., "data": ...} 格式，提取 data 字段
    data = result
    if isinstance(result, dict) and "data" in result:
        data = result["data"]
    
    # 记录 API 调用
    _log_api_call(tool_name, params, port, data, duration_ms)
    
    return data


# ============================================================================
# 基础 Fixtures
# ============================================================================

@pytest.fixture(scope="session")
def coordinator_available():
    """检查 coordinator 是否可用。"""
    url = f"http://{COORDINATOR_HOST}:{COORDINATOR_PORT}/instances"
    result = http_get(url)
    if isinstance(result, dict) and "error" in result:
        pytest.skip(f"Coordinator not available: {result['error']}")
    return True


@pytest.fixture(scope="session")
def instance_port(coordinator_available):
    """获取第一个可用实例的端口。"""
    url = f"http://{COORDINATOR_HOST}:{COORDINATOR_PORT}/instances"
    result = http_get(url)
    # API 直接返回列表，不是 {"instances": [...]} 格式
    instances = result if isinstance(result, list) else []
    if not instances:
        pytest.skip("No IDA instances available")
    return instances[0].get("port")


@pytest.fixture
def tool_caller(instance_port):
    """返回工具调用函数。"""
    def caller(tool_name: str, params: Optional[dict] = None) -> Any:
        return call_tool(tool_name, params or {}, instance_port)
    return caller


# ============================================================================
# 前置信息 Fixtures（Session 级别缓存）
# ============================================================================

@pytest.fixture(scope="session")
def metadata(instance_port) -> Dict[str, Any]:
    """获取 IDB 元数据（缓存）。"""
    result = call_tool("get_metadata", {}, instance_port)
    if "error" in result:
        pytest.skip(f"Cannot get metadata: {result['error']}")
    return result


@pytest.fixture(scope="session")
def functions_cache(instance_port) -> List[Dict[str, Any]]:
    """获取函数列表缓存（前 100 个）。"""
    # 显式传递所有参数以兼容签名问题
    result = call_tool("list_functions", {"offset": 0, "count": 100}, instance_port)
    if "error" in result:
        pytest.skip(f"Cannot list functions: {result['error']}")
    return result.get("items", [])


@pytest.fixture(scope="session")
def strings_cache(instance_port) -> List[Dict[str, Any]]:
    """获取字符串列表缓存（前 100 个）。"""
    # 显式传递所有参数以兼容签名问题
    result = call_tool("list_strings", {"offset": 0, "count": 100}, instance_port)
    if "error" in result:
        pytest.skip(f"Cannot list strings: {result['error']}")
    return result.get("items", [])


@pytest.fixture(scope="session")
def globals_cache(instance_port) -> List[Dict[str, Any]]:
    """获取全局变量列表缓存（前 100 个）。"""
    # 显式传递所有参数以兼容签名问题
    result = call_tool("list_globals", {"offset": 0, "count": 100}, instance_port)
    if "error" in result:
        pytest.skip(f"Cannot list globals: {result['error']}")
    return result.get("items", [])


@pytest.fixture(scope="session")
def entry_points_cache(instance_port) -> List[Dict[str, Any]]:
    """获取入口点缓存。"""
    result = call_tool("get_entry_points", {}, instance_port)
    if "error" in result:
        return []  # 入口点可能为空，不跳过测试
    return result.get("items", [])


@pytest.fixture(scope="session")
def local_types_cache(instance_port) -> List[Dict[str, Any]]:
    """获取本地类型缓存。"""
    result = call_tool("list_local_types", {}, instance_port)
    if "error" in result:
        return []  # 类型可能为空，不跳过测试
    return result.get("items", [])


# ============================================================================
# 便捷的单项 Fixtures
# ============================================================================

@pytest.fixture(scope="session")
def first_function(functions_cache) -> Dict[str, Any]:
    """获取第一个函数（用于需要函数地址的测试）。"""
    if not functions_cache:
        pytest.skip("No functions available in IDB")
    return functions_cache[0]


@pytest.fixture(scope="session")
def first_function_address(first_function) -> int:
    """获取第一个函数的起始地址。"""
    addr = first_function["start_ea"]
    return int(addr, 16) if isinstance(addr, str) else addr


@pytest.fixture(scope="session")
def first_function_name(first_function) -> str:
    """获取第一个函数的名称。"""
    return first_function["name"]


@pytest.fixture(scope="session")
def first_string(strings_cache) -> Dict[str, Any]:
    """获取第一个字符串。"""
    if not strings_cache:
        pytest.skip("No strings available in IDB")
    return strings_cache[0]


@pytest.fixture(scope="session")
def first_string_address(first_string) -> int:
    """获取第一个字符串的地址。"""
    addr = first_string["ea"]
    return int(addr, 16) if isinstance(addr, str) else addr


@pytest.fixture(scope="session")
def first_global(globals_cache) -> Dict[str, Any]:
    """获取第一个全局变量。"""
    if not globals_cache:
        pytest.skip("No globals available in IDB")
    return globals_cache[0]


@pytest.fixture(scope="session")
def first_global_address(first_global) -> int:
    """获取第一个全局变量的地址。"""
    addr = first_global["ea"]
    return int(addr, 16) if isinstance(addr, str) else addr


@pytest.fixture(scope="session")
def main_function(functions_cache) -> Optional[Dict[str, Any]]:
    """尝试获取 main 函数。"""
    for func in functions_cache:
        if func.get("name") in ("main", "_main", "WinMain", "wWinMain", "mainCRTStartup"):
            return func
    return None


@pytest.fixture(scope="session")
def main_function_address(main_function) -> int:
    """获取 main 函数地址。"""
    if not main_function:
        pytest.skip("No main function found")
    addr = main_function["start_ea"]
    return int(addr, 16) if isinstance(addr, str) else addr


# ============================================================================
# 测试标记和钩子
# ============================================================================

def pytest_configure(config):
    """注册自定义标记。"""
    config.addinivalue_line("markers", "slow: 标记为慢速测试")
    config.addinivalue_line("markers", "debug: 需要调试器的测试")
    config.addinivalue_line("markers", "hexrays: 需要 Hex-Rays 的测试")


def pytest_sessionfinish(session, exitstatus):
    """测试结束时保存 API 日志。"""
    _save_api_log()
