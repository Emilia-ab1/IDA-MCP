#!/usr/bin/env python
"""IDA-MCP 测试主入口。

使用方法:
    1. 启动 IDA 并加载插件
    2. 运行测试:
        python -m pytest test/ -v           # 运行全部测试
        python -m pytest test/ -v -k core   # 只运行 core 测试
        python -m pytest test/ -v -m debug  # 只运行调试器测试
        python -m pytest test/ -v --ignore=test/test_debug.py  # 跳过调试器测试
    
    或者直接运行此文件:
        python test/test.py                 # 运行全部测试
        python test/test.py --quick         # 快速测试（跳过慢速测试）
        python test/test.py --debug         # 运行调试器测试
"""
import sys
import os

# 添加项目根目录到路径
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)


def check_coordinator() -> bool:
    """检查 coordinator 是否可用。"""
    import urllib.request
    import urllib.error
    import json
    
    try:
        url = "http://127.0.0.1:11337/instances"
        req = urllib.request.Request(url)
        with urllib.request.urlopen(req, timeout=2) as resp:
            data = json.loads(resp.read().decode('utf-8'))
            # API 直接返回列表，不是 {"instances": [...]} 格式
            instances = data if isinstance(data, list) else []
            return len(instances) > 0
    except Exception:
        return False


def run_tests(args: list | None = None):
    """运行测试。"""
    try:
        import pytest
    except ImportError:
        print("ERROR: pytest not installed. Run: pip install pytest")
        return 1
    
    # 检查 coordinator
    if not check_coordinator():
        print("WARNING: No IDA instances available.")
        print("Please start IDA and load the MCP plugin first.")
        print()
        response = input("Continue anyway? (y/N): ").strip().lower()
        if response != 'y':
            return 1
    
    # 构建 pytest 参数
    test_dir = os.path.dirname(os.path.abspath(__file__))
    pytest_args = [test_dir, "-v"]
    
    if args:
        if "--quick" in args:
            # 快速测试：跳过慢速和调试器测试
            pytest_args.extend(["-m", "not slow and not debug"])
            args.remove("--quick")
        
        if "--debug" in args:
            # 调试器测试
            pytest_args.extend(["-m", "debug"])
            args.remove("--debug")
        
        if "--hexrays" in args:
            # Hex-Rays 测试
            pytest_args.extend(["-m", "hexrays"])
            args.remove("--hexrays")
        
        # 传递其他参数给 pytest
        pytest_args.extend(args)
    
    # 运行测试
    return pytest.main(pytest_args)


def main():
    """主函数。"""
    args = sys.argv[1:]
    
    if "--help" in args or "-h" in args:
        print(__doc__)
        return 0
    
    return run_tests(args)


if __name__ == "__main__":
    sys.exit(main())

