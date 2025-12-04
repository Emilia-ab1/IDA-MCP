"""测试 api_analysis.py 中的工具。

测试逻辑：
1. 使用 fixtures 预先获取函数/字符串等前置信息
2. 基于这些信息调用分析工具
3. 验证返回结果的格式和内容

API 参数对应：
- decompile: addr (逗号分隔的地址或名称字符串)
- disasm: addr (逗号分隔的地址或名称字符串)
- linear_disassemble: start_address, count
- xrefs_to: addr (逗号分隔的地址字符串)
"""
import pytest


class TestDecompile:
    """反编译测试。"""
    
    @pytest.mark.hexrays
    def test_decompile_by_address(self, tool_caller, first_function_address):
        """测试按地址反编译。"""
        result = tool_caller("decompile", {"addr": hex(first_function_address)})
        
        assert isinstance(result, list)
        assert len(result) == 1
        # 结果应该包含 decompiled 或 error
        assert "decompiled" in result[0] or "error" in result[0]
    
    @pytest.mark.hexrays
    def test_decompile_by_name(self, tool_caller, first_function_name):
        """测试按名称反编译。"""
        result = tool_caller("decompile", {"addr": first_function_name})
        
        assert isinstance(result, list)
        assert len(result) == 1
    
    @pytest.mark.hexrays
    def test_decompile_batch(self, tool_caller, functions_cache):
        """测试批量反编译（逗号分隔）。"""
        if len(functions_cache) < 3:
            pytest.skip("Not enough functions for batch test")
        
        # API 接受逗号分隔的字符串（cache 中的 start_ea 已经是 hex 字符串）
        addr_list = ",".join(f["start_ea"] for f in functions_cache[:3])
        result = tool_caller("decompile", {"addr": addr_list})
        
        assert isinstance(result, list)
        assert len(result) == 3
    
    @pytest.mark.hexrays
    def test_decompile_invalid_address(self, tool_caller):
        """测试无效地址反编译。"""
        result = tool_caller("decompile", {"addr": "0xDEADBEEF"})
        
        assert isinstance(result, list)
        assert len(result) == 1
        assert "error" in result[0]
    
    @pytest.mark.hexrays
    def test_decompile_main(self, tool_caller, main_function_address):
        """测试反编译 main 函数。"""
        result = tool_caller("decompile", {"addr": hex(main_function_address)})
        
        assert isinstance(result, list)
        if result and "decompiled" in result[0]:
            # main 函数应该包含一些常见元素
            code = result[0]["decompiled"]
            assert len(code) > 0


class TestDisasm:
    """反汇编测试。"""
    
    def test_disasm_by_address(self, tool_caller, first_function_address):
        """测试按地址反汇编。"""
        result = tool_caller("disasm", {"addr": hex(first_function_address)})
        
        assert isinstance(result, list)
        assert len(result) == 1
        if "error" not in result[0]:
            assert "instructions" in result[0]
            assert len(result[0]["instructions"]) > 0
    
    def test_disasm_by_name(self, tool_caller, first_function_name):
        """测试按名称反汇编。"""
        result = tool_caller("disasm", {"addr": first_function_name})
        
        assert isinstance(result, list)
        assert len(result) == 1
    
    def test_disasm_batch(self, tool_caller, functions_cache):
        """测试批量反汇编（逗号分隔）。"""
        if len(functions_cache) < 3:
            pytest.skip("Not enough functions for batch test")
        
        addr_list = ",".join(f["start_ea"] for f in functions_cache[:3])
        result = tool_caller("disasm", {"addr": addr_list})
        
        assert isinstance(result, list)
        assert len(result) == 3
    
    def test_disasm_invalid_address(self, tool_caller):
        """测试无效地址反汇编。"""
        result = tool_caller("disasm", {"addr": "0xDEADBEEF"})
        
        assert isinstance(result, list)
        assert len(result) == 1
        assert "error" in result[0]


class TestLinearDisassemble:
    """线性反汇编测试。"""
    
    def test_linear_disassemble(self, tool_caller, first_function_address):
        """测试线性反汇编。"""
        result = tool_caller("linear_disassemble", {
            "start_address": hex(first_function_address),
            "count": 10
        })
        
        if "error" not in result:
            assert "instructions" in result
            assert len(result["instructions"]) <= 10
    
    def test_linear_disassemble_more(self, tool_caller, first_function_address):
        """测试较多指令的线性反汇编。"""
        result = tool_caller("linear_disassemble", {
            "start_address": hex(first_function_address),
            "count": 50
        })
        
        if "error" not in result:
            assert "instructions" in result
            # 验证指令格式
            if result["instructions"]:
                inst = result["instructions"][0]
                assert "ea" in inst  # API 返回 ea
    
    def test_linear_disassemble_invalid_count(self, tool_caller, first_function_address):
        """测试无效计数。"""
        result = tool_caller("linear_disassemble", {
            "start_address": hex(first_function_address),
            "count": 0
        })
        assert "error" in result
    
    def test_linear_disassemble_count_too_large(self, tool_caller, first_function_address):
        """测试计数过大（max 64）。"""
        result = tool_caller("linear_disassemble", {
            "start_address": hex(first_function_address),
            "count": 100
        })
        assert "error" in result


class TestXrefsTo:
    """交叉引用测试。"""
    
    def test_xrefs_to_function(self, tool_caller, first_function_address):
        """测试函数的交叉引用。"""
        result = tool_caller("xrefs_to", {"addr": hex(first_function_address)})
        
        assert isinstance(result, list)
        assert len(result) == 1
        if "error" not in result[0]:
            assert "xrefs" in result[0]
    
    def test_xrefs_to_decimal_address(self, tool_caller, first_function_address):
        """测试十进制地址格式。"""
        # xrefs_to API 只支持地址格式，不支持名称
        result = tool_caller("xrefs_to", {"addr": str(first_function_address)})
        
        assert isinstance(result, list)
        assert len(result) == 1
    
    def test_xrefs_to_batch(self, tool_caller, functions_cache):
        """测试批量交叉引用查询（逗号分隔）。"""
        if len(functions_cache) < 3:
            pytest.skip("Not enough functions for batch test")
        
        addr_list = ",".join(f["start_ea"] for f in functions_cache[:3])
        result = tool_caller("xrefs_to", {"addr": addr_list})
        
        assert isinstance(result, list)
        assert len(result) == 3
    
    def test_xrefs_to_string(self, tool_caller, first_string_address):
        """测试字符串的交叉引用。"""
        result = tool_caller("xrefs_to", {"addr": hex(first_string_address)})
        
        assert isinstance(result, list)
        assert len(result) == 1
        # 字符串通常会有引用
        if "error" not in result[0]:
            assert "xrefs" in result[0]


class TestXrefsToField:
    """结构体字段引用测试。"""
    
    def test_xrefs_to_field_nonexistent(self, tool_caller):
        """测试不存在的结构体字段引用。"""
        result = tool_caller("xrefs_to_field", {
            "struct_name": "nonexistent_struct_xyz",
            "field_name": "field"
        })
        # 应该返回错误或空结果
        assert isinstance(result, dict)
    
    def test_xrefs_to_field_with_types(self, tool_caller, local_types_cache):
        """测试已知类型的字段引用。"""
        if not local_types_cache:
            pytest.skip("No local types available")
        
        # 尝试找一个结构体类型
        # API 返回 {ordinal, name, decl} 字段，检查 decl 中是否包含 struct
        struct_type = None
        for t in local_types_cache:
            decl = t.get("decl", "")
            if "struct" in decl.lower():
                struct_type = t
                break
        
        if not struct_type:
            pytest.skip("No struct types found")
        
        result = tool_caller("xrefs_to_field", {
            "struct_name": struct_type["name"],
            "field_name": "unknown_field"
        })
        assert isinstance(result, dict)
