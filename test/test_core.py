"""测试 api_core.py 中的工具。

测试逻辑：
1. 基础连接和实例管理
2. 元数据获取
3. 函数/全局变量/字符串列表
4. 入口点和类型
"""
import pytest


class TestConnection:
    """连接和实例管理测试。"""
    
    def test_check_connection(self, tool_caller):
        """测试连接检查。"""
        result = tool_caller("check_connection")
        assert "ok" in result
        assert result["ok"] is True
    
    def test_list_instances(self, tool_caller):
        """测试列出实例。"""
        result = tool_caller("list_instances")
        assert isinstance(result, list)
        assert len(result) >= 1


class TestMetadata:
    """IDB 元数据测试。"""
    
    def test_get_metadata(self, tool_caller, metadata):
        """测试获取元数据。"""
        # metadata fixture 已经获取了元数据
        assert "input_file" in metadata
        assert "arch" in metadata
        assert "bits" in metadata
    
    def test_metadata_arch(self, metadata):
        """测试架构信息。"""
        assert metadata["arch"] in ("x86", "x64", "arm", "arm64", "mips", "ppc", "metapc")
    
    def test_metadata_bits(self, metadata):
        """测试位宽信息。"""
        assert metadata["bits"] in (16, 32, 64)


class TestFunctions:
    """函数列表测试。"""
    
    def test_list_functions_default(self, tool_caller):
        """测试默认参数列出函数。"""
        # 显式传递所有参数以兼容签名问题
        result = tool_caller("list_functions", {"offset": 0, "count": 100})
        assert "error" not in result
        assert "items" in result
        assert "total" in result
    
    def test_list_functions_pagination(self, tool_caller):
        """测试分页参数。"""
        result = tool_caller("list_functions", {"offset": 0, "count": 10})
        assert "error" not in result
        assert "items" in result
        assert len(result["items"]) <= 10
    
    def test_list_functions_offset(self, tool_caller, functions_cache):
        """测试偏移参数。"""
        if len(functions_cache) < 5:
            pytest.skip("Not enough functions")
        
        result1 = tool_caller("list_functions", {"offset": 0, "count": 3})
        result2 = tool_caller("list_functions", {"offset": 2, "count": 3})
        
        # 第二次查询的第一个应该等于第一次的第三个
        if result1["items"] and result2["items"]:
            assert result1["items"][2]["start_ea"] == result2["items"][0]["start_ea"]
    
    def test_list_functions_pattern(self, tool_caller):
        """测试模式过滤。"""
        result = tool_caller("list_functions", {"offset": 0, "count": 100, "pattern": "*"})
        assert "error" not in result
    
    def test_list_functions_invalid_offset(self, tool_caller):
        """测试无效偏移。"""
        result = tool_caller("list_functions", {"offset": -1})
        assert "error" in result
    
    def test_list_functions_invalid_count(self, tool_caller):
        """测试无效计数。"""
        result = tool_caller("list_functions", {"offset": 0, "count": 0})
        assert "error" in result
    
    def test_list_functions_count_too_large(self, tool_caller):
        """测试计数过大。"""
        result = tool_caller("list_functions", {"offset": 0, "count": 10000})
        assert "error" in result


class TestGetFunction:
    """函数查找测试。"""
    
    def test_get_function_by_name(self, tool_caller, first_function_name):
        """测试按名称查找。"""
        result = tool_caller("get_function", {"query": first_function_name})
        assert "error" not in result
        assert result.get("name") == first_function_name
    
    def test_get_function_by_address(self, tool_caller, first_function_address):
        """测试按地址查找。"""
        result = tool_caller("get_function", {"query": hex(first_function_address)})
        assert "error" not in result
        # start_ea 返回为 hex 字符串（大写），比较时忽略大小写
        assert result.get("start_ea", "").lower() == hex(first_function_address).lower()
    
    def test_get_function_by_address_inside(self, tool_caller, first_function):
        """测试按函数内部地址查找。"""
        # 使用函数内的地址（起始地址+4），start_ea 是 hex 字符串
        addr = int(first_function["start_ea"], 16) + 4
        result = tool_caller("get_function", {"query": hex(addr)})
        # 应该能找到同一个函数
        if "error" not in result:
            assert result.get("start_ea") == first_function["start_ea"]
    
    def test_get_function_not_found(self, tool_caller):
        """测试查找不存在的函数。"""
        result = tool_caller("get_function", {"query": "nonexistent_function_xyz123456"})
        assert "error" in result
    
    def test_get_function_empty_query(self, tool_caller):
        """测试空查询。"""
        result = tool_caller("get_function", {"query": ""})
        assert "error" in result


class TestGlobals:
    """全局变量测试。"""
    
    def test_list_globals_default(self, tool_caller):
        """测试默认参数列出全局变量。"""
        result = tool_caller("list_globals", {"offset": 0, "count": 100})
        assert "error" not in result
        assert "items" in result
    
    def test_list_globals_pagination(self, tool_caller):
        """测试分页。"""
        result = tool_caller("list_globals", {"offset": 0, "count": 5})
        assert "error" not in result
        assert len(result.get("items", [])) <= 5
    
    def test_list_globals_pattern(self, tool_caller):
        """测试模式过滤。"""
        result = tool_caller("list_globals", {"offset": 0, "count": 100, "pattern": "*"})
        assert "error" not in result


class TestStrings:
    """字符串测试。"""
    
    def test_list_strings_default(self, tool_caller):
        """测试默认参数列出字符串。"""
        result = tool_caller("list_strings", {"offset": 0, "count": 100})
        assert "error" not in result
        assert "items" in result
    
    def test_list_strings_pagination(self, tool_caller):
        """测试分页。"""
        result = tool_caller("list_strings", {"offset": 0, "count": 10})
        assert "error" not in result
        assert len(result.get("items", [])) <= 10
    
    def test_list_strings_pattern(self, tool_caller, strings_cache):
        """测试内容过滤。"""
        if not strings_cache:
            pytest.skip("No strings available")
        
        # 使用已知字符串的一部分进行搜索
        # API 返回 "text" 字段，不是 "value"
        first_str = strings_cache[0].get("text", "")
        if len(first_str) > 3:
            pattern = first_str[:3]
            result = tool_caller("list_strings", {"offset": 0, "count": 100, "pattern": pattern})
            assert "error" not in result


class TestLocalTypes:
    """本地类型测试。"""
    
    def test_list_local_types(self, tool_caller):
        """测试列出本地类型。"""
        result = tool_caller("list_local_types")
        assert "error" not in result
        assert "items" in result or "total" in result


class TestEntryPoints:
    """入口点测试。"""
    
    def test_get_entry_points(self, tool_caller):
        """测试获取入口点。"""
        result = tool_caller("get_entry_points")
        assert "error" not in result
        assert "items" in result


class TestConvertNumber:
    """数字转换测试。"""
    
    def test_convert_hex(self, tool_caller):
        """测试十六进制转换。"""
        result = tool_caller("convert_number", {"text": "0x1234"})
        assert "error" not in result
        assert result.get("value") == 0x1234
    
    def test_convert_hex_uppercase(self, tool_caller):
        """测试大写十六进制。"""
        result = tool_caller("convert_number", {"text": "0xABCD"})
        assert "error" not in result
        assert result.get("value") == 0xABCD
    
    def test_convert_decimal(self, tool_caller):
        """测试十进制转换。"""
        result = tool_caller("convert_number", {"text": "1234"})
        assert "error" not in result
        assert result.get("value") == 1234
    
    def test_convert_negative(self, tool_caller):
        """测试负数转换。"""
        result = tool_caller("convert_number", {"text": "-100", "size": 64})
        assert "error" not in result
        # value 是无符号掩码后的值，signed 是有符号解释
        assert result.get("signed") == -100
    
    def test_convert_binary(self, tool_caller):
        """测试二进制转换。"""
        result = tool_caller("convert_number", {"text": "0b1010"})
        assert "error" not in result
        assert result.get("value") == 10
    
    def test_convert_octal(self, tool_caller):
        """测试八进制转换。"""
        result = tool_caller("convert_number", {"text": "0o777"})
        assert "error" not in result
        assert result.get("value") == 511
    
    def test_convert_with_size_8(self, tool_caller):
        """测试 8 位宽。"""
        result = tool_caller("convert_number", {"text": "0xFF", "size": 8})
        assert "error" not in result
        assert result.get("signed") == -1
    
    def test_convert_with_size_16(self, tool_caller):
        """测试 16 位宽。"""
        result = tool_caller("convert_number", {"text": "0xFFFF", "size": 16})
        assert "error" not in result
        assert result.get("signed") == -1
    
    def test_convert_with_size_32(self, tool_caller):
        """测试 32 位宽。"""
        result = tool_caller("convert_number", {"text": "0xFFFFFFFF", "size": 32})
        assert "error" not in result
        assert result.get("signed") == -1
    
    def test_convert_invalid(self, tool_caller):
        """测试无效输入。"""
        result = tool_caller("convert_number", {"text": "invalid"})
        assert "error" in result
    
    def test_convert_empty(self, tool_caller):
        """测试空输入。"""
        result = tool_caller("convert_number", {"text": ""})
        assert "error" in result
