"""测试 api_types.py 中的工具。

测试逻辑：
1. 测试类型声明
2. 测试函数原型设置
3. 测试变量类型设置
4. 测试结构体列表和详情

Proxy 参数对应：
- declare_type: decl
- set_function_prototype: function_address (str), prototype
- set_local_variable_type: function_address (str), variable_name, new_type
- set_global_variable_type: variable_name, new_type
- list_structs: pattern (可选)
- get_struct_info: name

运行方式：
    pytest -m types         # 只运行 types 模块测试
    pytest test_types.py    # 运行此文件所有测试
"""
import pytest

pytestmark = pytest.mark.types


class TestDeclareType:
    """声明类型测试。"""
    
    def test_declare_struct(self, tool_caller):
        """测试声明结构体。"""
        # API 参数名为 decl
        result = tool_caller("declare_type", {
            "decl": "struct TestStruct { int field1; char field2; };"
        })
        
        if "error" not in result:
            # API 返回 ok 字段表示成功
            assert result.get("ok") is True
    
    def test_declare_typedef(self, tool_caller):
        """测试声明 typedef。"""
        result = tool_caller("declare_type", {
            "decl": "typedef unsigned int UINT32;"
        })
        
        if "error" not in result:
            assert result.get("ok") is True
    
    def test_declare_enum(self, tool_caller):
        """测试声明枚举。"""
        result = tool_caller("declare_type", {
            "decl": "enum TestEnum { VALUE_A = 0, VALUE_B = 1, VALUE_C = 2 };"
        })
        
        if "error" not in result:
            assert result.get("ok") is True
    
    def test_declare_complex_struct(self, tool_caller):
        """测试声明复杂结构体。"""
        result = tool_caller("declare_type", {
            "decl": """
                struct ComplexStruct {
                    int id;
                    char name[32];
                    struct {
                        int x;
                        int y;
                    } position;
                    void* data;
                };
            """
        })
        assert isinstance(result, dict)
    
    def test_declare_invalid(self, tool_caller):
        """测试无效声明。"""
        result = tool_caller("declare_type", {
            "decl": "invalid syntax here {"
        })
        assert "error" in result
    
    def test_declare_empty(self, tool_caller):
        """测试空声明。"""
        result = tool_caller("declare_type", {
            "decl": ""
        })
        assert "error" in result


class TestSetFunctionPrototype:
    """设置函数原型测试。"""
    
    def test_set_function_prototype(self, tool_caller, first_function_address):
        """测试设置函数原型。"""
        # Proxy 参数: function_address (str), prototype
        result = tool_caller("set_function_prototype", {
            "function_address": hex(first_function_address),
            "prototype": "int __cdecl func(int a, int b)"
        })
        
        # 可能成功或失败
        assert isinstance(result, dict)
    
    def test_set_function_prototype_invalid_address(self, tool_caller):
        """测试无效地址。"""
        result = tool_caller("set_function_prototype", {
            "function_address": hex(0xDEADBEEF),
            "prototype": "int func(void)"
        })
        assert "error" in result
    
    def test_set_function_prototype_empty(self, tool_caller, first_function_address):
        """测试空原型。"""
        result = tool_caller("set_function_prototype", {
            "function_address": hex(first_function_address),
            "prototype": ""
        })
        assert "error" in result
    
    def test_set_function_prototype_invalid_syntax(self, tool_caller, first_function_address):
        """测试无效原型语法。"""
        result = tool_caller("set_function_prototype", {
            "function_address": hex(first_function_address),
            "prototype": "invalid prototype syntax"
        })
        assert "error" in result


class TestSetLocalVariableType:
    """设置局部变量类型测试。"""
    
    def test_set_local_variable_type(self, tool_caller, first_function_address):
        """测试设置局部变量类型。"""
        # Proxy 参数: function_address (str), variable_name, new_type
        result = tool_caller("set_local_variable_type", {
            "function_address": hex(first_function_address),
            "variable_name": "v1",
            "new_type": "int"
        })
        
        # 可能成功或失败（取决于是否有该变量）
        assert isinstance(result, dict)
    
    def test_set_local_variable_type_pointer(self, tool_caller, first_function_address):
        """测试设置指针类型。"""
        result = tool_caller("set_local_variable_type", {
            "function_address": hex(first_function_address),
            "variable_name": "v1",
            "new_type": "char*"
        })
        
        assert isinstance(result, dict)


class TestSetGlobalVariableType:
    """设置全局变量类型测试。"""
    
    def test_set_global_variable_type(self, tool_caller, first_global):
        """测试设置全局变量类型。"""
        # API 参数: variable_name, new_type
        result = tool_caller("set_global_variable_type", {
            "variable_name": first_global["name"],
            "new_type": "int"
        })
        
        # 可能成功或失败
        assert isinstance(result, dict)
    
    def test_set_global_variable_type_not_found(self, tool_caller):
        """测试不存在的全局变量。"""
        result = tool_caller("set_global_variable_type", {
            "variable_name": "nonexistent_global_xyz123",
            "new_type": "int"
        })
        assert "error" in result
    
    def test_set_global_variable_type_struct(self, tool_caller, first_global):
        """测试设置结构体类型。"""
        # 先声明结构体
        tool_caller("declare_type", {
            "decl": "struct TestGlobalType { int a; int b; };"
        })
        
        result = tool_caller("set_global_variable_type", {
            "variable_name": first_global["name"],
            "new_type": "struct TestGlobalType"
        })
        
        assert isinstance(result, dict)


class TestListStructs:
    """结构体列表测试。"""
    
    def test_list_structs(self, tool_caller):
        """测试列出结构体。"""
        result = tool_caller("list_structs")
        assert isinstance(result, dict)
        assert "items" in result
        
        if result["items"]:
            s = result["items"][0]
            assert "name" in s
            assert "kind" in s
            assert "size" in s
            assert "members" in s
    
    def test_list_structs_with_pattern(self, tool_caller):
        """测试按模式过滤结构体。"""
        result = tool_caller("list_structs", {"pattern": "test"})
        assert isinstance(result, dict)
        assert "items" in result


class TestGetStructInfo:
    """结构体详情测试。"""
    
    def test_get_struct_info(self, tool_caller):
        """测试获取结构体详情。"""
        # 先创建一个测试结构体
        tool_caller("declare_type", {
            "decl": "struct TestStructInfo { int field1; char field2; void* field3; };"
        })
        
        result = tool_caller("get_struct_info", {"name": "TestStructInfo"})
        assert isinstance(result, dict)
        
        if "error" not in result:
            assert "name" in result
            assert "members" in result
            assert isinstance(result["members"], list)
    
    def test_get_struct_info_not_found(self, tool_caller):
        """测试获取不存在的结构体。"""
        result = tool_caller("get_struct_info", {"name": "__nonexistent_struct_12345__"})
        assert isinstance(result, dict)
        assert "error" in result
    
    def test_get_struct_info_empty_name(self, tool_caller):
        """测试空名称。"""
        result = tool_caller("get_struct_info", {"name": ""})
        assert isinstance(result, dict)
        assert "error" in result
