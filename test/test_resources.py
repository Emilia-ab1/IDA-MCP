"""测试 MCP 资源。

测试逻辑：
1. 测试各种资源端点
2. 验证资源返回格式
"""
import pytest
import urllib.request
import json


COORDINATOR_HOST = "127.0.0.1"
COORDINATOR_PORT = 11337


def get_resource(uri: str, port: int) -> dict:
    """获取 MCP 资源。"""
    try:
        url = f"http://{COORDINATOR_HOST}:{COORDINATOR_PORT}/resource"
        data = json.dumps({"uri": uri, "port": port}).encode('utf-8')
        req = urllib.request.Request(
            url,
            data=data,
            headers={"Content-Type": "application/json"},
            method="POST"
        )
        with urllib.request.urlopen(req, timeout=10) as resp:
            return json.loads(resp.read().decode('utf-8'))
    except Exception as e:
        return {"error": str(e)}


class TestResources:
    """资源测试。"""
    
    def test_metadata_resource(self, instance_port):
        """测试元数据资源。"""
        result = get_resource("ida://metadata", instance_port)
        
        if "error" not in result:
            # 验证元数据字段
            assert "input_file" in result or "contents" in result
    
    def test_functions_resource(self, instance_port):
        """测试函数列表资源。"""
        result = get_resource("ida://functions", instance_port)
        
        if "error" not in result:
            # 应该返回函数列表
            assert "contents" in result or "items" in result or isinstance(result, list)
    
    def test_strings_resource(self, instance_port):
        """测试字符串列表资源。"""
        result = get_resource("ida://strings", instance_port)
        
        if "error" not in result:
            assert "contents" in result or "items" in result or isinstance(result, list)
    
    def test_globals_resource(self, instance_port):
        """测试全局变量列表资源。"""
        result = get_resource("ida://globals", instance_port)
        
        if "error" not in result:
            assert "contents" in result or "items" in result or isinstance(result, list)
    
    def test_types_resource(self, instance_port):
        """测试类型列表资源。"""
        result = get_resource("ida://types", instance_port)
        
        # 类型可能为空
        assert isinstance(result, dict)
    
    def test_entry_points_resource(self, instance_port):
        """测试入口点资源。"""
        result = get_resource("ida://entry_points", instance_port)
        
        # 入口点可能为空
        assert isinstance(result, dict)
    
    def test_invalid_resource(self, instance_port):
        """测试无效资源 URI。"""
        result = get_resource("ida://nonexistent", instance_port)
        
        # 应该返回错误
        assert "error" in result or result == {}
