#!/usr/bin/env python3
"""
日志解析器测试
"""

import pytest
from pathlib import Path
from mcp_log_analyzer.log_parser import LogParser, LogEntry

def test_log_entry_creation():
    """测试LogEntry创建"""
    entry = LogEntry(
        request_time="2024-01-01 12:00:00",
        request_duration="100ms",
        attack_type="SQL",
        intercept_status="blocked",
        client_ip="192.168.1.1",
        proxy_ip="10.0.0.1",
        domain="example.com",
        url="/test",
        request_method="GET",
        referer="-",
        cache_status="miss",
        status_code="200",
        page_size="1024",
        user_agent="Mozilla/5.0",
        raw_line="test line"
    )
    
    assert entry.request_time == "2024-01-01 12:00:00"
    assert entry.attack_type == "SQL"
    assert entry.client_ip == "192.168.1.1"

def test_log_parser_initialization():
    """测试LogParser初始化"""
    parser = LogParser("test.log")
    assert parser.file_path == Path("test.log")

def test_parse_line_with_valid_data():
    """测试解析有效日志行"""
    parser = LogParser("test.log")
    line = "2024-01-01 12:00:00 100ms SQL blocked 192.168.1.1 10.0.0.1 example.com /test GET - miss 200 1024 Mozilla/5.0"
    
    entry = parser.parse_line(line)
    
    assert entry is not None
    assert entry.request_time == "2024-01-01 12:00:00"
    assert entry.attack_type == "SQL"
    assert entry.client_ip == "192.168.1.1"

def test_parse_line_with_invalid_data():
    """测试解析无效日志行"""
    parser = LogParser("test.log")
    
    # 测试空行
    assert parser.parse_line("") is None
    
    # 测试注释行
    assert parser.parse_line("# This is a comment") is None
    
    # 测试字段不足的行
    assert parser.parse_line("2024-01-01 12:00:00 100ms") is None

if __name__ == "__main__":
    pytest.main([__file__])