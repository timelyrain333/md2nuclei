"""
HTTP请求解析模块
用于解析原始HTTP请求，提取方法、路径、headers、body等
"""
import re
from dataclasses import dataclass, field
from typing import Dict, Optional


@dataclass
class HTTPRequest:
    """HTTP请求数据结构"""
    method: str = "GET"
    path: str = "/"
    headers: Dict[str, str] = field(default_factory=dict)
    body: str = ""
    raw_request: str = ""


class HTTPParser:
    """HTTP请求解析器"""

    def parse(self, raw_request: str) -> HTTPRequest:
        """解析原始HTTP请求"""
        request = HTTPRequest()
        request.raw_request = raw_request

        # 标准化换行符
        raw_request = raw_request.replace('\r\n', '\n').strip()
        lines = raw_request.split('\n')

        if not lines:
            return request

        # 解析请求行
        request_line = lines[0].strip()
        method, path = self._parse_request_line(request_line)
        request.method = method
        request.path = path

        # 分离headers和body
        header_lines = []
        body_lines = []
        in_body = False
        body_start_index = 0

        for i, line in enumerate(lines[1:], 1):
            if in_body:
                body_lines.append(line)
            elif line.strip() == "":
                # 空行标记headers结束
                in_body = True
                body_start_index = i + 1
            else:
                header_lines.append(line)

        # 解析headers
        request.headers = self._parse_headers(header_lines)

        # 解析body
        if body_lines:
            request.body = '\n'.join(body_lines).strip()

        return request

    def _parse_request_line(self, line: str) -> tuple:
        """解析请求行"""
        parts = line.split(' ')
        method = parts[0].upper() if parts else "GET"

        # 提取路径（第二个部分，忽略HTTP版本）
        path = "/"
        if len(parts) >= 2:
            path = parts[1]
            # 移除可能的HTTP版本信息
            if path.startswith('HTTP/'):
                path = "/"

        return method, path

    def _parse_headers(self, header_lines: list) -> Dict[str, str]:
        """解析HTTP headers"""
        headers = {}
        for line in header_lines:
            if ':' in line:
                key, value = line.split(':', 1)
                headers[key.strip()] = value.strip()
        return headers

    def get_content_type(self, headers: Dict[str, str]) -> Optional[str]:
        """获取Content-Type"""
        content_type = headers.get('Content-Type', headers.get('content-type', ''))
        if content_type:
            # 提取主类型
            return content_type.split(';')[0].strip().lower()
        return None

    def is_json_body(self, headers: Dict[str, str], body: str) -> bool:
        """判断body是否是JSON格式"""
        content_type = self.get_content_type(headers)
        if content_type == 'application/json':
            return True
        # 尝试解析JSON
        body = body.strip()
        if body.startswith('{') or body.startswith('['):
            return True
        return False