"""
MD文档解析模块
用于解析漏洞复现文档，提取关键信息
"""
import re
from dataclasses import dataclass, field
from typing import Optional, List, Dict


@dataclass
class VulnerabilityInfo:
    """漏洞信息数据结构"""
    title: str = ""
    description: str = ""
    affected_versions: List[str] = field(default_factory=list)
    fofa_query: str = ""
    http_requests: List[str] = field(default_factory=list)  # 原始HTTP请求
    source_file: str = ""
    category: str = ""  # 文档分类（如OA、EDU等）


class MDParser:
    """Markdown文档解析器"""

    def __init__(self):
        # 匹配各部分的正则表达式
        self.section_patterns = {
            'description': r'#\s*一\s*[,、]?\s*漏洞简介\s*\n([\s\S]*?)(?=#\s*二|\n#|\Z)',
            'affected_versions': r'#\s*二\s*[,、]?\s*影响版本\s*\n([\s\S]*?)(?=#\s*三|\n#|\Z)',
            'fofa': r'#\s*三\s*[,、]?\s*资产测绘\s*\n([\s\S]*?)(?=#\s*四|\n#|\Z)',
            'poc': r'#\s*四\s*[,、]?\s*漏洞复现\s*\n([\s\S]*?)(?=>\s*更新|\n#\s*五|\Z)',
        }

    def parse(self, file_path: str, category: str = "") -> VulnerabilityInfo:
        """解析MD文件"""
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()

        info = VulnerabilityInfo()
        info.source_file = file_path
        info.category = category

        # 提取标题
        title_match = re.search(r'^#\s+(.+?)(?:\n|$)', content, re.MULTILINE)
        if title_match:
            info.title = title_match.group(1).strip()

        # 提取描述
        desc_match = re.search(self.section_patterns['description'], content)
        if desc_match:
            info.description = self._clean_text(desc_match.group(1))

        # 提取影响版本
        version_match = re.search(self.section_patterns['affected_versions'], content)
        if version_match:
            version_text = version_match.group(1)
            # 提取版本列表
            versions = re.findall(r'[*\-]\s*(.+?)(?:\n|$)', version_text, re.MULTILINE)
            info.affected_versions = [v.strip() for v in versions if v.strip()]

        # 提取FOFA查询
        fofa_match = re.search(self.section_patterns['fofa'], content)
        if fofa_match:
            fofa_text = fofa_match.group(1)
            # 匹配 fofa`...` 或 fofa: ...
            fofa_queries = re.findall(r'fofa[`:]\s*`?([^`\n]+)`?', fofa_text, re.IGNORECASE)
            if fofa_queries:
                info.fofa_query = fofa_queries[0].strip().strip('`')

        # 提取HTTP请求
        poc_match = re.search(self.section_patterns['poc'], content)
        if poc_match:
            poc_text = poc_match.group(1)
            info.http_requests = self._extract_http_requests(poc_text)

        return info

    def _clean_text(self, text: str) -> str:
        """清理文本，移除多余的空白和换行"""
        # 移除图片引用
        text = re.sub(r'!\[.*?\]\(.*?\)', '', text)
        # 移除多余空白
        text = re.sub(r'\s+', ' ', text)
        return text.strip()

    def _extract_http_requests(self, text: str) -> List[str]:
        """从文本中提取HTTP请求"""
        requests = []

        # 匹配代码块中的内容
        code_blocks = re.findall(r'```(?:bash|java|plain|http)?\s*\n([\s\S]*?)\n```', text)

        for block in code_blocks:
            # 检查是否是HTTP请求（以HTTP方法或包含Host头）
            if self._is_http_request(block):
                requests.append(block.strip())

        return requests

    def _is_http_request(self, text: str) -> bool:
        """判断文本是否是HTTP请求"""
        http_methods = ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'HEAD', 'OPTIONS']
        first_line = text.strip().split('\n')[0] if text.strip() else ""

        # 检查是否以HTTP方法开头
        if any(first_line.upper().startswith(method) for method in http_methods):
            return True

        # 检查是否包含Host头
        if re.search(r'^Host:\s*', text, re.MULTILINE | re.IGNORECASE):
            return True

        return False


def get_category_from_path(file_path: str) -> str:
    """从文件路径提取分类"""
    parts = file_path.split('/')
    for part in parts:
        if part in ['OA', 'EDU', 'CMS', 'web应用', '中间件', '主机应用', '医疗',
                    '开发语言', '操作系统', '组件', '虚拟化服务', '设备', '邮件服务', 'AI大模型']:
            return part
    return "other"