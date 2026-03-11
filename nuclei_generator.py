"""
Nuclei Template生成模块
用于将漏洞信息转换为Nuclei YAML模板
"""
import re
import yaml
import hashlib
from datetime import datetime
from typing import List, Dict, Optional
from dataclasses import dataclass, field

from md_parser import VulnerabilityInfo
from http_parser import HTTPParser, HTTPRequest


@dataclass
class NucleiTemplate:
    """Nuclei模板数据结构"""
    id: str = ""
    info: Dict = field(default_factory=dict)
    requests: List[Dict] = field(default_factory=list)


class NucleiGenerator:
    """Nuclei模板生成器"""

    # 漏洞严重程度映射
    SEVERITY_MAP = {
        'rce': 'critical',
        '远程命令执行': 'critical',
        '远程代码执行': 'critical',
        '命令执行': 'critical',
        '代码执行': 'critical',
        'sql注入': 'high',
        'sql': 'high',
        'sqli': 'high',
        '注入': 'high',
        '任意文件上传': 'high',
        '文件上传': 'high',
        '任意文件读取': 'high',
        '文件读取': 'high',
        '任意文件写入': 'high',
        '文件写入': 'high',
        'ssrf': 'high',
        'xxe': 'high',
        '未授权访问': 'high',
        '信息泄露': 'medium',
        '信息泄漏': 'medium',
        '敏感信息': 'medium',
        '目录遍历': 'medium',
        '密码重置': 'high',
        '越权': 'medium',
        'druid': 'medium',
    }

    def __init__(self):
        self.http_parser = HTTPParser()

    def generate(self, vuln_info: VulnerabilityInfo) -> Optional[NucleiTemplate]:
        """生成Nuclei模板"""
        if not vuln_info.http_requests:
            return None

        template = NucleiTemplate()

        # 生成模板ID
        template.id = self._generate_id(vuln_info)

        # 生成info部分
        template.info = self._generate_info(vuln_info)

        # 生成requests部分
        template.requests = self._generate_requests(vuln_info)

        return template

    def _generate_id(self, vuln_info: VulnerabilityInfo) -> str:
        """生成模板ID"""
        # 使用标题生成ID
        title = vuln_info.title.lower()

        # 移除特殊字符
        title = re.sub(r'[^\w\s\u4e00-\u9fff]', '', title)
        title = re.sub(r'\s+', '-', title)

        # 如果标题太长，使用hash
        if len(title) > 50:
            hash_suffix = hashlib.md5(vuln_info.title.encode()).hexdigest()[:8]
            title = title[:40] + '-' + hash_suffix

        return title.strip('-')

    def _generate_info(self, vuln_info: VulnerabilityInfo) -> Dict:
        """生成info部分"""
        # 判断严重程度
        severity = self._determine_severity(vuln_info)

        # 生成标签
        tags = self._generate_tags(vuln_info)

        info = {
            'name': vuln_info.title,
            'author': 'x_x',
            'severity': severity,
            'description': vuln_info.description[:500] if vuln_info.description else "",
            'reference': [],
            'tags': tags,
            'metadata': {
                'max-request': 1,
            }
        }

        # 添加FOFA查询
        if vuln_info.fofa_query:
            info['metadata']['fofa-query'] = vuln_info.fofa_query

        # 添加影响版本
        if vuln_info.affected_versions:
            info['metadata']['affected-product'] = vuln_info.affected_versions[0]

        return info

    def _determine_severity(self, vuln_info: VulnerabilityInfo) -> str:
        """判断漏洞严重程度"""
        title_lower = vuln_info.title.lower()
        desc_lower = vuln_info.description.lower()
        combined = title_lower + ' ' + desc_lower

        for keyword, severity in self.SEVERITY_MAP.items():
            if keyword in combined:
                return severity

        return 'medium'

    def _generate_tags(self, vuln_info: VulnerabilityInfo) -> str:
        """生成标签"""
        tags = []

        # 添加分类标签
        if vuln_info.category:
            tags.append(vuln_info.category.lower())

        # 根据标题添加标签
        title = vuln_info.title.lower()
        tag_keywords = {
            'rce': ['rce', '远程命令执行', '远程代码执行', '命令执行', '代码执行'],
            'sqli': ['sql注入', 'sqli', 'sql'],
            'lfi': ['文件读取', '任意文件读取', '目录遍历'],
            'upload': ['文件上传', '任意文件上传'],
            'info-leak': ['信息泄露', '信息泄漏', '敏感信息'],
            'unauth': ['未授权访问', '未授权'],
            'ssrf': ['ssrf'],
            'xxe': ['xxe'],
        }

        for tag, keywords in tag_keywords.items():
            for keyword in keywords:
                if keyword in title:
                    tags.append(tag)
                    break

        return ','.join(list(set(tags))) if tags else vuln_info.category.lower()

    def _generate_requests(self, vuln_info: VulnerabilityInfo) -> List[Dict]:
        """生成requests部分"""
        requests = []

        for raw_request in vuln_info.http_requests:
            http_req = self.http_parser.parse(raw_request)
            request_dict = self._build_request_dict(http_req, vuln_info)
            if request_dict:
                requests.append(request_dict)

        # 如果没有生成有效的请求，创建一个基本检测请求
        if not requests:
            requests = [self._create_basic_request(vuln_info)]

        return requests

    def _build_request_dict(self, http_req: HTTPRequest, vuln_info: VulnerabilityInfo) -> Optional[Dict]:
        """构建请求字典"""
        request = {
            'method': http_req.method,
            'path': [
                '{{BaseURL}}' + http_req.path
            ]
        }

        # 添加headers（排除Host等）
        exclude_headers = ['host', 'content-length', 'connection', 'accept-encoding',
                           'accept-language', 'accept', 'user-agent']

        headers = {}
        for key, value in http_req.headers.items():
            key_lower = key.lower()
            if key_lower not in exclude_headers:
                headers[key] = value

        if headers:
            request['headers'] = headers

        # 添加body
        if http_req.body:
            request['body'] = http_req.body

        # 添加匹配器
        request['matchers'] = self._generate_matchers(http_req, vuln_info)

        return request

    def _generate_matchers(self, http_req: HTTPRequest, vuln_info: VulnerabilityInfo) -> List[Dict]:
        """生成匹配器"""
        matchers = []

        # 根据漏洞类型生成不同的匹配器
        title = vuln_info.title.lower()

        # 状态码匹配器
        status_matcher = {
            'type': 'status',
            'status': [200, 500]
        }

        # 单词匹配器
        word_matcher = {
            'type': 'word',
            'part': 'body',
            'words': []
        }

        # 根据漏洞类型设置匹配词
        if '信息泄露' in title or '信息泄漏' in title or '敏感信息' in title:
            word_matcher['words'] = ['datasource', 'database', 'connection', 'password',
                                      'username', 'jdbc', 'mysql', 'oracle', 'success']
        elif '文件读取' in title or '任意文件读取' in title:
            word_matcher['words'] = ['root:', '[extensions]', 'etc/passwd', 'boot.ini']
        elif '未授权访问' in title:
            word_matcher['words'] = ['success', 'true', 'data', 'result', 'code']
        elif 'sql注入' in title or 'sql' in title:
            word_matcher['words'] = ['sql', 'syntax', 'mysql', 'oracle', 'error', 'query']
        elif 'rce' in title or '命令执行' in title or '代码执行' in title:
            word_matcher['words'] = ['whoami', 'root', 'admin', 'users', 'administrator']
        elif 'druid' in title:
            word_matcher['words'] = ['druid', 'datasource', 'stat']
        else:
            # 默认匹配
            word_matcher['words'] = ['success', 'true', 'code', 'data']

        # 如果有匹配词，添加到matchers
        if word_matcher['words']:
            matchers.append(word_matcher)

        matchers.append(status_matcher)

        # 设置匹配条件
        if len(matchers) > 1:
            matchers[-1]['condition'] = 'or'

        return matchers

    def _create_basic_request(self, vuln_info: VulnerabilityInfo) -> Dict:
        """创建基本的检测请求"""
        return {
            'method': 'GET',
            'path': ['{{BaseURL}}/'],
            'matchers': [
                {
                    'type': 'status',
                    'status': [200]
                }
            ]
        }

    def to_yaml(self, template: NucleiTemplate) -> str:
        """将模板转换为YAML字符串"""
        data = {
            'id': template.id,
            'info': template.info,
            'requests': template.requests
        }

        # 自定义YAML输出格式
        yaml_str = yaml.dump(data, allow_unicode=True, default_flow_style=False,
                             sort_keys=False, indent=2)

        # 添加nuclei注释
        header = "# Generated by md2nuclei converter\n"
        header += f"# Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n"

        return header + yaml_str