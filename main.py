#!/usr/bin/env python3
"""
MD文档转Nuclei Template工具
将漏洞复现文档批量转换为Nuclei YAML模板
"""
import os
import sys
import argparse
import subprocess
from pathlib import Path
from typing import List, Tuple, Optional
from concurrent.futures import ThreadPoolExecutor, as_completed

from md_parser import MDParser, get_category_from_path
from md_parser import VulnerabilityInfo
from nuclei_generator import NucleiGenerator


class MD2NucleiConverter:
    """MD到Nuclei模板转换器"""

    def __init__(self, input_dir: str, output_dir: str, quiet: bool = False):
        self.input_dir = Path(input_dir)
        self.output_dir = Path(output_dir)
        self.quiet = quiet
        self.md_parser = MDParser()
        self.nuclei_generator = NucleiGenerator()

        # 统计信息
        self.total_files = 0
        self.success_count = 0
        self.fail_count = 0
        self.failed_files: List[Tuple[str, str]] = []  # (文件名, 失败原因)

    def find_md_files(self) -> List[Path]:
        """查找所有MD文件"""
        md_files = list(self.input_dir.rglob("*.md"))
        # 过滤掉index.md
        md_files = [f for f in md_files if f.name != "index.md"]
        return md_files

    def convert_single_file(self, md_file: str, output_file: Optional[str] = None) -> Tuple[bool, str]:
        """转换单个MD文件"""
        md_path = Path(md_file)
        if not md_path.exists():
            return False, f"File not found: {md_file}"

        try:
            category = get_category_from_path(str(md_path))
            vuln_info = self.md_parser.parse(str(md_path), category)

            if not vuln_info.http_requests:
                return False, "No HTTP requests found in document"

            template = self.nuclei_generator.generate(vuln_info)
            if not template:
                return False, "Failed to generate template"

            yaml_content = self.nuclei_generator.to_yaml(template)

            if output_file:
                out_path = Path(output_file)
            else:
                out_path = md_path.with_suffix('.yaml')

            out_path.parent.mkdir(parents=True, exist_ok=True)

            with open(out_path, 'w', encoding='utf-8') as f:
                f.write(yaml_content)

            return True, str(out_path)

        except Exception as e:
            return False, f"Error: {str(e)}"

    def convert_file(self, md_file: Path) -> Tuple[bool, str, str]:
        """转换单个MD文件（批量处理用）
        返回: (是否成功, 消息, 完整路径)
        """
        try:
            category = get_category_from_path(str(md_file))
            vuln_info = self.md_parser.parse(str(md_file), category)

            if not vuln_info.http_requests:
                return False, f"No HTTP requests found", str(md_file)

            template = self.nuclei_generator.generate(vuln_info)
            if not template:
                return False, f"Failed to generate template", str(md_file)

            yaml_content = self.nuclei_generator.to_yaml(template)

            relative_path = md_file.relative_to(self.input_dir)
            output_subdir = self.output_dir / relative_path.parent
            output_subdir.mkdir(parents=True, exist_ok=True)

            output_file = output_subdir / f"{md_file.stem}.yaml"

            with open(output_file, 'w', encoding='utf-8') as f:
                f.write(yaml_content)

            return True, str(output_file), str(md_file)

        except Exception as e:
            return False, f"Error: {str(e)}", str(md_file)

    def convert_all(self, workers: int = 4) -> None:
        """批量转换所有MD文件"""
        md_files = self.find_md_files()
        self.total_files = len(md_files)

        if not self.quiet:
            print(f"[+] Found {self.total_files} markdown files to convert")
            print(f"[+] Output directory: {self.output_dir}")
            print(f"[+] Using {workers} workers")
            print("-" * 60)

        self.output_dir.mkdir(parents=True, exist_ok=True)

        with ThreadPoolExecutor(max_workers=workers) as executor:
            futures = {executor.submit(self.convert_file, md_file): md_file
                       for md_file in md_files}

            for future in as_completed(futures):
                md_file = futures[future]
                success, message, full_path = future.result()

                if success:
                    self.success_count += 1
                    if not self.quiet:
                        print(f"[OK] {md_file.name}")
                else:
                    self.fail_count += 1
                    self.failed_files.append((full_path, message))
                    if not self.quiet:
                        print(f"[FAIL] {md_file.name}: {message}")

        self._print_summary()
        self._generate_failed_report()

    def _print_summary(self) -> None:
        """打印转换统计"""
        if self.quiet:
            return

        print("\n" + "=" * 60)
        print("Conversion Summary")
        print("=" * 60)
        print(f"Total files:    {self.total_files}")
        print(f"Success:        {self.success_count}")
        print(f"Failed:         {self.fail_count}")
        if self.total_files > 0:
            print(f"Success rate:   {self.success_count/self.total_files*100:.1f}%")

        if self.failed_files:
            print(f"\nFailed files: {len(self.failed_files)}")
            print(f"See: {self.output_dir / 'failed_conversion_report.md'}")

    def _generate_failed_report(self) -> None:
        """生成失败报告"""
        if not self.failed_files:
            return

        report_path = self.output_dir / 'failed_conversion_report.md'

        # 按失败原因分类
        reason_categories = {}
        for file_path, reason in self.failed_files:
            if reason not in reason_categories:
                reason_categories[reason] = []
            reason_categories[reason].append(file_path)

        # 生成报告内容
        content = f"""# MD文档转换失败报告

## 统计信息

- **总文件数**: {self.total_files}
- **成功转换**: {self.success_count}
- **转换失败**: {self.fail_count}
- **成功率**: {self.success_count/self.total_files*100:.1f}%

---

## 失败原因分类

"""

        for reason, files in sorted(reason_categories.items(), key=lambda x: -len(x[1])):
            content += f"### {reason} ({len(files)} 个文件)\n\n"
            for f in files:
                content += f"- `{f}`\n"
            content += "\n"

        content += """---

## 说明

转换失败的常见原因：

1. **No HTTP requests found**: 文档中没有标准的HTTP请求格式（如操作系统漏洞、默认口令类漏洞）
2. **Failed to generate template**: 无法生成有效的Nuclei模板
3. **Error**: 处理过程中发生错误

对于这些文件，建议手动编写Nuclei模板或检查文档格式。

---

*Generated by md2nuclei converter*
"""

        with open(report_path, 'w', encoding='utf-8') as f:
            f.write(content)

        if not self.quiet:
            print(f"\n[+] Failed report generated: {report_path}")


def validate_template(yaml_file: str) -> Tuple[bool, str]:
    """验证Nuclei模板（需要安装nuclei）"""
    try:
        result = subprocess.run(
            ['nuclei', '-template', yaml_file, '-validate'],
            capture_output=True,
            text=True,
            timeout=30
        )
        if result.returncode == 0:
            return True, "Valid"
        else:
            return False, result.stderr.strip() or result.stdout.strip()
    except FileNotFoundError:
        return False, "nuclei command not found, please install nuclei"
    except subprocess.TimeoutExpired:
        return False, "Validation timeout"
    except Exception as e:
        return False, str(e)


def main():
    parser = argparse.ArgumentParser(
        description='Convert vulnerability markdown documents to Nuclei templates',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Batch convert directory
  python main.py -i /path/to/md/docs -o /path/to/output

  # Convert single file
  python main.py -f /path/to/vuln.md -o /path/to/output.yaml

  # Validate generated template
  python main.py -f /path/to/vuln.md -o /path/to/output.yaml --validate

  # Batch convert with more workers
  python main.py -i ./vuln-docs -o ./nuclei-templates -w 8
        """
    )

    # 输入选项（二选一）
    input_group = parser.add_mutually_exclusive_group(required=True)
    input_group.add_argument('-i', '--input-dir',
                             help='Input directory containing markdown files')
    input_group.add_argument('-f', '--file',
                             help='Single markdown file to convert')

    # 输出选项
    parser.add_argument('-o', '--output', required=True,
                        help='Output directory (batch) or file (single)')

    # 其他选项
    parser.add_argument('-w', '--workers', type=int, default=4,
                        help='Number of worker threads (default: 4)')
    parser.add_argument('-q', '--quiet', action='store_true',
                        help='Quiet mode, suppress output')
    parser.add_argument('--validate', action='store_true',
                        help='Validate generated template with nuclei')

    args = parser.parse_args()

    # 单文件模式
    if args.file:
        converter = MD2NucleiConverter("", "", args.quiet)
        success, message = converter.convert_single_file(args.file, args.output)

        if success:
            if not args.quiet:
                print(f"[+] Successfully converted: {args.file}")
                print(f"[+] Output: {message}")

            if args.validate:
                valid, validation_msg = validate_template(message)
                if valid:
                    print("[+] Template validation: PASSED")
                else:
                    print(f"[-] Template validation: FAILED - {validation_msg}")

            sys.exit(0)
        else:
            print(f"[-] Conversion failed: {message}")
            sys.exit(1)

    # 批量转换模式
    if not os.path.isdir(args.input_dir):
        print(f"Error: Input directory does not exist: {args.input_dir}")
        sys.exit(1)

    converter = MD2NucleiConverter(args.input_dir, args.output, args.quiet)
    converter.convert_all(args.workers)

    # 批量验证
    if args.validate:
        print("\n[+] Validating templates...")
        output_path = Path(args.output)
        yaml_files = list(output_path.rglob("*.yaml"))
        valid_count = 0
        invalid_count = 0

        for yaml_file in yaml_files:
            valid, msg = validate_template(str(yaml_file))
            if valid:
                valid_count += 1
            else:
                invalid_count += 1
                print(f"  [INVALID] {yaml_file.name}: {msg}")

        print(f"\n[+] Validation complete: {valid_count} valid, {invalid_count} invalid")


if __name__ == "__main__":
    main()