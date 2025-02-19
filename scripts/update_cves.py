import os
import sys
from pathlib import Path

# 添加backend目录到Python路径
sys.path.append(str(Path(__file__).parent.parent / 'backend'))

from cve_crawler import CVECrawler
from deepseek_analyzer import VulnerabilityAnalyzer

def main():
    # 初始化爬虫
    crawler = CVECrawler()
    
    # 初始化分析器
    analyzer = VulnerabilityAnalyzer(os.getenv('OPENAI_API_KEY'))
    
    # 获取最新CVE
    cves = crawler.fetch_latest_cves(days_back=7)
    
    # 为每个CVE生成修复建议
    for cve in cves:
        if not cve.get('remediation'):
            try:
                remediation = analyzer.generate_remediation(cve)
                cve['remediation'] = remediation
            except Exception as e:
                print(f"Error generating remediation for {cve['id']}: {e}")
                cve['remediation'] = "暂无修复建议"
    
    # 保存更新后的数据
    crawler._save_cves(cves)

if __name__ == '__main__':
    main() 