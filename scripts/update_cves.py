import os
import sys
from pathlib import Path

# 获取项目根目录
ROOT_DIR = Path(__file__).parent.parent.absolute()
sys.path.insert(0, str(ROOT_DIR))
print(ROOT_DIR)

from backend.cve_crawler import CVECrawler
from backend.deepseek_analyzer import DeepSeekAnalyzer

def main():
    # 初始化爬虫
    crawler = CVECrawler()
    
    # 初始化分析器
    analyzer = DeepSeekAnalyzer()
    
    # 获取最新的CVE
    cves = crawler.fetch_latest_cves(days_back=7)
    
    # 使用DeepSeek分析并添加修复建议
    enriched_cves = [analyzer.enrich_cve_data(cve) for cve in cves]
    
    # 保存更新后的数据
    crawler._save_cves(enriched_cves)

if __name__ == '__main__':
    main() 