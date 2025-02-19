import os
import sys
from pathlib import Path
import argparse

# 获取项目根目录
ROOT_DIR = Path(__file__).parent.parent.absolute()
sys.path.insert(0, str(ROOT_DIR))
print(ROOT_DIR)

from backend.cve_crawler import CVECrawler
from backend.deepseek_analyzer import DeepSeekAnalyzer

def main():
    parser = argparse.ArgumentParser(description='更新 CVE 数据')
    parser.add_argument('--days', type=int, default=7,
                       help='获取最近几天的数据（默认：7天）')
    parser.add_argument('--min-severity', type=float, default=0.0,
                       help='最低严重性分数（默认：0.0）')
    parser.add_argument('--has-poc', action='store_true',
                       help='只获取有 PoC 的 CVE')
    parser.add_argument('--keywords', type=str, nargs='+',
                       help='按关键词过滤（可多个）')
    
    args = parser.parse_args()
    
    # 初始化爬虫
    crawler = CVECrawler()
    
    # 初始化分析器
    analyzer = DeepSeekAnalyzer()
    
    # 获取最新的CVE
    cves = crawler.fetch_latest_cves(days_back=args.days)
    
    # 应用过滤条件
    if args.min_severity > 0 or args.has_poc or args.keywords:
        cves = crawler.filter_cves(
            cves,
            min_severity=args.min_severity,
            has_poc=args.has_poc,
            keywords=args.keywords
        )
    
    # 使用DeepSeek分析并添加修复建议
    enriched_cves = [analyzer.enrich_cve_data(cve) for cve in cves]
    
    # 保存更新后的数据
    crawler._save_cves(enriched_cves)

if __name__ == '__main__':
    main() 