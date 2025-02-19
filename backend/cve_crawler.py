import requests
import json
from datetime import datetime, timedelta
import os
from typing import List, Dict, Any
import time
import sys
from pathlib import Path

# 修改导入语句
from backend.utils.logger import Logger  # 使用完整的导入路径
from bs4 import BeautifulSoup
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urljoin

ROOT_DIR = Path(__file__).parent.parent.absolute()
sys.path.insert(0, str(ROOT_DIR))

class CVECrawler:
    def __init__(self):
        self.base_url = "https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves"
        self.data_dir = "data"
        self.logger = Logger("CVECrawler")
        self.max_workers = 5  # 并发线程数
        self.headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        }
        
    def fetch_cve_details(self, year: int, cve_id: str) -> Dict[str, Any]:
        """获取单个CVE的详细信息"""
        try:
            # 添加 0.1 秒延迟
            time.sleep(0.1)
            prefix = cve_id.split('-')[2][:5] + "xxx"
            url = f"{self.base_url}/{year}/{prefix}/{cve_id}.json"
            self.logger.info(f"Fetching CVE details for {cve_id}")
            
            # 使用与目录获取相同的认证方式
            api_url = url.replace(
                'https://raw.githubusercontent.com/CVEProject/cvelistV5/main',
                'https://api.github.com/repos/CVEProject/cvelistV5/contents'
            )
            headers = {
                'Accept': 'application/vnd.github.v3+json',
                'User-Agent': 'CVE-Monitor-Bot'
            }
            if 'GITHUB_TOKEN' in os.environ:
                headers['Authorization'] = f"Bearer {os.environ['GITHUB_TOKEN']}"
            
            response = requests.get(api_url, headers=headers)
            if response.status_code == 200:
                content = response.json()
                if 'content' in content:
                    # GitHub API 返回的是 Base64 编码的内容
                    import base64
                    data = json.loads(base64.b64decode(content['content']).decode('utf-8'))
                    return self._parse_cve_data(data)
                self.logger.error(f"No content found in response for {cve_id}")
                return None
            
            self.logger.error(f"Failed to fetch CVE {cve_id}: Status code {response.status_code}")
            return None
        except Exception as e:
            self.logger.error(f"Error fetching CVE {cve_id}: {e}")
            return None

    def _parse_cve_data(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """解析CVE数据为标准格式"""
        try:
            containers = data.get('containers', {})
            cna = containers.get('cna', {})
            
            parsed_data = {
                'id': data.get('cveId'),
                'publishedDate': data.get('datePublished', ''),
                'lastModifiedDate': data.get('dateUpdated', ''),
                'description': cna.get('descriptions', [{}])[0].get('value', ''),
                'severity': self._get_severity(cna),
                'references': self._get_references(cna),
                'affected': cna.get('affected', []),
                'problemType': self._get_problem_type(cna)
            }
            self.logger.info(f"Successfully parsed CVE {parsed_data['id']}")
            return parsed_data
        except Exception as e:
            self.logger.error(f"Error parsing CVE data: {e}")
            return None

    def _get_severity(self, cna: Dict[str, Any]) -> str:
        """获取CVE严重性"""
        metrics = cna.get('metrics', [])
        for metric in metrics:
            if 'cvssV3_1' in metric:
                return metric['cvssV3_1'].get('baseScore', 'N/A')
        return 'N/A'

    def _get_references(self, cna: Dict[str, Any]) -> List[Dict[str, str]]:
        """获取CVE参考链接"""
        references = []
        for ref in cna.get('references', []):
            ref_data = {
                'url': ref.get('url', ''),
                'type': 'reference'
            }
            if 'exploit' in ref.get('tags', []):
                ref_data['type'] = 'poc'
            references.append(ref_data)
        return references

    def _get_problem_type(self, cna: Dict[str, Any]) -> List[str]:
        """获取问题类型"""
        problem_types = []
        for pt in cna.get('problemTypes', []):
            for desc in pt.get('descriptions', []):
                if desc.get('description'):
                    problem_types.append(desc['description'])
        return problem_types

    def _get_directory_content(self, url: str) -> List[str]:
        """获取目录内容"""
        try:
            self.logger.info(f"Fetching directory: {url}")
            # 使用 GitHub API
            api_url = url.replace(
                'https://raw.githubusercontent.com/CVEProject/cvelistV5/main',
                'https://api.github.com/repos/CVEProject/cvelistV5/contents'
            )
            headers = {
                'Accept': 'application/vnd.github.v3+json',
                'User-Agent': 'CVE-Monitor-Bot'
            }
            if 'GITHUB_TOKEN' in os.environ:
                headers['Authorization'] = f"Bearer {os.environ['GITHUB_TOKEN']}"
            
            response = requests.get(api_url, headers=headers)
            if response.status_code == 200:
                items = response.json()
                if isinstance(items, list):
                    return [item['name'] for item in items]
                self.logger.error(f"Unexpected response format from {url}")
                return []
            self.logger.error(f"Failed to fetch directory {url}: Status code {response.status_code}")
            return []
        except Exception as e:
            self.logger.error(f"Error fetching directory {url}: {e}")
            return []

    def fetch_latest_cves(self, days_back: int = 7) -> List[Dict[str, Any]]:
        """获取最近几天的CVE数据"""
        self.logger.info(f"Starting to fetch CVEs for the last {days_back} days")
        current_year = datetime.now().year
        all_cves = []
        cutoff_date = datetime.now() - timedelta(days=days_back)

        if not os.path.exists(self.data_dir):
            os.makedirs(self.data_dir)
            self.logger.info(f"Created data directory: {self.data_dir}")

        # 使用线程池处理CVE获取
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            future_to_cve = {}
            
            # 只获取当前年份的数据
            year_url = f"{self.base_url}/{current_year}"
            self.logger.info(f"Fetching CVEs for year: {current_year}")
            year_dirs = self._get_directory_content(year_url)
            
            for prefix_dir in year_dirs:
                if not prefix_dir.endswith('xxx'):
                    continue
                    
                prefix_url = f"{year_url}/{prefix_dir}"
                self.logger.info(f"Processing prefix directory: {prefix_url}")
                
                cve_files = self._get_directory_content(prefix_url)
                for cve_file in cve_files:
                    if not cve_file.startswith('CVE-'):
                        continue
                        
                    cve_id = cve_file.replace('.json', '')
                    future = executor.submit(self.fetch_cve_details, current_year, cve_id)
                    future_to_cve[future] = cve_id

            for future in as_completed(future_to_cve):
                cve_id = future_to_cve[future]
                try:
                    cve_data = future.result()
                    if cve_data:
                        published_date = datetime.fromisoformat(
                            cve_data['publishedDate'].replace('Z', '+00:00')
                        )
                        if published_date >= cutoff_date:
                            all_cves.append(cve_data)
                except Exception as e:
                    self.logger.error(f"Error processing CVE {cve_id}: {e}")

        # 按发布日期和严重性排序
        sorted_cves = self._sort_cves(all_cves)
        self.logger.info(f"Total CVEs collected: {len(sorted_cves)}")
        self._save_cves(sorted_cves)
        return sorted_cves

    def _sort_cves(self, cves: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """对CVE数据进行排序（按严重性和发布日期）"""
        def get_sort_key(cve):
            severity = float(cve['severity']) if cve['severity'] != 'N/A' else 0.0
            date = datetime.fromisoformat(cve['publishedDate'].replace('Z', '+00:00'))
            return (-severity, -date.timestamp())  # 负号使得排序为降序

        return sorted(cves, key=get_sort_key)

    def filter_cves(self, cves: List[Dict[str, Any]], 
                   min_severity: float = 0.0,
                   keywords: List[str] = None,
                   has_poc: bool = False) -> List[Dict[str, Any]]:
        """过滤CVE数据"""
        filtered_cves = []
        
        for cve in cves:
            severity = float(cve['severity']) if cve['severity'] != 'N/A' else 0.0
            
            # 检查严重性
            if severity < min_severity:
                continue
                
            # 检查关键词
            if keywords:
                description = cve['description'].lower()
                if not any(keyword.lower() in description for keyword in keywords):
                    continue
                    
            # 检查是否有POC
            if has_poc:
                if not any(ref['type'] == 'poc' for ref in cve['references']):
                    continue
                    
            filtered_cves.append(cve)
            
        return filtered_cves

    def _save_cves(self, cves: List[Dict[str, Any]]) -> None:
        """保存CVE数据到文件，包含元数据"""
        output_data = {
            'metadata': {
                'total_count': len(cves),
                'last_updated': datetime.now().isoformat(),
                'severity_distribution': self._get_severity_distribution(cves)
            },
            'cves': cves
        }
        
        output_file = os.path.join(self.data_dir, 'cves.json')
        try:
            with open(output_file, 'w', encoding='utf-8') as f:
                json.dump(output_data, f, ensure_ascii=False, indent=2)
            self.logger.info(f"Successfully saved {len(cves)} CVEs to {output_file}")
        except Exception as e:
            self.logger.error(f"Error saving CVEs to file: {e}")

    def _get_severity_distribution(self, cves: List[Dict[str, Any]]) -> Dict[str, int]:
        """统计严重性分布"""
        distribution = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'none': 0}
        
        for cve in cves:
            severity = float(cve['severity']) if cve['severity'] != 'N/A' else 0.0
            if severity >= 9.0:
                distribution['critical'] += 1
            elif severity >= 7.0:
                distribution['high'] += 1
            elif severity >= 4.0:
                distribution['medium'] += 1
            elif severity > 0.0:
                distribution['low'] += 1
            else:
                distribution['none'] += 1
                
        return distribution 