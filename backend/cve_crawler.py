import requests
import json
from datetime import datetime, timedelta, timezone
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
        self.max_workers = 20  # 并发线程数
        self.headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        }
        
    def fetch_cve_details(self, year: int, cve_id: str, github_link: str = None) -> Dict[str, Any]:
        """获取单个CVE的详细信息"""
        try:
            # 添加 0.1 秒延迟
            time.sleep(0.1)
            
            # 使用提供的 github_link
            if github_link:
                url = github_link
            else:
                prefix = cve_id.split('-')[2][:5] + "xxx"
                url = f"{self.base_url}/{year}/{prefix}/{cve_id}.json"
            
            self.logger.info(f"Fetching CVE details from {url}")
            
            headers = {
                'Accept': 'application/json',
                'User-Agent': 'CVE-Monitor-Bot'
            }
            if 'GITHUB_TOKEN' in os.environ:
                headers['Authorization'] = f"Bearer {os.environ['GITHUB_TOKEN']}"
            
            response = requests.get(url, headers=headers)
            if response.status_code == 200:
                try:
                    data = response.json()
                    # 打印原始数据以便调试
                    self.logger.debug(f"Raw CVE data: {json.dumps(data, indent=2)}")
                    
                    # 检查数据结构
                    if 'cveMetadata' not in data:
                        self.logger.error(f"Invalid data structure for {cve_id}: missing 'cveMetadata'")
                        return None
                    
                    # 从 cveMetadata 中获取数据
                    cve_metadata = data['cveMetadata']
                    if 'cveId' not in cve_metadata:
                        self.logger.error(f"Missing cveId in data for URL: {url}")
                        return None
                    
                    parsed_data = self._parse_cve_data(data)
                    if parsed_data:
                        self.logger.info(f"Successfully fetched and parsed CVE {cve_id}")
                        return parsed_data
                    else:
                        self.logger.error(f"Failed to parse CVE data for {cve_id}")
                        return None
                except json.JSONDecodeError as e:
                    self.logger.error(f"Failed to parse JSON for CVE {cve_id}: {e}")
                    return None
            
            self.logger.error(f"Failed to fetch CVE {cve_id} from {url}: Status code {response.status_code}")
            return None
        except Exception as e:
            self.logger.error(f"Error fetching CVE {cve_id}: {e}")
            return None

    def _parse_cve_data(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """解析CVE数据为标准格式"""
        try:
            # 从 cveMetadata 中获取数据
            cve_metadata = data.get('cveMetadata', {})
            parsed_data = {
                'id': cve_metadata.get('cveId', ''),
                'publishedDate': cve_metadata.get('datePublished', ''),
                'lastModifiedDate': cve_metadata.get('dateUpdated', ''),
                'description': '',  # 默认空描述
                'severity': 'N/A',  # 默认严重性
                'references': [
                    {
                        'url': cve_metadata.get('cveOrgLink', ''),
                        'type': 'reference'
                    },
                    {
                        'url': cve_metadata.get('githubLink', ''),
                        'type': 'reference'
                    }
                ],
                'affected': [],
                'problemType': []
            }
            
            # 检查日期字段
            if not parsed_data['publishedDate']:
                self.logger.warning(f"No published date found for CVE {parsed_data['id']}, using current time")
                parsed_data['publishedDate'] = datetime.now(timezone.utc).isoformat()
            
            # 验证日期格式
            try:
                datetime.fromisoformat(parsed_data['publishedDate'].replace('Z', '+00:00'))
            except ValueError as e:
                self.logger.error(f"Invalid published date format for CVE {parsed_data['id']}: {e}")
                return None
            
            # 如果有 CVE 详情数据，则更新这些字段
            if 'containers' in data:
                cna = data.get('containers', {}).get('cna', {})
                if cna:
                    parsed_data.update({
                        'description': cna.get('descriptions', [{}])[0].get('value', ''),
                        'severity': self._get_severity(cna),
                        'references': self._get_references(cna),
                        'affected': cna.get('affected', []),
                        'problemType': self._get_problem_type(cna)
                    })
            
            # 验证必要字段
            if not parsed_data['id']:
                self.logger.error("Missing CVE ID in data")
                return None
            
            # 检查解析后的数据是否有效
            if not parsed_data['description']:
                self.logger.warning(f"No description found for CVE {parsed_data['id']}")
            
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
        all_cves = []
        cutoff_date = datetime.now(timezone.utc) - timedelta(days=days_back)

        if not os.path.exists(self.data_dir):
            os.makedirs(self.data_dir)
            self.logger.info(f"Created data directory: {self.data_dir}")

        try:
            # 首先获取 delta.json
            delta_url = "https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/delta.json"
            headers = {
                'Accept': 'application/json',
                'User-Agent': 'CVE-Monitor-Bot'
            }
            if 'GITHUB_TOKEN' in os.environ:
                headers['Authorization'] = f"Bearer {os.environ['GITHUB_TOKEN']}"
                self.logger.info("Using GitHub token for authentication")
            
            self.logger.info(f"Fetching delta.json from {delta_url}")
            response = requests.get(delta_url, headers=headers)
            self.logger.info(f"Delta.json response status: {response.status_code}")
            
            if response.status_code == 200:
                delta_data = response.json()
                self.logger.info(f"Delta.json content: {json.dumps(delta_data, indent=2)}")
                
                # 收集所有需要获取的 CVE
                cve_list = []
                
                # 处理新增的 CVE
                new_cves = delta_data.get('new', [])
                self.logger.info(f"Found {len(new_cves)} new CVEs")
                for cve in new_cves:
                    cve_list.append((cve['cveId'], cve['githubLink']))
                
                # 处理更新的 CVE
                updated_cves = delta_data.get('updated', [])
                self.logger.info(f"Found {len(updated_cves)} updated CVEs")
                for cve in updated_cves:
                    cve_list.append((cve['cveId'], cve['githubLink']))
                
                self.logger.info(f"Total CVEs to process: {len(cve_list)}")
                
                # 使用线程池获取 CVE 详情
                with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
                    future_to_cve = {}
                    
                    for cve_id, github_link in cve_list:
                        year = int(cve_id.split('-')[1])
                        self.logger.info(f"Submitting {cve_id} for processing")
                        future = executor.submit(self.fetch_cve_details, year, cve_id, github_link)
                        future_to_cve[future] = cve_id

                    for future in as_completed(future_to_cve):
                        cve_id = future_to_cve[future]
                        try:
                            cve_data = future.result()
                            if cve_data:
                                # 确保 publishedDate 是带时区的
                                published_date = datetime.fromisoformat(
                                    cve_data['publishedDate'].replace('Z', '+00:00')
                                ).astimezone(timezone.utc)
                                if published_date >= cutoff_date:
                                    all_cves.append(cve_data)
                                    self.logger.info(f"Added CVE {cve_id} to results")
                                else:
                                    self.logger.info(f"Skipped CVE {cve_id} due to old publish date")
                            else:
                                self.logger.error(f"Failed to process CVE {cve_id}: No data returned")
                        except Exception as e:
                            self.logger.error(f"Error processing CVE {cve_id}: {e}")

            else:
                self.logger.error(f"Failed to fetch delta.json: {response.text}")

        except Exception as e:
            self.logger.error(f"Error fetching delta.json: {e}")

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
            "dataType": "CVE_RECORD",
            "dataVersion": "5.1",
            "cveMetadata": {
                "total_count": len(cves),
                "last_updated": datetime.now().isoformat(),
                "severity_distribution": self._get_severity_distribution(cves)
            },
            "cves": cves
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