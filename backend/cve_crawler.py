import requests
import json
from datetime import datetime, timedelta
import os
import logging
from typing import List, Dict, Any
import time

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class CVECrawler:
    def __init__(self):
        self.base_url = "https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves"
        self.data_dir = "data"
        
    def fetch_cve_details(self, year: int, cve_id: str) -> Dict[str, Any]:
        """获取单个CVE的详细信息"""
        try:
            # 添加 0.1 秒延迟
            time.sleep(0.1)
            prefix = cve_id.split('-')[2][:5] + "xxx"
            url = f"{self.base_url}/{year}/{prefix}/{cve_id}.json"
            response = requests.get(url)
            if response.status_code == 200:
                data = response.json()
                return self._parse_cve_data(data)
        except Exception as e:
            logger.error(f"Error fetching CVE {cve_id}: {e}")
        return None

    def _parse_cve_data(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """解析CVE数据为标准格式"""
        try:
            containers = data.get('containers', {})
            cna = containers.get('cna', {})
            
            return {
                'id': data.get('cveId'),
                'publishedDate': data.get('datePublished', ''),
                'lastModifiedDate': data.get('dateUpdated', ''),
                'description': cna.get('descriptions', [{}])[0].get('value', ''),
                'severity': self._get_severity(cna),
                'references': self._get_references(cna),
                'affected': cna.get('affected', []),
                'problemType': self._get_problem_type(cna)
            }
        except Exception as e:
            logger.error(f"Error parsing CVE data: {e}")
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

    def fetch_latest_cves(self, days_back: int = 7) -> List[Dict[str, Any]]:
        """获取最近几天的CVE数据"""
        current_year = datetime.now().year
        cves = []
        
        if not os.path.exists(self.data_dir):
            os.makedirs(self.data_dir)
            
        cutoff_date = datetime.now() - timedelta(days=days_back)
        
        for year in [current_year, current_year-1]:
            logger.info(f"Fetching CVEs for year {year}")
            
            # 获取年份目录下的所有CVE
            for i in range(0, 99999, 1000):
                prefix = f"{i:05d}xxx"
                try:
                    # 获取目录列表
                    response = requests.get(f"{self.base_url}/{year}/{prefix}")
                    if response.status_code == 200:
                        # 解析目录内容获取CVE ID列表
                        cve_ids = self._parse_directory_listing(response.text)
                        
                        for cve_id in cve_ids:
                            cve_data = self.fetch_cve_details(year, cve_id)
                            if cve_data:
                                published_date = datetime.fromisoformat(
                                    cve_data['publishedDate'].replace('Z', '+00:00')
                                )
                                if published_date >= cutoff_date:
                                    cves.append(cve_data)
                
                except Exception as e:
                    logger.error(f"Error processing prefix {prefix}: {e}")
                    continue
                
        # 保存结果
        self._save_cves(cves)
        return cves

    def _parse_directory_listing(self, content: str) -> List[str]:
        """解析目录列表内容获取CVE ID列表"""
        # 这里需要根据实际的目录列表格式进行解析
        # 示例实现
        cve_ids = []
        for line in content.split('\n'):
            if line.strip().endswith('.json'):
                cve_id = line.strip().replace('.json', '')
                if cve_id.startswith('CVE-'):
                    cve_ids.append(cve_id)
        return cve_ids

    def _save_cves(self, cves: List[Dict[str, Any]]) -> None:
        """保存CVE数据到文件"""
        output_file = os.path.join(self.data_dir, 'cves.json')
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(cves, f, ensure_ascii=False, indent=2) 