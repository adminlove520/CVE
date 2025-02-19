import os
from typing import Dict
import requests
from backend.utils.logger import Logger

class DeepSeekAnalyzer:
    def __init__(self):
        self.api_key = os.getenv("DEEPSEEK_API_KEY")
        self.api_url = "https://api.deepseek.com/v1/chat/completions"  # 需要替换为实际的DeepSeek API地址
        self.logger = Logger("DeepSeekAnalyzer")

    def generate_fix_suggestion(self, cve_data: Dict) -> str:
        """使用DeepSeek生成修复建议"""
        try:
            description = cve_data.get('description', '')
            cve_id = cve_data.get('id', 'Unknown')
            
            self.logger.info(f"Generating fix suggestion for {cve_id}")
            
            prompt = f"""基于以下CVE漏洞描述，请提供具体的修复建议：
            
            漏洞描述：{description}
            
            请提供：
            1. 漏洞成因分析
            2. 具体修复步骤
            3. 预防措施
            """

            headers = {
                "Authorization": f"Bearer {self.api_key}",
                "Content-Type": "application/json"
            }
            
            data = {
                "model": "deepseek-chat",
                "messages": [{"role": "user", "content": prompt}]
            }

            response = requests.post(self.api_url, headers=headers, json=data)
            if response.status_code == 200:
                suggestion = response.json()['choices'][0]['message']['content']
                self.logger.info(f"Successfully generated fix suggestion for {cve_id}")
                return suggestion
            else:
                self.logger.error(f"Failed to generate fix suggestion for {cve_id}: Status code {response.status_code}")
                return "无法生成修复建议"
        except Exception as e:
            self.logger.error(f"Error generating fix suggestion for {cve_id}: {e}")
            return "生成修复建议时发生错误"

    def enrich_cve_data(self, cve_data: Dict) -> Dict:
        """扩充CVE数据，添加修复建议"""
        cve_id = cve_data.get('id', 'Unknown')
        self.logger.info(f"Enriching CVE data for {cve_id}")
        try:
            cve_data['fix_suggestion'] = self.generate_fix_suggestion(cve_data)
            return cve_data
        except Exception as e:
            self.logger.error(f"Error enriching CVE data for {cve_id}: {e}")
            cve_data['fix_suggestion'] = "处理数据时发生错误"
            return cve_data 