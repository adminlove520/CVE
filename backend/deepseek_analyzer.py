from openai import OpenAI

class VulnerabilityAnalyzer:
    def __init__(self, api_key):
        self.client = OpenAI(api_key=api_key)
        
    def generate_remediation(self, cve_data):
        """使用Deepseek生成修复建议"""
        prompt = f"""
        基于以下CVE信息生成详细的修复建议：
        
        CVE ID: {cve_data['cveId']}
        描述: {cve_data['description']}
        
        请提供具体的修复步骤和最佳实践建议。
        """
        
        response = self.client.chat.completions.create(
            model="deepseek-chat",
            messages=[{"role": "user", "content": prompt}]
        )
        
        return response.choices[0].message.content 