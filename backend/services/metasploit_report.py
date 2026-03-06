import json
import google.generativeai as genai
from core.config import GEMINI_API_KEY

genai.configure(api_key=GEMINI_API_KEY)

model = genai.GenerativeModel("gemini-1.5-flash")


async def generate_vulnerability_report(scan_results):

    prompt = f"""
Analyze these Metasploit command outputs.

{json.dumps(scan_results)}

Return JSON:

[
{{
"Vulnerability":"",
"Description":"",
"Impact":"",
"Sensitive information found":"",
"Remediation":""
}}
]

Only return JSON.
"""

    response = model.generate_content(prompt)

    return json.loads(response.text)