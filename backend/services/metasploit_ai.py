import json
import google.generativeai as genai
from core.config import GEMINI_API_KEY

genai.configure(api_key=GEMINI_API_KEY)

model = genai.GenerativeModel("gemini-1.5-flash")


async def generate_msf_commands(scan_results):

    prompt = f"""
You are a senior penetration tester.

Target: testphp.vulnweb.com

Scan Results:
{json.dumps(scan_results)}

Generate 5 safe Metasploit commands.

Output format:

[
{{"command":"use auxiliary/...; set RHOSTS target; run; exit"}}
]

Only output JSON.
"""

    response = model.generate_content(prompt)

    return json.loads(response.text)