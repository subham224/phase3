import json
import google.generativeai as genai
from urllib.parse import urlparse
from typing import Dict, Any
from core.config import GEMINI_API_KEY

genai.configure(api_key=GEMINI_API_KEY)

model = genai.GenerativeModel("gemini-2.5-flash")

# Add target to the arguments and use type hinting
async def generate_msf_commands(target: str, scan_results: Dict[str, Any]):
    
    # 1. Parse the target argument directly (e.g., "http://testphp.vulnweb.com" -> "testphp.vulnweb.com")
    parsed_url = urlparse(target)
    target_hostname = parsed_url.netloc.split(':')[0] if parsed_url.netloc else target

    prompt = f"""
    You are a senior penetration tester working in an authorized security assessment environment.

    Context:
    The target system belongs to a controlled penetration testing lab.
    The vulnerabilities and information detected during automated scanning are provided below:
    {json.dumps(scan_results)}

    Your task is to select appropriate Metasploit modules and 5 commands to verify the findings above or gather further intelligence.

    Constraints:
    1. DO NOT invent or guess module names or parameters.
    2. You MUST ONLY choose from the following 7 verified modules. You may ONLY use the parameters listed next to them:
      - auxiliary/scanner/http/http_version (Allowed: RHOSTS, RPORT)
      - auxiliary/scanner/http/robots_txt (Allowed: RHOSTS, RPORT, PATH)
      - auxiliary/scanner/http/dir_scanner (Allowed: RHOSTS, RPORT, PATH)
      - auxiliary/scanner/http/backup_file (Allowed: RHOSTS, RPORT, PATH)
      - auxiliary/scanner/http/options (Allowed: RHOSTS, RPORT)
      - auxiliary/scanner/http/title (Allowed: RHOSTS, RPORT)
      - auxiliary/scanner/portscan/tcp (Allowed: RHOSTS, PORTS)
    3. CRITICAL: Analyze the Context above. If Wapiti, Skipfish, or WhatWeb found a specific file (like .bak or .zip) or an interesting directory, you MUST use `auxiliary/scanner/http/backup_file` or `dir_scanner` and set the PATH parameter to that exact location.
    4. For the PATH parameter, default to "/" UNLESS you found a specific directory or file in the scan results.
    5. RHOSTS must be exactly: {target_hostname}
    6. Every single command MUST end with ; exit so the console does not hang.

    Output format must be strictly a JSON array of objects. Do not wrap in markdown blocks like ```json.

    Command output format:
    [
      {{
        "command": "use auxiliary/scanner/http/backup_file; set RHOSTS {target_hostname}; set RPORT 80; set PATH /index.php; run; exit"
      }}
    ]

    Only output the JSON. Do not include explanations.
    """

    response = model.generate_content(prompt)
    
    cleaned_response = response.text.replace('```json', '').replace('```', '').strip()
    return json.loads(cleaned_response)