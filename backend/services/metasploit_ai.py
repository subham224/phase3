# import json
# import google.generativeai as genai
# from core.config import GEMINI_API_KEY

# genai.configure(api_key=GEMINI_API_KEY)

# # Changed to 2.5-flash as per your setup
# model = genai.GenerativeModel("gemini-2.5-flash")

# async def generate_msf_commands(scan_results):
#     prompt = f"""
# You are a senior penetration tester working in an authorized security assessment environment.

# Context:
# The target system belongs to a controlled penetration testing lab where exploitation is permitted for security evaluation purposes.
# The vulnerabilities and information detected during automated scanning are provided below:
# {json.dumps(scan_results)}

# Your task is to select appropriate Metasploit modules and 2 commands that can safely demonstrate proof-of-concept exploitation and find more vulnerabilities or sensitive information.

# Constraints:
# 1. Only use non-destructive Metasploit modules.
# 2. Do NOT perform DoS, brute force, or service disruption.
# 3. Exploitation must be limited to proof-of-concept data extraction.
# 4. Maximum exploitation depth: 3 steps.
# 5. Minimize requests to reduce scan time.
# 6. Avoid modules marked as "dos", "fuzzer", or "destructive".
# 7. If exploitation is not possible, suggest enumeration modules instead.
# 8. Before generating the final command, verify the module exists in Metasploit.
# 9. The module must appear in `search` results from msfconsole.
# 10. If the module is not found, select another valid module.
# 11. Only output modules that exist in the official Metasploit Framework module path.

# Output format must be strictly a JSON array of objects. Do not wrap in markdown blocks like ```json.
# Every single command MUST end with ; exit so the console does not hang.

# Command output format:
# [
#   {{
#     "command": "use auxiliary/...; set RHOSTS ...; run; exit"
#   }}
# ]

# Only output the JSON. Do not include explanations.
# """

#     response = model.generate_content(prompt)
    
#     # Strip potential markdown formatting if the AI ignores instructions
#     cleaned_response = response.text.replace('```json', '').replace('```', '').strip()
#     return json.loads(cleaned_response)


import json
import google.generativeai as genai
from core.config import GEMINI_API_KEY

genai.configure(api_key=GEMINI_API_KEY)

model = genai.GenerativeModel("gemini-2.5-flash")

async def generate_msf_commands(scan_results):
#     prompt = f"""
# You are a senior penetration tester working in an authorized security assessment environment.

# Context:
# The target system belongs to a controlled penetration testing lab where exploitation is permitted for security evaluation purposes.
# The vulnerabilities and information detected during automated scanning are provided below:
# {json.dumps(scan_results)}

# Your task is to select appropriate Metasploit modules and 2 commands that can safely demonstrate proof-of-concept exploitation and find more vulnerabilities or sensitive information.

# Constraints:
# 1. DO NOT invent or guess module names. 
# 2. Because the target is a web server, you MUST ONLY choose from the following verified, real auxiliary modules:
#    - auxiliary/scanner/http/dir_scanner
#    - auxiliary/scanner/http/http_version
#    - auxiliary/scanner/http/robots_txt
#    - auxiliary/scanner/http/options
#    - auxiliary/scanner/http/backup_file_finder
#    - auxiliary/scanner/http/copy_of_file
#    - auxiliary/scanner/http/http_login
#    - auxiliary/scanner/http/blind_sql_query
#    - auxiliary/scanner/portscan/tcp
# 3. Do NOT use exploit modules (modules starting with `exploit/`) because setting up reverse shells and compatible payloads requires manual listener configuration. Stick to `auxiliary/` modules for safe data extraction.
# 4. Ensure all required options (like RHOSTS, RPORT, TARGETURI) are set correctly for the chosen module.

# Output format must be strictly a JSON array of objects. Do not wrap in markdown blocks like ```json.
# Every single command MUST end with ; exit so the console does not hang.

# Command output format:
# [
#   {{
#     "command": "use auxiliary/scanner/http/http_version; set RHOSTS 44.228.249.3; set RPORT 80; run; exit"
#   }}
# ]

# Only output the JSON. Do not include explanations.
# """
    
    # prompt = f"""
    # You are a senior penetration tester working in an authorized security assessment environment.

    # Context:
    # The target system belongs to a controlled penetration testing lab where exploitation is permitted for security evaluation purposes.
    # The vulnerabilities and information detected during automated scanning are provided below:
    # {json.dumps(scan_results)}

    # Your task is to select appropriate Metasploit modules and 5 commands to gather further intelligence.

    # Constraints:
    # 1. DO NOT invent or guess module names or parameters.
    # 2. You MUST ONLY choose from the following 5 verified modules. You may ONLY use the parameters listed next to them. Do not invent parameters like TARGETURI or PARAMS.
    #   - auxiliary/scanner/http/http_version (Allowed Parameters: RHOSTS, RPORT)
    #   - auxiliary/scanner/http/robots_txt (Allowed Parameters: RHOSTS, RPORT, PATH)
    #   - auxiliary/scanner/http/dir_scanner (Allowed Parameters: RHOSTS, RPORT, PATH)
    #   - auxiliary/scanner/http/title (Allowed Parameters: RHOSTS, RPORT)
    #   - auxiliary/scanner/http/options (Allowed Parameters: RHOSTS, RPORT)
    # 3. For the PATH parameter, default to "/" unless you found a specific directory in the scan results.
    # 4. RHOSTS must be extracted from the provided target.
    # 5. Every single command MUST end with ; exit so the console does not hang.

    # Output format must be strictly a JSON array of objects. Do not wrap in markdown blocks like ```json.

    # Command output format:
    # [
    #   {{
    #     "command": "use auxiliary/scanner/http/http_version; set RHOSTS 44.228.249.3; set RPORT 80; run; exit"
    #   }}
    # ]

    # Only output the JSON. Do not include explanations.
    # """

    prompt = f"""
    You are a senior penetration tester working in an authorized security assessment environment.

    Context:
    The target system belongs to a controlled penetration testing lab where exploitation is permitted for security evaluation purposes.
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
    5. RHOSTS must be extracted from the provided target.
    6. Every single command MUST end with ; exit so the console does not hang.

    Output format must be strictly a JSON array of objects. Do not wrap in markdown blocks like ```json.

    Command output format:
    [
      {{
        "command": "use auxiliary/scanner/http/backup_file; set RHOSTS testphp.vulnweb.com; set RPORT 80; set PATH /index.php; run; exit"
      }}
    ]

    Only output the JSON. Do not include explanations.
    """

    response = model.generate_content(prompt)
    
    cleaned_response = response.text.replace('```json', '').replace('```', '').strip()
    return json.loads(cleaned_response)

