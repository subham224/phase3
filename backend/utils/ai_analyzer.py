# utils/ai_analyzer.py

import json
import re
from typing import Dict, Any
import google.generativeai as genai

from core.config import GEMINI_API_KEY

genai.configure(api_key=GEMINI_API_KEY)


# import re
# from urllib.parse import urlparse

# def sanitize_scan_data(data: dict, target_url: str) -> str:
#     """
#     Converts scan data to a string and sanitizes sensitive identifiers.
#     """
#     # Convert to string to do raw text replacement
#     data_str = json.dumps(data, indent=2)
    
#     # 1. Extract domain and base URL from the target
#     parsed_url = urlparse(target_url)
#     domain = parsed_url.netloc.split(':')[0]
#     base_url = f"{parsed_url.scheme}://{parsed_url.netloc}"
    
#     # 2. Replace URLs and Domains
#     # Order matters: replace the longer string (URL) before the shorter one (domain)
#     data_str = data_str.replace(base_url, "[TARGET_URL]")
#     data_str = data_str.replace(domain, "[TARGET_DOMAIN]")
    
#     # 3. Replace IP Addresses using Regex
#     # Matches standard IPv4 addresses (e.g., 44.228.249.3)
#     ip_pattern = re.compile(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b')
#     data_str = ip_pattern.sub("[TARGET_IP]", data_str)
    
#     # 4. Replace common Cloud hostnames (like AWS EC2 in your example)
#     aws_pattern = re.compile(r'ec2-[\d\-]+\.[a-z0-9\-]+\.compute\.amazonaws\.com')
#     data_str = aws_pattern.sub("[TARGET_HOSTNAME]", data_str)
    
#     return data_str

import re
import json
from urllib.parse import urlparse

def sanitize_scan_data(data, target_url: str) -> str:
    """
    Converts scan data to a string and sanitizes sensitive identifiers.
    """
    # Convert to string to do raw text replacement
    data_str = json.dumps(data, indent=2) if isinstance(data, (dict, list)) else str(data)
    
    # 1. Extract domain and base URL from the target
    parsed_url = urlparse(target_url)
    domain = parsed_url.netloc.split(':')[0]
    base_url = f"{parsed_url.scheme}://{parsed_url.netloc}"
    
    # 2. Replace URLs and Domains
    if base_url != "://": # Ensure it parsed correctly
        data_str = data_str.replace(base_url, "[TARGET_URL]")
    if domain:
        data_str = data_str.replace(domain, "[TARGET_DOMAIN]")
    
    # 3. Replace IPv4 Addresses
    ipv4_pattern = re.compile(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b')
    data_str = ipv4_pattern.sub("[TARGET_IP]", data_str)
    
    # 4. Replace IPv6 Addresses (New addition for Metasploit)
    ipv6_pattern = re.compile(r'(?:[A-Fa-f0-9]{1,4}:){1,7}[A-Fa-f0-9]{1,4}|(?:[A-Fa-f0-9]{1,4}:){1,7}:|:(?::[A-Fa-f0-9]{1,4}){1,7}')
    data_str = ipv6_pattern.sub("[TARGET_IPV6]", data_str)
    
    # 5. Replace common Cloud hostnames
    aws_pattern = re.compile(r'ec2-[\d\-]+\.[a-z0-9\-]+\.compute\.amazonaws\.com')
    data_str = aws_pattern.sub("[TARGET_HOSTNAME]", data_str)
    
    return data_str


async def generate_ai_response(target: str, combined_results: Dict[str, Any]) -> Dict[str, Any]:
    """Generates a single Executive Summary AI response for the entire pentest."""
    response = None 
    
    try:
        # Convert the massive results dict to JSON string
        # summary_text = json.dumps(combined_results, indent=2)

        # Sanitize the massive results dict before converting to a string prompt
        print("Original Combined Results:", json.dumps(combined_results, indent=2))  # Debug: Print original results
        print("----------------------------------------------------------------------------")
        summary_text = sanitize_scan_data(combined_results, target)
        print("Sanitized Scan Results:", summary_text)  # Debug: Print sanitized results

        # prompt = f"""
        # You are an expert Senior Penetration Tester.
        # Here are the combined JSON results from multiple security scanners (Nmap, Wapiti, Skipfish, WhatWeb, Harvester, SQLMap):
        # {summary_text}

        # Analyze these combined findings. Ignore minor informational warnings. Focus on the real threats. 
        # Correlate the data if possible (e.g., an open port from Nmap relating to a Wapiti vulnerability).

        # Output an Executive Summary in JSON format containing the major threats. Use this exact schema:
        # [
        #   {{
        #     "Vulnerability": "Name of the issue",
        #     "Description": "Detailed explanation of the vulnerability and where it was found",
        #     "Impact": "Potential business or technical impact",
        #     "Remediation": "How to fix it"
        #   }}
        # ]

        # Return ONLY the JSON array, without any markdown fences like ```json.
        # """
        # print(summary_text)
        prompt = f"""
You are an expert Senior Penetration Tester.

You are given combined JSON results from multiple security scanners:
- Nmap
- Wapiti
- Skipfish
- WhatWeb
- theHarvester
- SQLMap

Scanner Output:
{summary_text}

IMPORTANT PRIVACY RULES:
1. Do NOT reveal or repeat any website name, domain, IP address, hostname, URL, endpoint path, or organization name found in the scanner output.
2. Replace any such identifiers with neutral terms such as:
   - "the target application"
   - "the affected endpoint"
   - "the web server"
3. Your response must never expose the scanned website identity.

Analysis Instructions:
- Correlate findings across scanners when possible.
- Focus only on meaningful security issues.
- Ignore purely informational warnings or noise.
- Prioritize vulnerabilities that present real security risks.
- If multiple tools detect related issues, combine them into one coherent vulnerability explanation.

Output Requirements:
Return an Executive Security Summary in JSON format using the following schema:

[
  {{
    "Vulnerability": "Name of the issue",
    "Description": "Detailed explanation of the vulnerability and where it occurs in the target application without revealing any domain, IP, or URL",
    "Impact": "Potential business or technical impact if exploited",
    "Remediation": "Recommended mitigation steps to fix the vulnerability"
  }}
]

Output Rules:
- Return ONLY the JSON array.
- Do NOT include markdown fences.
- Do NOT include any website identifiers.
"""
        
        model = genai.GenerativeModel('gemini-2.5-flash')
        response = await model.generate_content_async(prompt)
        
        cleaned_response = response.text.strip()
        
        # Clean markdown fences
        json_pattern = re.compile(r'```(?:json)?\n(.*?)\n```', re.DOTALL)
        match = json_pattern.match(cleaned_response)
        if match:
            cleaned_response = match.group(1).strip()
        else:
            cleaned_response = re.sub(r'^```.*?\n|\n```$', '', cleaned_response, flags=re.MULTILINE).strip()
            
        # Fix unescaped backslashes
        cleaned_response = re.sub(r'\\(?![/"\\bfnrtu])', r'\\\\', cleaned_response)
            
        try:
            ai_output = json.loads(cleaned_response, strict=False)
            if not isinstance(ai_output, list):
                return {"error": "AI response is not a valid JSON array", "raw_response": response.text}
            return {"threats": ai_output}
            
        except json.JSONDecodeError as e:
            print(f"Error decoding Executive Summary AI JSON: {e}")
            return {"error": f"Invalid JSON format: {e}", "raw_response": response.text}
            
    except Exception as e:
        error_msg = str(e)
        if "429" in error_msg or "quota" in error_msg.lower():
            print(f"[AI Warning] Gemini Quota Exceeded. Executive Summary skipped.")
            return {"error": "AI analysis skipped due to Google API free-tier quota limits (20 requests/day)."}
            
        print(f"Error generating Executive AI response: {error_msg}")
        return {
            "error": error_msg,
            "raw_response": response.text if response and hasattr(response, 'text') else None
        }