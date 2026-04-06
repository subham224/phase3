import json
import re
from typing import Dict, Any
import google.generativeai as genai
from urllib.parse import urlparse

from core.config import GEMINI_API_KEY

genai.configure(api_key=GEMINI_API_KEY)


def sanitize_scan_data(data, target_url: str) -> str:
    """
    Converts scan data to a string and sanitizes sensitive identifiers.
    """
    data_str = json.dumps(data, indent=2) if isinstance(data, (dict, list)) else str(data)
    
    parsed_url = urlparse(target_url)
    domain = parsed_url.netloc.split(':')[0]
    base_url = f"{parsed_url.scheme}://{parsed_url.netloc}"
    
    if base_url != "://": 
        data_str = data_str.replace(base_url, "[TARGET_URL]")
    if domain:
        data_str = data_str.replace(domain, "[TARGET_DOMAIN]")
    
    ipv4_pattern = re.compile(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b')
    data_str = ipv4_pattern.sub("[TARGET_IP]", data_str)
    
    ipv6_pattern = re.compile(r'(?:[A-Fa-f0-9]{1,4}:){1,7}[A-Fa-f0-9]{1,4}|(?:[A-Fa-f0-9]{1,4}:){1,7}:|:(?::[A-Fa-f0-9]{1,4}){1,7}')
    data_str = ipv6_pattern.sub("[TARGET_IPV6]", data_str)
    
    aws_pattern = re.compile(r'ec2-[\d\-]+\.[a-z0-9\-]+\.compute\.amazonaws\.com')
    data_str = aws_pattern.sub("[TARGET_HOSTNAME]", data_str)
    
    return data_str


async def generate_ai_response(target: str, combined_results: Dict[str, Any]) -> Dict[str, Any]:
    """Generates a single Executive Summary AI response for the entire pentest."""
    response = None 
    
    try:
        summary_text = sanitize_scan_data(combined_results, target)

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
        
        raw_text = response.text
        
        # ---------------------------------------------------------
        # BULLETPROOF JSON PARSER
        # ---------------------------------------------------------
        
        # 1. Extract ONLY the JSON array using index bounds
        start_idx = raw_text.find('[')
        end_idx = raw_text.rfind(']')
        
        if start_idx != -1 and end_idx != -1:
            clean_text = raw_text[start_idx:end_idx+1]
        else:
            clean_text = raw_text # Fallback just in case
            
        # 2. Safely escape stray backslashes
        clean_text = re.sub(r'\\(?!["\\/bfnrtu])', r'\\\\', clean_text)
            
        # 3. Parse the JSON
        try:
            ai_output = json.loads(clean_text)
            if not isinstance(ai_output, list):
                return {"error": "AI response is not a valid JSON array", "raw_response": raw_text}
            return {"threats": ai_output}
            
        except json.JSONDecodeError as e:
            print(f"Error decoding Executive Summary AI JSON: {e}")
            print(f"Attempted to parse: {clean_text}") # Debugging
            return {"error": f"Invalid JSON format: {e}", "raw_response": raw_text}
            
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