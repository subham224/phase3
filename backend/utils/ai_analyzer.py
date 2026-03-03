# utils/ai_analyzer.py

import json
import re
from typing import Dict, Any
import google.generativeai as genai

from core.config import GEMINI_API_KEY

genai.configure(api_key=GEMINI_API_KEY)

async def generate_ai_response(target: str, combined_results: Dict[str, Any]) -> Dict[str, Any]:
    """Generates a single Executive Summary AI response for the entire pentest."""
    response = None 
    
    try:
        # Convert the massive results dict to JSON string
        summary_text = json.dumps(combined_results, indent=2)
        
        prompt = f"""
        You are an expert Senior Penetration Tester. I have performed an automated penetration test on the target: {target}.
        
        Here are the combined JSON results from multiple security scanners (Nmap, Wapiti, Skipfish, WhatWeb, Harvester, SQLMap):
        {summary_text}

        Analyze these combined findings. Ignore minor informational warnings. Focus on the real threats. 
        Correlate the data if possible (e.g., an open port from Nmap relating to a Wapiti vulnerability).

        Output an Executive Summary in JSON format containing the major threats. Use this exact schema:
        [
          {{
            "Vulnerability": "Name of the issue",
            "Description": "Detailed explanation of the vulnerability and where it was found",
            "Impact": "Potential business or technical impact",
            "Remediation": "How to fix it"
          }}
        ]

        Return ONLY the JSON array, without any markdown fences like ```json.
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