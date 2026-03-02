# utils/ai_analyzer.py

import json
import re
from typing import List, Dict, Any
import google.generativeai as genai

# Import and configure the AI key
from core.config import GEMINI_API_KEY

genai.configure(api_key=GEMINI_API_KEY)

async def generate_ai_response(tool_name: str, filtered_data: List[Dict[str, Any]], target: str) -> Dict[str, Any]:
    """Generates AI response for filtered data and returns it as a dictionary."""
    try:
        summary_text = json.dumps(filtered_data, indent=2)
        prompt = f"""
        Provide me all the major possible threats which may occur due to the data in {summary_text}.Output should be in
    json format with fields in json being Vulnerability, Description, Impact, Remediation

Output the analysis in JSON format with the following fields for each identified threat:
- Vulnerability: Name of the vulnerability or issue.
- Description: Detailed explanation of the vulnerability.
- Impact: Potential impact of the vulnerability on the system or application.
- Remediation: Steps or recommendations to mitigate or fix the vulnerability.

Ensure the output is a JSON array of objects, each containing the above fields. Return only the JSON array, without any markdown or code fences.
"""
        # Note: Updated to gemini-2.5-flash as it was in your original code
        model = genai.GenerativeModel('gemini-2.5-flash')
        response = await model.generate_content_async(prompt)
        
        # Clean the response to extract JSON content
        cleaned_response = response.text.strip()
        
        # Remove markdown code fences if present
        json_pattern = re.compile(r'```(?:json)?\n(.*?)\n```', re.DOTALL)
        match = json_pattern.match(cleaned_response)
        if match:
            cleaned_response = match.group(1).strip()
        else:
            # Remove any leading/trailing ``` or other non-JSON content
            cleaned_response = re.sub(r'^```.*?\n|\n```$', '', cleaned_response, flags=re.MULTILINE).strip()
            
        try:

            # This regex escapes any backslash that isn't followed by a valid JSON escape character
            cleaned_response = re.sub(r'\\(?![/"\\bfnrtu])', r'\\\\', cleaned_response)
            
            # Parse the cleaned response as JSON
            # ai_output = json.loads(cleaned_response)
            ai_output = json.loads(cleaned_response, strict=False)
            if not isinstance(ai_output, list):
                print(f"AI response for {tool_name} is not a list: {cleaned_response}")
                return {"error": "AI response is not a valid JSON array", "raw_response": response.text}
                
            # Validate that each item has required fields
            required_fields = {"Vulnerability", "Description", "Impact", "Remediation"}
            for item in ai_output:
                if not isinstance(item, dict) or not all(field in item for field in required_fields):
                    print(f"Invalid item in AI response for {tool_name}: {item}")
                    return {
                        "error": "AI response contains invalid items missing required fields",
                        "raw_response": response.text,
                        "cleaned_response": cleaned_response
                    }
                    
            return {"threats": ai_output}
            
        except json.JSONDecodeError as e:
            print(f"Error decoding AI response for {tool_name}: {e}")
            return {
                "error": f"Invalid JSON format in AI response: {e}",
                "raw_response": response.text,
                "cleaned_response": cleaned_response
            }
            
    except Exception as e:
        print(f"Error generating AI response for {tool_name}: {e}")
        return {
            "error": str(e),
            "raw_response": response.text if hasattr(response, 'text') else None,
            "cleaned_response": None
        }