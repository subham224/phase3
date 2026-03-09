# # import json
# # import google.generativeai as genai
# # from core.config import GEMINI_API_KEY

# # genai.configure(api_key=GEMINI_API_KEY)

# # model = genai.GenerativeModel('gemini-2.5-flash')


# # async def generate_vulnerability_report(scan_results):

# #     prompt = f"""
# # Analyze these Metasploit command outputs.

# # {json.dumps(scan_results)}

# # Return JSON:

# # [
# # {{
# # "Vulnerability":"",
# # "Description":"",
# # "Impact":"",
# # "Sensitive information found":"",
# # "Remediation":""
# # }}
# # ]

# # Only return JSON.
# # """

# #     response = model.generate_content(prompt)

# #     return json.loads(response.text)

# import json
# import google.generativeai as genai
# from core.config import GEMINI_API_KEY

# genai.configure(api_key=GEMINI_API_KEY)

# # Changed to 2.0-flash
# model = genai.GenerativeModel("gemini-2.5-flash")

# async def generate_vulnerability_report(scan_results):
#     prompt = f"""
# Review the provided JSON array containing executed Metasploit commands and their corresponding raw terminal outputs from a scan against the authorized lab.

# Your task is to analyze the raw_output of each command. Identify any exposed sensitive information, misconfigurations, or vulnerabilities.

# You must output your final analysis strictly as a JSON array of objects using the exact schema below. Do not include any conversational text, markdown formatting outside of the JSON block, or explanations. If a command's output reveals no vulnerabilities, do not create an object for it.

# Required Output Format:
# [
#   {{
#     "Vulnerability": "Name of the issue found (or 'Information Disclosure')",
#     "Description": "Brief explanation of what the output reveals",
#     "Impact": "Potential security risk",
#     "Sensitive information found": "Extract the specific finding from the raw output",
#     "Remediation": "How to fix it"
#   }}
# ]

# Scan Results for Analysis:
# {json.dumps(scan_results)}
# """

#     response = model.generate_content(prompt)
    
#     cleaned_response = response.text.replace('```json', '').replace('```', '').strip()
#     return json.loads(cleaned_response)


import json
import google.generativeai as genai
from core.config import GEMINI_API_KEY
from utils.ai_analyzer import sanitize_scan_data  # <-- Import the sanitizer

genai.configure(api_key=GEMINI_API_KEY)
model = genai.GenerativeModel("gemini-2.5-flash")

# <-- Add target_url parameter here
async def generate_vulnerability_report(target_url: str, scan_results: list): 
    
    # <-- Sanitize the raw results here
    print("Original Scan Results:", json.dumps(scan_results, indent=2))  # Debug: Print original results
    print("------------------------------------------------------------------------------------------------")
    sanitized_results = sanitize_scan_data(scan_results, target_url)
    print("Sanitized Scan Results:", sanitized_results)  # Debug: Print sanitized results before sending to model
    # print(sanitized_results)  # For debugging purposes, to see the sanitized output before sending to the model

    prompt = f"""
Review the provided JSON array containing executed Metasploit commands and their corresponding raw terminal outputs from a scan against the authorized lab.

Your task is to analyze the raw_output of each command. Identify any exposed sensitive information, misconfigurations, or vulnerabilities.

You must output your final analysis strictly as a JSON array of objects using the exact schema below. Do not include any conversational text, markdown formatting outside of the JSON block, or explanations. If a command's output reveals no vulnerabilities, do not create an object for it.

Required Output Format:
[
  {{
    "Vulnerability": "Name of the issue found (or 'Information Disclosure')",
    "Description": "Brief explanation of what the output reveals",
    "Impact": "Potential security risk",
    "Sensitive information found": "Extract the specific finding from the raw output",
    "Remediation": "How to fix it"
  }}
]

Scan Results for Analysis:
{sanitized_results} 
"""

    response = model.generate_content(prompt)
    
    cleaned_response = response.text.replace('```json', '').replace('```', '').strip()
    return json.loads(cleaned_response)