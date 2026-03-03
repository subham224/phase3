# # scanners/whatweb.py

# import os
# import re
# import json
# from typing import List, Tuple, Optional

# from core.config import SCAN_OUTPUT_DIR
# from models.schemas import WhatWebResult
# from utils.command_runner import run_command
# from utils.ai_analyzer import generate_ai_response

# async def run_whatweb(target: str, scan_id: str, update_progress: callable, command_increment: float, timestamp: str) -> Tuple[List[WhatWebResult], Optional[str]]:
#     target_sanitized = re.sub(r'[^a-zA-Z0-9.-]', '_', target).strip('_')
#     raw_output_file = os.path.join(SCAN_OUTPUT_DIR, f"whatweb_raw_{target_sanitized}.json")
#     filtered_output_file = os.path.join(SCAN_OUTPUT_DIR, f"whatweb_filtered_{target_sanitized}.json")
#     ai_output_file = os.path.join(SCAN_OUTPUT_DIR, f"ai_whatweb_output_{target_sanitized}_{timestamp}.json")
#     os.makedirs(SCAN_OUTPUT_DIR, exist_ok=True)
    
#     command = ["whatweb", "--log-json", raw_output_file, target]
#     await update_progress(f"Executing WhatWeb: {command[0]}", 0)
    
#     try:
#         await run_command(command)
#         await update_progress("WhatWeb command completed", command_increment)
#         if not os.path.exists(raw_output_file) or os.path.getsize(raw_output_file) == 0:
#             print(f"WhatWeb output file issue: {raw_output_file}")
#             return [], None
            
#         with open(raw_output_file, 'r', encoding='utf-8', errors='ignore') as f:
#             raw_results = json.load(f)
            
#         filtered_results = []
#         for res in raw_results:
#             if isinstance(res, dict):
#                 plugins = res.get("plugins", {})
#                 http_status = res.get("http_status")
#                 if http_status == 200:
#                     def get_plugin_string(plugin_name: str) -> Optional[str]:
#                         plugin = plugins.get(plugin_name)
#                         if not plugin:
#                             return None
#                         strings = plugin.get("string")
#                         if isinstance(strings, list):
#                             return ", ".join(set(strings))
#                         elif isinstance(strings, str):
#                             return strings
#                         return None
                        
#                     def get_plugin_string_list(plugin_name: str) -> List[str]:
#                         plugin_data = plugins.get(plugin_name)
#                         if plugin_data:
#                             strings = plugin_data.get("string")
#                             if isinstance(strings, list):
#                                 return strings
#                         return []
                        
#                     result = WhatWebResult(
#                         target=res.get("target"),
#                         http_status=http_status,
#                         HTTPServer=get_plugin_string("HTTPServer"),
#                         IP=get_plugin_string("IP"),
#                         MetaGenerator=get_plugin_string("MetaGenerator"),
#                         Title=get_plugin_string("Title"),
#                         UncommonHeaders=get_plugin_string_list("UncommonHeaders"),
#                         **{
#                             "X-Frame-Options": get_plugin_string("X-Frame-Options"),
#                             "X-XSS-Protection": get_plugin_string("X-XSS-Protection"),
#                             "X-Powered-By": get_plugin_string_list("X-Powered-By")
#                         }
#                     )
#                     filtered_results.append(result)
                    
#         if filtered_results:
#             with open(filtered_output_file, 'w', encoding='utf-8') as f_out:
#                 json.dump([r.model_dump() for r in filtered_results], f_out, indent=4)
#             # Generate AI response
#             ai_response = await generate_ai_response("WhatWeb", [r.model_dump() for r in filtered_results], target)
#             with open(ai_output_file, 'w', encoding='utf-8') as f_out:
#                 json.dump(ai_response, f_out, indent=4)
                
#         return filtered_results, ai_output_file
#     except Exception as e:
#         print(f"Error in WhatWeb: {e}")
#         await update_progress(f"WhatWeb command failed: {str(e)}", command_increment)
#         return [], None

# scanners/whatweb.py

import os
import re
import json
from typing import List, Tuple, Optional

from core.config import SCAN_OUTPUT_DIR
from models.schemas import WhatWebResult
from utils.command_runner import run_command
from utils.ai_analyzer import generate_ai_response

async def run_whatweb(target: str, scan_id: str, update_progress: callable, command_increment: float, timestamp: str) -> Tuple[List[WhatWebResult], Optional[str]]:
    target_sanitized = re.sub(r'[^a-zA-Z0-9.-]', '_', target).strip('_')
    raw_output_file = os.path.join(SCAN_OUTPUT_DIR, f"whatweb_raw_{target_sanitized}.json")
    filtered_output_file = os.path.join(SCAN_OUTPUT_DIR, f"whatweb_filtered_{target_sanitized}.json")
    ai_output_file = os.path.join(SCAN_OUTPUT_DIR, f"ai_whatweb_output_{target_sanitized}_{timestamp}.json")
    os.makedirs(SCAN_OUTPUT_DIR, exist_ok=True)
    
    command = ["whatweb", "--log-json", raw_output_file, target]
    await update_progress(f"Executing WhatWeb: {command[0]}", 0)
    
    try:
        await run_command(command)
        await update_progress("WhatWeb command completed", command_increment)
        if not os.path.exists(raw_output_file) or os.path.getsize(raw_output_file) == 0:
            print(f"WhatWeb output file issue: {raw_output_file}")
            return [], None
            
        with open(raw_output_file, 'r', encoding='utf-8', errors='ignore') as f:
            raw_results = json.load(f)
            
        filtered_results = []
        for res in raw_results:
            if isinstance(res, dict):
                plugins = res.get("plugins", {})
                http_status = res.get("http_status")
                
                # Only process if it returned a 200 OK status
                # if http_status == 200:
                if http_status and http_status != 0:
                    def get_plugin_string(plugin_name: str) -> Optional[str]:
                        plugin = plugins.get(plugin_name)
                        if not plugin:
                            return None
                        strings = plugin.get("string")
                        if isinstance(strings, list):
                            return ", ".join(set(strings))
                        elif isinstance(strings, str):
                            return strings
                        return None
                        
                    def get_plugin_string_list(plugin_name: str) -> List[str]:
                        plugin_data = plugins.get(plugin_name)
                        if plugin_data:
                            strings = plugin_data.get("string")
                            if isinstance(strings, list):
                                return strings
                        return []
                        
                    result = WhatWebResult(
                        target=res.get("target"),
                        http_status=http_status,
                        HTTPServer=get_plugin_string("HTTPServer"),
                        IP=get_plugin_string("IP"),
                        MetaGenerator=get_plugin_string("MetaGenerator"),
                        Title=get_plugin_string("Title"),
                        UncommonHeaders=get_plugin_string_list("UncommonHeaders"),
                        **{
                            "X-Frame-Options": get_plugin_string("X-Frame-Options"),
                            "X-XSS-Protection": get_plugin_string("X-XSS-Protection"),
                            "X-Powered-By": get_plugin_string_list("X-Powered-By")
                        }
                    )
                    filtered_results.append(result)
                    
        # --- THE FIX ---
        if filtered_results:
            with open(filtered_output_file, 'w', encoding='utf-8') as f_out:
                json.dump([r.model_dump() for r in filtered_results], f_out, indent=4)
            # Generate AI response
            # ai_response = await generate_ai_response("WhatWeb", [r.model_dump() for r in filtered_results], target)
            # with open(ai_output_file, 'w', encoding='utf-8') as f_out:
            #     json.dump(ai_response, f_out, indent=4)
                
            # Only return the AI file path if results were found and the file was saved
            return filtered_results, None
        # ai_output_file
            
        # If no valid results were found, return None to prevent a 404 error
        return [], None
        
    except Exception as e:
        print(f"Error in WhatWeb: {e}")
        await update_progress(f"WhatWeb command failed: {str(e)}", command_increment)
        return [], None