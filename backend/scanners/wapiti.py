# scanners/wapiti.py

import os
import re
import json
import asyncio
from typing import List, Tuple, Optional

from core.config import SCAN_OUTPUT_DIR
from models.schemas import WapitiScanResult, WapitiVulnerability, ScanType
from utils.ai_analyzer import generate_ai_response

# async def wapiti_run_command(command: List[str], scan_id: str, update_progress: callable, command_increment: float) -> None:
#     await update_progress(f"Executing Wapiti: {' '.join(command[:3])}", 0)
#     try:
#         process = await asyncio.create_subprocess_exec(
#             *command,
#             stdout=asyncio.subprocess.PIPE,
#             stderr=asyncio.subprocess.PIPE
#         )
#         stdout, stderr = await process.communicate()
#         await update_progress(f"Wapiti command completed: {' '.join(command[:3])}", command_increment)
        
#         if process.returncode != 0:
#             raise RuntimeError(f"Command {' '.join(command)} failed with exit code {process.returncode}")
#     except Exception as e:
#         print(f"[!] Error while running Wapiti command: {' '.join(command)}")
#         await update_progress(f"Wapiti command failed: {str(e)}", command_increment)
#         raise

# scanners/wapiti.py (Update this specific function)

async def wapiti_run_command(command: List[str], scan_id: str, update_progress: callable, command_increment: float) -> None:
    await update_progress(f"Executing Wapiti: {' '.join(command[:3])}", 0)
    try:
        process = await asyncio.create_subprocess_exec(
            *command,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        stdout, stderr = await process.communicate()
        await update_progress(f"Wapiti command completed: {' '.join(command[:3])}", command_increment)
        
        # REMOVE the raise RuntimeError here. 
        # Wapiti safely exits with non-zero if it finds vulnerabilities or SSL warnings.
        if process.returncode != 0:
            print(f"[Wapiti Warning] Exited with code {process.returncode}. This is usually normal if vulns/warnings are found.")
            
    except Exception as e:
        print(f"[!] Error while running Wapiti command: {' '.join(command)}")
        await update_progress(f"Wapiti command failed: {str(e)}", command_increment)
        raise

async def run_wapiti(target: str, scan_type: ScanType, scan_id: str, update_progress: callable, command_increment: float, timestamp: str) -> Tuple[WapitiScanResult, Optional[str]]:
    def parse_wapiti_results(file_path: str) -> List[WapitiVulnerability]:
        vulnerabilities = []
        if not os.path.exists(file_path) or os.stat(file_path).st_size == 0:
            return vulnerabilities
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                raw_results = json.load(f)
        except json.JSONDecodeError as e:
            print(f"Error decoding Wapiti JSON from {file_path}: {e}")
            return vulnerabilities
            
        vuln_dict = raw_results.get("vulnerabilities", {})
        for category, findings in vuln_dict.items():
            if not findings:
                continue
            for finding in findings:
                if isinstance(finding, dict) and "info" in finding:
                    vulnerabilities.append(WapitiVulnerability(info=finding["info"]))
                elif isinstance(finding, dict) and "name" in finding and "description" in finding:
                    vulnerabilities.append(WapitiVulnerability(info=f"{finding['name']}: {finding['description']}"))
        return vulnerabilities

    target_sanitized = re.sub(r'[^a-zA-Z0-9.-]', '_', target).strip('_')
    ai_output_file = os.path.join(SCAN_OUTPUT_DIR, f"ai_wapiti_output_{target_sanitized}_{timestamp}.json")
    
    try:
        # Using the same phase 3 command for both light and deep scans
        raw_output_file = os.path.join(SCAN_OUTPUT_DIR, f"wapiti_raw_{scan_type.value}_{target_sanitized}.json")
        filtered_output_file = os.path.join(SCAN_OUTPUT_DIR, f"wapiti_filtered_{scan_type.value}_{target_sanitized}.json")
        
        commands = [
            "wapiti", "-u", target,
            "-m", "all,-nikto,-sql,-permanentxss,-wp_enum,-ldap,-wapp,-brute_login_form,-xxe,-xss,-buster,-file,-exec,-log4shell,-spring4shell,-redirect,-timesql,-ssl",
            "-d", "5", "--flush-attacks", "--no-bugreport", "-f", "json", "-o", raw_output_file
        ]

      
        
        # Execute the single Phase 3 Wapiti command
        await wapiti_run_command(commands, scan_id, update_progress, command_increment)
        vulns = parse_wapiti_results(raw_output_file)
                
        unique_infos = {}
        for v in vulns:
            if v.info not in unique_infos:
                unique_infos[v.info] = v
        deduped_vulns = list(unique_infos.values())
        
        if deduped_vulns:
            with open(filtered_output_file, 'w', encoding='utf-8') as f_out:
                json.dump([v.model_dump() for v in deduped_vulns], f_out, indent=4)
            # Generate AI response
            ai_response = await generate_ai_response("Wapiti", [v.model_dump() for v in deduped_vulns], target)
            with open(ai_output_file, 'w', encoding='utf-8') as f_out:
                json.dump(ai_response, f_out, indent=4)
                
            return WapitiScanResult(vulnerabilities=deduped_vulns), ai_output_file
            
        # If no vulnerabilities found, return None for the file path to prevent a 404
        return WapitiScanResult(vulnerabilities=[]), None

    except Exception as e:
        print(f"Error running Wapiti: {e}")
        return WapitiScanResult(), None