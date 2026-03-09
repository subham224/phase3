# scanners/skipfish.py

import os
import re
import json
import asyncio
from datetime import datetime
from typing import List, Tuple, Optional

from core.config import (
    SCAN_OUTPUT_DIR, 
    SKIPFISH_DUMMY_TXT, 
    MINIMAL_WL_PATH, 
    COMPLETE_WL_PATH, 
    EXTENSIONS_WL_PATH
)
from models.schemas import SkipfishScanResult, SkipfishIssueSample, ScanType
from utils.ai_analyzer import generate_ai_response

async def skipfish_run_command(command: List[str], capture_output: bool, cwd: Optional[str], scan_id: str, update_progress: callable, command_increment: float) -> Optional[str]:
    await update_progress(f"Executing Skipfish: {' '.join(command[:3])}", 0)
    print(f"Executing skipfish command: {' '.join(command)}")
    try:
        process = await asyncio.create_subprocess_exec(
            *command,
            stdout=asyncio.subprocess.PIPE if capture_output else asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.PIPE,
            cwd=cwd
        )
        stdout, stderr = await process.communicate()
        await update_progress(f"Skipfish command completed: {' '.join(command[:3])}", command_increment)
        
        if process.returncode != 0:
            raise Exception(f"Command '{' '.join(command)}' failed: {stderr.decode()}")
        return stdout.decode().strip() if capture_output and stdout else None
    except FileNotFoundError:
        await update_progress("Skipfish command failed: Tool not found", command_increment)
        raise Exception(f"Tool not found: {command[0]}. Please ensure it's installed and in your PATH.")
    except Exception as e:
        await update_progress(f"Skipfish command failed: {str(e)}", command_increment)
        raise Exception(f"Error running command '{' '.join(command)}': {e}")

async def run_skipfish(target: str, scan_type: ScanType, scan_id: str, update_progress: callable, command_increment: float, timestamp: str) -> Tuple[SkipfishScanResult, Optional[str]]:
    target_sanitized = re.sub(r'[^a-zA-Z0-9.-]', '_', target).strip('_')
    output_dir_base = os.path.join(SCAN_OUTPUT_DIR, f"skipfish_{target_sanitized}_{datetime.now().strftime('%H%M%S')}")
    os.makedirs(output_dir_base, exist_ok=True)
    
    filtered_output_file = os.path.join(SCAN_OUTPUT_DIR, f"skipfish_filtered_{target_sanitized}_{timestamp}.json")
    ai_output_file = os.path.join(SCAN_OUTPUT_DIR, f"ai_skipfish_output_{target_sanitized}_{timestamp}.json")
    
    if not os.path.exists(SKIPFISH_DUMMY_TXT):
        with open(SKIPFISH_DUMMY_TXT, 'w') as f:
            f.write("")
            
    issue_samples = []
    
    async def run_and_parse_skipfish_single(cmd: list, out_dir: str, scan_index: int, total_scans: int) -> list:
        samples = []
        start_increment = command_increment * 0.1
        scan_increment = command_increment * 0.7
        parse_increment = command_increment * 0.2
        
        try:
            await update_progress(f"Skipfish scan {scan_index}/{total_scans}: Starting", start_increment)
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.PIPE,
                cwd=None
            )
            
            max_scan_duration = 300 
            poll_interval = 10
            elapsed_time = 0
            scan_sub_increment = scan_increment / (max_scan_duration / poll_interval)
            sample_js_path = os.path.join(out_dir, "samples.js")
            
            while await process.communicate() is None: 
                if os.path.exists(sample_js_path):
                    await update_progress(f"Skipfish scan {scan_index}/{total_scans}: Scanning ({elapsed_time}s)", scan_sub_increment)
                await asyncio.sleep(poll_interval)
                elapsed_time += poll_interval
                if elapsed_time >= max_scan_duration:
                    break 
                    
            _, stderr = await process.communicate()
            if process.returncode != 0:
                raise Exception(f"Skipfish command failed: {stderr.decode()}")
                
            await update_progress(f"Skipfish scan {scan_index}/{total_scans}: Parsing results", parse_increment)
            if os.path.exists(sample_js_path):
                with open(sample_js_path, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                match = re.search(r'var issue_samples\s*=\s*(\[.*?\]);', content, re.DOTALL)
                if match:
                    json_str = match.group(1)
                    json_str = re.sub(r"'\s*([a-zA-Z_$][a-zA-Z0-9_$]*)\s*'\s*:", r'"\1":', json_str)
                    json_str = re.sub(r"(?<![:\w])'([^']*)'", r'"\1"', json_str)
                    json_str = re.sub(r'\\(?!["\\/bfnrtu])', r'\\\\', json_str)
                    try:
                        raw_samples = json.loads(json_str)
                        for group in raw_samples:
                            severity = str(group.get("severity", "N/A"))
                            type_id = str(group.get("type", "N/A"))
                            for sample_item in group.get("samples", []):
                                samples.append(SkipfishIssueSample(
                                    severity=severity,
                                    type=type_id,
                                    url=str(sample_item.get("url") or "N/A")
                                ))
                    except json.JSONDecodeError as e:
                        print(f"Error decoding Skipfish samples.js JSON: {e}")
            else:
                print(f"Skipfish samples.js not found: {sample_js_path}")
        except Exception as e:
            print(f"Error running Skipfish scan {scan_index}/{total_scans}: {e}")
            await update_progress(f"Skipfish scan {scan_index}/{total_scans}: Failed", 0)
        return samples

    try:
        if scan_type == ScanType.LIGHT:
            command = [
                "skipfish", "-d", "3", "-c", "8", "-x", "4", "-r", "10000", "-f", "5", "-t", "15", "-i", "7",
                "-Z", "-O", "-U", "-Q", "-k", "0:5:0",
                "-W", SKIPFISH_DUMMY_TXT,
                "-S", MINIMAL_WL_PATH,
                "-o", output_dir_base, target
            ]
            issue_samples.extend(await run_and_parse_skipfish_single(command, output_dir_base, 1, 1))
        else:
            output_dir1 = os.path.join(output_dir_base, "scan1")
            output_dir2 = os.path.join(output_dir_base, "scan2")
            os.makedirs(output_dir1, exist_ok=True)
            os.makedirs(output_dir2, exist_ok=True)
            command1 = [
                "skipfish", "-d", "3", "-c", "8", "-x", "4", "-r", "10000", "-f", "5", "-t", "15", "-i", "7",
                "-Z", "-O", "-U", "-Q", "-k", "0:5:0",
                "-W", SKIPFISH_DUMMY_TXT,
                "-S", MINIMAL_WL_PATH,
                "-o", output_dir1, target
            ]
            command2 = [
                "skipfish", "-d", "5", "-c", "16", "-x", "8", "-r", "100000", "-f", "5", "-t", "15", "-i", "7",
                "-Z", "-O", "-U", "-Q", "-k", "0:15:0",
                "-W", SKIPFISH_DUMMY_TXT,
                "-S", MINIMAL_WL_PATH,
                "-S", COMPLETE_WL_PATH,
                "-S", EXTENSIONS_WL_PATH,
                "-o", output_dir2, target
            ]
            issues1 = await run_and_parse_skipfish_single(command1, output_dir1, 1, 2)
            issues2 = await run_and_parse_skipfish_single(command2, output_dir2, 2, 2)
            issue_samples.extend(issues1)
            issue_samples.extend(issues2)

        if issue_samples:
            with open(filtered_output_file, 'w', encoding='utf-8') as f_out:
                json.dump([s.model_dump() for s in issue_samples], f_out, indent=4)
            # Generate AI response
            # ai_response = await generate_ai_response("Skipfish", [s.model_dump() for s in issue_samples], target)
            # with open(ai_output_file, 'w', encoding='utf-8') as f_out:
            #     json.dump(ai_response, f_out, indent=4)
                
        return SkipfishScanResult(issue_samples=issue_samples),None
        # ai_output_file
    except Exception as e:
        print(f"Error running Skipfish: {e}")
        await update_progress("Skipfish failed", 0)
        return SkipfishScanResult(), None