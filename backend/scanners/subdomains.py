# scanners/subdomains.py

import os
import re
import json
import asyncio
from typing import List, Tuple, Optional

from core.config import SCAN_OUTPUT_DIR, WORDLIST_PATH
from models.schemas import SubdomainResult
from utils.file_handlers import clean_domain

async def run_harvester(domain: str, limit: int, scan_id: str, update_progress: callable, command_increment: float, timestamp: str) -> Tuple[List[SubdomainResult], Optional[str]]:
    n_domain = clean_domain(domain)
    harvester_base_name = f"harvester_output_{n_domain.replace('.', '_')}"
    raw_output_file = os.path.join(SCAN_OUTPUT_DIR, f"{harvester_base_name}.json")
    filtered_output_file = os.path.join(SCAN_OUTPUT_DIR, f"harvester_filtered_{n_domain.replace('.', '_')}.json")
    ai_output_file = os.path.join(SCAN_OUTPUT_DIR, f"ai_harvester_output_{n_domain.replace('.', '_')}_{timestamp}.json")
    
    command =[
    "theHarvester",
    "-d", n_domain,                    # domain only (no http/https)
    "-b", "crtsh,certspotter",         # removed bing (unsupported)
    "-l", str(limit),
    "-f", harvester_base_name
]
    #["theHarvester", "-d", n_domain, "-b", "bing,crtsh,certspotter", "-l", str(limit), "-f", harvester_base_name]
    subdomains = []
    
    await update_progress(f"Executing theHarvester: {command[0]}", 0)
    try:
        # We run this manually instead of run_command to ignore exit code 1
        process = await asyncio.create_subprocess_exec(
            *command,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            cwd=SCAN_OUTPUT_DIR
        )
        await process.communicate() # Wait for completion, ignore exit code
        
        await update_progress("theHarvester command completed", command_increment)
        await asyncio.sleep(1) # Small delay to ensure file write finishes
        
        if os.path.exists(raw_output_file) and os.path.getsize(raw_output_file) > 0:
            with open(raw_output_file, 'r') as f:
                try:
                    data = json.loads(f.read())
                    if 'hosts' in data:
                        for host in data['hosts']:
                            if ':' in host:
                                s, ip = host.split(':', 1)
                                subdomains.append(SubdomainResult(subdomain=s.strip(), source="harvester", resolved_ip=ip.strip()))
                            else:
                                subdomains.append(SubdomainResult(subdomain=host.strip(), source="harvester"))
                    if 'ips' in data:
                        for ip in data['ips']:
                            subdomains.append(SubdomainResult(subdomain=f"[IP]:{ip.strip()}", source="harvester", resolved_ip=ip.strip()))
                    
                    if subdomains:
                        with open(filtered_output_file, 'w', encoding='utf-8') as f_out:
                            json.dump([s.model_dump() for s in subdomains], f_out, indent=4)
                            
                except json.JSONDecodeError as e:
                    print(f"Error decoding JSON from theHarvester output: {e}")
                    
        return subdomains, None
    except Exception as e:
        print(f"Error running theHarvester: {e}")
        await update_progress(f"theHarvester command failed: {str(e)}", command_increment)
        return subdomains, None

async def run_gobuster(domain: str, scan_id: str, update_progress: callable, command_increment: float, timestamp: str) -> Tuple[List[SubdomainResult], Optional[str]]:
    n_domain = clean_domain(domain)
    raw_output_file = os.path.join(SCAN_OUTPUT_DIR, f"gobuster_raw_{n_domain.replace('.', '_')}.txt")
    filtered_output_file = os.path.join(SCAN_OUTPUT_DIR, f"gobuster_filtered_{n_domain.replace('.', '_')}.json")
    ai_output_file = os.path.join(SCAN_OUTPUT_DIR, f"ai_gobuster_output_{n_domain.replace('.', '_')}_{timestamp}.json")
    
    command = ["gobuster", "dns", "-q", "--domain", n_domain, "-w", WORDLIST_PATH, "-t", "50", "--wildcard"]
    #["gobuster", "dns", "-d", n_domain, "-w", WORDLIST_PATH, "-t", "50", "--wildcard"]
    subdomains = []
    
    await update_progress(f"Executing Gobuster: {command[0]}", 0)
    try:
        process = await asyncio.create_subprocess_exec(
            *command, 
            stdout=asyncio.subprocess.PIPE, 
            stderr=asyncio.subprocess.PIPE
        )
        stdout, stderr = await process.communicate()
        await update_progress("Gobuster command completed", command_increment)
        
        if stdout:
            decoded_stdout = stdout.decode().strip()
            with open(raw_output_file, 'w', encoding='utf-8') as f: 
                f.write(decoded_stdout)
            
            for line in decoded_stdout.splitlines():
                # Flexible regex to catch gobuster output formats
                match = re.search(r'Found:\s+([\w.-]+)\s*(?:\(([\d.]+)\))?', line)
                if match:
                    sub = match.group(1).strip()
                    ip = match.group(2).strip() if match.group(2) else None
                    subdomains.append(SubdomainResult(subdomain=sub, source="gobuster", resolved_ip=ip))
                    
        if stderr:
            stderr_text = stderr.decode().strip()
            if "error" in stderr_text.lower() or "invalid" in stderr_text.lower():
                print(f"[Gobuster Warning] {stderr_text}")

        if subdomains:
            with open(filtered_output_file, 'w', encoding='utf-8') as f_out:
                json.dump([s.model_dump() for s in subdomains], f_out, indent=4)
                
        return subdomains, None 
    except Exception as e:
        print(f"Error running Gobuster: {e}")
        await update_progress(f"Gobuster command failed: {str(e)}", command_increment)
        return subdomains, None