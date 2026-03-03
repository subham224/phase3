# services/orchestrator.py

import asyncio
import os
from urllib.parse import urlparse
from datetime import datetime
from fastapi import WebSocket
from typing import Dict, Any, Optional
from concurrent.futures import ThreadPoolExecutor
import re

from core.state import active_scans
from core.config import SCAN_OUTPUT_DIR, NMAP_TARGETS_FILE
from models.schemas import ScanType
from utils.file_handlers import clear_scan_outputs, resolve_domain_sync, write_lines_to_file, get_root_domain
from scanners.whatweb import run_whatweb
from scanners.wapiti import run_wapiti
from scanners.skipfish import run_skipfish
from scanners.subdomains import run_harvester, run_gobuster
from scanners.nmap import run_nmap_scans
from scanners.sqlmap import run_sqlmap

async def process_scan(target_url: str, scan_type: ScanType, scan_id: str, websocket: Optional[WebSocket] = None) -> Dict[str, Any]:
    target_url = str(target_url)
    print(f"Starting {scan_type.value} scan for: {target_url} with scan_id: {scan_id}")
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    active_scans[scan_id] = {"progress": 0, "status": "running", "step": "Initializing", "error": None}

    async def update_progress(step: str, increment: float):
        if scan_id in active_scans:
            active_scans[scan_id]["progress"] = min(active_scans[scan_id]["progress"] + increment, 100.0)
            active_scans[scan_id]["step"] = step
            if websocket:
                try:
                    await websocket.send_json({
                        "scan_id": scan_id,
                        "progress": active_scans[scan_id]["progress"],
                        "step": step,
                        "status": active_scans[scan_id]["status"],
                        "error": active_scans[scan_id].get("error", None)
                    })
                except Exception as e:
                    print(f"WebSocket send error for {scan_id}: {e}")
                    active_scans[scan_id]["status"] = "failed"
                    active_scans[scan_id]["error"] = f"WebSocket communication error: {str(e)}"

    await clear_scan_outputs()
    all_results = {
        "whatweb_info": [],
        "harvester_info": [],
        "gobuster_info": [],
        "nmap_info": {},
        "wapiti_info": {},
        "skipfish_info": {},
        "sqlmap_info": {},
        "ai_output_files": {}
    }
    
    parsed_url = urlparse(target_url)
    exact_domain = parsed_url.netloc.split(':')[0] # Example: nis.nist.edu
    root_domain = get_root_domain(target_url)      # Example: nist.edu

    if not exact_domain:
        active_scans[scan_id]["status"] = "failed"
        active_scans[scan_id]["error"] = "Invalid exact domain parsed."
        await update_progress("Invalid domain", 0)
        raise ValueError("Invalid exact domain parsed.")

    progress_weights = {
        "whatweb": 5.0,
        "harvester": 10.0,
        "gobuster": 10.0,
        "nmap_prep": 5.0,
        "nmap": 40.0,
        "wapiti": 20.0,
        "skipfish": 25.0,
        "sqlmap": 25.0
    }

    # Step 1: WhatWeb
    await update_progress("Starting WhatWeb", 0)
    try:
        whatweb_results, ai_whatweb_file = await run_whatweb(target_url, scan_id, update_progress, progress_weights["whatweb"], timestamp)
        all_results["whatweb_info"] = [r.model_dump() for r in whatweb_results]
        if ai_whatweb_file:
            all_results["ai_output_files"]["whatweb"] = [ai_whatweb_file]
        await update_progress("WhatWeb completed", progress_weights["whatweb"])
    except Exception as e:
        print(f"WhatWeb error: {e}")
        all_results["whatweb_info"] = [{"error": str(e)}]
        active_scans[scan_id]["error"] = str(e)
        await update_progress("WhatWeb failed", 0)

    # Step 2: Wapiti
    await update_progress("Starting Wapiti", 0)
    try:
        # wapiti_commands = 1 if scan_type == ScanType.LIGHT else 2
        # wapiti_increment = progress_weights["wapiti"] / wapiti_commands
        wapiti_increment = progress_weights["wapiti"]
        wapiti_results, ai_wapiti_file = await run_wapiti(target_url, scan_type, scan_id, update_progress, wapiti_increment, timestamp)
        all_results["wapiti_info"] = wapiti_results.model_dump()
        if ai_wapiti_file:
            all_results["ai_output_files"]["wapiti"] = [ai_wapiti_file]
        await update_progress("Wapiti completed", 0)
    except Exception as e:
        print(f"Wapiti error: {e}")
        all_results["wapiti_info"] = [{"error": str(e)}]
        active_scans[scan_id]["error"] = str(e)
        await update_progress("Wapiti failed", 0)

    # Step 3: Skipfish
    await update_progress("Starting Skipfish", 0)
    try:
        skipfish_commands = 1 if scan_type == ScanType.LIGHT else 2
        skipfish_increment = progress_weights["skipfish"] / skipfish_commands
        skipfish_results, ai_skipfish_file = await run_skipfish(target_url, scan_type, scan_id, update_progress, skipfish_increment, timestamp)
        all_results["skipfish_info"] = skipfish_results.model_dump()
        if ai_skipfish_file:
            all_results["ai_output_files"]["skipfish"] = [ai_skipfish_file]
        await update_progress("Skipfish completed", 0)
    except Exception as e:
        print(f"Skipfish error: {e}")
        all_results["skipfish_info"] = [{"error": str(e)}]
        active_scans[scan_id]["error"] = str(e)
        await update_progress("Skipfish failed", 0)

    # Step 4: Subdomain Enumeration (Uses ROOT DOMAIN to prevent Gobuster parse error)
    await update_progress("Starting Subdomain Enumeration", 0)
    try:
        domains_for_sub_enum = [root_domain]
        live_targets_from_whatweb = [urlparse(r.target).netloc.split(':')[0] for r in whatweb_results if r.http_status == 200 and urlparse(r.target).netloc]
        domains_for_sub_enum.extend(live_targets_from_whatweb)
        
        # Deduplicate and ensure we are using root domains for the OSINT tools
        domains_for_sub_enum = list(set([get_root_domain(f"http://{d}") for d in filter(None, domains_for_sub_enum)]))
        
        all_harvester_subdomains = []
        all_gobuster_subdomains = []
        ai_harvester_files = []
        ai_gobuster_files = []
        
        if domains_for_sub_enum:
            harvester_limit = 100 if scan_type == ScanType.LIGHT else 300
            sub_enum_increment = (progress_weights["harvester"] + progress_weights["gobuster"]) / (len(domains_for_sub_enum) * 2)
            
            harvester_tasks = [run_harvester(domain, harvester_limit, scan_id, update_progress, sub_enum_increment, timestamp) for domain in domains_for_sub_enum]
            gobuster_tasks = [run_gobuster(domain, scan_id, update_progress, sub_enum_increment, timestamp) for domain in domains_for_sub_enum]
            
            harvester_raw, gobuster_raw = await asyncio.gather(
                asyncio.gather(*harvester_tasks, return_exceptions=True),
                asyncio.gather(*gobuster_tasks, return_exceptions=True)
            )
            
            for i, res in enumerate(harvester_raw):
                if isinstance(res, Exception):
                    print(f"Harvester task for {domains_for_sub_enum[i]} failed: {repr(res)}")
                else:
                    subdomains, ai_file = res
                    all_harvester_subdomains.extend(subdomains)
                    if ai_file:
                        ai_harvester_files.append(ai_file)
                        
            for i, res in enumerate(gobuster_raw):
                if isinstance(res, Exception):
                    print(f"Gobuster task for {domains_for_sub_enum[i]} failed: {repr(res)}")
                else:
                    subdomains, ai_file = res
                    all_gobuster_subdomains.extend(subdomains)
                    if ai_file:
                        ai_gobuster_files.append(ai_file)
                        
            all_results["harvester_info"] = [r.model_dump() for r in all_harvester_subdomains]
            all_results["gobuster_info"] = [r.model_dump() for r in all_gobuster_subdomains]
            if ai_harvester_files:
                all_results["ai_output_files"]["harvester"] = ai_harvester_files
            if ai_gobuster_files:
                all_results["ai_output_files"]["gobuster"] = ai_gobuster_files
                
        await update_progress("Subdomain Enumeration completed", 0)
    except Exception as e:
        print(f"Subdomain Enumeration error: {e}")
        all_results["harvester_info"] = [{"error": str(e)}]
        all_results["gobuster_info"] = [{"error": str(e)}]
        active_scans[scan_id]["error"] = str(e)
        await update_progress("Subdomain Enumeration failed", 0)

    # Step 5: Nmap Prep (Uses EXACT DOMAIN)
    await update_progress("Preparing Nmap Targets", 0)
    try:
        unique_targets = set()
        if exact_domain:
            unique_targets.add(exact_domain)
        for r in whatweb_results:
            if r.IP:
                unique_targets.add(r.IP)
        if scan_type == ScanType.DEEP:
            for r in all_harvester_subdomains + all_gobuster_subdomains:
                if r.subdomain and not r.subdomain.startswith("[IP]:"):
                    unique_targets.add(r.subdomain)
                if r.resolved_ip:
                    unique_targets.add(r.resolved_ip)
                    
        unique_targets = list(set(filter(None, unique_targets)))
        final_nmap_targets = []
        
        if unique_targets:
            with ThreadPoolExecutor(max_workers=10) as executor:
                loop = asyncio.get_event_loop()
                resolution_tasks = []
                for target_entry in unique_targets:
                    if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", target_entry):
                        resolution_tasks.append(asyncio.to_thread(lambda t=target_entry: t))
                    else:
                        resolution_tasks.append(loop.run_in_executor(executor, resolve_domain_sync, target_entry))
                resolved_ips = await asyncio.gather(*resolution_tasks, return_exceptions=True)
                for i, target_entry in enumerate(unique_targets):
                    resolved_ip = resolved_ips[i]
                    if isinstance(resolved_ip, Exception):
                        final_nmap_targets.append(target_entry)
                    elif resolved_ip:
                        final_nmap_targets.append(resolved_ip)
                    else:
                        final_nmap_targets.append(target_entry)
                        
        final_nmap_targets = list(set(filter(None, final_nmap_targets)))
        if not final_nmap_targets and exact_domain:
            resolved_base_ip = await asyncio.to_thread(resolve_domain_sync, exact_domain)
            if resolved_base_ip:
                final_nmap_targets.append(resolved_base_ip)
            else:
                final_nmap_targets.append(exact_domain)
                
        if final_nmap_targets:
            await write_lines_to_file(NMAP_TARGETS_FILE, final_nmap_targets)
        else:
            raise Exception("No valid Nmap targets could be determined")
            
        await update_progress("Nmap Targets Prepared", progress_weights["nmap_prep"])
    except Exception as e:
        print(f"Nmap Prep error: {e}")
        all_results["nmap_info"] = {"error": f"Nmap target preparation failed: {str(e)}"}
        active_scans[scan_id]["error"] = str(e)
        await update_progress("Nmap Target Prep failed", 0)

    # Step 6: Nmap Scan
    max_nmap_targets = 2
    try:
        if os.path.exists(NMAP_TARGETS_FILE) and os.stat(NMAP_TARGETS_FILE).st_size > 0:
            with open(NMAP_TARGETS_FILE, "r") as f:
                targets = [line.strip() for line in f.readlines() if line.strip()]
            limited_targets = targets[:max_nmap_targets]
            await write_lines_to_file(NMAP_TARGETS_FILE, limited_targets)
            
            nmap_commands = 6 if scan_type == ScanType.LIGHT else 8
            nmap_increment = progress_weights["nmap"] / nmap_commands
            await update_progress("Starting Nmap Scans", 0)
            
            nmap_results, ai_nmap_file = await run_nmap_scans(scan_type, scan_id, update_progress, nmap_increment, timestamp)
            all_results["nmap_info"] = nmap_results
            if ai_nmap_file:
                all_results["ai_output_files"]["nmap"] = [ai_nmap_file]
            await update_progress("Nmap Scans completed", 0)
        else:
            all_results["nmap_info"] = {"message": "No valid targets for Nmap scan."}
            await update_progress("No Nmap targets", 0)
    except Exception as e:
        print(f"Nmap Scan error: {e}")
        all_results["nmap_info"] = {"error": str(e)}
        active_scans[scan_id]["error"] = str(e)
        await update_progress("Nmap Scans failed", 0)

    # Step 7: SQLMap
    await update_progress("Starting SQLMap", 0)
    try:
        sqlmap_results, ai_sqlmap_file = await run_sqlmap(target_url, scan_type, scan_id, update_progress, progress_weights["sqlmap"], timestamp)
        all_results["sqlmap_info"] = sqlmap_results.model_dump()
        if ai_sqlmap_file:
            all_results["ai_output_files"]["sqlmap"] = [os.path.basename(ai_sqlmap_file)]
        await update_progress("SQLMap completed", 0)
    except Exception as e:
        print(f"SQLMap error: {e}")
        all_results["sqlmap_info"] = {"error": str(e)}
        active_scans[scan_id]["error"] = str(e)
        await update_progress("SQLMap failed", 0)

    active_scans[scan_id]["status"] = "completed"
    await update_progress("Scan completed", 0)
    return all_results

    