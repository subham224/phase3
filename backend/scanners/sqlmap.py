# scanners/sqlmap.py

import os
import re
import csv
import json
import glob
from typing import Tuple, Optional
from urllib.parse import urlparse

from core.config import SCAN_OUTPUT_DIR
from models.schemas import SqlmapScanResult, SqlmapVulnerability, ScanType
from utils.command_runner import run_command
from utils.ai_analyzer import generate_ai_response

async def run_sqlmap(target: str, scan_type: ScanType, scan_id: str, update_progress: callable, command_increment: float, timestamp: str) -> Tuple[SqlmapScanResult, Optional[str]]:
    target_sanitized = re.sub(r'[^a-zA-Z0-9.-]', '_', target).strip('_')
    sqlmap_output_dir = os.path.join(SCAN_OUTPUT_DIR, f"sqlmap_{target_sanitized}")
    filtered_output_file = os.path.join(SCAN_OUTPUT_DIR, f"sqlmap_filtered_{target_sanitized}_{timestamp}.json")
    ai_output_file = os.path.join(SCAN_OUTPUT_DIR, f"ai_sqlmap_output_{target_sanitized}_{timestamp}.json")
    
    # We use --output-dir to force the CSV/logs into our local scans folder
    command = [
        "sqlmap", "-u", target, 
        "--crawl=3", "--forms", "--batch", 
        "--threads=10", "--time-sec=3", 
        "--risk=3", "--level=3", 
        "--tamper=between", "--flush-session",
        "--output-dir", sqlmap_output_dir
    ]
    
    await update_progress(f"Executing SQLMap", 0)
    print(f"Executing command: {' '.join(command)}")
    
    try:
        # Run the command
        await run_command(command, capture_output=False)
        await update_progress("SQLMap command completed", command_increment)
        
        # Locate the CSV file inside the sqlmap output directory
        # Sqlmap creates a folder named after the domain
        domain = urlparse(target).netloc.split(':')[0]
        target_dir = os.path.join(sqlmap_output_dir, domain)
        
        vulns = []
        
        # Search for any CSV file generated in the target directory
        csv_files = glob.glob(os.path.join(target_dir, "*.csv"))
        
        if csv_files:
            # Grab the most recently created CSV
            latest_csv = max(csv_files, key=os.path.getctime)
            print(f"Parsing SQLMap CSV: {latest_csv}")
            
            with open(latest_csv, mode='r', encoding='utf-8', errors='ignore') as csv_file:
                reader = csv.DictReader(csv_file)
                for row in reader:
                    # Map CSV columns to our schema (adjust keys if your CSV headers differ)
                    vulns.append(SqlmapVulnerability(
                        parameter=row.get('Parameter', row.get('Place', 'Unknown')),
                        type=row.get('Type', 'Unknown'),
                        title=row.get('Title', 'Unknown'),
                        payload=row.get('Payload', 'Unknown')
                    ))
        
        # If no CSV was generated, sqlmap found no injectable parameters
        if vulns:
            with open(filtered_output_file, 'w', encoding='utf-8') as f_out:
                json.dump([v.model_dump() for v in vulns], f_out, indent=4)
                
            # Generate AI response
            ai_response = await generate_ai_response("SQLMap", [v.model_dump() for v in vulns], target)
            with open(ai_output_file, 'w', encoding='utf-8') as f_out:
                json.dump(ai_response, f_out, indent=4)
                
            return SqlmapScanResult(vulnerabilities=vulns), ai_output_file
            
        return SqlmapScanResult(vulnerabilities=[]), None
        
    except Exception as e:
        print(f"Error running SQLMap: {e}")
        await update_progress(f"SQLMap failed: {str(e)}", command_increment)
        return SqlmapScanResult(), None