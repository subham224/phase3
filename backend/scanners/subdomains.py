import os
import asyncio
from typing import List, Tuple, Optional, Callable

from core.config import SCAN_OUTPUT_DIR
from models.schemas import SubdomainResult
from utils.file_handlers import clean_domain


# ==========================================================
# SUBLIST3R (Replaces theHarvester)
# ==========================================================
async def run_sublist3r(
    domain: str,
    limit: int, # Kept for signature compatibility, though Sublist3r doesn't use it directly
    scan_id: str,
    update_progress: Callable,
    command_increment: float,
    timestamp: str
) -> Tuple[List[SubdomainResult], Optional[str]]:

    n_domain = clean_domain(domain)

    # 🔒 Per-scan directory isolation (prevents contamination)
    scan_dir = os.path.join(SCAN_OUTPUT_DIR, scan_id)
    os.makedirs(scan_dir, exist_ok=True)

    raw_output_file = os.path.join(scan_dir, f"sublister_{n_domain.replace('.', '_')}.txt")

    # 🧹 Remove stale file if exists
    if os.path.exists(raw_output_file):
        os.remove(raw_output_file)

    command = [
        "sublist3r",
        "-d", n_domain,
        "-e", "baidu,yahoo,google,bing,ask,netcraft,threatcrowd,ssl,passivedns",
        "-o", raw_output_file
    ]

    subdomains: List[SubdomainResult] = []

    await update_progress("Executing Sublist3r...", 0)
    print(f"Executing Sublist3r command: {' '.join(command)}")

    try:
        process = await asyncio.create_subprocess_exec(
            *command,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            cwd=scan_dir
        )

        try:
            stdout, stderr = await asyncio.wait_for(
                process.communicate(),
                timeout=300 # Sublist3r can take a while
            )
        except asyncio.TimeoutError:
            process.kill()
            await update_progress("Sublist3r timed out", command_increment)
            return [], "Sublist3r timeout"

        await update_progress("Sublist3r command completed", command_increment)

        if process.returncode != 0:
            print(f"[Sublist3r] Exit code: {process.returncode}")
            if stderr:
                print(stderr.decode(errors="ignore"))

        # Ensure file exists and isn't empty
        if not os.path.exists(raw_output_file) or os.path.getsize(raw_output_file) == 0:
            return [], None

        # Parse Sublist3r plain text output
        with open(raw_output_file, "r", encoding="utf-8") as f:
            for line in f:
                sub = line.strip()
                if sub and not sub.startswith("Error"): # basic validation
                    subdomains.append(
                        SubdomainResult(
                            subdomain=sub,
                            source="sublist3r",
                            resolved_ip=None # Sublist3r plain text output doesn't include IPs
                        )
                    )

        return subdomains, None

    except Exception as e:
        print(f"Error running Sublist3r: {e}")
        await update_progress(f"Sublist3r failed: {str(e)}", command_increment)
        return [], str(e)


# ==========================================================
# GOBUSTER DIR (Replaces Gobuster DNS)
# ==========================================================
# async def run_gobuster(
#     domain: str,
#     scan_id: str,
#     update_progress: Callable,
#     command_increment: float,
#     timestamp: str
# ) -> Tuple[List[SubdomainResult], Optional[str]]:

#     n_domain = clean_domain(domain)
#     target_url = f"http://{n_domain}" # Gobuster dir requires a full URL

#     # 🔒 Per-scan directory isolation
#     scan_dir = os.path.join(SCAN_OUTPUT_DIR, scan_id)
#     os.makedirs(scan_dir, exist_ok=True)

#     raw_output_file = os.path.join(scan_dir, f"gobuster_raw_{n_domain.replace('.', '_')}.txt")
    
#     # Wordlist path provided in your requirements
#     custom_wordlist = "/home/subham/Downloads/slh.txt"

#     command = [
#         "gobuster", "dir",
#         "-u", target_url,
#         "-w", custom_wordlist,
#         "-b", "400,403,404",
#         "-t", "100",
#         "-r",
#         "-q" # Quiet mode to remove banners and make stdout parsing cleaner
#     ]

#     results: List[SubdomainResult] = []

#     await update_progress("Executing Gobuster Directory Scan...", 0)
#     print(f"Executing Gobuster command: {' '.join(command)}")

#     try:
#         process = await asyncio.create_subprocess_exec(
#             *command,
#             stdout=asyncio.subprocess.PIPE,
#             stderr=asyncio.subprocess.PIPE
#         )

#         try:
#             stdout, stderr = await asyncio.wait_for(
#                 process.communicate(),
#                 timeout=600 # Dir busting takes longer than DNS
#             )
#         except asyncio.TimeoutError:
#             process.kill()
#             await update_progress("Gobuster timed out", command_increment)
#             return [], "Gobuster timeout"

#         await update_progress("Gobuster command completed", command_increment)

#         if process.returncode != 0:
#             print(f"[Gobuster] Exit code: {process.returncode}")
#             if stderr:
#                 print(stderr.decode(errors="ignore"))

#         if not stdout:
#             return [], None

#         decoded_stdout = stdout.decode(errors="ignore").strip()

#         # Save raw output
#         with open(raw_output_file, "w", encoding="utf-8") as f:
#             f.write(decoded_stdout)

#         # Parse output - Replicating `awk '{print $1}'`
#         # Gobuster dir output usually looks like: /admin (Status: 200)
#         for line in decoded_stdout.splitlines():
#             line = line.strip()
#             if not line or line.startswith("="):
#                 continue
            
#             # Split the line by spaces and grab the first element (the path)
#             parts = line.split()
#             if parts:
#                 path = parts[0]
#                 results.append(
#                     SubdomainResult(
#                         subdomain=path, # Storing path in subdomain field to match current schema
#                         source="gobuster_dir",
#                         resolved_ip=None
#                     )
#                 )

#         return results, None

#     except Exception as e:
#         print(f"Error running Gobuster: {e}")
#         await update_progress(f"Gobuster failed: {str(e)}", command_increment)
#         return [], str(e)


# # ==========================================================
# GOBUSTER DIR (Updated Strict Parser)
# ==========================================================
async def run_gobuster(
    domain: str,
    scan_id: str,
    update_progress: Callable,
    command_increment: float,
    timestamp: str
) -> Tuple[List[SubdomainResult], Optional[str]]:

    n_domain = clean_domain(domain)
    target_url = f"http://{n_domain}" # Gobuster dir requires a full URL

    # 🔒 Per-scan directory isolation
    scan_dir = os.path.join(SCAN_OUTPUT_DIR, scan_id)
    os.makedirs(scan_dir, exist_ok=True)

    raw_output_file = os.path.join(scan_dir, f"gobuster_raw_{n_domain.replace('.', '_')}.txt")
    
    # Wordlist path provided in your requirements
    custom_wordlist = "/home/subham/Downloads/slh.txt"

    command = [
        "gobuster", "dir",
        "-u", target_url,
        "-w", custom_wordlist,
        "-b", "400,403,404",
        "-t", "100",
        "-r"
    ]

    results: List[SubdomainResult] = []

    await update_progress("Executing Gobuster Directory Scan...", 0)
    print(f"Executing Gobuster command: {' '.join(command)}")

    try:
        process = await asyncio.create_subprocess_exec(
            *command,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )

        try:
            stdout, stderr = await asyncio.wait_for(
                process.communicate(),
                timeout=600 # Dir busting takes longer
            )
        except asyncio.TimeoutError:
            process.kill()
            await update_progress("Gobuster timed out", command_increment)
            return [], "Gobuster timeout"

        await update_progress("Gobuster command completed", command_increment)

        if process.returncode != 0:
            print(f"[Gobuster] Exit code: {process.returncode}")
            if stderr:
                print(stderr.decode(errors="ignore"))

        if not stdout:
            return [], None

        decoded_stdout = stdout.decode(errors="ignore").strip()

        # Save raw output just in case
        with open(raw_output_file, "w", encoding="utf-8") as f:
            f.write(decoded_stdout)

        # 🧠 STRICT PARSING LOGIC FOR GOBUSTER BANNERS
        is_scanning_phase = False

        for line in decoded_stdout.splitlines():
            line = line.strip()
            
            # 1. Skip empty lines and separator lines
            if not line or line.startswith("="):
                continue
                
            # 2. Track where the actual results begin and end
            if line.startswith("Starting"):
                is_scanning_phase = True
                continue
            if line.startswith("Finished"):
                is_scanning_phase = False
                continue
                
            # 3. ONLY process lines if we are actively in the scanning phase
            if is_scanning_phase:
                # 4. Just in case Gobuster prints an error/info mid-scan
                if not line.startswith("[+]") and not line.startswith("Error"):
                    # Grab just the path, ignoring (Status: 200) [Size: 107]
                    path = line.split()[0]
                    results.append(
                        SubdomainResult(
                            subdomain=path, # Storing path in subdomain field
                            source="gobuster_dir",
                            resolved_ip=None
                        )
                    )

        return results, None

    except Exception as e:
        print(f"Error running Gobuster: {e}")
        await update_progress(f"Gobuster failed: {str(e)}", command_increment)
        return [], str(e)