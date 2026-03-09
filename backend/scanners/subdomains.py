import os
import re
import json
import asyncio
from typing import List, Tuple, Optional, Callable

from core.config import SCAN_OUTPUT_DIR, WORDLIST_PATH
from models.schemas import SubdomainResult
from utils.file_handlers import clean_domain


# ==========================================================
# THE HARVESTER
# ==========================================================
async def run_harvester(
    domain: str,
    limit: int,
    scan_id: str,
    update_progress: Callable,
    command_increment: float,
    timestamp: str
) -> Tuple[List[SubdomainResult], Optional[str]]:

    n_domain = clean_domain(domain)

    # 🔒 Per-scan directory isolation (prevents contamination)
    scan_dir = os.path.join(SCAN_OUTPUT_DIR, scan_id)
    os.makedirs(scan_dir, exist_ok=True)

    harvester_base_name = f"harvester_output_{n_domain.replace('.', '_')}"
    raw_output_file = os.path.join(scan_dir, f"{harvester_base_name}.json")
    filtered_output_file = os.path.join(scan_dir, f"harvester_filtered_{n_domain.replace('.', '_')}.json")

    # 🧹 Remove stale file if exists
    if os.path.exists(raw_output_file):
        os.remove(raw_output_file)

    command = [
        "theHarvester",
        "-d", n_domain,
        "-b", "crtsh,certspotter",
        "-l", str(limit),
        "-f", harvester_base_name
    ]

    subdomains: List[SubdomainResult] = []

    await update_progress("Executing theHarvester...", 0)
    print(f"Executing theHarvester command: {' '.join(command)}")

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
                timeout=180
            )
        except asyncio.TimeoutError:
            process.kill()
            await update_progress("theHarvester timed out", command_increment)
            return [], "theHarvester timeout"

        await update_progress("theHarvester command completed", command_increment)

        if process.returncode != 0:
            print(f"[theHarvester] Exit code: {process.returncode}")
            if stderr:
                print(stderr.decode(errors="ignore"))

        # Ensure file exists
        if not os.path.exists(raw_output_file):
            return [], None

        if os.path.getsize(raw_output_file) == 0:
            return [], None

        # Parse JSON safely
        with open(raw_output_file, "r", encoding="utf-8") as f:
            try:
                data = json.load(f)
            except json.JSONDecodeError:
                print("Invalid JSON from theHarvester")
                return [], "Invalid JSON"

        # 🛡️ Domain validation (prevents stale file parsing)
        cmd_string = data.get("cmd", "")
        if n_domain not in cmd_string:
            print("Stale theHarvester output detected — ignoring.")
            return [], None

        # ✅ Correct host parsing (IPv4 + IPv6 safe)
        for host in data.get("hosts", []):
            parts = host.strip().split()

            sub = parts[0]
            resolved_ip = None

            if len(parts) > 1:
                resolved_ip = parts[1]

            subdomains.append(
                SubdomainResult(
                    subdomain=sub,
                    source="harvester",
                    resolved_ip=resolved_ip
                )
            )

        # Some versions also provide separate IPs
        for ip in data.get("ips", []):
            ip = ip.strip()
            subdomains.append(
                SubdomainResult(
                    subdomain=f"[IP]:{ip}",
                    source="harvester",
                    resolved_ip=ip
                )
            )

        # Save filtered output
        if subdomains:
            with open(filtered_output_file, "w", encoding="utf-8") as f_out:
                json.dump(
                    [s.model_dump() for s in subdomains],
                    f_out,
                    indent=4
                )

        return subdomains, None

    except Exception as e:
        print(f"Error running theHarvester: {e}")
        await update_progress(f"theHarvester failed: {str(e)}", command_increment)
        return [], str(e)


# ==========================================================
# GOBUSTER DNS
# ==========================================================
async def run_gobuster(
    domain: str,
    scan_id: str,
    update_progress: Callable,
    command_increment: float,
    timestamp: str
) -> Tuple[List[SubdomainResult], Optional[str]]:

    n_domain = clean_domain(domain)

    # 🔒 Per-scan directory isolation
    scan_dir = os.path.join(SCAN_OUTPUT_DIR, scan_id)
    os.makedirs(scan_dir, exist_ok=True)

    raw_output_file = os.path.join(scan_dir, f"gobuster_raw_{n_domain.replace('.', '_')}.txt")
    filtered_output_file = os.path.join(scan_dir, f"gobuster_filtered_{n_domain.replace('.', '_')}.json")

    # command = [
    #     "gobuster",
    #     "dns",
    #     "-d", n_domain,
    #     "-w", WORDLIST_PATH,
    #     "-t", "50",
    #     "-q"
    # ]
    command = ["gobuster", "dns", "-q", "--domain", n_domain, "-w", WORDLIST_PATH, "-t", "50", "--wildcard", "--resolver", "8.8.8.8", "--timeout", "3s"]

    subdomains: List[SubdomainResult] = []

    await update_progress("Executing Gobuster...", 0)
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
                timeout=300
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

        # Save raw output
        with open(raw_output_file, "w", encoding="utf-8") as f:
            f.write(decoded_stdout)

        # ✅ Compatible with Gobuster v3+ DNS output
        for line in decoded_stdout.splitlines():
            sub = line.strip()

            if not sub:
                continue
            if sub.startswith("#"):
                continue

            # Remove trailing status info if exists
            sub = sub.split()[0]

            subdomains.append(
                SubdomainResult(
                    subdomain=sub,
                    source="gobuster",
                    resolved_ip=None
                )
            )

        # Save filtered
        if subdomains:
            with open(filtered_output_file, "w", encoding="utf-8") as f_out:
                json.dump(
                    [s.model_dump() for s in subdomains],
                    f_out,
                    indent=4
                )

        return subdomains, None

    except Exception as e:
        print(f"Error running Gobuster: {e}")
        await update_progress(f"Gobuster failed: {str(e)}", command_increment)
        return [], str(e)