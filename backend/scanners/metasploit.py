#metasploit.py
import asyncio
import json
from pathlib import Path
from core.config import SCAN_OUTPUT_DIR

async def run_msf_command(command: str):
    try:
        process = await asyncio.create_subprocess_exec(
            "msfconsole",
            "-q",
            "-x",
            command,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        
        # Add a timeout so hung exploits don't freeze the server
        stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=240.0)
        return stdout.decode(errors='ignore') + stderr.decode(errors='ignore')
        
    except asyncio.TimeoutError:
        try:
            process.kill()
        except:
            pass
        return f"[-] Execution timed out after 60 seconds."
    except Exception as e:
        return f"[-] Execution error: {str(e)}"

async def execute_commands(commands, scan_id):
    results = []
    output_dir = Path(SCAN_OUTPUT_DIR) / "metasploit"
    output_dir.mkdir(parents=True, exist_ok=True)

    for cmd in commands:
        # Extract the command string safely
        command_str = cmd.get("command", "")
        if not command_str:
            continue
            
        raw_output = await run_msf_command(command_str)

        # Structure exactly as requested in objective
        results.append({
            "command_executed": command_str,
            "raw_output": raw_output.strip()
        })

    result_file = output_dir / f"ms_scan_results_{scan_id}.json"

    with open(result_file, "w", encoding='utf-8') as f:
        json.dump(results, f, indent=2)

    return results