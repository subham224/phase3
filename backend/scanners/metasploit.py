import asyncio
import json
from pathlib import Path
from core.config import SCAN_OUTPUT_DIR


async def run_msf_command(command: str):

    process = await asyncio.create_subprocess_exec(
        "msfconsole",
        "-q",
        "-x",
        command,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE
    )

    stdout, stderr = await process.communicate()

    return stdout.decode() + stderr.decode()


async def execute_commands(commands, scan_id):

    results = []

    output_dir = Path(SCAN_OUTPUT_DIR) / "metasploit"
    output_dir.mkdir(parents=True, exist_ok=True)

    for cmd in commands:

        raw_output = await run_msf_command(cmd["command"])

        results.append({
            "command_executed": cmd["command"],
            "raw_output": raw_output
        })

    result_file = output_dir / f"ms_scan_results_{scan_id}.json"

    with open(result_file, "w") as f:
        json.dump(results, f, indent=2)

    return results