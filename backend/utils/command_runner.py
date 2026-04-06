# utils/command_runner.py

import asyncio
from typing import List, Optional

async def run_command(command: List[str], capture_output: bool = True, cwd: Optional[str] = None) -> Optional[str]:
    """Runs a shell command and optionally captures its output."""
    print(f"Executing command: {' '.join(command)}")
    try:
        if capture_output:
            process = await asyncio.create_subprocess_exec(
                *command,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                cwd=cwd
            )
            stdout, stderr = await process.communicate()
            if process.returncode != 0:
                print(f"Command failed with error: {stderr.decode()}")
                raise Exception(f"Command '{' '.join(command)}' failed with exit code {process.returncode}: {stderr.decode()}")
            return stdout.decode().strip()
        else:
            process = await asyncio.create_subprocess_exec(
                *command,
                stdout=asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.PIPE,
                cwd=cwd
            )
            _, stderr = await process.communicate()
            if process.returncode != 0:
                print(f"Command failed with error: {stderr.decode()}")
                raise Exception(f"Command '{' '.join(command)}' failed with exit code {process.returncode}: {stderr.decode()}")
            return None
    except FileNotFoundError:
        raise Exception(f"Tool not found: {command[0]}. Please ensure it's installed and in your PATH.")
    except Exception as e:
        raise Exception(f"Error running command '{' '.join(command)}': {e}")