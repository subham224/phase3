# utils/file_handlers.py

import os
import shutil
import socket
from typing import List, Optional
import tldextract

from core.config import SCAN_OUTPUT_DIR

async def clear_scan_outputs():
    """Clears all temporary output files in the scans directory."""
    if os.path.exists(SCAN_OUTPUT_DIR):
        print(f"Clearing contents of {SCAN_OUTPUT_DIR}...")
        for filename in os.listdir(SCAN_OUTPUT_DIR):
            file_path = os.path.join(SCAN_OUTPUT_DIR, filename)
            try:
                if os.path.isfile(file_path) or os.path.islink(file_path):
                    os.unlink(file_path)
                elif os.path.isdir(file_path):
                    shutil.rmtree(file_path)
            except Exception as e:
                print(f"Failed to delete {file_path}. Reason: {e}")
        print("Scan outputs cleared.")
    else:
        os.makedirs(SCAN_OUTPUT_DIR)

async def read_file_lines(file_path: str) -> List[str]:
    """Reads lines from a file, stripping whitespace and empty lines."""
    lines = []
    if os.path.exists(file_path):
        with open(file_path, 'r') as f:
            for line in f:
                stripped_line = line.strip()
                if stripped_line:
                    lines.append(stripped_line)
    return lines

async def write_lines_to_file(file_path: str, lines: List[str]):
    """Writes a list of strings to a file, each on a new line."""
    with open(file_path, 'w') as f:
        for line in lines:
            f.write(f"{line}\n")

def resolve_domain_sync(domain: str) -> Optional[str]:
    """Attempts to resolve a domain to an IP address (synchronous)."""
    try:
        ip = socket.gethostbyname(domain)
        return ip
    except socket.gaierror:
        return None

def clean_domain(domain: str) -> str:
    """Removes http://, https://, www., and trailing slashes from the domain string."""
    # Strip whitespace and trailing slashes first
    domain = domain.strip().strip('/')
    
    if domain.startswith("http://"):
        domain = domain[len("http://"):]
    elif domain.startswith("https://"):
        domain = domain[len("https://"):]
        
    if domain.startswith("www."):
        domain = domain[len("www."):]
        
    return domain.strip().strip('/')

def get_root_domain(url: str) -> str:
    """
    Extracts the root registered domain (e.g., 'flipkart.com' from 'https://flipkart.com').
    This prevents Gobuster/theHarvester parse errors.
    """
    extracted = tldextract.extract(url)
    if extracted.domain and extracted.suffix:
        return f"{extracted.domain}.{extracted.suffix}"
    return clean_domain(url) # Fallback if extraction fails