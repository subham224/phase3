import os
from dotenv import load_dotenv

load_dotenv()

# Gemini Config
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")

# Paths
SCAN_OUTPUT_DIR = "scans/"
os.makedirs(SCAN_OUTPUT_DIR, exist_ok=True)

NMAP_TARGETS_FILE = os.path.join(SCAN_OUTPUT_DIR, "targets.txt")
UPORTS_PATH = "uports.txt"
TPORTS_PATH = "tports.txt"
WORDLIST_PATH = "/home/subham/SecLists/Discovery/DNS/subdomains-top1million-20000.txt"
MINIMAL_WL_PATH = "/home/subham/skipfish/dictionaries/minimal.wl"
COMPLETE_WL_PATH = "/home/subham/skipfish/dictionaries/complete.wl"
EXTENSIONS_WL_PATH = "/home/subham/skipfish/dictionaries/extensions-only.wl"
SKIPFISH_DUMMY_TXT = os.path.join(SCAN_OUTPUT_DIR, "dummy.txt")
SKIPFISH_INDEX_HTML_PATH = "/home/subham/globalai/backend/scans/skipfish/index.html"
SKIPFISH_ISSUE_DESCRIPTIONS_JSON_PATH = "/home/subham/issue_descriptions.json"