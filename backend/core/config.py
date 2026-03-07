import os
from dotenv import load_dotenv
from pathlib import Path

load_dotenv()

BASE_DIR = Path(__file__).resolve().parent.parent

# Gemini Config
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")

# Paths
SCAN_OUTPUT_DIR = os.path.join(BASE_DIR, "scans")
os.makedirs(SCAN_OUTPUT_DIR, exist_ok=True)

NMAP_TARGETS_FILE = os.path.join(SCAN_OUTPUT_DIR, "targets.txt")
UPORTS_PATH = os.path.join(BASE_DIR, "uports.txt")
TPORTS_PATH = os.path.join(BASE_DIR, "tports.txt")

# Wordlists
WORDLIST_DIR = os.path.join(BASE_DIR, "wordlists")
WORDLIST_PATH = os.path.join(WORDLIST_DIR, "subdomains-top1million-20000.txt")
MINIMAL_WL_PATH = os.path.join(WORDLIST_DIR, "minimal.wl")
COMPLETE_WL_PATH = os.path.join(WORDLIST_DIR, "complete.wl")
EXTENSIONS_WL_PATH = os.path.join(WORDLIST_DIR, "extensions-only.wl")

# Skipfish
SKIPFISH_DUMMY_TXT = os.path.join(SCAN_OUTPUT_DIR, "dummy.txt")
SKIPFISH_INDEX_HTML_PATH = os.path.join(SCAN_OUTPUT_DIR, "skipfish", "index.html")


SKIPFISH_ISSUE_DESCRIPTIONS_JSON_PATH = os.path.join(WORDLIST_DIR, "issue_descriptions.json")