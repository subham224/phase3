# models/schemas.py

from pydantic import BaseModel, Field, HttpUrl
from typing import List, Dict, Any, Optional, Literal
from enum import Enum

# --- WhatWeb Models ---
class WhatWebResult(BaseModel):
    target: str
    http_status: int
    HTTPServer: Optional[str] = None
    IP: Optional[str] = None
    UncommonHeaders: Optional[List[str]] = None
    X_Frame_Options: Optional[str] = Field(None, alias="X-Frame-Options")
    X_Powered_By: Optional[List[str]] = Field(None, alias="X-Powered-By")
    MetaGenerator: Optional[str] = None
    Title: Optional[str] = None
    X_XSS_Protection: Optional[str] = Field(None, alias="X-XSS-Protection")


# --- Subdomain Models ---
class SubdomainResult(BaseModel):
    subdomain: str
    source: str
    resolved_ip: Optional[str] = None


# --- Nmap Models ---
class NmapCipherDetail(BaseModel):
    name: str
    kex: Optional[str] = None
    auth: Optional[str] = None
    bits: Optional[int] = None
    strength: Optional[str] = None
    raw_kex_auth: Optional[str] = None

class NmapPort(BaseModel):
    portid: str
    protocol: str
    state: str
    service: Optional[str] = None
    version: Optional[str] = None
    reason: Optional[str] = None
    cipher_details: List[NmapCipherDetail] = []

class NmapOSClass(BaseModel):
    type: Optional[str] = None
    vendor: Optional[str] = None
    osfamily: Optional[str] = None
    osgen: Optional[str] = None
    accuracy: Optional[str] = None
    cpe: Optional[str] = None

class NmapHost(BaseModel):
    address: str
    hostname: Optional[str] = None
    ports: List[NmapPort] = []
    os_details: Optional[str] = None
    os_classes: List[NmapOSClass] = []
    scripts: Optional[Dict[str, Any]] = {}

class NmapScanResult(BaseModel):
    scan_type: str
    hosts: List[NmapHost] = []


# --- Wapiti Models ---
class WapitiVulnerability(BaseModel):
    info: str

class WapitiScanResult(BaseModel):
    vulnerabilities: List[WapitiVulnerability] = []


# --- Skipfish Models ---
class SkipfishIssueSample(BaseModel):
    severity: str
    type: str
    url: str

class SkipfishScanResult(BaseModel):
    issue_samples: List[SkipfishIssueSample] = []


# --- Enum Models ---
class ScanType(str, Enum):
    LIGHT = "light"
    DEEP = "deep"


# --- Request and Response API Models ---
class ScanRequest(BaseModel):
    target: HttpUrl
    scan_type: Literal["light_scan", "deep_scan"]
    scan_id: str

class ScanResponse(BaseModel):
    whatweb_info: List[Dict]
    harvester_info: List[Dict]
    gobuster_info: List[Dict]
    nmap_info: Dict
    wapiti_info: Dict
    skipfish_info: Dict
    ai_output_files: Dict[str, List[str]]

class ScanSummaryRequest(BaseModel):
    scanSummary: List[Dict[str, Any]]

# Add this near your other result models in models/schemas.py

class SqlmapVulnerability(BaseModel):
    parameter: Optional[str] = "Unknown"
    type: Optional[str] = "Unknown"
    title: Optional[str] = "Unknown"
    payload: Optional[str] = "Unknown"

class SqlmapScanResult(BaseModel):
    vulnerabilities: List[SqlmapVulnerability] = []


# --- Metasploit Models ---

class MetasploitCommand(BaseModel):
    command: str


class MetasploitExecution(BaseModel):
    command_executed: str
    raw_output: str


class MetasploitReport(BaseModel):
    Vulnerability: str
    Description: str
    Impact: str
    Sensitive_information_found: str
    Remediation: str

# --- Update your existing ScanResponse model to include sqlmap ---
class ScanResponse(BaseModel):
    whatweb_info: List[Dict]
    harvester_info: List[Dict]
    gobuster_info: List[Dict]
    nmap_info: Dict
    wapiti_info: Dict
    skipfish_info: Dict
    sqlmap_info: Dict
    metasploit_info: Dict   # NEW
    ai_output_files: Dict[str, List[str]]

