# scanners/nmap.py

import os
import re
import json
import asyncio
import xml.etree.ElementTree as ET
from typing import List, Dict, Any, Tuple, Optional

from core.config import SCAN_OUTPUT_DIR, NMAP_TARGETS_FILE, UPORTS_PATH, TPORTS_PATH
from models.schemas import NmapCipherDetail, NmapPort, NmapOSClass, NmapHost, NmapScanResult, ScanType
from utils.command_runner import run_command
from utils.file_handlers import read_file_lines
from utils.ai_analyzer import generate_ai_response

def parse_ssl_ciphers_script_output(script_output: str) -> List[NmapCipherDetail]:
    ciphers_list = []
    cipher_pattern = re.compile(
        r'^\s*(?P<name>TLS_[A-Z0-9_]+(?:_WITH_[A-Z0-9_]+)*)\s*'
        r'(?:\((?P<raw_kex_auth>[^)]+)\))?\s*'
        r'(?:(?P<bits>\d+)\s+bits)?\s*'
        r'-\s*(?P<strength>[A-Z0-9+-]+)\s*$'
    )
    lines = script_output.strip().split('\n')
    current_section = None
    
    for line in lines:
        line = line.strip()
        if line.startswith('TLSv'):
            current_section = line
        elif line.startswith('ciphers:'):
            current_section = 'ciphers'
        elif current_section == 'ciphers' and line:
            match = cipher_pattern.match(line)
            if match:
                data = match.groupdict()
                cipher_name_upper = data['name'].upper()
                raw_kex_auth = data.get('raw_kex_auth', '')
                kex_auth_raw_lower = raw_kex_auth.lower()
                kex = None
                auth = None
                
                if 'ecdh' in kex_auth_raw_lower:
                    kex = 'ECDH'
                elif 'dhe' in kex_auth_raw_lower:
                    kex = 'DHE'
                elif 'rsa' in kex_auth_raw_lower:
                    kex = 'RSA'
                    
                if 'AKE' in cipher_name_upper:
                    kex = 'AKE'
                    auth = 'AKE'
                elif 'RSA' in cipher_name_upper:
                    auth = 'RSA'
                elif 'DSS' in cipher_name_upper:
                    auth = 'DSS'
                elif 'ECDHE' in cipher_name_upper:
                    auth = 'ECDHE'
                    
                bits = None
                if data.get('bits'):
                    try:
                        bits = int(data['bits'])
                    except (ValueError, TypeError):
                        pass
                if bits is None:
                    bits_match_in_name = re.search(r'_(?P<bits_val>\d{3})_', cipher_name_upper)
                    if bits_match_in_name:
                        try:
                            bits = int(bits_match_in_name.group('bits_val'))
                        except (ValueError, TypeError):
                            pass
                            
                ciphers_list.append(NmapCipherDetail(
                    name=data['name'], kex=kex, auth=auth,
                    bits=bits, strength=data.get('strength'), raw_kex_auth=raw_kex_auth
                ))
                
    unique_ciphers = []
    seen = set()
    for cipher in ciphers_list:
        cipher_tuple = (cipher.name, cipher.kex, cipher.auth, cipher.bits, cipher.strength, cipher.raw_kex_auth)
        if cipher_tuple not in seen:
            seen.add(cipher_tuple)
            unique_ciphers.append(cipher)
    return unique_ciphers

async def parse_nmap_xml(xml_file: str) -> NmapScanResult:
    hosts = []
    try:
        tree = ET.parse(xml_file)
        root = tree.getroot()
        for host_elem in root.findall('host'):
            address_elem = host_elem.find('address')
            if address_elem is None:
                continue
            host_address = address_elem.get('addr')
            hostname_elem = host_elem.find('hostnames/hostname')
            host_hostname = hostname_elem.get('name') if hostname_elem is not None else None
            
            os_details = None
            os_classes_list = []
            for os_match_elem in host_elem.findall('os/osmatch'):
                os_details = os_match_elem.get('name')
                for os_class_elem in os_match_elem.findall('osclass'):
                    os_classes_list.append(NmapOSClass(
                        type=os_class_elem.get('type'), vendor=os_class_elem.get('vendor'),
                        osfamily=os_class_elem.get('osfamily'), osgen=os_class_elem.get('osgen'),
                        accuracy=os_class_elem.get('accuracy'), cpe=os_class_elem.get('cpe')
                    ))
                    
            ports_list = []
            for port_elem in host_elem.findall('ports/port'):
                portid = port_elem.get('portid')
                protocol = port_elem.get('protocol')
                state_elem = port_elem.find('state')
                state = state_elem.get('state') if state_elem is not None else None
                reason = state_elem.get('reason') if state_elem is not None else None
                service_elem = port_elem.find('service')
                service_name = service_elem.get('name') if service_elem is not None else None
                port_cipher_details = []
                
                for script_elem in port_elem.findall('script'):
                    script_id = script_elem.get('id')
                    script_output = script_elem.get('output')
                    if script_id == 'ssl-enum-ciphers' and script_output:
                        parsed_ciphers = parse_ssl_ciphers_script_output(script_output)
                        port_cipher_details.extend(parsed_ciphers)
                        
                ports_list.append(NmapPort(
                    portid=portid, protocol=protocol, state=state,
                    service=service_name, reason=reason, cipher_details=port_cipher_details
                ))
                
            scripts_output = {}
            for script_elem in host_elem.findall('ports/port/script'):
                try:
                    script_id = script_elem.get('id')
                    if script_id not in ['ssl-enum-ciphers']:
                        script_output = script_elem.get('output', '').strip()
                        if script_output:
                            scripts_output[script_id] = script_output
                except Exception:
                    pass
            for script_elem in host_elem.findall('hostscript/script'):
                try:
                    script_id = script_elem.get('id')
                    script_output = script_elem.get('output', '').strip()
                    if script_output:
                        scripts_output[script_id] = script_output
                except Exception:
                    pass
                    
            hosts.append(NmapHost(
                address=host_address, hostname=host_hostname, ports=ports_list,
                os_details=os_details, os_classes=os_classes_list, scripts=scripts_output
            ))
        return NmapScanResult(scan_type="generic", hosts=hosts)
    except Exception as e:
        print(f"Error parsing Nmap XML: {e}")
        return NmapScanResult(scan_type="generic")

async def nmap_run_command(commands: List[List[str]], capture_output: bool, scan_id: str, update_progress: callable, command_increment: float) -> None:
    async def execute_single_command(cmd: List[str]):
        await update_progress(f"Executing Nmap: {cmd[0]} {' '.join(cmd[1:3])}", 0)
        try:
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE if capture_output else None,
                stderr=asyncio.subprocess.PIPE if capture_output else None
            )
            stdout, stderr = await process.communicate()
            await update_progress(f"Nmap command completed: {cmd[0]} {' '.join(cmd[1:3])}", command_increment)
            if process.returncode != 0:
                error_message = f"Command failed: {' '.join(cmd)} with exit code {process.returncode}"
                if stderr:
                    error_message += f"\nStderr: {stderr.decode().strip()}"
                raise RuntimeError(error_message)
        except Exception as e:
            await update_progress(f"Nmap command failed: {str(e)}", command_increment)
            raise RuntimeError(f"Error running command '{' '.join(cmd)}': {e}")
            
    tasks = [execute_single_command(cmd) for cmd in commands]
    await asyncio.gather(*tasks)

async def run_nmap_scans(scan_type: ScanType, scan_id: str, update_progress: callable, command_increment: float, timestamp: str) -> Tuple[Dict[str, Any], Optional[str]]:
    nmap_results = {}
    target_list_path = NMAP_TARGETS_FILE
    ai_output_file = os.path.join(SCAN_OUTPUT_DIR, f"ai_nmap_output_{scan_id}_{timestamp}.json")
    
    if not os.path.exists(target_list_path) or os.stat(target_list_path).st_size == 0:
        print(f"Targets file not found or empty: {target_list_path}")
        return {}, None
        
    uports_list = await read_file_lines(UPORTS_PATH)
    uports = ",".join(uports_list) if uports_list else "53,67,68,123,137,138,139"
    tports_list = await read_file_lines(TPORTS_PATH)
    tports = ",".join(tports_list) if tports_list else "20,21,22,23,25,53,67,68,80,110,119,137,138,139,443,445,3389,8080"
    
    commands_to_run = []
    scan_keys_and_output_files = []
    
    if scan_type == ScanType.LIGHT:
        commands_to_run.extend([
            ["nmap", "-p", uports, "-sU", "-sV", "-O", "--max-retries", "3", "-iL", target_list_path, "-oX", os.path.join(SCAN_OUTPUT_DIR, "nmap1_udp_svc_os_light.xml")],
            ["nmap", "-p", tports, "-sT", "-sV", "-O", "--max-retries", "3", "-iL", target_list_path, "-oX", os.path.join(SCAN_OUTPUT_DIR, "nmap2_tcp_svc_os_light.xml")],
            ["nmap", "-sO", "--max-retries", "3", "-iL", target_list_path, "-oX", os.path.join(SCAN_OUTPUT_DIR, "nmap3_ip_protocol_light.xml")],
            ["nmap", "--script", "ssh-auth-methods", "-p", "22", "--max-retries", "3", "-iL", target_list_path, "-oX", os.path.join(SCAN_OUTPUT_DIR, "nmap4_ssh_auth_light.xml")],
            ["nmap", "--script", "ssl-enum-ciphers", "-p", "443", "--max-retries", "3", "-iL", target_list_path, "-oX", os.path.join(SCAN_OUTPUT_DIR, "nmap5_ssl_ciphers_light.xml")],
            ["nmap", "--script", "http-enum", "-p", "80", "--max-retries", "3", "-iL", target_list_path, "-oX", os.path.join(SCAN_OUTPUT_DIR, "nmap6_http_enum_light.xml")]
        ])
        scan_keys_and_output_files.extend([
            ("udp_service_os_light", os.path.join(SCAN_OUTPUT_DIR, "nmap1_udp_svc_os_light.xml")),
            ("tcp_service_os_light", os.path.join(SCAN_OUTPUT_DIR, "nmap2_tcp_svc_os_light.xml")),
            ("ip_protocol_light", os.path.join(SCAN_OUTPUT_DIR, "nmap3_ip_protocol_light.xml")),
            ("ssh_auth_methods_light", os.path.join(SCAN_OUTPUT_DIR, "nmap4_ssh_auth_light.xml")),
            ("ssl_enum_ciphers_light", os.path.join(SCAN_OUTPUT_DIR, "nmap5_ssl_ciphers_light.xml")),
            ("http_enum_light", os.path.join(SCAN_OUTPUT_DIR, "nmap6_http_enum_light.xml"))
        ])
    else:
        commands_to_run.extend([
            ["nmap", "-p", uports, "-sU", "-sV", "-O", "--max-retries", "3", "-iL", target_list_path, "-oX", os.path.join(SCAN_OUTPUT_DIR, "nmap1_udp_svc_os_deep.xml")],
            ["nmap", "-p", tports, "-sT", "-sV", "-O", "--max-retries", "3", "-iL", target_list_path, "-oX", os.path.join(SCAN_OUTPUT_DIR, "nmap2_tcp_svc_os_deep.xml")],
            ["nmap", "-sO", "--max-retries", "3", "-iL", target_list_path, "-oX", os.path.join(SCAN_OUTPUT_DIR, "nmap3_ip_protocol_deep.xml")],
            ["nmap", "--script", "ssh-auth-methods", "-p", "22", "--max-retries", "3", "-iL", target_list_path, "-oX", os.path.join(SCAN_OUTPUT_DIR, "nmap4_ssh_auth_deep.xml")],
            ["nmap", "--script", "ssl-enum-ciphers", "-p", "443", "--max-retries", "3", "-iL", target_list_path, "-oX", os.path.join(SCAN_OUTPUT_DIR, "nmap5_ssl_ciphers_deep.xml")],
            ["nmap", "--script", "http-enum", "-p", "80", "--max-retries", "3", "-iL", target_list_path, "-oX", os.path.join(SCAN_OUTPUT_DIR, "nmap6_http_enum_deep.xml")],
            ["nmap", "--script", "vulners", "--max-retries", "3", "-iL", target_list_path, "-oX", os.path.join(SCAN_OUTPUT_DIR, "nmap7_vulners_deep.xml")],
            ["nmap", "--script", "vuln", "--max-retries", "3", "-iL", target_list_path, "-oX", os.path.join(SCAN_OUTPUT_DIR, "nmap8_vuln_deep.xml")]
        ])
        scan_keys_and_output_files.extend([
            ("udp_service_os_deep", os.path.join(SCAN_OUTPUT_DIR, "nmap1_udp_svc_os_deep.xml")),
            ("tcp_service_os_deep", os.path.join(SCAN_OUTPUT_DIR, "nmap2_tcp_svc_os_deep.xml")),
            ("ip_protocol_deep", os.path.join(SCAN_OUTPUT_DIR, "nmap3_ip_protocol_deep.xml")),
            ("ssh_auth_methods_deep", os.path.join(SCAN_OUTPUT_DIR, "nmap4_ssh_auth_deep.xml")),
            ("ssl_enum_ciphers_deep", os.path.join(SCAN_OUTPUT_DIR, "nmap5_ssl_ciphers_deep.xml")),
            ("http_enum_deep", os.path.join(SCAN_OUTPUT_DIR, "nmap6_http_enum_deep.xml")),
            ("vulners_deep", os.path.join(SCAN_OUTPUT_DIR, "nmap7_vulners_deep.xml")),
            ("vuln_deep", os.path.join(SCAN_OUTPUT_DIR, "nmap8_vuln_deep.xml"))
        ])
        
    try:
        for i, (cmd, (key, output_file)) in enumerate(zip(commands_to_run, scan_keys_and_output_files)):
            await update_progress(f"Executing Nmap scan {i+1}/{len(commands_to_run)}: {cmd[0]} {' '.join(cmd[1:3])}", 0)
            await run_command(cmd, capture_output=False)
            await update_progress(f"Nmap scan {i+1}/{len(commands_to_run)} completed", command_increment)
            
            if os.path.exists(output_file):
                parsed_data = await parse_nmap_xml(output_file)
                parsed_data.scan_type = key
                nmap_results[key] = parsed_data.model_dump()
            else:
                nmap_results[key] = {"error": "Output file not generated"}
                
        if nmap_results:
            output_filename = os.path.join(SCAN_OUTPUT_DIR, 'nmap_results.json')
            with open(output_filename, 'w', encoding='utf-8') as f_ou:
                json.dump(nmap_results, f_ou, indent=4)

            # ai_response = await generate_ai_response("Nmap", nmap_results, target_list_path)
            # with open(ai_output_file, 'w', encoding='utf-8') as f_out:
            #     json.dump(ai_response, f_out, indent=4)
                
            return nmap_results,None
        # ai_output_file
        
        # If Nmap generated absolutely no results, return None for the file path
        return {}, None
    
    except Exception as e:
        print(f"Error during Nmap scans: {e}")
        for key, _ in scan_keys_and_output_files:
            nmap_results[key] = {"error": str(e)}
        return nmap_results, None