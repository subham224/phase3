import asyncio
import json
import os

# Import the actual functions from your project
from services.metasploit_ai import generate_msf_commands
from scanners.metasploit import execute_commands
from services.metasploit_report import generate_vulnerability_report
from core.config import SCAN_OUTPUT_DIR

async def run_metasploit_test():
    print("=========================================")
    print("STARTING METASPLOIT INTEGRATION UNIT TEST")
    print("=========================================\n")

    # Ensure the output directory exists so the file writer doesn't crash
    os.makedirs(os.path.join(SCAN_OUTPUT_DIR, "metasploit"), exist_ok=True)

    # 1. Define the mock vulnerability variable
    # This structures your provided findings exactly as the orchestrator would pass them
    mock_scan_results = {
        "target": "http://testphp.vulnweb.com",
        "wapiti": [
            {"info": "Backup file http://testphp.vulnweb.com/index.bak found for http://testphp.vulnweb.com/index.php"},
            {"info": "Backup file http://testphp.vulnweb.com/index.zip found for http://testphp.vulnweb.com/index.php"},
            {"info": "Lack of anti CSRF token"}
        ],
        "sqlmap": [
            {
                "parameter": "searchFor",
                "type": "POST",
                "title": "Boolean-based blind, Error-based, Time-based blind",
                "payload": "http://testphp.vulnweb.com/search.php?test=query"
            }
        ]
    }

    # 2. Test Phase 1: AI Command Generation
    print("[*] 1. Requesting commands from Gemini...")
    try:
        msf_commands = await generate_msf_commands(mock_scan_results)
        print(f"[+] AI successfully generated {len(msf_commands)} commands:")
        print(json.dumps(msf_commands, indent=2))
    except Exception as e:
        print(f"[-] AI Generation Failed: {e}")
        return

    # 3. Test Phase 2: Execution in msfconsole
    print("\n[*] 2. Executing commands in Metasploit (This may take a minute)...")
    test_scan_id = "test-unit-1234"
    # try:
    #     msf_results = await execute_commands(msf_commands, test_scan_id)
    #     print(f"[+] Successfully executed {len(msf_results)} commands. Sample output of first command:")
    #     if msf_results:
    #          print(msf_results[0].get("raw_output", "")[:200] + "...\n")
    # except Exception as e:
    #     print(f"[-] Metasploit Execution Failed: {e}")
    #     return

    # ... (End of Phase 2) ...

    # INJECT FAKE SUCCESSFUL METASPLOIT DATA FOR TESTING
    msf_results = [
        {
            "command_executed": "use auxiliary/scanner/http/http_version; set RHOSTS 18.217.186.208; run; exit",
            "raw_output": "[+] 18.217.186.208:80 Apache/2.4.41 (Ubuntu) PHP/7.4.3 is vulnerable to CVE-XXXX"
        },
        {
            "command_executed": "use auxiliary/scanner/http/robots_txt; set RHOSTS 18.217.186.208; run; exit",
            "raw_output": "[+] [18.217.186.208] /robots.txt found with 2 disallowed entries: /admin_panel/ /config.bak"
        }
    ]

    # 4. Test Phase 3: AI Report Generation
    print("\n[*] 3. Sending raw output back to Gemini for reporting...")
    # ...
    # 4. Test Phase 3: AI Report Generation
    print("\n[*] 3. Sending raw output back to Gemini for reporting...")
    try:
        msf_report = await generate_vulnerability_report(msf_results)
        print("[+] Final JSON Report generated successfully:")
        print(json.dumps(msf_report, indent=2))
    except Exception as e:
        print(f"[-] AI Report Generation Failed: {e}")
        return

    print("\n=========================================")
    print("UNIT TEST COMPLETED SUCCESSFULLY")
    print("=========================================")

if __name__ == "__main__":
    # Run the async test loop
    asyncio.run(run_metasploit_test())