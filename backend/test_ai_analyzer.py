import unittest
import json
from utils.ai_analyzer import sanitize_scan_data

class TestDataSanitization(unittest.TestCase):

    def setUp(self):
        # The target URL that the user initiated the scan against
        self.target_url = "http://testphp.vulnweb.com"
        
        # A mock payload simulating combined results from Nmap, Wapiti, and WhatWeb
        self.mock_scan_data = {
            "whatweb": [
                {
                    "target": "http://testphp.vulnweb.com/",
                    "IP": "44.228.249.3",
                    "Title": "Home of Acunetix Art"
                }
            ],
            "wapiti": [
                {
                    "info": "Backup file http://testphp.vulnweb.com/index.bak found for http://testphp.vulnweb.com/index.php"
                },
                {
                    "info": "Vulnerability found on subdomain admin.testphp.vulnweb.com"
                }
            ],
            "nmap": {
                "hosts": [
                    {
                        "address": "44.228.249.3",
                        "hostname": "ec2-44-228-249-3.us-west-2.compute.amazonaws.com",
                        "ports": [
                            {"portid": "80", "state": "open"}
                        ]
                    },
                    {
                        "address": "192.168.1.100", # Random internal IP that might show up
                        "hostname": "internal-server",
                        "ports": []
                    }
                ]
            }
        }

    def test_sanitize_scan_data(self):
        # Run the sanitization function
        sanitized_output_str = sanitize_scan_data(self.mock_scan_data, self.target_url)
        print(sanitized_output_str)  # For debugging purposes

        # 1. Verify exact URL replacement
        self.assertIn("[TARGET_URL]/index.bak", sanitized_output_str)
        self.assertNotIn("http://testphp.vulnweb.com", sanitized_output_str)

        # 2. Verify Domain replacement (e.g., in subdomains or raw text)
        self.assertIn("admin.[TARGET_DOMAIN]", sanitized_output_str)
        self.assertNotIn("testphp.vulnweb.com", sanitized_output_str)

        # 3. Verify IP Address replacement
        self.assertIn("[TARGET_IP]", sanitized_output_str)
        self.assertNotIn("44.228.249.3", sanitized_output_str)
        self.assertNotIn("192.168.1.100", sanitized_output_str) # Should catch all IPs

        # 4. Verify AWS Hostname replacement
        self.assertIn("[TARGET_HOSTNAME]", sanitized_output_str)
        self.assertNotIn("ec2-44-228-249-3.us-west-2.compute.amazonaws.com", sanitized_output_str)

        # 5. Ensure non-sensitive data remains intact
        self.assertIn("Home of Acunetix Art", sanitized_output_str)
        self.assertIn("Backup file", sanitized_output_str)
        self.assertIn("portid", sanitized_output_str)
        
        # Optional: Print to visually inspect during the test run
        # print("\n--- Sanitized Output ---")
        # print(sanitized_output_str)

if __name__ == '__main__':
    unittest.main()