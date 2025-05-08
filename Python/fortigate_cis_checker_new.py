#!/usr/bin/env python3

import os
import re
from datetime import datetime
import csv
import sys
import glob
import logging
import json
from tqdm import tqdm

class FortiGateCISAudit:
    def __init__(self, config_file):
        self.config_file = config_file
        # Create audit_reports folder if it doesn't exist
        self.reports_dir = "audit_reports"
        if not os.path.exists(self.reports_dir):
            os.makedirs(self.reports_dir)
        
        # Generate output filenames with timestamp, excluding file extension
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        base_filename = os.path.splitext(os.path.basename(config_file))[0]  # Remove .txt or .conf
        self.csv_file = os.path.join(self.reports_dir, f"AUDIT_{timestamp}_{base_filename}.csv")
        self.html_file = os.path.join(self.reports_dir, f"AUDIT_{timestamp}_{base_filename}.html")
        
        # Load the config content during initialization
        self.config_content = ""
        if self.is_valid_config():
            try:
                with open(self.config_file, 'r', encoding='utf-8') as f:
                    self.config_content = f.read()
            except Exception as e:
                logging.error(f"Error reading config file {self.config_file}: {e}")
                print(f"Error reading config file {self.config_file}: {e}")
        
        # Extract hostname
        self.hostname = self.extract_hostname()
        # Extract firmware version
        self.firmware_version = self.extract_firmware_version()

    def is_valid_config(self):
        """Validate that the config file starts with '#config-version='"""
        try:
            with open(self.config_file, 'r', encoding='utf-8') as f:
                first_line = f.readline().strip()
                if first_line.startswith("#config-version="):
                    return True
                logging.warning(f"Invalid config file {self.config_file}: Does not start with '#config-version='")
                print(f"Skipping {self.config_file}: Invalid config file (must start with '#config-version=')")
                return False
        except Exception as e:
            logging.error(f"Error validating config file {self.config_file}: {e}")
            print(f"Error validating config file {self.config_file}: {e}")
            return False

    def extract_hostname(self):
        """Extract hostname from config file"""
        match = re.search(r'set hostname "([^"]+)"', self.config_content)
        return match.group(1) if match else "Unknown"

    def extract_firmware_version(self):
        """Extract firmware version from config file, excluding model"""
        match = re.search(r'config-version=[A-Za-z0-9]+-([0-9.-]+-FW-build[0-9]+-[0-9]+):opmode', self.config_content)
        return match.group(1) if match else "Unknown"

    def print_banner(self):
        print("========================================")
        print("Tool: FortiGate CIS Benchmark Audit Tool")
        print(f"Config File: {self.config_file}")
        print(f"Hostname: {self.hostname}")
        print(f"Firmware Version: {self.firmware_version}")
        print("========================================")

    def grep_config(self, pattern):
        """Simulates grep functionality for config file"""
        try:
            return bool(re.search(pattern, self.config_content))
        except Exception as e:
            logging.error(f"Error searching config file {self.config_file} with pattern {pattern}: {e}")
            return False

    def evaluate_check(self, check):
        """Evaluate a single check from the checks.json configuration"""
        try:
            benchmark_id = check["id"]
            logic = check["logic"]
            result_message = check["result_message"]

            if logic["type"] == "simple_grep":
                if all(self.grep_config(pattern) for pattern in logic["patterns"]):
                    return f"PASS: {result_message['pass']}"
                return f"FAIL: {result_message['fail']}"

            elif logic["type"] == "negated_grep":
                if not any(self.grep_config(pattern) for pattern in logic["patterns"]):
                    return f"PASS: {result_message['pass']}"
                return f"FAIL: {result_message['fail']}"

            elif logic["type"] == "tls_versions":
                if self.grep_config(r"config system global"):
                    ssl_versions_match = re.search(r"set admin-https-ssl-versions\s+([^\n]+)", self.config_content)
                    if ssl_versions_match:
                        versions = ssl_versions_match.group(1).split()
                        if any(v in versions for v in logic["forbidden_versions"]):
                            return f"FAIL: {result_message['fail']}"
                    return f"PASS: {result_message['pass']}"
                return f"PASS: {result_message['pass_default']}"

            elif logic["type"] == "count_grep":
                if self.grep_config(logic["section"]):
                    count = len(re.findall(logic["pattern"], self.config_content))
                    if count >= logic["min_count"]:
                        return f"PASS: {result_message['pass']}"
                return f"FAIL: {result_message['fail']}"

            elif logic["type"] == "complex_grep":
                conditions = [
                    self.grep_config(p["pattern"]) if not p["negated"] else not self.grep_config(p["pattern"])
                    for p in logic["patterns"]
                ]
                if all(conditions):
                    return f"PASS: {result_message['pass']}"
                return f"FAIL: {result_message['fail']}"

            else:
                logging.error(f"Unknown check logic type {logic['type']} for check {benchmark_id}")
                return f"ERROR: Unknown check logic type for {benchmark_id}"

        except Exception as e:
            logging.error(f"Error evaluating check {benchmark_id} for {self.config_file}: {e}")
            return f"ERROR: Check {benchmark_id} failed ({str(e)})"

    def load_checks(self):
        """Load check definitions from checks.json"""
        try:
            with open("checks.json", 'r', encoding='utf-8') as f:
                return json.load(f)
        except Exception as e:
            logging.critical(f"Error loading checks.json: {e}")
            print(f"Error: Could not load checks.json: {e}")
            sys.exit(1)

    def generate_csv_report(self, results):
        """Generate CSV report from results"""
        try:
            with open(self.csv_file, 'w', newline='', encoding='utf-8') as f:
                writer = csv.writer(f)
                writer.writerow(['Benchmark ID', 'Description', 'Result', 'Fix Location', 'Fix Commands'])
                
                for benchmark, result, check in results:
                    benchmark_id = benchmark.split()[0]
                    description = ' '.join(benchmark.split()[1:])
                    fix_location = self.get_fix_location(benchmark_id)
                    fix_commands = check.get("fix_commands", "No fix commands available") if "FAIL" in result else "No fixes needed"
                    
                    writer.writerow([
                        benchmark_id,
                        description,
                        result,
                        fix_location,
                        fix_commands
                    ])
            logging.info(f"CSV report generated: {self.csv_file}")
            print(f"CSV report generated: {self.csv_file}")
        except Exception as e:
            logging.error(f"Error generating CSV report for {self.csv_file}: {e}")
            print(f"Error generating CSV report for {self.csv_file}: {e}")

    def get_fix_location(self, benchmark_id):
        """Get the web interface location for fixing a benchmark"""
        locations = {
            "1.1": "System > Settings > Administration Settings",
            "1.2": "System > Admin > Administrator",
            "2.1": "System > Settings > Security Settings",
            "2.2": "System > Settings > Time & NTP",
            "2.3": "Log & Report > Log Settings",
            "2.4": "System > SNMP",
            "Custom": "VPN > SSL-VPN Settings"
        }
        
        for prefix, location in locations.items():
            if benchmark_id.startswith(prefix):
                return location
        return "Location not specified"

    def generate_html_report(self, results):
        """Generate minimalistic HTML report"""
        total_checks = len(results)
        total_pass = sum(1 for check in results if "PASS" in check[1])
        total_fail = sum(1 for check in results if "FAIL" in check[1])

        html_content = f"""
        <html>
        <head>
            <title>FortiGate CIS Audit Report</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 20px; }}
                table {{ border-collapse: collapse; width: 100%; }}
                th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
                th {{ background-color: #f2f2f2; }}
                .pass {{ color: green; }}
                .fail {{ color: red; }}
                .error {{ color: red; }}
                .summary {{ margin-bottom: 20px; }}
                .fix-commands {{ background-color: #f8f9fa; padding: 10px; margin-top: 5px; font-family: monospace; white-space: pre-wrap; }}
            </style>
        </head>
        <body>
            <h1>FortiGate CIS Audit Report</h1>
            <p>Hostname: {self.hostname}</p>
            <p>Firmware Version: {self.firmware_version}</p>
            <div class="summary">
                <p>Total Checks: {total_checks} | Passed: {total_pass} | Failed: {total_fail}</p>
            </div>
            <table>
                <tr>
                    <th>Benchmark</th>
                    <th>Result</th>
                    <th>Fix Location</th>
                    <th>Fix Commands Example</th>
                </tr>"""

        for benchmark, result, check in results:
            benchmark_id = benchmark.split()[0]
            result_class = "pass" if "PASS" in result else "fail" if "FAIL" in result else "error"
            fix_location = self.get_fix_location(benchmark_id)
            fix_commands = check.get("fix_commands", "") if "FAIL" in result else ""
            # Replace newlines with <br> for HTML rendering
            fix_commands_html = fix_commands.replace('\n', '<br>') if fix_commands else ""

            html_content += f"""
                <tr>
                    <td>{benchmark}</td>
                    <td class="{result_class}">{result}</td>
                    <td>{fix_location if "FAIL" in result else ""}</td>
                    <td>
                        <div class="fix-commands">{fix_commands_html}</div>
                    </td>
                </tr>"""

        html_content += """
            </table>
        </body>
        </html>"""

        try:
            with open(self.html_file, 'w', encoding='utf-8') as f:
                f.write(html_content)
            logging.info(f"HTML report generated: {self.html_file}")
            print(f"HTML report generated: {self.html_file}")
        except Exception as e:
            logging.error(f"Error generating HTML report for {self.html_file}: {e}")
            print(f"Error generating HTML report for {self.html_file}: {e}")

def setup_logging():
    """Set up logging to a unique file in audit_reports"""
    reports_dir = "audit_reports"
    if not os.path.exists(reports_dir):
        os.makedirs(reports_dir)
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    log_file = os.path.join(reports_dir, f"audit_log_{timestamp}.log")
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s [%(levelname)s] %(message)s',
        handlers=[
            logging.FileHandler(log_file),
            logging.StreamHandler()
        ]
    )
    logging.info("Audit log initialized")

def main():
    # Set up logging
    setup_logging()
    
    if len(sys.argv) != 2:
        logging.error("Invalid usage. Usage: python3 FortiGateCISAudit.py <config_folder>")
        print("Usage: python3 FortiGateCISAudit.py <config_folder>")
        sys.exit(1)

    config_folder = sys.argv[1]
    
    # Check if folder exists
    if not os.path.isdir(config_folder):
        logging.error(f"{config_folder} is not a valid directory")
        print(f"Error: {config_folder} is not a valid directory")
        sys.exit(1)

    # Get all .txt and .conf files in the folder
    config_files = glob.glob(os.path.join(config_folder, "*.txt")) + \
                   glob.glob(os.path.join(config_folder, "*.conf"))

    if not config_files:
        logging.warning(f"No configuration files found in {config_folder}")
        print(f"No configuration files found in {config_folder}")
        sys.exit(1)

    # Load checks from checks.json
    auditor = FortiGateCISAudit(config_files[0])  # Temporary instance to load checks
    checks = auditor.load_checks()

    # Process each config file with progress bar
    print(f"Processing {len(config_files)} config files...")
    for config_file in tqdm(config_files, desc="Processing files", unit="file"):
        logging.info(f"Processing file: {config_file}")
        auditor = FortiGateCISAudit(config_file)
        
        # Skip if config is invalid
        if not auditor.config_content:
            logging.warning(f"Skipping {config_file} due to invalid or unreadable config")
            continue
        
        auditor.print_banner()
        
        # Run all checks and collect results
        results = []
        for check in checks:
            try:
                benchmark_id = check["id"]
                result = auditor.evaluate_check(check)
                logging.info(f"Check {benchmark_id} for {config_file}: {result}")
                print(f"{benchmark_id}: {result}")
                results.append((f"{benchmark_id} {check['description']}", result, check))
            except Exception as e:
                logging.error(f"Error executing check {check['id']} for {config_file}: {e}")
                print(f"Error executing check {check['id']}: {e}")
                results.append((f"{check['id']} {check['description']}", f"ERROR: Check failed ({str(e)})", check))
        
        # Generate both HTML and CSV reports
        auditor.generate_html_report(results)
        auditor.generate_csv_report(results)
        logging.info(f"Completed processing: {config_file}")
        print(f"Completed processing: {config_file}\n")
    
    logging.info("All files processed. Review logs and reports in the audit_reports folder.")
    print("All files processed. Review logs and reports in the audit_reports folder.")

if __name__ == "__main__":
    main()
