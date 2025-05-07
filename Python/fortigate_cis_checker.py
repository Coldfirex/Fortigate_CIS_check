#!/usr/bin/env python3

import os
import re
import sys
from datetime import datetime
import csv
from pathlib import Path

class FortiGateCISAudit:
    def __init__(self, config_file):
        self.config_file = config_file
        # Extract just the filename without path for report names
        config_basename = os.path.basename(config_file)
        config_name = os.path.splitext(config_basename)[0]
        
        # Use config name in output filenames
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        self.csv_file = f"FortiGate_{config_name}_CIS_BENCHMARK_v1.3.0_AUDIT_{timestamp}.csv"
        self.html_file = f"FortiGate_{config_name}_CIS_BENCHMARK_v1.3.0_AUDIT_{timestamp}.html"
        
        # Load the config content during initialization
        try:
            with open(self.config_file, 'r') as f:
                self.config_content = f.read()
        except Exception as e:
            print(f"Error reading config file {self.config_file}: {e}")
            self.config_content = ""

    def print_banner(self):
        print("========================================")
        print("Tool: FortiGate CIS Benchmark Audit Tool")
        print("Creator: Priyam Patel")
        print("========================================")

    def grep_config(self, pattern):
        """Simulates grep functionality for config file"""
        try:
            return bool(re.search(pattern, self.config_content))
        except Exception as e:
            print(f"Error searching config file: {e}")
            return False

    def check_dns_configuration(self):
        """Check DNS server configuration"""
        if self.grep_config(r"config system dns"):
            return "PASS: DNS server is configured"
        return "FAIL: DNS server is not configured"

    # ... [rest of check methods remain the same] ...

    def generate_csv_report(self, results):
        """Generate CSV report from results"""
        try:
            with open(self.csv_file, 'w', newline='') as f:
                writer = csv.writer(f)
                # Write header
                writer.writerow(['Benchmark ID', 'Description', 'Result', 'Fix Location', 'Fix Commands'])
                
                # Write results
                for benchmark, result, _, _ in results:
                    benchmark_id = benchmark.split()[0]
                    description = ' '.join(benchmark.split()[1:])
                    fix_location = self.get_fix_location(benchmark_id)
                    fix_commands = self.get_fix_commands(benchmark_id) if "FAIL" in result else "No fixes needed"
                    
                    writer.writerow([
                        benchmark_id,
                        description,
                        result,
                        fix_location,
                        fix_commands
                    ])
            print(f"CSV report generated: {self.csv_file}")
        except Exception as e:
            print(f"Error generating CSV report: {e}")

    def get_fix_location(self, benchmark_id):
        """Get the web interface location for fixing a benchmark"""
        locations = {
            "1.1": "System > Settings > Administration Settings",
            "1.2": "System > Admin > Administrator",
            "2.1": "System > Settings > Security Settings",
            "2.2": "System > Settings > Time & NTP",
            "2.3": "Log & Report > Log Settings",
            "2.4": "System > SNMP"
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
            <title>FortiGate CIS Audit Report - {os.path.basename(self.config_file)}</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 20px; }}
                table {{ border-collapse: collapse; width: 100%; }}
                th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
                th {{ background-color: #f2f2f2; }}
                .pass {{ color: green; }}
                .fail {{ color: red; }}
                .summary {{ margin-bottom: 20px; }}
                .fix-commands {{ background-color: #f8f9fa; padding: 10px; margin-top: 5px; font-family: monospace; }}
            </style>
        </head>
        <body>
            <h1>FortiGate CIS Audit Report - {os.path.basename(self.config_file)}</h1>
            <div class="summary">
                <p>Total Checks: {total_checks} | Passed: {total_pass} | Failed: {total_fail}</p>
            </div>
            <table>
                <tr>
                    <th>Benchmark</th>
                    <th>Result</th>
                    <th>Fix Location</th>
                    <th>Fix Commands</th>
                </tr>"""

        for benchmark, result, _, _ in results:
            benchmark_id = benchmark.split()[0]
            result_class = "pass" if "PASS" in result else "fail"
            fix_location = self.get_fix_location(benchmark_id)
            fix_commands = self.get_fix_commands(benchmark_id) if "FAIL" in result else ""

            html_content += f"""
                <tr>
                    <td>{benchmark}</td>
                    <td class="{result_class}">{result}</td>
                    <td>{fix_location if "FAIL" in result else ""}</td>
                    <td>
                        <div class="fix-commands">{fix_commands if "FAIL" in result else ""}</div>
                    </td>
                </tr>"""

        html_content += """
            </table>
        </body>
        </html>"""

        try:
            with open(self.html_file, 'w') as f:
                f.write(html_content)
            print(f"HTML report generated: {self.html_file}")
        except Exception as e:
            print(f"Error generating HTML report: {e}")


def process_single_file(file_path):
    """Process a single config file"""
    print(f"\nProcessing file: {file_path}")
    auditor = FortiGateCISAudit(file_path)
    
    # Run all checks and collect results
    results = []
    for method_name in dir(auditor):
        if method_name.startswith('check_') and callable(getattr(auditor, method_name)):
            check_method = getattr(auditor, method_name)
            result = check_method()
            # Extract benchmark ID from method name by removing the 'check_' prefix
            benchmark_name = method_name[6:].replace('_', ' ').capitalize()
            results.append((benchmark_name, result, "", ""))
    
    # Generate both HTML and CSV reports
    auditor.generate_html_report(results)
    auditor.generate_csv_report(results)
    return len(results), sum(1 for r in results if "PASS" in r[1])

def main():
    if len(sys.argv) != 2:
        print("Usage: python3 FortiGate_cis_audit.py <config_file_or_directory>")
        sys.exit(1)

    path = sys.argv[1]
    
    # Create output directory for reports if it doesn't exist
    output_dir = "audit_reports"
    os.makedirs(output_dir, exist_ok=True)
    
    # Change to output directory for report generation
    original_dir = os.getcwd()
    os.chdir(output_dir)

    # Print banner once
    print("========================================")
    print("Tool: FortiGate CIS Benchmark Audit Tool")
    print("Creator: Priyam Patel")
    print("========================================")
    
    total_files = 0
    total_checks = 0
    total_passed = 0
    
    try:
        if os.path.isfile(path):
            # Process single file
            checks, passed = process_single_file(path)
            total_files = 1
            total_checks = checks
            total_passed = passed
        elif os.path.isdir(path):
            # Process all files in directory
            config_extensions = ['.conf', '.txt', '.cfg']
            for root, _, files in os.walk(path):
                for file in files:
                    # Process only files with certain extensions
                    if any(file.endswith(ext) for ext in config_extensions):
                        file_path = os.path.join(root, file)
                        checks, passed = process_single_file(file_path)
                        total_files += 1
                        total_checks += checks
                        total_passed += passed
            
            if total_files == 0:
                print(f"No config files found in {path}")
        else:
            print(f"Path not found: {path}")
            sys.exit(1)
        
        # Print summary
        print("\n========== SUMMARY ==========")
        print(f"Total files processed: {total_files}")
        print(f"Total checks performed: {total_checks}")
        print(f"Total checks passed: {total_passed}")
        print(f"Total checks failed: {total_checks - total_passed}")
        print(f"Overall compliance: {(total_passed / total_checks * 100) if total_checks > 0 else 0:.2f}%")
        print(f"Reports saved to: {os.path.abspath(output_dir)}")
        
    finally:
        # Return to original directory
        os.chdir(original_dir)

if __name__ == "__main__":
    main()
