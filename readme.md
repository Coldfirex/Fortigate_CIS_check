# FortiGate CIS Benchmark Checker

##
Synced from Priyam Patel's repository.

Focused on:
  - Enhancing the python implementation
  - Exanded CIS Controls checks
  - Additional Best Practices checks
  - Scanning multiple config files at same time
  - Enhanced logging, auditing, and validation

## Purpose

This tool automates the process of checking FortiGate firewall configurations against CIS (Center for Internet Security) benchmarks. It helps security professionals and network administrators to:

- Audit FortiGate configurations for security best practices
- Identify potential security misconfigurations
- Generate detailed reports in both CSV and HTML formats
- Track compliance with CIS security standards

## Implementations

This tool is available in two implementations:
1. Bash script (`fortigate_cis_checker.sh`)
2. Python script (`fortigate_cis_checker.py`)

Choose the implementation that best suits your environment and requirements.

## Features

- Automated checking of 50+ CIS benchmark controls
- Detailed pass/fail status for each control
- Current configuration status
- Specific recommendations for failed checks
- HTML report with color-coded results
- CSV output for further analysis
- Summary statistics of overall compliance
- Configuration location guidance for failed checks

## Prerequisites

### For Bash Implementation
- Bash shell environment (version 4.0 or higher)
- Access to FortiGate configuration file
- Read permissions for the configuration file
- Minimum 100MB free disk space for reports
- Internet connectivity (optional, for updates)

### For Python Implementation
- Python 3.6 or higher
- Required Python packages:
  ```
  pip install argparse logging typing
  pip install tqdm
  ```
- Access to FortiGate configuration file
- Read permissions for the configuration file

## Installation

### Bash Implementation
1. Download the script:

## Output Files

The script generates two output files in the current directory:

1. CSV Report: `AUDIT_YYYYMMDD_HHMMSS.csv`
2. HTML Report: `AUDIT_YYYYMMDD_HHMMSS.html`

## Checks Performed

The script checks various security aspects including:

- DNS Configuration
- Intra-zone Traffic Settings
- Management Services Configuration
- Banner Settings
- System Time and NTP
- Firmware Status
- USB Port Security
- TLS Configuration
- Password Policies
- SNMP Settings
- Admin Access Controls
- High Availability Settings
- Firewall Policies
- Security Profiles
- Logging Configuration
- And many more...

## Sample Output

The HTML report includes:

- Summary statistics
- Detailed results table
- Color-coded pass/fail indicators
- Current configuration values
- Specific recommendations for failed checks
- Configuration location guidance for failed checks

### Output Format
For failed checks, the report shows:
- Status: FAIL
- Current: Location: [configuration path]
- Recommendation: [specific fix details]

For passed checks, the report shows:
- Status: PASS
- Current: [actual configured value]
- Recommendation: N/A

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Author

[Priyam Patel](https://www.linkedin.com/in/priyam-patel-450307206/)

## Version

1.0.0

## Note

- This tool is designed for FortiGate version 7.0.x configurations
- Results may vary for other versions
- Always review results and recommendations before implementing changes
- Backup your configuration before making any changes

## Troubleshooting

Common issues and solutions:

1. Permission denied
```bash
chmod +x fortigate-csi-check.sh
```

2. Invalid configuration file
- Ensure the configuration file is in plain text format
- Verify file permissions
- Check for file corruption
