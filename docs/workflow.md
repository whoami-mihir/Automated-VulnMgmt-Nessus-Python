# Vulnerability Management Automation Workflow

## Steps
1. Download the JSON export from Nessus:
   - Endpoint: `/scans/{scan_id}/export`
   - Export type: JSON

2. Parse the JSON report:
   - Extract only vulnerabilities with severity "Critical"
   - Capture: Plugin ID, Name, Host

3. Create Jira tickets:
   - Summary: Critical Vulnerability: [Plugin ID] on [Host]
   - Description includes plugin ID, name, host, scan date
   - Tickets assigned to a pre-defined owner

## Output
- Console logs the scan report analysis and ticket creation
- Jira ticket example:

Summary: Critical Vulnerability: 12345 on host 192.168.1.10  
Description: 
Vulnerability Name: Remote Code Execution
Plugin ID: 12345
Affected Host: 192.168.1.10
Scan Date: 2025-08-25
Assignee: security_owner
