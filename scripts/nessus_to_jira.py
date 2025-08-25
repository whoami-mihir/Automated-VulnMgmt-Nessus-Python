#!/usr/bin/env python3
"""
Automated Vulnerability Management: Nessus JSON → Jira

Educational script to:
1. Download a Nessus JSON scan report
2. Parse critical vulnerabilities
3. Create Jira tickets automatically
"""

import requests
import json
import time
from datetime import datetime

# -----------------------------
# Configuration (replace with your own credentials)
# -----------------------------
NESSUS_URL = "https://demo.tenable.com:8834"
NESSUS_API_KEY = "demo_access_key"
NESSUS_SECRET_KEY = "demo_secret_key"
SCAN_ID = 1  # Example scan ID
EXPORT_FILE = "reports/nessus_scan.json"

JIRA_URL = "https://yourjira.atlassian.net/rest/api/2/issue"
JIRA_USER = "jira_user@example.com"
JIRA_API_TOKEN = "jira_api_token"
JIRA_PROJECT_KEY = "SEC"
ASSIGNEE = "security_owner"

# -----------------------------
# Disable SSL warnings (for demo purposes)
# -----------------------------
requests.packages.urllib3.disable_warnings()

# -----------------------------
# Logging helper
# -----------------------------
def log(msg):
    print(f"[{datetime.now()}] {msg}")

# -----------------------------
# Export Nessus scan JSON
# -----------------------------
def download_nessus_report(scan_id, export_file):
    headers = {"X-ApiKeys": f"accessKey={NESSUS_API_KEY}; secretKey={NESSUS_SECRET_KEY}"}

    # Step 1: Request export
    export_url = f"{NESSUS_URL}/scans/{scan_id}/export"
    payload = {"format": "json"}
    r = requests.post(export_url, headers=headers, json=payload, verify=False)
    r.raise_for_status()
    file_id = r.json()["file"]

    # Step 2: Poll export status
    status_url = f"{export_url}/{file_id}/status"
    while True:
        r = requests.get(status_url, headers=headers, verify=False)
        r.raise_for_status()
        if r.json()["status"] == "ready":
            break
        log("Export status: waiting...")
        time.sleep(5)

    # Step 3: Download export
    download_url = f"{export_url}/{file_id}/download"
    r = requests.get(download_url, headers=headers, verify=False)
    r.raise_for_status()
    with open(export_file, "wb") as f:
        f.write(r.content)
    log(f"[+] Nessus JSON report saved to {export_file}")

# -----------------------------
# Parse critical vulnerabilities
# -----------------------------
def parse_critical_vulns(json_file):
    with open(json_file, "r") as f:
        data = json.load(f)

    criticals = []
    for host in data.get("hosts", []):
        hostname = host.get("hostname")
        for vuln in host.get("vulnerabilities", []):
            if vuln.get("severity") == "Critical":
                criticals.append({
                    "plugin_id": vuln.get("plugin_id"),
                    "name": vuln.get("name"),
                    "host": hostname
                })
    log(f"Found {len(criticals)} critical vulnerabilities")
    return criticals

# -----------------------------
# Create Jira ticket
# -----------------------------
def create_jira_ticket(vuln):
    summary = f"Critical Vulnerability: {vuln['plugin_id']} on host {vuln['host']}"
    description = (
        f"Vulnerability Name: {vuln['name']}\n"
        f"Plugin ID: {vuln['plugin_id']}\n"
        f"Affected Host: {vuln['host']}\n"
        f"Scan Date: {datetime.now().strftime('%Y-%m-%d')}"
    )
    payload = {
        "fields": {
            "project": {"key": JIRA_PROJECT_KEY},
            "summary": summary,
            "description": description,
            "issuetype": {"name": "Bug"},
            "assignee": {"name": ASSIGNEE}
        }
    }
    auth = (JIRA_USER, JIRA_API_TOKEN)
    headers = {"Content-Type": "application/json"}
    r = requests.post(JIRA_URL, auth=auth, headers=headers, json=payload)
    if r.status_code == 201:
        log(f"[+] Jira ticket created for {vuln['name']}")
    else:
        log(f"[-] Failed to create Jira ticket: {r.status_code} {r.text}")

# -----------------------------
# Main workflow
# -----------------------------
if __name__ == "__main__":
    log("Starting Nessus → Jira automation")
    download_nessus_report(SCAN_ID, EXPORT_FILE)
    critical_vulns = parse_critical_vulns(EXPORT_FILE)
    for vuln in critical_vulns:
        create_jira_ticket(vuln)
    log("Automation completed")
