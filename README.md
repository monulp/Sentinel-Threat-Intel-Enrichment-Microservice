# Sentinel Threat Intel Enrichment Microservice

## Project Overview
This project is a lightweight, Python-based Security Orchestration, Automation, and Response (SOAR) microservice. It acts as a webhook receiver for Microsoft Sentinel (or any SIEM). When High or Medium severity alerts are generated, this service automatically extracts IP entities, runs an OPSEC validation check, and simultaneously queries multiple Threat Intelligence platforms to return a consolidated malicious confidence score.

The goal of this service is to eliminate Tier 1 manual triage toil and reduce the time-to-verdict for critical security incidents.

## Architecture & Tech Stack
*   **Language:** Python 3
*   **Web Framework:** Flask (REST API / Webhook listener)
*   **Threat Intel APIs:** VirusTotal (API v3), AbuseIPDB (API v2)

## Key Features
*   **Automated Webhook Ingestion:** Exposes an `/api/sentinel-webhook` endpoint accepting JSON payloads formatted identically to Microsoft Sentinel incident entities.
*   **OPSEC Pre-Filtering:** Utilizes Python's native `ipaddress` library to evaluate all extracted IPs. Internal, loopback, or private RFC-1918 IPs (e.g., `10.x.x.x`, `192.168.x.x`) are dropped immediately to prevent leaking internal infrastructure to public external APIs.
*   **Multi-Source Enrichment:** Queries external indicators against VirusTotal and AbuseIPDB concurrently.
*   **Environment Variable Security:** API keys are injected dynamically via environment variables during runtime.

---
##  My Development Setup
I built and tested this environment locally before deploying to the cloud. 
* **OS:** Arch Linux (with HyDE / Hyprland)
* **Package Manager:** `paru`
* **Language:** Python 3 (Flask, Requests)
* **Testing:** Postman & `curl` natively in the Kitty/Foot terminal
* **APIs:** VirusTotal (v3) & AbuseIPDB (v2)
---

## Installation & Setup

### Prerequisites
1.  **Python 3.x** installed on your system.
2.  **API Keys:** Free accounts and API keys from [VirusTotal](https://www.virustotal.com/) and [AbuseIPDB](https://www.abuseipdb.com/).
3.  **Testing Tool:** `curl` or Postman to simulate SIEM webhooks.
---

**1. Install Dependencies**

You can install the required packages (flask and requests) using a Python virtual environment, or via your system's package manager.

Arch Linux (Native Packages via paru)
If you are running Arch Linux and enforce PEP 668 (externally-managed environments), you can install the dependencies directly via paru or pacman:
```
paru -S python-flask python-requests
```
(For Debian/Ubuntu or macOS, you can use ```python -m venv venv && pip install flask requests)```

**2.Get Your API Key**

Log in to VirusTotal and AbuseIPdb and get ready with your both API keys

**3. Install Postman**

```
paru -S postman-bin
```

***4. Project Directory & app.py***

Create a clean workspace somewhere and create a python file and paste the code shown as below: 

```
import os
import ipaddress
import requests
from flask import Flask, request, jsonify

app = Flask(__name__)

# Pull both keys from environment variables
VT_API_KEY = os.environ.get("VT_API_KEY", "YOUR_VT_KEY")
ABUSEIPDB_API_KEY = os.environ.get("ABUSEIPDB_API_KEY", "YOUR_ABUSEIPDB_KEY")

def is_public_ip(ip_str):
    """OPSEC Check: Ensure RFC 1918 / loopback / private IPs are not leaked."""
    try:
        ip = ipaddress.ip_address(ip_str)
        return ip.is_global
    except ValueError:
        return False

def check_virustotal(ip):
    """Queries VirusTotal and returns the malicious score."""
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    headers = {"x-apikey": VT_API_KEY}
    
    try:
        response = requests.get(url, headers=headers, timeout=10)
        if response.status_code == 200:
            stats = response.json().get('data', {}).get('attributes', {}).get('last_analysis_stats', {})
            malicious = stats.get('malicious', 0)
            total = sum(stats.values())
            return f"{malicious}/{total} engines detected"
        return f"VT Error {response.status_code}"
    except requests.RequestException as e:
        return f"Error: {str(e)}"

def check_abuseipdb(ip):
    """Queries AbuseIPDB and returns the abuse confidence score."""
    url = "https://api.abuseipdb.com/api/v2/check"
    querystring = {
        'ipAddress': ip,
        'maxAgeInDays': '90' # Looks back at the last 90 days of reports
    }
    headers = {
        'Accept': 'application/json',
        'Key': ABUSEIPDB_API_KEY
    }
    
    try:
        response = requests.get(url, headers=headers, params=querystring, timeout=10)
        if response.status_code == 200:
            data = response.json()['data']
            score = data.get('abuseConfidenceScore', 0)
            return f"{score}% confidence of abuse"
        return f"AbuseIPDB Error {response.status_code}"
    except requests.RequestException as e:
        return f"Error: {str(e)}"

@app.route('/api/sentinel-webhook', methods=['POST'])
def sentinel_webhook():
    data = request.get_json(silent=True)
    if not data:
        return jsonify({"error": "Invalid JSON payload"}), 400

    entities = data.get("Entities", [])
    target_ips = [
        entity["Address"]
        for entity in entities
        if entity.get("Type", "").lower() == "ip" and "Address" in entity
    ]

    if not target_ips:
        return jsonify({"message": "No IP addresses found."}), 200

    results = []

    for ip in target_ips:
        if not is_public_ip(ip):
            print(f"[\033[93mOPSEC BLOCKED\033[0m] {ip} is private/internal. Will not route to APIs.")
            results.append({"ip": ip, "status": "Internal IP - Ignored"})
            continue

        print(f"[\033[94mQUERY\033[0m] Checking VirusTotal and AbuseIPDB for {ip}...")
        
        # Fire both API queries
        vt_result = check_virustotal(ip)
        abuse_result = check_abuseipdb(ip)

        print(f"[\033[91mALERT\033[0m] IP: {ip} | VT: {vt_result} | AbuseIPDB: {abuse_result}")
        results.append({
            "ip": ip, 
            "virustotal": vt_result,
            "abuseipdb": abuse_result
        })

    return jsonify({"status": "success", "data": results}), 200

if __name__ == '__main__':
    print("\033[92m[*] SOC Webhook Listener running on http://127.0.0.1:5000\033[0m")
    app.run(host="127.0.0.1", port=5000, debug=True)
```

---

## TESTING

**1. Start the Microservice**

Get your free API keys from VirusTotal and AbuseIPDB. Inject them into your terminal as environment variables so you don't hardcode secrets, and run the script:

```
VT_API_KEY="your_vt_key" ABUSEIPDB_API_KEY="your_abuse_key" python app.py
```

**2.Simulate a SIEM Alert**

Using postman:

- Create a HTTP request
- Change GET to POST in the dropdown.
- Paste the URL: ```http://127.0.0.1:5000/api/sentinel-webhook```
- Click the Body tab.
- Select raw.
- Paste the mock Sentinel JSON payload:
```
{
  "IncidentTitle": "Suspicious Login Attempt from Malicious IP",
  "Severity": "High",
  "Entities": [
    {
      "Type": "ip",
      "Address": "192.168.1.50"
    },
    {
      "Type": "ip",
      "Address": "143.110.232.223"
    }
  ]
}
```
-Hit send to watch the listening terminal to populate the output.

**3. Expected Output**

Your Flask server terminal will immediately block the internal IP for OPSEC reasons, and return the threat intel scores for the external IP










































































