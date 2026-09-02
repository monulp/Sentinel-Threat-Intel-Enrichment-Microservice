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

## Installation & Setup

### Prerequisites
1.  **Python 3.x** installed on your system.
2.  **API Keys:** Free accounts and API keys from [VirusTotal](https://www.virustotal.com/) and [AbuseIPDB](https://www.abuseipdb.com/).
3.  **Testing Tool:** `curl` or Postman to simulate SIEM webhooks.

```bash
git clone [https://github.com/YOUR_USERNAME/sentinel-enricher.git](https://github.com/YOUR_USERNAME/sentinel-enricher.git)
cd sentinel-enricher
