# Shodan-RedTeam-Search v0.1

**Advanced CVE Discovery & Risk Analysis Engine**

This tool was developed for Red Team professionals and security consultants who require surgical precision in vulnerability identification. Unlike conventional scanners, the **OiSecurity Shodan Red Team Intelligence Search** utilizes software lineage logic and real-time threat intelligence metrics (EPSS, KEV, Ransomware) to separate technical noise from actual critical risks.

## Strategic Differentials

* **Lineage Analysis:** Intelligently identifies if a legacy version inherits vulnerabilities discovered in higher versions of the same branch.
* **Force-CPE Discovery:** Overcomes indexing inconsistencies in databases (e.g., automatically resolves vendor conflicts between `apache`, `httpd`, `f5`, and `nginx`).
* **Risk-Based Prioritization (EPSS + KEV):** Integrates the *Exploit Prediction Scoring System* and CISA's *Known Exploited Vulnerabilities* catalog for realistic triaging.
* **Sanity Filter:** Semantically analyzes CVE summaries to discard false positives where the target version already contains the fix.

---

## Installation

```bash

# Clone the repository

git clone https://github.com/Leooliveoi/Shodan-RedTeam-Search.git
cd Shodan-RedTeam-Search

```
# Install dependencies
*Dependencies: `requests`, `rich`, `packaging`.*

---

## Usage

The tool operates in three primary modes:

### 1. Discovery Mode (Recon)

Search by product and version to map the attack surface. The version is optional; if omitted, the tool provides a general vulnerability history.
```bash
python3 main.py -p nginx -v 1.16.0
```

### 2. Direct Intel Mode (Deep Dive)

Extracts all technical fields for a specific CVE ID, including attack vectors, exploit references, and probability metrics.
```bash
python3 main.py -c CVE-2019-20372
```

### 3. Reporting Mode

Exports collected intelligence into structured formats for integration into Pentest reports.
```bash
python3 main.py -p httpd -v 2.4.48 -o audit_report.json -f json
```

---

## Preliminary Risk Matrix

The tool classifies risk based on threat context, not just the raw CVSS score:

| Risk | Classification Trigger |
| --- | --- |
| **CRITICAL (Active)** | Present in CISA KEV or used in active Ransomware campaigns. |
| **CRITICAL (High Prob)** | EPSS > 80% and significant impact (CVSS > 7.0). |
| **HIGH** | CVSS > 9.0 or high probability of exploitation (EPSS > 50%). |
| **MEDIUM/LOW** | Theoretical vulnerabilities with no evidence of active exploitation. |

---

## Disclaimer

This tool is intended exclusively for security auditing and authorized penetration testing purposes. Misuse for illegal activities is the sole responsibility of the user.

**Developed with <3 by Leonardo Oi | OiSecurity**


