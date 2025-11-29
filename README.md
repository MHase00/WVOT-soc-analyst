
# WVOT-soc-analyst

SOC content and automation for the West Virginia Office of Technology (WVOT).

This repository contains:

- **Detection Rule Engineering** – High-signal, low-noise KQL queries for Microsoft Sentinel  
- **Alert Enrichment Automation** – Python pipeline to reduce alert triage time  
- **Tuning Framework** – 5-step methodology for false-positive reduction and continuous improvement  

---

## Quick Start

### For WVOT Team

1. **Detection Rules**  
   - Navigate to [`/detection-rules`](./detection-rules)  
   - Copy the relevant `.kql` queries into your Microsoft Sentinel instance  
   - Create **Scheduled Query Rules** and deploy in **staging** first

2. **Automation**  
   - Navigate to [`/automation`](./automation)  
   - Configure and deploy the Python alert enrichment pipeline  
   - Integrate with your SOAR platform (e.g., Tines, n8n) for automated workflows

3. **Playbooks**  
   - Navigate to [`/playbooks`](./playbooks)  
   - Use the **5-step false-positive tuning framework** to tune both existing and new rules

### Expected Outcomes (Targets with Proper Tuning & Integration)

- ~40% reduction in alert fatigue (by Month 1)  
- MTTR improvement: 90 min → ~45 min (50% reduction, by Month 2)  
- <0.1% false-positive rate on tuned rules (Week 3–4)  
- 100% audit-ready documentation (by Month 1)  

---

## Contents

### 1. Detection Rules (`/detection-rules`)

Production-oriented KQL queries for Microsoft Sentinel mapped to MITRE ATT&CK tactics.

**Current Rules:**

- **Registry Persistence (T1547.001)**  
  Detects suspicious modifications to `Run` / `RunOnce` registry keys, typically using `DeviceRegistryEvents`.  
  Focuses on:
  - `HKLM\Software\Microsoft\Windows\CurrentVersion\Run`
  - `HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce`  
  Excludes common system binaries and trusted directories, and aggregates multiple events per device/user.

- **Privilege Escalation via Token Impersonation (T1134)**  
  Detects anomalous token creation/impersonation activity indicative of privilege escalation.

- **Lateral Movement via RDP (T1570)**  
  Detects unusual RDP activity patterns that may indicate lateral movement or credential misuse.

**Status:**  
Designed for production with tuning.  
False-positive rate target (after tuning): **<0.1%** per rule.

**Tuning Notes:**

Each rule is built to support allowlisting, for example:

```kusto
// Example allowlisting patterns
| where InitiatingProcessName !in ("your-trusted-process.exe", "approved-tool.exe")
| where Computer !in ("server1", "server2")    // exclude known-safe systems
| where User !in ("service_account", "automation_user")
```

Deploy in staging, monitor for 1–2 weeks, then introduce **narrow, documented** allowlists.

---

### 2. Automation (`/automation`)

Python-based alert enrichment pipeline integrating external threat intelligence with Sentinel alerts.

**Current Features:**

- **AbuseIPDB IP reputation checks**
  - Queries AbuseIPDB for:
    - `abuseConfidenceScore` (0–100)
    - `totalReports`
  - Derives IP status (`malicious` / `clean` / `unknown` on error).

- **VirusTotal file hash lookups**
  - Queries VirusTotal v3 `/files/{hash}` endpoint.
  - Reads `last_analysis_stats.malicious`.
  - Derives file status based on detection count.

- **Risk scoring and decisioning**
  - Normalizes IP and file scores into a risk score from `0.0` to `1.0`.
  - Maps risk scores to recommended actions:
    - `AUTO_TICKET_TIER3`
    - `MANUAL_REVIEW`
    - `CLOSE_FP`
  - Outputs JSON ready for SOAR or ticketing integration.

- **Error-aware behavior**
  - Network/API errors are captured with `status: "unknown"`.
  - When intel is unavailable for both IP and file, the pipeline defaults to **manual review**, not auto-closing.

**Configuration:**

Example configuration file (`config.example.yaml`, copy to `config.yaml`):

```yaml
abuseipdb:
  api_key: "YOUR_ABUSEIPDB_API_KEY"
  max_age_days: 90

virustotal:
  api_key: "YOUR_VIRUSTOTAL_API_KEY"

sentinel:
  workspace_id: "YOUR_SENTINEL_WORKSPACE_ID"
  resource_group: "YOUR_RESOURCE_GROUP"
  subscription_id: "YOUR_SUBSCRIPTION_ID"

soar:
  platform: "tines"  # or "n8n"
  webhook_url: "https://your-soar-webhook-url"
  high_priority_channel: "high-priority-alerts"
  medium_priority_channel: "manual-review"

slack:
  webhook_url: "https://hooks.slack.com/services/YOUR/WEBHOOK/URL"
  enabled: true

risk_thresholds:
  auto_ticket_tier3: 0.70
  manual_review: 0.40
  close_false_positive: 0.00
```

> Note: The reference script currently reads API keys from environment variables; if you adopt `config.yaml`, ensure the script loads and uses these values.

**Extensible / Planned Integrations:**

The pipeline is designed to be extended with:

- Geolocation enrichment (e.g., ipinfo.io, ip-api.com)  
- Internal blocklist correlation (local JSON/DB of known bad IPs/domains/hashes)  
- Ticket auto-creation via SOAR or ticketing API  
- Slack/Email notifications through webhooks  
- Direct Sentinel API integration, if needed, for automated incident updates  

**Impact (Target):**

- Up to **60% reduction** in Tier 1 manual enrichment work once integrated with SOAR and notifications.

---

### 3. Playbooks (`/playbooks`)

Documented methodologies for continuous SOC improvement.

**Includes:**

- **5-Step False-Positive Tuning Process**  
  A structured workflow to:
  - Analyze alerts
  - Identify benign patterns
  - Introduce precise allowlists
  - Avoid over-tuning (missing true positives)

- **Incident Response Playbook Template**  
  A generic IR flow you can adapt:
  - Detection → Triage → Containment → Eradication → Recovery → Lessons Learned

- **Control Mapping for ISO 27001 / NIST 800-53**  
  High-level mapping between SOC processes/detections and major compliance controls.

---

## Expected Outcomes

With proper deployment, integration, and tuning:

| Metric              | Before                             | Target After Tuning        | Timeline |
|---------------------|-------------------------------------|----------------------------|----------|
| Alert Fatigue       | 500+ alerts/day, ~97% FP           | ~40% reduction             | Month 1  |
| MTTR                | ~90 minutes                        | ~45 minutes                | Month 2  |
| False-Positive Rate | High variance, noisy               | <0.1% (for tuned rules)    | Week 3–4 |
| Audit Readiness     | Reactive documentation             | 100% on-time, traceable    | Month 1  |
| Tier 1 Manual Work  | ~10 min/alert enrichment           | ~30 sec (automated)        | Month 2  |

These are **targets**, not guarantees; results depend on:

- Data quality and coverage  
- Rule deployment and tuning discipline  
- Depth of SOAR and notification integration  
- Team processes and training  

---

## Tools & Technologies

- **SIEM:** Microsoft Sentinel  
- **EDR:** LimaCharlie (or equivalent EDR)  
- **SOAR:** Tines, n8n, or similar automation platform  
- **Languages:** KQL (Kusto Query Language), Python 3.8+  
- **Threat Intel:** AbuseIPDB, VirusTotal  
- **Compliance:** ISO 27001, NIST SP 800-53  

---

## Security & Operational Notes

- **API Keys & Secrets:**  
  - Never commit real API keys or secrets to the repository.  
  - Use `config.example.yaml` as a template and keep `config.yaml` and environment variables local/secure.

- **Customization:**  
  - Adapt detection rules to your own log schemas.  
  - Extend the enrichment pipeline to your SOAR, ticketing system, and notification channels.  
  - Maintain documentation for all tuning and allowlists to remain audit-ready.
