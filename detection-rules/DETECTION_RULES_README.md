# Detection Rules

All rules are designed for production use and can be tuned for multi‑agency environments.

---

## How to Use (Microsoft Sentinel)

1. Copy the contents of the relevant `.kql` file (for example, `persistence-registry-run-key.kql`).
2. In Sentinel, go to **Analytics → Create → Scheduled query rule**.
3. Paste the KQL into the **Set rule logic** / **Query** (Detection) section.
4. Configure:
   - **Severity** (e.g., High for persistence / privilege escalation)
   - **Run frequency** and **Lookback period**
   - **Entity mappings** (Device, Account, etc.)
5. Enable the rule in **staging** first and monitor alerts before moving to full production.

---

## Rules Included

### 1. Registry Persistence Detection

- **File:** `persistence-registry-run-key.kql`  
- **Log source:** `DeviceRegistryEvents`  
- **MITRE ATT&CK:** T1547.001 – Boot or Logon Autostart Execution  
- **Severity:** High  
- **Estimated FP Rate (after tuning):** < 0.1%  
- **Use Case:**  
  Detect malware or unauthorized tools establishing persistence by writing to:
  - `HKLM\Software\Microsoft\Windows\CurrentVersion\Run`
  - `HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce`

The rule:
- Filters on `ActionType` such as `RegistryValueSet` / `RegistryKeyCreated`
- Focuses on `RegistryKey` paths containing the Run / RunOnce locations
- Excludes common Windows system processes and processes running from standard, trusted directories
- Aggregates multiple suspicious modifications per device and user, and alerts when a threshold (e.g., 3+ events) is exceeded

---

### 2. Privilege Escalation (Token Impersonation)

- **File:** `privilege-escalation-token-impersonation.kql`  
- **MITRE ATT&CK:** T1134 – Access Token Manipulation  
- **Severity:** High  
- **Estimated FP Rate (after tuning):** < 0.2%  
- **Use Case:**  
  Detect anomalous token creation and impersonation activity indicative of privilege escalation.

---

### 3. Lateral Movement (RDP Anomalies)

- **File:** `lateral-movement-rdp-anomaly.kql`  
- **MITRE ATT&CK:** T1570 – Lateral Tool Transfer  
- **Severity:** Medium–High  
- **Estimated FP Rate (after tuning):** < 0.15%  
- **Use Case:**  
  Detect unusual RDP usage patterns and potential pass‑the‑hash or credential misuse via remote desktop.

---

## Tuning Guidelines

Each rule is designed with allowlisting in mind. You **should** customize them for your environment to reduce false positives.

For the **Registry Persistence** rule (using `DeviceRegistryEvents`), typical allowlist adjustments look like:

```kusto
// Exclude known, trusted binaries from triggering the alert
| where InitiatingProcessFileName !in ("your-trusted-process.exe", "approved-tool.exe")

// Exclude specific devices/servers that are known to have legitimate, noisy activity
| where DeviceName !in ("server1", "server2")

// Exclude specific accounts (e.g., service or automation accounts) if appropriate
| where User !in ("service_account", "automation_user")
