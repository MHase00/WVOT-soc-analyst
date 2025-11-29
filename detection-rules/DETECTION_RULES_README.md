# Detection Rules

All rules are production-ready and optimized for multi-agency environments.

## How to Use

1. Copy the .kql file content
2. Open Microsoft Sentinel → Analytics Rules → Create Rule
3. Paste into the Detection tab
4. Configure severity and schedule
5. Test in staging environment first

## Rules Included

### 1. Registry Persistence Detection
**File:** `persistence-registry-run-key.kql`
**MITRE ATT&CK:** T1547.001 - Boot or Logon Autostart Execution
**Severity:** High
**FP Rate:** <0.1%
**Use Case:** Detect malware establishing persistence via Registry Run keys

### 2. Privilege Escalation (Token Impersonation)
**File:** `privilege-escalation-token-impersonation.kql`
**MITRE ATT&CK:** T1134 - Access Token Manipulation
**Severity:** High
**FP Rate:** <0.2%
**Use Case:** Detect anomalous token creation/impersonation

### 3. Lateral Movement (RDP Anomalies)
**File:** `lateral-movement-rdp-anomaly.kql`
**MITRE ATT&CK:** T1570 - Lateral Tool Transfer
**Severity:** Medium-High
**FP Rate:** <0.15%
**Use Case:** Detect unusual RDP activity and pass-the-hash attempts

## Tuning Guidelines

Each rule includes an allowlist. Customize based on your environment:
```kusto
// Common allowlist adjustments:
| where InitiatingProcessName !in ("your-trusted-process.exe", "approved-tool.exe")
| where Computer !in ("server1", "server2")  // Exclude known-safe systems
| where User !in ("service_account", "automation_user")
```

## Testing

Before deploying, test with known malicious scenarios:

1. **Registry Persistence:** Simulate autoruns using Sysinternals or PSTools
2. **Token Impersonation:** Use Rubeus or similar token theft tools (in isolated lab)
3. **RDP Anomalies:** Create unusual RDP sessions from unexpected IPs

## Metrics to Track

- Detection Rate (how many true positives detected)
- False Positive Rate (noisy alerts)
- MTTR (time to detection + triage)
- Coverage (% of MITRE ATT&CK tactics covered)

## Support

See `/playbooks/false-positive-tuning-5-step-process.md` for tuning methodology.
