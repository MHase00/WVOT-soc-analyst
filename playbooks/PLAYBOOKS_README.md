# Playbooks & Documentation

This directory contains operational playbooks, templates, and guidance used by the WVOT SOC. They are written to be directly usable or easily adapted by other organizations.

---

## Included Playbooks

1. **false-positive-tuning-5-step-process.md**  
   - Structured 5-step methodology for reducing alert noise  
   - Focuses on:
     - Identifying benign patterns
     - Implementing narrowly scoped allowlists
     - Avoiding over-tuning (missing true positives)  
   - Designed to be used alongside the KQL detection rules in `/detection-rules`

2. **incident-response-playbook-template.md**  
   - Standardized template for incident response procedures  
   - Covers:
     - Roles and responsibilities  
     - Escalation and communication paths  
     - Triage → Containment → Eradication → Recovery → Lessons Learned  
   - Includes documentation checkpoints to support audit readiness

3. **control-mapping-iso27001-nist800-53.md**  
   - High-level mapping between SOC activities / detections and:
     - ISO 27001 controls  
     - NIST SP 800-53 controls  
   - Useful for:
     - Audit preparation
     - Demonstrating coverage and control effectiveness
     - Aligning SOC operations with governance requirements

---

## How to Use

1. **Select the relevant playbook or template**
   - Use `false-positive-tuning-5-step-process.md` when tuning or creating detection rules
   - Use `incident-response-playbook-template.md` when formalizing or updating IR procedures
   - Use `control-mapping-iso27001-nist800-53.md` for audit / compliance work

2. **Copy and adapt**
   - Make a copy into your internal documentation (wiki, runbook system, etc.)
   - Customize:
     - Organization name
     - Contacts and escalation chains
     - Tooling (SIEM, SOAR, ticketing platform)
     - Local regulatory/compliance context

3. **Follow the procedures step-by-step**
   - For tuning, follow all 5 steps, recording:
     - What noise was observed
     - What changes were made (KQL, allowlists, thresholds)
     - Who approved the change
   - For incidents, ensure all stages and documentation items are completed

4. **Document actions and outcomes**
   - Capture:
     - Timeline of events
     - Decisions made and rationale
     - Evidence (screenshots, logs, ticket IDs)

5. **Archive and review**
   - Store final versions for:
     - Future reference
     - Audits and assessments
   - Periodically review and update playbooks (e.g., quarterly or after major incidents)

---

## Contributing

To add or update playbooks:

1. **Create a new `.md` file** in this directory  
   - Use a clear, descriptive name (e.g., `phishing-response-playbook.md`)

2. **Follow the existing structure**
   - Overview / purpose
   - Prerequisites (tools, access, roles)
   - Step-by-step process
   - Documentation / evidence requirements
   - Metrics or success criteria (if applicable)

3. **Include practical examples where possible**
   - Example alerts
   - Example email / chat templates
   - Example KQL snippets or automation steps

4. **Update this README**
   - Add your new playbook under **Included Playbooks**
   - Provide a brief description and intended use

5. **Keep operational and audit needs in mind**
   - Ensure processes are:
     - Clear enough for Tier 1 analysts
     - Detailed enough for auditors and reviewers
