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
