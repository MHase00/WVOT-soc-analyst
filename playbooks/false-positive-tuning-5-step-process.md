# False-Positive Tuning: 5-Step Process

## Overview
This playbook documents the methodology for reducing false positives while maintaining detection coverage.

## Real-World Example
**Rule:** SQL Injection Detection in WAF logs
- **Before:** 500 alerts/day | 97% false positives
- **After:** 3 alerts/day | 99.4% FP reduction | 100% coverage maintained
- **Timeline:** 2 weeks to full tuning

## The 5-Step Process

### Step 1: IDENTIFY
**Goal:** Understand what the rule is doing and why it's firing so much.

**Action:**
1. Review rule logic in Sentinel (KQL query)
2. Check rule creation date and original intent
3. Pull baseline data:
   - How many alerts per day?
   - When do they start/stop?
   - Are there patterns (time-of-day, specific servers)?
4. Run query manually to see sample events

**Example:** SQL injection rule was firing on:
- Legitimate reporting tools using `WHERE` clauses in API calls
- Maintenance scripts with SQL syntax in query strings
- Automated backup jobs with encoded SQL

### Step 2: ASSESS
**Goal:** Determine if alerts are actually malicious or benign.

**Action:**
1. Pivot to supporting data sources:
   - Windows/application logs
   - Firewall/proxy logs
   - Database logs
   - EDR timelines
2. Look for indicators of actual SQL injection:
   - Unauthorized DB access?
   - Unusual query patterns?
   - Data exfiltration?
   - Failed authentication attempts?
3. Check affected systems:
   - Production databases or test environments?
   - Known application servers or unknown?
4. Cross-reference with change tickets and maintenance windows

**Example:** Pivoting to database logs showed:
- No unauthorized DB access
- Queries came from known application servers
- Matched maintenance window schedules
- **Conclusion:** All benign activity

### Step 3: ACT
**Goal:** Adjust the rule to filter out benign activity.

**Action:**
1. Identify common characteristics of false positives:
   - Specific servers or IP ranges?
   - Specific user accounts (service accounts, automation)?
   - Specific times of day (maintenance windows)?
   - Specific keywords in query strings?
2. Create exclusion logic:
   - Add allowlist for known-good systems
   - Exclude service accounts
   - Add time-based suppression (maintenance windows)
   - Adjust regex patterns to be more specific
3. Update rule with new exclusions

**Example:** Added exclusions:
```kusto
| where Computer !in ("webserver1", "webserver2", "automation-server")
| where User !in ("service_account", "backup_automation")
| where TimeGenerated !between (datetime(2024-01-01 02:00Z) .. datetime(2024-01-01 04:00Z))
| where QueryString !contains ("SELECT * FROM Reports")
```

### Step 4: VERIFY
**Goal:** Confirm that malicious signals still fire while false positives drop.

**Action:**
1. Test the modified rule against historical data
2. Run test queries:
   - How many alerts now? (Should be significantly lower)
   - Are real malicious events still caught?
   - Run the rule against known-good benign events (should fire 0 times)
   - Run the rule against known-malicious events (should fire 100% of the time)
3. Check edge cases:
   - What if someone uses similar pattern to bypass allowlist?
   - What if a service account is compromised?

**Example:** Testing showed:
- Before exclusions: 500 alerts/day
- After exclusions: 3 alerts/day (actual SQL injection attempts)
- Manual review of the 3: All confirmed malicious
- Malicious test cases: 100% detection rate

### Step 5: IMPROVE
**Goal:** Document the tuning and prevent regression.

**Action:**
1. Update playbook with final rule version
2. Document:
   - What was the problem? (Too many false positives)
   - What was the root cause? (Generic rule pattern, no context)
   - What was the solution? (Added exclusions/allowlists)
   - What were the results? (% reduction, coverage maintained)
   - When was this tuned? (Date)
   - Who tuned it? (Your name)
3. Add unit tests:
   - Test case 1: Known-benign events (should NOT fire)
   - Test case 2: Known-malicious events (SHOULD fire)
   - Test case 3: Edge cases
4. Set up monitoring:
   - Alert if false-positive rate increases again
   - Quarterly review to ensure tuning is still valid

**Example Documentation:**
```markdown
## SQL Injection Detection - Post-Tuning

**Tuned By:** Madhur Hase
**Date:** 2024-01-15
**Result:** 99.4% FP reduction (500 → 3 alerts/day)

**Changes Made:**
- Added allowlist for known-good servers
- Excluded service accounts
- Added maintenance window suppression
- Refined regex pattern for SQL keywords

**Unit Tests:**
✓ Test 1: Benign reporting queries → 0 alerts
✓ Test 2: Known SQLi payload → Alert fired
✓ Test 3: Edge case (encoded payload) → Alert fired

**Monitoring:**
- Alert if daily alert count > 50 (regression)
- Quarterly review on [Date]
```

## Quick Reference

| Step | Focus | Time |
|------|-------|------|
| 1. Identify | Understand the rule | 30 min |
| 2. Assess | Is it malicious? | 1-2 hours |
| 3. Act | Create exclusions | 30 min |
| 4. Verify | Test the fix | 30 min |
| 5. Improve | Document it | 30 min |
| **Total** | | **3-4 hours per rule** |

## Expected Outcomes

**Per Rule:**
- 80-99% false-positive reduction
- 100% coverage maintained for real threats
- Sustainable (can be re-tuned quarterly)

**For SOC:**
- 40% overall alert reduction (Month 1, top 5 rules)
- Tier 1 team morale improves (less noise)
- MTTR improves (faster to real alerts)

## Pro Tips

1. **Never tune too aggressively.** Leave a small buffer for edge cases.
2. **Document everything.** Future you will thank current you.
3. **Test before deploying.** Always test in a staging/lab environment first.
4. **Monitor after tuning.** False-positive rates can creep back up as environments change.
5. **Involve the team.** Ask Tier 1 which rules cause the most pain; tune those first.

---

**Version:** 1.0  
**Last Updated:** 2024-01-15
