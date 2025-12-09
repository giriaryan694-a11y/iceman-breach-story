# 🍦 **Company: Iceman’s Icecreams**

A cyberattack happens.
Attackers try to access the **owner’s old high-school results** stored in the company database.

Here is the **full story of what happens step-by-step**, with every SOC role involved.

---

# 🏢 **1. Who Works Inside a SOC? (Your Characters)**

Inside Iceman’s Icecreams SOC, we have:

### 👨‍💻 **L1 SOC Analyst**

Monitors alerts and triage.

### 🕵️‍♂️ **L2 SOC Analyst**

Investigates deeper, analyzes logs.

### 🧠 **L3 SOC Analyst / Detection Engineer**

Builds detection rules, handles advanced cases.

### 🚨 **Incident Responder / CSIRT**

Handles containment, remediation, recovery.

### 🔍 **Threat Intelligence Analyst**

Checks attacker IPs, domains, and patterns with safe TI sources.

### 🛠️ **SOC Manager**

Coordinates the whole team, communicates with leadership.

No one attacks anything — all actions are defensive.

---

# 🚨 **2. The Attack Begins — What Triggers an Alert?**

The attackers try *some method* to access the database.
(We don’t describe any harmful method — just that “suspicious behavior” occurs.)

**Example safe triggers:**

* Unusual login attempts to the database admin account
* Database queries coming from an unknown location
* Many failed login attempts
* Suspicious API requests
* A user logs in at midnight from another country

These alerts automatically appear in the SOC dashboard (SIEM).

---

# 🧊 **3. L1 SOC Analyst — First to Notice**

L1 sees alerts like:

* “Multiple failed login attempts from unknown IP”
* “Privileged account login from a new device”
* “Unusual query: SELECT * FROM userdata WHERE… (high-volume)”

### L1 Actions:

* Checks if it is a false positive
* Confirms the activity is unusual
* Escalates to L2 because it involves **database access + sensitive data**

L1 job = Identify **“is this worth investigating?”**

---

# 🔎 **4. L2 SOC Analyst — Deep Investigation**

L2 takes the case and checks:

### ✔️ Login logs

Who logged in? From where?
Is the device trusted?

### ✔️ Database logs

What queries were made?
Were they reading sensitive tables?

### ✔️ System behavior

Were there any unexpected processes?

### ✔️ Network patterns

Is the traffic coming from suspicious IPs?

If L2 sees something like:

* The query tries to read “owner_highschool_results” table
* IP belongs to an unknown region
* Time of access is unusual
* Account never queried such data before

Then L2 confirms:

> “This is likely a real ongoing attack.”

L2 escalates to **Incident Response** and informs the SOC Manager.

---

# 🚑 **5. Incident Response (IR) Team Steps In**

The IR Team takes control to **stop the attack safely**.

### They do:

* Isolate affected server from the network
* Disable compromised account
* Block suspicious IPs/domains
* Reset credentials
* Stop malicious sessions
* Ensure attacker is no longer connected

All defensive actions, 100% legal.

Nothing offensive or harmful.

---

# 🕵️‍♀️ **6. Threat Intelligence Analyst Joins**

They check:

* IP addresses in threat intelligence databases
* Domains against safe blacklists
* Patterns compared with known cybercriminal behaviors

They report:

“IP used belongs to a known cybercrime botnet”
**or**
“No public record — could be targeted attack”

This helps the team understand the attacker’s intention.

---

# 🧠 **7. L3 SOC Analyst / Detection Engineer**

They analyze:

* How did the attacker bypass initial defenses?
* Was there a misconfiguration?
* Do we need new SIEM rules?

They create or update:

* Detection rules
* Alerts
* Firewall policies
* Use cases

This prevents the SAME attack from happening again.

---

# ♻️ **8. Recovery Phase**

Once safe, the IR Team:

* Cleans the affected server
* Applies patches
* Rebuilds from backups if needed
* Re-enables service carefully
* Confirms everything is healthy

Database is restored safely.

---

# 📄 **9. Reporting & Lessons Learned**

The SOC Manager prepares a full report:

### Report includes:

* Timeline
* How attackers tried to access owner’s high-school data
* What they did
* How SOC responded
* What was the impact
* What improvements will be made

This goes to upper management.

---

# 🔐 **10. Post-Incident Hardening**

SOC makes the company stronger:

* Multi-factor authentication enforced
* Access control improved
* Database access logging enhanced
* Better network segmentation
* New alerts added
* Staff receives awareness training

This ensures future attacks fail.

---

# 🌟 **Simple Summary**

| Stage         | What Happens                    | Who Works   |
| ------------- | ------------------------------- | ----------- |
| Detection     | Alerts fire                     | L1 SOC      |
| Investigation | Deep log + query analysis       | L2 SOC      |
| Containment   | Block attacker, isolate systems | IR Team     |
| Intelligence  | Check attacker info             | TI Team     |
| Rule Updates  | Improve detection rules         | L3 SOC      |
| Recovery      | Restore systems                 | IR Team     |
| Reporting     | Documentation                   | SOC Manager |

---

# 💬 If you want, I can also simulate:

* A **safe red-team perspective** of how such an attack is *simulated* ethically
* How SOC + Red Team collaborate
* A purple-team scenario
* How YOU would analyze such an attack as a future red-teamer

Tell me what you want next.

# 🚨 Iceman's Icecreams — Incident Response Walkthrough

A fictional, safe, educational cybersecurity scenario demonstrating how a Security Operations Center (SOC) responds to an attempted data-access attack.

This write-up is suitable for learning SOC workflows, IR lifecycle, and defensive security methodologies.

---

## 🏢 Scenario Overview

**Company:** Iceman's Icecreams
**Incident Type:** Unauthorized attempt to access sensitive database records
**Targeted Data:** Owner’s old high‑school examination results

The goal of this walkthrough is to show **how a SOC detects, analyzes, contains, and resolves a cyber incident** without using any harmful actions.

---

## 🧩 1. Roles Inside the SOC

### SOC Roles and Their Actions During the Incident

| Role                                    | Main Responsibility                                           | What They Did in This Incident                                                  |
| --------------------------------------- | ------------------------------------------------------------- | ------------------------------------------------------------------------------- |
| **L1 SOC Analyst**                      | First-level monitoring and triage                             | Detected unusual login + DB access alerts and escalated the case                |
| **L2 SOC Analyst**                      | Deep investigation through logs, network traffic and patterns | Confirmed unauthorized DB access attempts, correlated logs, escalated to IR     |
| **L3 Analyst / Detection Engineer**     | Detection rule creation and advanced analysis                 | Updated SIEM rules, improved detections to stop similar attacks in future       |
| **Incident Response (IR) Team / CSIRT** | Containment, eradication, and recovery                        | Isolated server, disabled compromised accounts, blocked malicious IPs           |
| **Threat Intelligence Analyst**         | Enrich indicators with safe TI feeds                          | Checked attacker IPs/domains against threat databases, assessed attacker intent |
| **SOC Manager**                         | Coordination, reporting, communication                        | Oversaw response, prepared final incident report and improvement plan           |

A typical SOC team in this scenario includes:

* **L1 SOC Analyst** – Monitors alerts, performs initial triage.
* **L2 SOC Analyst** – Performs deeper investigation using logs and tools.
* **L3 Analyst / Detection Engineer** – Enhances detection logic and performs advanced analysis.
* **Incident Response (IR) Team / CSIRT** – Contains, eradicates, and recovers systems.
* **Threat Intelligence Analyst** – Enriches indicators (IPs/domains) with safe TI feeds.
* **SOC Manager** – Coordinates, reports, and communicates with leadership.

---

## 🚨 2. Detection Phase (L1 Analyst)

The SIEM reports unusual activity:

* Multiple failed login attempts on the database account.
* Successful login from a never-before-seen device.
* Suspicious database queries reading sensitive tables.

L1 confirms that the activity is abnormal and escalates the case to L2.

---

## 🔍 3. Investigation Phase (L2 Analyst)

L2 performs deeper analysis across:

### ✔ Login logs

Identifies suspicious authentication activity from unusual locations.

### ✔ Database logs

Sees unusual queries attempting to access the high‑school results table.

### ✔ Network traffic

Detects access attempts from unfamiliar IPs.

After confirming this is not normal business behavior, L2 escalates to the IR team.

---

## 🚑 4. Containment Phase (Incident Response Team)

To stop the incident safely, IR:

* Isolates the affected server.
* Disables compromised accounts.
* Blocks suspicious IPs or domains.
* Resets credentials and active sessions.

All actions are legal, defensive, and approved.

---

## 🌐 5. Threat Intelligence Enrichment

The TI analyst checks:

* Whether the suspicious IPs are associated with known malicious activity.
* Whether the network behavior matches known threat patterns.

This helps understand attacker intent and context.

---

## 🧠 6. Detection Engineering (L3 Analyst)

L3 reviews:

* Gaps that allowed the incident to progress.
* Improvements required in SIEM rules, alerts, or firewall logic.

New use-cases and detection rules are created to prevent similar incidents.

---

## 🔧 7. Recovery Phase

Once the environment is safe:

* Systems are cleaned.
* Updated patches are applied.
* Services are restored from clean backups.

SOC verifies that systems are functioning normally.

---

## 📄 8. Reporting & Lessons Learned

The SOC Manager prepares a detailed post‑incident report including:

* Timeline of the attack
* Impact assessment
* Containment and remediation steps
* Improvement recommendations

This strengthens the overall security posture.

---

## 🛡 9. Post‑Incident Hardening

To reduce future risk:

* MFA is enforced
* Access controls are tightened
* Database logging is improved
* Network segmentation is reviewed
* User security awareness training is conducted

---

## 📘 Summary

This scenario demonstrates:

* How different SOC roles collaborate
* How alerts progress from triage to recovery
* How IR teams contain and resolve threats
* How organizations improve using lessons learned

This is a clean, purely defensive, educational example with no harmful actions.

---

## 🏷 Suggested Repository Topics

* SOC
* IR
* DFIR
* Cybersecurity Writeup
* Defensive Security
* SIEM
* Threat Intelligence

---

Feel free to use this as a template for learning, portfolio building, or teaching others about SOC and Incident Response fundamentals.

## Role-by-Role: How the SOC Acts (Table)

| **Role**                           | **Primary Duty**                    | **How This Role Acts During an Incident**                                                                                 |
| ---------------------------------- | ----------------------------------- | ------------------------------------------------------------------------------------------------------------------------- |
| **Tier 1 Analyst (L1)**            | Initial monitoring & alert triage   | Reviews alerts, filters false positives, escalates suspicious events to L2 with notes.                                    |
| **Tier 2 Analyst (L2)**            | Deep investigation                  | Performs log correlation, checks threat intelligence, analyzes patterns, reconstructs attacker steps, decides escalation. |
| **Tier 3 Analyst (L3)**            | Advanced forensics & threat hunting | Does memory/disk forensics, malware analysis, hunts undetected threats, supports incident containment.                    |
| **SOC Manager**                    | Leadership & coordination           | Approves major actions, coordinates with other departments, prepares reports for executives.                              |
| **Incident Responder (IR)**        | Containment & recovery              | Isolates systems, blocks IPs/domains, resets credentials, restores services safely.                                       |
| **Threat Intelligence Analyst**    | Provides intel & context            | Supplies IOC lists, attacker profiles, trends, and supports SOC with actionable TI.                                       |
| **Malware Analyst**                | Understands malicious files         | Analyzes malware behavior, extracts IOCs, builds defensive signatures.                                                    |
| **Digital Forensics Expert**       | Evidence collection & preservation  | Acquires disk/memory images, preserves evidence, supports legal documentation.                                            |
| **Compliance / Reporting Officer** | Documentation & auditing            | Ensures incident logs, reports, and processes meet legal and audit requirements.                                          |
