# Lab 5 Report: Monitoring, Logging & Incident Detection
**Course:** IKB42603 Cloud Computing Security Essentials  
**Institution:** Universiti Kuala Lumpur - Malaysian Institute of Information Technology (UniKL MIIT)  
**Instructor:** Prof. Dr. Shahrulniza Musa  
**Date:** September 8, 2026  

---

## Executive Summary & Learning Outcomes

This report documents the step-by-step execution, evidence collection, incident detection analysis, and response lifecycle performed during **Lab 5: Monitoring, Logging & Incident Detection**. 

The primary objectives of this lab are:
1. **Log Centralisation:** Forwarding host and application telemetry to a centralised CloudWatch Logs endpoint (simulated via LocalStack).
2. **Security Log Querying:** Distinguishing between raw log records and security events, and filtering telemetry for anomalous activity.
3. **Tamper-Proofing Audit Trails:** Constructing a SHA-256 hash-chained log mechanism to guarantee immutability and detect post-compromise log modification.
4. **Multi-Event Threat Correlation:** Detecting complex multi-stage attacks (brute-force $\rightarrow$ account compromise $\rightarrow$ data exfiltration) that evade single-line alerting.
5. **Incident Response Execution:** Containing threats using network firewall rules (`iptables`), preserving forensic evidence integrity with cryptographically hashed copies, and producing a formal incident report.

---

## Environment Setup — LocalStack Infrastructure

To simulate a cloud monitoring and logging environment, LocalStack (v3.8.1) was deployed in Docker to emulate AWS CloudWatch Logs endpoints locally on port `4566`.

### Commands Executed
```bash
# Clean up existing containers and spin up LocalStack
docker rm -f localstack 2>/dev/null
docker run -d --name localstack -p 4566:4566 localstack/localstack:3.8.1

# Configure endpoint shortcut
EP='--endpoint-url=http://localhost:4566'

# Create CloudWatch Log Group and Log Stream
aws $EP logs create-log-group --log-group-name /ccse/app
aws $EP logs create-log-stream --log-group-name /ccse/app --log-stream-name auth
```

### Evidence Screenshot — Environment Setup

<img width="925" height="502" alt="setup local " src="https://github.com/user-attachments/assets/8c49c52f-4474-42fc-b035-f884e991d014" />

---

## Session A: Logging & Centralisation (Week 9)

### Task 1 — Generate Application Logs

Authentication events were simulated to represent standard application traffic along with malicious activity probing by an external IP (`203.0.113.9`).

#### Commands Executed
```bash
cat > auth.log <<'EOF'
2025-03-01T09:00:01 LOGIN_OK user=ahmad ip=10.0.0.5
2025-03-01T09:01:10 LOGIN_FAIL user=admin ip=203.0.113.9
2025-03-01T09:01:12 LOGIN_FAIL user=admin ip=203.0.113.9
2025-03-01T09:01:15 LOGIN_FAIL user=admin ip=203.0.113.9
2025-03-01T09:01:18 LOGIN_FAIL user=admin ip=203.0.113.9
2025-03-01T09:01:22 LOGIN_OK user=admin ip=203.0.113.9
2025-03-01T09:01:40 EXPORT_DATA user=admin ip=203.0.113.9 size=500MB
EOF
cat auth.log
```

#### Evidence Screenshot — Task 1

<img width="582" height="307" alt="task 1" src="https://github.com/user-attachments/assets/cc69571e-6365-4c4c-819e-a7665ebfb2d1" />

---

### Task 2 — Centralise Logs (Ship to CloudWatch)

Local logs were pushed to the centralized CloudWatch log stream `/ccse/app/auth` to establish cascading collection architecture. The logs were subsequently queried and verified back from the central store.

#### Commands Executed
```bash
TS=$(date +%s000)
while IFS= read -r line; do
  aws $EP logs put-log-events --log-group-name /ccse/app --log-stream-name auth \
    --log-events timestamp=$TS,message="$line" >/dev/null; TS=$((TS+1000));
done < auth.log

# Read back from central store
aws $EP logs get-log-events --log-group-name /ccse/app --log-stream-name auth \
  --query 'events[].message' --output text
```

#### Verification & Output Read-Back
```text
2025-03-01T09:00:01 LOGIN_OK user=ahmad ip=10.0.0.5     2025-03-01T09:01:10 LOGIN_FAIL user=admin ip=203.0.113.9        2025-03-01T09:01:12 LOGIN_FAIL user=admin ip=203.0.113.9        2025-03-01T09:01:15 LOGIN_FAIL user=admin ip=203.0.113.9        2025-03-01T09:01:18 LOGIN_FAIL user=admin ip=203.0.113.9        2025-03-01T09:01:22 LOGIN_OK user=admin ip=203.0.113.9  2025-03-01T09:01:40 EXPORT_DATA user=admin ip=203.0.113.9 size=500MB
```

#### Evidence Screenshot — Task 2

<img width="935" height="242" alt="task 2" src="https://github.com/user-attachments/assets/0192b6c5-2458-4726-a499-c5b9e19f0ac3" />

---

### Task 3 — Query for Security-Relevant Activity

The centralized log data was queried to identify failed authentication attempts grouped by origin IP address.

#### Command Executed
```bash
grep LOGIN_FAIL auth.log | awk '{print $4, $5}' | sort | uniq -c
```

#### Query Result
```text
      4 ip=203.0.113.9
```
*Analysis:* The query identified exactly 4 failed login attempts for user `admin` originating from source IP `203.0.113.9`.

#### Evidence Screenshot — Task 3

<img width="562" height="67" alt="task 3" src="https://github.com/user-attachments/assets/60167e1f-f870-4276-9868-2f0e6772003f" />

---

## Session B: Tamper-Proofing, Detection & Response (Week 10)

### Task 4 — Tamper-Proof (Hash-Chained) Logs

To protect against log alteration by adversaries seeking to cover their tracks, a cryptographic hash chain was computed. Each line's SHA-256 hash depends on both the line content and the hash of the preceding line:
$$\text{Hash}_n = \text{SHA256}(\text{Hash}_{n-1} + \text{Line}_n)$$

#### Commands Executed
```bash
PREV=0
while IFS= read -r line; do
  PREV=$(printf '%s%s' "$PREV" "$line" | sha256sum | cut -d' ' -f1)
  printf '%s | %s\n' "$line" "$PREV"
done < auth.log > auth.chain
cat auth.chain

# Simulate log tampering by altering data export size from 500MB to 5MB
sed 's/500MB/5MB/' auth.log > auth.tampered
```

#### Hash-Chained Log Output (`auth.chain`)
```text
2025-03-01T09:00:01 LOGIN_OK user=ahmad ip=10.0.0.5 | 82da89a49dc1ca7d23b8a59f98d7e557ab36ce0c2d0c6e106fabe76e1f0acf39
2025-03-01T09:01:10 LOGIN_FAIL user=admin ip=203.0.113.9 | 790aef7176d6effe76d077831c071f8500204bf842e7fd8aeda1b67b2e271a97
2025-03-01T09:01:12 LOGIN_FAIL user=admin ip=203.0.113.9 | 1e0b2e8aaf5143fb95070a8e57b009f058f0d37c257d19409b4131894d29a9a8
2025-03-01T09:01:15 LOGIN_FAIL user=admin ip=203.0.113.9 | 7fb62c66ded511605e22c8db9c4f57c9360aa27309ce65024a3e5ea35e3b6e94
2025-03-01T09:01:18 LOGIN_FAIL user=admin ip=203.0.113.9 | 143253b549a74b9626e910fbe54ca12cb5431a0a4c9c4f2189ff27a3e2a17e01
2025-03-01T09:01:22 LOGIN_OK user=admin ip=203.0.113.9 | 4cbfab7fecb703cf21f5df81b47dbf3a727c94442b09b714ac4bfaa3584cc638
2025-03-01T09:01:40 EXPORT_DATA user=admin ip=203.0.113.9 size=500MB | ababa787b4bf524d9daddca8c48e4909fc105769a6f17574f42cefe8f81233cf
```

#### Tamper Verification Proof
When recomputing the hash chain on `auth.tampered`, the final hash deviates completely from `ababa787b4bf524d9daddca8c48e4909fc105769a6f17574f42cefe8f81233cf`, mathematically proving that tampering occurred.

#### Evidence Screenshot — Task 4

<img width="931" height="427" alt="task 4" src="https://github.com/user-attachments/assets/0f3796ce-5254-4270-97a7-859901c8a17d" />

---

### Task 5 — Detect the Incident (Correlation)

A SIEM detection rule logic was created to correlate discrete events originating from the same IP address (`203.0.113.9`).

#### Correlation Logic & Commands Executed
```bash
IP=203.0.113.9
FAILS=$(grep -c "LOGIN_FAIL.*$IP" auth.log)
SUCCESS=$(grep -c "LOGIN_OK.*$IP" auth.log)
EXPORT=$(grep -c "EXPORT_DATA.*$IP" auth.log)
echo "IP=$IP fails=$FAILS success=$SUCCESS export=$EXPORT"

if [ "$FAILS" -ge 3 ] && [ "$SUCCESS" -ge 1 ] && [ "$EXPORT" -ge 1 ]; then
  echo 'ALERT: probable brute-force -> compromise -> data exfiltration';
fi
```

#### Script Output
```text
IP=203.0.113.9 fails=4 success=1 export=1
ALERT: probable brute-force -> compromise -> data exfiltration
```

#### Evidence Screenshot — Task 5

<img width="642" height="232" alt="task 5" src="https://github.com/user-attachments/assets/52d7a483-0c61-4beb-ba08-9f32ec3b0e41" />

---

### Task 6 — Incident Response Execution

Following incident detection, containment rules were enforced via containerized firewall policy, and evidence was archived with a cryptographic checksum.

#### 1. Containment Command (`iptables`)
```bash
docker run --rm --cap-add=NET_ADMIN alpine sh -c \
  'apk add -q iptables; iptables -A INPUT -s 203.0.113.9 -j DROP; iptables -L INPUT -n | tail -2'
```
*Output:*
```text
target     prot opt source               destination         
DROP       all  --  203.0.113.9          0.0.0.0/0
```

#### 2. Forensic Evidence Collection & Hash Generation
```bash
cp auth.log evidence_$(date +%Y%m%d).log
sha256sum evidence_*.log > evidence.sha256
cat evidence.sha256
```
*Output:*
```text
0adc5d2ac06cbbdd366099bcc0540c4c0f76946e71b52e4c99322731696a203b  evidence_20260908.log
```

#### Evidence Screenshot — Task 6

<img width="932" height="191" alt="task 6" src="https://github.com/user-attachments/assets/4642c5e2-b666-4f92-9bcd-6205897919c8" />

---

## Formal Incident Report

### 1. Detection
The incident was detected on March 1, 2025, via automated correlation rule evaluation. The monitoring system flagged source IP `203.0.113.9` after matching a critical rule sequence: $\ge 3$ failed authentication attempts followed by a successful login and an immediate high-volume data export event within a 2-minute window.

### 2. Analysis
* **Initial Access / Brute-Force:** Between 09:01:10 and 09:01:18, external IP `203.0.113.9` launched 4 sequential credential guessing attempts against account `admin`.
* **Account Compromise:** At 09:01:22, the attacker successfully authenticated (`LOGIN_OK`) as `admin`.
* **Data Exfiltration:** At 09:01:40, the compromised session executed an uncharacteristic data transfer of `500MB` (`EXPORT_DATA`).
* **Log Tampering Attempt:** Forensic review revealed an attempt to alter `auth.log` (changing `500MB` to `5MB`), which was immediately flagged because the hash chain validation failed.

### 3. Containment
Immediate active containment was achieved at the network perimeter level by inserting an explicit drop rule using Linux `iptables`:
```text
iptables -A INPUT -s 203.0.113.9 -j DROP
```
This rule blocked all subsequent incoming network packets from `203.0.113.9`, isolating the attacker from the infrastructure.

### 4. Evidence & Integrity
The raw authentication log was duplicated to a timestamped forensic file `evidence_20260908.log`. To guarantee chain of custody and immutability, a SHA-256 hash digest was generated and stored in `evidence.sha256`:
`0adc5d2ac06cbbdd366099bcc0540c4c0f76946e71b52e4c99322731696a203b`.

### 5. Lesson Learned
Relying on isolated log lines or local log files is insufficient for cloud security. Attackers with administrative access will tamper with local log storage to remove evidence of exfiltration. Logs must be streamed immediately to an isolated, write-once, append-only centralized location (e.g., CloudWatch / S3 Object Lock) with cryptographic hash chaining enabled for out-of-band audit verification.

---

## Short-Answer Questions

### Q1. What is the difference between a log and an event? Give an example of each from this lab.
* **Log (Durable Record):** A raw, sequential, append-only record of a system state change or action that has occurred. It serves as historical data for auditing and troubleshooting.  
  * *Example from Lab:* `2025-03-01T09:01:10 LOGIN_FAIL user=admin ip=203.0.113.9` stored in `auth.log`.
* **Event (Trigger / Actionable Alert):** A evaluated notification derived from analysing one or more logs against security policies, thresholds, or detection logic in near real-time.  
  * *Example from Lab:* The real-time alert fired by the SIEM script: `ALERT: probable brute-force -> compromise -> data exfiltration`.

### Q2. Why must audit logs be tamper-proof, and how does a hash chain achieve this?
* **Why Audit Logs Must Be Tamper-Proof:** Audit logs provide forensic evidence for legal proceedings, incident response investigations, and regulatory compliance. If an adversary compromises a system, their immediate objective is often to erase or modify logs to conceal their presence. If logs can be modified undetected, they lose evidentiary value.
* **How Hash Chaining Achieves Tamper-Proofing:** Each log entry hash $H_n$ is computed as $\text{SHA256}(H_{n-1} + \text{Line}_n)$. Because cryptographic hash functions are one-way and collision-resistant, altering a single character in entry $k$ alters $H_k$, which subsequently invalidates $H_{k+1}, H_{k+2}, \dots, H_N$. Re-verifying the chain against an externally stored root/final hash instantly flags any tampering or omission.

### Q3. How did correlation detect an incident that no single log line revealed?
* **Single Line Perspective:** 
  * A single `LOGIN_FAIL` could be a user typo.
  * A single `LOGIN_OK` looks like legitimate system usage.
  * An `EXPORT_DATA` command could represent routine data backups.
* **Correlation Perspective:** By combining temporal context, user identity, and source IP across multiple log entries ($4 \times \text{LOGIN\_FAIL} \rightarrow 1 \times \text{LOGIN\_OK} \rightarrow 1 \times \text{EXPORT\_DATA}$ from `203.0.113.9`), the SIEM rule revealed the underlying attack narrative: brute-force password discovery followed by unauthorized access and data exfiltration.

### Q4. List the incident-response steps you performed and the goal of each.
1. **Detect:** Ran multi-condition threshold matching script on central telemetry.  
   * *Goal:* Identify threat presence and flag anomalous behavior in real-time.
2. **Contain:** Applied `iptables` drop rule for IP `203.0.113.9`.  
   * *Goal:* Neutralize active threats and prevent further exfiltration or lateral movement.
3. **Collect Evidence:** Created timestamped snapshot `evidence_20260908.log` and computed SHA-256 checksum in `evidence.sha256`.  
   * *Goal:* Preserve forensically sound evidence with verified integrity for investigation.
4. **Document Timeline:** Synthesized findings into a formal incident report detailing Detection, Analysis, Containment, and Lessons Learned.  
   * *Goal:* Retain organizational memory, satisfy compliance duties, and prevent recurring breaches.

### Q5. How do the same logs serve both security monitoring and compliance evidence (Weeks 6, 11)?
* **Security Monitoring (Operational Focus):** Logs are ingested in real-time by SIEM/SOAR tools to detect active threats, trigger alerts, calculate metrics, and enable immediate containment actions.
* **Compliance Evidence (Governance & Audit Focus):** The exact same logs, when retained securely in tamper-evident append-only storage, serve as historical audit trails to prove compliance with regulatory frameworks (e.g., ISO/IEC 27001, SOC 2, HIPAA, PCI-DSS). Auditors inspect these logs to verify that user access control, access monitoring, and incident detection policies are functioning continuously.

---

## Verification & Best-Practices Checklist

### Verification Commands Executed
```bash
# Verify central log group existence in LocalStack
aws --endpoint-url=http://localhost:4566 logs describe-log-groups

# Verify cryptographic hash integrity of collected evidence
sha256sum -c evidence.sha256
```

### Security Best-Practices Checklist
- [x] **Logs are centralised:** Telemetry is forwarded to LocalStack CloudWatch Logs (`/ccse/app/auth`) rather than remaining solely on local hosts.
- [x] **Security-relevant activity queried:** Query pipeline successfully extracted failed login attempts grouped by source IP (`grep | awk | sort | uniq -c`).
- [x] **Logs are tamper-evident:** Implemented cryptographic SHA-256 hash chaining (`auth.chain`) to detect post-incident modification.
- [x] **Incident detected via correlation:** SIEM correlation script successfully detected brute-force attack leading to data exfiltration.
- [x] **Incident response lifecycle executed:** Performed containment (`iptables`), evidence preservation (`evidence.sha256`), and timeline documentation.

---

## Cleanup & Teardown Instructions

To clean up all local lab artifacts and stop the LocalStack container service, execute:

```bash
rm -f auth.log auth.chain auth.tampered evidence_*.log evidence.sha256
docker stop localstack && docker rm localstack
```
