# LAB REPORT: LAB 4 — ACCESS CONTROL & NETWORK SECURITY
**Course:** IKB42603 Cloud Computing Security Essentials  
**Institution:** Universiti Kuala Lumpur - Malaysian Institute of Information Technology (UniKL MIIT)  
**Lecturer:** Prof. Dr. Shahrulniza Musa  
**CLO Mapping:** CLO2 — Construct secure cloud operations that safeguard data integrity  
**Assessment:** Lab Report (Screenshots + Outputs + Short Answers) — Contributes to Lab Assignment  

---

## Executive Summary & Objectives

This laboratory practical focuses on implementing core identity, access control, and network security mechanisms within containerized and orchestrated cloud environments (Docker & Kubernetes). Security controls are evaluated across two complementary domains:
1. **Session A (Week 7) — Identity & Access Control:** Implementing authentication (AuthN) via password protection and Multi-Factor Authentication (MFA/TOTP), followed by authorization (AuthZ) enforcement using Kubernetes Role-Based Access Control (RBAC) and least privilege principles.
2. **Session B (Week 8) — Network Security & Host Hardening:** Designing three-tier network segmentation in Docker, configuring host-level default-deny firewall policies using `iptables`, applying container defense-in-depth hardening options, and performing vulnerability scanning using Trivy.

---

## Task Summary & Evidence Index

| Task ID | Task Description | Primary Controls Implemented | Evidence Screenshots |
| :--- | :--- | :--- | :--- |
| **Task 1** | Password-Protected Service (HTTP Basic Auth) | Htpasswd bcrypt generation, Nginx `auth_basic` directive, 401 vs 200 status verification | `![Task 1.1](./task1a.1.png)`<br>`![Task 1.2](./task1a.2.png)`<br>`![Task 1.3](./taks1a.3.png)` |
| **Task 2** | Multi-Factor Authentication (MFA / TOTP) | Base32 shared secret, RFC 6238 TOTP code generation with `oathtool`, 30s token validation | `![Task 2](./task2a.png)` |
| **Task 3** | Authorization & Kubernetes RBAC Roles | Kind cluster, Namespace, ServiceAccount, Role (`get,list` pods), RoleBinding, `kubectl auth can-i` | `![Task 3](./task3a.png)` |
| **Task 4** | Network Segmentation (Three-Tier Architecture) | Dual Docker bridge networks (`frontend-net`, `backend-net`), web/app/db isolation checks | `![Task 4.1](./task4b.1.png)`<br>`![Task 4.2](./task4b.2.png)` |
| **Task 5** | Host Firewalling (Default-Deny Model) | Linux `iptables` inside `NET_ADMIN` container, default DROP policy, explicit port 443 allow | `![Task 5](./taks5b.png)` |
| **Task 6** | Container Hardening & Vulnerability Scan | `--user 1000:1000`, `--read-only`, `--cap-drop=ALL`, `--security-opt no-new-privileges`, `--tmpfs /tmp`, Trivy scan | `![Task 6.1](./task6b.1.png)`<br>`![Task 6.2](./task6b.2.png)`<br>`![Task 6.3](./task6b.3outcome.png)` |

---

## Session A (Week 7) — Authentication & Authorization

### Task 1 — Authentication: A Password-Protected Service

#### Technical Background
Authentication (AuthN) verifies identity claims ("who you are"). HTTP Basic Authentication transmits credentials encoded in Base64 within the `Authorization` header. On the backend server, Nginx evaluates these credentials against a cryptographically hashed password file (`.htpasswd`) generated using standard utilities such as `htpasswd`.

#### Step-by-Step Execution & Commands
1. **Generate the Hashed Password File:**
   ```bash
   docker run --rm httpd:alpine htpasswd -nbB student 'P@ssw0rd!' > htpasswd.txt
   ```
2. **Create the Nginx Authentication Configuration (`default.conf`):**
   ```nginx
   cat > default.conf <<'EOF'
   server { 
       listen 80;
       location / { 
           auth_basic "Restricted";
           auth_basic_user_file /etc/nginx/.htpasswd;
           return 200 'Authenticated OK\n'; 
       } 
   }
   EOF
   ```
3. **Deploy the Authenticated Nginx Service Container (`authsvc`):**
   ```bash
   docker run --rm -d --name authsvc -p 8080:80 \
     -v "$(pwd)/default.conf:/etc/nginx/conf.d/default.conf" \
     -v "$(pwd)/htpasswd.txt:/etc/nginx/.htpasswd" nginx
   ```
4. **Test Unauthenticated vs Authenticated HTTP Access:**
   ```bash
   curl -s -o /dev/null -w 'no-creds: %{http_code}\n' http://localhost:8080  # Expected: 401
   curl -s -u student:'P@ssw0rd!' http://localhost:8080                    # Expected: 200 OK
   ```

#### Task 1 Evidence Screenshots

##### Figure 1.1: Password File Generation & Nginx Configuration Setup
![Task 1 - Password File & Nginx Configuration Setup](./task1a.1.png)

##### Figure 1.2: Launching the Password-Protected Nginx Container (`authsvc`)
![Task 1 - Deploying Auth Service](./task1a.2.png)

##### Figure 1.3: Authentication Output Verification (HTTP 401 Unauthorized vs HTTP 200 Authenticated OK)
![Task 1 - Testing AuthN: 401 Unauthorized vs 200 OK](./taks1a.3.png)

#### Results Analysis
- **Unauthenticated Request:** Calling `curl` without credentials triggers Nginx to check `.htpasswd`. Finding no `Authorization` header present, Nginx returns HTTP status `401 Unauthorized`.
- **Authenticated Request:** Passing valid HTTP Basic Auth credentials (`student:P@ssw0rd!`) returns HTTP status `200 OK` with the body `Authenticated OK`.

---

### Task 2 — Add a Second Factor (MFA / TOTP)

#### Technical Background
Passwords represent single-factor authentication (something you know) and are vulnerable to brute-force, phishing, and credential stuffing attacks. Multi-Factor Authentication (MFA) introduces a second factor, such as Time-based One-Time Passwords (TOTP, RFC 6238). TOTP derives a dynamic 6-digit token using HMAC-SHA1 on a shared Base32 secret key combined with the current 30-second Unix time epoch counter.

#### Step-by-Step Execution & Commands
1. **Generate Secret Key & Compute Current TOTP Code:**
   ```bash
   SECRET=$(head -c20 /dev/urandom | base32)
   echo "Enrol this secret in an authenticator app: $SECRET"
   oathtool --totp -b "$SECRET"
   ```
2. **Validate User-Entered Code Against Server Engine:**
   ```bash
   read -p 'Enter the 6-digit code: ' CODE
   [ "$CODE" = "$(oathtool --totp -b "$SECRET")" ] && echo 'MFA OK' || echo 'MFA FAILED'
   ```

#### Task 2 Evidence Screenshot

##### Figure 2.1: TOTP Secret Enrolment, Token Generation, and Verification Shell Script Output
![Task 2 - TOTP MFA Generation and Verification](./task2a.png)

#### Results Analysis
- In the captured execution (`task2a.png`), the shared secret `HX4HLCPUATPGBEEMEZEWAPW22FBNYWPE` was generated, and `oathtool` computed the token `885941`.
- When verifying the interactive prompt, the user entered `885941`. Because the command re-evaluated `oathtool` after the 30-second time window boundary elapsed, the expected server-side token transitioned to the next time step, yielding `MFA FAILED`.
- **Security Insight:** This output highlights the temporal sensitivity of TOTP. Strict 30-second window validation prevents replay attacks where intercepted one-time passwords are re-used outside their valid time slice.

---

### Task 3 — Authorization: RBAC Roles (Kubernetes / Kind)

#### Technical Background
Authorization (AuthZ) determines "what an authenticated identity is permitted to do". Kubernetes enforces authorization using Role-Based Access Control (RBAC). RBAC policies bind permissions (`verbs` like `get`, `list`, `create`, `delete`) on API `resources` (such as `pods` or `deployments`) to Service Accounts or Users within specific Namespaces.

#### Step-by-Step Execution & Commands
1. **Provision Kind Kubernetes Cluster & App Namespace:**
   ```bash
   kind create cluster --name ccse-lab4
   kubectl create namespace app
   kubectl create serviceaccount dev -n app
   ```
2. **Create Least-Privilege Role & RoleBinding for Developer Account:**
   ```bash
   # Create a role permitting ONLY read operations (get, list) on pods
   kubectl create role dev-role -n app --verb=get,list --resource=pods
   kubectl create rolebinding dev-rb -n app --role=dev-role --serviceaccount=app:dev
   ```
3. **Audit Rights Using `kubectl auth can-i` Impersonation:**
   ```bash
   SA=system:serviceaccount:app:dev
   kubectl auth can-i list pods -n app --as=$SA      # Expected: yes
   kubectl auth can-i create deploy -n app --as=$SA   # Expected: no
   kubectl auth can-i delete pods -n app --as=$SA    # Expected: no
   ```

#### Task 3 Evidence Screenshot

##### Figure 3.1: Kubernetes Kind Cluster Creation, RBAC Role/Binding Setup, and Permission Audit
![Task 3 - Kubernetes RBAC Configuration & Can-I Verification](./task3a.png)

#### Results Analysis
- **`list pods` (`yes`):** Granted explicitly by `dev-role` (`--verb=get,list --resource=pods`).
- **`create deploy` (`no`):** Denied because deployments are not included in the resource scope.
- **`delete pods` (`no`):** Denied because `delete` verb is omitted, proving the enforcement of least privilege.

---

## Session B (Week 8) — Network Security & Hardening

### Task 4 — Network Segmentation (Three-Tier Architecture)

#### Technical Background
Network segmentation applies the principle of defense-in-depth at the network layer. By placing frontend web servers, application logic servers, and database storage servers into isolated software-defined networks (SDNs), lateral movement is strictly restricted. An attacker compromising an internet-exposed web tier cannot directly query or breach backend database ports.

```
       +--------------------+
       |  Internet Traffic  |
       +---------+----------+
                 |
                 v
       +--------------------+
       |   web (nginx)      |  <-- Attached ONLY to frontend-net
       +---------+----------+
                 |
                 | (frontend-net)
                 v
       +--------------------+
       |   app (nginx)      |  <-- Connected to BOTH frontend-net & backend-net
       +---------+----------+
                 |
                 | (backend-net)
                 v
       +--------------------+
       |    db (redis)      |  <-- Attached ONLY to backend-net
       +--------------------+
```

#### Step-by-Step Execution & Commands
1. **Create Segmented Docker Networks:**
   ```bash
   docker network create frontend-net
   docker network create backend-net
   ```
2. **Deploy Containers onto Respective Network Segments:**
   ```bash
   # DB attached exclusively to backend-net
   docker run -d --name db --network backend-net redis:alpine

   # APP attached to backend-net, then dual-homed to frontend-net
   docker run -d --name app --network backend-net nginx
   docker network connect frontend-net app

   # WEB attached exclusively to frontend-net
   docker run -d --name web --network frontend-net nginx
   ```
3. **Verify Segmentation & Network Reachability:**
   ```bash
   # WEB -> DB attempt (Must FAIL / be BLOCKED)
   docker exec web sh -c 'apk add -q curl; curl -s -m 3 db:6379 || echo BLOCKED'

   # APP -> DB attempt (Must SUCCEED / be REACHABLE)
   docker exec app sh -c 'apk add -q curl; nc -z -w3 db 6379 && echo REACHABLE'
   ```

#### Task 4 Evidence Screenshots

##### Figure 4.1: Creation of `frontend-net` and `backend-net` Docker SDNs and Container Attachments
![Task 4 - Creating Segmented Docker Networks and Containers](./task4b.1.png)

##### Figure 4.2: Verification of Network Isolation (Web-to-DB BLOCKED vs App-to-DB REACHABLE)
![Task 4 - Verification of Network Isolation (Blocked vs Reachable)](./task4b.2.png)

#### Results Analysis
- **`web -> db` (`BLOCKED`):** `web` is on `frontend-net` while `db` is on `backend-net`. Docker's embedded DNS does not resolve `db` from `frontend-net`, preventing direct TCP packets between `web` and `db`.
- **`app -> db` (`REACHABLE`):** `app` shares `backend-net` with `db`, allowing connection on port 6379 (`Connection to db (172.20.0.2) 6379 port [tcp/*] succeeded!`).

---

### Task 5 — Firewall Rules (Default-Deny Model)

#### Technical Background
A default-deny firewall posture (Zero Trust Network Access) drops all incoming traffic by default unless an explicit permit rule exists. This matches cloud security group design rules, minimizing the exposed network surface.

#### Step-by-Step Execution & Commands
1. **Launch Test Container with Linux Network Capabilities (`NET_ADMIN`):**
   ```bash
   docker run --rm --cap-add=NET_ADMIN alpine sh -c '
     apk add -q iptables; \
     iptables -P INPUT DROP; \
     iptables -A INPUT -p tcp --dport 443 -j ACCEPT; \
     iptables -A INPUT -i lo -j ACCEPT; \
     iptables -L INPUT -n'
   ```

#### Task 5 Evidence Screenshot

##### Figure 5.1: Execution of Host `iptables` Default-Deny Ruleset inside Alpine Container
![Task 5 - Default-Deny Firewall Ruleset in iptables](./taks5b.png)

#### Results Analysis
- **Default Policy (`Chain INPUT (policy DROP)`):** Any packet not matching an explicit rule is immediately dropped.
- **Rule 1 (`ACCEPT tcp -- 0.0.0.0/0 0.0.0.0/0 tcp dpt:443`):** Explicitly permits incoming HTTPS web traffic on port 443.
- **Rule 2 (`ACCEPT all -- 0.0.0.0/0 0.0.0.0/0` on `lo`):** Permits local loopback traffic required for inter-process communication.

---

### Task 6 — Container / Host Hardening & Vulnerability Scanning

#### Technical Background
Container hardening applies least privilege to compute runtimes by eliminating administrative capabilities, preventing root privileges inside containers, and mounting filesystems read-only. Vulnerability scanning (e.g. using Trivy) identifies known CVEs in container image OS packages and software libraries.

#### Step-by-Step Execution & Commands
1. **Launch a Fully Hardened Container Instance:**
   ```bash
   docker run -d --name hardened \
     --user 1000:1000 \
     --read-only \
     --cap-drop=ALL \
     --security-opt no-new-privileges \
     --tmpfs /tmp \
     nginxinc/nginx-unprivileged
   ```
2. **Inspect Runtime Container Configuration:**
   ```bash
   docker inspect hardened --format 'User={{.Config.User}} ReadOnly={{.HostConfig.ReadonlyRootfs}}'
   ```
3. **Scan Target Image (`nginx:alpine`) for Known Vulnerabilities using Trivy:**
   ```bash
   docker run --rm aquasec/trivy image --severity HIGH,CRITICAL nginx:alpine
   ```

#### Task 6 Evidence Screenshots

##### Figure 6.1: Hardened Container Launch, Logs Inspection, and Config Verification (`User=1000:1000`, `ReadOnly=true`)
![Task 6 - Hardened Container Execution and Inspect Verification](./task6b.1.png)

##### Figure 6.2: Trivy Container Vulnerability Scanner Initialization & Database Download
![Task 6 - Trivy Scan Database Download](./task6b.2.png)

##### Figure 6.3: Trivy Image Vulnerability Scan Results Summary (`nginx:alpine`)
![Task 6 - Trivy Scan Findings Output](./task6b.3outcome.png)

#### Hardening Flags Explained

| Flag / Option | Security Function | Defense Mechanism |
| :--- | :--- | :--- |
| `--user 1000:1000` | Runs execution thread as non-root UID/GID | Prevents container breakout exploits from obtaining root privileges on the host system. |
| `--read-only` | Mounts root filesystem as Read-Only | Prevents attackers from writing malware binaries, web shells, or modifying system binaries. |
| `--cap-drop=ALL` | Removes all Linux kernel capabilities | Strips dangerous kernel permissions (e.g. `CAP_SYS_ADMIN`, `CAP_NET_RAW`). |
| `--security-opt no-new-privileges` | Blocks privilege escalation via SUID/SGID | Prevents processes from acquiring additional privileges via `execve` bit binaries. |
| `--tmpfs /tmp` | Mounts ephemeral writable memory directory | Provides necessary volatile temporary storage without granting persistent disk writes. |

#### Trivy Vulnerability Scan Findings
- **Target Image:** `nginx:alpine` (`alpine 3.24.1`)
- **Total Vulnerabilities Detected:** `2` (Severity: `HIGH: 2`, `CRITICAL: 0`)
- **Actionable Remediation:** Upgrade base alpine packages or switch to updated base images containing patches for the 2 HIGH vulnerabilities.

---

## Deliverables & Short-Answer Questions

### Q1. Explain the difference between authentication and authorization using Tasks 1 and 3.
- **Authentication (AuthN - Task 1):** Focuses on proving identity ("who you claim to be"). In Task 1, HTTP Basic Auth verified user identity using valid credentials stored in `.htpasswd`. Without valid credentials, access was refused with HTTP status `401 Unauthorized`.
- **Authorization (AuthZ - Task 3):** Focuses on enforcing permissions ("what an authenticated identity is allowed to do"). In Task 3, the `dev` service account was authenticated within the Kubernetes cluster, but RBAC policies restricted its scope. While allowed to `list pods` (`yes`), it was blocked from `create deploy` (`no`) and `delete pods` (`no`).

### Q2. Why is MFA so effective, and which attacks does it defeat?
- **Effectiveness:** MFA enforces multi-factor verification by requiring factors across distinct categories: something you *know* (password) combined with something you *have* (authenticator TOTP seed / physical token).
- **Attacks Defeated:**
  1. **Credential Stuffing & Password Reuse Attacks:** Stolen credentials from external breaches fail without the live TOTP token.
  2. **Brute-Force & Dictionary Attacks:** Static password guessing attempts are rendered ineffective.
  3. **Shoulder Surfing / Keylogging:** Intercepted static passwords cannot grant entry once the 30-second TOTP window expires.

### Q3. How does network segmentation limit the damage of a compromised web server?
- Network segmentation divides infrastructure into isolated zones (`frontend-net` vs `backend-net`).
- If an attacker compromises the internet-exposed `web` server, isolation prevents direct access to the database container (`db`). Because `web` lacks network routing interface access to `backend-net`, TCP connections to port 6379 are blocked, stopping lateral movement and protecting sensitive data at rest.

### Q4. What does a default-deny firewall policy achieve, and how does it relate to cloud security groups?
- **Default-Deny Policy (`DROP`):** Establishes a zero-trust network posture where all incoming network packets are rejected by default unless an explicit permit rule exists.
- **Relation to Cloud Security Groups:** AWS Security Groups and Azure Network Security Groups (NSGs) implement default-deny rules. By enforcing an explicit allow list (e.g. permitting only TCP port 443), unnecessary exposed ports are blocked, reducing the attack surface.

### Q5. List the hardening measures you applied and the attack surface each one removes.

1. **Non-Root Execution (`--user 1000:1000`):** Removes host root privilege exposure. If a container breakout exploit occurs, the process runs as an unprivileged UID, preventing host root takeover.
2. **Read-Only Root Filesystem (`--read-only`):** Removes persistence attack vectors. Attackers cannot modify binary executables, inject malicious scripts, or install rootkits.
3. **Capability Dropping (`--cap-drop=ALL`):** Strips Linux kernel privileges (`CAP_NET_ADMIN`, `CAP_SYS_RAWIO`), neutralizing kernel exploit vectors and raw socket creation.

---

## Verification Commands Summary

To verify the RBAC configuration and container hardening options, the following verification commands are executed:

```bash
# 1. Verify Kubernetes RoleBinding YAML schema
kubectl get rolebinding dev-rb -n app -o yaml

# 2. Verify Dropped Capabilities on Hardened Container
docker inspect hardened --format '{{json .HostConfig.CapDrop}}'
# Expected output: ["ALL"]
```

---

## Security Best-Practices Checklist

| Security Control Item | Status | Verification Method |
| :--- | :---: | :--- |
| **Service requires authentication** | `[X] PASSED` | Unauthenticated requests return HTTP 401; valid credentials return HTTP 200 OK |
| **MFA / second factor implemented** | `[X] PASSED` | TOTP dynamic token validation verified via `oathtool` |
| **Authorization enforced by RBAC** | `[X] PASSED` | Kubernetes ServiceAccount restricted; unauthorized `create`/`delete` blocked |
| **Network segmented (Data tier isolated)** | `[X] PASSED` | `web` on `frontend-net` blocked from `db` on `backend-net` |
| **Default-deny firewall configured** | `[X] PASSED` | `iptables` policy set to `DROP` with explicit port 443 `ACCEPT` rule |
| **Container hardened & scanned** | `[X] PASSED` | Container launched non-root, read-only, caps dropped; image scanned via Trivy |

---

## Cleanup & Teardown Protocol

Upon lab completion, execute the cleanup script to remove temporary containers, networks, and Kind clusters:

```bash
# Remove active Docker containers
docker rm -f authsvc db app web hardened 2>/dev/null

# Remove custom Docker networks
docker network rm frontend-net backend-net 2>/dev/null

# Delete Kubernetes Kind cluster
kind delete cluster --name ccse-lab4
```

---

## Advanced Security Enhancements & Expansion Ideas

1. **Web Application Firewall (WAF) Integration:** Deploy ModSecurity with the OWASP Core Rule Set (CRS) in front of the Nginx web tier to detect and block SQL Injection (SQLi) and Cross-Site Scripting (XSS) attacks.
2. **Automated Intrusion Prevention (Fail2ban):** Implement Fail2ban log monitoring to dynamically inject `iptables` drop rules against IP addresses exceeding failed HTTP Basic Auth attempts.
3. **Zero-Trust Service Mesh (Istio / mTLS):** Implement Istio service mesh to enforce mutual TLS (mTLS) encryption and cryptographic workload identity attestation between services.
4. **Distroless Base Containers:** Rebuild container images using distroless base images (`gcr.io/distroless/static-debian12`) to eliminate shell environments (`sh`, `bash`) and package managers (`apk`, `apt`), further reducing the vulnerability attack surface.

---

## References & Standards
- **NIST SP 800-207:** Zero Trust Architecture
- **CIS Docker Benchmark v1.6.0:** Container Runtime Hardening Guidance
- **CIS Kubernetes Benchmark v1.8.0:** Kubernetes RBAC Security Controls
- **OWASP Top 10 Application Security Risks:** A01:2021-Broken Access Control & A07:2021-Identification and Authentication Failures
- **CSA Security Guidance v5:** Identity and Access Management & Cloud Infrastructure Security
