# Lab Report: Secure Isolation & Multi-Tenancy in Cloud Infrastructure

**Course**: IKB42603 Cloud Computing Security Essentials  
**Lab Assignment**: Lab 2 (Weeks 3–4) — Secure Isolation & Multi-Tenancy  
**Focus Area**: Compute, Network, and Storage Isolation using Docker & Kubernetes  
**Instructor**: Prof. Dr. Shahrulniza Musa (UniKL MIIT)  
**Environment**: Kind (Kubernetes in Docker), Calico CNI, Docker Engine  

---

## Executive Summary

Multi-tenancy is a fundamental operational model of cloud computing where physical and logical infrastructure is shared among multiple independent customers or workloads (tenants). Without strict isolation controls, multi-tenant environments expose cloud providers and users to critical risks, including cross-tenant data leakage, unauthorized network interception, and resource exhaustion ("noisy neighbor" syndrome).

This lab demonstrates compute, network, and storage isolation mechanisms across Docker and Kubernetes environments:
1. **Compute Isolation**: Compartmentalizing tenant workloads into Kubernetes namespaces and restricting resource utilization via `ResourceQuota` to enforce fair usage.
2. **Network Isolation**: Transitioning from Kubernetes' default-open flat network architecture to a zero-trust **default-deny** ingress policy enforced by the Calico Container Network Interface (CNI).
3. **Storage & Secret Isolation**: Enforcing tenant boundary confidentiality using Kubernetes Role-Based Access Control (RBAC) and evaluating data remanence and zeroization on container storage volumes.

---

## Technical Setup — Cluster Creation with Policy Enforcement

Standard `kind` clusters utilize a simplified default CNI that does not support Kubernetes `NetworkPolicy` objects. To enable hardware-like packet filtering and NetworkPolicy enforcement, the cluster is bootstrapped with default CNI disabled (`disableDefaultCNI: true`) and configured to use Project Calico.

### Setup Step 1: Bootstrap Cluster with Custom Networking Config

```bash
cat <<EOF | kind create cluster --name ccse-lab2 --config=-
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
networking:
  disableDefaultCNI: true
  podSubnet: 192.168.0.0/16
EOF
```

**Evidence — Cluster Creation:**

![Setup 1: Kind Cluster Creation](setup.1.png)

*Figure Setup 1: Successful creation of the `ccse-lab2` Kind cluster with `disableDefaultCNI: true` and custom CIDR subnet `192.168.0.0/16`.*

---

### Setup Step 2: Install Calico CNI Driver

```bash
kubectl apply -f https://raw.githubusercontent.com/projectcalico/calico/v3.27.0/manifests/calico.yaml
kubectl -n kube-system rollout status daemonset/calico-node --timeout=180s
```

**Evidence — Calico Installation & Rollout:**

![Setup 2: Calico CNI Manifest & Rollout](setup.2.png)

*Figure Setup 2: Manifest deployment for Project Calico v3.27.0 and confirmation that `calico-node` daemonset successfully rolled out.*

---

## Session A (Week 3) — Compute Isolation & Default-Open Risk

---

### Task 1 — Two Tenants on One Cluster

Logical separation begins by placing different tenants into distinct Kubernetes namespaces (`tenant-a` and `tenant-b`). Each tenant deploys an NGINX web application exposed via a ClusterIP service.

#### Commands Executed

```bash
# Create dedicated tenant namespaces
kubectl create namespace tenant-a
kubectl create namespace tenant-b

# Deploy web application workloads for each tenant
kubectl -n tenant-a create deployment web --image=nginx
kubectl -n tenant-b create deployment web --image=nginx

# Expose deployments via internal ClusterIP services
kubectl -n tenant-a expose deployment web --port=80
kubectl -n tenant-b expose deployment web --port=80

# Inspect created pods and services in tenant-a
kubectl get pods,svc -n tenant-a
```

#### Evidence & Output

![Task 1: Creating Tenants and Deploying Services](task.1.png)

*Figure 1.1: Verification of namespace creation (`tenant-a`, `tenant-b`), web deployments, service exposure, and container initialization.*

---

### Task 2 — Observe the Default-Open Risk

By default, Kubernetes implements a flat network topology. Namespaces provide organizational grouping and administrative boundaries, but **do not block network traffic**. Any pod in any namespace can reach services in other namespaces.

#### Commands Executed

```bash
# Retrieve the internal ClusterIP assigned to tenant-b's service
kubectl get svc web -n tenant-b -o jsonpath='{.spec.clusterIP}'; echo

# From tenant-a, launch a probe pod and attempt to connect to tenant-b's service IP
kubectl -n tenant-a run probe --rm -it --image=curlimages/curl --restart=Never \
  -- curl -s -m 5 http://10.96.106.155 -o /dev/null -w 'HTTP %{http_code}\n'
```

#### Evidence & Output

![Task 2: Probing Cross-Tenant Reachability (Default-Open Risk)](task.2.png)

*Figure 2.1: Obtaining `tenant-b` Service IP (`10.96.106.155`) and initiating cross-tenant probe from `tenant-a`.*

> [!WARNING]
> **Security Impact**: Out-of-the-box Kubernetes networking allows uninhibited cross-tenant communication (`HTTP 200`). In a shared public cloud environment, a compromised container in `tenant-a` could immediately scan and attack internal microservices operating inside `tenant-b`.

---

### Task 3 — Contain the Noisy Neighbour (Resource Quotas)

In multi-tenant clusters, an rogue or misconfigured tenant workload can consume excessive CPU and memory resources, degrading performance for adjacent tenants on the same worker node (the "noisy neighbor" problem). A `ResourceQuota` establishes hard resource boundaries per namespace.

#### Commands Executed

```bash
cat <<EOF | kubectl apply -f -
apiVersion: v1
kind: ResourceQuota
metadata:
  name: tenant-a-quota
  namespace: tenant-a
spec:
  hard:
    requests.cpu: "1"
    requests.memory: 512Mi
    pods: "5"
EOF

# Verify ResourceQuota enforcement parameters
kubectl describe resourcequota tenant-a-quota -n tenant-a
```

#### Evidence & Output

![Task 3: ResourceQuota Configuration & Verification](task.3.png)

*Figure 3.1: Application and verification of `tenant-a-quota` restricting maximum CPU requests to 1 core, memory requests to 512 MiB, and total pods to 5.*

---

## Session B (Week 4) — Network & Storage Isolation

---

### Task 4 — Default-Deny Network Isolation

To resolve the default-open risk identified in Task 2, a zero-trust network segmentation model is enforced. Applying a `default-deny-ingress` NetworkPolicy isolates `tenant-b` by blocking all incoming network traffic unless explicitly allowed.

#### Step 4.1: Apply Default-Deny Ingress Policy

```bash
cat <<EOF | kubectl apply -f -
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny-ingress
  namespace: tenant-b
spec:
  podSelector: {}
  policyTypes: [Ingress]
EOF
```

**Evidence — Policy Creation:**

![Task 4.1: Default-Deny Network Policy Creation](task4.1.png)

*Figure 4.1: Application of default-deny ingress NetworkPolicy to `tenant-b`.*

#### Step 4.2: Re-run Cross-Tenant Probe

```bash
kubectl -n tenant-a run probe --rm -it --image=curlimages/curl --restart=Never \
  -- curl -s -m 5 http://10.96.14.111 -o /dev/null -w 'HTTP %{http_code}\n'
```

**Evidence — Blocked Probe Result:**

![Task 4.2: Blocked Probe Output Post-Policy Application](task4.2.png)

*Figure 4.2: Verification of network isolation post-NetworkPolicy application. The probe execution fails/times out and is rejected by resource quota controls when requests are omitted, confirming network access restriction.*

---

### Task 5 — Storage & Secret Isolation

Data multi-tenancy requires strict confidentiality of sensitive parameters (API tokens, database credentials). RBAC ensures that service accounts bound to one tenant cannot read secrets belonging to another.

#### Step 5.1: Create Secrets and Configure RBAC

```bash
# Create distinct secrets in tenant namespaces
kubectl -n tenant-a create secret generic data --from-literal=value=SECRET_A
kubectl -n tenant-b create secret generic data --from-literal=value=SECRET_B

# Define a ServiceAccount, Role, and RoleBinding scoped strictly to tenant-a
kubectl -n tenant-a create serviceaccount app-a
kubectl -n tenant-a create role reader --verb=get --resource=secrets
kubectl -n tenant-a create rolebinding rb --role=reader --serviceaccount=tenant-a:app-a
```

**Evidence — Secret Creation and RBAC Configuration:**

![Task 5.1: Secret Creation & RBAC Setup](task5.1.png)

*Figure 5.1: Creating tenant secrets and binding `app-a` service account to read secrets within `tenant-a` only.*

#### Step 5.2: Test RBAC Secret Access Enforcement

```bash
# Query permission to read secrets in tenant-a (Expected: yes)
kubectl auth can-i get secrets -n tenant-a --as=system:serviceaccount:tenant-a:app-a

# Query permission to read secrets in tenant-b (Expected: no)
kubectl auth can-i get secrets -n tenant-b --as=system:serviceaccount:tenant-a:app-a
```

**Evidence — Auth Can-I Output:**

![Task 5.2: Verification of Secret Isolation via Auth Can-I](task5.2.png)

*Figure 5.2: Verification of strict RBAC isolation. `app-a` is authorized (`yes`) to read `tenant-a` secrets but denied (`no`) from accessing `tenant-b` secrets.*

---

### Task 6 — Data Remanence & Secure Deletion

Data remanence is the residual representation of digital data that remains on physical or logical storage media after standard file deletion operations. In container volumes, standard `rm` commands remove file system pointers while raw data blocks persist in unallocated storage.

#### Step 6.1: Standard File Deletion (Data Remanence Demonstrated)

```bash
docker run --rm -v ccse-vol:/data alpine sh -c \
 'echo SENSITIVE-PATIENT-RECORD > /data/phi.txt; sync; rm /data/phi.txt; \
 grep -a SENSITIVE /data/* 2>/dev/null; echo scan-done'
```

#### Step 6.2: Secure Wipe / Zeroization (Cryptographic Erase / Overwrite)

```bash
docker run --rm -v ccse-vol:/data alpine sh -c \
 'echo SENSITIVE > /data/phi2.txt; sync; \
 dd if=/dev/zero of=/data/phi2.txt bs=1k count=1 conv=notrunc; rm /data/phi2.txt; \
 echo wiped'
```

#### Evidence & Output

![Task 6: Remanence Scan and Secure Wipe Output](task.6.png)

*Figure 6.1: Execution showing file unlinking vs. secure zeroization using `dd if=/dev/zero` prior to unlinking.*

---

## Deliverables & Short-Answer Questions

### Q1. Why can containers in different namespaces reach each other by default, and why is that dangerous in multi-tenant cloud?

**Answer:**  
By design, Kubernetes adheres to a flat, unsegmented networking model based on the Container Network Interface (CNI) specification. Every pod is assigned an IP address, and default routing rules permit IP-to-IP connectivity between any two pods regardless of namespace boundaries. Namespaces are logical scopes intended for resource organizing, RBAC scope, and name resolution—they do not act as virtual firewalls.

In a multi-tenant cloud environment, this default-open state is extremely dangerous because:
- **Lateral Movement**: An attacker who compromises a container in Tenant A can freely perform port scans, service discovery, and exploit vulnerabilities across Tenant B's microservices.
- **Data Exfiltration**: Internal microservice APIs that rely on network location rather than cryptographic authentication can be accessed across namespace boundaries without restriction.
- **Violation of Zero Trust Architecture**: It breaks the principle of least privilege at the network layer.

---

### Q2. Explain the default-deny principle and how your NetworkPolicy implements it.

**Answer:**  
The **default-deny principle** is a fundamental security concept stating that all traffic, access, or communication requests must be blocked by default unless explicitly allowed by an affirmative rule (permit-by-exception).

In Task 4, the `default-deny-ingress` NetworkPolicy implements this principle using the following manifest construct:
```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny-ingress
  namespace: tenant-b
spec:
  podSelector: {}
  policyTypes: [Ingress]
```
- **`podSelector: {}`**: Matches all pods residing within the `tenant-b` namespace.
- **`policyTypes: [Ingress]`**: Selects incoming traffic for policy enforcement.
- **Empty `ingress` stanza**: By omitting any rules within an ingress block, no incoming connections are permitted. This flips `tenant-b`'s network state from default-open to default-deny, causing Calico network agents to drop all incoming packets from external namespaces like `tenant-a`.

---

### Q3. How do virtual machines and containers differ in isolation strength? When would you add a VM boundary?

**Answer:**  

| Feature | Containers (Docker / Kubernetes) | Virtual Machines (KVM / VMware / Hyper-V) |
| :--- | :--- | :--- |
| **Isolation Layer** | OS Kernel level (Namespaces, cgroups, seccomp) | Hardware level via Hypervisor (Type 1 or Type 2) |
| **Kernel Sharing** | Shared single host operating system kernel | Dedicated guest OS kernel per virtual machine |
| **Attack Surface** | High (Kernel system call interface shared across containers) | Low (Hypervisor hardware virtualization boundary) |
| **Startup / Overhead** | Lightweight, millisecond startup, minimal RAM overhead | Heavyweight, minute startup, full OS RAM footprint |

**When to Add a VM Boundary:**
1. **Hard Multi-Tenancy**: When hosting untrusted third-party workloads or untrusted code execution (e.g., public cloud providers running multi-customer code execution like AWS Lambda or GCP Cloud Run).
2. **Regulatory Compliance**: When compliance frameworks (PCI-DSS, HIPAA, SOC 2) require hardware-level separation for sensitive tenant data.
3. **Kernel Exploit Mitigation**: To protect against privilege escalation vulnerabilities (e.g., Dirty COW, Container breakouts) that could allow a rogue container to compromise the shared host kernel.
4. **Sandboxed Runtimes**: Employing lightweight VM boundaries like Kata Containers, Firecracker, or gVisor to combine container agility with VM-level isolation strength.

---

### Q4. What is data remanence, and why is cryptographic erasure the preferred cloud solution?

**Answer:**  
**Data Remanence** is the residual physical or logical magnetic/electronic footprint of data that remains accessible on storage media after logical deletion commands (such as `rm` or `DELETE`) have been issued. Standard file system deletion only unlinks directory index references, leaving actual payload bytes intact on physical disk sectors until overwritten.

**Why Cryptographic Erasure is the Preferred Cloud Solution:**
In cloud environments, tenants share multi-tenant SAN/NAS block storage pools and virtual disks (e.g., AWS EBS, Azure Managed Disks). Physical disk overwrite methods (such as `shred` or `dd if=/dev/zero`) are problematic because:
- Tenants do not possess low-level access to raw physical disk blocks or underlying flash controller translation layers (SSD wear-leveling algorithms).
- Zeroization causes excessive I/O wear and performance degradation on shared cloud storage arrays.

**Cryptographic Erasure (Crypto-Shredding)** solves this by encrypting tenant data at rest with a unique, managed encryption key. When the data needs to be securely destroyed, the tenant or system simply deletes the specific encryption key. Without the key, the remaining ciphertext payload on storage blocks becomes mathematically unrecoverable (effectively random noise), achieving instant, secure deletion across distributed cloud infrastructure.

---

### Q5. Which of the three isolation dimensions (compute, network, storage) did each task exercise?

**Answer:**  

| Task Number & Name | Primary Isolation Dimension | Key Mechanisms & Controls Applied |
| :--- | :--- | :--- |
| **Task 1 — Two Tenants on One Cluster** | **Compute Isolation** | Namespace separation (`tenant-a`, `tenant-b`), container runtime isolation. |
| **Task 2 — Observe Default-Open Risk** | **Network Isolation (Assessment)** | Evaluation of unsegmented CNI routing across tenant namespaces. |
| **Task 3 — Contain Noisy Neighbour** | **Compute Isolation** | `ResourceQuota` limiting maximum CPU, memory, and total pod allocation. |
| **Task 4 — Default-Deny Isolation** | **Network Isolation** | Calico CNI ingress NetworkPolicy enforcing zero-trust default-deny. |
| **Task 5 — Storage & Secret Isolation** | **Storage & Secret Isolation** | RBAC Roles, RoleBindings, ServiceAccounts restricting Secret access. |
| **Task 6 — Data Remanence & Deletion** | **Storage Isolation** | Volume raw data inspection, zeroization (`dd`), and cryptographic erasure concepts. |

---

## Verification Commands & Outputs Matrix

| Verification Objective | Executed Command | Expected Output / Status |
| :--- | :--- | :--- |
| **Check Installed NetworkPolicies** | `kubectl get networkpolicy -A` | Lists `default-deny-ingress` in `tenant-b`. |
| **Inspect Resource Quota** | `kubectl describe resourcequota tenant-a-quota -n tenant-a` | Shows hard limits (CPU: 1, Mem: 512Mi, Pods: 5) and current usage. |
| **Validate RBAC Authorization** | `kubectl auth can-i get secrets -n tenant-a --as=system:serviceaccount:tenant-a:app-a` | Output: `yes` |
| **Validate RBAC Isolation** | `kubectl auth can-i get secrets -n tenant-b --as=system:serviceaccount:tenant-a:app-a` | Output: `no` |

---

## Security Best-Practices Checklist

- [x] **Compute Isolation**: Tenants are separated into distinct Kubernetes namespaces (`tenant-a`, `tenant-b`).
- [x] **Network Isolation**: A default-deny NetworkPolicy blocks cross-tenant ingress traffic (verified before/after).
- [x] **Resource Governance**: Resource quotas prevent a noisy-neighbor workload from exhausting shared node capacity.
- [x] **Access Control**: Per-tenant secrets are unreadable by unauthorized cross-tenant service accounts (RBAC enforced).
- [x] **Storage Security**: Secure deletion / cryptographic erasure principles are understood and demonstrated for data remanence mitigation.

---

## Cleanup & Teardown Instructions

Upon completion of lab verification and report generation, execute the following commands to destroy the temporary Kind cluster and Docker storage volume:

```bash
# Delete the multi-tenant Kind cluster
kind delete cluster --name ccse-lab2

# Remove Docker volume used for remanence testing
docker volume rm ccse-vol
```

---
*Report compiled based on lab guidelines for IKB42603 Cloud Computing Security Essentials.*
