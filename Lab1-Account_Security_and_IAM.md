# LAB 1 — WEEKS 1–2: Cloud Account Security, Identity & Access Management
**Identity Governance and Least Privilege — LocalStack IAM & Kubernetes RBAC**

- **Course:** IKB42603 Cloud Computing Security Essentials
- **Institution:** UniKL MIIT
- **Instructor:** Prof. Dr. Shahrulniza Musa
- **Document Title:** Lab 1 Final Report — Cloud Account Security & IAM
- **Target Environment:** LocalStack (AWS IAM Simulator) & Kind (Kubernetes-in-Docker RBAC)

---

## Executive Summary & Overview

This laboratory report documents the implementation and verification of fundamental cloud security controls, focusing on **Identity and Access Management (IAM)** and **Role-Based Access Control (RBAC)** across simulated cloud environments (AWS via LocalStack) and container orchestration platforms (Kubernetes via Kind).

### Lab Learning Outcomes
1. Stand up a local cloud lab using Docker and LocalStack (an AWS-compatible simulator).
2. Apply the **principle of least privilege** by replacing root usage with scoped IAM users, groups, and policies.
3. Create and test fine-grained permissions, distinguishing what an identity is *allowed* versus *denied* to do.
4. Implement and verify **Role-Based Access Control (RBAC)** in Kubernetes as an enforcement engine.
5. Audit identities and reason about Multi-Factor Authentication (MFA), access key rotation, and credential hygiene.

### Course & Assessment Mapping
| Item | Mapping |
| :--- | :--- |
| **Course Learning Outcome** | **CLO2** — Construct secure cloud operations that safeguard data integrity |
| **Lecture Topics** | Weeks 1–2 (Fundamentals, Security Architecture) · Weeks 5 & 7 (Access Control, Identity) |
| **Value / Skill Clusters** | VBE3 (Integrity) · SC8 (Integrated Problem-Solving) |
| **Assessment Type** | Lab Report (Screenshots + CLI Output + Analysis Answers) |

### Technical Prerequisites
- Laptop with at least 8 GB RAM and Administrator rights.
- **Docker Desktop / Engine** (Containerization platform).
- **AWS CLI v2** (Configured against LocalStack endpoint `http://localhost:4566`).
- **kind** (Kubernetes-in-Docker) and **kubectl** CLI utility.
- Isolated local cloud environment (No connection to live cloud providers).

---

## Session A (Week 1) — Cloud Identity with LocalStack

### One-Time Environment Setup

The lab setup initializes Docker Desktop and launches the LocalStack container to emulate AWS IAM services locally. The AWS CLI is configured with non-sensitive test credentials pointing to `http://localhost:4566`.

#### Setup Execution Commands:
```bash
# 1. Confirm Docker is installed and running
docker --version

# 2. Start LocalStack (AWS-compatible cloud simulator) in a container
docker run -d --name localstack -p 4566:4566 localstack/localstack

# 3. Confirm container health status
curl http://localhost:4566/_localstack/health

# 4. Configure dummy credentials (LocalStack accepts any credentials)
aws configure set aws_access_key_id test
aws configure set aws_secret_access_key test
aws configure set region us-east-1

# 5. Define helper environment variable for LocalStack endpoint
EP='--endpoint-url=http://localhost:4566'

# 6. Verify operation identity against LocalStack STS
aws $EP sts get-caller-identity
```

---

### Task 1 — Map the Cloud Identity Landscape

Before configuring identities, the primary building blocks of cloud identity management are mapped in the table below:

| Concept | AWS Term | Purpose (Detailed Description) |
| :--- | :--- | :--- |
| **All-powerful owner** | **Root user** | The initial super-user identity created upon AWS account creation. Has complete, unrestricted access to all resources and billing. Should be locked down with MFA and avoided for daily operational tasks. |
| **Human/app identity** | **IAM User** | A persistent identity created within AWS to represent a specific person or service, configured with custom long-term credentials (passwords or programmatic access key pairs). |
| **Permission bundle** | **IAM Policy** | A structured JSON document defining explicit permission statements (Allow/Deny rules over specific Actions, Resources, and Conditions). Attached to users, groups, or roles. |
| **Collection of users** | **IAM Group** | A collection of IAM Users used to administer permissions collectively. Granting policies to groups enforces consistent permissions across team members and avoids individual user drift. |
| **Temporary identity** | **IAM Role** | An identity with specific permissions meant to be assumed temporarily by authorized users, applications, or services, providing temporary security tokens without long-lived keys. |

---

### Task 2 — Create a Least-Privilege Admin (Stop Using Root)

Using the account root user for daily administrative operations introduces severe security risk. To mitigate this, a dedicated `Admins` group was created, populated with administrative policies, and assigned a dedicated user (`CloudAdmin_YOURNAME`).

#### Step-by-Step Execution Commands:
```bash
# 2.1 Create an Admins group and attach AWS managed AdministratorAccess policy
aws $EP iam create-group --group-name Admins
aws $EP iam attach-group-policy --group-name Admins \
  --policy-arn arn:aws:iam::aws:policy/AdministratorAccess

# 2.2 Create dedicated personal administrator user
aws $EP iam create-user --user-name CloudAdmin_YOURNAME

# 2.3 Add user to Admins group (permissions flow automatically from group)
aws $EP iam add-user-to-group --group-name Admins \
  --user-name CloudAdmin_YOURNAME

# 2.4 Verify group membership and user assignment
aws $EP iam get-group --group-name Admins
```

#### Verification Evidence & Terminal Screenshots:
<img width="677" height="817" alt="1 task2" src="https://github.com/user-attachments/assets/66e2db71-9bd2-4934-81ff-16d5ebfc1361" />

*Figure 2.1: Terminal output displaying group creation, policy attachment, user provisioning, and group assignment.*

<img width="667" height="400" alt="1 outcome t2 " src="https://github.com/user-attachments/assets/295c096c-bcea-4e73-abc3-477bbb4d9c2a" />

*Figure 2.2: JSON output verifying that `CloudAdmin_YOURNAME` is an active member of the `Admins` IAM group.*

> [!TIP]
> **Security Best Practice:** Attaching permission policies to IAM Groups rather than individual IAM Users simplifies audits, maintains policy uniformity, and avoids privilege accumulation over time.

---

### Task 3 — Enforce Least Privilege with a Scoped Policy

To implement fine-grained access control, a non-administrative identity (`Analyst_YOURNAME`) was created for data analysis duties, restricted exclusively to read-only S3 operations.

#### Step-by-Step Execution Commands:
```bash
# 3.1 Create read-only user for analysis tasks
aws $EP iam create-user --user-name Analyst_YOURNAME

# 3.2 Attach scoped read-only policy (AmazonS3ReadOnlyAccess)
aws $EP iam attach-user-policy --user-name Analyst_YOURNAME \
  --policy-arn arn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess

# 3.3 Verify attached user policies
aws $EP iam list-attached-user-policies --user-name Analyst_YOURNAME
```

#### Verification Evidence & Terminal Screenshots:
<img width="717" height="511" alt="2 task3 " src="https://github.com/user-attachments/assets/367d484a-1fa8-486c-a5c2-6530ef295522" />

*Figure 3.1: Execution log showing creation of `Analyst_YOURNAME` and attachment of `AmazonS3ReadOnlyAccess` policy.*

#### Security Analysis: Blast-Radius Reduction
If the `Analyst_YOURNAME` account credentials are compromised by an attacker:
1. **Scope Restriction:** The attacker can only execute `get` and `list` operations against Amazon S3 data.
2. **Blast Radius Limitation:** The attacker is strictly blocked from writing, altering, or deleting S3 objects, nor can they create IAM identities, alter networking configs, or touch EC2 compute instances.
3. **Comparison to Admin Compromise:** If an administrative account were stolen, the blast radius would include total infrastructure wipeout, resource hijacking, and credential exfiltration. Least privilege confines potential security breach damage to a minimal boundary.

---

### Task 4 — Credential Hygiene & Access Keys

Programmatic access to cloud APIs requires access key pairs. To maintain credential security, long-lived access keys must be regularly audited and rotated.

#### Step-by-Step Execution Commands:
```bash
# 4.1 Create an initial access key pair for Analyst
aws $EP iam create-access-key --user-name Analyst_YOURNAME

# 4.2 List active access keys associated with user
aws $EP iam list-access-keys --user-name Analyst_YOURNAME

# 4.3 Key Rotation: Deactivate old key by ID
aws $EP iam update-access-key --user-name Analyst_YOURNAME \
  --access-key-id LKIAQAAAAAAAJ5XLE2OL --status Inactive
```

#### Verification Evidence & Terminal Screenshots:
<img width="676" height="470" alt="3 task4" src="https://github.com/user-attachments/assets/5b289eb0-28da-48b8-aec5-c8316941fa52" />

*Figure 4.1: Creation of AccessKey ID `LKIAQAAAAAAA********` and key metadata listing.*


<img width="402" height="110" alt="3 outcome" src="https://github.com/user-attachments/assets/9703bf94-7fbc-41a5-9052-f614bebcd935" />

*Figure 4.2: Deactivation command putting access key into `Inactive` status.*

> [!CAUTION]
> **Credential Hygiene Rule:** In production environments, never create access keys for Root users and never commit access key secrets to code repositories. Prefer temporary security credentials via IAM Roles (e.g., AWS STS / IAM Identity Center).

---

## Session B (Week 2) — Enforced Access Control with Kubernetes RBAC

While LocalStack validates IAM mechanics, Kubernetes Role-Based Access Control (RBAC) acts as an active runtime enforcement engine that intercept API requests and blocks unauthorized actions.

### Setup — Create a Local Kubernetes Cluster

A lightweight local Kubernetes cluster (`ccse-lab1`) was launched using `kind` (Kubernetes-in-Docker).

```bash
# Create local single-node cluster
kind create cluster --name ccse-lab1

# Verify cluster control-plane and nodes
kubectl cluster-info --context kind-ccse-lab1
kubectl get nodes
```
<img width="852" height="427" alt="4 section2 1" src="https://github.com/user-attachments/assets/8b1155b2-5957-46f1-adad-b561fe4d364a" />

*Figure B.1: Terminal output demonstrating Kind cluster `ccse-lab1` creation and active node status.*

---

### Task 5 — Separate Environments with Namespaces

Namespaces provide logical partition boundaries within a Kubernetes cluster to segregate work environments (e.g., development vs production).

```bash
# Create isolated dev and prod namespaces
kubectl create namespace dev
kubectl create namespace prod

# List active cluster namespaces
kubectl get namespaces
```

<img width="312" height="241" alt="5 section 2 2" src="https://github.com/user-attachments/assets/cf89fd8e-1932-42e0-b60f-0d7ff3d2dd02" />

*Figure 5.1: Creation and verification of `dev` and `prod` namespaces.*

---

### Task 6 — Define a Role and Bind It (Least Privilege)

Kubernetes RBAC relies on three core entities:
1. **ServiceAccount:** Identity representing a workload or developer within a namespace.
2. **Role:** List of permitted actions (`verbs`) on specific `resources` within a namespace.
3. **RoleBinding:** Link associating a ServiceAccount with a specific Role.

```bash
# 6.1 Create service account representing a developer in 'dev' namespace
kubectl create serviceaccount dev-user -n dev

# 6.2 Create Role granting read-only pod access in 'dev' namespace
kubectl create role pod-reader -n dev \
  --verb=get,list,watch --resource=pods

# 6.3 Bind Role to dev-user ServiceAccount
kubectl create rolebinding dev-user-binding -n dev \
  --role=pod-reader --serviceaccount=dev:dev-user
```

<img width="537" height="322" alt="6 section 2 3" src="https://github.com/user-attachments/assets/14d339a0-9f6e-405c-9a25-b4f04936caf1" />

*Figure 6.1: Creation of `dev-user` ServiceAccount, `pod-reader` Role, and `dev-user-binding` RoleBinding.*

---

### Task 7 — Test That Access Control Works

The authorization enforcement engine was tested using `kubectl auth can-i` under the identity of `dev-user`.

```bash
# Set environment variable for ServiceAccount fully-qualified identity
SA=system:serviceaccount:dev:dev-user

# Test 1: List pods in dev namespace (Allowed)
kubectl auth can-i list pods -n dev --as=$SA
# Output: yes

# Test 2: Delete pods in dev namespace (Forbidden)
kubectl auth can-i delete pods -n dev --as=$SA
# Output: no

# Test 3: List pods in prod namespace (Forbidden - cross-namespace access)
kubectl auth can-i list pods -n prod --as=$SA
# Output: no
```

<img width="430" height="241" alt="7  section 2 4" src="https://github.com/user-attachments/assets/d4d3be0f-ae34-409b-b63d-da093ac16b75" />

*Figure 7.1: Verification results for authorization checks (`yes` / `no` / `no`).*

#### Detailed Evaluation: Authentication vs. Authorization
- **Authentication Step:** In all three tests, Kubernetes successfully authenticated the caller identity (`system:serviceaccount:dev:dev-user`). The identity was recognized as valid by the cluster API server.
- **Authorization Step:**
  - **Test 1 (`list pods -n dev`):** **Passed Authorization** (`yes`) because `pod-reader` explicitly permits `get`, `list`, `watch` verbs on `pods` within namespace `dev`.
  - **Test 2 (`delete pods -n dev`):** **Blocked by Authorization** (`no`) because the `delete` verb is absent from the `pod-reader` role definition.
  - **Test 3 (`list pods -n prod`):** **Blocked by Authorization** (`no`) because `pod-reader` and `dev-user-binding` are scoped strictly to namespace `dev`. RBAC rules do not grant access outside their assigned namespace.

---

## Deliverables & Assessment

### 1. Complete Evidence Screenshots Mapping

| # | Deliverable Requirement | Screenshot Artifact | Verified Command / Output |
| :---: | :--- | :--- | :--- |
| **1** | STS Operating Identity | `1.task2.png` | `aws $EP sts get-caller-identity` |
| **2** | Admin Group Membership | `1.outcome t2 .png` | `aws $EP iam get-group --group-name Admins` |
| **3** | Analyst Scoped Policy List | `2.task3 .png` | `aws $EP iam list-attached-user-policies --user-name Analyst_YOURNAME` |
| **4** | Access Key Creation & List | `3.task4.png` | `aws $EP iam list-access-keys --user-name Analyst_YOURNAME` |
| **5** | Access Key Deactivation | `3.outcome.png` | `aws $EP iam update-access-key --status Inactive` |
| **6** | Kind K8s Cluster | `4.section2.1.png` | `kind create cluster --name ccse-lab1` |
| **7** | K8s Namespaces | `5.section 2.2.png` | `kubectl get namespaces` |
| **8** | K8s Role & Binding Setup | `6.section 2.3.png` | `kubectl create rolebinding dev-user-binding` |
| **9** | K8s Authorization Verification | `7. section 2.4.png` | `kubectl auth can-i ... --as=$SA` |
| **10** | RBAC YAML Export | `0.3. verification command .png` | `kubectl get rolebinding dev-user-binding -n dev -o yaml` |
| **11** | Cleanup & Teardown | `cleanup & teardown .png` | `kind delete cluster && docker stop localstack` |

---

### 2. Short-Answer Questions

#### Q1. Why is attaching policies to groups better than attaching them directly to users?
**Answer:** Attaching policies to groups ensures centralized, scalable, and manageable permission administration. When job roles evolve or security policies require updating, modifying the group policy automatically updates permissions for all member users simultaneously. In contrast, assigning policies directly to individual users leads to "privilege creep" (accumulation of unneeded rights), policy fragmentation, and increased audit complexity as organizations scale.

#### Q2. What is the difference between an IAM User and an IAM Role?
**Answer:** An **IAM User** represents a permanent identity associated with a specific person or service, accompanied by persistent long-term credentials (console password or static access key pairs). An **IAM Role** is an identity that does not have permanent credentials attached to it; instead, authorized entities (users, services, or external applications) assume the Role temporarily to receive short-lived, auto-expiring security tokens generated by AWS STS.

#### Q3. Explain least privilege using the Analyst account, and how it reduces blast radius if compromised.
**Answer:** The principle of least privilege dictates that an identity should receive only the minimum access rights essential to fulfill its specified task. `Analyst_YOURNAME` was granted read-only access to S3 (`AmazonS3ReadOnlyAccess`). If an attacker steals the Analyst's credentials, the **blast radius** is constrained strictly to reading S3 bucket contents. The attacker cannot alter or delete data, shut down compute nodes, modify security policies, or access other cloud services, preventing total system compromise.

#### Q4. In Kubernetes, what is the difference between a Role and a RoleBinding?
**Answer:** A **Role** is an API object that defines *what actions are allowed* (verbs like `get`, `list`, `watch`) on specific API resources (like `pods` or `services`) within a single namespace. A **RoleBinding** is an API object that defines *who receives those permissions* by linking (binding) a Role to one or more subjects (such as a `ServiceAccount`, `User`, or `Group`) within that namespace.

#### Q5. Why did the developer service account fail to access prod, and which security principle does that demonstrate?
**Answer:** The `dev-user` service account failed to list pods in `prod` because both the `pod-reader` Role and the `dev-user-binding` RoleBinding were explicitly scoped to the `dev` namespace (`-n dev`). In Kubernetes RBAC, namespace-scoped roles provide no permissions outside their target namespace. This demonstrates the principle of **Default Deny / Implicit Deny** and **Namespace Compartmentalization**, where access across security boundaries is denied unless explicitly permitted.

---

### 3. Verification Command Output

#### Command Executed:
```bash
kubectl get rolebinding dev-user-binding -n dev -o yaml
```

#### Output Captured:
```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  creationTimestamp: "2026-08-05T08:45:58Z"
  name: dev-user-binding
  namespace: dev
  resourceVersion: "1703"
  uid: 3e186d73-017d-4039-847a-b6a3ab357e83
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: Role
  name: pod-reader
subjects:
- kind: ServiceAccount
  name: dev-user
  namespace: dev
```

<img width="493" height="300" alt="0 3  verification command " src="https://github.com/user-attachments/assets/5d065369-05d6-44d6-b716-2cc5e304088b" />

*Figure V.1: Terminal YAML output confirming active RoleBinding structure connecting `pod-reader` Role with `dev-user` ServiceAccount.*

---

### Security Best-Practices Checklist

- [x] **Root user is not used for daily tasks:** Dedicated admin group (`Admins`) and user (`CloudAdmin_YOURNAME`) created.
- [x] **Permissions granted via groups/roles:** Attached `AdministratorAccess` to `Admins` group rather than directly to user.
- [x] **Least-privilege read-only identity created & tested:** Created `Analyst_YOURNAME` with `AmazonS3ReadOnlyAccess`.
- [x] **Access key rotation demonstrated:** Created key `LKIAQAAAAAAAJ5XLE2OL` and updated status to `Inactive`.
- [x] **Kubernetes RBAC blocks unauthorized action:** Verified deletion failure (`no`) and cross-namespace failure (`prod` -> `no`).

---

## Cleanup & Teardown

To ensure complete resource reclamation and prevent orphan containers, the cluster and localstack resources were deleted at lab conclusion.

#### Cleanup Commands:
```bash
# Remove local Kubernetes cluster
kind delete cluster --name ccse-lab1

# Stop and remove LocalStack container
docker stop localstack && docker rm localstack
```

<img width="422" height="157" alt="cleanup   teardown " src="https://github.com/user-attachments/assets/9078b7c6-f375-408d-8631-74a5fb6ae21f" />

*Figure C.1: Terminal output verifying deletion of Kind cluster nodes and LocalStack container cleanup.*

---

## Expansion Ideas & Advanced Topics

1. **Infrastructure as Code (IaC):** Recreate the AWS IAM group, user provisioning, and policy attachments using Terraform scripts targeted at LocalStack endpoint (`http://localhost:4566`).
2. **Policy Conditions:** Implement IAM JSON policies with strict condition keys, such as `aws:MultiFactorAuthPresent: true` or IP CIDR source restrictions.
3. **ClusterRole vs. Role Scope:** Define cluster-scoped permissions using `ClusterRole` and `ClusterRoleBinding` to compare multi-namespace administrative models against single-namespace isolation.
4. **Policy-as-Code Guardrails:** Deploy Open Policy Agent (OPA) Gatekeeper or Kyverno in Kubernetes to enforce security policies blocking container pods running with root privileges (`runAsRoot: false`).

---

## References

- **Course Lectures:** Week 1 (Fundamentals), Week 2 (Security Architecture), Week 5 (Access Control), Week 7 (Identity Management).
- **LocalStack Documentation:** [https://docs.localstack.cloud](https://docs.localstack.cloud)
- **Kubernetes Authorization Reference:** [https://kubernetes.io/docs/reference/access-authn-authz/rbac/](https://kubernetes.io/docs/reference/access-authn-authz/rbac/)
- **Cloud Security Alliance (CSA):** Security Guidance v5 — Domain 01: Identity & Access Management.
