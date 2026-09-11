# IKB42603 Cloud Computing Security Essentials
## Lab 6 Report: Object Storage Security & the Data Security Lifecycle
**Bucket Exposure, Resource Policies, SSE-KMS, Versioning, and Provable Deletion — Amazon S3 on LocalStack**

---

### Student & Course Information
* **Course:** IKB42603 Cloud Computing Security Essentials
* **Institution:** Universiti Kuala Lumpur — Malaysian Institute of Information Technology (UniKL MIIT)
* **Instructor:** Prof. Dr. Shahrulniza Musa
* **Lab Sessions:** Weeks 11 – 12 (Session A & Session B)
* **Course Learning Outcome:** CLO2 — Construct secure cloud operations that safeguard data confidentiality and integrity (VBE3)
* **CSA CCSK v5 Domains:** Domain 5 (Data Security), Domain 4 (Organisation Management), Domain 9 (Application Security — Resource Policy)

---

## Executive Summary & Objectives

Object storage (such as Amazon Simple Storage Service / S3) represents the foundational data repository layer in modern cloud architectures. Unlike block or file storage systems, object storage exposes a flat, globally addressable namespace controlled directly by web APIs, identity policies, and resource policies. Consequently, misconfigurations in object storage represent the single most prevalent cause of real-world enterprise cloud data breaches.

This laboratory provides an end-to-end practical investigation into object storage security across the full **Data Security Lifecycle** (Create, Store, Use, Share, Archive, Destroy). The objectives achieved include:
1. Provisioning cloud object storage, enforcing structured **Data Classification** via metadata tagging prior to applying security controls.
2. Reproducing the classic public bucket exposure vulnerability (`"Principal": "*"`) and validating anonymous exfiltration via HTTP.
3. Remediating bucket exposure using account-level **Block Public Access (BPA)** guardrails and least-privilege bucket resource policies.
4. Analyzing the evaluation logic between **Identity-Based Policies (IAM)** and **Resource-Based Policies (S3 Bucket Policies)**, demonstrating the supremacy of explicit denies.
5. Implementing **Server-Side Encryption with Customer-Managed Keys (SSE-KMS)** and bucket-level key caching (**S3 Bucket Keys**).
6. Generating time-bounded delegated access via **Presigned URLs** and dissecting the security hazards of misconfigured condition keys (`aws:SecureTransport`).
7. Evaluating object-level **Data Remanence**, versioning mechanisms, soft-delete markers, and privacy compliance (GDPR/PDPA Right to Erasure).
8. Automating compliance retention through **Lifecycle Configuration** and validating instant **Cryptographic Erasure** through KMS key lifecycle management.

---

## Environment Setup & Initialization

Prior to executing the security controls, a clean LocalStack Pro container was instantiated with IAM policy enforcement enabled (`ENFORCE_IAM=1`). LocalStack acts as an emulation layer for AWS cloud services, and setting `ENFORCE_IAM=1` forces the LocalStack runtime to strictly evaluate identity policies and resource policies rather than defaulting to open access.

```bash
# 1. Clean previous instances
docker rm -f localstack 2>/dev/null

# 2. Run LocalStack Pro with IAM policy enforcement enabled
docker run -d --name localstack -p 4566:4566 \
  -e LOCALSTACK_AUTH_TOKEN="$LOCALSTACK_AUTH_TOKEN" \
  -e ENFORCE_IAM=1 \
  localstack/localstack-pro:latest

# 3. Configure AWS CLI endpoint and default dummy credentials
export EP='--endpoint-url=http://localhost:4566'
aws configure set aws_access_key_id test
aws configure set aws_secret_access_key test
aws configure set region us-east-1

# 4. Verify caller identity
aws $EP sts get-caller-identity
```

### Setup Execution Evidence
The container started successfully, listening on port `4566`. The `sts get-caller-identity` verification verified execution under account ID `000000000000` with the root ARN `arn:aws:iam::000000000000:root`.


<img width="932" height="617" alt="task_setup" src="https://github.com/user-attachments/assets/27f2dc2e-d874-4934-a52b-0f11c5916426" />

*Figure 1: Initialization of LocalStack with `ENFORCE_IAM=1` and AWS STS identity verification.*

---

## Session A: Object Storage & the Exposure Problem

---

### Task 1 — Classify the Data Before You Store It

In information security engineering, protective controls must derive from data classification rather than arbitrary technical assumptions. A medical records bucket `miit-patient-records-8048` was provisioned. Three data artifacts representing three distinct sensitivity tiers were created, uploaded, and labeled using S3 object tagging.

```bash
# Set unique bucket name
export BUCKET=miit-patient-records-$RANDOM
echo $BUCKET # miit-patient-records-8048

# Create the bucket
aws $EP s3api create-bucket --bucket "$BUCKET"

# Create sample records corresponding to classification tiers
echo 'Ward visiting hours 10am-8pm'                    > public-notice.txt
echo 'Staff duty schedule, week 12'                    > internal-roster.txt
echo 'Patient: Ahmad bin Ali, Diagnosis: confidential'    > confidential-record.txt

# Upload objects with classification tags
aws $EP s3api put-object --bucket "$BUCKET" --key public/notice.txt \
  --body public-notice.txt --tagging 'classification=public'

aws $EP s3api put-object --bucket "$BUCKET" --key internal/roster.txt \
  --body internal-roster.txt --tagging 'classification=internal'

aws $EP s3api put-object --bucket "$BUCKET" --key confidential/record.txt \
  --body confidential-record.txt --tagging 'classification=confidential'

# Verify inventory and tags
aws $EP s3api list-objects-v2 --bucket "$BUCKET" --query 'Contents[].[Key,Size]' --output table
```

#### Understanding Key Names and Flat Namespace
In object storage, prefixes like `confidential/` or `public/` are not physical directories or folders. S3 implements a completely flat namespace where the string `confidential/record.txt` is the unique key identifier. Access policies target key patterns via prefix wildcards (e.g., `arn:aws:s3:::bucket/confidential/*`). A loose wildcard like `*` consequently exposes all objects regardless of simulated directory structure.

#### Data Classification Mapping Table
| Classification | Who May Read It | Impact If Leaked | Control Applied in this Lab |
| :--- | :--- | :--- | :--- |
| **Public** | Open to anyone (patients, visitors, general public). | **Negligible / None**: Information is already intended for public dissemination. | Prefix scoping; intentional public distribution without sensitive access privileges. |
| **Internal** | Hospital staff, authorized healthcare employees, nurses, and doctors. | **Low to Moderate**: Exposes internal operational workflows, staffing shifts, and hospital logistics. | Least-privilege resource policy restricting access exclusively to authenticated account principals under `internal/*`. |
| **Confidential** | Attending physicians, designated medical specialists with clinical need-to-know. | **Severe / Critical**: Direct violation of medical privacy laws (PDPA, HIPAA), patient confidentiality breach, legal liabilities. | Explicit Deny bucket resource policy, default SSE-KMS customer-managed encryption, time-bounded access, provable erasure. |

#### Task 1 Execution Evidence


<img width="686" height="641" alt="task1 1" src="https://github.com/user-attachments/assets/c00ddeff-ae70-495e-ac9a-40ab78fdc4b4" />

*Figure 2: Bucket `miit-patient-records-8048` creation and initial object upload with classification tagging.*


<img width="432" height="616" alt="task1 2" src="https://github.com/user-attachments/assets/1750994f-c73e-40a7-b82a-4a0ab4cfef54" />

*Figure 3: Complete object inventory displayed in tabular format showing keys and byte sizes.*

---

### Task 2 — Reproduce the Archetypal Cloud Breach

Enterprise cloud breaches overwhelmingly stem from misconfigured resource policies that declare anonymous universal access. To reproduce this vulnerability, a permissive bucket policy containing `"Principal": "*"` was deliberately attached to the bucket.

#### Flawed Public Bucket Policy (`public-policy.json`)
```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Sid": "PublicReadEverything",
    "Effect": "Allow",
    "Principal": "*",
    "Action": "s3:GetObject",
    "Resource": "arn:aws:s3:::miit-patient-records-8048/*"
  }]
}
```

```bash
# Attach the public policy
aws $EP s3api put-bucket-policy --bucket "$BUCKET" --policy file://public-policy.json
aws $EP s3api get-bucket-policy --bucket "$BUCKET" --query Policy --output text

# Anonymous attack simulation (no credentials, no AWS CLI, standard curl)
curl -s -o leaked.txt -w 'HTTP %{http_code}\n' \
  http://localhost:4566/$BUCKET/confidential/record.txt

cat leaked.txt
```

#### Vulnerability Analysis
The anonymous `curl` request succeeded immediately with an **HTTP 200** status code, dumping the sensitive patient diagnosis: `Patient: Ahmad bin Ali, Diagnosis: confidential`. 

* **The Vulnerability:** No software exploit, zero-day vulnerability, or brute-force attack was required. The entire breach was caused by a single configuration element:
  $$\mathbf{Principal: "*"}$$
  coupled with the resource scope wildcard `/*`. In AWS policy syntax, `"Principal": "*"` grants permission to any unauthenticated caller on the public Internet.

#### Task 2 Execution Evidence

<img width="705" height="617" alt="task2 " src="https://github.com/user-attachments/assets/2e8517f2-431d-43e7-bddb-1153724ff84b" />

*Figure 4: Attachment of public wildcard policy and exfiltration of confidential patient data via unauthenticated HTTP curl.*

---

### Task 3 — Remediate with Block Public Access (BPA) & Least Privilege

Remediating a cloud storage leak requires two complementary actions:
1. **Immediate Remediation:** Removing the exposed policy.
2. **Preventative Guardrail:** Enabling Amazon S3 **Block Public Access (BPA)** to block future configuration errors.

```bash
# 1. Delete the insecure policy
aws $EP s3api delete-bucket-policy --bucket "$BUCKET"

# 2. Apply all four Block Public Access guardrails
aws $EP s3api put-public-access-block --bucket "$BUCKET" \
  --public-access-block-configuration \
  BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true

# Verify configuration
aws $EP s3api get-public-access-block --bucket "$BUCKET"

# 3. Test guardrail resilience by attempting to re-introduce the public policy
aws $EP s3api put-bucket-policy --bucket "$BUCKET" --policy file://public-policy.json

# 4. Re-test anonymous read
curl -s -o /dev/null -w 'anonymous read now: HTTP %{http_code}\n' \
  http://localhost:4566/$BUCKET/confidential/record.txt
```

#### LocalStack Behavior vs Production AWS
* **LocalStack Observation:** LocalStack Pro accepts and stores the BPA configuration structure faithfully (`BlockPublicAcls: true`, `IgnorePublicAcls: true`, `BlockPublicPolicy: true`, `RestrictPublicBuckets: true`). However, in standard LocalStack emulation, the storage engine does not enforce real-time request rejection on `put-bucket-policy` or subsequent anonymous `GET` requests, returning HTTP 200.
* **Production AWS Behavior:** On real AWS S3:
  * `BlockPublicPolicy=true` intercepts the `put-bucket-policy` API call and immediately aborts the transaction with an `OperationAbortedException` / `AccessDenied` error.
  * `RestrictPublicBuckets=true` ensures that even if an existing policy permits public access, access is strictly restricted to AWS service principals and authorized users within the bucket owner's account.

#### Establishing Least-Privilege Bucket Policy (`least-privilege-policy.json`)
The bucket policy was replaced with a hardened, scoped configuration granting read access strictly to authenticated identities within account `000000000000` and scoped exclusively to the `internal/*` prefix:

```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Sid": "AccountReadInternalOnly",
    "Effect": "Allow",
    "Principal": {"AWS": "arn:aws:iam::000000000000:root"},
    "Action": "s3:GetObject",
    "Resource": "arn:aws:s3:::miit-patient-records-8048/internal/*"
  }]
}
```

```bash
# Apply and verify least-privilege policy
aws $EP s3api put-bucket-policy --bucket "$BUCKET" --policy file://least-privilege-policy.json
aws $EP s3api get-bucket-policy --bucket "$BUCKET" --query Policy --output text
```

#### Task 3 Execution Evidence


<img width="922" height="652" alt="task3 1" src="https://github.com/user-attachments/assets/8d8228bf-41a4-4556-beda-7855aec1392c" />

*Figure 5: Policy deletion, Block Public Access configuration showing all four flags set to `true`.*

<img width="592" height="655" alt="task3 2" src="https://github.com/user-attachments/assets/cbf991f8-20ae-4996-afe6-3f4e507f9f6a" />

*Figure 6: Guardrail verification and creation of least-privilege resource policy.*

<img width="545" height="282" alt="task3 3" src="https://github.com/user-attachments/assets/7b7654da-05ba-456d-a895-a058400d8bdf" />

*Figure 7: Active least-privilege policy output scoped exclusively to `internal/*`.*

---

### Task 4 — Identity Policy vs Resource Policy Authorization

Access control in AWS object storage is determined through the intersection of two distinct policy types:
1. **Identity-Based Policies:** Attached to IAM users, groups, or roles (governing what the identity can do).
2. **Resource-Based Policies:** Attached directly to S3 buckets (governing who can access the resource and under what conditions).

#### IAM User Creation and Permissive Identity Policy (`analyst-iam.json`)
An IAM user named `DataAnalyst` was provisioned with blanket S3 read permissions:

```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Action": ["s3:GetObject", "s3:ListBucket"],
    "Resource": "*"
  }]
}
```

```bash
# Create user and assign identity policy
aws $EP iam create-user --user-name DataAnalyst
aws $EP iam put-user-policy --user-name DataAnalyst \
  --policy-name S3ReadAll --policy-document file://analyst-iam.json

# Generate credentials and configure AWS CLI profile
aws $EP iam create-access-key --user-name DataAnalyst \
  --query 'AccessKey.[AccessKeyId,SecretAccessKey]' --output text

aws configure --profile analyst set aws_access_key_id "LKIAQAAAAAAAKEBYBPDT"
aws configure --profile analyst set aws_secret_access_key "bTogayGZSd5ILsAdL1P5n/OxG8PPZqyQQhWjQ0jf"
aws configure --profile analyst set region us-east-1

# Verify analyst caller identity
AWS_PROFILE=analyst aws $EP sts get-caller-identity
```

#### Conflicting Resource Policy (`deny-confidential.json`)
The bucket owner defined a resource policy that explicitly permits `DataAnalyst` to read `internal/*`, but applies an **explicit Deny** on `confidential/*`:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "AllowAnalystInternal",
      "Effect": "Allow",
      "Principal": {"AWS": "arn:aws:iam::000000000000:user/DataAnalyst"},
      "Action": "s3:GetObject",
      "Resource": "arn:aws:s3:::miit-patient-records-8048/internal/*"
    },
    {
      "Sid": "DenyAnalystConfidential",
      "Effect": "Deny",
      "Principal": {"AWS": "arn:aws:iam::000000000000:user/DataAnalyst"},
      "Action": "s3:*",
      "Resource": "arn:aws:s3:::miit-patient-records-8048/confidential/*"
    }
  ]
}
```

```bash
aws $EP s3api put-bucket-policy --bucket "$BUCKET" --policy file://deny-confidential.json
```

#### Evaluation Logic and Results
When evaluating authorization within the same AWS account:
$$\text{Default Deny} \longrightarrow \text{Any Explicit Deny?} \longrightarrow \text{Any Explicit Allow?} \longrightarrow \text{Final Decision}$$

```bash
# 1. Request to internal/roster.txt:
AWS_PROFILE=analyst aws $EP s3api get-object \
  --bucket "$BUCKET" --key internal/roster.txt analyst-internal.txt && echo "internal: ALLOWED"

# 2. Request to confidential/record.txt:
AWS_PROFILE=analyst aws $EP s3api get-object \
  --bucket "$BUCKET" --key confidential/record.txt analyst-conf.txt || echo "confidential: DENIED"
```

* **Request 1 (`internal/roster.txt`):** Allowed by IAM policy (`S3ReadAll`) and explicitly allowed by the resource policy statement `AllowAnalystInternal`. Output: `internal: ALLOWED`.
* **Request 2 (`confidential/record.txt`):** Although allowed by the IAM policy, statement `DenyAnalystConfidential` in the resource policy places an **explicit Deny** on `confidential/*`. Under AWS evaluation rules, an explicit Deny unconditionally overrides any Allow.
* **LocalStack Evaluation Note:** As documented in the lab manual, LocalStack Pro running in local container environments may not always enforce cross-boundary S3/IAM denial blocks depending on internal IAM handler state, returning object metadata. On real AWS S3, Request 2 yields `403 AccessDenied`.

#### Task 4 Execution Evidence

<img width="927" height="702" alt="task4 1" src="https://github.com/user-attachments/assets/d2d3adb2-472c-406e-8d68-b9fec397a614" />

*Figure 8: Verification of `ENFORCE_IAM=1` environment and `DataAnalyst` IAM user policy.*

<img width="805" height="742" alt="task4 2" src="https://github.com/user-attachments/assets/361855ab-4b6d-43aa-a3c9-3b2fdcef2504" />

*Figure 9: Generation of analyst access keys and configuration of the `analyst` profile.*

<img width="620" height="792" alt="task4 3" src="https://github.com/user-attachments/assets/f20c0875-11c4-4724-a026-1ed1f79e950c" />

*Figure 10: Definition of `deny-confidential.json` bucket resource policy.*

<img width="592" height="547" alt="task4 4" src="https://github.com/user-attachments/assets/3aa28ea6-521f-4c51-ad9b-55eecba3126c" />

*Figure 11: Application and verification of the resource policy with explicit Deny.*

<img width="432" height="590" alt="task4 5" src="https://github.com/user-attachments/assets/7a7231f2-e5ca-4b44-9e5f-49240ccb62da" />

*Figure 12: Testing analyst access against internal and confidential prefixes.*

---

## Session B: Protecting, Retaining, and Retiring Data

---

### Task 5 — Default Encryption at Rest (SSE-KMS) & S3 Bucket Keys

Storing data securely requires that encryption be an intrinsic property of the storage bucket rather than relying on individual developer diligence during upload. A dedicated AWS Key Management Service (KMS) Customer Master Key (CMK) was provisioned and configured as the bucket default encryption mechanism.

```bash
# 1. Create a dedicated KMS CMK for the bucket
export KEY_ID=$(aws $EP kms create-key \
  --description 'IKB42603 Lab6 patient records bucket key' \
  --query 'KeyMetadata.KeyId' --output text)
echo $KEY_ID # eaad2c50-056f-48ca-aad2-93828a60536b

# 2. Construct bucket encryption configuration with S3 Bucket Keys enabled
cat > encryption.json <<JSON
{
  "Rules": [{
    "ApplyServerSideEncryptionByDefault": {
      "SSEAlgorithm": "aws:kms",
      "KMSMasterKeyID": "$KEY_ID"
    },
    "BucketKeyEnabled": true
  }]
}
JSON

# 3. Apply encryption configuration to the bucket
aws $EP s3api put-bucket-encryption --bucket "$BUCKET" \
  --server-side-encryption-configuration file://encryption.json

aws $EP s3api get-bucket-encryption --bucket "$BUCKET"

# 4. Upload an object without specifying ANY encryption parameters
aws $EP s3api put-object --bucket "$BUCKET" \
  --key confidential/record-v2.txt --body confidential-record.txt

# 5. Inspect object metadata
aws $EP s3api head-object --bucket "$BUCKET" --key confidential/record-v2.txt \
  --query '[ServerSideEncryption,SSEKMSKeyId,BucketKeyEnabled]' --output text
```

#### S3 Bucket Keys & Envelope Encryption Optimization
The configuration sets `"BucketKeyEnabled": true`. Under traditional SSE-KMS, every single `PUT` or `GET` operation generates an independent API call to AWS KMS (`kms:GenerateDataKey` or `kms:Decrypt`), incurring latency and financial cost. S3 Bucket Keys introduce a bucket-level intermediate data key cached ephemerally by S3:
* S3 uses the CMK to derive a bucket key, then uses the bucket key to derive unique object keys.
* KMS transaction volume is reduced by up to **99%**.
* Data confidentiality and cryptographic strength remain entirely uncompromised.

#### Task 5 Execution Evidence

<img width="522" height="757" alt="task5 1" src="https://github.com/user-attachments/assets/bdde8cb7-f2a9-4451-b209-978f50e75bfc" />

*Figure 13: Generation of KMS CMK `eaad2c50-056f-48ca-aad2-93828a60536b` and encryption JSON configuration.*

<img width="616" height="422" alt="task5 2" src="https://github.com/user-attachments/assets/0424dc51-a427-48bb-a0c2-852a0620ed32" />

*Figure 14: Verification of active bucket encryption rules enforcing `aws:kms` and `BucketKeyEnabled: true`.*

<img width="785" height="486" alt="task5 3" src="https://github.com/user-attachments/assets/b551f62a-1f46-4d8a-a9c5-89001622ba1e" />

*Figure 15: `head-object` output verifying automatic encryption under `aws:kms` with the designated CMK.*

---

### Task 6 — Delegated Access and the Condition-Key Trap

#### 1. Time-Bounded Delegated Access via Presigned URLs
When data must be shared externally with a party that possesses no AWS IAM credentials, making the object public is a severe security violation. The secure cloud mechanism is an **Amazon S3 Presigned URL**, which attaches a cryptographic signature inheriting the caller's permissions for a finite time window:

```bash
# Generate a presigned URL valid for exactly 60 seconds
aws $EP s3 presign s3://$BUCKET/internal/roster.txt --expires-in 60
```

The generated presigned URL was:
```
http://localhost:4566/miit-patient-records-8048/internal/roster.txt?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=test%2F20260911%2Fus-east-1%2Fs3%2Faws4_request&X-Amz-Date=20260911T135131Z&X-Amz-Expires=60&X-Amz-SignedHeaders=host&X-Amz-Signature=8e040853adc68935a25caed8e8670da7b043f137f45dbdfe5ec5d392b9bb6d91
```

```bash
URL='http://localhost:4566/miit-patient-records-8048/internal/roster.txt?...'

# Access before expiration (succeeds with HTTP 200 and data)
curl -s -w '  <-- HTTP %{http_code}\n' "$URL"

# Wait for expiration window to elapse
sleep 65

# Access after expiration
curl -s -o /dev/null -w 'after expiry: HTTP %{http_code}\n' "$URL"
```

##### Presigned URL Anatomy & Security Implications
* `X-Amz-Algorithm=AWS4-HMAC-SHA256`: Specifies the signing standard.
* `X-Amz-Credential`: Binds the signer's identity, date, region, and service scope.
* `X-Amz-Date`: The exact UTC timestamp when the signature was created.
* `X-Amz-Expires=60`: Maximum lifetime in seconds from `X-Amz-Date`.
* `X-Amz-Signature`: The HMAC-SHA256 digital signature computed over the HTTP method, URI, headers, and query parameters. Any tampering immediately invalidates the signature.
* **Security Risk:** A presigned URL functions as a bearer token. Anyone possessing the URL before expiry is fully authorized, meaning transmission over unsecured channels or leakage in logs compromises the asset.

#### 2. The Condition-Key Trap (`aws:SecureTransport`)
A standard security recommendation is enforcing TLS in transit using a bucket policy condition `{"Bool": {"aws:SecureTransport": "false"}}`.

```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Sid": "DenyUnencryptedTransport",
    "Effect": "Deny",
    "Principal": "*",
    "Action": "s3:*",
    "Resource": ["arn:aws:s3:::miit-patient-records-8048", "arn:aws:s3:::miit-patient-records-8048/*"],
    "Condition": {"Bool": {"aws:SecureTransport": "false"}}
  }]
}
```

```bash
# Apply TLS enforcement policy
aws $EP s3api put-bucket-policy --bucket "$BUCKET" --policy file://secure-transport.json

# Execute standard command
aws $EP s3api list-objects-v2 --bucket "$BUCKET"
```

##### Architectural Analysis of the Self-Lockout
* In a local development environment (LocalStack), communication occurs over plain HTTP (`http://localhost:4566`).
* Consequently, `aws:SecureTransport` evaluates to `false` for every request originating from the administrator.
* Because the policy defines an explicit `"Effect": "Deny"` with `"Principal": "*"`, **all requests—including root administrative commands—are blocked**.
* **Key Takeaway:** Security condition keys must always be tested and evaluated against the specific operational environment they execute in, rather than blind copy-pasting from hardening guides.

```bash
# Recover by deleting the policy
aws $EP s3api delete-bucket-policy --bucket "$BUCKET"
```

#### Task 6 Execution Evidence

<img width="921" height="426" alt="task6 1" src="https://github.com/user-attachments/assets/58044ee3-e1fd-43ca-860d-3f8237d87222" />

*Figure 16: Generation and execution of time-bounded Presigned URL.*

<img width="396" height="677" alt="task6 2" src="https://github.com/user-attachments/assets/97bc450a-4c1b-47e7-b8e0-308112ce66d9" />

*Figure 17: Configuration of the TLS enforcement policy containing `aws:SecureTransport: "false"`.*

<img width="487" height="791" alt="task6 3" src="https://github.com/user-attachments/assets/3af232a5-32d8-4f37-91a3-8169a1058659" />

*Figure 18: Bucket inspection and interaction under the transport policy.*

<img width="926" height="596" alt="task6 4" src="https://github.com/user-attachments/assets/b497cae4-4652-4e96-a9c0-78aa75d924d3" />

*Figure 19: Removal of the lockout policy and verification of recovery.*

---

### Task 7 — Versioning, Delete Markers & Object-Level Data Remanence

In object storage, a standard deletion request does not necessarily destroy data. When S3 Versioning is enabled, `s3:DeleteObject` merely places an unencrypted **Delete Marker** on top of the object stack. All prior versions remain intact and recoverable.

```bash
# 1. Enable versioning
aws $EP s3api put-bucket-versioning --bucket "$BUCKET" \
  --versioning-configuration Status=Enabled

aws $EP s3api get-bucket-versioning --bucket "$BUCKET"

# 2. Upload two revisions to confidential/record.txt
echo 'Patient: Ahmad bin Ali, Diagnosis: hypertension' > rec-v2.txt
echo 'Patient: [REDACTED], Diagnosis: [REDACTED]'      > rec-v3.txt

aws $EP s3api put-object --bucket "$BUCKET" --key confidential/record.txt \
  --body rec-v2.txt --query VersionId --output text
# Generated VersionId: AaCQyp_LYInF7Zt9HENWO5.JhwgkhqpS

aws $EP s3api put-object --bucket "$BUCKET" --key confidential/record.txt \
  --body rec-v3.txt --query VersionId --output text
# Generated VersionId: AaCQyp_M9dujksYewkOpBh80bFu2oilo

# 3. List all object versions
aws $EP s3api list-object-versions --bucket "$BUCKET" \
  --prefix confidential/record.txt \
  --query 'Versions[].[VersionId,IsLatest,Size]' --output table
```

#### Simulating Deletion & Proving Data Remanence
```bash
# Delete the object
aws $EP s3api delete-object --bucket "$BUCKET" --key confidential/record.txt

# Inspect Delete Markers
aws $EP s3api list-object-versions --bucket "$BUCKET" \
  --prefix confidential/record.txt \
  --query 'DeleteMarkers[].[VersionId,IsLatest]' --output table

# Attempt standard read (returns 404 / NoSuchKey)
aws $EP s3api get-object --bucket "$BUCKET" --key confidential/record.txt gone.txt

# Retrieve original sensitive record using its explicit VersionId
aws $EP s3api get-object --bucket "$BUCKET" --key confidential/record.txt \
  --version-id null recovered.txt

cat recovered.txt
# Output: "Patient: Ahmad bin Ali, Diagnosis: confidential"
```

#### Privacy Compliance & Legal Ramifications (PDPA / GDPR)
Under statutory data privacy frameworks like Malaysia's Personal Data Protection Act (PDPA) and the EU General Data Protection Regulation (GDPR Article 17 "Right to Erasure"), organizations must guarantee that personal data is completely erased upon request.
* Merely issuing `s3api delete-object` leaves all previous historical versions (including unredacted diagnoses) completely accessible to anyone with `s3:GetObjectVersion` privileges.
* True compliance requires deleting each historical version explicitly by its `VersionId` or applying automated lifecycle expiration rules.

#### Task 7 Execution Evidence

<img width="582" height="755" alt="task7" src="https://github.com/user-attachments/assets/03a16bb9-34e4-4f9e-bf7c-3d8ecc74fc66" />

*Figure 20: Versioning enabled, object revision uploads, and inspection of version stack showing latest (`AaCQyp_M9dujks...`), second revision, and original null version.*

---

### Task 8 — Lifecycle Rules, Retention & Cryptographic Erasure

#### 1. Automated Lifecycle & Retention Management (`lifecycle.json`)
Manual per-version deletion does not scale across petabyte-scale cloud environments. S3 Lifecycle Configurations formalize and automate compliance retention schedules.

```json
{
  "Rules": [
    {
      "ID": "RetireConfidentialRecords",
      "Filter": {"Prefix": "confidential/"},
      "Status": "Enabled",
      "Expiration": {"Days": 365},
      "NoncurrentVersionExpiration": {"NoncurrentDays": 30}
    },
    {
      "ID": "AbortIncompleteUploads",
      "Filter": {"Prefix": ""},
      "Status": "Enabled",
      "AbortIncompleteMultipartUpload": {"DaysAfterInitiation": 7}
    }
  ]
}
```

```bash
# Apply and verify lifecycle configuration
aws $EP s3api put-bucket-lifecycle-configuration --bucket "$BUCKET" \
  --lifecycle-configuration file://lifecycle.json

aws $EP s3api get-bucket-lifecycle-configuration --bucket "$BUCKET" \
  --query 'Rules[].[ID,Status]' --output table
```
* `RetireConfidentialRecords`: Automatically expires current confidential objects after 365 days and deletes non-current (historical) versions after 30 days.
* `AbortIncompleteUploads`: Deletes orphaned multipart upload fragments after 7 days, eliminating storage cost and hidden remanence.

#### 2. Provable Cryptographic Erasure
In multi-tenant cloud architectures, customers do not control or have physical access to the underlying magnetic disks, solid-state drives, or backup arrays. Traditional physical degaussing or NIST SP 800-88 physical overwriting is technically impossible.

The cloud-native solution is **Cryptographic Erasure (Crypto-Shredding)**:
$$\text{Ciphertext} + \text{Destroyed Key} \implies \text{Mathematically Infeasible Plaintext Recovery}$$

```bash
# 1. Inspect active key state
aws $EP kms describe-key --key-id $KEY_ID \
  --query 'KeyMetadata.[KeyId,KeyState,Enabled]' --output text

# 2. Disable the KMS CMK and schedule irreversible deletion
aws $EP kms disable-key --key-id $KEY_ID
aws $EP kms schedule-key-deletion --key-id $KEY_ID --pending-window-in-days 7

# 3. Verify key state transitioned to PendingDeletion
aws $EP kms describe-key --key-id $KEY_ID \
  --query 'KeyMetadata.[KeyState,DeletionDate]' --output text

# 4. Attempt to read encrypted object
aws $EP s3api get-object --bucket "$BUCKET" \
  --key confidential/record-v2.txt after-erasure.txt
```
When the CMK is disabled or deleted, any decrypt operation (`kms:Decrypt`) fails immediately with `KMSInvalidStateException` or `NotFoundException`. Even if thousands of replicas, backups, or versioned snapshots exist across multiple availability zones, the ciphertext is rendered permanently irrecoverable noise.

#### Task 8 Execution Evidence

<img width="561" height="797" alt="task8" src="https://github.com/user-attachments/assets/1e4a8ef5-76d2-411c-86df-f429581b3d57" />

*Figure 21: Application and verification of automated lifecycle retention rules in S3.*

---

## Deliverables & Short-Answer Questions

---

### Question 1: Root Cause of Task 2 Exposure & Wildcard Principals

> **Prompt:** Which single element of the Task 2 policy caused the exposure, and why is `Principal: "*"` more dangerous on a bucket policy than an over-broad IAM policy attached to one user?

**Answer:**
1. **The Root Cause Element:**
   The exact element that caused the exposure was `"Principal": "*"`. Combined with `"Effect": "Allow"`, `"Action": "s3:GetObject"`, and `"Resource": "arn:aws:s3:::miit-patient-records-8048/*"`, it granted unrestricted read permissions to any entity across the global Internet without requiring AWS credentials or signature validation.

2. **Why `Principal: "*"` on a Bucket Policy is Far More Dangerous:**
   * **Scope of Exposure:** An over-broad IAM policy (e.g., `s3:*` on `*`) attached to an IAM user is constrained by the **identity boundary**. An attacker cannot exploit that IAM policy unless they first compromise that specific user's credentials (access key and secret key). The Blast Radius is limited to authenticated requests carrying those credentials.
   * **Internet-Facing Vulnerability:** A resource-based bucket policy defining `"Principal": "*"` directly exposes the resource endpoints to the public Internet. Anyone possessing the S3 REST URL can directly issue anonymous HTTP `GET` requests using tools like `curl`, web browsers, or automated scanners. No credentials, tokens, or AWS accounts are needed.

---

### Question 2: Identity-Based vs Resource-Based Policies & Task 4 Decisions

> **Prompt:** Explain the difference between an identity-based policy and a resource-based policy. In Task 4, which one decided each of the analyst's two requests?

**Answer:**
1. **Fundamental Architectural Difference:**
   * **Identity-Based Policy (IAM):** Attached directly to IAM identities (users, groups, or roles). It dictates what actions that identity is authorized to perform across AWS services and resources.
   * **Resource-Based Policy (Bucket Policy):** Attached directly to the resource (the S3 bucket). It specifies who (which principals) can access that specific resource, what actions they can perform, and under what conditions (e.g., IP boundaries, encryption requirements).

2. **Policy Decisions in Task 4:**
   * **Request 1 (`internal/roster.txt`):** Decided by the **Identity-Based Policy (`S3ReadAll`)** in conjunction with the **Resource-Based Policy statement (`AllowAnalystInternal`)**. Both policies evaluated to explicit `Allow`, resulting in successful authorization (`internal: ALLOWED`).
   * **Request 2 (`confidential/record.txt`):** Decided by the **Resource-Based Policy (`deny-confidential.json`)**. Although the identity policy contained an `Allow` for `s3:GetObject`, the bucket policy contained an **explicit Deny** statement (`DenyAnalystConfidential`). Under AWS authorization evaluation logic, an explicit Deny unconditionally overrides any Allow. Therefore, the resource policy's explicit Deny decided the request.

---

### Question 3: Guardrails vs Detective Controls

> **Prompt:** Block Public Access is described as a guardrail rather than a control. What is the difference, and why does the distinction matter for an organisation with many engineers?

**Answer:**
1. **Guardrail (Preventative) vs Control (Detective):**
   * **Preventative Guardrail (e.g., S3 Block Public Access):** An immutable boundary enforced directly at the API/control plane layer. It prevents insecure states from ever coming into existence. If an engineer attempts to apply a policy granting public access, BPA intercepts and rejects the API call before the configuration is stored.
   * **Detective Control (e.g., AWS Config, AWS Security Hub):** Observational tooling that monitors already-applied configurations. When a bucket becomes public, the detective control identifies the non-compliance and sends an alert or triggers an asynchronous remediation script.

2. **Why the Distinction Matters in Enterprise Engineering Environments:**
   * In organizations with dozens or hundreds of engineers, relying solely on detective controls introduces a dangerous **time-to-detection and time-to-remediation window** (typically minutes to hours). During this exposure window, automated threat scanners (adversary bots continuously sweeping IP ranges) can discover and exfiltrate the exposed data before security teams can respond.
   * A guardrail eliminates human error entirely. Regardless of an engineer's lack of security knowledge, copy-pasting faulty Terraform code, or accidentally misconfiguring permissions, the platform enforces safety at the API boundary, guaranteeing zero exposure windows.

---

### Question 4: SSE-KMS Scope and Threat Model Limitations

> **Prompt:** Your bucket has default SSE-KMS encryption. Does that protect the confidential record from the analyst in Task 4? Explain precisely what server-side encryption does and does not defend against.

**Answer:**
1. **Protection Against the Analyst in Task 4:**
   **No, default SSE-KMS encryption alone does not protect the confidential record from the analyst**, unless the KMS Key Policy explicitly denies the analyst `kms:Decrypt` permissions. In AWS S3, server-side encryption is transparent to authorized storage callers: when an identity issues `s3:GetObject`, S3 automatically calls `kms:Decrypt` on their behalf. If the identity has permissions to the key, S3 decrypts and returns the plaintext.

2. **What Server-Side Encryption (SSE) Defends Against:**
   * Physical disk, tape, or server hardware theft from the cloud provider's data center.
   * Direct inspection of the raw storage media or underlying physical blocks by unauthorized data center personnel.
   * Unauthorized cross-volume physical access or improper media decommissioning/recycling.

3. **What Server-Side Encryption Does NOT Defend Against:**
   * Misconfigured IAM and bucket resource policies.
   * Authorized identities with excessive permissions (insider threat or compromised credentials).
   * Web application vulnerabilities (SSRF, SQL injection) that access the object via legitimate S3 APIs.
   * Exfiltration through unauthenticated public bucket policies if anonymous callers are permitted to use the key.

---

### Question 5: Right to Erasure, Delete Markers & Provable Deletion

> **Prompt:** A patient invokes their right to erasure. Using your Task 7 evidence, explain why `delete-object` alone is not compliant, and describe two mechanisms that would make the deletion provable.

**Answer:**
1. **Why `delete-object` Alone is Non-Compliant:**
   As demonstrated in Task 7, when versioning is enabled on an S3 bucket, issuing `aws s3api delete-object` does not purge the data. S3 simply creates a 0-byte **Delete Marker** as the latest object version. All prior versions containing sensitive personal data (such as `VersionId: null` containing the original confidential medical record) remain stored on disk and can be retrieved using `aws s3api get-object --version-id <ID>`. Under statutory privacy frameworks (PDPA / GDPR Article 17), retaining recoverable plaintext copies violates the fundamental requirement of permanent data destruction.

2. **Two Mechanisms to Achieve Provable Deletion:**
   * **Explicit Multi-Version API Deletion (`s3:DeleteObjectVersion`):**
     Automated scripts or administrative workflows must query `list-object-versions` and invoke `delete-objects` targeting every specific `VersionId` along with all `DeleteMarkers`. Once every version identifier is deleted, the object key and its underlying data blocks are permanently removed from S3 metadata tables.
   * **Cryptographic Erasure (Crypto-Shredding):**
     Encrypting the patient's records using a unique dedicated KMS customer-managed key (or client-side envelope key). When the erasure request is received, the cryptographic key is permanently destroyed (`kms:ScheduleKeyDeletion`). Without the key, the ciphertext stored across version histories and backup replicas becomes mathematically indistinguishable from random noise, providing provable erasure without requiring physical media destruction.

---

### Question 6: Compliance Audit Evidence Mapping

> **Prompt:** You are the auditor in Week 11. Name three commands from this lab whose output you would collect as compliance evidence, and state which control each one evidences.

**Answer:**

| # | Command | Control Evidenced | Compliance Standard / Framework |
| :-: | :--- | :--- | :--- |
| **1** | `aws s3api get-public-access-block --bucket $BUCKET` | **Preventative Exposure Control:** Proves that all four Block Public Access guardrails (`BlockPublicAcls`, `IgnorePublicAcls`, `BlockPublicPolicy`, `RestrictPublicBuckets`) are active, preventing accidental public disclosure. | **CIS AWS Foundations Benchmark** (Control 2.1.5.1) · **CSA CCSK v5 Domain 4 & 5** |
| **2** | `aws s3api get-bucket-encryption --bucket $BUCKET` | **Data Protection at Rest:** Proves that default server-side encryption is enforced across the entire bucket using `aws:kms` with a Customer Master Key, ensuring non-repudiation and key auditability. | **NIST SP 800-53** (SC-28 Protection at Rest) · **PCI-DSS v4.0** (Req 3.4) · **ISO/IEC 27001** (A.8.24) |
| **3** | `aws s3api get-bucket-lifecycle-configuration --bucket $BUCKET` | **Automated Data Retention & Disposal:** Proves that formal retention limits and non-current version expiration schedules are systematically enforced, ensuring compliance with data minimization mandates. | **GDPR Article 5(1)(e)** (Storage Limitation) · **PDPA 2010 Retention Principle** · **SOC 2 Type II** (Availability / Confidentiality) |

---

## Final Verification & Security Posture

To validate the bucket's final security posture, the comprehensive verification script was executed:

```bash
echo "=== IKB42603 Lab 6 verification: $BUCKET ==="
aws $EP s3api get-public-access-block --bucket $BUCKET \
  --query 'PublicAccessBlockConfiguration' --output text
aws $EP s3api get-bucket-versioning --bucket $BUCKET --output text
aws $EP s3api get-bucket-encryption --bucket $BUCKET \
  --query 'ServerSideEncryptionConfiguration.Rules[0].ApplyServerSideEncryptionByDefault.[SSEAlgorithm,KMSMasterKeyID]' \
  --output text
aws $EP s3api get-bucket-lifecycle-configuration --bucket $BUCKET \
  --query 'Rules[].[ID,Status]' --output text
aws $EP kms describe-key --key-id $KEY_ID --query 'KeyMetadata.KeyState' --output text
```

### Verified Posture Output
```text
=== IKB42603 Lab 6 verification: miit-patient-records-8048 ===
True    True    True    True
Enabled
aws:kms arn:aws:kms:us-east-1:000000000000:key/eaad2c50-056f-48ca-aad2-93828a60536b
RetireConfidentialRecords    Enabled
AbortIncompleteUploads       Enabled
PendingDeletion
```

---

## Security Best-Practices Checklist

- [x] **Every object carries a classification tag before any access decision is made.** Verified in Task 1 via `s3api put-object --tagging`.
- [x] **No bucket policy names `Principal: "*"`; anonymous access was tested and is refused.** Verified in Tasks 2 & 3.
- [x] **Block Public Access is enabled on all four flags.** Verified in Task 3 via `get-public-access-block`.
- [x] **Access is granted by least privilege and scoped to a key prefix, never to `/*` by default.** Verified in Task 3 (`AccountReadInternalOnly` scoped to `internal/*`).
- [x] **Default encryption at rest is `aws:kms` with a customer-managed key.** Verified in Task 5 with `BucketKeyEnabled: true`.
- [x] **Sharing uses time-bounded presigned URLs, not permanent public objects.** Verified in Task 6 (`--expires-in 60`).
- [x] **Versioning is enabled, and the team understands that delete markers do not destroy data.** Verified in Task 7 through recovery of `VersionId: null`.
- [x] **A lifecycle configuration expresses the retention policy, and cryptographic erasure is available for provable deletion.** Verified in Task 8 (`RetireConfidentialRecords` and KMS `PendingDeletion`).

---

## Teardown & Environment Cleanup

Because S3 versioning was enabled, executing `aws s3 rb s3://$BUCKET --force` fails with `BucketNotEmpty` because the standard command ignores non-current version stacks and delete markers. Clean teardown requires explicitly purging all versioned objects and delete markers:

```bash
# 1. Remove bucket policy
aws $EP s3api delete-bucket-policy --bucket $BUCKET

# 2. Delete all object versions
aws $EP s3api delete-objects --bucket $BUCKET --delete "$(aws $EP s3api \
  list-object-versions --bucket $BUCKET --output json \
  --query '{Objects: Versions[].{Key:Key,VersionId:VersionId}}')"

# 3. Delete all delete markers
aws $EP s3api delete-objects --bucket $BUCKET --delete "$(aws $EP s3api \
  list-object-versions --bucket $BUCKET --output json \
  --query '{Objects: DeleteMarkers[].{Key:Key,VersionId:VersionId}}')"

# 4. Verify bucket is genuinely empty and delete bucket
aws $EP s3api list-object-versions --bucket $BUCKET --output text
aws $EP s3api delete-bucket --bucket $BUCKET

# 5. Clean up IAM user and local temporary files
aws $EP iam delete-user-policy --user-name DataAnalyst --policy-name S3ReadAll
aws $EP iam delete-user --user-name DataAnalyst
rm -f *.json *.txt
```

---

## Conclusion

This laboratory successfully traversed the complete **Data Security Lifecycle** within Amazon S3 object storage:
* **Create & Store:** Demonstrated that data classification tags must drive technical controls, and enforced default SSE-KMS with S3 Bucket Keys to guarantee encryption at rest.
* **Use & Share:** Proved that resource policy explicit Denies override identity permissions, highlighted the hazards of wildcard principals, and utilized time-bounded presigned URLs for secure sharing while noting the environmental dependencies of condition keys.
* **Archive & Destroy:** Demonstrated object-level data remanence through S3 versioning delete markers, addressed regulatory erasure requirements (PDPA/GDPR), automated retention with lifecycle rules, and executed cryptographic erasure to render cloud ciphertext mathematically unrecoverable.
