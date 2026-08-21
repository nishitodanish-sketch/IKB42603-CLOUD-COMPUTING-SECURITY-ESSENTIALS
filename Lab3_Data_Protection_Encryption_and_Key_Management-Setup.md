# Lab Report: Data Protection — Encryption & Key Management

**Course**: IKB42603 Cloud Computing Security Essentials  
**Lab Assignment**: Lab 3 (Weeks 5–6) — Data Protection: Encryption & Key Management  
**Focus Area**: At-Rest & In-Transit Encryption, Envelope Encryption, Cryptographic Erasure, and Log Integrity  
**Instructor**: Prof. Dr. Shahrulniza Musa (UniKL MIIT)  
**Environment**: Kali Linux, OpenSSL 3.x, Docker Engine, AWS CLI v2, LocalStack KMS  

---

## Executive Summary

Data protection is the foundational security pillar of cloud infrastructure. In multi-tenant cloud environments, sensitive customer data must be safeguarded across its entire lifecycle: **at rest** (in storage volumes and databases), **in transit** (across internal and public networks), and **in use** (during execution). Cryptographic controls provide confidentiality, integrity, and authenticity guarantees, provided that underlying encryption keys are generated, distributed, and managed securely.

This lab provides an end-to-end practical investigation into modern cryptographic primitives and cloud key management systems across two structured sessions:

1. **Session A (Week 5) — Cryptographic Fundamentals**: Hands-on evaluation of symmetric cipher suites (AES-256-CBC), asymmetric public/private key cryptography (RSA-2048), digital signatures for origin authentication, and Transport Layer Security (TLS) for protecting data in transit.
2. **Session B (Week 6) — KMS, Envelope Encryption & Cryptographic Erasure**: Architectural implementation of AWS Key Management Service (KMS) via LocalStack, executing **envelope encryption** for high-performance payload protection, enforcing **per-tenant key isolation**, executing **cryptographic erasure** for provable cloud data destruction, and constructing **tamper-evident hash chains** for immutable audit trails.

---

## Technical Prerequisites & Setup

The execution environment requires Docker Engine and OpenSSL, along with AWS CLI v2 configured to interact with LocalStack's emulated KMS endpoint (`http://localhost:4566`).

### Environment Endpoint Configuration

```bash
# Define LocalStack KMS API Endpoint Variable
EP='--endpoint-url=http://localhost:4566'
```

---

## Session A (Week 5) — Encryption Fundamentals

Session A builds the core mathematical and operational concepts of cryptography by hand using `openssl`.

---

### Task 1 — Symmetric Encryption (Data at Rest)

#### Objective
Create a sample sensitive medical record, encrypt it using the AES-256-CBC cipher with PBKDF2 key derivation, demonstrate that the ciphertext is unreadable, and verify successful restoration via decryption.

#### Commands Executed

```bash
# Create a sample sensitive record
echo 'Patient: Ahmad, Diagnosis: confidential' > record.txt

# Encrypt with AES-256-CBC (salted with PBKDF2 password derivation)
openssl enc -aes-256-cbc -pbkdf2 -salt -in record.txt -out record.enc

# Prove the ciphertext is unreadable
cat record.enc

# Decrypt back to plaintext and verify byte-for-byte identity
openssl enc -d -aes-256-cbc -pbkdf2 -in record.enc -out record.dec.txt
diff record.txt record.dec.txt && echo 'MATCH: decryption successful'
```

#### Evidence & Output

![Task 1: Symmetric Encryption (AES-256) and Decryption Match](task1.png)

*Figure 1.1: Creation of `record.txt`, AES-256 encryption producing binary ciphertext `record.enc`, and successful decryption matching original content (`MATCH: decryption successful`).*

> [!NOTE]
> **Technical Observation**: Symmetric encryption uses a single shared secret key for both encryption and decryption. `PBKDF2` (Password-Based Key Derivation Function 2) applies pseudo-random functions along with a salt to protect against dictionary attacks and rainbow tables.

---

### Task 2 — Asymmetric Encryption & Digital Signatures

#### Objective
Generate a 2048-bit RSA key pair. Demonstrate dual asymmetric operations:
1. **Confidentiality**: Encrypt with the public key; decrypt exclusively with the private key.
2. **Integrity & Authenticity**: Sign a hash of the document with the private key; verify origin with the public key.

#### Commands Executed

```bash
# Generate a 2048-bit RSA private key
openssl genrsa -out private.pem 2048

# Extract the corresponding public key
openssl rsa -in private.pem -pubout -out public.pem

# Encrypt payload with PUBLIC key; decrypt with PRIVATE key
openssl pkeyutl -encrypt -pubin -inkey public.pem -in record.txt -out record.rsa
openssl pkeyutl -decrypt -inkey private.pem -in record.rsa -out record.rsa.txt

# Sign SHA-256 hash with PRIVATE key; verify signature with PUBLIC key
openssl dgst -sha256 -sign private.pem -out record.sig record.txt
openssl dgst -sha256 -verify public.pem -signature record.sig record.txt
```

#### Evidence & Output

![Task 2: Asymmetric RSA Key Pair, Public Key Encryption, and Digital Signature Verification](task2.png)

*Figure 2.1: RSA 2048-bit key pair generation, public key encryption, private key decryption, and digital signature validation yielding `Verified OK`.*

> [!IMPORTANT]
> **Key Cryptographic Inversion**:
> - **Encryption**: Uses Public Key to lock $\rightarrow$ Private Key to unlock (Provides Confidentiality).
> - **Digital Signing**: Uses Private Key to sign $\rightarrow$ Public Key to verify (Provides Authenticity and Non-Repudiation).

---

### Task 3 — Encryption in Transit (TLS)

#### Objective
Generate an X.509 self-signed certificate, deploy a secure HTTPS server via an NGINX container, serve `record.txt` over port 8443, and establish an encrypted TLS session.

#### Commands Executed

```bash
# Generate a self-signed TLS certificate and private key
openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem -days 7 -nodes -subj '/CN=localhost'

# Serve HTTPS on port 8443 using an NGINX container
docker run --rm -d --name tls -p 8443:443 \
  -v $(pwd)/cert.pem:/etc/nginx/cert.pem \
  -v $(pwd)/key.pem:/etc/nginx/key.pem \
  -v $(pwd)/record.txt:/usr/share/nginx/html/record.txt nginx

# Connect over TLS (-k bypasses self-signed CA warning)
curl -k https://localhost:8443/record.txt
```

#### Evidence & Output

![Task 3: Self-Signed Certificate Generation](task3.png)

*Figure 3.1: Generation of self-signed X.509 certificate (`cert.pem`) and private key (`key.pem`) for subject `/CN=localhost`.*

![Task 3.1: NGINX HTTPS Container Launch](task3.1.png)

*Figure 3.2: Pulling and deploying the official `nginx` Docker image with TLS volume mounts and port mapping `8443:443`.*

![Task 3.2: Connecting over TLS via curl](task3.2.png)

*Figure 3.3: Successfully executing `curl -k https://localhost:8443/record.txt` to retrieve sensitive data over an encrypted TLS channel.*

> [!TIP]
> **Security Impact**: In plain HTTP, payload bytes travel unencrypted across network routers, leaving them vulnerable to sniffing and Man-in-the-Middle (MITM) inspection. TLS encrypts packet payloads using asymmetric key exchange to agree on ephemeral symmetric keys, rendering wiretapped data unreadable.

---

## Session B (Week 6) — Key Management, Envelope Encryption & Erasure

Session B transitions from manual file-based key operations to an enterprise cloud Key Management Service (KMS) architecture.

---

### Task 4 — Create and Use a KMS Master Key

#### Objective
Bootstrap LocalStack KMS, create a dedicated Customer Master Key (CMK) for `Tenant A`, capture its `KeyId`, and perform direct encryption of a small secret string via the KMS API.

#### Commands Executed

```bash
EP='--endpoint-url=http://localhost:4566'

# Create a Customer Master Key (CMK) for Tenant A
aws $EP kms create-key --description 'CCSE tenant-A master key'

# Assign the returned KeyId to environment variable KEY_A
KEY_A="38d5051b-b68a-4f2c-843c-2e92d1eb1a37"

# Encrypt a small secret directly with KMS
aws $EP kms encrypt --key-id $KEY_A --plaintext "$(echo -n 'hello' | base64)" \
  --query CiphertextBlob --output text
```

#### Evidence & Output

![Task 4: KMS Customer Master Key (CMK) Creation for Tenant A](task4.png)

*Figure 4.1: KMS `create-key` output generating KeyId `38d5051b-b68a-4f2c-843c-2e92d1eb1a37` with state `Enabled`.*

![Task 4.1: Direct Payload Encryption with KMS Master Key](task4.1.png)

*Figure 4.2: Direct API call to KMS `encrypt` using `$KEY_A`, returning base64-encoded `CiphertextBlob`.*

---

### Task 5 — Envelope Encryption

#### Objective
Implement **envelope encryption** to protect large files efficiently:
1. Request a Data Encryption Key (DEK) from KMS (returns plaintext DEK + CMK-wrapped DEK).
2. Encrypt the target payload locally with the plaintext DEK using OpenSSL AES-256.
3. Purge the plaintext DEK from disk, leaving only the encrypted payload (`record.env.enc`) and the wrapped DEK (`datakey.enc`).

#### Commands Executed

```bash
# Step 5.1: Request Data Encryption Key (DEK) from KMS
aws $EP kms generate-data-key --key-id $KEY_A --key-spec AES_256 \
  --query '[Plaintext,CiphertextBlob]' --output text > datakey.txt

# Split plaintext DEK (col 1) and wrapped DEK (col 2)
awk '{print $1}' datakey.txt > datakey.b64
awk '{print $2}' datakey.txt > datakey.enc
ls -l datakey.b64 datakey.enc

# Step 5.2: Decode plaintext DEK and encrypt payload locally
base64 -d datakey.b64 > datakey.bin
openssl enc -aes-256-cbc -pbkdf2 -in record.txt -out record.env.enc -pass file:./datakey.bin
ls -l record.env.enc datakey.enc

# Step 5.3: Destroy plaintext DEK from local disk
rm datakey.bin datakey.b64 datakey.txt
echo 'Only the KMS-wrapped data key (datakey.enc) remains.'
```

#### Evidence & Output

![Task 5: Generating Data Key and Local Payload Encryption](task5.png)

*Figure 5.1: Requesting DEK from KMS, isolating plaintext base64 and wrapped ciphertexts, binary decoding, local AES-256 payload encryption (`record.env.enc`), and inspecting file sizes.*

![Task 5.1: Destroying Plaintext Data Key from Disk](task5.1.png)

*Figure 5.2: Purging `datakey.bin`, `datakey.b64`, and `datakey.txt` from local storage.*

![Task 5.2: Verifying Only KMS-Wrapped Data Key Remains](task5.2.png)

*Figure 5.3: Confirmation that only the wrapped DEK (`datakey.enc`) remains stored alongside encrypted data.*

> [!NOTE]
> **Why Envelope Encryption?**: Direct KMS APIs are restricted to small payload sizes ($\le 4 \text{ KB}$) and incur API latency/cost. Envelope encryption allows local high-speed symmetric encryption of arbitrary payload sizes using a unique DEK, while the DEK itself is protected under the HSM-backed master key (CMK).

---

### Task 6 — Per-Tenant Keys & Cryptographic Erasure

#### Objective
Demonstrate multi-tenant key separation by creating a separate CMK for `Tenant B`. Execute **cryptographic erasure** by scheduling deletion of Tenant A's CMK, disabling access, and proving that unwrapping Tenant A's DEK is mathematically impossible.

#### Commands Executed

```bash
# Create a dedicated KMS master key for Tenant B
aws $EP kms create-key --description 'CCSE tenant-B master key'
KEY_B="738b2480-8463-46fc-8c22-e203c2aa7a88"

# Schedule key deletion for Tenant A's master key (7-day window)
aws $EP kms schedule-key-deletion --key-id $KEY_A --pending-window-in-days 7

# Attempt to disable key (fails because key is pending deletion)
aws $EP kms disable-key --key-id $KEY_A

# Attempt to unwrap Tenant A's data key via KMS (MUST FAIL)
aws $EP kms decrypt --ciphertext-blob fileb://datakey.enc 2>&1 | head -3
```

#### Evidence & Output

![Task 6: Tenant B Key Creation, Key Deletion Scheduling, and Decryption Failure](task6.png)

*Figure 6.1: Creation of Tenant B key (`738b2480...`), scheduling deletion of Tenant A key (`38d5051b...`), state transition to `PendingDeletion`, and subsequent failure of `kms decrypt` with `NotFoundException`.*

> [!CAUTION]
> **Security Impact of Cryptographic Erasure**: Once the master key ($KEY\_A$) is deleted or rendered inaccessible, the wrapped DEK (`datakey.enc`) cannot be unwrapped. Consequently, `record.env.enc` becomes computationally indistinguishable from random noise across all cloud storage mirrors, achieving instant, provable deletion without requiring physical drive destruction.

---

### Task 7 — Integrity & Tamper-Evidence

#### Objective
Demonstrate payload integrity verification using SHA-256 hashes, show how a single-character modification alters hash output, and build a tamper-evident **hash chain** for audit logging.

#### Commands Executed

```bash
# Compute SHA-256 hash fingerprint of original record
sha256sum record.txt

# Tamper with a copy of the payload
cp record.txt tampered.txt
echo 'x' >> tampered.txt

# Compare original vs tampered file hashes
sha256sum record.txt tampered.txt

# Execute cryptographic hash chain for audit records
PREV=0
for line in 'login ok' 'file read' 'export data'; do
  PREV=$(echo -n "$PREV$line" | sha256sum | cut -d' ' -f1)
  echo "$line | $PREV"
done
```

#### Evidence & Output

![Task 7: SHA-256 Hashing, Tamper Detection, and Hash Chain Execution](task7.png)

*Figure 7.1: SHA-256 fingerprinting of original vs. tampered records, followed by execution of an iterative hash-chain loop.*

#### Hash Comparison & Log Output

- **Original `record.txt` SHA-256**:  
  `9345a32351cc1ad03e8b318059b753da6cd4e325688da97a01599b32bc945dd5`
- **Tampered `tampered.txt` SHA-256**:  
  `8c8afc8a3e34425ab38ef90213102c638a82f756bd7187a03b306c5683065eb7`

#### Hash-Chain Sequence

$$\text{Hash}_1 = \text{SHA256}("0" \mathbin{\Vert} \text{"login ok"}) = \texttt{573f9af26d45d395a1089ef5fec4d50ccddc17c0ea4269c2c91d90929a820053}$$
$$\text{Hash}_2 = \text{SHA256}(\text{Hash}_1 \mathbin{\Vert} \text{"file read"}) = \texttt{6c3adc61ece69412b338e43d761435e95dbfc948253f8f600087b0a4c5ad2d3d}$$
$$\text{Hash}_3 = \text{SHA256}(\text{Hash}_2 \mathbin{\Vert} \text{"export data"}) = \texttt{e1470ccfaf43dcab3c17d5710dc9eacbb7ac65c9f522ca98c2c503431b32da68}$$

---

## Deliverables & Assessment

### Summary of Evidence Artifacts

| Task Identifier | Command Executed | Primary Output / Verification | Image Artifact |
| :--- | :--- | :--- | :--- |
| **Task 1** | `openssl enc -aes-256-cbc ...` | Decryption `MATCH: decryption successful` | ![task1](task1.png) |
| **Task 2** | `openssl dgst -sha256 -verify ...` | RSA Signature validation `Verified OK` | ![task2](task2.png) |
| **Task 3** | `curl -k https://localhost:8443/...` | Encrypted payload served over TLS | ![task3](task3.png) ![task3.1](task3.1.png) ![task3.2](task3.2.png) |
| **Task 4** | `aws kms create-key` & `encrypt` | Tenant A Key ID & CiphertextBlob creation | ![task4](task4.png) ![task4.1](task4.1.png) |
| **Task 5** | `aws kms generate-data-key` | Local AES-256 payload enc & DEK cleanup | ![task5](task5.png) ![task5.1](task5.1.png) ![task5.2](task5.2.png) |
| **Task 6** | `aws kms decrypt ...` post erasure | Operation fails with `NotFoundException` | ![task6](task6.png) |
| **Task 7** | `sha256sum` & hash chain loop | Hash change on tamper & sequential chain | ![task7](task7.png) |

---

### Short-Answer Questions

#### Q1. Compare symmetric and asymmetric encryption: speed, key distribution, and typical use.

| Property | Symmetric Encryption (e.g., AES-256) | Asymmetric Encryption (e.g., RSA-2048, ECC) |
| :--- | :--- | :--- |
| **Execution Speed** | Extremely fast (hardware-accelerated via AES-NI instructions). | Orders of magnitude slower due to complex modular exponentiation. |
| **Key Distribution** | **High Complexity**: Requires secure pre-sharing of a single secret key between parties. | **Low Complexity**: Public keys are freely distributed; private keys remain strictly confidential. |
| **Primary Use Cases** | Bulk data-at-rest encryption (disk volumes, databases, cloud storage buckets). | Key exchange protocols (TLS handshake), digital signatures, PKI identity verification. |
| **Hybrid Integration** | Used in hybrid schemes: Asymmetric encryption exchanges a symmetric key, which encrypts bulk data. | Encrypts small symmetric keys or hashes. |

---

#### Q2. Why is key management described as the weakest link, not the algorithm?

Modern standardized cryptographic algorithms such as AES-256 and RSA-2048 are mathematically robust against brute-force attacks given current computational capabilities. However, a cryptographic system is only as secure as its key management architecture. Key management represents the primary operational weakness due to several human and system factors:
1. **Insecure Storage**: Hardcoding private keys or passwords into source code repositories or unencrypted environment variables.
2. **Access Control Failures**: Inadequate IAM policies granting overly permissive key access to non-essential roles.
3. **Lack of Key Rotation**: Reusing static keys over long periods increases vulnerability to key compromise.
4. **Improper Destruction**: Retaining plain key material on persistent storage media after process completion.

---

#### Q3. Explain envelope encryption and why only the master key needs hardware-grade protection.

**Envelope Encryption** is a security pattern where data is encrypted locally using a unique **Data Encryption Key (DEK)**, and the DEK itself is encrypted (wrapped) using a **Customer Master Key (CMK)** managed by a Key Management Service (KMS).

```
                      +-------------------+
                      | Master Key (CMK)  |  <-- Kept inside Hardware Security Module (HSM)
                      +---------+---------+
                                | (Encrypts / Wraps)
                                v
+------------------+  +-------------------+  +------------------+
| Data Payload     |  | Wrapped Data Key  |  | Plaintext DEK    | (Used locally, then
| (Arbitrary Size) |  | (datakey.enc)     |  | (datakey.bin)    |  purged from disk)
+--------+---------+  +-------------------+  +--------+---------+
         |                                            |
         +------------------[ AES-256 ]---------------+
                                |
                                v
                      +-------------------+
                      | Encrypted Payload |
                      | (record.env.enc)  |
                      +-------------------+
```

- **Why Master Keys Need Hardware-Grade Protection**: Customer Master Keys (CMKs) reside permanently inside FIPS 140-2/3 validated **Hardware Security Modules (HSMs)**. CMKs never leave the HSM unencrypted, preventing physical key extraction.
- **Why DEKs Do Not Require HSM Protection**: Protecting every DEK in an HSM would overload KMS infrastructure and create significant network bottlenecks during bulk data reads/writes. By wrapping DEKs with the CMK, wrapped DEKs can be safely stored alongside encrypted datasets in standard storage systems (e.g., AWS S3). To decrypt, only the small wrapped DEK is sent to KMS for unwrapping.

---

#### Q4. How does cryptographic erasure achieve provable deletion where overwriting cannot (in the cloud)?

In virtualized multi-tenant cloud storage systems, physical drive overwriting (e.g., `shred`, `dd if=/dev/zero`, degaussing) is ineffective and non-verifiable due to underlying abstraction layers:
- **Storage Virtualization & RAID**: Logical block addresses (LBAs) do not map directly to static physical flash memory locations.
- **Wear-Leveling on SSDs**: Flash controllers redistribute writes across physical blocks, leaving orphaned data remnants.
- **Replication & Snapshots**: Automated backups, storage snapshots, and cross-region replicas silently maintain redundant data copies.

**Cryptographic Erasure (Crypto-Shredding)** solves this problem by ensuring data is encrypted at rest using a unique per-tenant or per-object master key. When deletion is requested, the provider permanently deletes or disables the specific master key in KMS. Without the master key:
1. Wrapped data keys can never be unwrapped.
2. All encrypted data blocks across all distributed storage mirrors and backup snapshots instantly become computationally un-decryptable ciphertext (indistinguishable from random noise).
3. Deletion is **provable and instantaneous**, regardless of physical storage architecture.

---

#### Q5. How does a hash chain make a log tamper-evident (link to tamper-proof logs, Week 6)?

A **hash chain** binds log entries together sequentially by incorporating the hash of the preceding record into the computation of the current record's digest:

$$H_0 = 0$$
$$H_n = \text{SHA-256}(H_{n-1} \mathbin{\Vert} \text{Log\_Message}_n)$$

If an attacker attempts to modify, insert, or delete a historical log line ($\text{Log\_Message}_k$), the resulting hash $H_k$ will change due to the avalanche effect of cryptographic hash functions. Because every subsequent hash $H_{k+1}, H_{k+2}, \dots, H_N$ depends directly on $H_k$, the entire chain following the tampered entry breaks.

```
Log Entry 1 ("login ok")    --> Hash 1: 573f9af2...
                                   |
Log Entry 2 ("file read")   --> Hash 2: 6c3adc61... (derived from Hash 1 + "file read")
                                   |
Log Entry 3 ("export data") --> Hash 3: e1470cca... (derived from Hash 2 + "export data")
```

In cloud auditing systems (such as AWS CloudTrail digest validation or append-only ledgers), storing the latest hash root in write-once-read-many (WORM) storage or publishing it periodically ensures that any retroactive tampering by an adversary is mathematically detectable.

---

## Verification Commands

To verify active KMS keys and validate cryptographic signature verification, execute the following commands:

```bash
# List all active KMS keys in LocalStack
aws --endpoint-url=http://localhost:4566 kms list-keys

# Verify RSA signature on record.txt using public key
openssl dgst -sha256 -verify public.pem -signature record.sig record.txt
```

---

## Security Best-Practices Checklist

- [x] **Data Encrypted at Rest**: Sensitive data encrypted using AES-256-CBC and PBKDF2; decryption verified.
- [x] **Asymmetric Key Usage**: RSA 2048-bit keys correctly separated (public key for encryption/verification, private key for decryption/signing).
- [x] **In-Transit Protection**: HTTPS/TLS established via Dockerized NGINX with certificate volume bindings.
- [x] **Envelope Encryption Enforced**: Data keys generated via KMS, used locally for bulk encryption, and purged from disk memory.
- [x] **Per-Tenant KMS Keys & Erasure**: Multi-tenant CMK separation established; cryptographic erasure demonstrated by key deletion and unwrapping failure.
- [x] **Integrity & Tamper-Evidence**: SHA-256 hashing applied to detect unauthorized modifications; sequential hash chain implemented for audit trail protection.

---

## Cleanup & Teardown

To stop active containers and purge temporary cryptographic artifacts from the working directory, execute:

```bash
# Stop and remove running NGINX TLS container
docker stop tls 2>/dev/null

# Clean up local cryptographic files and key artifacts
rm -f record.* private.pem public.pem key.pem cert.pem datakey.* tampered.txt

# Stop and remove LocalStack container
docker stop localstack && docker rm localstack
```

---

## References

1. UniKL MIIT — *IKB42603 Cloud Computing Security Essentials*, Week 4 (Data Protection) & Week 9 (Key Management Patterns).
2. OpenSSL Cryptographic Documentation — [https://www.openssl.org/docs](https://www.openssl.org/docs)
3. AWS Key Management Service (KMS) Developer Guide — [Envelope Encryption Concepts](https://docs.aws.amazon.com/kms/latest/developerguide/concepts.html)
4. Cloud Security Alliance (CSA) — *Security Guidance for Critical Areas of Focus in Cloud Computing v5.0*, Data Security & Encryption Domain.
