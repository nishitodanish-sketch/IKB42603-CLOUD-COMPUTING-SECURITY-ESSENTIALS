# Lab 0: Environment Setup Report

**Course:** IKB42603 Cloud Computing Security Essentials  
**Student Name:** MUHAMMMAD DANISH BIN MAHAMAD MAHAZAN  
**Class No:** L02-B04  
**Guide Document:** `IKB42603_Lab0_Environment_Setup_Cheatsheet.pdf`  

---

## Executive Summary & Tool Overview

This report documents the step-by-step installation and verification of the local lab environment required for **IKB42603 Cloud Computing Security Essentials**. All lab tools are hosted and executed locally within a Kali Linux / WSL environment, eliminating the need for paid cloud subscriptions or remote internet access during lab exercises.

### Tool Summary Table

| Tool | Purpose | Primary Use Case | Verification Command |
| :--- | :--- | :--- | :--- |
| **Docker** | Containerization platform & LocalStack host | All Labs | `docker --version` |
| **AWS CLI v2** | Command-line interface for AWS APIs | Labs 1, 3, 5 | `aws --version` |
| **kind** | Kubernetes-in-Docker cluster management | Labs 1, 2, 4 | `kind --version` |
| **kubectl** | Kubernetes command-line controller | Labs 1, 2, 4 | `kubectl version --client` |
| **OpenSSL** | Cryptographic & certificate management | Lab 3 | `openssl version` |
| **oathtool** | One-Time Password (TOTP/MFA) generation | Lab 4 | `oathtool --version` |
| **LocalStack** | Local cloud service emulator (AWS API) | Labs 1, 3, 5 | `curl http://localhost:4566/_localstack/health` |

---

## Step-by-Step Installation & Verification

### Step 1: Docker Installation & Verification

Docker runs containers and hosts the LocalStack cloud simulator.

#### Verification Commands
```bash
docker --version
sudo docker run --rm hello-world
```

#### Terminal Output Evidence
- **Docker Version:**
  ```text
  Docker version 28.5.2+dfsg4, build 9cc6dea35e9a963f281434761c656fba4ac43aed
  ```
- **Docker Hello World Test:**
  ```text
  Hello from Docker!
  This message shows that your installation appears to be working correctly.
  ```

#### Evidence Screenshots
![Docker Version Verification](1.docker%20install.png)  
![Docker Hello-World Verification](1.docker%20hello.png)

---

### Step 2: AWS CLI v2 Installation & Verification

The AWS CLI v2 sends requests to LocalStack rather than real AWS cloud endpoints.

#### Verification Command
```bash
aws --version
```

#### Terminal Output Evidence
```text
aws-cli/2.36.9 Python/3.14.6 Linux/5.15.0-kali3-amd64 exe/x86_64.kali.2022
```

#### Evidence Screenshot
![AWS CLI Version Verification](2.aws_cli.png)

---

### Step 3: Kubernetes Tools Installation (kind & kubectl)

`kind` (Kubernetes-in-Docker) provisions local Kubernetes clusters, while `kubectl` controls the cluster objects.

#### Verification Commands
```bash
kind --version
kubectl version --client
```

#### Terminal Output Evidence
- **kind Output:**
  ```text
  kind version 0.23.0
  ```
- **kubectl Output:**
  ```text
  Client Version: v1.33.4
  Kustomize Version: v5.5.0
  ```

#### Evidence Screenshots
![kind Version Verification](03.kind%20version.png)  
![kubectl Client Version Verification](3.kind_client.png)

---

### Step 4: Helper Tools Verification (OpenSSL & oathtool)

OpenSSL provides cryptographic capabilities for Lab 3, while `oathtool` generates Multi-Factor Authentication (MFA) codes for Lab 4.

#### Verification Commands
```bash
openssl version
oathtool --version
```

#### Terminal Output Evidence
- **OpenSSL Output:**
  ```text
  OpenSSL 1.1.1m  14 Dec 2021
  ```
- **oathtool Output:**
  ```text
  oathtool (OATH Toolkit) 2.6.14
  Copyright (C) 2009-2026 Simon Josefsson.
  ```

#### Evidence Screenshots
![OpenSSL Version Verification](04.openSLL.png)  
![oathtool Version Verification](4.oathtool.png)

---

### Step 5: LocalStack Setup & Lifecycle Management

LocalStack simulates AWS cloud APIs locally.

#### 5.1 Initializing LocalStack Container
To launch LocalStack in detached mode mapping port 4566:
```bash
sudo docker run -d --name localstack -p 4566:4566 localstack/localstack
```

![LocalStack Container Start](5.%20local_stack.png)

#### 5.2 Container Status Check
Verify that the container is up and running:
```bash
sudo docker ps
```
```text
CONTAINER ID   IMAGE                      COMMAND                  CREATED        STATUS                    PORTS
fea1a2bb2bd9   localstack/localstack:3.8.1   "docker-entrypoint.sh"   9 seconds ago  Up 8 seconds (health: starting)   0.0.0.0:4566->4566/tcp, :::4566->4566/tcp   localstack
```

![LocalStack Docker PS Verification](6.%20health.png)

#### 5.3 LocalStack Health Endpoint Check
Verify health status of local AWS services:
```bash
curl http://localhost:4566/_localstack/health
```
```json
{
  "services": {
    "ec2": "available",
    "lambda": "available",
    "s3": "available",
    "sts": "available"
  },
  "edition": "community",
  "version": "3.8.1"
}
```

![LocalStack Health Endpoint Check](6.%20health%20best%20.png)

#### 5.4 Container Lifecycle Management (Stop, Start, Remove)
Demonstrating standard lifecycle operations for LocalStack:
```bash
# Stop LocalStack
sudo docker stop localstack

# Start LocalStack
sudo docker start localstack

# Force Remove LocalStack
sudo docker rm -f localstack
```

![LocalStack Lifecycle Management](6.%20stopp_start%20.png)

---

### Step 6: Kubernetes Cluster Management (kind & kubectl)

Provisions a local Kubernetes cluster named `ccse` inside Docker.

#### 6.1 Creating Cluster
```bash
sudo kind create cluster --name ccse
```
```text
Creating cluster "ccse" ...
 ✓ Ensuring node image (kindest/node:v1.30.0) 🖼
 ✓ Preparing nodes 📦
 ✓ Writing configuration 📜
 ✓ Starting control-plane 🕹
 ✓ Installing CNI 🔌
 ✓ Installing StorageClass 💾
Set kubectl context to "kind-ccse"
```

![kind Cluster Creation](7.%20kubernete.png)

#### 6.2 Checking Cluster Info
```bash
sudo kubectl cluster-info --context kind-ccse
```
```text
Kubernetes control plane is running at https://127.0.0.1:45189
CoreDNS is running at https://127.0.0.1:45189/api/v1/namespaces/kube-system/services/kube-dns:dns/proxy
```

![kubectl Cluster Info Verification](7.kubectl.png)

#### 6.3 Checking Cluster Nodes
```bash
sudo kubectl get nodes
```
```text
NAME                 STATUS   ROLES           AGE     VERSION
ccse-control-plane   Ready    control-plane   4m6s    v1.30.0
```

![kubectl Get Nodes Verification](7.get%20node.png)

#### 6.4 Deleting Cluster
```bash
sudo kind delete cluster --name ccse
```
```text
Deleting cluster "ccse" ...
Deleted nodes: ["ccse-control-plane"]
```

![kind Cluster Deletion](7,%20delte.png)

---

### Step 7: One-Time AWS CLI Configuration & Endpoint Testing

Configure dummy credentials for AWS CLI to interact with LocalStack without requiring active AWS accounts or keys.

#### 7.1 Setting Dummy Credentials
```bash
sudo aws configure set aws_access_key_id test
sudo aws configure set aws_secret_access_key test
sudo aws configure set region us-east-1
```

![AWS CLI Dummy Configuration](8.aws%20_test.png)

#### 7.2 Setting LocalStack Endpoint Variable
To simplify requests, store the LocalStack endpoint in the `EP` environment variable:
```bash
EP="--endpoint-url=http://localhost:4566"
echo $EP
```

![LocalStack Endpoint Environment Variable](8.endpoint%20test%20.png)

#### 7.3 Verifying LocalStack STS Communication
Test STS caller identity to confirm AWS CLI communicates with LocalStack:
```bash
aws $EP sts get-caller-identity
```
```json
{
    "UserId": "AKIAIOSFODNN7EXAMPLE",
    "Account": "000000000000",
    "Arn": "arn:aws:iam::000000000000:root"
}
```

![AWS CLI Get Caller Identity Verification](8.cli%20caller%20.png)

---

## Step 8: Pre-Lab Verification Checklist

All items on the pre-lab verification checklist have been executed and validated against empirical output:

- [x] **Docker:** `docker --version` prints valid version (`28.5.2`).
- [x] **AWS CLI v2:** `aws --version` prints valid version (`2.36.9`).
- [x] **kind & kubectl:** `kind --version` (`0.23.0`) and `kubectl version --client` (`v1.33.4`) operational.
- [x] **Helper Tools:** OpenSSL (`1.1.1m`) and `oathtool` (`2.6.14`) present.
- [x] **LocalStack:** Starts properly, container health endpoint `http://localhost:4566/_localstack/health` returns healthy JSON response.
- [x] **AWS CLI Integration:** `aws $EP sts get-caller-identity` returns valid local root ARN (`arn:aws:iam::000000000000:root`).
- [x] **Kubernetes Cluster:** `kind create cluster --name ccse` creates `ccse-control-plane` node in `Ready` state, and cluster deletion operates cleanly.
- [x] **Environment:** Working inside Kali Linux terminal shell.

---

## Security & Operational Notes

1. **Local Isolation:** All resources and state in LocalStack and `kind` operate strictly within local memory and Docker container networks. No internet connection or remote AWS infrastructure is required during lab execution.
2. **Credential Neutrality:** Dummy keys (`test`/`test`) prevent accidental exposure of real cloud credentials.
3. **Clean Teardown:** LocalStack containers and `kind` clusters can be recreated at any time with zero persistence issues using `docker rm -f localstack` and `kind delete cluster --name ccse`.
