---
title: Linux Distribution Landscape
key: page-linux_type
categories:
- Engineering
- SysOps & Infrastructure
author: hyoeun
math: false
mathjax_autoNumber: false
image: "/assets/thumbnails/2019-05-12-linux_type.png"
bilingual: true
date: 2019-05-12 09:00:00
---

## Why Distribution Choice Is an Architectural Decision

Choosing a Linux distribution feels like a trivial ops decision until you're three years into a project and facing an EOL crisis, a licensing audit, or a CVE that won't be backported to your aging kernel. Every distro embeds assumptions about update cadence, support contracts, tooling, and community behavior — and those assumptions ripple through your entire stack. If you're running infrastructure, writing deployment automation, or hardening systems, you need to understand the distribution landscape at a level deeper than "Ubuntu for dev, CentOS for prod."

## Core Concept: Two Families, Divergent Philosophies

Every mainstream Linux distribution descends from one of two packaging lineages, and that lineage determines more than just which package manager you use.

### The Debian Family

Debian itself is the philosophical root: a volunteer-driven project that prizes correctness and stability over speed. The `.deb` format and `dpkg`/`apt` toolchain descend from here.

**Ubuntu** is the most commercially successful Debian derivative. Canonical ships two tracks:
- **LTS releases** (e.g., 20.04, 22.04, 24.04) — 5-year standard support, 10-year ESM. The right choice for production servers and enterprise deployments.
- **Interim releases** (e.g., 23.10) — 9-month lifecycle, track newer kernels and toolchain updates. Development workstations only.

**Debian stable** ships older packages but is extraordinarily stable. It's the foundation for many security-focused distributions.

**Kali Linux** is Debian-based but ships as a rolling release with offensive security tools pre-packaged. Never run Kali as a general server OS — its configuration is optimized for a pentester's workstation, not hardening.

**Alpine Linux** is the outlier: Debian lineage in heritage but uses `apk` and `musl libc` instead of `glibc`. Its entire base image is ~5MB, making it the dominant choice for container base images. The musl/glibc incompatibility bites you with pre-compiled binaries — know this before you base a container on it.

### The Red Hat Family

Red Hat Enterprise Linux (RHEL) is the commercial anchor. The `.rpm` format and `yum`/`dnf` toolchain define this family.

**RHEL** itself is the gold standard for enterprise Linux: strict certification program (SAP, Oracle, hardware vendors), 10-year support lifecycle, and subscription-based CVE backporting. The price is real, but so is the value in regulated industries.

**CentOS** was the free RHEL rebuild for a decade. CentOS 7 reaches EOL June 2024. CentOS 8 was killed early and replaced with **CentOS Stream**, which is now a *rolling preview* of the next RHEL minor release — not the stable RHEL clone it used to be. This distinction matters operationally.

**AlmaLinux and Rocky Linux** are the community responses to the CentOS pivot. Both aim for binary compatibility with RHEL. Rocky was founded by a CentOS co-founder; AlmaLinux is backed by CloudLinux. Either is a reasonable CentOS replacement for 2024 and beyond.

**Fedora** is Red Hat's upstream innovation platform — newer packages, shorter support cycles (~13 months), and where Red Hat tests features before RHEL. Use it on developer workstations, not servers.

**Amazon Linux 2 / Amazon Linux 2023** are RPM-based distros tuned for AWS. AL2023 uses `dnf` and tracks closer to Fedora. Good for AWS-native deployments; awkward anywhere else.

### The Independent Track: Arch and Derivatives

**Arch Linux** is a rolling release with a minimalist philosophy: you build the system you need from scratch. The result is deep understanding and full control — and a significant investment of time. **Manjaro** wraps Arch with a gentler installer and slightly delayed updates for stability. Neither belongs in production, but Arch is valuable as a learning environment and for developers who need bleeding-edge toolchain access.

## How It Works: Key Technical Differences

### Kernel and Libc

| Distro | Default libc | Kernel track |
|--------|-------------|--------------|
| RHEL 8/9 | glibc | LTS, heavily patched |
| Ubuntu LTS | glibc | LTS + HWE stack option |
| Alpine | musl libc | LTS |
| Arch | glibc | Latest stable |

The **Hardware Enablement (HWE) stack** on Ubuntu LTS deserves mention: it lets you run a newer kernel (e.g., 6.5 on 22.04) while keeping the LTS userland. Useful for new hardware support without upgrading the full OS.

### Package Management Comparison

```bash
# Debian/Ubuntu
apt update && apt upgrade
apt install <package>
apt search <keyword>
dpkg -l | grep <package>        # list installed
dpkg -L <package>               # list files in package

# RHEL/CentOS/AlmaLinux/Rocky
dnf update
dnf install <package>
dnf search <keyword>
rpm -qa | grep <package>        # list installed
rpm -ql <package>               # list files in package

# Alpine
apk update && apk upgrade
apk add <package>
apk search <keyword>

# Arch
pacman -Syu                     # sync and upgrade
pacman -S <package>
pacman -Ss <keyword>
```

### Init Systems

All modern major distributions use **systemd** as their init system. The only notable exceptions are Alpine (uses OpenRC) and minimal embedded/container-focused distros. If you're still writing SysV init scripts in 2024, stop.

```bash
# Managing services — same syntax across systemd distros
systemctl start nginx
systemctl enable nginx          # start on boot
systemctl status nginx
journalctl -u nginx -f          # follow logs for a unit
```

## Practical Application: Choosing the Right Distro

### Production Web/App Server

**First choice: RHEL (with subscription) or AlmaLinux/Rocky Linux.**

The 10-year support lifecycle means you're not forced into OS upgrades mid-project. CVE backporting means security patches don't drag in API-breaking version bumps. SELinux enforcement is mature and well-documented for this family.

**Second choice: Ubuntu LTS.**

Better Docker/Kubernetes ecosystem support, more current packages, and more developer-friendly tooling. Canonical's Landscape and ESM provide enterprise-grade support if you need it.

### Containers

**Alpine for minimal images; Ubuntu or Debian slim for compatibility.**

```dockerfile
# Alpine — minimal, ~5MB base
FROM alpine:3.19
RUN apk add --no-cache python3 py3-pip

# When you need glibc compatibility
FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 python3-pip && rm -rf /var/lib/apt/lists/*
```

The key Alpine trap: compiled Python extensions, glibc-linked binaries, and some Go binaries that bundle glibc won't run on musl. Test your full dependency tree before committing to Alpine.

### Security/Penetration Testing

**Kali Linux** for dedicated pentest workstations. It ships with maintained tooling and AppArmor profiles for pentest tools. Do not harden a Kali system for production use — its defaults (root-capable user, disabled firewall, etc.) are intentional for the use case.

**Parrot OS** is a lighter Debian-based alternative worth knowing.

### Learning / Home Lab

**Ubuntu** for the largest community and most documentation. **Arch** if you want to understand Linux deeply — the Arch Wiki is genuinely the best Linux reference document in existence, useful even when you're running other distributions.

## Gotchas: What Experts Know

**CentOS Stream is not a RHEL replacement.** It sits *upstream* of RHEL, meaning you may encounter bugs that are fixed in RHEL before they appear in Stream. Production workloads that relied on CentOS 7/8 stability need to move to AlmaLinux, Rocky, or RHEL — not Stream.

**Ubuntu LTS kernel options are confusing.** The GA kernel for 22.04 is 5.15; the HWE kernel is newer. Running `apt install linux-image-generic-hwe-22.04` gets you the HWE track. If you're automating kernel management, be explicit about which track you're pinning.

**Alpine's DNS behavior in containers differs from glibc distros.** The `musl` resolver doesn't honor `search` domains the same way. This breaks service discovery in Kubernetes in subtle ways. Use `ndots:5` in your pod DNS config and test DNS resolution explicitly.

**RPM and DEB packages are not interchangeable.** Tools like `alien` exist to convert between them but produce unreliable results for anything beyond simple packages. Never use converted packages in production.

**RHEL 8+ uses `dnf` as default, not `yum`.** `yum` is a symlink to `dnf` on RHEL 8/9 for backward compatibility, but `dnf` has different module/stream behavior. Scripts that relied on `yum` behavior should be tested, not assumed compatible.

**EOL dates are hard deadlines, not suggestions.**

| Distro | EOL Date |
|--------|----------|
| CentOS 7 | June 30, 2024 |
| Ubuntu 20.04 LTS | April 2025 (standard) |
| Ubuntu 22.04 LTS | April 2027 (standard) |
| RHEL 8 | May 2029 |
| RHEL 9 | May 2032 |
| AlmaLinux 8 | 2029 |
| Debian 12 (Bookworm) | ~2028 |

## Quick Reference

```text
DISTRO DECISION TREE
─────────────────────────────────────────────────────────
Need 10-year support + CVE backporting?     → RHEL or AlmaLinux/Rocky
Production server, cost-sensitive?          → AlmaLinux or Rocky Linux
Cloud-native / Kubernetes workload?         → Ubuntu LTS or Amazon Linux 2023
Container base image (size matters)?        → Alpine (if no glibc deps)
Container base image (compatibility)?       → debian:slim or ubuntu:focal
Developer workstation (latest tooling)?     → Ubuntu (interim) or Fedora
Penetration testing workstation?            → Kali Linux
Learning Linux internals deeply?            → Arch Linux
Edge / IoT / embedded?                      → Alpine or Yocto-based
```

```bash
# Identify distribution on any system
cat /etc/os-release
lsb_release -a          # if lsb-release is installed
uname -r                # kernel version
```

```bash
# Check installed packages across families
rpm -qa --queryformat '%{NAME}-%{VERSION}\n' | sort  # RPM
dpkg-query -W -f='${Package} ${Version}\n' | sort    # DEB
```

---

## 왜 배포판 선택이 아키텍처 결정인가

Linux 배포판 선택은 사소한 운영 결정처럼 보이지만, 3년 후 EOL 위기나 라이선스 감사, 오래된 커널에 백포팅되지 않는 CVE를 마주하는 순간 그 무게가 드러난다. 모든 배포판은 업데이트 주기, 지원 계약, 도구, 커뮤니티 행동 방식에 대한 가정을 내포하고 있으며, 그 가정들은 전체 스택에 영향을 미친다. 인프라를 운영하거나 배포 자동화를 작성하거나 시스템을 강화하는 작업을 한다면, "개발은 Ubuntu, 프로덕션은 CentOS" 수준을 넘어 배포판 생태계를 이해해야 한다.

## 핵심 개념: 두 계열, 서로 다른 철학

주류 Linux 배포판은 모두 두 패키징 계보 중 하나에서 파생되며, 그 계보는 패키지 매니저 이상의 것을 결정한다.

### Debian 계열

Debian 자체는 철학적 뿌리다. 속도보다 정확성과 안정성을 우선시하는 자원봉사 주도 프로젝트다. `.deb` 형식과 `dpkg`/`apt` 툴체인이 여기서 비롯된다.

**Ubuntu**는 가장 상업적으로 성공한 Debian 파생 배포판이다. Canonical은 두 트랙을 제공한다:
- **LTS 릴리스** (예: 20.04, 22.04, 24.04) — 5년 표준 지원, 10년 ESM. 프로덕션 서버와 기업 배포에 적합한 선택.
- **중간 릴리스** (예: 23.10) — 9개월 라이프사이클, 최신 커널과 툴체인 업데이트 추적. 개발 워크스테이션 전용.

**Debian stable**은 오래된 패키지를 제공하지만 매우 안정적이다. 많은 보안 중심 배포판의 기반이다.

**Kali Linux**는 Debian 기반이지만 롤링 릴리스로 공격적 보안 도구를 사전 패키징해서 제공한다. Kali를 범용 서버 OS로 실행하지 마라 — 그 설정은 하드닝이 아닌 펜테스터 워크스테이션에 최적화되어 있다.

**Alpine Linux**는 이단아다. Debian 계보를 가지지만 `glibc` 대신 `musl libc`와 `apk`를 사용한다. 전체 베이스 이미지가 약 5MB로, 컨테이너 베이스 이미지의 지배적 선택이다. musl/glibc 비호환성은 사전 컴파일된 바이너리에서 문제가 생긴다 — Alpine을 컨테이너 베이스로 선택하기 전에 이를 알아야 한다.

### Red Hat 계열

Red Hat Enterprise Linux(RHEL)는 상업적 기반이다. `.rpm` 형식과 `yum`/`dnf` 툴체인이 이 계열을 정의한다.

**RHEL** 자체는 기업용 Linux의 황금 표준이다. 엄격한 인증 프로그램(SAP, Oracle, 하드웨어 벤더), 10년 지원 라이프사이클, 구독 기반 CVE 백포팅. 비용은 실제이지만, 규제 산업에서는 그 가치도 실제다.

**CentOS**는 10년간 무료 RHEL 재빌드였다. CentOS 7은 2024년 6월 EOL. CentOS 8은 일찍 종료되고 **CentOS Stream**으로 교체되었는데, 이는 이제 다음 RHEL 마이너 릴리스의 *롤링 프리뷰*다 — 이전처럼 안정적인 RHEL 클론이 아니다. 이 구분은 운영상 중요하다.

**AlmaLinux와 Rocky Linux**는 CentOS 전환에 대한 커뮤니티 응답이다. 둘 다 RHEL과의 바이너리 호환성을 목표로 한다. Rocky는 CentOS 공동 창립자가 설립했고, AlmaLinux는 CloudLinux가 지원한다.

**Fedora**는 Red Hat의 업스트림 혁신 플랫폼이다. 더 새로운 패키지, 짧은 지원 주기(약 13개월), 그리고 RHEL에 들어가기 전 기능을 테스트하는 곳이다. 개발자 워크스테이션에는 적합하지만 서버에는 아니다.

**Amazon Linux 2 / Amazon Linux 2023**은 AWS에 맞춰진 RPM 기반 배포판이다. AL2023은 `dnf`를 사용하고 Fedora에 더 가깝다. AWS 네이티브 배포에는 좋지만 다른 환경에서는 어색하다.

### 독립 트랙: Arch와 파생 배포판

**Arch Linux**는 미니멀리스트 철학의 롤링 릴리스다. 처음부터 필요한 시스템을 직접 구성한다. 결과는 깊은 이해와 완전한 제어 — 그리고 상당한 시간 투자다. **Manjaro**는 Arch를 더 친절한 설치 프로그램과 약간 지연된 업데이트로 포장한다. 둘 다 프로덕션에는 적합하지 않지만, Arch는 학습 환경과 최신 툴체인이 필요한 개발자에게 가치 있다.

## 동작 원리: 핵심 기술적 차이

### 커널과 Libc

| 배포판 | 기본 libc | 커널 트랙 |
|--------|----------|-----------|
| RHEL 8/9 | glibc | LTS, 중요한 패치 적용 |
| Ubuntu LTS | glibc | LTS + HWE 스택 옵션 |
| Alpine | musl libc | LTS |
| Arch | glibc | 최신 안정 버전 |

Ubuntu LTS의 **Hardware Enablement(HWE) 스택**은 주목할 만하다. LTS 유저랜드를 유지하면서 더 새로운 커널(예: 22.04에서 6.5)을 실행할 수 있다. 전체 OS를 업그레이드하지 않고도 새 하드웨어 지원이 가능하다.

### 패키지 관리 비교

```bash
# Debian/Ubuntu
apt update && apt upgrade
apt install <package>
apt search <keyword>
dpkg -l | grep <package>        # 설치된 패키지 목록
dpkg -L <package>               # 패키지 내 파일 목록

# RHEL/CentOS/AlmaLinux/Rocky
dnf update
dnf install <package>
dnf search <keyword>
rpm -qa | grep <package>        # 설치된 패키지 목록
rpm -ql <package>               # 패키지 내 파일 목록

# Alpine
apk update && apk upgrade
apk add <package>
apk search <keyword>

# Arch
pacman -Syu                     # 동기화 및 업그레이드
pacman -S <package>
pacman -Ss <keyword>
```

### Init 시스템

모든 현대적 주요 배포판은 **systemd**를 init 시스템으로 사용한다. 주목할 만한 예외는 Alpine(OpenRC 사용)과 최소화된 임베디드/컨테이너 중심 배포판뿐이다.

```bash
# 모든 systemd 배포판에서 동일한 구문
systemctl start nginx
systemctl enable nginx          # 부팅 시 시작
systemctl status nginx
journalctl -u nginx -f          # 유닛 로그 실시간 확인
```

## 실전 적용: 적합한 배포판 선택

### 프로덕션 웹/앱 서버

**우선 선택: RHEL(구독 포함) 또는 AlmaLinux/Rocky Linux.**

10년 지원 라이프사이클은 프로젝트 중간에 OS 업그레이드를 강제하지 않는다. CVE 백포팅은 API를 깨는 버전 업그레이드 없이 보안 패치를 적용한다. SELinux 강제 적용이 이 계열에서 성숙하고 잘 문서화되어 있다.

**두 번째 선택: Ubuntu LTS.**

더 나은 Docker/Kubernetes 에코시스템 지원, 더 최신 패키지, 개발자 친화적 도구. Canonical의 Landscape와 ESM이 필요한 경우 기업급 지원을 제공한다.

### 컨테이너

**최소 이미지에는 Alpine, 호환성이 필요하면 Ubuntu 또는 Debian slim.**

```dockerfile
# Alpine — 최소화, ~5MB 베이스
FROM alpine:3.19
RUN apk add --no-cache python3 py3-pip

# glibc 호환성이 필요할 때
FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 python3-pip && rm -rf /var/lib/apt/lists/*
```

핵심 Alpine 함정: 컴파일된 Python 확장, glibc 링크 바이너리, glibc를 번들한 일부 Go 바이너리는 musl에서 실행되지 않는다. Alpine을 선택하기 전에 전체 의존성 트리를 테스트하라.

### 보안/침투 테스트

전용 펜테스트 워크스테이션에는 **Kali Linux**. 유지 관리된 도구와 AppArmor 프로파일이 포함되어 있다. 프로덕션 용도로 Kali를 하드닝하려 하지 마라 — 기본 설정(루트 권한 사용자, 비활성화된 방화벽 등)은 사용 목적을 위한 의도적 선택이다.

### 학습 / 홈 랩

**Ubuntu** — 가장 큰 커뮤니티와 가장 많은 문서. **Arch** — Linux 내부를 깊이 이해하고 싶다면. Arch Wiki는 다른 배포판을 실행할 때도 유용한, 현존하는 최고의 Linux 참고 문서다.

## 함정: 전문가들이 아는 것

**CentOS Stream은 RHEL 대체품이 아니다.** RHEL의 *업스트림*에 위치하기 때문에, RHEL에서 수정되기 전에 Stream에서 버그를 만날 수 있다. CentOS 7/8의 안정성에 의존했던 프로덕션 워크로드는 Stream이 아닌 AlmaLinux, Rocky, 또는 RHEL로 이전해야 한다.

**Ubuntu LTS 커널 옵션이 복잡하다.** 22.04의 GA 커널은 5.15이고 HWE 커널은 더 최신이다. `apt install linux-image-generic-hwe-22.04`가 HWE 트랙을 제공한다. 커널 관리를 자동화한다면 어느 트랙을 고정할지 명시적으로 지정하라.

**컨테이너에서 Alpine의 DNS 동작이 glibc 배포판과 다르다.** `musl` 리졸버는 `search` 도메인을 같은 방식으로 처리하지 않는다. Kubernetes에서 서비스 디스커버리를 미묘하게 깨뜨린다. Pod DNS 설정에서 `ndots:5`를 사용하고 DNS 해석을 명시적으로 테스트하라.

**RPM과 DEB 패키지는 교환 가능하지 않다.** `alien` 같은 도구가 변환을 수행하지만 단순한 패키지 외에는 신뢰할 수 없는 결과를 만든다. 프로덕션에서 변환된 패키지를 절대 사용하지 마라.

**RHEL 8+은 기본적으로 `yum`이 아닌 `dnf`를 사용한다.** RHEL 8/9에서 `yum`은 하위 호환성을 위해 `dnf`의 심링크이지만, `dnf`는 다른 모듈/스트림 동작을 가진다.

**EOL 날짜는 제안이 아닌 데드라인이다.**

| 배포판 | EOL 날짜 |
|--------|---------|
| CentOS 7 | 2024년 6월 30일 |
| Ubuntu 20.04 LTS | 2025년 4월 (표준) |
| Ubuntu 22.04 LTS | 2027년 4월 (표준) |
| RHEL 8 | 2029년 5월 |
| RHEL 9 | 2032년 5월 |
| AlmaLinux 8 | 2029년 |
| Debian 12 (Bookworm) | ~2028년 |

## 빠른 참조

```text
배포판 결정 트리
─────────────────────────────────────────────────────────
10년 지원 + CVE 백포팅 필요?         → RHEL 또는 AlmaLinux/Rocky
프로덕션 서버, 비용 절감?            → AlmaLinux 또는 Rocky Linux
클라우드 네이티브 / Kubernetes?      → Ubuntu LTS 또는 Amazon Linux 2023
컨테이너 베이스 이미지 (크기 중요)?  → Alpine (glibc 의존성 없을 때)
컨테이너 베이스 이미지 (호환성)?     → debian:slim 또는 ubuntu:focal
개발자 워크스테이션 (최신 도구)?     → Ubuntu (중간 릴리스) 또는 Fedora
침투 테스트 워크스테이션?            → Kali Linux
Linux 내부 깊게 학습?               → Arch Linux
엣지 / IoT / 임베디드?              → Alpine 또는 Yocto 기반
```

```bash
# 모든 시스템에서 배포판 식별
cat /etc/os-release
lsb_release -a          # lsb-release 설치된 경우
uname -r                # 커널 버전
```

```bash
# 계열별 설치된 패키지 확인
rpm -qa --queryformat '%{NAME}-%{VERSION}\n' | sort  # RPM
dpkg-query -W -f='${Package} ${Version}\n' | sort    # DEB
```
