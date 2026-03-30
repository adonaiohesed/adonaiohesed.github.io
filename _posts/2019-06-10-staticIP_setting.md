---
title: Configuring Static IP on Linux Servers
key: page-staticIP_setting
categories:
- Engineering
- SysOps & Infrastructure
author: hyoeun
math: false
mathjax_autoNumber: false
image: "/assets/thumbnails/2019-06-10-staticIP_setting.png"
bilingual: true
date: 2019-06-10 09:00:00
---

## Why Static IP Configuration Is Still a Skill You Need

Cloud infrastructure does most of this automatically, but the moment you're provisioning bare-metal servers, configuring network appliances, setting up VMs with specific IP requirements, or debugging a host that lost connectivity after an update, you need to understand Linux network configuration at the file level. The tooling has fragmented: RHEL/CentOS uses `nmcli` and `ifcfg` files, Ubuntu 18+ uses Netplan, and containers use their own overlay networking. The abstraction layers don't always agree. Knowing what's underneath each layer is what gets you unstuck.

## Core Concept: Linux Network Configuration Layers

Linux network configuration has multiple layers, and the confusion usually comes from not knowing which layer is authoritative.

### The Three Configuration Systems

**NetworkManager** — the dominant approach on desktop and server distros that prioritize ease of use (RHEL 7+, Ubuntu 20.04+, Fedora). NetworkManager manages connections via a daemon and stores configuration in `/etc/NetworkManager/system-connections/`. It can read legacy `ifcfg` files. Tools: `nmcli`, `nmtui`.

**systemd-networkd** — a lightweight network manager that's part of systemd. Preferred for servers, containers, and minimal installs where you don't want the NetworkManager overhead. Configuration: `/etc/systemd/network/*.network` files.

**Netplan** — Ubuntu 17.10+ abstraction layer that generates configuration for either NetworkManager or systemd-networkd backends. Configuration: `/etc/netplan/*.yaml`. This is now Ubuntu's canonical interface.

**Legacy ifcfg/interfaces files** — older static configuration files still found on RHEL 6, CentOS 6-7, and Debian systems:
- RHEL/CentOS: `/etc/sysconfig/network-scripts/ifcfg-<interface>`
- Debian/Ubuntu (pre-17.10): `/etc/network/interfaces`

The critical operational point: **if NetworkManager is running, it owns the network configuration.** Editing `ifcfg` files or `networkd` configs while NetworkManager is active may have no effect until NM is told to reload or is disabled. Know which system is in charge.

### Interface Naming

Older kernel uses `eth0`, `eth1`. Modern systems use predictable interface names from `udev`:
- `enpXsY` — PCIe bus (e.g., `enp3s0`)
- `ensX` — hotplug slot
- `enoX` — onboard
- `ethX` — older or VM interfaces

```bash
ip link show                    # list all interfaces
ip addr show                    # list with addresses
nmcli device status             # NetworkManager device list
```

## How It Works: Configuration Deep Dive

### RHEL/CentOS/AlmaLinux with NetworkManager

`nmcli` is the primary interface. It's verbose but scriptable and idempotent.

```bash
# Show connections
nmcli connection show
nmcli device status

# Create a static IP connection
nmcli connection add \
  type ethernet \
  con-name "eth-static" \
  ifname enp3s0 \
  ipv4.method manual \
  ipv4.addresses 192.168.1.100/24 \
  ipv4.gateway 192.168.1.1 \
  ipv4.dns "8.8.8.8,8.8.4.4" \
  ipv4.dns-search "example.com" \
  connection.autoconnect yes

# Activate the connection
nmcli connection up eth-static

# Modify an existing connection
nmcli connection modify eth-static ipv4.addresses 192.168.1.101/24
nmcli connection reload
nmcli connection up eth-static
```

**The equivalent ifcfg file** (written by nmcli, readable/editable directly):

```bash
# /etc/sysconfig/network-scripts/ifcfg-enp3s0
TYPE=Ethernet
BOOTPROTO=none
NAME=enp3s0
DEVICE=enp3s0
ONBOOT=yes
IPADDR=192.168.1.100
PREFIX=24
GATEWAY=192.168.1.1
DNS1=8.8.8.8
DNS2=8.8.4.4
DOMAIN=example.com
```

After editing ifcfg files directly:
```bash
nmcli connection reload
nmcli connection up enp3s0
# or
systemctl restart NetworkManager
```

### Ubuntu/Debian with Netplan

Netplan files are YAML and live in `/etc/netplan/`. The filename convention is `XX-<name>.yaml` where lower numbers have lower priority.

```yaml
# /etc/netplan/01-static-config.yaml
network:
  version: 2
  renderer: networkd          # or 'NetworkManager'
  ethernets:
    enp3s0:
      dhcp4: false
      addresses:
        - 192.168.1.100/24
      routes:
        - to: default
          via: 192.168.1.1
      nameservers:
        addresses:
          - 8.8.8.8
          - 8.8.4.4
        search:
          - example.com
```

```bash
# Validate before applying (dry run)
netplan try                     # applies for 120s, reverts if not confirmed

# Apply permanently
netplan apply

# Debug
netplan generate --debug
```

### systemd-networkd (Minimal/Server)

```ini
# /etc/systemd/network/10-static.network
[Match]
Name=enp3s0

[Network]
Address=192.168.1.100/24
Gateway=192.168.1.1
DNS=8.8.8.8
DNS=8.8.4.4
Domains=example.com
```

```bash
systemctl enable --now systemd-networkd
systemctl enable --now systemd-resolved   # DNS resolver
networkctl status                         # show network status
networkctl list                           # list managed interfaces
```

### DNS Configuration

DNS configuration has its own layer of confusion:

```bash
# Modern systems (systemd-resolved)
resolvectl status
resolvectl query example.com

# /etc/resolv.conf — may be a symlink to systemd-resolved stub
ls -la /etc/resolv.conf
# → /run/systemd/resolve/stub-resolv.conf  (systemd-resolved managed)
# → /run/NetworkManager/resolv.conf        (NM managed)
# → a real file                            (static, override)

# Static DNS override (when not using systemd-resolved)
cat /etc/resolv.conf
nameserver 8.8.8.8
nameserver 8.8.4.4
search example.com
```

**Warning**: Many packages overwrite `/etc/resolv.conf` on startup. If you need persistent DNS settings, configure them through NetworkManager or Netplan, not by editing `/etc/resolv.conf` directly.

## Practical Application: Common Server Scenarios

### Scenario: RHEL 9 Production Server Static IP

```bash
# Identify the interface name
ip link show

# Set static IP with nmcli
nmcli connection modify "Wired connection 1" \
  ipv4.method manual \
  ipv4.addresses "10.0.1.50/24" \
  ipv4.gateway "10.0.1.1" \
  ipv4.dns "10.0.1.10,10.0.1.11" \
  ipv4.dns-search "internal.corp" \
  connection.autoconnect yes

nmcli connection up "Wired connection 1"

# Verify
ip addr show
ip route show
ping -c 3 10.0.1.1
ping -c 3 8.8.8.8
nslookup internal.corp
```

### Scenario: Ubuntu 22.04 Server Static IP

```bash
# List current netplan configs
ls /etc/netplan/

# Backup existing config
cp /etc/netplan/00-installer-config.yaml /etc/netplan/00-installer-config.yaml.bak
```

```yaml
# /etc/netplan/00-installer-config.yaml
network:
  version: 2
  ethernets:
    ens3:
      dhcp4: false
      addresses:
        - 10.0.1.50/24
      routes:
        - to: default
          via: 10.0.1.1
          metric: 100
      nameservers:
        addresses:
          - 10.0.1.10
          - 8.8.8.8
        search:
          - internal.corp
```

```bash
netplan try
# Confirm within 120 seconds
netplan apply
```

### Scenario: Multiple IPs on One Interface (IP Aliasing)

Useful for hosting multiple services or SSL certs on one server.

```bash
# nmcli approach
nmcli connection modify eth-static \
  +ipv4.addresses "192.168.1.101/24"

# Netplan approach — add to addresses list
# addresses:
#   - 192.168.1.100/24
#   - 192.168.1.101/24

# Verify
ip addr show enp3s0
```

### Verification Checklist

```bash
# 1. Interface has correct IP
ip addr show dev enp3s0

# 2. Default route is set
ip route show
# Should see: default via 192.168.1.1 dev enp3s0

# 3. DNS resolves
nslookup google.com
dig @8.8.8.8 google.com   # test specific DNS server

# 4. Ping gateway
ping -c 3 192.168.1.1

# 5. Ping external
ping -c 3 8.8.8.8

# 6. Check config survives reboot
systemctl reboot
# verify after reboot
```

## Gotchas: What Experts Know

**`netplan try` is your safest friend.** It applies the config for 120 seconds and automatically reverts if you don't confirm. Always use it over `netplan apply` when working on remote systems — a bad Netplan config without `try` can lock you out.

**NetworkManager and systemd-networkd conflict if both are active.** On Ubuntu, if you set `renderer: networkd` in Netplan but NetworkManager is also enabled and watching the interface, you'll get unpredictable results. Check what's managing your interface: `nmcli device status` — "unmanaged" means networkd is in charge.

**`/etc/resolv.conf` is frequently overwritten.** On systems with NetworkManager, `dhclient`, or `systemd-resolved`, manually editing `/etc/resolv.conf` is pointless — it gets overwritten on next DHCP renewal or network restart. Configure DNS through the network manager, not the file.

**RHEL 8/9 deprecated ifcfg files.** RHEL 9 removed support for ifcfg files entirely in favor of keyfiles in `/etc/NetworkManager/system-connections/`. If you're migrating scripts from CentOS 7 that edit ifcfg files, they need updating.

**Metric matters with multiple interfaces.** When a server has two NICs, the routing table may have two default routes with different metrics. Lower metric = higher priority. Misconfigured metrics cause asymmetric routing.

```bash
ip route show
# default via 10.0.1.1 dev eth0 proto static metric 100
# default via 192.168.1.1 dev eth1 proto static metric 200
# Traffic uses eth0; if eth0 goes down, falls back to eth1
```

**MTU mismatches cause mysterious packet loss.** If large packets work but small ones don't (or vice versa), check MTU:

```bash
ip link show enp3s0 | grep mtu
# Change MTU
ip link set enp3s0 mtu 1500
# Persistent via nmcli:
nmcli connection modify eth-static ethernet.mtu 1500
```

## Quick Reference

```bash
# Show current network state
ip addr show                    # IP addresses on all interfaces
ip route show                   # routing table
ip link show                    # link state
ss -tlnp                        # listening TCP ports
nmcli connection show           # NM connections
networkctl status               # systemd-networkd status

# Apply changes
nmcli connection reload         # NM: reload from files
nmcli connection up <name>      # activate connection
netplan apply                   # Ubuntu: apply netplan config
netplan try                     # Ubuntu: test with auto-revert
systemctl restart systemd-networkd  # restart networkd

# DNS debugging
resolvectl status               # current DNS config
resolvectl query example.com    # DNS lookup via resolved
dig example.com                 # DNS lookup
cat /etc/resolv.conf            # check resolver config
```

```text
CONFIGURATION FILE LOCATIONS BY DISTRO
────────────────────────────────────────────────────────────
RHEL 8 / AlmaLinux / Rocky:
  /etc/NetworkManager/system-connections/<name>.nmconnection
  (legacy: /etc/sysconfig/network-scripts/ifcfg-<iface>)

RHEL 7 / CentOS 7:
  /etc/sysconfig/network-scripts/ifcfg-<interface>

Ubuntu 18.04+:
  /etc/netplan/*.yaml

Debian (non-Ubuntu):
  /etc/network/interfaces

systemd-networkd (any distro):
  /etc/systemd/network/*.network
```

---

## 왜 고정 IP 설정은 여전히 필요한 기술인가

클라우드 인프라가 대부분 자동으로 처리하지만, 베어메탈 서버 프로비저닝, 특정 IP 요구사항이 있는 VM 구성, 업데이트 후 연결을 잃은 호스트 디버깅을 할 때는 파일 수준에서 Linux 네트워크 구성을 이해해야 한다. 도구가 분화되어 있다: RHEL/CentOS는 `nmcli`와 `ifcfg` 파일을 사용하고, Ubuntu 18+는 Netplan을 사용하며, 컨테이너는 자체 오버레이 네트워킹을 사용한다. 추상화 계층들이 항상 일치하지 않는다. 각 계층 아래에 무엇이 있는지 아는 것이 막혔을 때 빠져나오게 해준다.

## 핵심 개념: Linux 네트워크 구성 계층

Linux 네트워크 구성은 여러 계층이 있으며, 혼란은 보통 어느 계층이 권위 있는지 모르는 데서 온다.

### 세 가지 구성 시스템

**NetworkManager** — 사용 편의성을 우선시하는 데스크탑과 서버 배포판(RHEL 7+, Ubuntu 20.04+, Fedora)에서 지배적인 접근법. NetworkManager는 데몬을 통해 연결을 관리하고 `/etc/NetworkManager/system-connections/`에 구성을 저장한다. 도구: `nmcli`, `nmtui`.

**systemd-networkd** — systemd의 일부인 경량 네트워크 관리자. NetworkManager 오버헤드가 필요 없는 서버, 컨테이너, 최소 설치에 적합. 구성: `/etc/systemd/network/*.network` 파일.

**Netplan** — NetworkManager 또는 systemd-networkd 백엔드를 위한 구성을 생성하는 Ubuntu 17.10+ 추상화 계층. 구성: `/etc/netplan/*.yaml`. 현재 Ubuntu의 표준 인터페이스.

**레거시 ifcfg/interfaces 파일** — RHEL 6, CentOS 6-7, Debian 시스템에서 여전히 발견되는 오래된 정적 구성 파일:
- RHEL/CentOS: `/etc/sysconfig/network-scripts/ifcfg-<인터페이스>`
- Debian/Ubuntu (17.10 이전): `/etc/network/interfaces`

중요한 운영 포인트: **NetworkManager가 실행 중이면 네트워크 구성을 소유한다.** NetworkManager가 활성화된 상태에서 `ifcfg` 파일이나 `networkd` 구성을 편집해도 NM이 재로드하거나 비활성화될 때까지 효과가 없을 수 있다.

### 인터페이스 명명

오래된 커널은 `eth0`, `eth1`을 사용한다. 현대 시스템은 `udev`의 예측 가능한 인터페이스 이름을 사용한다:
- `enpXsY` — PCIe 버스 (예: `enp3s0`)
- `ensX` — 핫플러그 슬롯
- `enoX` — 온보드
- `ethX` — 오래된 또는 VM 인터페이스

```bash
ip link show                    # 모든 인터페이스 목록
ip addr show                    # 주소와 함께 목록
nmcli device status             # NetworkManager 장치 목록
```

## 동작 원리: 구성 심층 분석

### RHEL/CentOS/AlmaLinux with NetworkManager

`nmcli`가 기본 인터페이스다. 말이 많지만 스크립트 가능하고 멱등성이 있다.

```bash
# 연결 표시
nmcli connection show
nmcli device status

# 고정 IP 연결 생성
nmcli connection add \
  type ethernet \
  con-name "eth-static" \
  ifname enp3s0 \
  ipv4.method manual \
  ipv4.addresses 192.168.1.100/24 \
  ipv4.gateway 192.168.1.1 \
  ipv4.dns "8.8.8.8,8.8.4.4" \
  ipv4.dns-search "example.com" \
  connection.autoconnect yes

# 연결 활성화
nmcli connection up eth-static

# 기존 연결 수정
nmcli connection modify eth-static ipv4.addresses 192.168.1.101/24
nmcli connection reload
nmcli connection up eth-static
```

**동등한 ifcfg 파일** (nmcli가 작성, 직접 편집 가능):

```bash
# /etc/sysconfig/network-scripts/ifcfg-enp3s0
TYPE=Ethernet
BOOTPROTO=none
NAME=enp3s0
DEVICE=enp3s0
ONBOOT=yes
IPADDR=192.168.1.100
PREFIX=24
GATEWAY=192.168.1.1
DNS1=8.8.8.8
DNS2=8.8.4.4
DOMAIN=example.com
```

ifcfg 파일을 직접 편집한 후:
```bash
nmcli connection reload
nmcli connection up enp3s0
```

### Ubuntu/Debian with Netplan

Netplan 파일은 YAML이며 `/etc/netplan/`에 위치한다. 파일명 규칙은 `XX-<이름>.yaml`이고 숫자가 작을수록 우선순위가 낮다.

```yaml
# /etc/netplan/01-static-config.yaml
network:
  version: 2
  renderer: networkd
  ethernets:
    enp3s0:
      dhcp4: false
      addresses:
        - 192.168.1.100/24
      routes:
        - to: default
          via: 192.168.1.1
      nameservers:
        addresses:
          - 8.8.8.8
          - 8.8.4.4
        search:
          - example.com
```

```bash
netplan try                     # 120초 동안 적용, 확인 안 하면 자동 복원
netplan apply                   # 영구 적용
netplan generate --debug        # 디버그
```

### systemd-networkd (최소/서버)

```ini
# /etc/systemd/network/10-static.network
[Match]
Name=enp3s0

[Network]
Address=192.168.1.100/24
Gateway=192.168.1.1
DNS=8.8.8.8
DNS=8.8.4.4
Domains=example.com
```

```bash
systemctl enable --now systemd-networkd
systemctl enable --now systemd-resolved
networkctl status
networkctl list
```

### DNS 구성

```bash
# 현대 시스템 (systemd-resolved)
resolvectl status
resolvectl query example.com

# /etc/resolv.conf — systemd-resolved의 심링크일 수 있음
ls -la /etc/resolv.conf

# 정적 DNS 재정의
cat /etc/resolv.conf
# nameserver 8.8.8.8
# nameserver 8.8.4.4
# search example.com
```

**경고**: 많은 패키지가 시작 시 `/etc/resolv.conf`를 덮어쓴다. 영구 DNS 설정이 필요하면 `/etc/resolv.conf`를 직접 편집하지 말고 NetworkManager나 Netplan을 통해 구성하라.

## 실전 적용: 일반적인 서버 시나리오

### 시나리오: RHEL 9 프로덕션 서버 고정 IP

```bash
# 인터페이스 이름 확인
ip link show

# nmcli로 고정 IP 설정
nmcli connection modify "Wired connection 1" \
  ipv4.method manual \
  ipv4.addresses "10.0.1.50/24" \
  ipv4.gateway "10.0.1.1" \
  ipv4.dns "10.0.1.10,10.0.1.11" \
  ipv4.dns-search "internal.corp" \
  connection.autoconnect yes

nmcli connection up "Wired connection 1"

# 확인
ip addr show
ip route show
ping -c 3 10.0.1.1
ping -c 3 8.8.8.8
nslookup internal.corp
```

### 시나리오: Ubuntu 22.04 서버 고정 IP

```bash
ls /etc/netplan/
cp /etc/netplan/00-installer-config.yaml /etc/netplan/00-installer-config.yaml.bak
```

```yaml
# /etc/netplan/00-installer-config.yaml
network:
  version: 2
  ethernets:
    ens3:
      dhcp4: false
      addresses:
        - 10.0.1.50/24
      routes:
        - to: default
          via: 10.0.1.1
          metric: 100
      nameservers:
        addresses:
          - 10.0.1.10
          - 8.8.8.8
        search:
          - internal.corp
```

```bash
netplan try
netplan apply
```

### 검증 체크리스트

```bash
# 1. 인터페이스에 올바른 IP
ip addr show dev enp3s0

# 2. 기본 경로 설정
ip route show
# default via 192.168.1.1 dev enp3s0 이 보여야 함

# 3. DNS 해석
nslookup google.com
dig @8.8.8.8 google.com

# 4. 게이트웨이 ping
ping -c 3 192.168.1.1

# 5. 외부 ping
ping -c 3 8.8.8.8

# 6. 재부팅 후 구성 유지 확인
systemctl reboot
```

## 함정: 전문가들이 아는 것

**`netplan try`는 가장 안전한 방법이다.** 구성을 120초 동안 적용하고 확인하지 않으면 자동 복원한다. 원격 시스템 작업 시 항상 `netplan apply` 대신 사용하라 — 잘못된 Netplan 구성은 시스템에서 잠길 수 있다.

**NetworkManager와 systemd-networkd가 모두 활성화되면 충돌한다.** Ubuntu에서 Netplan에 `renderer: networkd`를 설정했지만 NetworkManager도 활성화되어 인터페이스를 관리하면 예측 불가한 결과가 나온다. 무엇이 인터페이스를 관리하는지 확인하라: `nmcli device status` — "unmanaged"는 networkd가 담당임을 의미한다.

**`/etc/resolv.conf`는 자주 덮어쓰인다.** NetworkManager, `dhclient`, 또는 `systemd-resolved`가 있는 시스템에서 `/etc/resolv.conf`를 수동으로 편집하는 것은 무의미하다 — 다음 DHCP 갱신이나 네트워크 재시작 시 덮어쓰인다. 파일이 아닌 네트워크 매니저를 통해 DNS를 구성하라.

**RHEL 8/9은 ifcfg 파일을 더 이상 사용하지 않는다.** RHEL 9는 ifcfg 파일 지원을 완전히 제거하고 `/etc/NetworkManager/system-connections/`의 keyfile을 선호한다. CentOS 7에서 ifcfg 파일을 편집하는 스크립트를 마이그레이션하면 업데이트가 필요하다.

**여러 인터페이스에서 메트릭이 중요하다.** 서버에 NIC가 두 개 있을 때 라우팅 테이블에 다른 메트릭의 두 기본 경로가 있을 수 있다. 낮은 메트릭 = 높은 우선순위. 잘못 구성된 메트릭은 비대칭 라우팅을 유발한다.

**MTU 불일치는 신비한 패킷 손실을 유발한다.** 큰 패킷은 작동하지만 작은 것은 안 된다면 MTU를 확인하라:

```bash
ip link show enp3s0 | grep mtu
ip link set enp3s0 mtu 1500
nmcli connection modify eth-static ethernet.mtu 1500
```

## 빠른 참조

```bash
# 현재 네트워크 상태 표시
ip addr show                    # 모든 인터페이스의 IP 주소
ip route show                   # 라우팅 테이블
ip link show                    # 링크 상태
ss -tlnp                        # 수신 중인 TCP 포트
nmcli connection show           # NM 연결
networkctl status               # systemd-networkd 상태

# 변경사항 적용
nmcli connection reload         # NM: 파일에서 재로드
nmcli connection up <name>      # 연결 활성화
netplan apply                   # Ubuntu: netplan 구성 적용
netplan try                     # Ubuntu: 자동 복원으로 테스트
systemctl restart systemd-networkd

# DNS 디버깅
resolvectl status               # 현재 DNS 구성
resolvectl query example.com    # DNS 조회
dig example.com
cat /etc/resolv.conf
```

```text
배포판별 구성 파일 위치
────────────────────────────────────────────────────────────
RHEL 8 / AlmaLinux / Rocky:
  /etc/NetworkManager/system-connections/<name>.nmconnection
  (레거시: /etc/sysconfig/network-scripts/ifcfg-<iface>)

RHEL 7 / CentOS 7:
  /etc/sysconfig/network-scripts/ifcfg-<interface>

Ubuntu 18.04+:
  /etc/netplan/*.yaml

Debian (Ubuntu 아닌):
  /etc/network/interfaces

systemd-networkd (모든 배포판):
  /etc/systemd/network/*.network
```
