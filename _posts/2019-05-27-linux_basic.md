---
title: Linux Fundamentals for Engineers
key: page-linux_basic
categories:
- Engineering
- SysOps & Infrastructure
author: hyoeun
math: false
mathjax_autoNumber: false
image: "/assets/thumbnails/2019-05-27-linux_basic.png"
bilingual: true
date: 2019-05-27 09:00:00
---

## Why the Linux Mental Model Matters More Than Commands

Memorizing Linux commands is the wrong goal. What separates engineers who get lost when something breaks from those who methodically diagnose any issue is a mental model: a framework for how Linux works that lets you reason about unfamiliar situations. The core insight — "everything is a file" — isn't a metaphor. It's a literal design principle that explains why you can read CPU stats from `/proc/cpuinfo`, configure network interfaces by writing to `/sys/class/net/`, and intercept process I/O by manipulating file descriptors. Once you have the model, the commands become obvious.

## Core Concept: The Linux Mental Model

### Everything Is a File

In Linux, almost everything is represented as a file in the filesystem:
- Regular files and directories — obvious
- Devices: `/dev/sda` (block device), `/dev/null`, `/dev/random`
- Process information: `/proc/PID/` (maps, fd, status, cmdline)
- Kernel tunables: `/proc/sys/`, `/sys/`
- Sockets and pipes: appear as file descriptors in `/proc/PID/fd/`
- Network interfaces: configurable via `/sys/class/net/`

This means every Unix tool that reads and writes files can interact with hardware, processes, and the kernel. `cat /proc/1/maps` shows the memory map of PID 1. `echo 1 > /proc/sys/net/ipv4/ip_forward` enables IP forwarding. This composability is the design's genius.

### Process Hierarchy

Every process except PID 1 has a parent. PID 1 is `systemd` (or `init` on older systems) — the ancestor of all processes. When a parent exits before its children, those orphaned children are re-parented to PID 1.

```text
PID 1: systemd
  ├── PID 234: sshd
  │     └── PID 891: sshd (session)
  │           └── PID 892: bash
  │                 └── PID 1023: vim
  ├── PID 567: nginx (master)
  │     ├── PID 568: nginx (worker)
  │     └── PID 569: nginx (worker)
  └── PID 789: cron
```

Understanding this tree matters for:
- **Signal propagation**: `kill -9 PID` only kills that process; `kill -9 -PGID` kills a process group
- **Resource inheritance**: file descriptors, environment variables, ulimits are inherited from parent
- **Zombie processes**: a process that has exited but whose parent hasn't called `wait()` to collect its exit status

### Filesystem Hierarchy Standard (FHS)

```text
/          Root filesystem — everything starts here
/bin       Essential user binaries (ls, cp, bash) — symlinked to /usr/bin on modern distros
/sbin      System binaries for root use — often symlinked to /usr/sbin
/etc       Configuration files (text, editable)
/home      User home directories
/root      Root user's home
/var       Variable data: logs (/var/log), spool (/var/spool), run (/var/run)
/tmp       Temporary files — cleared on reboot (usually)
/usr       Unix System Resources: /usr/bin, /usr/lib, /usr/share
/opt       Optional third-party software
/proc      Virtual filesystem: process and kernel state (in-memory, not on disk)
/sys       Virtual filesystem: device and kernel subsystem state
/dev       Device files
/mnt       Temporary mount points
/media     Removable media mount points
/lib       Shared libraries for /bin and /sbin
/boot      Kernel images, bootloader config
```

The key insight: `/proc` and `/sys` are not on disk. They're generated dynamically by the kernel. Writing to `/proc/sys/vm/drop_caches` drops page caches. It's I/O to the kernel.

## How It Works: Permissions, Users, and Process Management

### Unix Permissions Model

Every file has three permission sets — owner, group, others — each with read/write/execute bits.

```bash
ls -la /etc/passwd
-rw-r--r-- 1 root root 2847 Jan 10 09:00 /etc/passwd
# Mode     links owner group  size  date          filename
```

**Reading the mode string:**
```text
- rw- r-- r--
│ │   │   └── others: read only
│ │   └────── group: read only
│ └────────── owner: read + write
└──────────── file type: - = regular, d = directory, l = symlink, b = block, c = char
```

**Octal representation:**
```text
r = 4, w = 2, x = 1
rwxr-xr-x = 755
rw-r--r-- = 644
rwx------ = 700
```

```bash
chmod 755 /usr/local/bin/myscript  # rwxr-xr-x
chmod 640 /etc/myapp/config        # rw-r-----
chmod +x script.sh                  # add execute for all
chmod u+x,g-w file                  # symbolic mode
chown user:group file
chown -R www-data:www-data /var/www
```

### Special Permission Bits

These are where security vulnerabilities live if misconfigured.

**setuid (SUID)** — bit 4: When set on an executable, the process runs as the file's owner, not the calling user. `passwd` uses this to write to `/etc/shadow` as root. Dangerous on scripts and custom binaries.

```bash
ls -la /usr/bin/passwd
-rwsr-xr-x 1 root root 68208 /usr/bin/passwd
# 's' in owner execute position = setuid

# Find all setuid binaries on a system (security audit)
find / -perm /4000 -type f 2>/dev/null
```

**setgid (SGID)** — bit 2: On executables, same as setuid but with group. On directories, new files inherit the directory's group rather than the creator's group. Used for shared work directories.

**sticky bit** — bit 1: On directories, prevents users from deleting files they don't own. Classic use: `/tmp` has `1777` — everyone can create files, but only the owner can delete their own.

```bash
ls -la /tmp
drwxrwxrwt 10 root root 4096 Jan 10 /tmp
# 't' in others execute position = sticky bit
```

### Users and Groups

```bash
# User management
useradd -m -s /bin/bash -G sudo,docker username
passwd username
usermod -aG docker existing_user       # add to group (need re-login)
userdel -r username                    # -r removes home dir

# Key files
# /etc/passwd   - user accounts: username:x:UID:GID:comment:home:shell
# /etc/shadow   - password hashes (root-only)
# /etc/group    - group definitions

# Check current identity
id
whoami
groups
```

**Understanding UID/GID:**
- UID 0 = root — special kernel treatment, bypasses most permission checks
- UIDs 1-999 = system accounts (services)
- UIDs 1000+ = regular users
- `sudo` doesn't make you root permanently — it executes specific commands as root via `setuid` on the `sudo` binary

### Process Management

```bash
# Listing processes
ps aux                  # all processes, user-oriented format
ps -ef                  # all processes, full format
ps -eo pid,ppid,user,cmd,%cpu,%mem  # custom columns

# Real-time
top
htop                    # better UI if installed

# Process tree
pstree -p               # show PIDs in tree format

# Find by name
pgrep nginx
pidof nginx

# Background/foreground
# command &             - run in background
jobs                    # list background jobs
fg %1                   # bring job 1 to foreground
bg %1                   # push stopped job to background
# Ctrl+Z               - suspend foreground process
```

### Signals

Signals are the Linux IPC mechanism for process control. Understanding them prevents data loss and helps with graceful shutdowns.

```bash
kill -l                 # list all signals

# Common signals
kill -1  PID            # SIGHUP  (1): reload config
kill -2  PID            # SIGINT  (2): interrupt (same as Ctrl+C)
kill -9  PID            # SIGKILL (9): immediate termination, unblockable
kill -15 PID            # SIGTERM (15): graceful termination request (default)
kill -18 PID            # SIGCONT (18): resume stopped process
kill -19 PID            # SIGSTOP (19): pause process, unblockable

# Kill by name
pkill -SIGTERM nginx
pkill -9 zombie_process

# Kill process group
kill -15 -PGID
```

The critical distinction: **SIGTERM** is a request — the process can catch it, clean up, and exit gracefully. **SIGKILL** is delivered by the kernel directly — the process cannot intercept it. Always try SIGTERM first and give the process 5-30 seconds before SIGKILL.

## Practical Application: Real Troubleshooting Scenarios

### Scenario: Service Won't Start

```bash
# Step 1: Check systemd status and recent logs
systemctl status myapp
journalctl -u myapp -n 50 --no-pager

# Step 2: Check if port is already in use
ss -tlnp | grep :8080
lsof -i :8080

# Step 3: Check file permissions
ls -la /etc/myapp/
ls -la /var/log/myapp/
stat /usr/local/bin/myapp

# Step 4: Try running manually as the service user
sudo -u myapp /usr/local/bin/myapp --config /etc/myapp/config.yaml
```

### Scenario: Disk Space Exhausted

```bash
df -h                                   # overall disk usage
df -hi                                  # inode usage (different problem!)
du -sh /var/log/*  | sort -rh           # find log directory sizes
du -sh /home/*     | sort -rh           # user home dirs
find /var/log -name "*.log" -size +100M # find large log files
lsof | grep deleted                     # files deleted but still open (common gotcha)
```

### Package Management Across Distros

```bash
# Installing a package
apt install nginx          # Debian/Ubuntu
dnf install nginx          # RHEL/CentOS/AlmaLinux
apk add nginx              # Alpine
pacman -S nginx            # Arch

# Checking what package owns a file
dpkg -S /usr/bin/python3   # Debian
rpm -qf /usr/bin/python3   # RPM
```

## Gotchas: What Experts Know

**`rm -rf` on a path that expands unexpectedly is catastrophic.** Always quote paths. `rm -rf $DIR/` where `DIR` is empty becomes `rm -rf /`. Use `set -u` in scripts to catch unset variables.

**File permissions don't protect open file descriptors.** If a process has a file open, you can still read/write via `/proc/PID/fd/FD` even if you change the file's permissions or delete it. Deleted files remain allocated until all FDs to them are closed — this is why `lsof | grep deleted` finds disk space "leaks."

**`sudo` without specifying a command grants root shell in many configs.** `sudo -i` or `sudo su -` are common privilege escalation paths. Check `/etc/sudoers` carefully — `NOPASSWD` entries are particularly risky.

**The sticky bit on `/tmp` doesn't prevent symlink attacks.** A privileged process following a symlink from `/tmp` to a system file is still a classic vulnerability class. Use `mktemp` for temp files, not `touch /tmp/myscript.$$`.

**`/proc/sys/` changes are not persistent across reboots.** Writing to `/proc/sys/net/ipv4/ip_forward` takes effect immediately but reverts on reboot. For persistence, use `/etc/sysctl.d/99-custom.conf` with `sysctl -p`.

**Process UID vs EUID vs SUID.** A process has up to three user IDs: real UID (who ran it), effective UID (what permissions are used), and saved UID (what EUID can be restored to). `setuid` binaries switch EUID to the file owner but keep RUID as the calling user. `getuid()` vs `geteuid()` is a common source of privilege escalation bugs in suid programs.

## Quick Reference

```bash
# Permissions
chmod 755 file        # rwxr-xr-x
chmod 644 file        # rw-r--r--
chmod 600 file        # rw------- (private key files)
chmod +x file         # add execute
chown user:group file
find / -perm /4000    # find suid files

# Users
id                    # current user info
who                   # logged-in users
last                  # login history
passwd user           # change password
usermod -aG group user # add user to group

# Processes
ps aux | grep name
kill -15 PID          # graceful stop
kill -9 PID           # force kill
pgrep -a name         # find PID by name
nice -n 10 command    # run at lower priority
renice -n 5 -p PID    # change running process priority

# Filesystem
df -h                 # disk free
du -sh /path          # directory size
lsof -p PID           # open files for process
lsof -i :PORT         # process on port
stat file             # detailed file metadata
```

```text
PERMISSION OCTAL CHEATSHEET
4 = read    2 = write    1 = execute
7 = rwx     6 = rw-      5 = r-x
4 = r--     0 = ---

Common modes:
755 = rwxr-xr-x  (executables, directories)
644 = rw-r--r--  (config files, web files)
600 = rw-------  (private keys, sensitive configs)
700 = rwx------  (private directories)
1777 = rwxrwxrwt (shared directories like /tmp)
4755 = rwsr-xr-x (setuid executables)
```

---

## 왜 명령어보다 Linux 정신 모델이 더 중요한가

Linux 명령어를 외우는 것은 잘못된 목표다. 문제가 발생했을 때 길을 잃는 엔지니어와 어떤 상황도 체계적으로 진단하는 엔지니어를 구분하는 것은 정신 모델이다. "모든 것은 파일이다"라는 핵심 통찰은 은유가 아니다. `/proc/cpuinfo`에서 CPU 통계를 읽고, `/sys/class/net/`에 쓰기로 네트워크 인터페이스를 구성하고, 파일 디스크립터를 조작하여 프로세스 I/O를 가로챌 수 있는 이유를 설명하는 실제 설계 원칙이다. 모델을 이해하면 명령어는 자연스럽게 따라온다.

## 핵심 개념: Linux 정신 모델

### 모든 것은 파일이다

Linux에서 거의 모든 것이 파일시스템의 파일로 표현된다:
- 일반 파일과 디렉토리 — 당연한 것
- 장치: `/dev/sda` (블록 장치), `/dev/null`, `/dev/random`
- 프로세스 정보: `/proc/PID/` (maps, fd, status, cmdline)
- 커널 튜너블: `/proc/sys/`, `/sys/`
- 소켓과 파이프: `/proc/PID/fd/`의 파일 디스크립터로 나타남
- 네트워크 인터페이스: `/sys/class/net/`으로 구성 가능

이는 파일을 읽고 쓰는 모든 Unix 도구가 하드웨어, 프로세스, 커널과 상호작용할 수 있다는 의미다. `cat /proc/1/maps`는 PID 1의 메모리 맵을 보여준다. `echo 1 > /proc/sys/net/ipv4/ip_forward`는 IP 포워딩을 활성화한다. 이 조합 가능성이 설계의 천재성이다.

### 프로세스 계층구조

PID 1을 제외한 모든 프로세스는 부모를 가진다. PID 1은 `systemd`(또는 오래된 시스템에서 `init`) — 모든 프로세스의 조상이다. 부모가 자식보다 먼저 종료되면 고아가 된 자식들은 PID 1에 재부모화된다.

```text
PID 1: systemd
  ├── PID 234: sshd
  │     └── PID 891: sshd (세션)
  │           └── PID 892: bash
  │                 └── PID 1023: vim
  ├── PID 567: nginx (마스터)
  │     ├── PID 568: nginx (워커)
  │     └── PID 569: nginx (워커)
  └── PID 789: cron
```

이 트리를 이해하는 것이 중요한 이유:
- **시그널 전파**: `kill -9 PID`는 그 프로세스만 종료; `kill -9 -PGID`는 프로세스 그룹 종료
- **리소스 상속**: 파일 디스크립터, 환경 변수, ulimit은 부모로부터 상속됨
- **좀비 프로세스**: 종료했지만 부모가 `wait()`로 종료 상태를 수집하지 않은 프로세스

### 파일시스템 계층 표준 (FHS)

```text
/          루트 파일시스템
/bin       필수 사용자 바이너리 (현대 배포판에서 /usr/bin으로 심링크)
/etc       구성 파일 (텍스트, 편집 가능)
/home      사용자 홈 디렉토리
/var       가변 데이터: 로그, 스풀, 런
/tmp       임시 파일 (보통 재부팅 시 삭제)
/usr       Unix 시스템 리소스: /usr/bin, /usr/lib, /usr/share
/proc      가상 파일시스템: 프로세스 및 커널 상태 (메모리 내)
/sys       가상 파일시스템: 장치 및 커널 서브시스템 상태
/dev       장치 파일
/boot      커널 이미지, 부트로더 설정
```

핵심 통찰: `/proc`과 `/sys`는 디스크에 없다. 커널이 동적으로 생성한다. `/proc/sys/vm/drop_caches`에 쓰기는 페이지 캐시를 버린다. 커널에 대한 I/O다.

## 동작 원리: 권한, 사용자, 프로세스 관리

### Unix 권한 모델

모든 파일은 세 가지 권한 집합을 가진다 — 소유자, 그룹, 기타 — 각각 읽기/쓰기/실행 비트.

```bash
ls -la /etc/passwd
-rw-r--r-- 1 root root 2847 Jan 10 09:00 /etc/passwd
```

**모드 문자열 읽기:**
```text
- rw- r-- r--
│ │   │   └── 기타: 읽기 전용
│ │   └────── 그룹: 읽기 전용
│ └────────── 소유자: 읽기 + 쓰기
└──────────── 파일 유형: - = 일반, d = 디렉토리, l = 심링크
```

**8진수 표현:**
```text
r = 4, w = 2, x = 1
rwxr-xr-x = 755
rw-r--r-- = 644
rwx------ = 700
```

```bash
chmod 755 /usr/local/bin/myscript
chmod 640 /etc/myapp/config
chmod +x script.sh
chown user:group file
chown -R www-data:www-data /var/www
```

### 특수 권한 비트

잘못 구성될 경우 보안 취약점이 생기는 곳이다.

**setuid (SUID)** — 비트 4: 실행 파일에 설정되면 프로세스는 호출한 사용자가 아닌 파일 소유자로 실행된다. `passwd`는 이를 사용해 root로 `/etc/shadow`에 쓴다.

```bash
ls -la /usr/bin/passwd
-rwsr-xr-x 1 root root 68208 /usr/bin/passwd
# 소유자 실행 위치의 's' = setuid

# 시스템의 모든 setuid 바이너리 찾기 (보안 감사)
find / -perm /4000 -type f 2>/dev/null
```

**setgid (SGID)** — 비트 2: 디렉토리에서 새 파일이 생성자의 그룹 대신 디렉토리의 그룹을 상속한다.

**스티키 비트** — 비트 1: 디렉토리에서 사용자가 자신이 소유하지 않은 파일을 삭제하지 못하게 한다. `/tmp`에서 사용된다.

```bash
ls -la /tmp
drwxrwxrwt 10 root root 4096 Jan 10 /tmp
# 기타 실행 위치의 't' = 스티키 비트
```

### 사용자와 그룹

```bash
# 사용자 관리
useradd -m -s /bin/bash -G sudo,docker username
passwd username
usermod -aG docker existing_user       # 그룹 추가 (재로그인 필요)
userdel -r username                    # -r은 홈 디렉토리도 삭제

# 현재 신원 확인
id
whoami
groups
```

**UID/GID 이해:**
- UID 0 = root — 대부분의 권한 검사 우회
- UID 1-999 = 시스템 계정 (서비스)
- UID 1000+ = 일반 사용자

### 프로세스 관리

```bash
ps aux                  # 모든 프로세스, 사용자 중심 형식
ps -ef                  # 모든 프로세스, 전체 형식
ps -eo pid,ppid,user,cmd,%cpu,%mem  # 커스텀 컬럼

top
htop                    # 설치된 경우 더 나은 UI

pstree -p               # PID가 포함된 트리 형식

pgrep nginx
pidof nginx
```

### 시그널

시그널은 프로세스 제어를 위한 Linux IPC 메커니즘이다.

```bash
kill -l                 # 모든 시그널 목록

kill -1  PID            # SIGHUP  (1): 설정 재로드
kill -2  PID            # SIGINT  (2): 인터럽트 (Ctrl+C와 동일)
kill -9  PID            # SIGKILL (9): 즉시 종료, 차단 불가
kill -15 PID            # SIGTERM (15): 정상 종료 요청 (기본값)

pkill -SIGTERM nginx
pkill -9 zombie_process
```

핵심 구분: **SIGTERM**은 요청이다 — 프로세스가 정리하고 정상 종료할 수 있다. **SIGKILL**은 커널이 직접 전달한다 — 프로세스가 가로챌 수 없다. 항상 SIGTERM을 먼저 시도하고 SIGKILL 전에 5-30초를 기다려라.

## 실전 적용: 실제 문제 해결 시나리오

### 시나리오: 서비스가 시작되지 않는 경우

```bash
systemctl status myapp
journalctl -u myapp -n 50 --no-pager

ss -tlnp | grep :8080
lsof -i :8080

ls -la /etc/myapp/
stat /usr/local/bin/myapp

sudo -u myapp /usr/local/bin/myapp --config /etc/myapp/config.yaml
```

### 시나리오: 디스크 공간 소진

```bash
df -h                                   # 전체 디스크 사용량
df -hi                                  # 아이노드 사용량 (다른 문제!)
du -sh /var/log/*  | sort -rh           # 로그 디렉토리 크기
find /var/log -name "*.log" -size +100M # 대용량 로그 파일
lsof | grep deleted                     # 삭제되었지만 열려 있는 파일
```

### 배포판 간 패키지 관리

```bash
apt install nginx          # Debian/Ubuntu
dnf install nginx          # RHEL/CentOS/AlmaLinux
apk add nginx              # Alpine
pacman -S nginx            # Arch

dpkg -S /usr/bin/python3   # 파일 소유 패키지 확인 (Debian)
rpm -qf /usr/bin/python3   # 파일 소유 패키지 확인 (RPM)
```

## 함정: 전문가들이 아는 것

**예상치 못하게 확장되는 경로에서 `rm -rf`는 치명적이다.** 항상 경로를 따옴표로 감싸라. `DIR`이 비어 있을 때 `rm -rf $DIR/`는 `rm -rf /`가 된다. 스크립트에서 `set -u`를 사용해 설정되지 않은 변수를 잡아라.

**파일 권한은 열린 파일 디스크립터를 보호하지 않는다.** 프로세스가 파일을 열고 있다면, 파일 권한을 변경하거나 삭제해도 `/proc/PID/fd/FD`를 통해 읽고 쓸 수 있다. 삭제된 파일은 모든 FD가 닫힐 때까지 할당 상태를 유지한다 — `lsof | grep deleted`가 디스크 공간 "누수"를 찾는 이유다.

**`/etc/sudoers`의 `NOPASSWD` 항목은 특히 위험하다.** `sudo -i` 또는 `sudo su -`는 일반적인 권한 상승 경로다. sudoers 파일을 항상 신중하게 검토하라.

**`/tmp`의 스티키 비트는 심링크 공격을 방지하지 않는다.** 권한 있는 프로세스가 `/tmp`에서 시스템 파일로의 심링크를 따르는 것은 여전히 고전적인 취약점이다. 임시 파일에는 `mktemp`를 사용하라.

**`/proc/sys/` 변경은 재부팅 시 유지되지 않는다.** 지속을 위해서는 `sysctl -p`와 함께 `/etc/sysctl.d/99-custom.conf`를 사용하라.

**프로세스 UID vs EUID vs SUID.** 프로세스는 최대 세 개의 사용자 ID를 가진다: 실제 UID, 유효 UID, 저장된 UID. `setuid` 바이너리는 EUID를 파일 소유자로 전환하지만 RUID는 호출 사용자로 유지한다. `getuid()` vs `geteuid()`는 suid 프로그램에서 권한 상승 버그의 일반적인 원인이다.

## 빠른 참조

```bash
# 권한
chmod 755 file        # rwxr-xr-x
chmod 644 file        # rw-r--r--
chmod 600 file        # rw------- (개인 키 파일)
chmod +x file         # 실행 추가
chown user:group file
find / -perm /4000    # setuid 파일 찾기

# 사용자
id                    # 현재 사용자 정보
who                   # 로그인한 사용자
last                  # 로그인 기록
usermod -aG group user # 사용자를 그룹에 추가

# 프로세스
ps aux | grep name
kill -15 PID          # 정상 종료
kill -9 PID           # 강제 종료
pgrep -a name         # 이름으로 PID 찾기
nice -n 10 command    # 낮은 우선순위로 실행
renice -n 5 -p PID    # 실행 중인 프로세스 우선순위 변경

# 파일시스템
df -h                 # 디스크 여유 공간
du -sh /path          # 디렉토리 크기
lsof -p PID           # 프로세스의 열린 파일
lsof -i :PORT         # 포트를 사용 중인 프로세스
stat file             # 상세 파일 메타데이터
```

```text
권한 8진수 치트시트
4 = 읽기    2 = 쓰기    1 = 실행
7 = rwx     6 = rw-     5 = r-x
4 = r--     0 = ---

일반적인 모드:
755 = rwxr-xr-x  (실행 파일, 디렉토리)
644 = rw-r--r--  (구성 파일, 웹 파일)
600 = rw-------  (개인 키, 민감한 설정)
700 = rwx------  (개인 디렉토리)
1777 = rwxrwxrwt (공유 디렉토리, /tmp)
4755 = rwsr-xr-x (setuid 실행 파일)
```
