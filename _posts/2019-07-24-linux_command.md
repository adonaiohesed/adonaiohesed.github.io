---
title: Essential Linux Commands for Power Users
key: page-linux_command
categories:
- Engineering
- SysOps & Infrastructure
author: hyoeun
math: false
mathjax_autoNumber: false
image: "/assets/thumbnails/2019-07-24-linux_command.png"
bilingual: true
date: 2019-07-24 09:00:00
---

## The Commands That Actually Separate Skill Levels

There's a clear inflection point where Linux users stop searching "how to list files" and start asking "what process is holding this deleted file open?" or "how do I find all files modified in the last 10 minutes that aren't owned by root?" The commands in this post are the ones that mark that transition. These aren't reference material — they're patterns that experienced engineers reach for automatically when troubleshooting real systems.

## Core Concept: Composable Tools, Not Individual Commands

The power of Linux command-line work comes from composition — small tools piped together to solve specific problems. The key mental model is: `find` locates things, `xargs` feeds them to other commands, `awk`/`sed` transforms text, `sort`/`uniq` aggregates it, and `grep` filters it. Learning these five primitives deeply beats memorizing 50 obscure flags.

## How It Works: The Critical Commands

### find with -exec and xargs

`find` is much more than file location. The difference between a basic user and a power user is in the action flags.

```bash
# Basic: find by name
find /etc -name "*.conf" -type f

# Find modified in last 24 hours
find /var/log -mtime -1 -type f

# Find files larger than 100MB
find /home -size +100M -type f

# Find and execute: delete all .tmp files
find /tmp -name "*.tmp" -delete

# Find and execute a command per file (-exec)
find /etc -name "*.conf" -exec grep -l "password" {} \;

# Find and execute with xargs (faster for many files)
find /etc -name "*.conf" | xargs grep -l "password"

# Handle filenames with spaces
find /home -name "*.txt" -print0 | xargs -0 wc -l

# Find and change permissions
find /var/www -type f -name "*.php" -exec chmod 644 {} \;

# Find files NOT owned by root
find /usr/bin -type f ! -user root

# Find world-writable files (security audit)
find / -perm -o+w -type f 2>/dev/null

# Find setuid/setgid binaries
find / -perm /6000 -type f 2>/dev/null

# Execute with multiple args at once (more efficient)
find /etc -name "*.conf" | xargs -I{} cp {} {}.backup
```

**`-exec` vs `xargs`:** `-exec {} \;` runs the command once per file. `-exec {} +` (or `xargs`) groups files into a single command invocation — much faster for large file sets.

### awk: Structured Text Processing

`awk` is a mini-language. The pattern is: `awk 'condition { action }' file`. Default separator is whitespace; `-F` changes it.

```bash
# Print specific columns
awk '{print $1, $3}' /etc/passwd             # print field 1 and 3
awk -F: '{print $1, $6}' /etc/passwd         # colon-delimited, user:home

# Filter rows + print columns
awk -F: '$3 >= 1000 {print $1, $3}' /etc/passwd  # users with UID >= 1000

# Arithmetic
awk '{sum += $3} END {print "Total:", sum}' data.txt

# Count matches
awk '/ERROR/ {count++} END {print count}' app.log

# Conditional output
awk '{if ($5 > 10) print $0}' data.txt

# Multiple field separators
awk -F'[,:]' '{print $1}' data.txt

# Print lines between patterns
awk '/START/,/END/' file.txt

# Format output
awk -F: '{printf "%-20s %s\n", $1, $6}' /etc/passwd
```

### sed: Stream Editing

`sed` is for line-by-line transformations — substitution, deletion, insertion.

```bash
# Substitute (basic sed usage)
sed 's/old/new/' file           # first occurrence per line
sed 's/old/new/g' file          # all occurrences
sed 's/old/new/gi' file         # case-insensitive

# In-place editing
sed -i 's/old/new/g' file       # modify file
sed -i.bak 's/old/new/g' file   # modify with backup

# Delete lines matching pattern
sed '/^#/d' file                # delete comment lines
sed '/^$/d' file                # delete empty lines

# Print specific lines
sed -n '10,20p' file            # print lines 10-20
sed -n '/START/,/END/p' file    # print between patterns

# Insert/append
sed '5i\New line before line 5' file
sed '/pattern/a\Line after pattern' file

# Real-world: update config value
sed -i 's/^MAX_CONNECTIONS=.*/MAX_CONNECTIONS=1000/' /etc/myapp.conf
```

### sort and uniq Patterns

The `sort | uniq` combination is the backbone of log analysis and frequency counting.

```bash
# Basic sort
sort file
sort -r file                    # reverse
sort -n file                    # numeric sort
sort -k2 file                   # sort by field 2
sort -t: -k3 -n /etc/passwd     # sort passwd by UID

# Count occurrences (most common pattern)
sort file | uniq -c | sort -rn  # frequency count, sorted by count

# Find duplicates
sort file | uniq -d             # lines that appear more than once

# Find unique lines only
sort file | uniq -u             # lines that appear exactly once

# Real log analysis
awk '{print $1}' /var/log/nginx/access.log | sort | uniq -c | sort -rn | head -20
# Top 20 client IPs by request count

grep "ERROR" app.log | awk '{print $4}' | sort | uniq -c | sort -rn
# Error frequency by error code
```

### Process Inspection: lsof, ss, strace

```bash
# lsof: list open files
lsof -p PID                     # all open files for a process
lsof -u username                # all files opened by user
lsof -i :8080                   # process listening on port 8080
lsof -i TCP:1-1024              # all TCP on privileged ports
lsof +D /var/log                # all processes with files in /var/log
lsof | grep deleted             # find deleted files still held open

# ss: socket statistics (faster than netstat)
ss -tlnp                        # TCP listening, with process info
ss -tulnp                       # TCP+UDP listening
ss -t state established         # established connections
ss -s                           # summary
ss -tlnp | grep :443            # who's on port 443

# strace: system call tracer (the nuclear debugging option)
strace -p PID                   # attach to running process
strace -p PID -e trace=network  # only network syscalls
strace -p PID -e trace=file     # only file syscalls
strace -c command               # count syscalls by type
strace -f command               # follow forks

# ltrace: library call tracer
ltrace -p PID                   # trace library calls
ltrace -e malloc,free command   # trace specific functions
```

## Practical Application: Real Troubleshooting Scenarios

### Scenario: Find What's Eating Disk Space

```bash
# 1. Where is space used?
df -h
du -sh /var /tmp /home 2>/dev/null | sort -rh

# 2. Which subdirectory?
du -sh /var/* | sort -rh | head -20

# 3. Find large individual files
find /var -type f -size +50M 2>/dev/null | \
  xargs ls -lh 2>/dev/null | sort -k5 -rh | head -20

# 4. Deleted files still held open (common cause of "disk full" when ls shows no large files)
lsof | awk '$4 ~ /DEL/ {print $1, $2, $7}' | sort -k3 -rn | head -10
```

### Scenario: Who Is Connecting to This Server?

```bash
# Current connections
ss -tn state established | awk 'NR>1 {print $5}' | \
  cut -d: -f1 | sort | uniq -c | sort -rn | head -20

# Connections from access log (last hour)
awk -v cutoff="$(date -d '1 hour ago' '+%d/%b/%Y:%H')" \
  '$4 > "["cutoff {print $1}' /var/log/nginx/access.log | \
  sort | uniq -c | sort -rn | head -20

# Active SSH sessions
who
w
last | head -30
```

### Scenario: Diagnose a Slow/Hanging Process

```bash
# What is the process doing?
strace -p PID -e trace=all 2>&1 | head -50

# What files does it have open?
lsof -p PID

# What's it waiting for (Linux)
cat /proc/PID/wchan           # kernel function it's waiting in
cat /proc/PID/status | grep State

# Thread-level view
ps -T -p PID                  # threads
strace -f -p PID              # trace with forks/threads
```

### Text Pipeline: Parsing a Log Format

```bash
# Nginx log: get 5xx errors, count by URL, show top 10
grep ' 5[0-9][0-9] ' /var/log/nginx/access.log | \
  awk '{print $7}' | \               # extract URL field
  sed 's/?.*//' | \                  # remove query string
  sort | uniq -c | sort -rn | \
  head -10

# Application log: extract slow queries (> 1000ms)
grep "query_time" app.log | \
  awk -F'query_time=' '{print $2}' | \
  awk '{print $1}' | \
  awk '$1 > 1000' | \
  sort -n | \
  tail -20
```

### Disk Usage and Inode Analysis

```bash
# Disk usage
df -h                           # human-readable sizes
df -i                           # inode usage (full inodes = can't create files)
du -sh *                        # sizes of items in current dir
du -sh /* 2>/dev/null | sort -rh # all top-level dirs

# Find inode hogs (often lots of tiny files)
find / -xdev -printf '%h\n' 2>/dev/null | \
  sort | uniq -c | sort -rn | head -20
```

## Gotchas: What Experts Know

**`find -exec {} \;` is slow for many files.** Each `;` invocation spawns a new process per file. Use `+` instead: `find . -name "*.log" -exec gzip {} +` compresses all matching files with a single `gzip` invocation. Or pipe to `xargs`.

**`xargs` breaks on filenames with spaces.** Always use `-print0 | xargs -0` when filenames might contain spaces, newlines, or special characters.

**`awk` columns are split on any whitespace run by default, not single spaces.** Multiple spaces count as one separator. If you need single-space splitting, use `-F' '`.

**`sed -i` on macOS requires a backup extension.** `sed -i 's/old/new/g' file` fails on macOS BSD sed — you need `sed -i '' 's/old/new/g' file` (empty string for no backup). Scripts that work on Linux may break on macOS.

**`ss` replaces `netstat` but isn't installed by default everywhere.** On older systems, `netstat -tlnp` is still the go-to. On modern systemd-based systems, `ss` is faster and more feature-complete.

**`strace` has significant overhead.** Attaching `strace` to a production process will slow it down noticeably. Use it for short periods and be aware of the impact. On very high-traffic systems, use `perf` or eBPF-based tools instead.

**`lsof` output is huge and needs filtering.** Running `lsof` on a production server without a filter can take seconds and output thousands of lines. Always add `-p PID`, `-i :PORT`, or `-u user`.

## Quick Reference

```bash
# Find patterns
find /path -name "*.log" -mtime -7 -type f
find /path -size +100M 2>/dev/null
find /path -perm /4000 -type f       # setuid files
find /path -print0 | xargs -0 cmd    # handle spaces in names

# awk one-liners
awk '{print $1}' file                # print column 1
awk -F: '{print $1}' /etc/passwd     # custom delimiter
awk '{sum+=$1} END{print sum}' f     # sum a column
awk 'NR==10,NR==20' file             # print lines 10-20

# sed patterns
sed 's/old/new/g' file               # global replace
sed -i.bak 's/old/new/g' file        # in-place with backup
sed '/^#/d' file                     # delete comments
sed -n '5,10p' file                  # print lines 5-10

# Process inspection
lsof -i :PORT                        # process on port
lsof +D /directory                   # files in directory
ss -tlnp                             # listening sockets
strace -p PID                        # trace running process
cat /proc/PID/cmdline | tr '\0' ' '  # full command line

# Sort/uniq patterns
sort file | uniq -c | sort -rn       # frequency count
sort -t: -k3 -n /etc/passwd          # sort by field
awk '{print $1}' log | sort | uniq -c | sort -rn | head -20
```

---

## 기술 수준을 실제로 가르는 명령어들

Linux 사용자들이 "파일 목록 보는 방법"을 검색하는 것을 그치고 "이 삭제된 파일을 붙잡고 있는 프로세스는 무엇인가?" 또는 "root 소유가 아닌 최근 10분간 수정된 모든 파일을 찾는 방법은?"을 묻기 시작하는 명확한 변곡점이 있다. 이 포스트의 명령어들은 그 전환을 표시하는 것들이다. 참고 자료가 아니라 실제 시스템 문제 해결 시 경험 많은 엔지니어들이 자동으로 찾게 되는 패턴들이다.

## 핵심 개념: 개별 명령어가 아닌 조합 가능한 도구

Linux 명령줄 작업의 힘은 구성에서 온다 — 특정 문제를 해결하기 위해 파이프로 연결된 작은 도구들. 핵심 정신 모델: `find`는 것을 찾고, `xargs`는 다른 명령어에 피드하고, `awk`/`sed`는 텍스트를 변환하고, `sort`/`uniq`는 집계하고, `grep`은 필터링한다. 이 다섯 가지 기본 요소를 깊이 배우는 것이 50개의 불분명한 플래그를 외우는 것보다 낫다.

## 동작 원리: 핵심 명령어들

### find with -exec and xargs

`find`는 파일 위치 이상이다. 기본 사용자와 파워 유저의 차이는 액션 플래그에 있다.

```bash
# 기본: 이름으로 찾기
find /etc -name "*.conf" -type f

# 최근 24시간 내 수정된 것 찾기
find /var/log -mtime -1 -type f

# 100MB보다 큰 파일 찾기
find /home -size +100M -type f

# 찾고 실행: 모든 .tmp 파일 삭제
find /tmp -name "*.tmp" -delete

# 파일별 명령어 실행 (-exec)
find /etc -name "*.conf" -exec grep -l "password" {} \;

# xargs로 실행 (많은 파일에 더 빠름)
find /etc -name "*.conf" | xargs grep -l "password"

# 공백이 있는 파일명 처리
find /home -name "*.txt" -print0 | xargs -0 wc -l

# 찾고 권한 변경
find /var/www -type f -name "*.php" -exec chmod 644 {} \;

# root 소유가 아닌 파일 찾기
find /usr/bin -type f ! -user root

# 세상에서 쓸 수 있는 파일 (보안 감사)
find / -perm -o+w -type f 2>/dev/null

# setuid/setgid 바이너리 찾기
find / -perm /6000 -type f 2>/dev/null
```

**`-exec` vs `xargs`:** `-exec {} \;`는 파일당 한 번 명령어를 실행한다. `-exec {} +`(또는 `xargs`)는 파일들을 단일 명령어 호출로 그룹화한다 — 대용량 파일 세트에 훨씬 빠르다.

### awk: 구조화된 텍스트 처리

`awk`는 미니 언어다. 패턴은: `awk '조건 { 액션 }' 파일`. 기본 구분자는 공백이고, `-F`로 변경한다.

```bash
# 특정 열 출력
awk '{print $1, $3}' /etc/passwd             # 1번과 3번 필드
awk -F: '{print $1, $6}' /etc/passwd         # 콜론 구분, 사용자:홈

# 행 필터링 + 열 출력
awk -F: '$3 >= 1000 {print $1, $3}' /etc/passwd  # UID >= 1000인 사용자

# 산술
awk '{sum += $3} END {print "합계:", sum}' data.txt

# 일치 수 세기
awk '/ERROR/ {count++} END {print count}' app.log

# 형식화된 출력
awk -F: '{printf "%-20s %s\n", $1, $6}' /etc/passwd
```

### sed: 스트림 편집

`sed`는 줄별 변환 — 대체, 삭제, 삽입을 위한 것이다.

```bash
# 대체 (기본 sed 사용)
sed 's/old/new/' file           # 줄당 첫 번째 발생
sed 's/old/new/g' file          # 모든 발생
sed 's/old/new/gi' file         # 대소문자 구분 없이

# 인플레이스 편집
sed -i 's/old/new/g' file       # 파일 수정
sed -i.bak 's/old/new/g' file   # 백업으로 수정

# 패턴과 일치하는 줄 삭제
sed '/^#/d' file                # 주석 줄 삭제
sed '/^$/d' file                # 빈 줄 삭제

# 특정 줄 출력
sed -n '10,20p' file            # 10-20줄 출력

# 실제 사용: 설정 값 업데이트
sed -i 's/^MAX_CONNECTIONS=.*/MAX_CONNECTIONS=1000/' /etc/myapp.conf
```

### sort와 uniq 패턴

`sort | uniq` 조합은 로그 분석과 빈도 계산의 백본이다.

```bash
# 기본 정렬
sort file
sort -r file                    # 역순
sort -n file                    # 숫자 정렬
sort -k2 file                   # 2번 필드로 정렬
sort -t: -k3 -n /etc/passwd     # UID로 passwd 정렬

# 발생 수 세기 (가장 일반적인 패턴)
sort file | uniq -c | sort -rn  # 빈도 수, 수로 정렬

# 중복 찾기
sort file | uniq -d             # 두 번 이상 나타나는 줄

# 실제 로그 분석
awk '{print $1}' /var/log/nginx/access.log | sort | uniq -c | sort -rn | head -20
# 요청 수별 상위 20개 클라이언트 IP
```

### 프로세스 검사: lsof, ss, strace

```bash
# lsof: 열린 파일 목록
lsof -p PID                     # 프로세스의 모든 열린 파일
lsof -u username                # 사용자가 열은 모든 파일
lsof -i :8080                   # 포트 8080에서 수신 중인 프로세스
lsof +D /var/log                # /var/log에 파일이 있는 모든 프로세스
lsof | grep deleted             # 삭제되었지만 열려 있는 파일 찾기

# ss: 소켓 통계 (netstat보다 빠름)
ss -tlnp                        # TCP 수신, 프로세스 정보 포함
ss -tulnp                       # TCP+UDP 수신
ss -t state established         # 연결된 연결
ss -s                           # 요약

# strace: 시스템 호출 추적 (핵의 디버깅 옵션)
strace -p PID                   # 실행 중인 프로세스에 연결
strace -p PID -e trace=network  # 네트워크 시스콜만
strace -p PID -e trace=file     # 파일 시스콜만
strace -c command               # 유형별 시스콜 수
```

## 실전 적용: 실제 문제 해결 시나리오

### 시나리오: 디스크 공간을 먹는 것 찾기

```bash
# 1. 공간이 어디 사용되나?
df -h
du -sh /var /tmp /home 2>/dev/null | sort -rh

# 2. 어떤 하위 디렉토리?
du -sh /var/* | sort -rh | head -20

# 3. 큰 개별 파일 찾기
find /var -type f -size +50M 2>/dev/null | \
  xargs ls -lh 2>/dev/null | sort -k5 -rh | head -20

# 4. 여전히 열려 있는 삭제된 파일 (ls에 큰 파일이 없는데 "디스크 꽉 참"의 일반적 원인)
lsof | awk '$4 ~ /DEL/ {print $1, $2, $7}' | sort -k3 -rn | head -10
```

### 시나리오: 이 서버에 연결하는 사람 찾기

```bash
# 현재 연결
ss -tn state established | awk 'NR>1 {print $5}' | \
  cut -d: -f1 | sort | uniq -c | sort -rn | head -20

# 활성 SSH 세션
who
w
last | head -30
```

### 시나리오: 느리거나 걸려 있는 프로세스 진단

```bash
# 프로세스가 무엇을 하고 있나?
strace -p PID -e trace=all 2>&1 | head -50

# 어떤 파일을 열고 있나?
lsof -p PID

# 무엇을 기다리나 (Linux)
cat /proc/PID/wchan           # 대기 중인 커널 함수
cat /proc/PID/status | grep State
```

### 텍스트 파이프라인: 로그 형식 파싱

```bash
# Nginx 로그: 5xx 오류, URL별 수, 상위 10개 표시
grep ' 5[0-9][0-9] ' /var/log/nginx/access.log | \
  awk '{print $7}' | \
  sed 's/?.*//' | \
  sort | uniq -c | sort -rn | \
  head -10
```

## 함정: 전문가들이 아는 것

**`find -exec {} \;`는 많은 파일에 느리다.** 각 `;` 호출은 파일당 새 프로세스를 생성한다. 대신 `+`를 사용하라: `find . -name "*.log" -exec gzip {} +`는 단일 `gzip` 호출로 모든 일치하는 파일을 압축한다.

**`xargs`는 공백이 있는 파일명에서 깨진다.** 파일명에 공백, 줄 바꿈, 특수 문자가 있을 수 있을 때 항상 `-print0 | xargs -0`를 사용하라.

**`awk` 열은 기본적으로 단일 공백이 아닌 모든 공백 실행으로 분할된다.** 여러 공백은 하나의 구분자로 계산된다. 단일 공백 분할이 필요하면 `-F' '`를 사용하라.

**macOS에서 `sed -i`는 백업 확장이 필요하다.** macOS BSD sed에서 `sed -i 's/old/new/g' file`는 실패한다 — `sed -i '' 's/old/new/g' file`이 필요하다. Linux에서 작동하는 스크립트가 macOS에서 깨질 수 있다.

**`strace`는 상당한 오버헤드가 있다.** 프로덕션 프로세스에 `strace`를 연결하면 눈에 띄게 느려진다. 짧은 시간 동안만 사용하고 영향을 인식하라. 매우 트래픽이 많은 시스템에서는 `perf`나 eBPF 기반 도구를 사용하라.

**`lsof` 출력은 방대하며 필터링이 필요하다.** 프로덕션 서버에서 필터 없이 `lsof`를 실행하면 수천 줄 출력에 몇 초가 걸린다. 항상 `-p PID`, `-i :PORT`, 또는 `-u user`를 추가하라.

## 빠른 참조

```bash
# find 패턴
find /path -name "*.log" -mtime -7 -type f
find /path -size +100M 2>/dev/null
find /path -perm /4000 -type f       # setuid 파일
find /path -print0 | xargs -0 cmd    # 공백이 있는 이름 처리

# awk 한 줄짜리
awk '{print $1}' file                # 1번 열 출력
awk -F: '{print $1}' /etc/passwd     # 사용자 정의 구분자
awk '{sum+=$1} END{print sum}' f     # 열 합산
awk 'NR==10,NR==20' file             # 10-20줄 출력

# sed 패턴
sed 's/old/new/g' file               # 전역 대체
sed -i.bak 's/old/new/g' file        # 백업으로 인플레이스
sed '/^#/d' file                     # 주석 삭제
sed -n '5,10p' file                  # 5-10줄 출력

# 프로세스 검사
lsof -i :PORT                        # 포트의 프로세스
lsof +D /directory                   # 디렉토리의 파일
ss -tlnp                             # 수신 소켓
strace -p PID                        # 실행 중인 프로세스 추적

# sort/uniq 패턴
sort file | uniq -c | sort -rn       # 빈도 수
sort -t: -k3 -n /etc/passwd          # 필드로 정렬
awk '{print $1}' log | sort | uniq -c | sort -rn | head -20
```
