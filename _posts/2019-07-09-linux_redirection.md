---
title: Linux I/O Redirection and File Descriptors
key: page-linux_redirection
categories:
- Engineering
- SysOps & Infrastructure
author: hyoeun
math: false
mathjax_autoNumber: false
image: "/assets/thumbnails/2019-07-09-linux_redirection.png"
bilingual: true
date: 2019-07-09 09:00:00
---

## Why I/O Redirection Is Core Infrastructure Knowledge

Every experienced Linux engineer has a story about a bug that turned out to be output going to the wrong place — stderr being swallowed by a log pipeline, stdout and stderr interleaved in ways that made parsing impossible, or a daemon's error messages silently discarded because no one thought to redirect fd 2. I/O redirection isn't an advanced topic; it's fundamental plumbing. Understanding file descriptors at the model level lets you write reliable automation, debug broken pipelines, and reason about what any shell command is actually doing with its output streams.

## Core Concept: File Descriptors and Standard Streams

Every process starts with three open file descriptors inherited from its parent:

| FD | Name | Default target | C constant |
|----|------|---------------|------------|
| 0 | stdin | keyboard / terminal | `STDIN_FILENO` |
| 1 | stdout | terminal | `STDOUT_FILENO` |
| 2 | stderr | terminal | `STDERR_FILENO` |

These are just integers — indices into the per-process file descriptor table maintained by the kernel. When you write `echo "hello"`, the shell writes the string to fd 1. When `ls` reports "Permission denied", it writes to fd 2. Both appear on your terminal because both fd 1 and fd 2 point to the terminal device by default.

Redirection works by changing what file descriptor numbers point to. `> file` makes the kernel close fd 1 and open `file` for writing in its place — the process has no idea it's writing to a file instead of a terminal. This is the elegance: programs don't need to know where their output goes.

## How It Works: Redirection Operators

### Output Redirection

```bash
command > file          # redirect stdout to file (truncate)
command >> file         # redirect stdout to file (append)
command 2> file         # redirect stderr to file
command 2>> file        # redirect stderr to file (append)
command &> file         # redirect both stdout and stderr to file (bash 4+)
command > file 2>&1     # same: stdout to file, then stderr to fd 1 (wherever that is now)
command 2>&1 > file     # WRONG ORDER: stderr to terminal, stdout to file
```

The order of redirections matters critically. `> file 2>&1` means:
1. Open `file`, assign to fd 1
2. Make fd 2 point to wherever fd 1 currently points (which is now `file`)

Result: both streams go to `file`.

`2>&1 > file` means:
1. Make fd 2 point to wherever fd 1 currently points (which is the terminal)
2. Open `file`, assign to fd 1

Result: stdout goes to `file`, stderr still goes to terminal. Almost never what you want.

```bash
# Discard output entirely
command > /dev/null
command > /dev/null 2>&1    # discard both streams
command &> /dev/null        # bash shorthand for above

# Separate stdout and stderr to different files
command > output.log 2> error.log

# Append both to a log file
command >> combined.log 2>&1
```

### Input Redirection

```bash
command < file          # feed file as stdin
wc -l < /etc/passwd     # count lines in passwd

# Here-string: feed a string as stdin
grep "pattern" <<< "search in this string"
base64 <<< "encode me"
```

### Here-Documents

Here-docs are the clean way to embed multiline strings in scripts without temporary files.

```bash
# Basic heredoc
cat <<EOF
Line one
Line two with $variable expansion
EOF

# Suppress expansion with quoted delimiter
cat <<'EOF'
No $expansion here
Literal \n backslash
EOF

# Indented heredoc (bash 4.0+, uses tab indentation)
if true; then
    cat <<-EOF
        Tabs are stripped from the front
        Makes indented scripts readable
    EOF
fi

# Heredoc to a file
cat > /etc/myapp/config.yaml <<EOF
server:
  host: ${HOSTNAME}
  port: 8080
database:
  url: ${DB_URL}
EOF

# Heredoc as input to a command
ssh remote-host <<EOF
  echo "Running on \$(hostname)"
  sudo systemctl restart nginx
EOF
```

### Pipes

A pipe connects stdout of one process to stdin of the next via a kernel buffer.

```bash
cat /var/log/syslog | grep "error" | wc -l
ps aux | sort -k3 -rn | head -10   # top 10 CPU consumers
```

**Pipes only connect stdout.** Stderr passes through untouched (still goes to terminal unless redirected). To include stderr in a pipe:

```bash
command 2>&1 | grep pattern         # merge stderr into stdout before piping
command |& grep pattern             # bash shorthand for 2>&1 |
```

### Process Substitution

Process substitution creates a temporary pipe that looks like a filename to the shell. It solves the problem of commands that require filename arguments but you want to feed them from another command's output.

```bash
# <(command) creates a readable file-like thing
diff <(sort file1) <(sort file2)    # compare sorted versions

# Compare remote file with local
diff <(ssh remote cat /etc/hosts) /etc/hosts

# >(command) creates a writable file-like thing
tee >(gzip > output.gz) < input.txt

# Useful for feeding multiple log streams
command > >(grep ERROR >> error.log) 2> >(grep WARN >> warn.log)
```

### tee: Branching Output

`tee` reads stdin and writes to both stdout and a file simultaneously. Essential for logging while also displaying output.

```bash
command | tee output.log            # to screen and file
command | tee -a output.log         # append to file
command | tee file1 file2           # multiple files
command | tee >(other_command)      # to file and another command
```

## Practical Application: Real Workflows

### Logging Script Output

```bash
#!/bin/bash
# Redirect all script output to a log file while keeping terminal output
exec > >(tee -a /var/log/deploy.log) 2>&1

echo "Starting deployment at $(date)"
# All output from here goes to both terminal and log file
```

### Capturing and Testing Exit Codes with Redirected Output

```bash
# Silently check if command succeeds
if curl -s http://localhost:8080/health > /dev/null 2>&1; then
    echo "Service is up"
else
    echo "Service is down"
fi

# Capture output and check exit code
output=$(command 2>&1)
exit_code=$?
if [ $exit_code -ne 0 ]; then
    echo "Command failed with: $output"
fi
```

### Log Analysis Pipeline

```bash
# Count error types in application log
grep "ERROR" /var/log/app.log | \
  awk '{print $5}' | \
  sort | uniq -c | sort -rn | \
  head -20

# Tail log with filtering
tail -f /var/log/nginx/access.log | grep --line-buffered "500"

# Real-time error monitoring that writes to a file too
tail -f /var/log/app.log | grep --line-buffered "ERROR" | tee error_stream.log
```

### stdin in Scripts

```bash
# Read from stdin interactively
read -p "Enter value: " user_input

# Read from stdin in a pipeline
while IFS= read -r line; do
    echo "Processing: $line"
done < /etc/hosts

# Or from a pipe
cat /etc/hosts | while IFS= read -r line; do
    echo "Processing: $line"
done

# Check if stdin is a terminal or a pipe
if [ -t 0 ]; then
    echo "Reading from terminal"
else
    echo "Reading from pipe or file"
    cat -                           # read and echo stdin
fi
```

### SSH with Heredocs for Remote Automation

```bash
# Run commands on remote host with local variable expansion
DEPLOY_VERSION="1.2.3"
ssh deploy@server <<EOF
  cd /opt/app
  git fetch
  git checkout tags/v${DEPLOY_VERSION}
  systemctl restart app
  systemctl status app
EOF

# Single-quoted heredoc: no local expansion, everything runs remotely
ssh deploy@server <<'EOF'
  echo "Server hostname: $(hostname)"
  echo "Kernel: $(uname -r)"
  df -h /
EOF
```

## Gotchas: What Experts Know

**stderr from subcommands in `$()` is NOT captured.** When you do `output=$(command)`, only stdout is captured. stderr still goes to the terminal (or wherever fd 2 points in the calling script). To capture both:

```bash
output=$(command 2>&1)      # capture both into variable
```

**Pipes and exit codes.** In a pipeline `a | b | c`, the exit code of the whole pipeline is the exit code of the last command (`c`) by default. If `a` fails, you won't know. Fix this:

```bash
set -o pipefail             # pipeline fails if any command fails (bash)
a | b | c
echo "Exit: $?"             # now reflects failure in any stage

# Check individual pipeline exits with PIPESTATUS
a | b | c
echo "${PIPESTATUS[@]}"     # array of all exit codes
```

**`> file` truncates first, then the command runs.** `sort file > file` destroys the file before sort reads it. Use a temp file or `sponge` (from moreutils):

```bash
sort file > file.tmp && mv file.tmp file
# or
sort file | sponge file     # sponge buffers stdin before writing
```

**Buffering changes behavior with pipes.** Many programs use full buffering (4KB+ blocks) when stdout is not a terminal, switching from line buffering. This makes `tail -f app.log | grep ERROR` appear to hang — `grep` buffers its output. Fix: `grep --line-buffered` or `stdbuf -oL grep`.

**`/dev/null` is a write sink AND a read source.** `command < /dev/null` gives the command an immediate EOF on stdin. Useful for running daemons that might try to read stdin interactively.

**Heredoc indentation with `-` requires actual tabs, not spaces.** If your editor converts tabs to spaces, `<<-EOF` with space indentation won't work. This is one reason some engineers avoid `<<-` and just accept the visual indentation mismatch.

## Quick Reference

```bash
# Redirect operators
>               # stdout to file (truncate)
>>              # stdout to file (append)
2>              # stderr to file
2>&1            # stderr to wherever stdout goes
&>              # both stdout+stderr to file (bash)
<               # stdin from file
<<<             # stdin from string (here-string)
|               # stdout to next command's stdin
|&              # stdout+stderr to next command's stdin (bash)

# Useful patterns
cmd > /dev/null 2>&1        # discard all output
cmd > out.log 2> err.log    # split streams to files
cmd 2>&1 | tee out.log      # capture to file and display
cmd > >(cmd2) 2> >(cmd3)    # route streams to different commands

# Here-doc patterns
<<EOF ... EOF               # heredoc with expansion
<<'EOF' ... EOF             # heredoc without expansion
<<-EOF ... EOF              # heredoc stripping leading tabs

# Debug redirections
strace -e trace=write ./script  # trace actual write() calls
lsof -p PID                     # see open file descriptors
ls -la /proc/PID/fd             # same, via proc
```

---

## 왜 I/O 리다이렉션은 핵심 인프라 지식인가

경험 많은 Linux 엔지니어라면 버그가 알고 보니 출력이 잘못된 곳으로 가고 있었던 이야기가 있을 것이다 — stderr가 로그 파이프라인에서 삼켜지거나, stdout과 stderr가 파싱을 불가능하게 만드는 방식으로 섞이거나, 데몬의 오류 메시지가 fd 2를 리다이렉트하는 것을 아무도 생각하지 않아 조용히 버려지거나. I/O 리다이렉션은 고급 주제가 아니다. 기본 배관이다. 파일 디스크립터를 모델 수준에서 이해하면 신뢰할 수 있는 자동화를 작성하고, 깨진 파이프라인을 디버깅하고, 어떤 쉘 명령어가 출력 스트림으로 실제로 무엇을 하는지 추론할 수 있다.

## 핵심 개념: 파일 디스크립터와 표준 스트림

모든 프로세스는 부모로부터 상속된 세 개의 열린 파일 디스크립터로 시작한다:

| FD | 이름 | 기본 대상 | C 상수 |
|----|------|---------|-------|
| 0 | stdin | 키보드 / 터미널 | `STDIN_FILENO` |
| 1 | stdout | 터미널 | `STDOUT_FILENO` |
| 2 | stderr | 터미널 | `STDERR_FILENO` |

이것들은 단순한 정수 — 커널이 유지하는 프로세스별 파일 디스크립터 테이블의 인덱스다. `echo "hello"`를 입력하면 쉘은 fd 1에 문자열을 쓴다. `ls`가 "Permission denied"를 보고하면 fd 2에 쓴다. 둘 다 fd 1과 fd 2가 기본적으로 터미널 장치를 가리키기 때문에 터미널에 나타난다.

리다이렉션은 파일 디스크립터 번호가 가리키는 것을 변경해서 작동한다. `> file`은 커널이 fd 1을 닫고 대신 `file`을 쓰기 위해 열게 만든다 — 프로세스는 터미널이 아닌 파일에 쓰고 있다는 것을 전혀 모른다. 이것이 우아함이다: 프로그램은 출력이 어디로 가는지 알 필요가 없다.

## 동작 원리: 리다이렉션 연산자

### 출력 리다이렉션

```bash
command > file          # stdout을 파일로 리다이렉트 (잘라내기)
command >> file         # stdout을 파일로 리다이렉트 (추가)
command 2> file         # stderr를 파일로
command 2>> file        # stderr를 파일로 (추가)
command &> file         # stdout과 stderr 모두 파일로 (bash 4+)
command > file 2>&1     # 동일: stdout을 파일로, 그 다음 stderr를 fd 1로
command 2>&1 > file     # 잘못된 순서: stderr는 터미널, stdout은 파일
```

리다이렉션의 순서가 중요하다. `> file 2>&1`은:
1. `file`을 열어 fd 1에 할당
2. fd 2가 fd 1이 현재 가리키는 곳(이제 `file`)을 가리키게 함

결과: 두 스트림 모두 `file`로 간다.

`2>&1 > file`은:
1. fd 2가 fd 1이 현재 가리키는 곳(터미널)을 가리키게 함
2. `file`을 열어 fd 1에 할당

결과: stdout은 `file`로, stderr는 여전히 터미널로. 거의 항상 원하지 않는 결과다.

```bash
# 출력 완전히 버리기
command > /dev/null
command > /dev/null 2>&1    # 두 스트림 모두 버리기
command &> /dev/null        # bash 축약

# stdout과 stderr를 다른 파일로
command > output.log 2> error.log

# 두 스트림 모두 로그 파일에 추가
command >> combined.log 2>&1
```

### 입력 리다이렉션

```bash
command < file          # 파일을 stdin으로
wc -l < /etc/passwd     # passwd의 줄 수 세기

# Here-string: 문자열을 stdin으로
grep "pattern" <<< "이 문자열에서 검색"
base64 <<< "인코딩"
```

### Here-Documents

Here-doc은 임시 파일 없이 스크립트에 여러 줄 문자열을 내장하는 깔끔한 방법이다.

```bash
# 기본 heredoc
cat <<EOF
첫 번째 줄
$variable 확장이 있는 두 번째 줄
EOF

# 따옴표로 구분자 감싸면 확장 억제
cat <<'EOF'
여기는 $expansion이 없음
리터럴 \n 백슬래시
EOF

# 들여쓴 heredoc (bash 4.0+, 탭 들여쓰기 사용)
if true; then
    cat <<-EOF
        앞의 탭이 제거됨
        들여쓴 스크립트를 읽기 좋게 함
    EOF
fi

# 파일로 heredoc
cat > /etc/myapp/config.yaml <<EOF
server:
  host: ${HOSTNAME}
  port: 8080
database:
  url: ${DB_URL}
EOF

# 명령어 입력으로 heredoc
ssh remote-host <<EOF
  echo "실행 중인 호스트: \$(hostname)"
  sudo systemctl restart nginx
EOF
```

### 파이프

파이프는 커널 버퍼를 통해 한 프로세스의 stdout을 다음 프로세스의 stdin에 연결한다.

```bash
cat /var/log/syslog | grep "error" | wc -l
ps aux | sort -k3 -rn | head -10   # 상위 10개 CPU 사용 프로세스
```

**파이프는 stdout만 연결한다.** stderr는 건드리지 않고 통과한다. stderr를 파이프에 포함하려면:

```bash
command 2>&1 | grep pattern         # 파이프 전에 stderr를 stdout에 병합
command |& grep pattern             # 2>&1 |의 bash 축약
```

### 프로세스 치환

프로세스 치환은 쉘에게 파일 이름처럼 보이는 임시 파이프를 만든다. 파일 이름 인수가 필요하지만 다른 명령어의 출력을 피드하고 싶을 때 문제를 해결한다.

```bash
# <(command)는 읽기 가능한 파일 같은 것을 만든다
diff <(sort file1) <(sort file2)    # 정렬된 버전 비교

# 원격 파일과 로컬 비교
diff <(ssh remote cat /etc/hosts) /etc/hosts

# >(command)는 쓰기 가능한 파일 같은 것을 만든다
tee >(gzip > output.gz) < input.txt

# 여러 로그 스트림 라우팅
command > >(grep ERROR >> error.log) 2> >(grep WARN >> warn.log)
```

### tee: 출력 분기

`tee`는 stdin을 읽고 stdout과 파일 모두에 동시에 쓴다. 출력을 표시하면서 로깅하는 데 필수적이다.

```bash
command | tee output.log            # 화면과 파일
command | tee -a output.log         # 파일에 추가
command | tee file1 file2           # 여러 파일
command | tee >(other_command)      # 파일과 다른 명령어
```

## 실전 적용: 실제 워크플로우

### 스크립트 출력 로깅

```bash
#!/bin/bash
# 터미널 출력을 유지하면서 모든 스크립트 출력을 로그 파일로 리다이렉트
exec > >(tee -a /var/log/deploy.log) 2>&1

echo "$(date)에 배포 시작"
# 여기서부터 모든 출력이 터미널과 로그 파일 모두로 간다
```

### 리다이렉트된 출력으로 종료 코드 캡처 및 테스트

```bash
# 조용히 명령어 성공 여부 확인
if curl -s http://localhost:8080/health > /dev/null 2>&1; then
    echo "서비스 정상"
else
    echo "서비스 다운"
fi

# 출력 캡처 및 종료 코드 확인
output=$(command 2>&1)
exit_code=$?
if [ $exit_code -ne 0 ]; then
    echo "명령어 실패: $output"
fi
```

### 로그 분석 파이프라인

```bash
# 애플리케이션 로그에서 오류 유형 수
grep "ERROR" /var/log/app.log | \
  awk '{print $5}' | \
  sort | uniq -c | sort -rn | \
  head -20

# 필터링과 함께 로그 추적
tail -f /var/log/nginx/access.log | grep --line-buffered "500"

# 파일에도 쓰는 실시간 오류 모니터링
tail -f /var/log/app.log | grep --line-buffered "ERROR" | tee error_stream.log
```

### 원격 자동화를 위한 SSH + Heredoc

```bash
# 로컬 변수 확장으로 원격 호스트에서 명령어 실행
DEPLOY_VERSION="1.2.3"
ssh deploy@server <<EOF
  cd /opt/app
  git fetch
  git checkout tags/v${DEPLOY_VERSION}
  systemctl restart app
  systemctl status app
EOF

# 작은따옴표 heredoc: 로컬 확장 없음, 모든 것이 원격에서 실행
ssh deploy@server <<'EOF'
  echo "서버 호스트명: $(hostname)"
  echo "커널: $(uname -r)"
  df -h /
EOF
```

## 함정: 전문가들이 아는 것

**`$()`의 서브 명령어에서 나온 stderr는 캡처되지 않는다.** `output=$(command)`를 할 때 stdout만 캡처된다. stderr는 여전히 터미널(또는 호출 스크립트에서 fd 2가 가리키는 곳)로 간다. 둘 다 캡처하려면:

```bash
output=$(command 2>&1)      # 변수에 둘 다 캡처
```

**파이프와 종료 코드.** 파이프라인 `a | b | c`에서 전체 파이프라인의 종료 코드는 기본적으로 마지막 명령어(`c`)의 종료 코드다. `a`가 실패해도 알 수 없다:

```bash
set -o pipefail             # 어떤 명령어가 실패해도 파이프라인 실패 (bash)
a | b | c
echo "종료: $?"

# PIPESTATUS로 개별 파이프라인 종료 확인
a | b | c
echo "${PIPESTATUS[@]}"     # 모든 종료 코드의 배열
```

**`> file`은 먼저 잘라내고 그 다음 명령어가 실행된다.** `sort file > file`은 sort가 읽기 전에 파일을 파괴한다. 임시 파일이나 `sponge`를 사용하라:

```bash
sort file > file.tmp && mv file.tmp file
sort file | sponge file     # sponge는 쓰기 전에 stdin을 버퍼링
```

**버퍼링은 파이프에서 동작을 바꾼다.** 많은 프로그램이 stdout이 터미널이 아닐 때 전체 버퍼링(4KB+ 블록)을 사용하며, 라인 버퍼링에서 전환된다. 이로 인해 `tail -f app.log | grep ERROR`가 중단된 것처럼 보인다 — `grep`이 출력을 버퍼링한다. 해결: `grep --line-buffered` 또는 `stdbuf -oL grep`.

**`/dev/null`은 쓰기 싱크이자 읽기 소스다.** `command < /dev/null`은 명령어에게 stdin에 즉시 EOF를 준다. 대화형으로 stdin을 읽으려 할 수 있는 데몬을 실행하는 데 유용하다.

**`-`로 된 Heredoc 들여쓰기는 실제 탭이 필요하다.** 편집기가 탭을 공백으로 변환하면 공백 들여쓰기로 `<<-EOF`는 작동하지 않는다. 일부 엔지니어들이 `<<-`를 피하고 시각적 들여쓰기 불일치를 그냥 받아들이는 이유 중 하나다.

## 빠른 참조

```bash
# 리다이렉션 연산자
# >               stdout을 파일로 (잘라내기)
# >>              stdout을 파일로 (추가)
# 2>              stderr를 파일로
# 2>&1            stderr를 stdout이 가리키는 곳으로
# &>              stdout+stderr 모두 파일로 (bash)
# <               파일에서 stdin
# <<<             문자열에서 stdin (here-string)
# |               stdout을 다음 명령어의 stdin으로
# |&              stdout+stderr를 다음 명령어의 stdin으로 (bash)

# 유용한 패턴
# cmd > /dev/null 2>&1        모든 출력 버리기
# cmd > out.log 2> err.log    스트림을 다른 파일로 분리
# cmd 2>&1 | tee out.log      파일에 캡처하고 표시
# cmd > >(cmd2) 2> >(cmd3)    스트림을 다른 명령어로 라우팅

# Here-doc 패턴
# <<EOF ... EOF               확장이 있는 heredoc
# <<'EOF' ... EOF             확장이 없는 heredoc
# <<-EOF ... EOF              앞의 탭을 제거하는 heredoc

# 리다이렉션 디버그
strace -e trace=write ./script  # 실제 write() 호출 추적
lsof -p PID                     # 열린 파일 디스크립터 확인
ls -la /proc/PID/fd             # proc을 통해 동일하게
```
