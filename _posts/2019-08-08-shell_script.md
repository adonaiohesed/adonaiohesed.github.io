---
title: Shell Scripting That Actually Works in Production
key: page-shell_script
categories:
- Engineering
- SysOps & Infrastructure
author: hyoeun
math: false
mathjax_autoNumber: false
image: "/assets/thumbnails/2019-08-08-shell_script.png"
bilingual: true
date: 2019-08-08 09:00:00
---

## The Gap Between Shell Scripts That "Work" and Scripts That Work in Production

There's a specific failure mode in shell scripting: the script works perfectly in your test environment, works in staging, and then silently fails in production — eating an important file, leaving partial state everywhere, or doing nothing while returning exit code 0. The tools that prevent these failures are well-known among experienced engineers: `set -euo pipefail`, trap handlers, proper quoting, and explicit error handling. But they're rarely taught together as a coherent discipline. This post covers the practices that turn a fragile script into production-grade automation.

## Core Concept: The Robustness Triad

Three principles underpin robust shell scripts:

1. **Fail loudly and early** — detect errors when they happen, not three steps later
2. **Quote everything** — prevent word splitting and globbing from causing surprises
3. **Clean up on exit** — use `trap` to ensure partial state never persists

Everything else is built on these.

## How It Works: From Top to Bottom

### Shebang and Portability

```bash
#!/usr/bin/env bash      # Preferred: finds bash in PATH, works across systems
#!/bin/bash              # Direct path: faster, but assumes /bin/bash
#!/bin/sh                # POSIX sh: most portable, fewest features
```

Use `#!/usr/bin/env bash` for portability. Use `#!/bin/bash` when you need bash specifically and want the interpreter to be explicit and fast. Use `#!/bin/sh` only if you're writing scripts that must run on minimal systems (Alpine, BusyBox) where bash may not exist.

**Portability gotcha:** bash features not in POSIX sh include: arrays, `[[ ]]`, `$'...'` strings, `{a..z}` brace expansion, `$RANDOM`, process substitution `<(...)`, and `local`. If you use `#!/bin/sh`, you can't use these.

### The Safety Header

Every non-trivial bash script should start with:

```bash
#!/usr/bin/env bash
set -euo pipefail
IFS=$'\n\t'
```

What each option does:

**`set -e`** (errexit): Exit immediately if any command returns non-zero. Without this, scripts silently continue after failures.

```bash
# Without -e: script continues even after cp fails
cp important_file /nonexistent/dir   # fails silently
echo "Done"                          # still runs

# With -e: script exits on cp failure
set -e
cp important_file /nonexistent/dir   # exits here
echo "This never runs"
```

**`set -u`** (nounset): Treat unset variables as errors. Without this, a typo in a variable name produces empty string expansion — and `rm -rf $TMPDIR/` becomes `rm -rf /` when `TMPDIR` is accidentally unset.

```bash
set -u
echo $UNSET_VAR    # error: UNSET_VAR: unbound variable
```

**`set -o pipefail`**: The exit status of a pipeline is the exit status of the last command to fail, not just the last command. Without this, `failing_command | tee log.txt` returns 0 because `tee` succeeded.

```bash
set -o pipefail
false | echo "hello"   # returns exit code 1 (false failed)
```

**`IFS=$'\n\t'`**: Sets the Internal Field Separator to newline+tab (not space). Prevents `for file in $files` from splitting filenames on spaces. Not required if you always use arrays and proper quoting, but it's a safe default.

### Variable Quoting Rules

The most common source of shell script bugs is unquoted variables. The rule: **always double-quote variables unless you specifically need word splitting or globbing.**

```bash
# BAD — breaks on filenames with spaces
for f in $files; do
    cp $f /backup/
done

# GOOD — handles spaces correctly
for f in "${files[@]}"; do
    cp "$f" /backup/
done

# BAD — $dir could be empty, causing rm -rf /
rm -rf $dir/cache

# GOOD — explicit check + quote
if [[ -n "$dir" ]]; then
    rm -rf "${dir}/cache"
fi

# When NOT to quote (legitimate cases)
test -z $var              # wrong: $var="has spaces" breaks this
test -z "$var"            # right
echo $unquoted_glob       # OK if you want glob expansion
arr=( $list_of_words )    # OK: intentional word splitting
```

**Default value patterns:**

```bash
dir=${DIR:-/tmp}              # use /tmp if DIR is unset or empty
dir=${DIR:?'DIR must be set'} # exit with error if unset or empty
name=${1:-default}            # use default if $1 not provided
count=${COUNT:-0}             # default to 0
```

### Functions

Functions are the primary code organization mechanism in bash. Write them at the top, call them below.

```bash
#!/usr/bin/env bash
set -euo pipefail

# Function with local variables (prevent namespace pollution)
backup_file() {
    local src="$1"
    local dest="${2:-${src}.bak}"

    if [[ ! -f "$src" ]]; then
        echo "ERROR: Source file not found: $src" >&2
        return 1
    fi

    cp "$src" "$dest"
    echo "Backed up: $src -> $dest"
}

# Functions that return values via echo (captured with $())
get_timestamp() {
    date '+%Y%m%d_%H%M%S'
}

# Functions that return status codes
is_service_running() {
    local service="$1"
    systemctl is-active --quiet "$service"
}

# Usage
backup_file /etc/nginx/nginx.conf
timestamp=$(get_timestamp)

if is_service_running nginx; then
    echo "nginx is running"
fi
```

### Conditionals and Tests

```bash
# [[ ]] is bash-specific but safer than [ ]
# Differences: no word splitting, no globbing on variables, supports =~ regex

[[ -f "$file" ]]         # file exists and is regular file
[[ -d "$dir" ]]          # directory exists
[[ -z "$var" ]]          # string is empty
[[ -n "$var" ]]          # string is non-empty
[[ "$a" == "$b" ]]       # string equality
[[ "$a" != "$b" ]]       # string inequality
[[ "$a" =~ ^[0-9]+$ ]]  # regex match (bash only)
[[ "$a" < "$b" ]]        # string comparison

# Arithmetic
(( count > 0 ))           # numeric comparison
(( count++ ))             # increment
(( total = a + b ))

# Compound conditions
[[ -f "$file" && -r "$file" ]]    # AND
[[ "$x" == "a" || "$x" == "b" ]] # OR
[[ ! -d "$dir" ]]                  # NOT
```

### Loops

```bash
# for loop with array
files=( /etc/nginx/*.conf )
for f in "${files[@]}"; do
    echo "Processing: $f"
done

# for loop with range
for i in {1..10}; do
    echo "Iteration $i"
done

# C-style for loop
for (( i=0; i<count; i++ )); do
    echo "Index: $i"
done

# while loop with read (best practice for reading files)
while IFS= read -r line; do
    echo "Line: $line"
done < /etc/hosts

# while loop with command
while ! nc -z localhost 8080; do
    echo "Waiting for port 8080..."
    sleep 2
done

# until loop
until systemctl is-active --quiet nginx; do
    echo "Waiting for nginx..."
    sleep 1
done
```

### Argument Parsing with getopts

```bash
#!/usr/bin/env bash
set -euo pipefail

usage() {
    cat <<EOF
Usage: $(basename "$0") [OPTIONS] <required_arg>

Options:
  -h          Show this help
  -v          Verbose output
  -o FILE     Output file (default: output.txt)
  -n NUM      Number of iterations (default: 1)
EOF
    exit "${1:-0}"
}

verbose=false
output="output.txt"
num=1

while getopts "hvo:n:" opt; do
    case "$opt" in
        h) usage 0 ;;
        v) verbose=true ;;
        o) output="$OPTARG" ;;
        n) num="$OPTARG" ;;
        *) usage 1 ;;
    esac
done
shift $(( OPTIND - 1 ))

# Check required positional argument
if [[ $# -lt 1 ]]; then
    echo "ERROR: required_arg is missing" >&2
    usage 1
fi

required_arg="$1"
```

### Error Handling and trap

`trap` runs a command when the script receives a signal or exits. The essential pattern for cleanup:

```bash
#!/usr/bin/env bash
set -euo pipefail

# Create temp dir that will be cleaned up on exit
TMPDIR=$(mktemp -d)
readonly TMPDIR

cleanup() {
    local exit_code=$?
    rm -rf "$TMPDIR"
    # Do other cleanup here
    exit "$exit_code"   # preserve original exit code
}

# Register cleanup for normal exit, interrupt, and termination
trap cleanup EXIT INT TERM

# Now use TMPDIR freely — it will always be cleaned up
echo "temp work" > "$TMPDIR/work.txt"
do_something "$TMPDIR/work.txt"

# Explicit error handler
error_handler() {
    local exit_code=$?
    local line_number=$1
    echo "ERROR: Script failed at line $line_number with exit code $exit_code" >&2
}
trap 'error_handler $LINENO' ERR
```

### Heredocs in Scripts

```bash
# Write config file from script
cat > /etc/myapp/config.conf <<EOF
[settings]
host=${HOSTNAME}
port=${PORT:-8080}
log_level=${LOG_LEVEL:-info}
EOF

# Use heredoc for multiline messages
log_info() {
    local message="$1"
    logger -t "$(basename "$0")" "$message"
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] INFO: $message"
}
```

## Practical Application: A Production-Grade Script

```bash
#!/usr/bin/env bash
# deploy.sh — Deploy application to target environment
set -euo pipefail
IFS=$'\n\t'

readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly SCRIPT_NAME="$(basename "$0")"
readonly LOG_FILE="/var/log/deploy-$(date +%Y%m%d).log"

# Logging
log() {
    local level="$1"; shift
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] [$level] $*" | tee -a "$LOG_FILE"
}
log_info()  { log "INFO " "$@"; }
log_warn()  { log "WARN " "$@" >&2; }
log_error() { log "ERROR" "$@" >&2; }

usage() {
    cat <<EOF
Usage: $SCRIPT_NAME [OPTIONS] <environment>

Arguments:
  environment   Target: staging, production

Options:
  -h            Show help
  -v VERSION    Application version to deploy (required)
  -d            Dry run — print actions without executing
EOF
    exit "${1:-0}"
}

# Parse arguments
dry_run=false
version=""

while getopts "hv:d" opt; do
    case "$opt" in
        h) usage 0 ;;
        v) version="$OPTARG" ;;
        d) dry_run=true ;;
        *) usage 1 ;;
    esac
done
shift $(( OPTIND - 1 ))

[[ $# -lt 1 ]] && { log_error "Missing environment argument"; usage 1; }
[[ -z "$version" ]] && { log_error "Version is required (-v)"; usage 1; }

env="$1"
[[ "$env" == "production" || "$env" == "staging" ]] || {
    log_error "Invalid environment: $env"
    usage 1
}

# Cleanup on exit
TMPDIR=""
cleanup() {
    local exit_code=$?
    [[ -n "$TMPDIR" && -d "$TMPDIR" ]] && rm -rf "$TMPDIR"
    exit "$exit_code"
}
trap cleanup EXIT INT TERM

# Main logic
TMPDIR=$(mktemp -d)
log_info "Starting deploy of version $version to $env"

run_cmd() {
    if $dry_run; then
        log_info "[DRY RUN] $*"
    else
        "$@"
    fi
}

run_cmd systemctl stop myapp
run_cmd cp -r "/releases/${version}/." /opt/myapp/
run_cmd systemctl start myapp

log_info "Deploy complete"
```

## Gotchas: What Experts Know

**`set -e` has surprising non-error cases.** Some commands return non-zero legitimately. `grep` returns 1 if no match is found — so `grep "pattern" file` in a `set -e` script will exit the script if there's no match. Workarounds:

```bash
grep "pattern" file || true        # ignore exit code
if grep -q "pattern" file; then   # in a conditional, -e doesn't apply
    echo "found"
fi
```

**Arrays handle spaces in filenames; strings don't.**

```bash
# BAD: breaks on spaces
files="file one.txt file two.txt"
for f in $files; do ...            # splits on spaces

# GOOD: use arrays
files=( "file one.txt" "file two.txt" )
for f in "${files[@]}"; do ...     # handles spaces correctly
```

**`$()` strips trailing newlines.**

```bash
content=$(cat file)        # trailing newlines removed
lines=$(wc -l < file)      # fine for numbers
multiline=$(printf 'a\nb\n')  # trailing \n stripped
```

**`local` doesn't isolate `set -e` behavior.** Errors inside a function with `local` declarations won't always trigger `set -e` as expected. Assign and declare separately:

```bash
local result             # declare
result=$(some_command)   # assign (exit code is now checked)
```

**`trap` in subshells doesn't affect the parent.** If you call a function in a subshell `(cleanup_func)`, traps set in the parent don't apply.

**Parallel execution loses `set -e`.** Commands in `&` background processes don't inherit `set -e` behavior for the parent. Use `wait` with explicit error checking:

```bash
cmd1 &
cmd2 &
wait $!         # only waits for last background job
wait            # waits for all — but exit code is the last one
```

**Never `source` (`.`) untrusted files.** `source config.sh` executes arbitrary code in the current shell context — no sandbox. Validate config files or use key=value parsing instead.

## Quick Reference

```bash
# Safety header
set -euo pipefail
IFS=$'\n\t'

# Default values
var=${VAR:-default}          # default if unset/empty
var=${VAR:?'must be set'}    # error if unset/empty

# Conditional tests
[[ -f file ]]                # file exists
[[ -d dir ]]                 # directory exists
[[ -z "$var" ]]              # empty string
[[ -n "$var" ]]              # non-empty string
[[ "$a" =~ regex ]]          # regex match

# Error handling
command || { echo "failed"; exit 1; }
command || true              # ignore exit code

# Trap for cleanup
trap 'cleanup' EXIT INT TERM

# Array vs string
arr=( item1 item2 )
for i in "${arr[@]}"; do ... done   # safe iteration

# Read lines safely
while IFS= read -r line; do
    echo "$line"
done < file

# Argument parsing
while getopts "hvo:" opt; do
    case "$opt" in
        h) usage ;;
        v) verbose=true ;;
        o) output="$OPTARG" ;;
    esac
done
shift $(( OPTIND - 1 ))

# Temp files
tmpfile=$(mktemp)
tmpdir=$(mktemp -d)
trap "rm -rf $tmpdir $tmpfile" EXIT
```

---

## "작동하는" 쉘 스크립트와 프로덕션에서 작동하는 스크립트의 차이

쉘 스크립팅에서 특정 실패 패턴이 있다: 테스트 환경에서 완벽하게 작동하고, 스테이징에서도 작동하지만, 프로덕션에서 조용히 실패한다 — 중요한 파일을 삭제하거나, 곳곳에 부분적인 상태를 남기거나, 아무것도 하지 않으면서 종료 코드 0을 반환한다. 이런 실패를 방지하는 도구들은 경험 많은 엔지니어들에게 잘 알려져 있다: `set -euo pipefail`, trap 핸들러, 적절한 따옴표 처리, 명시적 오류 처리. 하지만 일관된 규율로 함께 가르치는 경우는 드물다. 이 포스트는 취약한 스크립트를 프로덕션 수준 자동화로 바꾸는 관행을 다룬다.

## 핵심 개념: 견고성의 삼원칙

견고한 쉘 스크립트를 뒷받침하는 세 가지 원칙:

1. **크게, 빨리 실패하라** — 3단계 후가 아니라 발생할 때 오류를 감지하라
2. **모든 것을 따옴표로 감싸라** — 단어 분리와 글로빙이 놀라움을 일으키는 것을 방지하라
3. **종료 시 정리하라** — `trap`을 사용해 부분적인 상태가 절대 유지되지 않도록 하라

다른 모든 것은 이 위에 구축된다.

## 동작 원리: 위에서 아래로

### 쉬뱅과 이식성

```bash
#!/usr/bin/env bash      # 선호: PATH에서 bash를 찾아 시스템 간 작동
#!/bin/bash              # 직접 경로: 빠르지만 /bin/bash를 가정
#!/bin/sh                # POSIX sh: 가장 이식성 높음, 기능 적음
```

이식성을 위해 `#!/usr/bin/env bash`를 사용하라. bash가 없을 수 있는 최소 시스템(Alpine, BusyBox)에서 실행해야 할 경우에만 `#!/bin/sh`를 사용하라.

**이식성 함정:** POSIX sh에 없는 bash 기능: 배열, `[[ ]]`, `$'...'` 문자열, `{a..z}` 중괄호 확장, `$RANDOM`, 프로세스 치환 `<(...)`, `local`. `#!/bin/sh`를 사용하면 이것들을 사용할 수 없다.

### 안전 헤더

모든 중요한 bash 스크립트는 이것으로 시작해야 한다:

```bash
#!/usr/bin/env bash
set -euo pipefail
IFS=$'\n\t'
```

각 옵션의 역할:

**`set -e`** (errexit): 명령어가 0이 아닌 값을 반환하면 즉시 종료. 이 없이는 스크립트가 실패 후 조용히 계속된다.

```bash
# -e 없이: cp 실패 후에도 스크립트 계속
cp important_file /nonexistent/dir   # 조용히 실패
echo "완료"                          # 여전히 실행됨

# -e 있이: cp 실패 시 스크립트 종료
set -e
cp important_file /nonexistent/dir   # 여기서 종료
echo "이것은 실행되지 않음"
```

**`set -u`** (nounset): 설정되지 않은 변수를 오류로 취급. 이 없이는 변수 이름의 오타가 빈 문자열 확장을 생성한다 — `TMPDIR`이 실수로 설정 해제되면 `rm -rf $TMPDIR/`은 `rm -rf /`가 된다.

**`set -o pipefail`**: 파이프라인의 종료 상태는 실패한 마지막 명령어의 종료 상태이지 마지막 명령어만의 것이 아니다. 이 없이는 `tee`가 성공했기 때문에 `failing_command | tee log.txt`는 0을 반환한다.

**`IFS=$'\n\t'`**: 내부 필드 구분자를 줄바꿈+탭으로 설정한다(공백 아님). 파일명이 공백으로 분리되는 것을 방지한다.

### 변수 따옴표 규칙

쉘 스크립트 버그의 가장 일반적인 원인은 따옴표로 감싸지 않은 변수다. 규칙: **단어 분리나 글로빙이 특별히 필요하지 않은 한 항상 변수를 이중 따옴표로 감싸라.**

```bash
# 나쁨 — 공백이 있는 파일명에서 깨짐
for f in $files; do
    cp $f /backup/
done

# 좋음 — 공백을 올바르게 처리
for f in "${files[@]}"; do
    cp "$f" /backup/
done

# 나쁨 — $dir이 비어 있으면 rm -rf /가 됨
rm -rf $dir/cache

# 좋음 — 명시적 확인 + 따옴표
if [[ -n "$dir" ]]; then
    rm -rf "${dir}/cache"
fi
```

**기본값 패턴:**

```bash
dir=${DIR:-/tmp}              # DIR이 설정되지 않거나 비어 있으면 /tmp 사용
dir=${DIR:?'DIR을 설정해야 함'} # 설정되지 않거나 비어 있으면 오류로 종료
name=${1:-default}            # $1이 제공되지 않으면 기본값 사용
```

### 함수

함수는 bash에서 기본 코드 구성 메커니즘이다.

```bash
#!/usr/bin/env bash
set -euo pipefail

# 로컬 변수가 있는 함수 (네임스페이스 오염 방지)
backup_file() {
    local src="$1"
    local dest="${2:-${src}.bak}"

    if [[ ! -f "$src" ]]; then
        echo "오류: 소스 파일을 찾을 수 없음: $src" >&2
        return 1
    fi

    cp "$src" "$dest"
    echo "백업 완료: $src -> $dest"
}

# echo를 통해 값을 반환하는 함수 ($()로 캡처)
get_timestamp() {
    date '+%Y%m%d_%H%M%S'
}

# 상태 코드를 반환하는 함수
is_service_running() {
    local service="$1"
    systemctl is-active --quiet "$service"
}

# 사용
backup_file /etc/nginx/nginx.conf
timestamp=$(get_timestamp)

if is_service_running nginx; then
    echo "nginx가 실행 중"
fi
```

### 조건문과 테스트

```bash
# [[ ]]는 bash 전용이지만 [ ]보다 안전
[[ -f "$file" ]]         # 파일이 존재하고 일반 파일
[[ -d "$dir" ]]          # 디렉토리가 존재
[[ -z "$var" ]]          # 문자열이 비어 있음
[[ -n "$var" ]]          # 문자열이 비어 있지 않음
[[ "$a" == "$b" ]]       # 문자열 동등성
[[ "$a" =~ ^[0-9]+$ ]]  # 정규식 일치 (bash 전용)

# 산술
(( count > 0 ))           # 숫자 비교
(( count++ ))             # 증가
(( total = a + b ))

# 복합 조건
[[ -f "$file" && -r "$file" ]]    # AND
[[ "$x" == "a" || "$x" == "b" ]] # OR
[[ ! -d "$dir" ]]                  # NOT
```

### 루프

```bash
# 배열로 for 루프
files=( /etc/nginx/*.conf )
for f in "${files[@]}"; do
    echo "처리 중: $f"
done

# 범위로 for 루프
for i in {1..10}; do
    echo "반복 $i"
done

# 파일 읽기를 위한 while 루프 (모범 사례)
while IFS= read -r line; do
    echo "줄: $line"
done < /etc/hosts

# 명령어로 while 루프
while ! nc -z localhost 8080; do
    echo "포트 8080 대기 중..."
    sleep 2
done
```

### getopts로 인수 파싱

```bash
#!/usr/bin/env bash
set -euo pipefail

usage() {
    cat <<EOF
사용법: $(basename "$0") [옵션] <필수_인수>

옵션:
  -h          도움말 표시
  -v          상세 출력
  -o FILE     출력 파일 (기본: output.txt)
  -n NUM      반복 횟수 (기본: 1)
EOF
    exit "${1:-0}"
}

verbose=false
output="output.txt"
num=1

while getopts "hvo:n:" opt; do
    case "$opt" in
        h) usage 0 ;;
        v) verbose=true ;;
        o) output="$OPTARG" ;;
        n) num="$OPTARG" ;;
        *) usage 1 ;;
    esac
done
shift $(( OPTIND - 1 ))

if [[ $# -lt 1 ]]; then
    echo "오류: 필수_인수가 없음" >&2
    usage 1
fi

required_arg="$1"
```

### 오류 처리와 trap

`trap`은 스크립트가 시그널을 받거나 종료할 때 명령어를 실행한다.

```bash
#!/usr/bin/env bash
set -euo pipefail

TMPDIR=$(mktemp -d)
readonly TMPDIR

cleanup() {
    local exit_code=$?
    rm -rf "$TMPDIR"
    exit "$exit_code"   # 원래 종료 코드 보존
}

# 정상 종료, 인터럽트, 종료에 대한 정리 등록
trap cleanup EXIT INT TERM

# 이제 TMPDIR을 자유롭게 사용 — 항상 정리됨
echo "임시 작업" > "$TMPDIR/work.txt"
```

## 실전 적용: 프로덕션 수준 스크립트

```bash
#!/usr/bin/env bash
# deploy.sh — 대상 환경에 애플리케이션 배포
set -euo pipefail
IFS=$'\n\t'

readonly SCRIPT_NAME="$(basename "$0")"
readonly LOG_FILE="/var/log/deploy-$(date +%Y%m%d).log"

log() {
    local level="$1"; shift
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] [$level] $*" | tee -a "$LOG_FILE"
}
log_info()  { log "INFO " "$@"; }
log_error() { log "ERROR" "$@" >&2; }

usage() {
    cat <<EOF
사용법: $SCRIPT_NAME [옵션] <환경>

인수:
  환경   대상: staging, production

옵션:
  -h            도움말 표시
  -v VERSION    배포할 애플리케이션 버전 (필수)
  -d            드라이 런
EOF
    exit "${1:-0}"
}

dry_run=false
version=""

while getopts "hv:d" opt; do
    case "$opt" in
        h) usage 0 ;;
        v) version="$OPTARG" ;;
        d) dry_run=true ;;
        *) usage 1 ;;
    esac
done
shift $(( OPTIND - 1 ))

[[ $# -lt 1 ]] && { log_error "환경 인수 없음"; usage 1; }
[[ -z "$version" ]] && { log_error "버전 필수 (-v)"; usage 1; }

env="$1"
[[ "$env" == "production" || "$env" == "staging" ]] || {
    log_error "잘못된 환경: $env"
    usage 1
}

TMPDIR=""
cleanup() {
    local exit_code=$?
    [[ -n "$TMPDIR" && -d "$TMPDIR" ]] && rm -rf "$TMPDIR"
    exit "$exit_code"
}
trap cleanup EXIT INT TERM

TMPDIR=$(mktemp -d)
log_info "버전 $version을 $env에 배포 시작"

run_cmd() {
    if $dry_run; then
        log_info "[DRY RUN] $*"
    else
        "$@"
    fi
}

run_cmd systemctl stop myapp
run_cmd cp -r "/releases/${version}/." /opt/myapp/
run_cmd systemctl start myapp

log_info "배포 완료"
```

## 함정: 전문가들이 아는 것

**`set -e`에는 놀라운 비오류 경우가 있다.** 일부 명령어는 합법적으로 0이 아닌 값을 반환한다. `grep`은 일치가 없으면 1을 반환한다 — `set -e` 스크립트에서 `grep "pattern" file`은 일치가 없으면 스크립트를 종료한다.

```bash
grep "pattern" file || true        # 종료 코드 무시
if grep -q "pattern" file; then   # 조건문에서 -e는 적용되지 않음
    echo "찾음"
fi
```

**배열은 파일명의 공백을 처리하지만 문자열은 그렇지 않다.**

```bash
# 나쁨: 공백에서 깨짐
files="file one.txt file two.txt"
for f in $files; do ...

# 좋음: 배열 사용
files=( "file one.txt" "file two.txt" )
for f in "${files[@]}"; do ...
```

**`$()`는 후행 줄 바꿈을 제거한다.** `content=$(cat file)` — 후행 줄 바꿈이 제거된다. 숫자에는 괜찮지만 여러 줄 내용에는 주의하라.

**`local`은 `set -e` 동작을 격리하지 않는다.** `local` 선언이 있는 함수 내의 오류가 항상 `set -e`를 예상대로 트리거하지 않는다. 별도로 선언하고 할당하라:

```bash
local result             # 선언
result=$(some_command)   # 할당 (이제 종료 코드 확인됨)
```

**신뢰할 수 없는 파일을 절대 `source`(`.`)하지 마라.** `source config.sh`는 현재 쉘 컨텍스트에서 임의의 코드를 실행한다 — 샌드박스 없음. 대신 key=value 파싱을 사용하라.

## 빠른 참조

```bash
# 안전 헤더
set -euo pipefail
IFS=$'\n\t'

# 기본값
var=${VAR:-default}          # 설정되지 않거나 비어 있으면 기본값
var=${VAR:?'설정해야 함'}    # 설정되지 않거나 비어 있으면 오류

# 조건 테스트
[[ -f file ]]                # 파일 존재
[[ -d dir ]]                 # 디렉토리 존재
[[ -z "$var" ]]              # 빈 문자열
[[ -n "$var" ]]              # 비어 있지 않은 문자열
[[ "$a" =~ regex ]]          # 정규식 일치

# 오류 처리
command || { echo "실패"; exit 1; }
command || true              # 종료 코드 무시

# 정리를 위한 trap
trap 'cleanup' EXIT INT TERM

# 배열 반복
arr=( item1 item2 )
for i in "${arr[@]}"; do ... done

# 줄 안전하게 읽기
while IFS= read -r line; do
    echo "$line"
done < file

# 임시 파일
tmpfile=$(mktemp)
tmpdir=$(mktemp -d)
trap "rm -rf $tmpdir $tmpfile" EXIT
```
