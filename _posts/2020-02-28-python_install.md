---
title: "Python Environment Management Done Right"
key: page-python_installation_differences
categories:
- Engineering
- Programming Fundamentals
author: hyoeun
math: false
mathjax_autoNumber: false
image: "/assets/thumbnails/2020-02-28-python_install.png"
bilingual: true
date: 2020-02-28 16:04:48
---

## Why Python Environment Management Is Harder Than It Looks

You'd think "install Python and run code" would be simple. It isn't. The Python ecosystem has an environment problem: multiple projects with conflicting dependencies, system Python being off-limits on modern macOS/Linux, and a historical mess of tools (virtualenv, venv, conda, pyenv, pipenv, poetry, and now uv) that each solved a different part of the problem.

Getting this wrong means dependency conflicts that silently break things, system Python corruption, or "works on my machine" bugs across team members. Getting it right means deterministic, reproducible environments that you can destroy and rebuild in seconds. For someone building security tools or data pipelines, this matters.

## Core Concepts: The Python Environment Problem

### Why System Python Is Off-Limits

Every modern macOS and RHEL-based Linux ships with a system Python. Don't touch it. The OS uses it for internal scripts, and `pip install` into it either gets blocked by permissions or — worse — modifies packages that the system depends on.

```bash
# This is what you'll see on modern macOS
% python3 -m pip install requests
error: externally-managed-environment
× This environment is externally managed
```

The right answer is always: use a separate Python installation, isolated per project.

### The Isolation Stack

There are three distinct concerns, each needing a different tool:

| Concern | Tool |
|:--|:--|
| Python version management | `pyenv` |
| Project-level isolation | `venv` / `virtualenv` |
| Dependency locking | `pip-tools`, `poetry`, or `uv` |

## How It Works: Deep Dive

### pyenv — Python Version Management

pyenv lets you install and switch between multiple Python versions without touching system Python.

```bash
# Install pyenv (macOS)
brew install pyenv

# Install pyenv (Linux)
curl https://pyenv.run | bash

# Add to shell profile (~/.zshrc or ~/.bashrc)
export PYENV_ROOT="$HOME/.pyenv"
export PATH="$PYENV_ROOT/bin:$PATH"
eval "$(pyenv init -)"

# Install a specific Python version
pyenv install 3.12.3

# Set global default
pyenv global 3.12.3

# Set version for a specific project directory
cd myproject
pyenv local 3.11.9   # creates .python-version file
```

pyenv works by shim binaries — every `python` call goes through pyenv's shim, which routes to the correct version based on `.python-version` or the global setting.

### venv — Standard Library Virtual Environments

`venv` is built into Python 3.3+. It creates a lightweight isolated environment with its own `site-packages`.

```bash
# Create environment
python -m venv .venv

# Activate
source .venv/bin/activate       # Linux/macOS
.venv\Scripts\activate.bat      # Windows CMD
.venv\Scripts\Activate.ps1      # Windows PowerShell

# Verify isolation
which python    # should point to .venv/bin/python
pip list        # only stdlib, pip, setuptools

# Deactivate
deactivate
```

**Always name your venv `.venv`** — it's the convention, gitignored by default in most templates, and recognized by VS Code and PyCharm automatically.

### pip — Dependency Management Basics

```bash
# Install a package
pip install requests

# Install specific version
pip install requests==2.31.0

# Install from requirements file
pip install -r requirements.txt

# Freeze current environment
pip freeze > requirements.txt
```

**The `pip freeze` trap:** `pip freeze` dumps every installed package including transitive dependencies with pinned versions. This creates fragile environments — a patch release of an indirect dependency will break your install on a new machine months later.

### pip-tools — Sane Dependency Locking

pip-tools separates *declared* dependencies from *locked* ones:

```bash
pip install pip-tools

# requirements.in — what you actually need (with loose constraints)
# requests>=2.28
# pandas
# pytest

# Compile to fully pinned lockfile
pip-compile requirements.in    # generates requirements.txt

# Sync environment to exact lockfile
pip-sync requirements.txt
```

This is the pattern: declare intent in `requirements.in`, lock everything in `requirements.txt`, commit both.

### Modern Alternatives: poetry and uv

**poetry** — project management + dependency resolution in one tool:

```bash
pip install poetry

poetry new myproject       # scaffold new project
poetry add requests        # add dependency, updates pyproject.toml + poetry.lock
poetry install             # install all deps from lockfile
poetry run python script.py
poetry shell               # activate venv
```

**uv** — dramatically faster than pip, written in Rust, drop-in replacement:

```bash
pip install uv

uv venv                    # create .venv (faster than python -m venv)
uv pip install requests    # install (10-100x faster than pip)
uv pip compile requirements.in -o requirements.txt
uv pip sync requirements.txt
```

For new projects in 2024+, uv is worth evaluating — it's significantly faster and handles the full workflow.

## Practical Application: Real Scenarios

### Starting a New Project (Recommended Workflow)

```bash
# 1. Pick Python version
pyenv install 3.12.3
pyenv local 3.12.3

# 2. Create isolated environment
python -m venv .venv
source .venv/bin/activate

# 3. Install pip-tools
pip install pip-tools

# 4. Create requirements.in with your direct dependencies
cat > requirements.in << 'EOF'
requests>=2.28
pydantic>=2.0
pytest
black
ruff
EOF

# 5. Compile lockfile
pip-compile requirements.in

# 6. Install
pip-sync requirements.txt

# 7. Add to .gitignore
echo ".venv/" >> .gitignore
echo "*.pyc" >> .gitignore
```

### Dealing with Python 2 Legacy Code

Python 2 reached EOL in January 2020. If you're maintaining it, `2to3` gives you a starting point:

```bash
# Automated conversion (creates .py.bak backups)
2to3 -w legacy_script.py

# Preview only (no write)
2to3 legacy_script.py
```

Key breaking changes between Python 2.7 and 3.x:
- `print` is a function: `print("x")` not `print "x"`
- Integer division: `3/4` returns `0.75` not `0` (use `//` for floor division)
- `unicode` is now the default string type
- `dict.keys()`, `.values()`, `.items()` return views not lists
- `range()` returns an iterator, not a list

### CentOS/RHEL: Installing Python from Source

When your distro's package manager offers an outdated Python (and pyenv isn't available in a restricted environment):

```bash
# Install build dependencies
yum install gcc openssl-devel bzip2-devel libffi-devel zlib-devel

# Download and build
cd /usr/src
wget https://www.python.org/ftp/python/3.12.3/Python-3.12.3.tgz
tar xzf Python-3.12.3.tgz
cd Python-3.12.3
./configure --enable-optimizations
make altinstall    # altinstall avoids overwriting system python3

# Verify
python3.12 -V

# Clean up
rm /usr/src/Python-3.12.3.tgz
```

`--enable-optimizations` runs profile-guided optimization — builds take longer but the resulting interpreter is ~10% faster. `altinstall` is critical: it installs as `python3.12` not `python3`, avoiding collision with system Python.

## Gotchas: What Experts Know

### Never Commit Your venv

The `.venv` directory contains compiled C extensions for your specific OS, architecture, and Python version. It's not portable and can be hundreds of megabytes.

```bash
# .gitignore — always include these
.venv/
venv/
env/
__pycache__/
*.pyc
*.pyo
.python-version    # optional — commit if you want to enforce version
```

### The `pip freeze` vs `pip-compile` Distinction

```bash
# pip freeze — dumps everything including transitive deps, highly brittle
pip freeze > requirements.txt
# Output includes things like:
# certifi==2024.2.2      # you didn't ask for this
# charset-normalizer==3.3.2  # indirect dependency
# urllib3==2.2.0         # indirect dependency

# pip-compile — separates intent from lock
# requirements.in: requests>=2.28
# requirements.txt (generated): pinned tree including all transitive deps
# The difference: you can still update and the intent is documented
```

### Activating the Wrong Environment

A common source of confusion: installing packages to the wrong Python.

```bash
# Always verify after activation
which python          # must point to .venv
python -c "import sys; print(sys.executable)"

# Verify a specific package is installed where expected
python -c "import requests; print(requests.__file__)"
```

### conda vs venv: When to Use Which

**Use venv/pip for:** pure Python projects, production deployments, when reproducibility and size matter.

**Use conda for:** data science workflows requiring non-Python dependencies (CUDA, MKL, geospatial libs), when you need to manage both Python and system library versions together. conda envs are much larger but handle complex binary dependencies more reliably.

## Quick Reference

### Environment Setup Commands

```bash
# pyenv
pyenv install 3.12.3        # install version
pyenv global 3.12.3         # set default
pyenv local 3.11.9          # set per-directory
pyenv versions              # list installed

# venv
python -m venv .venv                  # create
source .venv/bin/activate             # activate (Unix)
deactivate                            # deactivate
rm -rf .venv && python -m venv .venv  # rebuild from scratch

# pip-tools
pip install pip-tools
pip-compile requirements.in           # generate lockfile
pip-sync requirements.txt             # sync environment

# uv (modern, fast)
uv venv                               # create .venv
uv pip install package                # install
uv pip compile requirements.in        # lock
uv pip sync requirements.txt          # sync
```

### Tool Comparison

| Tool | Manages Python version | Manages venv | Manages dependencies | Speed |
|:--|:--:|:--:|:--:|:--|
| pyenv | ✓ | ✗ | ✗ | — |
| venv | ✗ | ✓ | ✗ | — |
| pip | ✗ | ✗ | ✓ | baseline |
| pip-tools | ✗ | ✗ | ✓ (lock) | baseline |
| poetry | ✗ | ✓ | ✓ (lock) | slow |
| uv | ✗ | ✓ | ✓ (lock) | very fast |

---

## Python 환경 관리가 생각보다 까다로운 이유

"Python 설치하고 코드 실행하면 되지"라고 생각하기 쉽다. 하지만 현실은 다르다. Python 생태계는 환경 문제를 안고 있다. 의존성 충돌이 있는 여러 프로젝트, 현대 macOS/Linux에서는 시스템 Python을 건드리면 안 되고, 그 사이에 virtualenv, venv, conda, pyenv, pipenv, poetry, 그리고 uv까지 등장하며 각자 문제의 다른 부분을 해결했다.

잘못하면 의존성 충돌이 조용히 일어나거나, 시스템 Python이 망가지거나, "내 컴퓨터에서는 되는데" 버그가 생긴다. 제대로 하면 수초 만에 파괴하고 재건할 수 있는 결정론적이고 재현 가능한 환경을 갖게 된다.

## 핵심 개념: Python 환경 문제

### 시스템 Python을 건드리면 안 되는 이유

현대 macOS와 RHEL 계열 Linux는 모두 시스템 Python을 포함한다. 절대 건드리지 마라. OS 내부 스크립트가 이를 사용하고, `pip install`을 하면 권한 에러가 나거나 — 더 나쁘게는 — 시스템이 의존하는 패키지를 바꿔버린다.

```bash
# 현대 macOS에서 시스템 pip 사용 시도 시
% python3 -m pip install requests
error: externally-managed-environment
```

정답은 항상: 프로젝트별로 분리된 Python 설치를 사용하라.

### 격리 스택

세 가지 별개의 문제가 있고, 각각 다른 도구가 필요하다:

| 문제 | 도구 |
|:--|:--|
| Python 버전 관리 | `pyenv` |
| 프로젝트 수준 격리 | `venv` / `virtualenv` |
| 의존성 잠금 | `pip-tools`, `poetry`, 또는 `uv` |

## 작동 원리: 깊이 들어가기

### pyenv — Python 버전 관리

pyenv는 시스템 Python을 건드리지 않고 여러 Python 버전을 설치하고 전환할 수 있게 한다.

```bash
# pyenv 설치 (macOS)
brew install pyenv

# pyenv 설치 (Linux)
curl https://pyenv.run | bash

# 쉘 프로파일에 추가 (~/.zshrc 또는 ~/.bashrc)
export PYENV_ROOT="$HOME/.pyenv"
export PATH="$PYENV_ROOT/bin:$PATH"
eval "$(pyenv init -)"

# Python 특정 버전 설치
pyenv install 3.12.3

# 전역 기본값 설정
pyenv global 3.12.3

# 특정 프로젝트 디렉토리에 버전 설정
cd myproject
pyenv local 3.11.9   # .python-version 파일 생성
```

pyenv는 shim 바이너리로 동작한다. 모든 `python` 호출은 pyenv의 shim을 통해 `.python-version` 또는 전역 설정에 따라 올바른 버전으로 라우팅된다.

### venv — 표준 가상 환경

`venv`는 Python 3.3+에 내장되어 있다. 자체 `site-packages`를 가진 경량 격리 환경을 만든다.

```bash
# 환경 생성
python -m venv .venv

# 활성화
source .venv/bin/activate       # Linux/macOS
.venv\Scripts\activate.bat      # Windows CMD

# 격리 확인
which python    # .venv/bin/python을 가리켜야 함
pip list        # 표준 라이브러리와 pip, setuptools만 있어야 함

# 비활성화
deactivate
```

**항상 `.venv`라는 이름을 사용하라** — 관례이고, 대부분의 템플릿에서 기본적으로 gitignore되며, VS Code와 PyCharm이 자동으로 인식한다.

### pip-tools — 올바른 의존성 잠금

pip-tools는 *선언된* 의존성과 *잠긴* 의존성을 분리한다:

```bash
pip install pip-tools

# requirements.in — 실제로 필요한 것 (느슨한 제약)
# requests>=2.28
# pandas

# 완전히 고정된 lockfile로 컴파일
pip-compile requirements.in    # requirements.txt 생성

# 정확한 lockfile에 환경 동기화
pip-sync requirements.txt
```

패턴: 의도는 `requirements.in`에, 잠금은 `requirements.txt`에, 둘 다 커밋.

### 현대적 대안: poetry와 uv

**poetry** — 프로젝트 관리 + 의존성 해결 통합:

```bash
pip install poetry

poetry new myproject       # 새 프로젝트 스캐폴딩
poetry add requests        # 의존성 추가
poetry install             # lockfile에서 모든 의존성 설치
poetry run python script.py
```

**uv** — Rust로 작성된 초고속 pip 대체제:

```bash
pip install uv

uv venv                    # .venv 생성 (매우 빠름)
uv pip install requests    # 설치 (pip보다 10-100배 빠름)
uv pip compile requirements.in
uv pip sync requirements.txt
```

## 실전 활용

### 새 프로젝트 시작 (권장 워크플로우)

```bash
# 1. Python 버전 선택
pyenv install 3.12.3
pyenv local 3.12.3

# 2. 격리 환경 생성
python -m venv .venv
source .venv/bin/activate

# 3. pip-tools 설치
pip install pip-tools

# 4. 직접 의존성 선언
cat > requirements.in << 'EOF'
requests>=2.28
pydantic>=2.0
pytest
black
ruff
EOF

# 5. lockfile 컴파일
pip-compile requirements.in

# 6. 설치
pip-sync requirements.txt

# 7. .gitignore 추가
echo ".venv/" >> .gitignore
```

### CentOS/RHEL: 소스에서 Python 설치

패키지 관리자가 오래된 Python만 제공하는 환경:

```bash
# 빌드 의존성 설치
yum install gcc openssl-devel bzip2-devel libffi-devel zlib-devel

# 다운로드 및 빌드
cd /usr/src
wget https://www.python.org/ftp/python/3.12.3/Python-3.12.3.tgz
tar xzf Python-3.12.3.tgz
cd Python-3.12.3
./configure --enable-optimizations
make altinstall    # altinstall로 시스템 python3 덮어쓰기 방지

# 확인
python3.12 -V
rm /usr/src/Python-3.12.3.tgz
```

`altinstall`이 핵심이다. 이게 없으면 `python3`가 덮어써진다.

## 전문가가 아는 함정들

### venv는 절대 커밋하지 말 것

`.venv` 디렉토리는 특정 OS, 아키텍처, Python 버전에 맞게 컴파일된 C 확장을 포함한다. 이식성이 없고 수백 MB가 될 수 있다.

```bash
# .gitignore — 항상 포함
.venv/
venv/
__pycache__/
*.pyc
```

### `pip freeze` vs `pip-compile` 차이

```bash
# pip freeze — 전이 의존성 포함 모든 것 덤프, 매우 취약
pip freeze > requirements.txt
# certifi==2024.2.2  ← 이걸 요청하지 않았음
# charset-normalizer==3.3.2  ← 간접 의존성

# pip-compile — 의도와 잠금을 분리
# requirements.in: requests>=2.28  (의도)
# requirements.txt: 전체 트리 고정  (잠금)
```

### conda vs venv: 언제 뭘 쓸까

**venv/pip 사용:** 순수 Python 프로젝트, 프로덕션 배포, 재현성과 크기가 중요할 때.

**conda 사용:** CUDA, MKL, 지리공간 라이브러리 같은 비Python 의존성이 있는 데이터 과학 워크플로우.

## 빠른 참조

```bash
# pyenv
pyenv install 3.12.3        # 버전 설치
pyenv global 3.12.3         # 기본값 설정
pyenv local 3.11.9          # 디렉토리별 설정

# venv
python -m venv .venv                  # 생성
source .venv/bin/activate             # 활성화 (Unix)
deactivate                            # 비활성화

# pip-tools
pip-compile requirements.in           # lockfile 생성
pip-sync requirements.txt             # 환경 동기화

# uv
uv venv && source .venv/bin/activate  # 빠른 생성 + 활성화
uv pip install package                # 초고속 설치
uv pip compile requirements.in        # 잠금
```
