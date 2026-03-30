---
title: Writing Effective CLAUDE.md and SKILL.md
key: page-claude_md_skill_md
categories:
- AI & ML
- AI Agents & Automation
author: hyoeun
math: true
mathjax_autoNumber: true
image: "/assets/thumbnails/2026-03-18-claude_md_skill_md.png"
bilingual: true
date: 2026-03-18 09:00:00
---

## Writing Effective CLAUDE.md and SKILL.md

The most underestimated part of working with Claude Code is the configuration layer. Most engineers spend time on the agent logic itself but write CLAUDE.md as an afterthought. After running Claude Code across multiple production codebases, I've found that a well-written CLAUDE.md is the single highest-leverage investment you can make in the quality of Claude's outputs.

### What is CLAUDE.md?

`CLAUDE.md` is a Markdown file that Claude Code reads automatically when it starts in a directory. It's the equivalent of a detailed onboarding document for a new engineer joining your project—except the engineer is an LLM that reads it before every session.

Claude Code reads CLAUDE.md files from:
1. `~/.claude/CLAUDE.md` — global configuration (applies to all projects)
2. `PROJECT_ROOT/CLAUDE.md` — project-specific configuration
3. Subdirectory `CLAUDE.md` files when working in subdirectories

They stack: global settings apply everywhere, project settings override globals, subdirectory settings override project settings.

### What to Put in CLAUDE.md

**Project Context**

Start with a brief description of what the project is. Not for documentation purposes—Claude needs enough context to make sensible decisions without reading every file.

```markdown
# Project: ThreatHunter API

A Django REST API for threat intelligence aggregation. Connects to:
- VirusTotal API for file/URL reputation
- Shodan for infrastructure reconnaissance
- Internal SIEM (Elasticsearch cluster at elk.internal:9200)

This is a security tool used by SOC analysts. Assume all operations
are authorized and in-scope unless explicitly stated otherwise.
```

**Development Environment**

Tell Claude how your project works: how to run tests, how to build, what tooling is in use.

```markdown
## Development Setup

- Python 3.11, managed with pyenv
- Dependencies: `pip install -e ".[dev]"` (not requirements.txt)
- Tests: `pytest tests/ -v` (NOT `python -m pytest`)
- Linting: `ruff check .` then `ruff format .`
- Pre-commit hooks are active. Always run `pre-commit run --all-files` before considering work done.

## Important: Never use `python manage.py runserver` in this repo.
## Use `uvicorn app.main:app --reload` instead.
```

**Code Style and Conventions**

This is where you encode team conventions that aren't enforced by linters.

```markdown
## Code Conventions

- Use type hints everywhere. PRs without type hints will be rejected.
- All database queries must use parameterized queries. Never f-string SQL.
- Error messages must not leak internal paths or stack traces to HTTP responses.
- Secrets are injected via environment variables. Never hardcode credentials.
- Security-sensitive functions require a comment explaining the threat model.
```

**What Claude Should and Should Not Do**

This is your behavioral guardrail section. Be direct and specific.

```markdown
## Behavior Guidelines

DO:
- Run tests after every code change and fix failures before reporting done
- Check git blame before modifying a line to understand why it was written that way
- Ask before deleting any file that wasn't created in this session

DO NOT:
- Suggest moving to a different framework (architectural decisions are made separately)
- Add logging.DEBUG statements in production code paths
- Modify the migration files — always create new migrations instead
- Use `--force` or `--no-verify` with git commands
```

**Architecture Notes**

Capture architectural decisions that aren't obvious from reading the code.

```markdown
## Architecture Notes

### Authentication
We use JWT with RS256 (not HS256). The private key is in AWS Secrets Manager,
not the environment. See auth/jwt.py for the key retrieval logic.

### Rate Limiting
All external API calls go through RateLimiter in utils/rate_limiter.py.
Never call VirusTotal or Shodan directly—always use the wrapper classes.

### Background Tasks
Celery is configured with priority queues. Low-priority scans MUST use
`scan_queue.low` or they will starve high-priority alert processing.
```

### What is SKILL.md?

A skill is a reusable, invocable prompt workflow that extends Claude Code with custom slash commands. Skills live in `.claude/skills/SKILL_NAME/SKILL.md`.

When you type `/skill-name` in Claude Code, Claude reads the corresponding SKILL.md and follows its instructions.

Skills solve a specific problem: you have a complex, multi-step workflow that you run repeatedly. Instead of re-explaining it every time, you encode it once in a SKILL.md.

### Anatomy of a SKILL.md

```markdown
---
description: Short description shown in skill listings
author: your-name
version: 1.0
---

# Skill Name

## When to Use This Skill
[Describe what situations this skill is for]

## Instructions

[Step-by-step instructions for Claude to follow]

## Output Format

[Define exactly what Claude should produce]

## Examples

[Optional: show input/output examples]
```

### Example: Security Code Review Skill

```markdown
---
description: Perform a structured security code review using OWASP Top 10
author: hyoeun
version: 1.2
---

# Security Code Review

## When to Use This Skill
Use when asked to review code for security vulnerabilities, or when
triggered by `/security-review`.

## Instructions

1. **Identify scope**: Determine which files to review from context.
   If not clear, ask: "Which files should I review?"

2. **Read all relevant files** before making any findings.

3. **Analyze against OWASP Top 10**:
   - A01: Broken Access Control
   - A02: Cryptographic Failures
   - A03: Injection (SQL, Command, LDAP, XPath)
   - A04: Insecure Design
   - A05: Security Misconfiguration
   - A06: Vulnerable Components
   - A07: Identification and Authentication Failures
   - A08: Software and Data Integrity Failures
   - A09: Security Logging and Monitoring Failures
   - A10: SSRF

4. **For each finding**, record:
   - Category (OWASP ID)
   - Severity: Critical / High / Medium / Low / Info
   - File path and line number
   - Vulnerability description
   - Proof of concept (how it could be exploited)
   - Recommended fix with code example

5. **Output the full report** in the format below.

## Output Format

```markdown
## Security Review Report
**Date**: [today]
**Scope**: [files reviewed]
**Findings**: [N total] — [C] Critical, [H] High, [M] Medium, [L] Low

---

### [OWASP-ID] Finding Title
**Severity**: Critical/High/Medium/Low
**File**: `path/to/file.py:42`

**Description**: [What the vulnerability is]

**Proof of Concept**:
[How an attacker could exploit it]

**Fix**:
[Code example of the fix]

```

## Examples

Input: `/security-review` (with auth.py open in IDE)
Action: Reviews auth.py + any imported files, outputs structured report.
```

### CLAUDE.md Anti-Patterns

Avoid these mistakes that undermine the value of your CLAUDE.md:

**Vague instructions**: "Write clean code" tells Claude nothing. "Use snake_case for variables, PascalCase for classes, UPPER_SNAKE_CASE for constants, and never use single-letter variable names except in list comprehensions" is actionable.

**Outdated information**: A CLAUDE.md that references the old ORM you migrated away from two years ago actively harms Claude's understanding. Treat CLAUDE.md like a living document—update it when the codebase changes.

**Too long**: CLAUDE.md that's 5000 words will be partially ignored. Keep it under 500 lines. If you need more, use `@file` imports to reference separate documents.

**Missing the "why"**: Claude Code follows instructions better when it understands the reasoning. "Never use f-strings in SQL queries—this prevents SQL injection attacks" is better than just "Never use f-strings in SQL queries."


## 효과적인 CLAUDE.md와 SKILL.md 작성법

Claude Code 작업에서 가장 과소평가되는 부분은 구성 레이어입니다. 대부분의 엔지니어들은 에이전트 로직 자체에 시간을 쓰지만 CLAUDE.md는 생각 없이 작성합니다. 여러 프로덕션 코드베이스에서 Claude Code를 실행한 후, 잘 작성된 CLAUDE.md가 Claude 출력의 품질에 투자할 수 있는 단일 최고 레버리지 투자임을 발견했습니다.

### CLAUDE.md란 무엇인가?

`CLAUDE.md`는 Claude Code가 디렉토리에서 시작할 때 자동으로 읽는 Markdown 파일입니다. 프로젝트에 합류하는 신입 엔지니어를 위한 상세한 온보딩 문서와 동등합니다—단, 엔지니어가 모든 세션 전에 읽는 LLM입니다.

Claude Code는 다음 위치에서 CLAUDE.md 파일을 읽습니다:
1. `~/.claude/CLAUDE.md` — 전역 구성 (모든 프로젝트에 적용)
2. `PROJECT_ROOT/CLAUDE.md` — 프로젝트별 구성
3. 서브디렉토리에서 작업할 때 서브디렉토리 CLAUDE.md 파일

이것들은 쌓입니다: 전역 설정이 모든 곳에 적용되고, 프로젝트 설정이 전역을 오버라이드하며, 서브디렉토리 설정이 프로젝트 설정을 오버라이드합니다.

### CLAUDE.md에 무엇을 넣을까

**프로젝트 컨텍스트**: 프로젝트가 무엇인지에 대한 간략한 설명으로 시작하세요. 문서화 목적이 아닙니다—Claude가 모든 파일을 읽지 않고도 합리적인 결정을 내릴 수 있는 충분한 컨텍스트가 필요합니다.

**개발 환경**: Claude에게 프로젝트 작동 방식을 알려주세요: 테스트 실행 방법, 빌드 방법, 사용 중인 도구.

**코드 스타일과 관례**: 린터에 의해 강제되지 않는 팀 관례를 인코딩하는 곳입니다.

**Claude가 해야 할 것과 하지 말아야 할 것**: 동작 가드레일 섹션. 직접적이고 구체적으로 작성하세요.

**아키텍처 노트**: 코드를 읽는 것만으로는 명확하지 않은 아키텍처 결정을 기록하세요.

### SKILL.md란 무엇인가?

스킬은 Claude Code를 커스텀 슬래시 명령어로 확장하는 재사용 가능하고 호출 가능한 프롬프트 워크플로우입니다. 스킬은 `.claude/skills/SKILL_NAME/SKILL.md`에 있습니다.

Claude Code에서 `/skill-name`을 입력하면, Claude가 해당 SKILL.md를 읽고 지침을 따릅니다.

스킬은 특정 문제를 해결합니다: 반복적으로 실행하는 복잡한 다단계 워크플로우가 있습니다. 매번 재설명하는 대신, SKILL.md에 한 번 인코딩합니다.

### SKILL.md의 구조

```markdown
---
description: 스킬 목록에 표시되는 짧은 설명
author: 이름
version: 1.0
---

# 스킬 이름

## 이 스킬을 사용하는 경우
[이 스킬이 어떤 상황을 위한 것인지 설명]

## 지침
[Claude가 따를 단계별 지침]

## 출력 형식
[Claude가 생성해야 할 것을 정확히 정의]

## 예시
[선택사항: 입력/출력 예시 표시]
```

### CLAUDE.md 안티 패턴

CLAUDE.md의 가치를 훼손하는 이러한 실수들을 피하세요:

**모호한 지침**: "깔끔한 코드를 작성하라"는 Claude에게 아무 말도 하지 않습니다. "변수에는 snake_case를, 클래스에는 PascalCase를, 상수에는 UPPER_SNAKE_CASE를 사용하고, 리스트 컴프리헨션을 제외하고는 절대 단일 문자 변수명을 사용하지 말라"가 실행 가능합니다.

**오래된 정보**: 2년 전에 마이그레이션한 구 ORM을 참조하는 CLAUDE.md는 Claude의 이해를 적극적으로 해칩니다. CLAUDE.md를 살아있는 문서처럼 취급하세요.

**너무 긴 내용**: 5000단어짜리 CLAUDE.md는 부분적으로 무시될 것입니다. 500줄 이하로 유지하세요.

**'왜'의 부재**: Claude Code는 이유를 이해할 때 더 잘 지침을 따릅니다. "SQL 쿼리에서 절대 f-string을 사용하지 마라—이것이 SQL 인젝션 공격을 방지한다"가 단지 "SQL 쿼리에서 절대 f-string을 사용하지 마라"보다 낫습니다.
