---
title: Claude Code as an AI Development Agent
key: page-claude_code_agent
categories:
- AI & ML
- AI Agents & Automation
author: hyoeun
math: true
mathjax_autoNumber: true
image: "/assets/thumbnails/2026-03-04-claude_code_agent.png"
bilingual: true
date: 2026-03-04 09:00:00
---

## Claude Code as an AI Development Agent

I've used many AI coding assistants. Copilot is fast. ChatGPT is conversational. But Claude Code is the first tool that genuinely changed how I work at the architectural level—not by autocompleting lines, but by becoming a peer that understands context, executes tasks autonomously, and can be configured to behave exactly as I need.

This post is a practical guide to Claude Code: what it is, how it works as an agent, and how to get the most out of it.

### What Claude Code Actually Is

Claude Code is Anthropic's CLI for Claude. It's not a plugin—it runs in your terminal as a first-class process with access to your filesystem, shell, and development environment.

The key insight: Claude Code is an *agentic* tool. It can:

* Read any file in your project without you pasting it
* Execute shell commands and observe their output
* Make multi-file edits across your codebase
* Run tests and iterate based on failures
* Search the web and read documentation
* Spawn subagents for parallel workstreams

This is fundamentally different from a chatbot that gives you code suggestions to paste. Claude Code acts.

### Installation and Basic Configuration

```bash
# Install
npm install -g @anthropic-ai/claude-code

# Launch in your project directory
cd /your/project
claude
```

On first launch, it indexes your project and reads your `CLAUDE.md` file if one exists (more on that later).

### The Agent Loop

When you give Claude Code a task, it enters an agentic loop:

```
User request
     ↓
Plan: "I'll need to read X, modify Y, run tests"
     ↓
Execute: Read X → Analyze → Edit Y → Run tests
     ↓
Observe: Tests fail at line 47
     ↓
Reason: "The import is wrong because..."
     ↓
Act: Fix import, re-run tests
     ↓
Observe: Tests pass
     ↓
Report: "Done. Changed import in Y, all 23 tests pass."
```

Each step is visible. You see what Claude reads, what it edits, what commands it runs. This transparency is not accidental—it's how you maintain oversight of an autonomous system.

### Permission Modes

Claude Code operates in different permission modes depending on how much autonomy you grant:

**Default mode**: Claude asks before writing files or running commands. Suitable for unfamiliar codebases.

**Auto-approve mode** (`--dangerously-skip-permissions`): Claude acts without asking. Use only in sandboxed environments you understand well—CI pipelines, Docker containers, throwaway VMs.

**Selective auto-approve**: Configure `settings.json` to auto-approve specific tools (e.g., read and grep but not write or execute).

```json
{
  "permissions": {
    "allow": ["Read", "Glob", "Grep", "Bash(git status)", "Bash(npm test)"],
    "deny": ["Bash(rm *)", "Bash(curl *)"]
  }
}
```

### Slash Commands

Claude Code has built-in slash commands that give you quick access to common workflows:

| Command | Description |
|---|---|
| `/help` | Show all commands |
| `/commit` | Generate a commit message and commit staged changes |
| `/review-pr` | Review a pull request |
| `/model` | Switch between Claude models |
| `/clear` | Clear conversation context |
| `/memory` | Inspect and manage Claude's memory |

You can also create custom slash commands. More on that in the SKILL.md post.

### The Agent SDK

For building your *own* agents on top of Claude Code's infrastructure, Anthropic provides the Claude Agent SDK:

```python
import anthropic

client = anthropic.Anthropic()

# Simple tool-use agent
response = client.messages.create(
    model="claude-opus-4-6",
    max_tokens=4096,
    tools=[
        {
            "name": "read_file",
            "description": "Read a file from the filesystem",
            "input_schema": {
                "type": "object",
                "properties": {
                    "path": {"type": "string", "description": "File path to read"}
                },
                "required": ["path"]
            }
        }
    ],
    messages=[
        {"role": "user", "content": "Read the main.py file and identify any security vulnerabilities."}
    ]
)

# Handle tool calls
for block in response.content:
    if block.type == "tool_use":
        if block.name == "read_file":
            file_content = open(block.input["path"]).read()
            # Continue with tool result...
```

The Agent SDK enables you to build custom agents that leverage Claude's reasoning while integrating with your own tooling.

### Multi-Agent with Claude Code

Claude Code itself can spawn subagents via the `Agent` tool. This is the mechanism behind parallel workstreams:

```
# In a CLAUDE.md or skill, you can direct Claude to:
# "Use the Agent tool to run these three analyses in parallel"

User: "Audit my entire codebase for security issues"
     ↓
Claude Code [Orchestrator]:
├─ Agent 1: "Scan Python files for injection vulnerabilities"
├─ Agent 2: "Check for hardcoded secrets and credentials"
└─ Agent 3: "Review authentication and authorization patterns"
     ↓
Synthesize findings into unified report
```

Each subagent runs with its own context window, enabling analysis of large codebases that would overflow a single context.

### Practical Workflows for Security Engineers

**Vulnerability review:**
```
"Review this PR diff for security vulnerabilities. Focus on:
SQL injection, XSS, authentication bypasses, and improper
privilege escalation. Output a structured finding report."
```

**Security test generation:**
```
"Write pytest security tests for the authentication module at
src/auth/. Cover: password hashing correctness, session fixation,
brute force protection, and JWT validation edge cases."
```

**Threat modeling:**
```
"Read the architecture docs in /docs/architecture/ and generate
a threat model. Use STRIDE methodology. Output as a markdown
table with: threat, component, likelihood (H/M/L), impact (H/M/L),
mitigation."
```

**Incident analysis:**
```
"Analyze the log files in /var/log/app/ from the past 24 hours.
Identify any anomalous patterns, failed authentication attempts,
or potential security events. Summarize with timestamps."
```

### What Claude Code Is Not

* **Not a replacement for code review**: Claude Code can catch many issues but it misses context that only a human with domain knowledge has.
* **Not infallible**: It makes mistakes. Always run tests and review diffs before merging.
* **Not a silver bullet for legacy code**: On large, undocumented codebases, its effectiveness decreases. Invest time in CLAUDE.md documentation for best results.

---

## 개발 AI 에이전트로서의 Claude Code

많은 AI 코딩 어시스턴트를 사용해봤습니다. Copilot은 빠릅니다. ChatGPT는 대화적입니다. 하지만 Claude Code는 아키텍처 수준에서 작업 방식을 진정으로 바꾼 첫 번째 도구입니다—줄을 자동완성하는 것이 아니라, 컨텍스트를 이해하고 자율적으로 태스크를 실행하며 필요에 따라 정확하게 동작하도록 구성할 수 있는 동료가 됩니다.

### Claude Code란 실제로 무엇인가

Claude Code는 Anthropic의 Claude용 CLI입니다. 플러그인이 아닙니다—파일시스템, 셸, 개발 환경에 접근할 수 있는 일급 프로세스로 터미널에서 실행됩니다.

핵심 인사이트: Claude Code는 *에이전트적* 도구입니다. 다음을 할 수 있습니다:

* 파일을 붙여넣지 않고도 프로젝트의 모든 파일 읽기
* 셸 명령을 실행하고 출력 관찰
* 코드베이스 전반에 걸쳐 멀티 파일 편집
* 테스트를 실행하고 실패를 기반으로 반복
* 웹 검색 및 문서 읽기
* 병렬 작업 흐름을 위한 서브에이전트 생성

이것은 붙여넣을 코드 제안을 주는 챗봇과 근본적으로 다릅니다. Claude Code는 행동합니다.

### 에이전트 루프

Claude Code에게 태스크를 주면, 에이전트 루프에 진입합니다:

```
사용자 요청
     ↓
계획: "X를 읽고 Y를 수정하고 테스트를 실행해야 합니다"
     ↓
실행: X 읽기 → 분석 → Y 편집 → 테스트 실행
     ↓
관찰: 47번 줄에서 테스트 실패
     ↓
추론: "임포트가 잘못되었습니다. 왜냐하면..."
     ↓
행동: 임포트 수정, 테스트 재실행
     ↓
관찰: 테스트 통과
     ↓
보고: "완료. Y의 임포트를 변경했으며 23개 테스트 모두 통과합니다."
```

각 단계가 보입니다. Claude가 무엇을 읽고, 무엇을 편집하고, 어떤 명령을 실행하는지 볼 수 있습니다. 이 투명성은 우연이 아닙니다—자율 시스템에 대한 감독을 유지하는 방법입니다.

### 권한 모드

Claude Code는 얼마나 많은 자율성을 부여하느냐에 따라 다른 권한 모드로 작동합니다:

* **기본 모드**: Claude가 파일을 쓰거나 명령을 실행하기 전에 묻습니다. 익숙하지 않은 코드베이스에 적합합니다.
* **자동 승인 모드**: Claude가 묻지 않고 행동합니다. 샌드박스된 환경에서만 사용하세요—CI 파이프라인, Docker 컨테이너, 일회용 VM.
* **선택적 자동 승인**: `settings.json`에서 특정 도구를 자동 승인하도록 구성합니다.

### 슬래시 명령어

Claude Code는 일반적인 워크플로우에 빠른 접근을 제공하는 내장 슬래시 명령어를 가집니다: `/commit`, `/review-pr`, `/model`, `/clear`, `/memory` 등. 커스텀 슬래시 명령어도 생성할 수 있습니다.

### 보안 엔지니어를 위한 실용적 워크플로우

**취약점 검토:**
"이 PR diff에서 보안 취약점을 검토하세요. SQL 인젝션, XSS, 인증 우회, 부적절한 권한 상승에 집중하세요."

**보안 테스트 생성:**
"src/auth/의 인증 모듈에 대한 pytest 보안 테스트를 작성하세요. 비밀번호 해싱 정확성, 세션 고정, 무차별 대입 보호, JWT 유효성 검사 엣지 케이스를 다루세요."

**위협 모델링:**
"/docs/architecture/의 아키텍처 문서를 읽고 위협 모델을 생성하세요. STRIDE 방법론을 사용하세요."

**인시던트 분석:**
"/var/log/app/의 지난 24시간 로그 파일을 분석하세요. 비정상적 패턴, 실패한 인증 시도, 또는 잠재적 보안 이벤트를 식별하세요."

### Claude Code가 아닌 것

* **코드 리뷰의 대체품이 아닙니다**: Claude Code는 많은 문제를 잡을 수 있지만 도메인 지식을 가진 인간만이 가진 컨텍스트를 놓칩니다.
* **무결하지 않습니다**: 실수를 합니다. 항상 테스트를 실행하고 머지 전에 diff를 검토하세요.
* **레거시 코드의 만능 해결책이 아닙니다**: 크고 문서화되지 않은 코드베이스에서는 효과가 줄어듭니다. 최선의 결과를 위해 CLAUDE.md 문서에 시간을 투자하세요.
