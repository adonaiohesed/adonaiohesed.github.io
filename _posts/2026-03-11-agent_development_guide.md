---
title: Building AI Agents - Architecture and Best Practices
key: page-agent_development_guide
categories:
- AI & ML
- AI Agents & Automation
author: hyoeun
math: true
mathjax_autoNumber: true
image: "/assets/thumbnails/2026-03-11-agent_development_guide.png"
bilingual: true
date: 2026-03-11 09:00:00
---

## Building AI Agents: Architecture and Best Practices

Building an AI agent for the first time feels deceptively simple. A few tool definitions, a system prompt, and a loop. But agents that survive contact with production look very different from prototypes. This guide distills lessons from building security automation agents that run in real pipelines—where failures have real consequences.

### Start with the Problem, Not the Architecture

Before writing a single line of agent code, answer these questions:

1. **What is the exact task?** Define it precisely. "Security analysis" is not a task. "Given a GitHub pull request diff, identify vulnerabilities using OWASP Top 10 as a checklist and output structured JSON findings" is a task.

2. **What does success look like?** How will you know the agent is working correctly? Define your evaluation criteria before you build.

3. **What can go wrong?** List the failure modes. What happens if an LLM call returns garbage? What if a tool call times out? What if the agent loops indefinitely?

4. **Does this actually need an LLM?** If the logic can be expressed as deterministic rules, use deterministic code. LLMs are powerful but non-deterministic and expensive. Maximize their use on tasks that require judgment.

### Tool Design: The Most Important Architectural Decision

Tools are the agent's interface to the world. Poorly designed tools are the most common reason agents fail.

**Principles for tool design:**

**Atomic**: Each tool should do exactly one thing. Don't build a tool called `analyze_and_report`—split it into `analyze` and `generate_report`. This gives the LLM finer control and makes debugging easier.

**Idempotent where possible**: A tool that can be safely called twice with the same arguments is much easier to work with. Design for retry.

**Well-described**: The docstring/description is read by the LLM, not by you. Write it for an intelligent reader who doesn't know your codebase.

```python
# Bad tool description
@tool
def scan(target: str) -> str:
    """Scan target."""
    ...

# Good tool description
@tool
def run_nmap_port_scan(target: str, ports: str = "1-1000") -> str:
    """
    Run an nmap TCP SYN scan against the target host to identify open ports and services.

    Args:
        target: IP address or hostname to scan (e.g., "192.168.1.1" or "example.com")
        ports: Port range to scan (e.g., "80,443" or "1-1000" or "1-65535")

    Returns:
        JSON string containing: open_ports (list), services (dict mapping port to service name),
        scan_timestamp, and raw_output.

    Note: Requires nmap installed. Only use on systems you have permission to scan.
    """
    ...
```

**Fail loudly**: When a tool fails, return a clear error message that tells the LLM what went wrong and what it should try instead. Don't return empty strings or None.

```python
@tool
def fetch_cve_details(cve_id: str) -> str:
    """..."""
    try:
        response = requests.get(f"https://nvd.nist.gov/...", timeout=10)
        response.raise_for_status()
        return json.dumps(response.json())
    except requests.Timeout:
        return f"ERROR: NVD API timed out for {cve_id}. Try again or use an alternative source."
    except requests.HTTPError as e:
        return f"ERROR: NVD API returned {e.response.status_code} for {cve_id}. The CVE may not exist."
    except Exception as e:
        return f"ERROR: Unexpected failure fetching {cve_id}: {str(e)}"
```

### System Prompt Engineering

The system prompt is your primary control surface for agent behavior. Treat it as code, not as documentation.

**Structure your system prompt explicitly:**

```
You are a [ROLE]. Your purpose is [PRECISE OBJECTIVE].

## Constraints
- [Hard rules the agent must never violate]

## Process
1. [Step-by-step process to follow]
2. [...]

## Output Format
[Exact schema of expected output]

## What NOT to Do
- [Common mistakes you've observed and want to prevent]
```

**Include examples**: Few-shot examples in the system prompt are often more effective than lengthy instructions. Show the agent what a good output looks like.

**Be explicit about uncertainty**: Tell the agent what to do when it doesn't know: "If you cannot determine X with confidence, say 'UNCERTAIN: [reason]' rather than guessing."

### State Machine Design

Well-designed agents have explicit state machines. This prevents ambiguity about what should happen next and makes the agent's behavior predictable.

```python
from enum import Enum
from dataclasses import dataclass, field
from typing import Optional, List

class AgentState(Enum):
    INITIALIZING = "initializing"
    PLANNING = "planning"
    EXECUTING = "executing"
    EVALUATING = "evaluating"
    REPORTING = "reporting"
    COMPLETE = "complete"
    FAILED = "failed"

@dataclass
class SecurityAuditAgent:
    target: str
    state: AgentState = AgentState.INITIALIZING
    plan: List[str] = field(default_factory=list)
    findings: List[dict] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    iteration: int = 0
    max_iterations: int = 20

    def step(self) -> AgentState:
        """Execute one state transition."""
        if self.iteration >= self.max_iterations:
            self.state = AgentState.FAILED
            self.errors.append(f"Exceeded max iterations ({self.max_iterations})")
            return self.state

        self.iteration += 1

        if self.state == AgentState.INITIALIZING:
            self.state = AgentState.PLANNING
        elif self.state == AgentState.PLANNING:
            self._execute_planning()
        elif self.state == AgentState.EXECUTING:
            self._execute_step()
        elif self.state == AgentState.EVALUATING:
            self._evaluate_results()
        elif self.state == AgentState.REPORTING:
            self._generate_report()
            self.state = AgentState.COMPLETE

        return self.state
```

The `max_iterations` guard is non-negotiable. Every agent loop must have a hard stop.

### Testing Strategy

Agent testing is harder than unit testing because agents are non-deterministic. Use a layered approach:

**Layer 1: Tool unit tests** (deterministic)
Test each tool independently with mock inputs. Verify output format, error handling, edge cases.

**Layer 2: Agent behavior tests** (with recorded fixtures)
Record real LLM outputs for a set of inputs. Replay them in tests to verify that your agent logic handles them correctly. This avoids API calls in CI while testing realistic behavior.

**Layer 3: End-to-end evaluation** (with LLM judge)
For production agents, run periodic E2E tests against a ground-truth dataset. Use a separate LLM call to evaluate whether the agent's output is correct.

```python
def evaluate_security_finding(finding: dict, expected: dict, llm) -> float:
    """Use LLM to score the quality of a security finding (0.0 - 1.0)."""
    prompt = f"""
    Expected finding: {json.dumps(expected)}
    Actual finding: {json.dumps(finding)}

    Score the actual finding from 0.0 to 1.0 based on:
    - Accuracy (does it identify the correct vulnerability?)
    - Completeness (does it cover all relevant details?)
    - Actionability (does it provide useful remediation guidance?)

    Return only a JSON object: {{"score": 0.0-1.0, "reasoning": "..."}}
    """
    # ...
```

### Deployment Considerations

**Rate limiting**: Implement token-per-minute and requests-per-minute tracking. An agent loop that hits rate limits will either stall or produce garbage outputs.

**Cost controls**: Set per-run and per-day token budgets. Alert when approaching limits.

**Observability**: Every LLM call, tool invocation, and state transition should be logged with:
- Timestamp
- Input tokens / output tokens
- Latency
- Tool name (if applicable)
- State before and after

**Graceful degradation**: If a non-critical tool fails, can the agent continue with reduced capability rather than failing completely?

---

## AI 에이전트 구축: 아키텍처와 모범 사례

처음 AI 에이전트를 구축하는 것은 기만적으로 간단해 보입니다. 몇 가지 도구 정의, 시스템 프롬프트, 그리고 루프. 하지만 프로덕션을 살아남은 에이전트는 프로토타입과 매우 다르게 보입니다. 이 가이드는 실패가 실제 결과를 갖는 실제 파이프라인에서 실행되는 보안 자동화 에이전트 구축의 교훈을 담습니다.

### 아키텍처가 아닌 문제부터 시작하라

에이전트 코드를 한 줄 작성하기 전에 다음 질문에 답하세요:

1. **정확한 태스크는 무엇인가?** 정밀하게 정의하세요. "보안 분석"은 태스크가 아닙니다. "GitHub pull request diff가 주어지면 OWASP Top 10을 체크리스트로 사용하여 취약점을 식별하고 구조화된 JSON 결과를 출력하라"가 태스크입니다.
2. **성공은 어떤 모습인가?** 에이전트가 올바르게 작동하고 있다는 것을 어떻게 알 수 있나요? 구축 전에 평가 기준을 정의하세요.
3. **무엇이 잘못될 수 있는가?** 실패 모드를 나열하세요.
4. **실제로 LLM이 필요한가?** 로직이 결정론적 규칙으로 표현될 수 있다면 결정론적 코드를 사용하세요.

### 도구 설계: 가장 중요한 아키텍처 결정

도구는 에이전트의 세계 인터페이스입니다. 잘못 설계된 도구는 에이전트 실패의 가장 일반적인 이유입니다.

**도구 설계 원칙:**

* **원자적**: 각 도구는 정확히 하나의 일을 해야 합니다.
* **가능하면 멱등적**: 같은 인수로 두 번 안전하게 호출할 수 있는 도구는 작업하기 훨씬 쉽습니다.
* **잘 설명된**: docstring/description은 LLM이 읽는 것입니다. 코드베이스를 모르는 지능적인 독자를 위해 작성하세요.
* **큰 소리로 실패**: 도구가 실패하면 LLM에게 무엇이 잘못되었는지, 대신 무엇을 시도해야 하는지 알려주는 명확한 오류 메시지를 반환하세요.

### 시스템 프롬프트 엔지니어링

시스템 프롬프트는 에이전트 동작을 위한 주요 제어 표면입니다. 문서가 아닌 코드로 취급하세요.

**시스템 프롬프트를 명시적으로 구조화하세요:**
- 역할과 정확한 목적
- 절대 위반하면 안 되는 하드 규칙
- 따라야 할 단계별 프로세스
- 예상 출력의 정확한 스키마
- 불확실성 처리: "확신 없이 X를 결정할 수 없다면 추측하지 말고 'UNCERTAIN: [이유]'라고 말하라"

### 상태 기계 설계

잘 설계된 에이전트는 명시적인 상태 기계를 가집니다. 다음에 무엇이 일어나야 하는지에 대한 모호성을 방지하고 에이전트 동작을 예측 가능하게 만듭니다.

`max_iterations` 가드는 협상 불가입니다. 모든 에이전트 루프에는 반드시 하드 정지가 있어야 합니다.

### 테스트 전략

에이전트 테스팅은 에이전트가 비결정론적이기 때문에 단위 테스팅보다 어렵습니다. 레이어드 접근법을 사용하세요:

* **레이어 1: 도구 단위 테스트** (결정론적) - 각 도구를 모의 입력으로 독립적으로 테스트합니다.
* **레이어 2: 에이전트 동작 테스트** (기록된 픽스처 사용) - 실제 LLM 출력을 기록하고 재생하여 API 호출 없이 CI에서 테스트합니다.
* **레이어 3: 엔드-투-엔드 평가** (LLM 심판 사용) - 기준 데이터셋에 대한 주기적 E2E 테스트를 실행하고 별도 LLM 호출로 결과를 평가합니다.

### 배포 고려사항

* **속도 제한**: 분당 토큰 및 분당 요청 추적을 구현하세요.
* **비용 제어**: 실행당 및 일당 토큰 예산을 설정하세요.
* **관찰 가능성**: 모든 LLM 호출, 도구 호출, 상태 전환을 타임스탬프, 토큰 수, 지연 시간과 함께 로깅하세요.
* **우아한 성능 저하**: 비핵심 도구가 실패하면, 에이전트가 완전히 실패하는 대신 감소된 능력으로 계속할 수 있는가?
