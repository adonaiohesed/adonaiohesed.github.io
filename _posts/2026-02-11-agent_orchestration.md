---
title: Agent Orchestration Patterns
key: page-agent_orchestration
categories:
- AI & ML
- AI Agents & Automation
author: hyoeun
math: true
mathjax_autoNumber: true
image: "/assets/thumbnails/2026-02-11-agent_orchestration.png"
bilingual: true
date: 2026-02-11 09:00:00
---

## Agent Orchestration Patterns: Directing the AI Workforce

Orchestration is the discipline of coordinating multiple AI agents toward a shared goal. If multi-agent architecture is the *what*, orchestration is the *how*. Having built automated penetration test pipelines and threat intelligence aggregators, I've found that the orchestration layer is where most production systems succeed or fail.

### What is an Orchestrator?

An orchestrator is an agent (or a non-LLM controller) responsible for:

1. **Decomposing** a high-level goal into concrete subtasks.
2. **Assigning** subtasks to the appropriate specialized agents.
3. **Sequencing** tasks according to dependency constraints.
4. **Monitoring** progress and handling failures.
5. **Synthesizing** subagent outputs into a final result.

The orchestrator does *not* need to be an LLM. For deterministic workflows with fixed steps, a plain Python state machine is more reliable and cheaper. Use an LLM as the orchestrator only when the decomposition strategy itself needs to be adaptive.

### Orchestration Frameworks

**LangGraph**

LangGraph models agent workflows as directed graphs where nodes are agents and edges are state transitions. It gives you explicit control over the execution graph.

```python
from langgraph.graph import StateGraph, END

def recon_node(state):
    # Run recon agent, return updated state
    return {"findings": run_recon(state["target"])}

def analysis_node(state):
    return {"report": analyze(state["findings"])}

graph = StateGraph(dict)
graph.add_node("recon", recon_node)
graph.add_node("analysis", analysis_node)
graph.add_edge("recon", "analysis")
graph.add_edge("analysis", END)
graph.set_entry_point("recon")

app = graph.compile()
result = app.invoke({"target": "example.com"})
```

LangGraph shines for workflows where you need branching, cycles, and human-in-the-loop checkpoints. Its state is explicit and inspectable, which matters for debugging and auditing.

**AutoGen (Microsoft)**

AutoGen takes a conversation-centric approach. Agents communicate by sending messages to each other in a shared conversation thread. The framework handles turn-taking and termination conditions.

```python
import autogen

orchestrator = autogen.AssistantAgent("orchestrator", llm_config=llm_config)
analyst = autogen.AssistantAgent("analyst", llm_config=llm_config)
user_proxy = autogen.UserProxyAgent("user", human_input_mode="NEVER")

user_proxy.initiate_chat(orchestrator, message="Analyze this threat report: ...")
```

AutoGen is excellent for collaborative reasoning tasks where agents need to critique and refine each other's outputs. It's less suitable for strict pipeline workflows where you need deterministic control flow.

**CrewAI**

CrewAI provides a high-level abstraction where you define a "crew" of agents with roles, goals, and tools, then assign them tasks. It handles orchestration internally.

```python
from crewai import Agent, Task, Crew

threat_hunter = Agent(role="Threat Hunter", goal="Identify IOCs", tools=[...]
analyst = Agent(role="Security Analyst", goal="Assess impact", tools=[...])

task1 = Task(description="Hunt for IOCs in logs", agent=threat_hunter)
task2 = Task(description="Write incident report", agent=analyst)

crew = Crew(agents=[threat_hunter, analyst], tasks=[task1, task2])
result = crew.kickoff()
```

CrewAI's abstraction reduces boilerplate but sacrifices fine-grained control. Good for rapid prototyping.

### Orchestration Strategies

**Static Orchestration**

The task graph is defined at design time. The orchestrator follows a predetermined sequence. Predictable, fast, easy to test.

```
Plan:  recon → scan → exploit_check → report
```

Use when: the problem domain is well-understood and steps rarely change.

**Dynamic Orchestration**

The LLM orchestrator decides at runtime which agents to invoke next, based on intermediate results. Flexible but harder to debug and more expensive.

```
Goal: "Find vulnerabilities in target.com"
→ LLM decides: call recon_agent first
→ Based on recon results: call web_scanner and api_fuzzer in parallel
→ Based on findings: call exploit_verifier for critical items only
```

Use when: the task requires adaptive problem-solving that can't be fully specified upfront.

**Supervisor Pattern**

A dedicated supervisor agent monitors all other agents and can intervene—retrying failed agents, reassigning tasks, or escalating to a human.

```
[Supervisor]
    ├─ monitors [Agent A, B, C]
    ├─ retries failed agents (max 3x)
    └─ escalates to human if all retries exhausted
```

This is the pattern I recommend for production security automation where you cannot afford silent failures.

### State Management in Orchestration

The orchestration layer must own the canonical state of the workflow. Design your state schema explicitly:

```python
from dataclasses import dataclass
from typing import Optional, List

@dataclass
class WorkflowState:
    target: str
    recon_findings: Optional[dict] = None
    vulnerabilities: Optional[List[dict]] = None
    report: Optional[str] = None
    errors: List[str] = field(default_factory=list)
    current_step: str = "recon"
    iteration_count: int = 0
```

Every agent reads from and writes to this state. The orchestrator checks `current_step` and `iteration_count` to prevent infinite loops.

### Human-in-the-Loop

Not all decisions should be delegated to agents. Build explicit human approval gates for:

* Actions with irreversible consequences (sending emails, deploying code, executing exploits in production)
* Results that fall below a confidence threshold
* Escalations when agents disagree

```python
def needs_human_review(state: WorkflowState) -> bool:
    return (
        state.vulnerabilities and
        any(v["severity"] == "critical" for v in state.vulnerabilities)
    )
```

### Observability

An orchestrated multi-agent system is a black box without proper instrumentation. Minimum requirements:

* **Trace each agent call**: log inputs, outputs, latency, token usage.
* **Persist workflow state**: so you can resume after failures.
* **Alert on anomalies**: unusually high token usage, repeated failures, long-running tasks.

Tools like LangSmith, Weights & Biases, or even a simple structured log to S3 will save you hours of debugging.

---

## 에이전트 오케스트레이션 패턴: AI 인력을 지휘하는 방법

오케스트레이션은 공유 목표를 향해 여러 AI 에이전트를 조율하는 학문입니다. 멀티 에이전트 아키텍처가 *무엇*이라면, 오케스트레이션은 *어떻게*입니다. 자동화된 침투 테스트 파이프라인과 위협 인텔리전스 집계기를 구축하면서, 오케스트레이션 레이어가 대부분의 프로덕션 시스템이 성공하거나 실패하는 곳임을 발견했습니다.

### 오케스트레이터란 무엇인가?

오케스트레이터는 다음을 담당하는 에이전트(또는 LLM이 아닌 컨트롤러)입니다:

1. 고수준 목표를 구체적인 서브태스크로 **분해**하기.
2. 적절한 전문화된 에이전트에게 서브태스크를 **할당**하기.
3. 의존성 제약에 따라 태스크를 **순서 배치**하기.
4. 진행 상황을 **모니터링**하고 실패를 처리하기.
5. 서브에이전트 출력을 최종 결과로 **종합**하기.

오케스트레이터가 반드시 LLM일 필요는 없습니다. 고정된 단계를 가진 결정론적 워크플로우에서는, 일반 Python 상태 기계가 더 신뢰할 수 있고 비용이 저렴합니다. 분해 전략 자체가 적응적이어야 할 때만 LLM을 오케스트레이터로 사용하세요.

### 오케스트레이션 프레임워크

**LangGraph**

LangGraph는 에이전트 워크플로우를 노드가 에이전트이고 엣지가 상태 전환인 방향 그래프로 모델링합니다. 실행 그래프에 대한 명시적 제어를 제공합니다.

LangGraph는 분기, 사이클, 인간 참여 체크포인트가 필요한 워크플로우에서 빛을 발합니다. 상태가 명시적이고 검사 가능하여 디버깅과 감사에 중요합니다.

**AutoGen (Microsoft)**

AutoGen은 대화 중심적 접근법을 취합니다. 에이전트들이 공유 대화 스레드에서 서로에게 메시지를 보내 통신합니다. 프레임워크가 턴 테이킹과 종료 조건을 처리합니다.

AutoGen은 에이전트들이 서로의 출력을 비판하고 개선해야 하는 협업적 추론 태스크에 뛰어납니다. 결정론적 제어 흐름이 필요한 엄격한 파이프라인 워크플로우에는 덜 적합합니다.

**CrewAI**

CrewAI는 역할, 목표, 도구를 가진 에이전트 "크루"를 정의한 다음 태스크를 할당하는 고수준 추상화를 제공합니다. 내부적으로 오케스트레이션을 처리합니다.

CrewAI의 추상화는 보일러플레이트를 줄이지만 세밀한 제어를 희생합니다. 빠른 프로토타이핑에 좋습니다.

### 오케스트레이션 전략

**정적 오케스트레이션 (Static Orchestration)**

태스크 그래프가 설계 시점에 정의됩니다. 오케스트레이터가 사전 결정된 순서를 따릅니다. 예측 가능하고 빠르며 테스트하기 쉽습니다.

사용 시점: 문제 도메인이 잘 이해되어 있고 단계가 거의 변하지 않을 때.

**동적 오케스트레이션 (Dynamic Orchestration)**

LLM 오케스트레이터가 중간 결과를 기반으로 런타임에 다음에 어떤 에이전트를 호출할지 결정합니다. 유연하지만 디버그하기 더 어렵고 비용이 더 많이 듭니다.

사용 시점: 태스크가 사전에 완전히 명시할 수 없는 적응적 문제 해결이 필요할 때.

**수퍼바이저 패턴 (Supervisor Pattern)**

전용 수퍼바이저 에이전트가 다른 모든 에이전트를 모니터링하고 개입할 수 있습니다—실패한 에이전트를 재시도하거나, 태스크를 재할당하거나, 인간에게 에스컬레이션합니다.

조용한 실패를 감당할 수 없는 프로덕션 보안 자동화에 추천하는 패턴입니다.

### 오케스트레이션의 상태 관리

오케스트레이션 레이어는 워크플로우의 정규 상태를 소유해야 합니다. 상태 스키마를 명시적으로 설계하세요. 모든 에이전트가 이 상태를 읽고 씁니다. 오케스트레이터는 무한 루프를 방지하기 위해 `current_step`과 `iteration_count`를 확인합니다.

### 인간 참여 루프 (Human-in-the-Loop)

모든 결정이 에이전트에게 위임되어서는 안 됩니다. 다음에 대한 명시적 인간 승인 게이트를 구축하세요:

* 돌이킬 수 없는 결과를 가진 행동 (이메일 발송, 코드 배포, 프로덕션에서 익스플로잇 실행)
* 신뢰도 임계값 아래로 떨어지는 결과
* 에이전트가 동의하지 않을 때의 에스컬레이션

### 관찰 가능성 (Observability)

적절한 계측 없이 오케스트레이션된 멀티 에이전트 시스템은 블랙박스입니다. 최소 요구사항:

* **각 에이전트 호출 추적**: 입력, 출력, 지연 시간, 토큰 사용량 로깅.
* **워크플로우 상태 유지**: 실패 후 재개할 수 있도록.
* **이상 징후 알림**: 비정상적으로 높은 토큰 사용량, 반복적인 실패, 장시간 실행 태스크.

LangSmith, Weights & Biases, 또는 S3에 대한 단순한 구조화된 로그 같은 도구들이 디버깅 시간을 절약해줄 것입니다.
