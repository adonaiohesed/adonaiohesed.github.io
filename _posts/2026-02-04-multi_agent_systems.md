---
title: Multi-Agent Systems
key: page-multi_agent_systems
categories:
- AI & ML
- AI Agents & Automation
author: hyoeun
math: true
mathjax_autoNumber: true
image: "/assets/thumbnails/2026-02-04-multi_agent_systems.png"
bilingual: true
date: 2026-02-04 09:00:00
---

## Multi-Agent Systems: Why One Agent Is Never Enough

After spending months building and testing AI agents in security automation pipelines, I kept running into the same wall: a single agent trying to do everything becomes brittle, expensive, and hard to reason about. The shift to multi-agent thinking changed how I approach every AI-driven workflow.

### The Single Agent Bottleneck

A single LLM agent faces hard constraints:

* **Context window limits**: A long security scan, code review, and report generation will overflow any context window if handled sequentially by one agent.
* **Specialization vs. generalization tradeoff**: An agent good at reasoning over CVSS scores is not necessarily good at writing executive summaries.
* **Fault isolation**: When one task fails, everything fails. There is no separation of concerns.

Multi-agent systems solve these problems by decomposing complex tasks across specialized, coordinated agents.

### Core Architectural Patterns

**1. Sequential Pipeline**

Agents process tasks in a chain. Each agent's output becomes the next agent's input.

```
[Reconnaissance Agent] → [Vulnerability Analysis Agent] → [Report Generation Agent]
```

Best for: linear workflows where each stage depends strictly on the prior stage's output.

**2. Parallel Fan-Out**

A coordinator dispatches independent subtasks to multiple agents simultaneously, then aggregates results.

```
                  ┌─ [Port Scan Agent]
[Coordinator] ──── ├─ [DNS Enum Agent]    → [Aggregator]
                  └─ [OSINT Agent]
```

Best for: reconnaissance, where multiple data sources can be queried concurrently. Reduces wall-clock time dramatically.

**3. Hierarchical (Orchestrator–Subagent)**

A high-level orchestrator decomposes goals into subtasks and delegates to specialized subagents. The orchestrator maintains global state and resolves conflicts.

```
[Orchestrator]
    ├─ [Offensive Security Agent]
    │       ├─ [Web Scanner Subagent]
    │       └─ [API Fuzzer Subagent]
    └─ [Reporting Agent]
```

Best for: complex, open-ended workflows where the decomposition strategy itself needs to be dynamic.

**4. Debate / Critique Pattern**

Two or more agents produce competing outputs; a judge agent selects or merges the best result. Particularly useful when accuracy of a single answer matters more than speed.

```
[Generator Agent A] ─┐
                     ├─ [Judge Agent] → Final Output
[Generator Agent B] ─┘
```

### Communication Between Agents

Agents communicate through one of three mechanisms:

| Mechanism | Description | When to Use |
|---|---|---|
| Shared memory / state store | Agents read/write to a shared key-value store (Redis, in-memory dict) | Low-latency, same-host deployments |
| Message passing | Agents communicate via queues (Kafka, RabbitMQ, simple function calls) | Distributed, async workflows |
| Structured tool calls | Orchestrator calls subagents as tools with typed inputs/outputs | LangChain / Claude SDK agent graphs |

In most Claude SDK implementations, subagents are invoked as tools. The orchestrator's LLM decides which subagent to call and with what arguments, making the graph both flexible and auditable.

### State Management

Multi-agent systems are stateful by nature. Each agent needs to know:

1. **Global task state**: What is the overall objective? What has been completed?
2. **Local task state**: What is this specific agent's current subtask?
3. **Shared artifacts**: Files, scan results, intermediate outputs that multiple agents need.

A common pattern is a **shared scratchpad**—a structured document or database that any agent can read and append to. The orchestrator enforces read/write access rules.

### Failure Modes and Mitigation

Multi-agent systems introduce new failure modes that single-agent systems don't have:

* **Cascading failures**: A subagent failure can stall the entire pipeline if not handled gracefully. Always wrap subagent calls in try/except with fallback strategies.
* **Conflicting outputs**: Two agents may produce contradictory results. The orchestrator needs explicit conflict resolution logic, not just concatenation.
* **Runaway loops**: An orchestrator that re-evaluates indefinitely must have a hard iteration cap.
* **Prompt injection propagation**: Output from one agent (e.g., web scraping) can contain adversarial instructions that poison a downstream agent. Sanitize all inter-agent data.

### When Multi-Agent is the Wrong Choice

Not every problem benefits from multiple agents:

* If the task fits comfortably within a single context window with no parallelism benefit, one agent is simpler and cheaper.
* If latency is critical and the tasks are inherently sequential, pipeline overhead may outweigh benefits.
* For prototyping, start with a single agent and extract subagents only when you hit real constraints.

Multi-agent architecture is a powerful tool, but it is also a complexity multiplier. Treat it as a scaling decision, not a default.

---

## 멀티 에이전트 시스템: 왜 하나의 에이전트로는 부족한가

보안 자동화 파이프라인에서 AI 에이전트를 수개월간 구축하고 테스트하면서, 반복적으로 같은 한계에 부딪혔습니다. 모든 것을 처리하려는 단일 에이전트는 취약하고, 비용이 많이 들며, 추론하기 어려워집니다. 멀티 에이전트적 사고방식으로의 전환은 AI 기반 워크플로우에 접근하는 방식을 근본적으로 바꾸었습니다.

### 단일 에이전트의 병목 현상

단일 LLM 에이전트는 명확한 제약에 직면합니다:

* **컨텍스트 윈도우 한계**: 보안 스캔, 코드 리뷰, 보고서 생성을 하나의 에이전트가 순차적으로 처리하면 어떤 컨텍스트 윈도우도 초과합니다.
* **전문화 vs. 일반화 트레이드오프**: CVSS 점수 추론에 강한 에이전트가 경영진 요약본 작성에도 강하지는 않습니다.
* **장애 격리**: 하나의 태스크가 실패하면 전체가 실패합니다. 관심사의 분리가 없습니다.

멀티 에이전트 시스템은 복잡한 태스크를 전문화되고 조율된 에이전트들로 분해함으로써 이러한 문제들을 해결합니다.

### 핵심 아키텍처 패턴

**1. 순차 파이프라인 (Sequential Pipeline)**

에이전트들이 체인 형태로 태스크를 처리합니다. 각 에이전트의 출력이 다음 에이전트의 입력이 됩니다.

```
[정찰 에이전트] → [취약점 분석 에이전트] → [보고서 생성 에이전트]
```

최적 사용 사례: 각 단계가 이전 단계의 출력에 엄격히 의존하는 선형 워크플로우.

**2. 병렬 팬아웃 (Parallel Fan-Out)**

코디네이터가 독립적인 서브태스크들을 여러 에이전트에 동시에 배분한 후 결과를 집계합니다.

최적 사용 사례: 여러 데이터 소스를 동시에 쿼리할 수 있는 정찰 작업. 전체 소요 시간을 획기적으로 단축합니다.

**3. 계층형 (오케스트레이터–서브에이전트)**

고수준 오케스트레이터가 목표를 서브태스크로 분해하고 전문 서브에이전트에 위임합니다. 오케스트레이터는 전역 상태를 유지하고 충돌을 해결합니다.

최적 사용 사례: 분해 전략 자체가 동적이어야 하는 복잡하고 개방형 워크플로우.

**4. 토론/비평 패턴 (Debate / Critique Pattern)**

두 개 이상의 에이전트가 경쟁하는 출력을 생성하고, 심판 에이전트가 최선의 결과를 선택하거나 병합합니다. 속도보다 정확성이 더 중요한 경우에 특히 유용합니다.

### 에이전트 간 통신

에이전트들은 세 가지 메커니즘 중 하나를 통해 통신합니다:

| 메커니즘 | 설명 | 사용 시점 |
|---|---|---|
| 공유 메모리 / 상태 저장소 | 에이전트들이 공유 키-값 저장소(Redis, 인메모리 딕셔너리)를 읽고 씁니다 | 저지연, 동일 호스트 배포 |
| 메시지 패싱 | 에이전트들이 큐(Kafka, RabbitMQ, 단순 함수 호출)를 통해 통신합니다 | 분산, 비동기 워크플로우 |
| 구조화된 도구 호출 | 오케스트레이터가 서브에이전트를 타입화된 입출력을 가진 도구로 호출합니다 | LangChain / Claude SDK 에이전트 그래프 |

대부분의 Claude SDK 구현에서 서브에이전트는 도구로 호출됩니다. 오케스트레이터의 LLM이 어떤 서브에이전트를 어떤 인수로 호출할지 결정하여, 그래프를 유연하고 감사 가능하게 만듭니다.

### 상태 관리

멀티 에이전트 시스템은 본질적으로 상태가 있습니다. 각 에이전트는 다음을 알아야 합니다:

1. **전역 태스크 상태**: 전체 목표는 무엇인가? 무엇이 완료되었는가?
2. **로컬 태스크 상태**: 이 특정 에이전트의 현재 서브태스크는 무엇인가?
3. **공유 아티팩트**: 여러 에이전트가 필요로 하는 파일, 스캔 결과, 중간 출력물.

일반적인 패턴은 **공유 스크래치패드**입니다—어떤 에이전트든 읽고 추가할 수 있는 구조화된 문서 또는 데이터베이스. 오케스트레이터가 읽기/쓰기 접근 규칙을 강제합니다.

### 실패 모드와 완화 방안

멀티 에이전트 시스템은 단일 에이전트 시스템에는 없는 새로운 실패 모드를 도입합니다:

* **연쇄 실패**: 서브에이전트 실패가 우아하게 처리되지 않으면 전체 파이프라인을 정지시킬 수 있습니다. 항상 서브에이전트 호출을 fallback 전략과 함께 try/except로 감싸세요.
* **상충하는 출력**: 두 에이전트가 모순된 결과를 생성할 수 있습니다. 오케스트레이터는 단순 연결이 아닌 명시적인 충돌 해결 로직이 필요합니다.
* **무한 루프**: 무한정 재평가하는 오케스트레이터는 반드시 하드 반복 횟수 제한이 있어야 합니다.
* **프롬프트 인젝션 전파**: 한 에이전트의 출력(예: 웹 스크래핑)이 하위 에이전트를 오염시키는 적대적 명령을 포함할 수 있습니다. 모든 에이전트 간 데이터를 살균하세요.

### 멀티 에이전트가 잘못된 선택인 경우

모든 문제가 여러 에이전트로부터 이익을 얻는 것은 아닙니다:

* 태스크가 병렬성 이점 없이 단일 컨텍스트 윈도우에 편안히 맞는다면, 하나의 에이전트가 더 단순하고 저렴합니다.
* 지연 시간이 중요하고 태스크가 본질적으로 순차적이라면, 파이프라인 오버헤드가 이점을 능가할 수 있습니다.
* 프로토타이핑 시에는 단일 에이전트로 시작하고 실제 제약에 부딪힐 때만 서브에이전트를 분리하세요.

멀티 에이전트 아키텍처는 강력한 도구이지만, 복잡성을 증폭시키기도 합니다. 기본값이 아닌 스케일링 결정으로 취급하세요.
