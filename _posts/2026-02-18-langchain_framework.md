---
title: LangChain Framework for AI Agents
key: page-langchain_framework
categories:
- AI & ML
- AI Agents & Automation
author: hyoeun
math: true
mathjax_autoNumber: true
image: "/assets/thumbnails/2026-02-18-langchain_framework.png"
bilingual: true
date: 2026-02-18 09:00:00
---

## LangChain: The Infrastructure Layer for LLM Applications

LangChain has become the de facto starting point for building LLM-powered applications. I was skeptical at first—another abstraction layer on top of API calls seemed unnecessary. But after building several security tools with it, I appreciate that LangChain solves real composition problems that emerge when you move beyond simple prompts.

This post covers the components that matter most for agent development, with an honest assessment of where LangChain excels and where it gets in your way.

### The Core Abstraction Stack

LangChain is built around composable primitives:

```
Prompt Templates
     ↓
LLMs / Chat Models
     ↓
Output Parsers
     ↓
Chains → Agents
     ↓
Memory + Tools
```

Each layer can be swapped independently. You can change the underlying LLM from OpenAI to Claude to a local Llama model without rewriting your chain logic.

### Chains: Composing LLM Calls

A **chain** is a sequence of operations. The simplest chain is a prompt → LLM call.

```python
from langchain_anthropic import ChatAnthropic
from langchain_core.prompts import ChatPromptTemplate
from langchain_core.output_parsers import StrOutputParser

llm = ChatAnthropic(model="claude-sonnet-4-6")
prompt = ChatPromptTemplate.from_messages([
    ("system", "You are a security analyst. Be precise and concise."),
    ("user", "{input}")
])
parser = StrOutputParser()

chain = prompt | llm | parser  # LangChain Expression Language (LCEL)
result = chain.invoke({"input": "Explain CVE-2024-3094 in 3 bullet points."})
```

LangChain Expression Language (LCEL) uses the pipe operator to compose components. This declarative style makes complex chains readable and enables parallel execution automatically.

### Tools: Giving Agents Capabilities

Tools are functions the LLM can choose to call. LangChain provides many built-in tools and a clean interface for defining custom ones.

```python
from langchain_core.tools import tool

@tool
def search_cve(cve_id: str) -> str:
    """Search the NVD database for a CVE and return its CVSS score and description."""
    # Call NVD API
    response = requests.get(f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}")
    data = response.json()
    vuln = data["vulnerabilities"][0]["cve"]
    score = vuln.get("metrics", {}).get("cvssMetricV31", [{}])[0].get("cvssData", {}).get("baseScore", "N/A")
    return f"CVE: {cve_id}\nScore: {score}\nDescription: {vuln['descriptions'][0]['value']}"

@tool
def check_exploit_availability(cve_id: str) -> str:
    """Check if a public exploit exists for the given CVE in ExploitDB."""
    # Implementation
    ...
```

The docstring is critical—it's what the LLM reads to decide when to use this tool. Write it as if you're explaining to a smart person who doesn't know your codebase.

### Memory: Persistent Context Across Interactions

LangChain provides several memory types for different use cases:

**ConversationBufferMemory**: Stores the full conversation history. Simple but context window fills up fast.

**ConversationSummaryMemory**: Summarizes older messages to keep context window manageable.

**VectorStoreMemory**: Stores past interactions as embeddings; retrieves semantically relevant history.

```python
from langchain.memory import ConversationSummaryBufferMemory

memory = ConversationSummaryBufferMemory(
    llm=llm,
    max_token_limit=2000,
    return_messages=True
)
```

For security automation tools, I prefer `ConversationSummaryBufferMemory`—it preserves recent context verbatim (important for precise technical details) while summarizing older context.

### Agents: LLM-Driven Decision Making

A LangChain agent lets the LLM decide which tools to use and in what order. The ReAct agent is the most common pattern:

```python
from langchain.agents import create_react_agent, AgentExecutor
from langchain import hub

# Pull standard ReAct prompt from LangChain Hub
prompt = hub.pull("hwchase17/react")

agent = create_react_agent(llm, tools=[search_cve, check_exploit_availability], prompt=prompt)
executor = AgentExecutor(
    agent=agent,
    tools=[search_cve, check_exploit_availability],
    verbose=True,
    max_iterations=10,
    handle_parsing_errors=True
)

result = executor.invoke({
    "input": "Is CVE-2024-3094 being actively exploited? What's the recommended remediation?"
})
```

The ReAct loop produces reasoning traces like:

```
Thought: I need to look up CVE-2024-3094 first.
Action: search_cve
Action Input: CVE-2024-3094
Observation: CVE: CVE-2024-3094, Score: 10.0, Description: ...
Thought: Score is 10.0 (critical). Now I should check for exploits.
Action: check_exploit_availability
...
```

This trace is invaluable for debugging and for building user trust in agent decisions.

### LangGraph: Stateful, Cyclic Agent Workflows

LangGraph is LangChain's answer to complex, stateful agent workflows. It goes beyond linear chains to support:

* **Cyclic graphs**: agents can loop back based on conditions
* **Persistent checkpointing**: save and resume workflow state
* **Branching**: conditional routing between agents

```python
from langgraph.graph import StateGraph, END
from typing import TypedDict, List

class SecurityAuditState(TypedDict):
    target: str
    recon_data: dict
    vulnerabilities: List[dict]
    needs_deep_scan: bool
    final_report: str

def should_deep_scan(state: SecurityAuditState) -> str:
    """Route to deep scan or directly to report."""
    return "deep_scan" if state["needs_deep_scan"] else "report"

graph = StateGraph(SecurityAuditState)
graph.add_node("recon", recon_agent)
graph.add_node("vuln_assess", vuln_assessment_agent)
graph.add_node("deep_scan", deep_scan_agent)
graph.add_node("report", report_agent)

graph.set_entry_point("recon")
graph.add_edge("recon", "vuln_assess")
graph.add_conditional_edges("vuln_assess", should_deep_scan)
graph.add_edge("deep_scan", "report")
graph.add_edge("report", END)
```

### LangChain's Weaknesses

LangChain is powerful but has real drawbacks worth knowing:

* **Abstraction leakage**: When things break (and they will), debugging through layers of abstractions is painful. Sometimes a direct API call is cleaner.
* **Rapid API churn**: LangChain has historically broken APIs between versions. Pin your versions in production.
* **Overhead for simple tasks**: For a single LLM call with no tools, LangChain adds complexity without value. Don't use it for simple use cases.
* **Prompt coupling**: If you use LangChain Hub prompts, your behavior depends on external prompts you don't control. Copy and version-control the prompts you rely on.

For complex agent pipelines with multiple tools, memory, and dynamic routing, LangChain + LangGraph is a strong choice. For simpler tasks, the raw SDK may serve you better.

---

## LangChain: AI 에이전트를 위한 인프라 레이어

LangChain은 LLM 기반 애플리케이션 구축의 사실상 표준 시작점이 되었습니다. 처음에는 회의적이었습니다—API 호출 위에 또 다른 추상화 레이어는 불필요해 보였습니다. 하지만 여러 보안 도구를 구축하고 나서, LangChain이 단순한 프롬프트를 넘어설 때 나타나는 실제 구성 문제들을 해결한다는 것을 이해하게 되었습니다.

이 포스트는 에이전트 개발에 가장 중요한 컴포넌트들을 다루며, LangChain이 뛰어난 곳과 방해가 되는 곳에 대한 솔직한 평가를 포함합니다.

### 핵심 추상화 스택

LangChain은 조합 가능한 기본 요소들을 중심으로 구축됩니다:

```
프롬프트 템플릿
     ↓
LLM / 챗 모델
     ↓
출력 파서
     ↓
체인 → 에이전트
     ↓
메모리 + 도구
```

각 레이어는 독립적으로 교체할 수 있습니다. 체인 로직을 다시 작성하지 않고도 OpenAI에서 Claude로, 로컬 Llama 모델로 기반 LLM을 변경할 수 있습니다.

### 체인 (Chains): LLM 호출 조합하기

**체인**은 일련의 작업입니다. 가장 단순한 체인은 프롬프트 → LLM 호출입니다.

LangChain Expression Language (LCEL)은 파이프 연산자를 사용하여 컴포넌트를 조합합니다. 이 선언적 스타일은 복잡한 체인을 읽기 쉽게 만들고 자동으로 병렬 실행을 가능하게 합니다.

### 도구 (Tools): 에이전트에게 능력 부여하기

도구는 LLM이 호출하도록 선택할 수 있는 함수입니다. LangChain은 많은 내장 도구와 커스텀 도구 정의를 위한 깔끔한 인터페이스를 제공합니다.

docstring이 중요합니다—LLM이 이 도구를 언제 사용할지 결정하기 위해 읽는 것입니다. 코드베이스를 모르는 똑똑한 사람에게 설명하는 것처럼 작성하세요.

### 메모리 (Memory): 인터랙션 간 지속적인 컨텍스트

LangChain은 다양한 사용 사례에 맞는 여러 메모리 유형을 제공합니다:

* **ConversationBufferMemory**: 전체 대화 이력을 저장합니다. 단순하지만 컨텍스트 윈도우가 빠르게 찹니다.
* **ConversationSummaryMemory**: 컨텍스트 윈도우를 관리 가능하게 유지하기 위해 오래된 메시지를 요약합니다.
* **VectorStoreMemory**: 과거 인터랙션을 임베딩으로 저장하고 의미적으로 관련된 이력을 검색합니다.

보안 자동화 도구에서는 `ConversationSummaryBufferMemory`를 선호합니다—정확한 기술적 세부 사항에 중요한 최근 컨텍스트를 그대로 보존하면서 오래된 컨텍스트를 요약합니다.

### 에이전트 (Agents): LLM 기반 의사 결정

LangChain 에이전트는 LLM이 어떤 도구를 어떤 순서로 사용할지 결정하게 합니다. ReAct 에이전트가 가장 일반적인 패턴입니다.

ReAct 루프는 다음과 같은 추론 트레이스를 생성합니다:

```
Thought: CVE-2024-3094를 먼저 조회해야 합니다.
Action: search_cve
Action Input: CVE-2024-3094
Observation: CVE: CVE-2024-3094, Score: 10.0, Description: ...
Thought: 점수가 10.0 (치명적)입니다. 이제 익스플로잇을 확인해야 합니다.
Action: check_exploit_availability
...
```

이 트레이스는 디버깅과 에이전트 결정에 대한 사용자 신뢰 구축에 매우 중요합니다.

### LangGraph: 상태 유지형, 순환 에이전트 워크플로우

LangGraph는 복잡한 상태 유지형 에이전트 워크플로우에 대한 LangChain의 답입니다. 선형 체인을 넘어 다음을 지원합니다:

* **순환 그래프**: 에이전트가 조건에 따라 루프백 가능
* **지속적 체크포인팅**: 워크플로우 상태 저장 및 재개
* **분기**: 에이전트 간 조건부 라우팅

### LangChain의 약점

LangChain은 강력하지만 알아두어야 할 실제 단점이 있습니다:

* **추상화 누수**: 문제가 발생하면(그리고 반드시 발생합니다), 추상화 레이어를 통한 디버깅이 고통스럽습니다. 때로는 직접 API 호출이 더 깔끔합니다.
* **빠른 API 변화**: LangChain은 역사적으로 버전 간 API를 깼습니다. 프로덕션에서는 버전을 고정하세요.
* **단순한 태스크에서의 오버헤드**: 도구 없이 단일 LLM 호출의 경우, LangChain은 가치 없이 복잡성을 추가합니다.
* **프롬프트 결합**: LangChain Hub 프롬프트를 사용하면 제어할 수 없는 외부 프롬프트에 의존하게 됩니다. 의존하는 프롬프트를 복사하고 버전 관리하세요.

여러 도구, 메모리, 동적 라우팅을 가진 복잡한 에이전트 파이프라인에서 LangChain + LangGraph는 강력한 선택입니다. 더 단순한 태스크에서는 raw SDK가 더 잘 serve할 수 있습니다.
