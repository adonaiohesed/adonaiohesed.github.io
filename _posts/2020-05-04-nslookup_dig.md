---
title: Nslookup & Dig
tags: Nslookup Dig
key: page-nslookup_dig
categories: [Tools, Networking]
author: hyoeun
math: true
mathjax_autoNumber: true
---

### **A Tale of Two Tools: Philosophy and Core Differences**

`nslookup` and `dig` are not just different commands that perform the same function. The two tools have different philosophies from their very inception.

#### **`nslookup`: The Master of Ubiquity and Interaction**

  * **Philosophy**: "Be everywhere, and converse quickly and easily."
  * **Strengths**: The greatest virtue of `nslookup` is its **ubiquity**. It's built into Windows systems, making it a reliable friend that is almost always there when you're in a restricted shell environment or can't install your preferred tools. Additionally, its interactive mode is optimized for 'conversational' reconnaissance, allowing you to ask a series of questions about different record types for a specific domain.

#### **`dig`: The Prince of Precision and Scripting**

  * **Philosophy**: "Show all the information, clearly and structurally." (`dig`: Domain Information Groper)
  * **Strengths**: `dig` was designed from the ground up for DNS troubleshooting and in-depth analysis. As a result, its output is extremely **detailed and structured**, making it perfect for parsing in shell scripts. Powerful options like `+trace` allow you to track the entire path of a DNS query, enabling a level of analysis that `nslookup` cannot provide.

| Feature                               | **nslookup** | **dig (Domain Information Groper)** |
| :------------------------------------ | :----------------------------------------- | :------------------------------------------------- |
| **Primary Platform** | Windows (also available on Linux/macOS)    | Linux/macOS (can be installed on Windows)          |
| **Output Style** | Human-friendly, concise                    | Detailed, structured, script-friendly              |
| **Core Use Case** | Interactive queries, quick & simple lookups | In-depth analysis, diagnostics, automation & scripting |
| **Key Feature** | Interactive mode                           | Full path tracing (`+trace`), fine-grained options |

### **A Pentester's DNS Playbook: Side-by-Side**

Let's explore how to leverage both tools side-by-side in real-world penetration testing scenarios.

#### **1. Basic Record Lookups: Mapping the Domain**

This is the most basic step, but it's the start of everything.

  * **nslookup (interactive mode)**: Excels at consecutive questions.
    ```shell
    nslookup
    > set type=mx
    > aac.mil
    # After checking the result, query for the next type
    > set type=ns
    > aac.mil
    ```
  * **dig (command-line)**: Excels at clear, detailed, single queries.
    ```shell
    $ dig aac.mil MX
    $ dig aac.mil NS
    ```

**When to use which?**: When you want to quickly browse through various pieces of information about a specific domain, `nslookup`'s interactive mode is efficient. When you need clear, detailed output for a report or to pipe into another tool, `dig` is the answer.

#### **2. Attempting a DNS Zone Transfer: The Holy Grail of Reconnaissance**

An attempt at a zone transfer (AXFR) is a crucial opportunity to get your hands on a map of the organization's network.

  * **nslookup**:
    1.  Specify the target server with `server <nameserver>`
    2.  Attempt the zone transfer with `ls -d <domain>`
    <!-- end list -->
    ```shell
    > server ns1.example.com
    > ls -d example.com
    ```
  * **dig**: Use `@` to specify the server more intuitively.
    ```shell
    $ dig @ns1.example.com example.com AXFR
    ```

**When to use which?**: Both tools can attempt a zone transfer. While `dig`'s `AXFR` option is more explicit, the functionality is ultimately the same. The important thing is that this classic technique should **always be attempted**. The moment you discover subdomains like `dev`, `vpn`, or `internal-wiki`, the next steps of your attack will become clear.

#### **3. Reverse DNS Lookups: IP Range Scanning**

  * **nslookup**:
    ```shell
    > 8.8.8.8
    ```
  * **dig**: Use the `-x` option.
    ```shell
    $ dig -x 8.8.8.8
    ```

**When to use which?**: A simple lookup is sufficient with `nslookup`, but when scanning an entire IP range via a script, `dig` with its `-x` option is more explicit and better suited for automation.

#### **4. Advanced Queries: Detecting Split-Horizon DNS and Path Tracing**

  * **Detecting Split-Horizon DNS**: Compare responses by querying an internal and an external DNS server respectively.

      * `nslookup`: Switch context with `server <DNS_server>`.
      * `dig`: Send a one-off query with `@<DNS_server>`.
        When you have a foothold on an internal network, a query like `dig @internal-dns private.example.com` becomes a powerful weapon for exposing internal assets that are invisible from the outside.

  * **DNS Path Tracing**: **This is the most powerful feature that sets `dig` apart.**

    ```shell
    $ dig +trace aac.mil
    ```

    The `+trace` option shows the entire journey of the query, starting from the root (`.`) name servers, through the `mil` TLD servers, all the way to the authoritative name servers for `aac.mil`. This allows you to diagnose complex DNS problems or understand a target's entire resolution path. This is a unique feature of `dig` that `nslookup` cannot offer.

### **Conclusion: The Wisdom of Choosing the Right Tool for the Situation**

The debate between `nslookup` and `dig` is pointless. A true professional understands the value of both tools and utilizes them in the right situations.

  * **`nslookup`** is like a Swiss Army knife that you can pull out instantly in any environment. It is optimized for quick, concise, interactive reconnaissance.
  * **`dig`** is like a power tool set for precision analysis and automation. It is essential for in-depth diagnostics and large-scale, script-based reconnaissance.

Ultimately, a great penetration tester isn't someone who just sticks to their favorite tool, but someone who deeply understands their entire toolkit and can achieve the best results in any situation. Being proficient in both `nslookup` and `dig` is a sure way to prove that expertise.

-----

### **두 도구 이야기: 철학과 핵심 차이점**

`nslookup`과 `dig`는 단순히 같은 기능을 하는 다른 명령어가 아닙니다. 두 도구는 태생부터 다른 철학을 가지고 있습니다.

#### **`nslookup`: 보편성과 상호작용의 대가**

  * **철학**: "어디에나 존재하며, 쉽고 빠르게 대화한다."
  * **강점**: `nslookup`의 가장 큰 미덕은 **보편성**입니다. Windows 시스템에 기본 내장되어 있어, 우리가 제한된 쉘 환경에 놓였거나 선호하는 도구를 설치할 수 없는 상황일 때 거의 항상 그 자리에 있는 믿음직한 친구입니다. 또한, 대화형 모드(interactive mode)는 특정 도메인에 대해 여러 종류의 레코드를 연속적으로 질문하며 답을 얻는 '대화형' 정찰에 최적화되어 있습니다.

#### **`dig`: 정밀함과 스크립팅의 왕자**

  * **철학**: "모든 정보를, 명확하고, 구조적으로 보여준다." (`dig`: Domain Information Groper)
  * **강점**: `dig`는 처음부터 DNS 문제 해결과 심층 분석을 위해 설계되었습니다. 그 결과, 출력은 매우 **상세하고 구조적**이며, 쉘 스크립트에서 파싱(parsing)하여 사용하기에 완벽합니다. `+trace`와 같은 강력한 옵션은 DNS 질의의 전체 경로를 추적하게 해주어, `nslookup`이 제공할 수 없는 깊이의 분석을 가능하게 합니다.

| 특징 (Feature) | **nslookup** | **dig (Domain Information Groper)** |
| :--- | :--- | :--- |
| **주요 플랫폼** | Windows (Linux/macOS에서도 사용 가능) | Linux/macOS (Windows에서도 설치 가능) |
| **출력 스타일** | 인간 친화적, 간결함 | 상세하고 구조적, 스크립팅에 용이 |
| **핵심 사용 사례** | 대화형 쿼리, 빠르고 간단한 조회 | 심층 분석, 진단, 자동화 및 스크립팅 |
| **대표 기능** | 대화형 모드 (`interactive mode`) | 전체 경로 추적 (`+trace`), 세분화된 옵션 |

### **침투 테스트 전문가를 위한 DNS 활용 전략: Side-by-Side**

실제 침투 테스트 시나리오에서 두 도구를 나란히 비교하며 어떻게 활용할 수 있는지 살펴보겠습니다.

#### **1. 기본 레코드 조회: 도메인 지도 그리기**

가장 기본이지만, 모든 것의 시작입니다.

  * **nslookup (대화형 모드)**: 연속적인 질문에 강합니다.
    ```shell
    nslookup
    > set type=mx
    > aac.mil
    # 결과 확인 후 바로 다음 쿼리
    > set type=ns
    > aac.mil
    ```
  * **dig (명령형)**: 명확하고 상세한 단일 쿼리에 강합니다.
    ```shell
    $ dig aac.mil MX
    $ dig aac.mil NS
    ```

**언제 무엇을 쓸까?**: 특정 도메인에 대해 여러 정보를 연달아 빠르게 훑어보고 싶을 땐 `nslookup`의 대화형 모드가 효율적입니다. 보고서에 첨부하거나 다른 도구로 파이핑할 명확하고 상세한 출력이 필요할 땐 `dig`가 정답입니다.

#### **2. DNS 존 전송 시도: 정찰의 성배**

존 전송(AXFR) 시도는 조직의 네트워크 지도를 손에 넣을 수 있는 결정적인 기회입니다.

  * **nslookup**:
    1.  `server <네임서버>` 로 대상 서버 지정
    2.  `ls -d <도메인>` 으로 존 전송 시도
    <!-- end list -->
    ```shell
    > server ns1.example.com
    > ls -d example.com
    ```
  * **dig**: `@`를 이용해 더 직관적으로 서버를 지정합니다.
    ```shell
    $ dig @ns1.example.com example.com AXFR
    ```

**언제 무엇을 쓸까?**: 두 도구 모두 존 전송 시도가 가능합니다. `dig`의 `AXFR` 옵션이 더 명시적이지만, 결과적으로 기능은 동일합니다. 중요한 것은 이 고전적인 기법을 **항상 시도해야 한다는 점**입니다. `dev`, `vpn`, `internal-wiki` 같은 서브도메인을 발견하는 순간, 공격의 다음 단계가 명확해질 것입니다.

#### **3. 역방향 DNS 조회: IP 대역 스캐닝**

  * **nslookup**:
    ```shell
    > 8.8.8.8
    ```
  * **dig**: `-x` 옵션을 사용합니다.
    ```shell
    $ dig -x 8.8.8.8
    ```

**언제 무엇을 쓸까?**: 간단한 조회는 `nslookup`으로 충분하지만, 스크립트를 통해 IP 대역 전체를 스캔할 때는 `-x` 옵션을 사용하는 `dig`가 더 명시적이고 자동화에 유리합니다.

#### **4. 고급 쿼리: 스플릿 DNS 탐지 및 경로 추적**

  * **스플릿 호라이즌 DNS 탐지**: 내부 DNS와 외부 DNS에 각각 쿼리하여 응답을 비교합니다.

      * `nslookup`: `server <DNS서버>` 로 컨텍스트를 전환합니다.
      * `dig`: `@<DNS서버>` 로 일회성 쿼리를 보냅니다.
        내부망에 발판을 마련했을 때, 내부 DNS 서버를 대상으로 한 `dig @internal-dns private.example.com` 쿼리는 외부에서 보이지 않는 내부 자산을 노출시키는 강력한 무기입니다.

  * **DNS 경로 추적**: **이것이 `dig`를 차별화하는 가장 강력한 기능입니다.**

    ```shell
    $ dig +trace aac.mil
    ```

    `+trace` 옵션은 루트(`.`) 네임서버부터 시작하여 `mil` TLD 서버, `aac.mil`의 권한 있는 네임서버까지 질의가 전달되는 모든 과정을 단계별로 보여줍니다. 이를 통해 복잡한 DNS 문제를 진단하거나, 대상의 DNS 해석 경로 전체를 이해할 수 있습니다. 이것은 `nslookup`은 제공하지 못하는 `dig`만의 독보적인 기능입니다.

### **결론: 상황에 맞는 최적의 도구를 선택하는 지혜**

`nslookup`과 `dig` 사이의 논쟁은 무의미합니다. 진정한 전문가는 두 도구의 가치를 모두 이해하고 적재적소에 활용합니다.

  * **`nslookup`**은 어떤 환경에서든 즉시 꺼내 쓸 수 있는 스위스 군용 칼과 같습니다. 빠르고 간결한 대화형 정찰에 최적화되어 있습니다.
  * **`dig`**는 정밀한 분석과 자동화를 위한 전동 공구 세트와 같습니다. 깊이 있는 진단과 스크립트 기반의 대규모 정찰에 필수적입니다.

결국 뛰어난 침투 테스트 전문가는 단지 자신이 선호하는 도구만 고집하는 사람이 아니라, 자신의 도구함 전체를 깊이 이해하고 어떤 상황에서든 최상의 결과를 이끌어내는 사람입니다. `nslookup`과 `dig` 모두를 능숙하게 다루는 것은 그 전문성을 증명하는 확실한 방법일 것입니다.