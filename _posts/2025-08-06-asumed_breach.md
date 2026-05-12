---
title: "Assumed Breach: Why Your Firewall Is No Longer Enough"
key: page-assumed_breach
categories:
- Security
- Security Operations
author: hyoeun
math: false
mathjax_autoNumber: false
image: "/assets/thumbnails/2025-08-06-asumed_breach.png"
bilingual: true
date: 2025-08-06 22:48:00
---
## The Uncomfortable Truth About Modern Security

Your firewall is running. Your antivirus is updated. Your VPN is locked down. And somewhere in your network, an attacker has been quietly watching for 73 days — the industry median dwell time before detection.

This is not a failure of technology. It's a failure of **philosophy**.

For decades, the dominant security model was built on a single, increasingly fragile assumption: *keep the bad guys out, and you're safe.* That assumption is now broken. The question is no longer whether to accept this reality, but how quickly your organization can adapt to it.

**Assumed Breach** is the security philosophy that starts from honesty: attackers will get in — and many already have.

> **Read next:** Once you understand the philosophy here, the follow-up post [Assumed Breach Methodology](/posts/assumed_breach_methodology/) walks through the exact technical controls, detection engineering, and red team exercises to operationalize this model.

## How We Got Here: The Death of the Perimeter

The traditional "castle-and-moat" security model made sense in a simpler era. You had an office. The office had a network. The network had a firewall. Employees inside the wall were trusted; the world outside was not.

Three forces destroyed this model:

**1. The Workforce Went Everywhere**
Remote work, contractors, and mobile devices dissolved the network boundary. The "inside" no longer maps to a physical location. Your most sensitive data is now accessed from home offices, coffee shops, and hotel WiFi — networks you don't control and can't protect.

**2. The Cloud Expanded the Attack Surface**
Cloud infrastructure, SaaS applications, and third-party integrations stretched your security perimeter far beyond any single firewall. Your data lives in AWS, your email in Google Workspace, your HR system in Workday. Each is a potential entry point.

**3. Attackers Learned to Be Trusted**
The most dangerous attacks today don't break through the perimeter — they walk through the front door. Supply chain attacks like SolarWinds compromised the update mechanism of trusted software used by 18,000 organizations. The attacker became the software vendor. The perimeter never saw them coming.

Credential phishing — the #1 attack vector — doesn't need to break your firewall. It just needs one employee to click a link. Once they have valid credentials, the attacker *is* the trusted insider.

## What "Assumed Breach" Actually Means

Assumed Breach is not defeatism. It's not saying "we've given up on prevention." It's a **design philosophy** — the security equivalent of building earthquake-resistant structures in a seismic zone. You still try to prevent earthquakes. But you design everything assuming one will eventually happen.

The core shift is from asking:
> *"How do we keep attackers out?"*

To asking:
> *"When an attacker gets in — not if — how fast do we detect them, how far can they move, and how quickly can we remove them?"*

This question changes everything. It changes how you design networks. It changes what you log. It changes how you manage user access. It changes what you practice.

### The Three Operational Pillars

An Assumed Breach organization is built on three capabilities:

**Segmentation — Contain the blast radius**
If an attacker lands on one endpoint, how far can they move? In a flat network, the answer is "everywhere." Segmentation limits lateral movement so that a compromised workstation doesn't mean a compromised domain.

**Detection — Find them fast**
The 73-day dwell time isn't inevitable. It's the result of poor detection. Organizations with mature assumed breach programs detect post-compromise behaviors in hours, not months. The difference is intentional investment in behavioral detection — watching for *what attackers do*, not just *what tools they use*.

**Response — Remove them decisively**
Detection without response is just surveillance. An assumed breach organization has practiced, documented, and drilled the answer to: "We've confirmed an active intrusion. What do we do in the next 30 minutes?"

## Why This Changes Your Security Investments

Most security budgets are heavily weighted toward prevention: firewalls, endpoint protection, email filtering, WAF. These are necessary. But they're insufficient alone.

Assumed Breach doesn't eliminate prevention spending — it rebalances it. The principle is simple: **prevention reduces the number of attackers who get in; assumed breach handles the ones who get through anyway.**

This rebalancing typically means investing more in:

- **Identity security**: Every major breach involves credential abuse. If you assume a credential will eventually be stolen, you invest in detecting abnormal use of valid credentials — not just blocking stolen ones.
- **Internal network visibility**: You can't detect lateral movement you can't see. East-west traffic (traffic between internal systems) is often unmonitored. Assumed breach demands visibility into what systems talk to each other and what's normal.
- **Detection engineering**: Writing, maintaining, and continuously improving detection rules is a discipline, not a one-time project. Assumed breach organizations treat detection as a core engineering function.
- **Adversary simulation**: The only way to know your detection and response capabilities actually work is to test them against realistic attack scenarios. Not annual penetration tests — continuous, structured exercises.

## Zero Trust and Assumed Breach: The Relationship

You'll often see these terms together. They're related but distinct.

**Zero Trust** is an access control architecture: never trust, always verify. No user or device gets access by default. Every request is authenticated, authorized, and validated based on identity, context, and policy.

**Assumed Breach** is the overarching philosophy that drives *why* you need Zero Trust. If you assume breach is possible at any time, you cannot afford to grant implicit trust based on network location. Zero Trust implements the controls; Assumed Breach is the mindset that justifies them.

## The Mental Model Shift: From Gates to Layers

Perimeter security is like a bank vault: one extremely strong door, relatively weak inside. If someone gets past the door, everything is accessible.

Assumed Breach security is like a submarine: every compartment has its own sealed door. A hull breach floods one section, not the whole vessel. The crew knows immediately because pressure alarms are everywhere. They have practiced the drill.

This is the mental model: **every compartment is secured, every space is monitored, and every crew member knows the emergency protocol.**

## Is Your Organization Ready?

Ask yourself these questions:

**Detection**: If an attacker with valid credentials started querying your Active Directory at 2am, would you know within an hour?

**Segmentation**: If one developer laptop was compromised today, could the attacker reach your production database? Your domain controller?

**Response**: Does your team have a documented, practiced playbook for "confirmed active intrusion"? Has anyone drilled it in the last six months?

**Identity**: Do you have controls that detect when a valid account starts behaving strangely — even if the credentials themselves haven't been flagged as stolen?

If any of these answers are "no" or "I'm not sure," your security posture is built on perimeter assumptions that the modern threat landscape has already invalidated.

## Where to Go From Here

Understanding the philosophy is step one. Operationalizing it is step two.

The follow-up post — **[Assumed Breach Methodology: Building the Technical Controls](/posts/assumed_breach_methodology/)** — covers exactly how to build an Assumed Breach program: behavioral detection engineering, network segmentation controls, MITRE ATT&CK coverage mapping, purple team exercises, and the common pitfalls that make these programs fail in practice.

Assumed Breach is not a product you buy. It's a posture you build. Start with the philosophy, then build the architecture.

---

## 현대 보안의 불편한 진실

방화벽은 작동 중이고, 백신 프로그램은 최신 상태를 유지하고 있으며, VPN도 잘 잠겨 있다. 그런데 어딘가에서 공격자가 조용히 73일 동안 네트워크를 들여다보고 있다. 이것이 업계의 탐지 전 평균 체류 시간이다.

이것은 기술의 실패가 아니다. **철학의 실패**다.

수십 년 동안 지배적인 보안 모델은 하나의 점점 더 취약해지는 가정 위에 세워졌다: *나쁜 놈들을 막아내면 안전하다.* 그 가정은 이제 깨졌다. 이 현실을 받아들일지 여부가 아니라, 얼마나 빨리 적응할 수 있는지가 문제다.

**Assumed Breach**는 솔직함에서 출발하는 보안 철학이다: 공격자는 결국 침투할 것이며, 많은 경우 이미 들어와 있다.

> **다음 글:** 이 철학을 이해한 후, 후속 글 [Assumed Breach Methodology](/posts/assumed_breach_methodology/)에서는 이 모델을 실제로 구현하기 위한 기술적 통제, 탐지 엔지니어링, 레드팀 연습을 자세히 다룬다.

## 우리가 여기까지 온 이유: 경계의 죽음

전통적인 "성-과-해자" 보안 모델은 더 단순한 시대에 의미가 있었다. 사무실이 있고, 사무실에 네트워크가 있고, 네트워크에 방화벽이 있었다. 내부의 직원은 신뢰받고, 외부는 신뢰받지 못했다.

세 가지 힘이 이 모델을 파괴했다:

**1. 인력이 어디에나 생겼다**
재택근무, 외주 직원, 모바일 기기가 네트워크 경계를 녹였다. "내부"는 더 이상 물리적 위치에 매핑되지 않는다. 가장 민감한 데이터는 이제 홈 오피스, 카페, 호텔 WiFi에서 접근된다.

**2. 클라우드가 공격 면을 확장했다**
클라우드 인프라, SaaS 애플리케이션, 서드파티 연동이 보안 경계를 단일 방화벽을 훨씬 넘어 뻗어 나갔다.

**3. 공격자들은 신뢰받는 법을 배웠다**
오늘날 가장 위험한 공격은 경계를 뚫지 않는다. 정문으로 걸어 들어온다. SolarWinds 같은 공급망 공격은 18,000개 조직이 사용하는 신뢰할 수 있는 소프트웨어의 업데이트 메커니즘을 침해했다. 경계는 이들을 결코 보지 못했다.

자격증명 피싱은 방화벽을 뚫을 필요가 없다. 직원 한 명이 링크를 클릭하기만 하면 된다. 공격자는 신뢰받는 내부인이 된다.

## "Assumed Breach"가 실제로 의미하는 것

Assumed Breach는 패배주의가 아니다. "예방을 포기했다"는 말이 아니다. 이것은 **설계 철학**이다. 지진 발생 지역에서 내진 설계로 건물을 짓는 것과 같다. 여전히 지진을 예방하려 노력한다. 하지만 결국 지진이 올 것을 가정하고 모든 것을 설계한다.

핵심 전환은 다음과 같이 묻는 것에서:
> *"어떻게 공격자를 막을까?"*

이렇게 묻는 것으로:
> *"공격자가 침투했을 때 — 만약이 아니라 언제 — 얼마나 빨리 탐지하고, 얼마나 멀리 이동할 수 있으며, 얼마나 빨리 제거할 수 있는가?"*

이 질문이 모든 것을 바꾼다. 네트워크 설계 방식을 바꾸고, 무엇을 로그로 남길지를 바꾸고, 사용자 접근 권한을 관리하는 방식을 바꾸고, 무엇을 훈련할지를 바꾼다.

### 세 가지 운영 기둥

**세분화 — 피해 범위 제한**
공격자가 하나의 엔드포인트에 착지한다면, 얼마나 멀리 이동할 수 있는가? 플랫 네트워크에서 답은 "어디든"이다. 세분화는 측면 이동을 제한하여 하나의 침해된 워크스테이션이 도메인 전체 침해로 이어지지 않도록 한다.

**탐지 — 빠르게 찾아라**
73일의 체류 시간은 피할 수 없는 것이 아니다. 그것은 빈약한 탐지의 결과다. 성숙한 Assumed Breach 프로그램을 가진 조직은 침해 후 행위를 몇 달이 아닌 몇 시간 안에 탐지한다.

**대응 — 단호하게 제거하라**
탐지 없는 대응은 그냥 감시에 불과하다. Assumed Breach 조직에는 "확인된 활성 침입. 다음 30분 안에 무엇을 하는가?"에 대한 연습되고 문서화된 답변이 있다.

## 왜 이것이 보안 투자를 바꾸는가

대부분의 보안 예산은 예방에 집중되어 있다: 방화벽, 엔드포인트 보호, 이메일 필터링, WAF. 이것들은 필요하다. 하지만 단독으로는 충분하지 않다.

Assumed Breach는 예방 지출을 없애지 않는다 — 균형을 재조정한다. 원칙은 단순하다: **예방은 침투하는 공격자의 수를 줄이고, Assumed Breach는 어쨌든 통과한 자들을 다룬다.**

## Zero Trust와 Assumed Breach의 관계

**Zero Trust**는 접근 제어 아키텍처다: 절대 신뢰하지 않고, 항상 검증하라. 어떤 사용자나 기기도 기본적으로 접근 권한을 얻지 못한다.

**Assumed Breach**는 *왜* Zero Trust가 필요한지를 이끄는 상위 철학이다. 침해가 언제든 가능하다고 가정하면, 네트워크 위치에 기반한 암묵적 신뢰를 줄 여유가 없다. Zero Trust는 통제를 구현하고, Assumed Breach는 그것을 정당화하는 사고방식이다.

## 정신 모델 전환: 문에서 레이어로

경계 보안은 은행 금고와 같다: 하나의 극히 강한 문, 내부는 상대적으로 약하다. 누군가 문을 통과하면, 모든 것이 접근 가능하다.

Assumed Breach 보안은 잠수함과 같다: 모든 구역에 자체 밀봉 문이 있다. 선체 파손은 한 구역만 침수시키고, 전체 선박은 아니다. 압력 경보가 어디에나 있기 때문에 승무원은 즉시 안다. 그들은 훈련을 받았다.

## 우리 조직은 준비됐는가?

스스로 이 질문들에 답해보라:

**탐지**: 유효한 자격증명을 가진 공격자가 새벽 2시에 Active Directory를 조회하기 시작한다면, 한 시간 안에 알 수 있는가?

**세분화**: 오늘 개발자 노트북 하나가 침해된다면, 공격자가 운영 데이터베이스에 도달할 수 있는가? 도메인 컨트롤러에는?

**대응**: "확인된 활성 침입"에 대한 문서화되고 연습된 플레이북이 있는가? 누군가 지난 6개월 안에 이것을 훈련했는가?

만약 어떤 답이라도 "아니오" 또는 "잘 모르겠다"라면, 당신의 보안 태세는 현대 위협 환경이 이미 무효화한 경계 가정 위에 세워진 것이다.

## 다음 단계

철학을 이해하는 것이 첫 번째 단계다. 이를 실제로 구현하는 것이 두 번째다.

후속 글 **[Assumed Breach Methodology: 기술적 통제 구축](/posts/assumed_breach_methodology/)** 에서는 Assumed Breach 프로그램을 실제로 어떻게 구축하는지를 다룬다: 행위 기반 탐지 엔지니어링, 네트워크 세분화 통제, MITRE ATT&CK 커버리지 매핑, 퍼플팀 연습, 그리고 이런 프로그램을 실패하게 만드는 함정들.

Assumed Breach는 구매하는 제품이 아니다. 구축하는 자세다. 철학부터 시작하고, 아키텍처를 구축하라.