---
title: Diamond Model of Intrustion Analysis
tags: Diamond-Model Intrusion Cybersecurity
key: page-diamond_model_intrusion
categories: [Cybersecurity, Security Operations]
author: hyoeun
math: true
mathjax_autoNumber: true
---

## What is the Diamond Model of Intrusion Analysis?

In the cyber threat intelligence (CTI) industry, several approaches are used to analyze and track the characteristics of cyber intrusions. Among them, one of the most widely known and effective frameworks is the **Diamond Model of Intrusion Analysis**. This model posits that every intrusion event consists of four core elements: the **Adversary**, **Capability**, **Infrastructure**, and **Victim**.

The model's core axiom is clear: **"For every intrusion event, there exists an adversary taking a step towards an intended goal by using a capability over an infrastructure against a victim."** This means that any single intrusion event can be described by connecting these four elements to clearly show who attacked whom, with what, and how. This structured approach is invaluable for analysts in assembling the complete picture of an attack from fragmented pieces of evidence.

### The Four Vertices

As its name suggests, the Diamond Model is composed of four vertices, each representing the following:

* **Adversary**: The actor responsible for the attack; an individual or organization that uses its capabilities to threaten a victim to achieve its goals. Analyzing the adversary is crucial for understanding not just *who* is attacking, but also *why*.
    * **Type**: Nation-state, Cybercriminal, Hacktivist, Hobby hacker, Cyberterrorist
    * **Intent**: Espionage, Political gain, Breach & sell, Ransomware/ransom, Destruction

* **Capability**: All the tools and techniques used by the adversary in the intrusion event. This reveals the adversary's skill level and preferred methods of attack.
    * **Examples**: Malware, exploits, hacker tools, stolen certificates, phishing emails, etc.

* **Infrastructure**: Any physical or logical communication structure the adversary uses to deliver a capability to the victim. This provides key clues for tracing and blocking the attack path.
    * **Examples**: C2 server IP addresses, malicious domain names, email addresses, social media accounts, etc.

* **Victim**: The ultimate target of the attack. The victim can be a specific organization or person, as well as the assets they own (servers, data, networks, etc.). The victim's vulnerabilities are a critical variable in determining the success of an attack.

### Connecting the Diamond Model and Threat Intelligence

The true value of the Diamond Model lies not just in recording events, but in connecting the elements to generate **actual Threat Intelligence**. For example, an analyst who discovers a specific piece of malware (Capability) being served from an IP address (Infrastructure) can pivot on that data to identify the same **Adversary** group in other intrusions or to predict other **Victim** groups they might be targeting.

This structured analytical information, derived from the Diamond Model, forms the basis of what the global IT research group Gartner defines as "threat intelligence."

## What is Threat Intelligence?

> "Threat intelligence is evidence-based knowledge, including context, mechanisms, indicators, implications and action-oriented advice about an existing or emerging menace or hazard to assets. This intelligence can be used to inform decisions regarding the subject's response to that menace or hazard." - Gartner

Gartner's definition hits the core point. Threat intelligence is not just data, like a list of malicious IP addresses. It only becomes true intelligence when it is given **context**—such as "Group A (Adversary) is attacking industry D (Victim) through IP address C (Infrastructure) using malware B (Capability)"—and leads to **action-oriented advice**, such as "Therefore, block the related IP and add the behavioral patterns of this specific malware to your detection rules."

In conclusion, the Diamond Model of Intrusion Analysis is a powerful and essential analytical framework that prevents threat data from remaining a simple list of information. Instead, it helps to organically connect and analyze that data, transforming it into actionable intelligence.

---

## 다이아몬드 침입 분석 모델이란?

사이버 위협 인텔리전스(Threat Intelligence) 업계에서는 복잡한 사이버 침입의 특성을 분석하고 추적하기 위해 여러 접근 방식을 사용합니다. 그중 가장 널리 알려지고 효과적인 프레임워크가 바로 **다이아몬드 침입 분석 모델(The Diamond Model of Intrusion Analysis)**입니다. 이 모델은 모든 침입 이벤트가 4가지 핵심 요소인 **공격자(Adversary), 역량(Capabilities), 인프라(Infrastructure), 희생자(Victim)**로 구성된다고 봅니다.

이 모델의 핵심 원칙(Axiom)은 명확합니다. **"모든 침입 이벤트는 공격자가 인프라를 통해 특정 역량을 사용하여 희생자를 공격하는 과정이다 (An adversary uses a capability over an infrastructure against a victim)."** 즉, 하나의 침입 이벤트는 이 네 가지 요소를 연결하여 누가, 무엇을 가지고, 어떻게, 누구를 공격했는지 명확하게 설명할 수 있어야 한다는 의미입니다. 이 구조적인 접근 방식은 분석가들이 단편적인 증거들을 모아 전체 공격 그림을 그리는 데 매우 유용합니다.

### 핵심 요소 (The Four Vertices)

다이아몬드 모델은 이름처럼 네 개의 꼭짓점으로 이루어져 있으며, 각 꼭짓점은 다음을 의미합니다.

* **공격자 (Adversary)**: 공격의 주체로, 목표 달성을 위해 자신의 역량을 이용해 희생자에게 위협을 가하는 개인 또는 조직입니다. 공격자를 분석하는 것은 단순히 '누가'를 넘어 '왜' 공격하는지를 파악하는 데 중요합니다.
    * **유형 (Type)**: 국가 지원 그룹(Nation-state), 사이버 범죄 조직(Cybercriminal), 핵티비스트(Hacktivist), 취미 해커(Hobby hacker), 사이버 테러리스트(Cyberterrorist)
    * **의도 (Intent)**: 정보 수집(Espionage), 정치적 목적(Political gain), 데이터 유출 및 판매(Breach & sell), 랜섬웨어/몸값 요구(Ransomware/ransom), 시스템 파괴(Destruction)

* **역량 (Capabilities)**: 공격자가 침입 이벤트에서 사용한 모든 도구와 기술을 의미합니다. 이는 공격자의 기술 수준과 선호하는 공격 방식을 보여줍니다.
    * **예시**: 악성코드(Malware), 제로데이 익스플로잇(Exploits), 해킹 도구(Hacker tools), 탈취한 인증서(Stolen certs), 피싱 이메일 등

* **인프라 (Infrastructure)**: 공격자가 희생자에게 역량을 전달하기 위해 사용하는 모든 물리적 또는 논리적 통신 구조입니다. 이는 공격의 경로를 추적하고 차단하는 데 핵심적인 단서가 됩니다.
    * **예시**: C&C 서버 IP 주소, 악성 도메인 주소, 이메일 주소, 소셜 미디어 계정 등

* **희생자 (Victim)**: 공격의 최종 목표가 되는 대상입니다. 희생자는 특정 조직이나 사람일 수도 있고, 그들이 소유한 자산(서버, 데이터, 네트워크 등)일 수도 있습니다. 희생자의 취약점은 공격의 성공 여부를 결정하는 중요한 변수입니다.

### 다이아몬드 모델과 위협 인텔리전스의 연결

다이아몬드 모델은 단순히 이벤트를 기록하는 데 그치지 않고, 각 요소를 연결하여 **실질적인 위협 인텔리전스(Threat Intelligence)**를 생성하는 데 그 진정한 가치가 있습니다. 예를 들어, 분석가는 특정 악성코드(역량)가 사용된 IP 주소(인프라)를 발견하면, 이를 축으로 다른 침입 사례들을 분석하여 동일한 공격자(Adversary) 그룹을 찾아내거나, 그들이 노리는 다른 희생자(Victim) 군을 예측할 수 있습니다.

이렇게 다이아몬드 모델을 통해 구조화된 분석 정보가 바로 세계적인 IT 리서치 그룹 가트너(Gartner)가 정의하는 '위협 인텔리전스'의 기반이 됩니다.

## 위협 인텔리전스 (Threat Intelligence) 란?

> "위협 인텔리전스는 자산에 대한 기존 또는 새로운 위협이나 위험에 관한 **맥락, 메커니즘, 지표, 시사점, 실행 가능한 조언을 포함하는 증거 기반 지식**이다. 이 인텔리전스는 해당 위협이나 위험에 대한 주체의 대응 관련 의사결정에 정보를 제공하는 데 사용될 수 있다."
>
> "Threat intelligence is evidence-based knowledge, including context, mechanisms, indicators, implications and action-oriented advice about an existing or emerging menace or hazard to assets. This intelligence can be used to inform decisions regarding the subject's response to that menace or hazard." - Gartner

가트너의 정의는 핵심을 짚고 있습니다. 위협 인텔리전스는 단순히 '악성 IP 주소 목록'과 같은 데이터(Data)가 아닙니다. "A 그룹(공격자)이 B 악성코드(역량)를 이용하여 C IP 주소(인프라)를 통해 D 산업군(희생자)을 공격하고 있다"와 같이 **맥락(Context)**이 부여되고, "따라서 관련 IP를 차단하고 특정 악성코드의 행위 패턴을 탐지 규칙에 추가해야 한다"는 **실행 가능한 조언(Action-oriented advice)**으로 이어질 때 비로소 진정한 인텔리전스가 됩니다.

결론적으로 다이아몬드 침입 분석 모델은 위협 데이터를 단순 정보의 나열에서 끝내지 않고, 유기적으로 연결하고 분석하여 실행 가능한 인텔리전스로 변환하는 강력하고 필수적인 분석 프레임워크라고 할 수 있습니다.