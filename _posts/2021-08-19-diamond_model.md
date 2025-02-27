---
title: Diamond Model of Intrustion Analysis
tags: Diamond-Model Intrusion Cybersecurity
key: page-diamond_model_intrusion
categories: [Cybersecurity, Security Operations]
author: hyoeun
mathjax: true
mathjax_autoNumber: true
---

## 다이아몬드 침입 분석 모델이란?
* 사이버 보안 및 threat ubtekkugebce ubdystrues애서는 사이버 침입 특성을 분석하고 추적하는데 사용하는 몇 가지 접근 방식이 있습니다. 그 중에 가장 인기 있는 접근 방식이 다이아몬드 모델입니다. 여기에 기본 구성 요소는 Adversary, Capabilities, Infrastructure, Victim입니다.
* 이 모델의 main axiom은 모든 intrusion event에 관해서는 adversary가 infrastructure를 아우르는 capability를 가지고 자신이 의도한 목적을 향해 전진하는 step이 있다고 봅니다. 그리고 이것은 intrusion event는 공격자가 어떤 capabilities와 techniques를 가지고 어떻게 infrastructure 전반에 걸쳐 타겟을 공격했는지에 대해 말해주고 있음을 의미합니다. An adversaary uses a capability over an infrastructure against a victim.

### 핵심 요소
* Adversary - 공격자는 목표를 달성하기 위해 자신의 capability를 이용해 피해자에게 위협을 가하는 조직 혹은 개인입니다.
  * Nation-state, cybercriminal, hacktivist, hobby hacker, cyberterrorist (Type)
  * Espionage, political gain, breach & sell, ransomware/ransom, destruction (Intent)
* Capabilities - An event에서 공격자가 사용한 도구나 기술을 의미합니다. 예를 들어, Malware, exploits, hacker tools, stolen certs가 될 수 있다.
* Infrastructure - 공격자가 공격을 행하기 위해 사용되는 물리적 혹은 논리적 communication structures입니다. 예를 들어 IP, 이메일 주소, 도메인 주소 등이 포함됩니다.
* Victim - 공격의 타겟이자 조직, 사람, 혹은 자산이 될 수 있습니다.

## Threat intelligence
* Threat intelligence is evidence-based knowledge, including context, mechanisms, indicators, implications and action-oriented advice about an existing or emerging menace or hazard to assets. This intelligence can be used to inform decisions regrading the subject's response to that menace or hazard. - Gartner