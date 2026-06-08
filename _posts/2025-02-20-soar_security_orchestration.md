---
title: "SOAR: Security Orchestration, Automation and Response"
key: page-soar_security_orchestration
categories:
- Security
- Security Operations
author: hyoeun
image: "/assets/thumbnails/2025-02-20-soar_security_orchestration.png"
bilingual: true
date: 2025-02-20 09:00:00
---

## SOAR: Security Orchestration, Automation and Response

Modern Security Operations Centers (SOCs) are drowning in alerts. A mid-sized enterprise can generate hundreds of thousands of security events per day from firewalls, EDR, identity providers, cloud services, and network sensors. The median SOC analyst manually investigates 20–30 alerts per shift — and the vast majority of those alerts are false positives.

This is the alert fatigue crisis, and it has real consequences: critical incidents get buried under noise, response times stretch from minutes to hours, and skilled analysts burn out doing repetitive, low-value triage work.

**SOAR (Security Orchestration, Automation and Response)** is the operational answer to this crisis. It doesn't replace analysts — it amplifies them by automating the routine, so humans can focus on decisions that require judgment.

## What SOAR Actually Does

SOAR platforms operate across three distinct capabilities that are often conflated:

| Capability | What it means |
|:---|:---|
| **Orchestration** | Connecting disparate security tools into coordinated workflows. SOAR acts as the integration hub between your SIEM, EDR, ticketing system, threat intel feeds, and communication platforms. |
| **Automation** | Executing predefined response actions without human intervention. Block an IP, disable a user account, quarantine an endpoint — triggered automatically based on alert conditions. |
| **Response** | Providing a structured framework for analyst-driven investigation and resolution — case management, evidence collection, timeline reconstruction, and post-incident reporting. |

A simple mental model: **Orchestration** wires things together. **Automation** runs the playbook. **Response** documents the investigation.

## The Core Component: Playbooks

The heart of any SOAR deployment is the **playbook** — a codified incident response procedure. A playbook translates what your best analyst does instinctively into a deterministic, repeatable workflow that the SOAR platform executes automatically.

### Anatomy of a Phishing Playbook

```
TRIGGER: SIEM alert — "Suspicious email with attachment"
          │
          ▼
[AUTOMATED] Extract IOCs from email
  - Sender domain, IP, attachment hash, embedded URLs
          │
          ▼
[AUTOMATED] Enrich IOCs via threat intelligence
  - VirusTotal, Shodan, internal threat intel platform
          │
          ▼
[DECISION] Is attachment hash known malicious?
  ├── YES → Quarantine email across all mailboxes (automated)
  │         Block sender domain in email gateway (automated)
  │         Disable recipient account (automated)
  │         Page on-call analyst → Escalate to IR team
  └── NO  → Is URL reputation suspicious?
              ├── YES → Submit for sandbox detonation
              │         Await verdict → re-enter decision tree
              └── NO  → Close as benign, log for metrics
```

This single playbook can handle thousands of phishing alerts per day — consistently, correctly, and in seconds rather than the 15–20 minutes an analyst would spend doing the same steps manually.

### Playbook Design Principles

**1. Start with your most common, most painful alert type.** Don't try to automate everything on day one. Identify the alert that burns the most analyst time (often phishing or brute-force detections) and build one high-quality playbook for it.

**2. Automate enrichment before automation of response.** Automating data enrichment (looking up IPs, hashes, domains) is low-risk and high-value. Automating response actions (blocking accounts, isolating endpoints) requires higher confidence thresholds — don't skip the enrichment step.

**3. Build in human approval gates for high-impact actions.** Automatically isolating a critical server or disabling a C-suite executive's account has blast radius. For high-severity or high-impact actions, require analyst approval before execution.

**4. Measure and iterate.** Track mean time to triage (MTTT), false positive rate per playbook, and analyst override frequency. If analysts are regularly overriding a playbook's automated decision, that playbook needs refinement.

## SOAR vs. SIEM: Complementary, Not Competing

The single most common confusion about SOAR is its relationship to SIEM. They are not alternatives — they are complementary layers of the security stack:

```
[Data Sources]
  Firewall / EDR / IdP / Cloud / Network
        │
        ▼
[SIEM]  — Collects, normalizes, correlates, and generates alerts
        │  "Something looks wrong with this user's login pattern"
        │
        ▼
[SOAR]  — Receives the alert, runs the playbook
        │  "Look up the IP, check if device is managed,
        │   query HR to confirm if user is on travel,
        │   if no travel → disable account + notify manager"
        │
        ▼
[Analyst] — Reviews the SOAR case, approves or overrides
             "Confirmed malicious — escalate to full IR"
```

SIEM detects. SOAR responds. Analysts decide.

## Key SOAR Use Cases

### 1. Phishing Triage and Response
The most universal use case. Automate: header analysis, sandbox detonation, mailbox search and purge, sender blocking.

### 2. Compromised Credential Response
Trigger: SIEM alert for impossible travel or credential stuffing.
Automated: Confirm via HR/IdP that travel is not expected → force MFA re-enrollment → notify user → page SOC if confirmed compromise.

### 3. Vulnerability Enrichment
When a vulnerability scanner reports a critical finding, SOAR automatically queries the CMDB to determine asset criticality, checks whether an exploit is publicly available, and prioritizes the ticket accordingly — before a human ever sees it.

### 4. Threat Intelligence Operationalization
New IOCs from threat feeds are automatically added to blocklists across firewall, email gateway, and proxy — and automatically checked against 90-day historical logs to identify any historical communication with the new IOC.

## Leading SOAR Platforms

| Platform | Key Strength |
|:---|:---|
| **Splunk SOAR (Phantom)** | Deep Splunk SIEM integration, large app ecosystem |
| **Palo Alto XSOAR** | Enterprise-scale, strong threat intel integration |
| **Microsoft Sentinel** | Native Azure integration, Logic Apps playbooks |
| **IBM QRadar SOAR** | Strong case management and regulatory compliance workflows |
| **Tines** | Code-optional, flexible, developer-friendly |

## Implementation Pitfalls

**Over-automation too early**: Automating response actions before you've validated enrichment accuracy leads to false-positive blocking and business disruption. Prove out enrichment fidelity before enabling automated response.

**Playbook sprawl**: Organizations that build hundreds of loosely maintained playbooks end up with the same problem as role explosion in RBAC — an unmaintainable mess. Enforce a playbook governance process.

**Integration debt**: SOAR's value is proportional to the number of tools it integrates. A SOAR platform with two integrations is just expensive ticketing. Budget for integration engineering time upfront.

## Conclusion

SOAR is not a magic box that eliminates the need for skilled security analysts. It is a force multiplier — it handles the repetitive, deterministic work so your analysts can focus on the ambiguous, high-judgment decisions that adversaries deliberately create to confuse automated systems.

A mature SOAR deployment measurably reduces mean time to respond (MTTR), shrinks analyst alert fatigue, and creates a documented, auditable trail of every incident response action taken — which is invaluable for compliance and post-incident reviews.

---

## SOAR: 보안 오케스트레이션, 자동화 및 대응

현대의 보안운영센터(SOC)는 알림의 홍수에 빠져 있습니다. 중규모 기업은 방화벽, EDR, ID 공급자, 클라우드 서비스, 네트워크 센서로부터 하루에 수십만 건의 보안 이벤트를 생성할 수 있습니다. 대부분의 알림은 오탐(False Positive)이며, 이로 인해 중요한 실제 사고가 노이즈 속에 묻히고, 대응 시간이 늘어나며, 숙련된 분석가들은 반복적인 저가치 트리아지 업무를 하다 번아웃됩니다.

**SOAR (Security Orchestration, Automation and Response)**는 이 위기에 대한 운영적 해답입니다. 분석가를 대체하는 것이 아니라, 루틴한 작업을 자동화함으로써 인간이 판단이 필요한 결정에 집중할 수 있도록 증폭시킵니다.

## SOAR가 실제로 하는 일

SOAR 플랫폼은 세 가지 핵심 역량에 걸쳐 작동합니다:

| 역량 | 의미 |
|:---|:---|
| **오케스트레이션** | 분산된 보안 도구들을 조율된 워크플로우로 연결. SOAR는 SIEM, EDR, 티켓팅 시스템, 위협 인텔리전스 피드, 커뮤니케이션 플랫폼 사이의 통합 허브 역할을 합니다. |
| **자동화** | 인간 개입 없이 사전 정의된 대응 조치를 실행. IP 차단, 사용자 계정 비활성화, 엔드포인트 격리 등이 알림 조건에 따라 자동으로 트리거됩니다. |
| **대응** | 분석가 주도의 조사와 해결을 위한 구조화된 프레임워크 제공 — 케이스 관리, 증거 수집, 타임라인 재구성, 사후 보고. |

간단한 메탈 모델: **오케스트레이션**은 연결하고, **자동화**는 플레이북을 실행하며, **대응**은 조사를 문서화합니다.

## 핵심 구성 요소: 플레이북

SOAR 배포의 핵심은 **플레이북**입니다. 플레이북은 최고의 분석가가 본능적으로 수행하는 인시던트 대응 절차를 SOAR 플랫폼이 자동으로 실행하는 결정론적이고 반복 가능한 워크플로우로 변환합니다.

### 피싱 플레이북 해부

```
트리거: SIEM 알림 — "첨부 파일이 있는 의심스러운 이메일"
        │
        ▼
[자동] 이메일에서 IOC 추출
  - 발신자 도메인, IP, 첨부 파일 해시, 삽입된 URL
        │
        ▼
[자동] 위협 인텔리전스로 IOC 보강
  - VirusTotal, Shodan, 내부 위협 인텔 플랫폼
        │
        ▼
[결정] 첨부 파일 해시가 알려진 악성 파일인가?
  ├── 예 → 모든 사서함에서 이메일 격리 (자동)
  │         이메일 게이트웨이에서 발신자 도메인 차단 (자동)
  │         수신자 계정 비활성화 (자동)
  │         온콜 분석가 호출 → IR 팀으로 에스컬레이트
  └── 아니오 → URL 평판이 의심스러운가?
               ├── 예 → 샌드박스 폭발 분석 제출
               │         판정 대기 → 결정 트리 재진입
               └── 아니오 → 정상으로 종료, 메트릭 로깅
```

이 단 하나의 플레이북이 하루에 수천 건의 피싱 알림을 처리할 수 있습니다. 분석가가 동일한 단계를 수동으로 수행하는 데 걸리는 15~20분 대신 수초 만에, 일관되고 정확하게.

## 플레이북 설계 원칙

**1. 가장 흔하고 가장 고통스러운 알림 유형부터 시작하세요.** 처음부터 모든 것을 자동화하려 하지 마세요. 가장 많은 분석가 시간을 소모하는 알림(주로 피싱 또는 무차별 대입 탐지)을 파악하고 그것을 위한 고품질 플레이북 하나를 먼저 구축하세요.

**2. 대응 자동화 전에 보강(Enrichment) 자동화부터.** 데이터 보강(IP, 해시, 도메인 조회) 자동화는 위험도가 낮고 가치가 높습니다. 대응 조치(계정 차단, 엔드포인트 격리) 자동화는 더 높은 신뢰 임계값이 필요합니다.

**3. 고영향 조치에 인간 승인 게이트를 만드세요.** 중요 서버를 자동으로 격리하거나 임원 계정을 비활성화하는 것은 큰 영향을 미칩니다. 심각도가 높거나 영향이 큰 조치에는 실행 전 분석가 승인을 요구하세요.

**4. 측정하고 반복하세요.** 평균 트리아지 시간(MTTT), 플레이북별 오탐률, 분석가 재정의 빈도를 추적하세요. 분석가들이 정기적으로 플레이북의 자동 결정을 재정의한다면, 그 플레이북은 수정이 필요합니다.

## SOAR vs. SIEM: 경쟁이 아닌 보완 관계

SIEM은 탐지하고, SOAR는 대응하며, 분석가는 결정합니다. 두 플랫폼은 보안 스택의 상호 보완적인 레이어입니다:

- **SIEM**: 데이터 소스로부터 이벤트를 수집, 정규화, 상관 분석하여 알림을 생성합니다.
- **SOAR**: SIEM의 알림을 수신하여 플레이북을 실행하고, 자동 대응을 수행하거나 분석가에게 케이스를 제시합니다.
- **분석가**: SOAR 케이스를 검토하고 승인 또는 재정의하여 최종 결정을 내립니다.

## 주요 SOAR 활용 사례

- **피싱 트리아지 및 대응**: 헤더 분석, 샌드박스 폭발, 사서함 검색 및 제거, 발신자 차단을 자동화.
- **침해 자격 증명 대응**: 불가능한 여행(Impossible Travel) 알림 → HR/IdP 확인 → MFA 재등록 강제 → 사용자 알림 → 확인된 침해 시 SOC 호출.
- **취약점 보강**: 취약점 스캐너 결과에 CMDB 쿼리로 자산 중요도를 자동 결정하고, 공개 익스플로잇 여부를 확인하여 티켓 우선순위를 자동 지정.
- **위협 인텔리전스 운영화**: 새 IOC를 방화벽, 이메일 게이트웨이, 프록시 차단 목록에 자동 추가하고, 90일 히스토리 로그와 자동 대조.

## 구현 시 주의점

**너무 이른 과도한 자동화**: 보강 정확도를 검증하기 전에 대응 조치를 자동화하면 오탐 차단과 업무 중단으로 이어집니다.

**플레이북 확산**: 느슨하게 관리되는 수백 개의 플레이북을 구축하면 RBAC의 역할 폭발 문제와 같이 유지 불가능한 혼란을 초래합니다. 플레이북 거버넌스 프로세스를 강제하세요.

**통합 부채**: SOAR의 가치는 통합하는 도구의 수에 비례합니다. 통합이 두 개뿐인 SOAR 플랫폼은 비싼 티켓팅 시스템에 불과합니다. 통합 엔지니어링 시간을 사전에 예산에 반영하세요.

## 결론

SOAR는 숙련된 보안 분석가의 필요성을 없애는 마법 상자가 아닙니다. 반복적이고 결정론적인 작업을 처리함으로써 분석가들이 적대자가 의도적으로 자동화된 시스템을 혼란시키기 위해 만들어내는 모호하고 고판단력이 필요한 결정에 집중할 수 있게 해주는 **역량 배가기(Force Multiplier)**입니다.

성숙한 SOAR 배포는 평균 대응 시간(MTTR)을 측정 가능하게 줄이고, 분석가 알림 피로를 줄이며, 취해진 모든 인시던트 대응 조치에 대한 문서화되고 감사 가능한 추적을 생성합니다 — 이는 컴플라이언스와 사후 검토에 매우 중요합니다.
