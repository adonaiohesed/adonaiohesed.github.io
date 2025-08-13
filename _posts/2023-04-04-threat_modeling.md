---
title: Threat Modeling
tags: Threat-Modeling Cybersecurity Risk-Management
key: page-threat_modeling
categories: [Cybersecurity, Security Operations]
author: hyoeun
math: true
mathjax_autoNumber: true
---

# Threat Modeling Practical Guide

## What is Threat Modeling?

**Threat modeling** is the process of **identifying potential security threats during the design phase of an application or system and proactively designing defensive measures**. It goes beyond simple vulnerability scanning by analyzing the **entire architecture's attack surface and preemptively designing defense strategies**.

* Threat modeling is not limited to code but is a **continuous process** assessing the **overall security posture of the system**.
* Typically starts by visualizing system flows through tools like a **Data Flow Diagram (DFD)** or whiteboard sessions.
* Threat modeling should be **continuously updated** whenever new features, design changes, or architectural modifications are introduced.

### Core Steps of Threat Modeling

* **Diagram**: Visually model the system architecture
* **Identify Threats**: Identify threats based on assets, components, entry points, trust boundaries, etc.
* **Mitigate**: Develop defenses (security measures, design changes) for each identified threat
* **Validate**: Verify the validity of threats and countermeasures, and assess risk

## Threat Modeling is a Team Sport

Threat modeling should not be performed alone; it requires participation from team members with diverse perspectives:

* **Business Persona**

  * Ensures security measures do not negatively impact business requirements (functional/non-functional)

* **Developer Persona**

  * Developers who best understand architectural design, sharing technical feasibility and implementation methods

* **Adversary Persona**

  * Imagines threat scenarios from an attacker’s perspective, identifying vulnerabilities

* **Defender Persona**

  * Proposes defenses for identified threats, evaluates operational and monitoring feasibility

* **AppSec SME Persona**

  * Security expert leading the threat modeling process, moderating discussions, and ensuring quality

## Maintain a Consistent Methodology

It is critical to use one consistent threat modeling methodology (format):

* Reduces learning curve during inter-team collaboration
* Facilitates reuse or referencing of previously created threat models
* Ensures consistent threat mitigation standards across the organization

## Leverage Existing Workflow Tools

* Use existing development team tools like **issue tracking and collaborative documentation tools** for threat modeling
* Manage **feedback, approvals, and action items** in one place, enabling **asynchronous collaboration**
* Allows AppSec SMEs to effectively support multiple teams simultaneously

## Decompose Workloads into Smaller Feature Units

* Perform threat modeling at the **feature level instead of the entire workload**
* Assume minimal scope consisting of at least one asset, one entry point, and two components. Smaller scopes than this are not practical for threat modeling.
* Assets might include user credentials or customer data; entry points could be REST API endpoints on an API Gateway; components could be services like API Gateway and Lambda functions.

### Advantages:

* Aligns well with Agile processes
* Enables more granular threat detection
* Creates **reusable Threat Models**
* Prevents an entire release from being blocked by threats identified in isolated features

## Distribute Ownership

* Centralized security teams creating all threat models face scalability and resource limits; thus, distributed ownership is preferred.
* **Feature development teams should create their own Threat Models**

  * Enhances security awareness and facilitates iterative improvements
* AppSec SMEs transition into **advisory and coordination roles**

## Clearly Identify Entry Points

* Clearly understand the **types of endpoints** used by AWS services

  * Example: S3 uses APIs, EC2 uses SSH/API, etc.
* Include **customer-configured entry points** in the threat modeling

## Identify Potential Threats

* Brainstorm using methodologies like **STRIDE** or **OWASP Top 10**
* Create a **threat catalog** tailored to the organization for consistency and speed

## Evaluate Security Countermeasures (Mitigations)

* Check directly developed code (input validation, authentication, session management)
* Consider external SaaS and AWS components as well
* Understand the **Shared Responsibility Model** clearly

### Example:

* **EC2**: Many customer responsibilities

* **RDS**: AWS manages OS, customer manages DB settings

* **S3, KMS, etc.**: AWS manages operations, customers manage API permissions

* Include security domains like **IAM, encryption, network security, logging, etc.**

* Clarify models using code-based evidence such as **CloudFormation and IAM Policies**

## Set Criteria for "How Much is Enough?"

* Aim for appropriate risk-based management instead of completely eliminating all threats
* Constructively balance the tension between **security and release schedules**

## Start "From Now" Rather Than Reviewing Past

* No need to retroactively threat model all previously deployed features
* Begin applying threat modeling with **upcoming features**

  * This fosters team learning and internalizes security capabilities

## Three Commonly Mentioned Methodologies
### STRIDE (Based on type of threat)
STRIDE focuses on systematically identifying and categorizing types of threats. It is typically used to analyze potential threats for each component (e.g., processes, data stores) based on a system's **Data Flow Diagram (DFD)**.

* **Spoofing** - The threat of gaining system access by using another user's credentials.
    * **Countermeasure**: **Authentication** (e.g., digital signatures, proper authentication like passwords or iris scans).
* **Tampering** - Maliciously modifying information on a system.
    * **Countermeasure**: **Integrity** (e.g., hashes, digital signatures).
* **Repudiation** - The threat of a user denying they performed a malicious action.
    * **Countermeasure**: **Non-repudiation** (e.g., digital signatures, audit logs).
* **Information Disclosure** - The threat of leaking sensitive data.
    * **Countermeasure**: **Confidentiality** (e.g., encryption).
* **Denial of Service** - The threat of making a system unavailable for normal use.
    * **Countermeasure**: **Availability** (e.g., filtering, attack monitoring).
* **Elevation of Privilege** - The threat of a user gaining higher privileges than they are authorized for.
    * **Countermeasure**: **Authorization**.

### DREAD (Based on level of dangerous threat)
Like STRIDE, DREAD is a methodology developed by Microsoft. It is used to quantitatively assess the risk of identified threats and to prioritize them. While STRIDE focuses on 'identifying' threats, DREAD focuses on determining how 'dangerous' a threat is.

* **Damage Potential** - The scale of damage if an attack succeeds.
* **Reproducibility** - How easily the attack can be reproduced.
* **Exploitability cost** - The effort or cost required to carry out the attack.
* **Affected users** - The number of users affected by the attack.
* **Discoverability** - How easy it is to discover the vulnerability.
* $$\text{Risk value} = (\text{Damage} + \text{Affected users}) \times (\text{Reproducibility} + \text{Exploitability} + \text{Discoverability})$$


### PASTA (Process for Attack Simulation and Threat Analysis)
PASTA is a 7-stage, risk-centric methodology that analyzes business risks from an **attacker's perspective**.

* **Stage 1: Define Business and Security Objectives**: Define business objectives and their corresponding security requirements.
* **Stage 2: Define the Technical Scope**: Define the architecture and data flows of the system to be analyzed.
* **Stage 3: Application Analysis**: Decompose the application's components and identify potential vulnerabilities.
* **Stage 4: Threat Analysis**: Analyze potential threats to the system based on threat intelligence.
* **Stage 5: Vulnerability Analysis**: Map and analyze the identified threats against the system's vulnerabilities.
* **Stage 6: Attack Modeling**: Simulate scenarios (attack trees) of how an attacker would exploit vulnerabilities.
* **Stage 7: Risk and Impact Analysis**: Evaluate risks based on the likelihood of a successful attack and its business impact, and develop mitigation strategies.

---

# Threat Modeling 실무 가이드

## Threat Modeling이란?

**Threat Modeling**은 애플리케이션이나 시스템의 설계 단계에서 **잠재적인 보안 위협을 식별하고, 이를 방어할 수 있는 조치를 미리 설계하는 과정**입니다. 단순한 취약점 진단을 넘어서, **전체 아키텍처의 위협 표면(attack surface)을 분석하고, 사전에 방어 전략을 설계**하는 것이 핵심입니다.

- Threat Modeling은 코드만을 위한 작업이 아니라, **시스템 전체의 보안 상태**를 점검하는 **지속적인 과정**입니다.
- 보통 **Data Flow Diagram(DFD)** 또는 화이트보드 등을 통해 시스템 흐름을 시각화하며 시작합니다.
- 한 번만 하고 끝내는 것이 아니라, **기능 추가/설계 변경/아키텍처 수정**이 있을 때마다 **지속적으로 업데이트**되어야 합니다.

### Threat Modeling의 핵심 단계

- **Diagram**: 시스템 아키텍처를 시각적으로 모델링  
- **Identify Threats**: 자산, 구성요소, 진입점, 신뢰 경계 등을 기준으로 위협 요소 식별  
- **Mitigate**: 각 위협에 대한 방어 방법(보안 조치, 설계 변경 등) 수립  
- **Validate**: 위협과 대응 방안이 유효한지 검토 및 리스크 평가

## Threat Modeling은 팀 스포츠다

Threat Modeling은 혼자 하는 작업이 아닙니다. 다양한 관점을 가진 팀원들이 참여해야 효과적으로 수행됩니다:

- **Business 페르소나**  
  → 보안 조치가 비즈니스 요구사항(기능/비기능)을 침해하지 않도록 균형 유지

- **Developer 페르소나**  
  → 아키텍처 설계를 가장 잘 아는 개발자로, 기술적인 현실성과 구현 방법 공유

- **Adversary 페르소나**  
  → 공격자의 입장에서 위협 시나리오를 상상하고 설계 취약점 탐색

- **Defender 페르소나**  
  → 식별된 위협에 대한 방어책을 제시하고 운영/모니터링 가능성 검토

- **AppSec SME 페르소나**  
  → Threat Modeling 전반을 이끄는 보안 전문가로, 토론 조율과 품질 보증 역할

## 일관된 방법론을 유지하라

하나의 Threat Modeling 방법론(포맷)을 **지속적으로 사용하는 것이 매우 중요**합니다.

- 다른 팀 간 협업 시 학습 시간이 줄어들고,
- 이전에 만든 Threat Model을 재사용하거나 참고하기 쉬우며,
- 조직 내 위협 대응 수준의 일관성이 유지됩니다.

## 기존 워크플로우 툴을 활용하라

- 개발팀이 이미 사용하는 **이슈 트래킹, 문서 협업 툴**을 Threat Modeling에도 활용
- **피드백, 승인, 조치사항**을 한 곳에서 관리 → **비동기 협업** 가능
- AppSec SME도 **여러 팀을 동시에 효과적으로 지원** 가능

## 워크로드를 작은 기능 단위로 나누자

- 전체 워크로드가 아닌 **기능 단위로 Threat Modeling 수행**
- 하나의 asset과 entry point 그리고 2개의 component로 최소한의 socpe이상을 가진 기능을 가정한다. 이거보다 더 작은 scope은 threat modeling의 대상이 아니다.
- Asset은 사용자 인증 정보, 고객 정보 등이 될 것이고 Entry Point는 API Gateway의 REST API endpoint와 같은 지점을 의미하고 두개 이상의 컴포넌트는 API Gateway와 Lambda 함수와 같은 구성요소를 의미한다.

### 장점:
- Agile 프로세스와 잘 맞음
- 더 세분화된 위협 탐지 가능
- **재사용 가능한 Threat Model** 구성 가능
- 일부 기능 위협으로 전체 릴리즈가 막히지 않음

## Ownership을 분산하라

- 중앙 보안팀이 모든 Threat Model을 만드는 구조는 **확장에 한계**, 인력에 한계에 도달하기에 중앙 전담보다 분산이 좋다.
- **기능 개발팀이 직접 Threat Model 작성**  
  → 보안 인식 향상 및 반복적 개선 가능
- AppSec SME는 **조율자 및 자문 역할**로 전환

## Entry Point를 명확히 식별하라

- 사용 중인 AWS 서비스의 **엔드포인트 종류 파악**
  - 예: S3는 API 기반, EC2는 SSH/API 등 다양한 진입점 존재
- **고객이 구성한 엔트리포인트도 포함**해 모델링해야 함

## 무엇이 잘못될 수 있는가 (위협)를 식별하라

- **STRIDE**, **OWASP Top 10** 등을 활용한 브레인스토밍
- 조직 특화된 **위협 카탈로그** 작성 → 일관성 및 속도 향상

## 위협에 대한 보안 대응(미티게이션)을 평가하라

- **직접 만든 코드**: input validation, 인증, 세션관리 등 확인
- **외부 SaaS, AWS 구성요소**도 함께 고려
- **Shared Responsibility Model** 이해 필요

### 예시:
- **EC2**: 고객 책임 많음
- **RDS**: OS는 AWS가 책임, DB 설정은 고객이 책임
- **S3, KMS 등**: 운영은 AWS, API 권한 등은 고객 책임

- **IAM, 암호화, 네트워크 보안, 로깅 등 보안 도메인**을 포함
- **CloudFormation, IAM Policy 등 코드 기반 증거**로 모델을 명확하게 설명

## ‘얼마나 하면 충분한가’의 기준 설정

- 모든 위협을 완벽히 제거하기보다, **리스크 기반 판단**으로 적절히 마무리
- **보안 vs. 릴리즈 일정** 사이의 긴장 관계를 **건설적으로 수용**

## 과거보다 ‘지금부터’ 시작하라

- 이미 배포된 기능 모두를 돌아볼 필요 없음
- **앞으로 배포할 기능부터 Threat Modeling 적용**
  → 팀이 학습하며 보안 역량 내재화

## 주로 언급되는 3가지 방법론
### STRIDE (Based on type of threat)
STRIDE는 위협의 유형을 체계적으로 식별하고 분류하는 데 중점을 둡니다. 보통 시스템의 데이터 흐름 다이어그램(DFD)을 기반으로 각 구성 요소(프로세스, 데이터 저장소 등)에 어떤 위협이 존재할 수 있는지 분석하는 데 사용됩니다.

* **Spoofing** - 다른 이용자의 권한을 이용해서 시스템의 접근 권한을 획득하는 위협.
  * **대응 (Countermeasure)**: 인증(Authentication) (예: 전자 서명, 패스워드, 홍채인식 등)

* **Tampering** - 시스템에 있는 정보를 악의적으로 수정하는 위협.
  * **대응 (Countermeasure)**: 무결성(Integrity) (예: 해시, 전자 서명)

* **Repudiation** - 공격을 했으나 그 공격을 부인하는 위협.
  * **대응 (Countermeasure)**: 부인 방지(Non-repudiation) (예: 전자 서명, 감시 로그)

* **Information Disclosure** - 민감한 데이터를 유출시키는 위협.
  * **대응 (Countermeasure)**: 기밀성(Confidentiality) (예: 암호화)

* **Denial of Service** - 시스템을 정상적으로 사용할 수 없도록 만드는 위협.
  * **대응 (Countermeasure)**: 가용성(Availability) (예: 필터링, 공격 모니터링)

* **Elevation of Privilege** - 권한이 없는 유저의 권한을 올려버리는 위협.
  * **대응 (Countermeasure)**: 인가/권한 부여(Authorization)

### DREAD(Based on level of dangerous threat)
DREAD는 STRIDE와 마찬가지로 마이크로소프트에서 개발된 방법론으로, 식별된 위협의 위험도를 정량적으로 평가하고 우선순위를 정하는 데 사용됩니다. STRIDE가 위협을 '식별'하는 데 중점을 둔다면, DREAD는 그 위협이 얼마나 '위험한지'를 판단하는 데 초점을 맞춥니다.
* Damage Potential - 공격 성공 시 피해 규모.
* Reproducibility - 공격의 재현이 얼마나 쉬운지.
* Exploitability cost - 공격에 필요한 노력이나 비용.
* Affected users - 공격에 영향을 받는 사용자의 수.
* Discoverability - 취약점을 발견하기 얼마나 쉬운지.
* $$ Risk value = {(Damage + Affected users) * (Reproducibility + Exploitability + discoverability)} $$

### PASTA (Process for Attack Simulation and Threat Analysis)
공격자 관점에서 비즈니스 위험을 분석하는 7단계의 리스크 중심 방법론입니다.
* **1단계: 비즈니스 및 보안 목표 정의**: 비즈니스 목표와 그에 따른 보안 요구사항을 정의합니다.
* **2단계: 기술 범위 정의**: 분석할 시스템의 아키텍처와 데이터 흐름을 정의합니다.
* **3단계: 애플리케이션 분석**: 애플리케이션의 구성요소를 분해하고 잠재적 취약점을 식별합니다.
* **4단계: 위협 분석**: 위협 인텔리전스를 기반으로 시스템에 대한 잠재적 위협을 분석합니다.
* **5단계: 취약점 분석**: 식별된 위협과 시스템의 취약점을 매핑하고 분석합니다.
* **6단계: 공격 모델링**: 공격자가 취약점을 이용하는 시나리오(공격 트리)를 시뮬레이션합니다.
* **7단계: 리스크 및 영향 분석**: 공격 성공 가능성과 비즈니스 영향을 기반으로 리스크를 평가하고 완화 전략을 수립합니다.