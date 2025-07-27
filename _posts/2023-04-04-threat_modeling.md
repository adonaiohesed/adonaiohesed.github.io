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

## Four Common Methodologies

### STRIDE (Based on Type of Threat)

* Conduct threat modeling based on the following six threats:

  1. **Spoofing**: Gaining unauthorized access using another user's identity – Countermeasure: Authentication, digital signatures
  2. **Tampering**: Malicious modification of information – Countermeasure: Integrity measures (hashes, digital signatures)
  3. **Repudiation**: Denying the attack actions – Countermeasure: Non-repudiation, digital signatures, audit logs
  4. **Information Disclosure**: Leakage of sensitive data – Countermeasure: Confidentiality, encryption
  5. **Denial of Service**: Rendering the system unusable – Countermeasure: Availability, filtering, monitoring
  6. **Elevation of Privilege**: Unauthorized privilege escalation – Countermeasure: Authorization

### DREAD (Based on Level of Threat Danger)

* Scores threats as High, Medium, or Low for each criterion, total score represents risk level
* Should be conducted by experienced security professionals, credibility based on expertise and reputable sources (e.g., FireEye reports)

  1. **Damage Potential**: Impact on system
  2. **Reproducibility**: Ease of repeated exploitation
  3. **Exploitability Cost**: Effort or cost needed to execute attack (lower cost implies higher risk)
  4. **Affected Users**: Number of users impacted
  5. **Discoverability**: Ease of discovering the vulnerability
* $$ Risk value = {(Damage + Affected users) * (Reproducibility + Exploitability + discoverability)} $$

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

## 주로 언급되는 4가지 방법론
### STRIDE(Based on type of threat)
* 다음 6가지 위협을 기반으로 threat modeling을 진행한다.
1. Spoofing - 다른 이용자의 권한을 이용해서 시스템의 접근 권한을 획득하는 위협. - Authentication로 대처, 전자 서명, 적절한 인증(패스워드, 홍채인식 등)
1. Tampering - 시스템에 있는 정보를 악의적으로 수정한다. - Integrity로 대처, 해쉬, 전자 서명
1. Repudiation - 공격을 했으나 그 공격을 부인하는 위협. - Non-repudiation으로 대처, 전자 서명, 감시 로그
1. Information Disclosure - 민감한 데이터를 유출시키는 위협 - Confidentiality로 대처, 암호화
1. Denial of Service - 시스템을 정상적으로 사용할 수 없도록 만드는 위협 - Availability로 대처, 필터링, 공격 모니터링, 
1. Elevation of Privilege - 권한이 없는 유저의 권한을 올려버리는 위협 - Authorization으로 대처

### DREAD(Based on level of dangerous threat)
* 각 항목들에 따라서 High, Medium, Low로 점수를 매겨 총점으로 공격의 위험도를 나타낸다. 이런 방법은 경력이 많은 보안 담당자가 해야 하고 이것의 신빙서은 그 작성자의 권위와 실력에서 나온다. 또는 fire eye와 같은 리포트에서 나온 점수를 기반으로 이러한 점수를 매길 수도 있다.
1. Damage Potential - 피해가 어느정도 시스템에 영향을 줄지
1. Reproducibility - 피해가 얼마나 쉽게 반복적으로 일어 날 수 있는지
1. Exploitability cost - 공격을 하기 위해 얼마나 비용이 드는지(비용이 적게 들수록 위험한거다)
1. Affected users - 몇명의 사용자가 피해를 입을지
1. Discoverability - 얼마나 찾기 쉬운 공격일지
* $$ Risk value = {(Damage + Affected users) * (Reproducibility + Exploitability + discoverability)} $$