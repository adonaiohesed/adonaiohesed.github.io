---
title: Key Roles in Data Governance and System Security
tags: Custodian
key: page-key_roles_in_data_governance
categories: [Cybersecurity, Governance Risk and Compliance]
author: hyoeun
math: true
mathjax_autoNumber: true
---

## Key Roles in Data Governance and System Security

In the **cybersecurity** landscape of a large organization, a clear distribution of responsibilities is essential for effectively protecting data and systems. Beyond merely implementing technical controls, establishing boundaries for who holds ultimate responsibility for which assets, who performs day-to-day operations, and who uses the systems forms the foundation of the security framework.

The following defines the six key entities that play crucial roles in data governance and system security, along with their security-related responsibilities.

### 1. Data Owner

The **Data Owner** is a senior manager or executive who holds the **ultimate responsibility for a specific data asset**. They are often the leader of the department that creates or maintains the data.

* **Key Responsibilities:**
    * **Data Classification:** Determining the importance and sensitivity of the data (e.g., Confidential, Internal Use Only, Public) and assigning the required security level.
    * **Defining Security Requirements:** Defining and approving the **minimum security controls** necessary to maintain the Confidentiality, Integrity, and Availability (CIA) of the data.
    * **Access Authorization:** Defining the groups of users who require access to the data and providing the final approval for those access requests.
    * **Compliance:** Ensuring compliance with all legal and regulatory requirements (e.g., GDPR, HIPAA) applicable to that data.

### 2. Data Custodian

The **Data Custodian** is responsible for the **physical and technical protection and management of the data** in accordance with the policies and security controls defined by the Data Owner. This role is typically carried out by the IT department or database administration teams.

* **Key Responsibilities:**
    * **Implementing Security Controls:** Implementing and maintaining technical controls such as backup, encryption, access control mechanisms, and audit logging, as mandated by the Data Owner's policies.
    * **Operation and Maintenance:** Securely operating the infrastructure that stores the data, such as database servers, file servers, and storage systems.
    * **Policy Execution:** Applying and managing the access permissions approved by the Data Owner within the systems.

### 3. System Owner

The **System Owner** is an individual or department responsible for the **acquisition, development, operation, maintenance, and security of a specific information system** (applications, network devices, servers, etc.). While the Data Owner focuses on the 'data,' the System Owner focuses on the 'system' that processes the data.

* **Key Responsibilities:**
    * **System Security Policies:** Developing and implementing security policies and procedures for the system.
    * **Risk Management:** Regularly assessing system vulnerabilities and implementing measures to mitigate identified risks.
    * **Resource Allocation:** Securing and allocating the financial and human resources necessary to meet the system's security requirements.
    * **Change Management:** Ensuring that all major system changes undergo a security impact assessment.

### 4. Administrator

The **Administrator (System Administrator or Security Administrator)** is the technical expert who performs the **day-to-day operations and technical management of the system** according to the policies and procedures defined by the System Owner. They often possess the highest technical privileges (e.g., Root or Domain Admin), making their role and controls critically important for security.

* **Key Responsibilities:**
    * **Patch and Configuration Management:** Performing regular security patching and vulnerability management for operating systems, middleware, and applications.
    * **User and Access Management:** Creating, modifying, and deleting user accounts, and setting and maintaining Access Control Lists (ACLs) based on the principle of least privilege.
    * **Monitoring and Response:** Monitoring system activities through Security Information and Event Management (SIEM) systems and taking initial response actions during security incidents.

### 5. End-User

The **End-User** is any employee who uses the organization's information systems and data to **perform their duties**. They are often the targets of the most common security risks—**human error** or **social engineering attacks**—and can therefore be a critical weak link in the security chain.

* **Key Responsibilities:**
    * **Compliance with Security Policies:** Adhering to the organization's password policy, confidential information handling procedures, and Acceptable Use Policy (AUP).
    * **Threat Awareness:** Identifying common threats such as phishing, malware, and social engineering attacks, and reporting them to the security team.
    * **Asset Protection:** Physically securing assigned devices (laptops, phones) and preventing unauthorized access.

### 6. Auditor

The **Auditor** is an independent professional, internal or external, who **objectively evaluates** the effectiveness of the organization's security controls, procedures, and regulatory compliance. They play a key role in ensuring the transparency and trustworthiness of the security environment.

* **Key Responsibilities:**
    * **Control Testing:** Testing and verifying that the security controls defined by the Data Owner and System Owner, and implemented by the Data Custodian, are operating effectively.
    * **Compliance Assessment:** Evaluating whether the organization is compliant with external regulations and standards such as GDPR, ISO 27001, and SOC 2.
    * **Reporting and Recommendations:** Documenting identified vulnerabilities, control deficiencies, and policy violations, reporting them to management, and providing recommendations for improvement.

| Role | Focus Area | Nature of Security Role |
| :--- | :--- | :--- |
| **Data Owner** | Data (Information) | Ultimate responsibility and policy definition |
| **Data Custodian** | Data (Technical Protection) | Implementation of technical controls based on policy |
| **System Owner** | System (Asset) | System security strategy and risk management |
| **Administrator** | System (Operation) | Day-to-day technical management and patching |
| **End-User** | Use of Information System | Policy adherence and threat awareness |
| **Auditor** | Controls (Verification) | Independent evaluation of control effectiveness and compliance |

This distribution of roles contributes to reducing the risk of insider threats or errors by enforcing the **Principle of Separation of Duties**, which prevents any single individual from having exclusive control over an entire system.

---

## 데이터 거버넌스 및 시스템 보안의 핵심 역할

대규모 조직의 **사이버 보안** 환경에서 데이터와 시스템을 효과적으로 보호하려면 명확한 책임 분배가 필수적입니다. 단순히 기술적 통제를 구현하는 것을 넘어, 누가 어떤 자산에 대해 최종 책임을 지고, 누가 일상적인 운영을 수행하며, 누가 시스템을 사용하는지에 대한 경계를 설정하는 것이 보안 프레임워크의 근간을 이룹니다.

다음은 데이터 거버넌스와 시스템 보안에 있어 핵심적인 역할을 수행하는 여섯 가지 주체에 대한 정의와 그들의 보안 관련 책임입니다.

### 1. Data Owner (데이터 소유자)

**Data Owner**는 특정 **데이터 자산에 대한 궁극적인 책임**을 지는 고위 관리자 또는 경영진입니다. 이들은 데이터를 생성하거나 유지 관리하는 부서의 리더인 경우가 많습니다.

* **주요 책임:**
    * **데이터 분류 (Data Classification):** 데이터의 중요도와 민감도(예: 기밀, 내부용, 공개)를 결정하고 보안 수준을 지정합니다.
    * **보안 요구 사항 정의:** 데이터의 기밀성, 무결성, 가용성(CIA)을 유지하기 위해 필요한 **최소 보안 통제**를 정의하고 승인합니다.
    * **접근 권한 승인:** 데이터에 대한 접근이 필요한 사용자의 그룹을 정의하고 해당 접근 요청을 최종적으로 승인합니다.
    * **규정 준수:** 해당 데이터에 적용되는 모든 법적, 규제적 요구 사항(예: GDPR, HIPAA)을 준수하는지 확인합니다.

### 2. Data Custodian (데이터 관리자)

**Data Custodian**은 Data Owner가 정의한 정책과 보안 통제에 따라 **데이터를 물리적/기술적으로 보호**하고 관리하는 역할을 합니다. 일반적으로 IT 부서나 데이터베이스 관리팀이 이 역할을 수행합니다.

* **주요 책임:**
    * **보안 통제 구현:** Data Owner가 정한 정책에 따라 백업, 암호화, 접근 제어 메커니즘, 감사 로깅 등의 기술적 통제를 구현하고 유지 관리합니다.
    * **운영 및 유지 보수:** 데이터베이스 서버, 파일 서버, 스토리지 시스템 등 데이터를 저장하는 인프라를 안전하게 운영합니다.
    * **정책 실행:** Data Owner가 승인한 접근 권한을 시스템에 적용하고 관리합니다.

### 3. System Owner (시스템 소유자)

**System Owner**는 특정 정보 시스템(애플리케이션, 네트워크 장치, 서버 등)의 **획득, 개발, 운영, 유지 관리 및 보안에 대한 책임**을 지는 개인 또는 부서입니다. Data Owner가 '데이터'에 초점을 맞춘다면, System Owner는 '데이터를 처리하는 시스템' 자체에 초점을 맞춥니다.

* **주요 책임:**
    * **시스템 보안 정책:** 시스템에 대한 보안 정책 및 절차를 개발하고 구현합니다.
    * **위험 관리:** 시스템의 취약점을 정기적으로 평가하고 식별된 위험을 완화하기 위한 조치를 시행합니다.
    * **자원 할당:** 시스템의 보안 요구 사항을 충족하는 데 필요한 재정 및 인적 자원을 확보하고 할당합니다.
    * **변경 관리:** 시스템의 모든 주요 변경 사항이 보안 영향 평가를 거치도록 보장합니다.

### 4. Administrator (관리자)

**Administrator (시스템 관리자 또는 보안 관리자)**는 System Owner가 정의한 정책과 절차에 따라 **시스템의 일상적인 운영 및 기술적 관리**를 수행하는 전문가입니다. 이들은 가장 높은 기술적 권한(예: Root 또는 Domain Admin)을 가지므로 그들의 역할과 통제가 보안에서 매우 중요합니다.

* **주요 책임:**
    * **패치 및 구성 관리:** 운영 체제, 미들웨어, 애플리케이션에 대한 정기적인 보안 패치 및 취약점 관리를 수행합니다.
    * **사용자 및 접근 관리:** 사용자 계정을 생성, 수정, 삭제하고, 최소 권한의 원칙에 따라 접근 제어 목록(ACL)을 설정하고 유지합니다.
    * **모니터링 및 대응:** 보안 이벤트 모니터링 시스템(SIEM)을 통해 시스템 활동을 감시하고, 보안 사고 발생 시 초기 대응 조치를 취합니다.

### 5. End-User (최종 사용자)

**End-User**는 조직의 정보 시스템과 데이터를 사용하여 **자신의 업무를 수행**하는 모든 직원입니다. 이들은 보안 환경에서 가장 흔한 **인적 오류**나 **사회 공학적 공격**의 대상이 되므로, 보안 체인의 중요한 약한 고리가 될 수 있습니다.

* **주요 책임:**
    * **보안 정책 준수:** 조직의 비밀번호 정책, 기밀 정보 처리 절차, Acceptable Use Policy(AUP)를 준수합니다.
    * **위협 인식:** 피싱, 멀웨어, 사회 공학적 공격과 같은 일반적인 위협을 식별하고 이를 보안팀에 보고합니다.
    * **자산 보호:** 할당된 장치(랩톱, 휴대폰)를 물리적으로 안전하게 보호하고 무단 접근을 방지합니다.

### 6. Auditor (감사자)

**Auditor**는 내부 또는 외부의 독립적인 전문가로서, 조직의 보안 통제, 절차, 규정 준수 여부를 **객관적으로 평가**합니다. 이들은 보안 환경의 투명성과 신뢰성을 보장하는 데 핵심적인 역할을 합니다.

* **주요 책임:**
    * **통제 테스트:** Data Owner와 System Owner가 정의하고 Data Custodian이 구현한 보안 통제가 효과적으로 작동하는지 테스트하고 검증합니다.
    * **규정 준수 평가:** 조직이 GDPR, ISO 27001, SOC 2 등의 외부 규제 및 표준을 준수하고 있는지 평가합니다.
    * **보고 및 권고:** 발견된 취약점, 통제 미비점, 정책 위반 사항을 정리하여 경영진에게 보고하고 개선을 위한 권고 사항을 제시합니다.

| 역할 | 초점 대상 | 보안 역할의 본질 |
| :--- | :--- | :--- |
| **Data Owner** | 데이터 (정보) | 궁극적인 책임 및 정책 정의 |
| **Data Custodian** | 데이터 (기술적 보호) | 정책에 따른 기술적 통제 구현 |
| **System Owner** | 시스템 (자산) | 시스템 보안 전략 및 리스크 관리 |
| **Administrator** | 시스템 (운영) | 일상적인 기술 관리 및 패치 적용 |
| **End-User** | 정보 시스템 사용 | 정책 준수 및 위협 인식 |
| **Auditor** | 통제 (검증) | 독립적인 통제 효과 및 규정 준수 평가 |

이러한 역할 분담은 **책임 분리의 원칙 (Separation of Duties)**을 통해 한 사람이 시스템 전체에 대한 통제 권한을 독점하는 것을 방지하여 내부자 위협이나 오류의 위험을 크게 줄이는 데 기여합니다.