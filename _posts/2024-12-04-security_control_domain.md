---
title: Security Control Domains and Associated Roles
tags: Intermediate-Payments-Cybersecurity
key: page-security_control_domain
categories: [Cybersecurity, Payment]
author: hyoeun
math: true
mathjax_autoNumber: true
---

# Understanding Information Security: Key Areas and Practices

## Organizational Structure of Information Security Under the CISO
- **Cyber Defense**  
- **GRC (Governance, Risk, and Compliance)**  
- **Security Operations**  
- **Identity and Access Management (IAM)**  
- **Endpoint Protection**  
- **Security Architecture**  
- **Applied Cryptography**  
- **Network Security**  
- **Vulnerability Management**  

## Security Policy Components and Governance
- **Policy**: Rules that define compliance requirements.  
- **Governance**: Oversees risk management and regulatory compliance.  
- **Standard**: Established criteria or norms.  
- **Process**: High-level workflows.  
- **Procedure**: Detailed instructions for specific tasks.  

## Human Resource Security
- Verify candidates' backgrounds and review their ability to perform job duties.  
- Ensure that they have received proper training and education.  
- Define responsibilities and establish acceptable work policies.  

## Security Awareness and Training
- Train employees to understand and follow cybersecurity guidelines to use systems safely.  
- Such training is a mandatory requirement under standards like PCI DSS.  

## Asset Management
- Goes beyond simple asset listing to include lifecycle management, risk assessment, and compliance facilitation.  

## Identity and Access Management (IAM)
1. **Authentication**: The process of verifying an entity’s identity.  
2. **Authorization**: The process of granting access to resources.  
- **Lifecycle**: Joining the organization → Access request ↔ Department transfer → Offboarding.  

## Data Protection
- **Data in Transit**: Protected using encryption technologies like SSL/TLS.  
- **Data at Rest**: Secured through hardware encryption or cryptographic methods.  
- **Data in Use**: Protected using methods like screen savers and data masking.  

## Physical Security
- Control access to facilities (locks, key management).  
- Secure power and communication cables.  
- Issue IDs for employees and visitors.  
- Protect IT assets from natural disasters and accidents.  
- Provide additional security for sensitive areas.  

## Security Operations

### Baseline Security Configuration
- Establishes security foundations through pre-configured security settings.  

### Change, Incident, and Problem Management
- **Change Management**: Ensures confidentiality, integrity, and availability (CIA) during system changes. Testing and approval are required for all changes.  
- **Incident Management**: Maintains service availability and ensures rapid recovery to minimize business impact.  
- **Problem Management**: Identifies root causes and prevents similar incidents from recurring.  

### Golden Rules of Change Management
- Test in a lower environment.  
- Create backup and rollback plans.  
- Involve at least two reviewers.  
- Verify changes in real-time before full implementation.  

### Security Logging and Monitoring
- **Security Logging**: Logs user logins, network connections, etc.  
- **Security Monitoring**: Observes and analyzes logs.  
- **Threat Detection**: Identifies patterns, fingerprints, etc.  
- **Real-time Alerting**: Generates alerts based on predefined rules and correlation of security events.  
- **Log Management & Analysis Tools**: Visualize log data for insights.  

### Patch and Vulnerability Management
- Includes penetration testing and security assessments:  
  - **Discover → Assess → Remediate → Verify.**  

### Data Loss Prevention (DLP)
- Tools that help comply with regulations like PCI DSS and protect sensitive data.  
- Typically operates using network-based tools.  

### Endpoint Security and Anti-Malware
- Manages antivirus, Endpoint Detection and Response (EDR), and privilege escalation prevention.  

### Backup and Recovery
- Perform regular backups and back up changes as well.  
- Establish disaster recovery plans and separate the service region from the recovery region.  
- Note that backup costs may be lower than recovery, but the approach can significantly affect costs.  

### Cloud Access Security Broker (CASB)
- A policy enforcement point between end users/devices and cloud applications.  

## Cyber Kill Chain
- **Phases**: Reconnaissance → Weaponization → Delivery → Command and Control → Actions on Objectives.  

## Network Security
- **Zone-based Security**: Divides the network into multiple zones to enhance security.  
- **Zero Trust Architecture**: Assumes no area of the network is inherently secure.  
- **IDS/IPS**: Detects and responds to anomalies, policy violations, and attack indicators.  

## Secure Software Development Lifecycle (SSDLC)
- Unlike traditional SDLC, it includes understanding all resources, data classification, compliance requirements, and access control.  
  - **Stages**: Security Training → Requirements Gathering → Design → Implementation → Verification and Testing → Deployment → Security Training.  

## Supply Chain Risk Management
- Identifies and mitigates risks that arise from supplier relationships and dependencies.  

## Incident Response
- **Phases**: Prepare → Detect ↔ Respond → Learn → Prepare.  
- Uses SIEM (Security Information and Event Management) systems to detect and respond to incidents.  
- Leverages incident knowledge for improvement in the recovery phase and future preparedness.  

## Risk vs. Compliance
- **Risk**: Threats that could harm the organization. Compliance is part of risk, but risks can include threats beyond regulatory concerns.  
- **Compliance**: Legal or regulatory obligations that the organization must follow.  

---

# 정보 보안 이해하기: 주요 영역 및 실천

## CISO 하의 정보 보안 조직 구조
- **사이버 방어 (Cyber Defense)**  
- **GRC (Governance, Risk, and Compliance)**  
- **보안 운영 (Security Operations)**  
- **아이덴티티 및 접근 관리 (IAM)**  
- **엔드포인트 보호 (Endpoint Protection)**  
- **보안 아키텍처 (Security Architecture)**  
- **응용 암호학 (Applied Cryptography)**  
- **네트워크 보안 (Network Security)**  
- **취약점 관리 (Vulnerability Management)**  

## 보안 정책 구성 요소 및 거버넌스
- **정책 (Policy)**: 규정 준수 요구 사항을 정의하는 규칙들.  
- **거버넌스 (Governance)**: 위험 관리 및 규정 준수 감독을 담당.  
- **표준 (Standard)**: 설정된 기준 또는 규범.  
- **프로세스 (Process)**: 높은 수준의 작업 흐름.  
- **절차 (Procedure)**: 특정 작업을 수행하는 세부 지침.  

## 인적 자원 보안
- 후보자의 배경을 확인하고 직무 수행 능력을 검토.  
- 적절한 교육 및 훈련을 받았는지 확인.  
- 책임을 정의하고 수용 가능한 업무 정책을 설정.  

## 보안 인식 및 교육
- 직원들이 사이버 보안에 대해 지켜야 할 것들을 이해하고 시스템을 안전하게 사용할 수 있도록 교육.  
- PCI DSS와 같은 표준에 따라 이러한 교육은 필수 요구 사항에 해당.  

## 자산 관리
- 단순한 자산 목록을 넘어서, 자산의 생애 주기 관리, 위험 평가 및 규정 준수 촉진까지 포함.  

## 아이덴티티 및 접근 관리 (IAM)
1. **인증 (Authentication)**: 엔터티의 신원을 확인하는 과정.  
2. **권한 부여 (Authorization)**: 자원에 대한 접근을 허용하는 과정.  
- **생애 주기 (Lifecycle)**: 조직에 입사 → 접근 요청 ↔ 부서 이동 → 퇴사.  

## 데이터 보호
- **전송 중 데이터 (Data in Transit)**: SSL/TLS와 같은 암호화 기술을 사용하여 보호.  
- **정지 중 데이터 (Data at Rest)**: 하드웨어 보안 또는 암호화를 통해 보호.  
- **사용 중 데이터 (Data in Use)**: 화면 보호기, 마스킹 등으로 보호.  

## 물리적 보안
- 시설 접근 제어(잠금장치, 키 관리).  
- 전력 및 통신 케이블 보안 확보.  
- 직원 및 방문객에 대한 신분증 발급.  
- IT 자산을 자연 재해나 사고로부터 보호.  
- 민감한 구역에 대한 추가 보안 제공.  

## 보안 운영

### 기준 보안 구성 (Baseline Security Configuration)
- 미리 구성된 보안 설정으로 보안 기반을 마련.  

### 변경, 사건, 문제 관리
- **변경 관리 (Change Management)**: 시스템 변경 시 CIA(기밀성, 무결성, 가용성)가 유지되도록 관리. 모든 변화에 테스트와 승인 과정을 거친다.
- **사건 관리 (Incident Management)**: 서비스의 가용성을 유지하고, 빠르게 복구하여 비즈니스에 미치는 영향을 최소화.
- **문제 관리 (Problem Management)**: 근본 원인을 파악하고, 동일한 사고가 발생하지 않도록 예방.  

### 변경 관리의 골든 룰
- 낮은 환경에서 테스트.  
- 백업 및 롤백 계획 작성.  
- 두 명 이상의 검토자 참여.  
- 실시간으로 변경 사항 검증 후 전면 적용.  

### Security logging and monitoring
- Security logging: user login, network connection, etc
- Security monitoring: observing and anlyzing logs
- Threat detection: identify patterns, fingerprint, etc
- Real-time Alerting: generating alerts based on predefined rules and correlation of security events
- Log management & Analysis tools: visualize log data

### 패치 및 취약점 관리
- 침투 테스트 및 보안 평가 등을 포함:  
  - **발견 → 평가 → 수정 → 검증.**  

### 데이터 손실 방지 (DLP)
- PCI DSS와 같은 규정을 준수하도록 돕고, 민감한 데이터 보호를 목표로 하는 툴.  
- 보통 네트워크 기반으로 작동하는 툴들을 사용.

### 엔드포인트 보안 및 안티-멀웨어
- 안티바이러스, EDR(엔드포인트 탐지 및 대응), 권한 상승 방지 등 관리.  

### 백업 및 복구
- 정기적으로 백업을 수행하고, 변경된 사항에 대해서도 백업 필요.  
- 재해 복구 계획을 세우고 서비스 지역과 복구 지역을 분리하는 것이 유리.  
- 백업이 복구에 비해 비용이 저렴할 수 있지만 방식에 따라 훨씬 더 비쌀 수 있음을 유의.

### 클라우드 접근 보안 중개 (CASB)
- 조직의 최종 사용자 및 장치와 클라우드 애플리케이션 간의 정책 집행 지점.  

## 사이버 킬 체인 (Cyber Kill Chain)
- **단계**: 정보 수집(Recon) → 무기화(Weaponization) → 전달(Delivery) → 명령 및 제어(Command and Control) → 목표 수행(Actions on Objectives).  

## 네트워크 보안
- **구역 기반 보안**: 네트워크를 여러 구역으로 나누어 보안을 강화.  
- **제로 트러스트 아키텍처**: 네트워크 내 모든 구역이 안전하지 않다고 가정하고 보안을 강화.  
- **IDS/IPS**: 이상 이벤트나 패턴, 정책 위반, 공격 징후를 탐지하고 대응.  

## 보안 소프트웨어 개발 생애 주기 (SSDLC)
- 기존 SDLC와는 달리 모든 리소스를 이해하고, 데이터 분류, 규정 준수 요구 사항, 접근 제어 등을 고려.  
  - **단계**: 보안 교육 → 요구 사항 수집 → 설계 → 구현 → 검증 및 테스트 → 배포 → 보안 교육.  

## 공급망 리스크 관리
- 공급업체 관계와 의존성에서 발생할 수 있는 리스크를 식별하고 완화.  

## 사건 대응
- **단계**: 준비(Prepare) → 탐지(Detect) ↔ 대응(Respond) → 학습(Learn) → 준비(Prepare).  
- SIEM(보안 사건 및 이벤트 관리) 시스템을 사용하여 사건을 탐지하고 대응.  
- 사건에 대한 지식을 축적하여 회복 단계에서 활용하고, 이후에는 교훈을 바탕으로 개선.  

## 리스크와 규정 준수 (Risk vs. Compliance)
- **리스크 (Risk)**: 조직에 해를 끼칠 수 있는 위협 요소. 규정 준수는 리스크의 일부로 포함되지만 그 이상의 위협도 리스크에 포함될 수 있음.  
- **규정 준수 (Compliance)**: 조직이 법적 규제를 준수해야 하는 사항.