---
title: MITRE ATT&CK
tags: MITRE ATT&CK
key: page-mitre_attck
categories: [Cybersecurity, Security Operations]
author: hyoeun
mathjax: true
mathjax_autoNumber: true
---

# MITRE ATT&CK Framework: Understanding Cyber Threats and Defense Strategies

## What is MITRE ATT&CK?

MITRE ATT&CK (Adversarial Tactics, Techniques, and Common Knowledge) is a globally accessible knowledge base built on observed real-world cyber attacks. This framework provides a common language that helps the cybersecurity community systematically classify and understand the tactics and techniques associated with specific threat actors.

ATT&CK contains detailed information about attackers' behaviors, the tools and techniques they use, and the objectives they aim to achieve. It's an essential tool for organizations to assess their defensive capabilities, develop threat intelligence, and make security-focused decisions.

## History and Evolution of MITRE ATT&CK

MITRE ATT&CK began as a research project at MITRE in 2013. Initially, it focused on documenting the post-compromise stages of Advanced Persistent Threat (APT) groups. However, over time, the framework expanded and now covers the entire attack lifecycle across various platforms (Windows, macOS, Linux, Cloud, Mobile, ICS, etc.).

Key developmental stages:
- 2015: Released as a publicly available resource
- 2017: Introduction of the Enterprise ATT&CK matrix
- 2018: Addition of Mobile ATT&CK and PRE-ATT&CK
- 2019: Addition of ICS (Industrial Control Systems) ATT&CK
- 2020: Expansion to Cloud and Container platforms
- 2021: Introduction of sub-techniques and improvements to Navigator tool
- 2022: Continuous updates and expansions

## Structure of the MITRE ATT&CK Framework

The MITRE ATT&CK framework consists of the following core components:

### 1. Tactics

Tactics represent the tactical goals that attackers aim to achieve and form the columns of the MITRE ATT&CK matrix. The current Enterprise ATT&CK framework includes the following 14 tactics:

1. **Initial Access**: Establishing an initial foothold in the network
2. **Execution**: Running malicious code
3. **Persistence**: Maintaining access
4. **Privilege Escalation**: Gaining higher-level permissions
5. **Defense Evasion**: Avoiding detection
6. **Credential Access**: Stealing account names and passwords
7. **Discovery**: Gathering information about the environment
8. **Lateral Movement**: Moving through the network
9. **Collection**: Targeting and collecting data of interest
10. **Command and Control**: Communicating with victims
11. **Exfiltration**: Stealing/extracting data
12. **Impact**: Manipulating, interrupting, or destroying data, system integrity, or availability
13. **Reconnaissance**: Gathering information before an attack
14. **Resource Development**: Building attack infrastructure

### 2. Techniques

Techniques describe the methods attackers use to achieve specific tactical objectives. MITRE ATT&CK currently documents over 600 techniques, each with a unique ID (e.g., T1566) and detailed information including:

- Description and how they are used
- Mitigation strategies
- Detection methods
- Related sub-techniques
- Known threat actor use cases
- References and additional materials

### 3. Sub-techniques

Sub-techniques provide more granular variants of a specific technique. For example, the "Phishing" technique (T1566) has sub-techniques such as:
- Spearphishing Attachment (T1566.001)
- Spearphishing Link (T1566.002)
- Spearphishing via Service (T1566.003)

### 4. Mitigations

Mitigations are specific measures to prevent attack techniques or reduce their impact. Each mitigation is identified by a unique ID (e.g., M1049) and linked to specific techniques.

### 5. Detections

MITRE ATT&CK suggests methods and relevant data sources for detecting each technique.

### 6. Groups

Threat actor groups documented in ATT&CK, with detailed descriptions of the techniques, tools, and objectives they use. Each group has a unique ID beginning with G (e.g., G0004).

### 7. Software

Malicious software and tools used by attackers. Each tool has a unique ID beginning with S (e.g., S0154) and is linked to related techniques.

## How to Utilize MITRE ATT&CK

### 1. Threat Modeling

You can use the ATT&CK framework to identify and model the most relevant threats to your organization:
- Identify threat actors relevant to your industry and region
- Understand techniques commonly used by threat actors
- Map potential attack paths and scenarios

### 2. Security Gap Analysis

Map your current security controls to the ATT&CK matrix to identify protection gaps:
- Identify unmapped tactics and techniques
- Evaluate the effectiveness of mitigation and detection controls
- Prioritize areas needing improvement

### 3. Red Team Exercises

ATT&CK helps design more realistic and relevant red team exercises:
- Simulate the TTPs of real threat actors
- Develop scenarios to test specific techniques
- Validate the effectiveness of defensive controls

### 4. Improving Detection and Analysis

Security operations teams can use ATT&CK to enhance detection capabilities:
- Develop SIEM rules and analytics to detect relevant techniques
- Guide threat hunting activities
- Structure alert triage and incident analysis

### 5. Enhancing Threat Intelligence

ATT&CK provides a common language for threat intelligence programs:
- Profile threat actors and analyze attack campaigns
- Organize intelligence around tactics and techniques
- Communicate industry-specific threat trends

### 6. Prioritizing Security Investments

Use ATT&CK to allocate limited resources most effectively:
- Evaluate security tools and solutions
- Develop risk-based mitigation strategies
- Measure the effectiveness of security programs

## Limitations of the MITRE ATT&CK Framework

While MITRE ATT&CK is a powerful tool, it has several limitations:

1. **Incomplete Coverage**: Does not cover all possible attack techniques
2. **Complexity**: May be difficult to fully implement in large organizations
3. **Requires Continuous Maintenance**: Needs regular updates as the threat landscape evolves
4. **Resource Intensive**: Requires significant effort and expertise for effective implementation
5. **Lacks Context**: Does not provide risk levels for all organizations

## Practical Steps for Implementing MITRE ATT&CK

### 1. Define Scope

Don't try to implement everything from the start. Begin by considering:
- The most relevant platforms (Windows, Linux, Cloud, etc.)
- Threat actors most relevant to your organization
- Techniques that represent the greatest risk to your business

### 2. Map Current Controls

Map your current security controls to the ATT&CK matrix:
- Identify current mitigations for each relevant technique
- Map current detection capabilities
- Connect threat response plans to techniques

### 3. Assess Gaps and Develop Roadmap

Identify high-priority gaps and develop a roadmap to address them:
- Identify protection gaps for key threat scenarios
- Develop implementation plans for new security controls and processes
- Create a roadmap for improving detection and response capabilities

### 4. Continuous Assessment and Improvement

Regularly reassess your defensive posture and adjust as needed:
- Incorporate regular red team exercises
- Update your model with new threat actors and techniques
- Measure the effectiveness of security improvements

## Tools and Resources Related to MITRE ATT&CK

### 1. Tools

- **ATT&CK Navigator**: A web-based tool for visually exploring and customizing the matrix
- **MITRE CALDERA**: An automated adversary emulation system based on ATT&CK
- **Atomic Red Team**: Small, executable tests for various ATT&CK techniques
- **ATT&CK Workbench**: A tool for customizing ATT&CK for your own environment
- **VECTR**: A tool for tracking ATT&CK-based red team and blue team exercises

### 2. Integrations

Various security tools and platforms integrate with MITRE ATT&CK:
- SIEM solutions (Splunk, Elastic, QRadar, etc.)
- EDR/XDR platforms (CrowdStrike, Microsoft Defender, SentinelOne, etc.)
- Threat intelligence platforms (ThreatConnect, MISP, Anomali, etc.)
- GRC (Governance, Risk, and Compliance) solutions

## Conclusion

The MITRE ATT&CK framework is an essential tool in modern cybersecurity, enabling organizations to understand and prepare for the behaviors of real threat actors. By integrating the matrix into defense strategies, organizations can allocate security resources more effectively, enhance threat detection capabilities, and strengthen their resilience against cyber threats.

Successful implementation of the framework requires adopting an incremental approach, aligning with business risks, and committing to continuous improvement. This allows organizations to maximize the rich knowledge base of ATT&CK in their security journey.

MITRE ATT&CK is more than just a reference tool. It's a common language and collaborative platform for the entire security community, enabling us to build stronger defenses against cyber threats together.

---

# MITRE ATT&CK 프레임워크: 사이버 위협 이해와 방어 전략

## MITRE ATT&CK란 무엇인가?

MITRE ATT&CK(Adversarial Tactics, Techniques, and Common Knowledge)는 실제 관찰된 사이버 공격을 기반으로 구축된 전 세계적으로 접근 가능한 지식 기반입니다. 이 프레임워크는 사이버 보안 커뮤니티가 특정 위협 행위자와 관련된 전술 및 기술을 체계적으로 분류하고 이해하는 데 도움을 주는 공통 언어를 제공합니다.

ATT&CK는 공격자의 행동, 그들이 사용하는 도구와 기술, 그리고 그들이 달성하고자 하는 목표에 관한 자세한 정보를 담고 있습니다. 이는 조직이 자신의 방어 능력을 평가하고, 위협 인텔리전스를 개발하며, 보안 중심의 의사 결정을 내리는 데 필수적인 도구입니다.

## MITRE ATT&CK의 역사와 발전

MITRE ATT&CK는 2013년 MITRE의 연구 프로젝트로 시작되었습니다. 초기에는 APT(Advanced Persistent Threat) 그룹의 후기 공격 단계를 문서화하는 데 중점을 두었습니다. 그러나 시간이 지남에 따라 프레임워크는 확장되어 이제는 다양한 플랫폼(Windows, macOS, Linux, 클라우드, 모바일, ICS 등)에 걸친 전체 공격 수명 주기를 포함합니다.

주요 발전 단계:
- 2015년: 공개적으로 사용 가능한 리소스로 출시
- 2017년: Enterprise ATT&CK 매트릭스 도입
- 2018년: Mobile ATT&CK 및 PRE-ATT&CK 추가
- 2019년: ICS(산업 제어 시스템) ATT&CK 추가
- 2020년: Cloud 및 Container 플랫폼 확장
- 2021년: 서브테크닉 도입 및 Navigator 도구 개선
- 2022년: 지속적인 업데이트 및 확장

## MITRE ATT&CK 프레임워크의 구조

MITRE ATT&CK 프레임워크는 다음과 같은 핵심 구성 요소로 이루어져 있습니다:

### 1. 전술(Tactics)

전술은 공격자가 달성하고자 하는 전술적 목표를 나타내며, MITRE ATT&CK 매트릭스의 열을 구성합니다. 현재 Enterprise ATT&CK 프레임워크에는 다음과 같은 14개의 전술이 포함되어 있습니다:

1. **초기 접근(Initial Access)**: 네트워크에 대한 초기 접근점 확보
2. **실행(Execution)**: 악성 코드 실행
3. **지속성(Persistence)**: 접근 유지
4. **권한 상승(Privilege Escalation)**: 높은 수준의 권한 획득
5. **방어 회피(Defense Evasion)**: 탐지 회피
6. **자격 증명 접근(Credential Access)**: 계정 이름 및 비밀번호 도용
7. **발견(Discovery)**: 환경에 대한 정보 수집
8. **측면 이동(Lateral Movement)**: 네트워크 내에서 이동
9. **수집(Collection)**: 관심 데이터 타겟팅 및 수집
10. **명령 및 제어(Command and Control)**: 피해자와의 통신
11. **유출(Exfiltration)**: 데이터 도난/유출
12. **영향(Impact)**: 데이터, 시스템 무결성 또는 가용성 조작, 방해 또는 파괴
13. **감시(Reconnaissance)**: 공격 전 정보 수집
14. **리소스 개발(Resource Development)**: 공격 인프라 구축

### 2. 기술(Techniques)

기술은 공격자가 특정 전술적 목표를 달성하기 위해 사용하는 방법을 설명합니다. MITRE ATT&CK에는 현재 600개 이상의 기술이 문서화되어 있으며, 각 기술은 고유한 ID(예: T1566)와 함께 다음과 같은 상세 정보를 포함합니다:

- 설명 및 사용 방법
- 완화 전략
- 탐지 방법
- 관련 서브테크닉
- 알려진 위협 행위자 사용 사례
- 참조 및 추가 자료

### 3. 서브테크닉(Sub-techniques)

서브테크닉은 특정 기술의 더 세분화된 변형을 제공합니다. 예를 들어, "피싱(Phishing)" 기술(T1566)에는 다음과 같은 서브테크닉이 있습니다:
- 스피어피싱 첨부 파일(T1566.001)
- 스피어피싱 링크(T1566.002)
- 스피어피싱 서비스(T1566.003)

### 4. 완화(Mitigations)

완화는 공격 기술을 방지하거나 그 영향을 줄이기 위한 구체적인 조치입니다. 각 완화는 고유 ID(예: M1049)로 식별되며 특정 기술과 연결됩니다.

### 5. 탐지(Detections)

MITRE ATT&CK는 각 기술을 탐지하기 위한 방법과 관련 데이터 소스를 제안합니다.

### 6. 그룹(Groups)

ATT&CK에 문서화된 위협 행위자 그룹으로, 그들이 사용하는 기술, 도구, 및 목표가 상세히 기술되어 있습니다. 각 그룹은 G로 시작하는 고유 ID(예: G0004)를 가집니다.

### 7. 소프트웨어(Software)

공격자가 사용하는 악성 소프트웨어 및 도구입니다. 각 도구는 S로 시작하는 고유 ID(예: S0154)를 가지며 관련 기술과 연결됩니다.

## MITRE ATT&CK 활용 방법

### 1. 위협 모델링

ATT&CK 프레임워크를 사용하여 조직에 가장 관련성 높은 위협을 식별하고 모델링할 수 있습니다:
- 산업 및 지역과 관련된 위협 행위자 식별
- 위협 행위자가 일반적으로 사용하는 기술 이해
- 잠재적 공격 경로 및 시나리오 매핑

### 2. 보안 격차 분석

현재 보안 제어를 ATT&CK 매트릭스에 매핑하여 보호 격차를 식별할 수 있습니다:
- 매핑되지 않은 전술 및 기술 식별
- 완화 및 탐지 제어의 효과 평가
- 개선이 필요한 영역 우선순위 지정

### 3. 레드 팀 실습

ATT&CK는 더 현실적이고 관련성 높은 레드 팀 실습을 설계하는 데 도움이 됩니다:
- 실제 위협 행위자의 TTPs를 시뮬레이션
- 특정 기술 테스트를 위한 시나리오 개발
- 방어 제어의 효과 검증

### 4. 탐지 및 분석 개선

보안 운영 팀은 ATT&CK를 사용하여 탐지 능력을 강화할 수 있습니다:
- 관련 기술을 탐지하기 위한 SIEM 규칙 및 분석 개발
- 위협 사냥 활동 안내
- 알림 분류 및 인시던트 분석 구조화

### 5. 위협 인텔리전스 강화

ATT&CK는 위협 인텔리전스 프로그램을 위한 공통 언어를 제공합니다:
- 위협 행위자 프로파일링 및 공격 캠페인 분석
- 전술 및 기술에 대한 인텔리전스 구성
- 산업별 위협 동향 커뮤니케이션

### 6. 보안 투자 우선순위 지정

제한된 리소스를 가장 효과적으로 할당하기 위해 ATT&CK를 사용합니다:
- 보안 도구 및 솔루션 평가
- 위험 기반 완화 전략 개발
- 보안 프로그램의 효과 측정

## MITRE ATT&CK 프레임워크의 한계

MITRE ATT&CK는 강력한 도구이지만 몇 가지 한계가 있습니다:

1. **완벽하지 않은 범위**: 모든 가능한 공격 기술을 다루지는 않습니다.
2. **복잡성**: 대규모 조직에서 완전히 구현하기 어려울 수 있습니다.
3. **지속적인 유지 관리 필요**: 위협 환경이 변화함에 따라 정기적인 업데이트가 필요합니다.
4. **리소스 집약적**: 효과적인 구현을 위해 상당한 노력과 전문성이 필요합니다.
5. **컨텍스트 부족**: 모든 조직에 대한 위험 수준을 제공하지 않습니다.

## MITRE ATT&CK 구현을 위한 실용적인 단계

### 1. 범위 정의

처음부터 모든 것을 구현하려고 하지 마세요. 다음을 고려하여 시작하세요:
- 가장 관련성 높은 플랫폼(Windows, Linux, Cloud 등)
- 조직에 가장 중요한 위협 행위자
- 비즈니스에 가장 큰 위험을 나타내는 기술

### 2. 현재 제어 매핑

현재 보안 제어를 ATT&CK 매트릭스에 매핑합니다:
- 각 관련 기술에 대한 현재 완화 조치 식별
- 현재 탐지 능력 매핑
- 위협 대응 계획을 기술에 연결

### 3. 격차 평가 및 로드맵 개발

우선 순위가 높은 격차를 식별하고 이를 해결하기 위한 로드맵을 개발합니다:
- 주요 위협 시나리오에 대한 보호 격차 식별
- 새로운 보안 제어 및 프로세스를 위한 구현 계획 개발
- 탐지 및 대응 역량 개선을 위한 로드맵 생성

### 4. 지속적인 평가 및 개선

정기적으로 방어 태세를 재평가하고 필요에 따라 조정합니다:
- 정기적인 레드 팀 연습 통합
- 새로운 위협 행위자 및 기술을 고려하여 모델 업데이트
- 보안 개선 사항의 효과 측정

## MITRE ATT&CK 관련 도구 및 리소스

### 1. 도구

- **ATT&CK Navigator**: 매트릭스를 시각적으로 탐색하고 사용자 지정할 수 있는 웹 기반 도구
- **MITRE CALDERA**: ATT&CK 기반 자동화된 적대적 에뮬레이션 시스템
- **Atomic Red Team**: 다양한 ATT&CK 기술을 테스트하기 위한 실행 가능한 소규모 테스트
- **ATT&CK Workbench**: 자체 환경에 맞게 ATT&CK를 사용자 지정하기 위한 도구
- **VECTR**: ATT&CK 기반 레드 팀 및 블루 팀 연습을 추적하는 도구

### 2. 통합

다양한 보안 도구 및 플랫폼이 MITRE ATT&CK와 통합됩니다:
- SIEM 솔루션(Splunk, Elastic, QRadar 등)
- EDR/XDR 플랫폼(CrowdStrike, Microsoft Defender, SentinelOne 등)
- 위협 인텔리전스 플랫폼(ThreatConnect, MISP, Anomali 등)
- GRC(거버넌스, 위험 및 규정 준수) 솔루션

## 결론

MITRE ATT&CK 프레임워크는 현대 사이버 보안의 필수적인 도구로, 조직이 실제 위협 행위자의 행동을 이해하고 이에 대비할 수 있게 해줍니다. 매트릭스를 방어 전략에 통합함으로써 조직은 보안 리소스를 더 효과적으로 할당하고, 위협 감지 능력을 향상시키며, 사이버 위협에 대한 대응력을 강화할 수 있습니다.

프레임워크를 성공적으로 구현하려면 점진적 접근 방식을 채택하고, 비즈니스 위험에 맞게 조정하며, 지속적인 개선에 전념해야 합니다. 이를 통해 조직은 보안 여정에서 ATT&CK의 풍부한 지식 기반을 최대한 활용할 수 있습니다.

MITRE ATT&CK는 단순한 참조 도구 이상입니다. 이는 보안 커뮤니티 전체를 위한 공통 언어이자 협업 플랫폼으로, 우리가 함께 사이버 위협에 대항하여 더 강력한 방어 체계를 구축할 수 있게 합니다.