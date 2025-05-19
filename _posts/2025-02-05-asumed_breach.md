---
title: Assumed Breach
tags: Assumed-Breach
key: page-assumed_breach
categories: [Cybersecurity, Security Operations]
author: hyoeun
math: true
mathjax_autoNumber: true
---

# Assumed Breach: A Paradigm Shift in Security Architecture

In modern cybersecurity, a purely "defensive" mindset is no longer sufficient. Advanced threat actors infiltrate systems through increasingly diverse vectors, rendering perimeter-based security models progressively ineffective. Against this backdrop, the concept of **Assumed Breach**—the presumption that a system has already been compromised—has emerged as a foundational security strategy. This article explores the conceptual underpinnings, security engineering implications, and practical implementations of the Assumed Breach model.

## Assumed Breach: Definition and Philosophical Foundation

**Assumed Breach** is predicated on the dissolution of the traditional trust boundary. Closely aligned with the philosophy of "Zero Trust," it posits that even internal systems should not be inherently trusted and assumes persistent compromise of subsystems. The model rests on the following core premises:

- Adversaries may already reside within the internal network.
- Credential theft or privilege escalation may have already occurred.
- Even defensive mechanisms and logging infrastructure may be manipulated.

Far from being pessimistic, these assumptions reflect a realism grounded in empirical threat analysis. For instance, the SolarWinds supply chain attack and the breach of identity systems like Okta illustrate how internal trust models can be fundamentally flawed.

## Contrasting Traditional Security Models

Conventional security models emphasize perimeter defense, drawing a rigid distinction between the "trusted" internal and the "untrusted" external. However, the rise of cloud-native infrastructure, remote work, and SaaS ecosystems has blurred these boundaries, significantly undermining perimeter effectiveness.

In contrast, Assumed Breach entails a philosophical inversion:

- **Breach is inevitable and should be assumed.**
- **Trust is not a default but must be verified.**
- **Security must prioritize redundancy and resilience.**

## Technical Principles of Implementation

The Assumed Breach model transcends abstraction, offering concrete principles for engineering resilient security systems:

- **Consistent Application of Least Privilege**
  - Users and service accounts should be granted the minimal level of access necessary, with regular privilege reviews.

- **Micro-segmentation of Internal Networks**
  - Logical and physical segmentation localizes breach impact. Even service-to-service communication should require explicit authorization and mutual authentication.

- **Detection & Response-first Security Posture**
  - The focus shifts from prevention to rapid detection and automated response. Implementation includes SOAR, MITRE ATT&CK-aligned detection rules, and integration of SIEM/SOAPA frameworks.

- **Ensuring Logging Integrity and Survivability**
  - Logs must be collected through segregated channels, stored in immutable formats (e.g., WORM storage), and architected with adversarial manipulation in mind.

## Applied Case Studies

### Re-architecting IAM Policies and Privilege Models
Under an Assumed Breach paradigm, identity and access management is not a barrier but a risk distribution mechanism. Rather than assigning broad access to individual accounts, roles are decomposed to the finest operational granularity, with conditional access controls enforced wherever possible.

### Institutionalizing Red/Blue Team Simulation Exercises
Breach assumption should not remain hypothetical. Red teams emulate real-world adversaries, while blue teams engage in real-time detection and containment. Purple team strategies formalize the feedback loop, enabling the continual evolution of detection capabilities.

### Redundant and Encrypted Log Collection Infrastructure
Centralized logging systems can present a single point of failure. From an Assumed Breach standpoint, logging pipelines must be diversified, encrypted in transit and at rest, and analyzed within isolated security domains.

### Mutual TLS and Policy-driven Internal Access Control
Even intra-system communications must not be implicitly trusted. Implementing mutual TLS with dynamic policy engines (e.g., OPA, Envoy with SPIRE) dramatically reduces the surface area for lateral movement.

---

좋아, 영어 버전은 이미 완료되었고, 이제 요청대로 같은 내용을 반영한 한글 버전도 마무리해서 아래에 정리해줄게:

---

# Assumed Breach: 침해 가정을 기반으로 한 보안 아키텍처의 패러다임 전환

현대 사이버 보안 환경에서 단순한 “방어적” 접근은 더 이상 충분하지 않다. 공격자는 다양한 경로로 조직 내부에 침투하며, 기존의 경계 기반 보안 모델은 점차 그 실효성을 상실하고 있다. 이러한 맥락 속에서 대두된 것이 바로 **Assumed Breach**, 즉 시스템이 이미 침해되었음을 전제로 한 보안 전략이다. 이 글에서는 해당 개념의 철학적 기반, 보안 공학적 함의, 그리고 실무 적용 사례에 대해 다룬다.

## Assumed Breach: 정의와 철학

**Assumed Breach**는 기존의 신뢰 경계를 해체한다. 이는 "제로 트러스트(Zero Trust)" 모델과 밀접하게 연관되어 있으며, 시스템 내부 역시 기본적으로 신뢰하지 않는다는 전제를 따른다. 핵심 가정은 다음과 같다:

- 공격자가 이미 네트워크 내부에 상주할 수 있다.
- 자격 증명 탈취 또는 권한 상승이 이미 일어났을 수 있다.
- 방어 시스템이나 로깅 인프라조차 조작되었을 수 있다.

이는 단순한 비관적 관점이 아니라, 실증적 사건 분석을 기반으로 한 현실주의적 모델이다. SolarWinds 공급망 공격이나 Okta 인증 인프라 침해 사건은 내부 신뢰 모델의 구조적 취약성을 명확히 보여준다.

## 전통 보안 모델과의 차이점

기존 모델은 내부와 외부를 경계로 구분하고, 외부의 위협만을 차단하는 데 집중한다. 그러나 클라우드 기반 인프라, 원격 업무, SaaS 생태계의 확산으로 인해 경계는 점차 모호해지고 있다.

Assumed Breach는 다음과 같은 사고 전환을 요구한다:

- **침해는 피할 수 없으며 전제되어야 한다.**
- **신뢰는 검증을 통해 동적으로 부여되어야 한다.**
- **보안은 이중화와 복원력을 중심으로 설계되어야 한다.**

## 구현을 위한 기술적 원칙

Assumed Breach는 단순한 개념적 모델을 넘어, 보안 시스템의 구조적 설계 원칙을 제시한다:

- **최소 권한 원칙의 일관된 적용**  
  사용자 및 서비스 계정은 가능한 가장 제한된 권한을 부여받아야 하며, 정기적으로 재검토되어야 한다.

- **내부 네트워크의 마이크로 세그멘테이션**  
  논리적/물리적 분리를 통해 침해 범위를 최소화하고, 모든 서비스 간 통신에 명시적 인증 및 승인을 요구한다.

- **탐지 및 대응 중심 보안 전략**  
  사전 차단보다는 조기 탐지와 자동화된 대응에 초점을 둔다. SOAR, MITRE ATT&CK 기반 탐지, SIEM/SOAPA 통합 전략 등이 포함된다.

- **로깅 무결성과 복원력 보장**  
  로그는 격리된 채널을 통해 수집되며, WORM 같은 불변 저장소에 저장되고 공격자의 조작 가능성까지 고려해 설계되어야 한다.

## 실무 적용 사례

### IAM 구조의 리디자인
Assumed Breach 모델은 계정 탈취를 기본 가정하므로 IAM은 권한 분산과 격리 중심으로 설계되어야 한다. 역할 단위로 세분화하고 조건 기반 접근 정책을 도입하여 리스크를 최소화한다.

### 침해 시뮬레이션의 체계화
침해 가정은 이론에 머물러선 안 되며, Red 팀은 실제 공격자처럼 행동하고 Blue 팀은 실시간 대응을 수행해야 한다. Purple 팀 전략은 이 두 팀 간의 피드백 루프를 통해 탐지 역량을 향상시킨다.

### 로그 인프라 이중화 및 암호화
로깅 시스템은 단일 실패 지점이 될 수 있으므로, 수집 경로의 중복 구성, 전송 및 저장 암호화, 별도의 분석 도메인을 적용해 공격 시도에 대비해야 한다.

### 내부 시스템 간 mTLS 및 정책 기반 접근 제어
내부 서비스 간 통신조차도 무조건 신뢰하지 않고, mTLS와 정책 엔진(예: OPA, Envoy + SPIRE)을 통해 lateral movement를 제한한다.