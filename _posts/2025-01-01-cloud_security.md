---
title: Cloud Security Overview
tags: Cloud-Security
key: page-cloud_security_overview
categories: [Cybersecurity, Cloud Security]
author: hyoeun
math: true
mathjax_autoNumber: true
---

When focusing on cloud security, one must consider securing infrastructure, network, data, applications, and managing identities and access, security operations, governance, risk, and compliance management. However, the key is not for the responsible person to try to handle all security aspects, but to effectively distribute responsibilities with the cloud provider and focus on the specific areas that are your direct responsibility.

# Google Cloud Security: A Comprehensive Cloud Security Guide

## 1. Shared Responsibility Model in Cloud Security

Cloud security is no longer the responsibility of a single entity. Google Cloud presents a new security approach that goes beyond 'Shared Responsibility' to 'Shared Fate'.

### Core of Shared Responsibility
- Cloud Provider: Responsible for infrastructure security
- Customers: Responsible for application and data security

### Shared Fate Approach
- Preparing a secure landing zone
- Providing clear security control guidance
- Supporting cyber insurance
- Offering security best practices

## 2. Infrastructure Security

Google Cloud's infrastructure security adopts a multi-layered and thorough approach.

### Key Security Features
- Custom-designed hardware infrastructure
- Lightweight and hardened Linux operating system
- Hardware trust establishment through Titan security chips
- End-to-end supply chain security

## 3. Network Security

### Google Cloud VPC Security Capabilities
- Private connectivity between regions
- VPC flow logs
- Centrally managed firewall rules
- Service perimeter security

## 4. Application Security

### Key Protection Mechanisms
- Traffic control based on user authentication and authorization
- Blocking bots and fraudulent users
- Web Application and API Protection (WAAP)
  * Cloud Load Balancing
  * Cloud Armor
  * reCAPTCHA Enterprise

## 5. Software Supply Chain Security

### Establishing Trust Chain
- SLSA (Supply Chain Levels for Software Artifacts) Framework
- Binary Authorization
- Dependency and vulnerability scanning
- Continuous policy verification

## 6. Data Security

### Encryption and Data Protection
- Encryption at rest and in transit
- Confidential Computing
- Bring Your Own Key (BYOK)
- Data Loss Prevention (DLP)

## 7. Identity and Access Management

### Core Security Mechanisms
- Authentication through Cloud Identity
- Multi-factor authentication
- Granular IAM roles
- BeyondCorp Zero Trust model

## 8. Endpoint Security

### User and Device Protection
- Safe Browsing
- Web Risk API
- Device policy management

## 9. Security Monitoring and Operations

### SecOps Tools
- Security Command Center
- Audit Logs
- Security Orchestration and Response (SOAR)

## 10. Governance, Risk, and Compliance

### Key Certifications and Standards
- PCI DSS
- FedRAMP
- HIPAA
- Continuous security verification

---

클라우드 보안을 신경쓸때, securing infrastructure, network, data, applications, and managing identities and access, security operations and governance, risk & compliance management 등을 신경써야 한다고 생각한다. 하지만 중요한건 담당자로써 모든 보안을 신경쓸 것이 아니라 Cloud provider와 그 책임을 잘 분배하여 내가 신경 써야 할 부분에 초점을 맞춘다.

# Google Cloud Security: 포괄적인 클라우드 보안 가이드

## 1. 클라우드 보안의 공유 책임 모델

클라우드 보안은 더 이상 단일 주체의 책임이 아닙니다. Google Cloud는 '공유된 책임(Shared Responsibility)'을 넘어 '공동의 운명(Shared Fate)'이라는 새로운 보안 접근 방식을 제시합니다.

### 공유된 책임의 핵심
- 클라우드 제공자: 인프라 보안 책임
- 고객: 애플리케이션 및 데이터 보안 책임

### 공동의 운명(Shared Fate) 접근 방식
- 안전한 랜딩 존 준비
- 명확한 보안 통제 가이드
- 사이버 보험 지원
- 보안 모범 사례 제공

## 2. 인프라 보안

Google Cloud의 인프라 보안은 다층적이고 철저한 접근 방식을 채택하고 있습니다.

### 주요 보안 특징
- 맞춤형 하드웨어 인프라 설계
- 경량화되고 강화된 Linux 운영체제
- Titan 보안 칩을 통한 하드웨어 신뢰 구축
- 엔드투엔드 공급망 보안

## 3. 네트워크 보안

### Google Cloud VPC 보안 기능
- 지역 간 비공개 연결
- VPC 흐름 로그
- 중앙 관리 방화벽 규칙
- 서비스 경계 보안

## 4. 애플리케이션 보안

### 주요 보호 메커니즘
- 사용자 인증 및 권한 기반 트래픽 제어
- 봇 및 사기성 사용자 차단
- 웹 애플리케이션 및 API 보호(WAAP)
  * 클라우드 로드 밸런싱
  * 클라우드 아머
  * reCAPTCHA 엔터프라이즈

## 5. 소프트웨어 공급망 보안

### 신뢰 체인 수립
- SLSA(Supply Chain Levels for Software Artifacts) 프레임워크
- 바이너리 인증
- 종속성 및 취약성 스캔
- 지속적인 정책 검증

## 6. 데이터 보안

### 암호화 및 데이터 보호
- 저장 중, 전송 중 데이터 암호화
- 기밀 컴퓨팅
- 고객 관리 암호화 키(BYOK)
- 데이터 손실 방지(DLP)

## 7. 아이덴티티 및 접근 관리

### 핵심 보안 메커니즘
- Cloud Identity를 통한 인증
- 다단계 인증
- 세분화된 IAM 역할
- BeyondCorp 제로 트러스트 모델

## 8. 엔드포인트 보안

### 사용자 및 디바이스 보호
- 안전 브라우징
- 웹 위험 API
- 디바이스 정책 관리

## 9. 보안 모니터링 및 운영

### SecOps 도구
- 보안 관제 센터
- 감사 로그
- 보안 오케스트레이션 및 대응(SOAR)

## 10. 거버넌스, 위험 및 규정 준수

### 주요 인증 및 표준
- PCI DSS
- FedRAMP
- HIPAA
- 지속적인 보안 검증