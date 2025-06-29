---
title: What Cybersecurity Certifications Should I Get Next?
tags: Cybersecurity-Certificates
key: page-certificates_cybersecurity
categories: [Carrer, Certificates]
author: hyoeun
math: true
mathjax_autoNumber: true
---

# 어떤 보안 자격증을 준비하면 좋을까? (펜테스트 & 클라우드 시큐리티 진로 고민)

보안 업계에서 일하며 CEH와 CISSP를 이미 취득한 지금, 앞으로 어떤 자격증을 준비하면 좋을까 고민해봤다.  
나는 **침투 테스트(펜테스트)**와 **클라우드 보안**에 관심이 많고, 실전 중심의 실력을 쌓고 싶다.  
이 글은 나를 위한 로드맵이자, 나중에 비슷한 길을 가려는 사람들에게도 도움이 될 수 있을 것 같아서 정리해봤다.

## 📍 목표: 펜테스트 & 클라우드 시큐리티 전문가

---

## 🛠️ 펜테스트 계열 자격증

### 🔐 OSCP (Offensive Security Certified Professional)
- **목적**: 실무형 외부 침투 테스트 능력 입증
- **특징**: 24시간 실전 시험 + 침투 테스트 보고서 작성
- **왜 필요한가?**
  - CEH가 이론 중심이라면, OSCP는 실전 중심이다.
  - 실제 고객 환경에서 침투 테스트를 수행할 준비가 되었다는 것을 보여줄 수 있다.
- **준비 방법**
  - PWK(PEN-200) 강의 수강 (Offensive Security)
  - HackTheBox, TryHackMe, TJNull OSCP Prep 목록 등으로 실력 쌓기
  - 보고서 작성 연습은 필수!

---

### 🧠 OSWE (Offensive Security Web Expert)
- **목적**: 고급 웹 애플리케이션 해킹 + 코드 감사 능력
- **특징**: 화이트박스 테스트, 웹 기반 익스플로잇, 코드 리딩
- **왜 필요한가?**
  - 펜테스터로서 웹 앱의 보안 취약점을 심도 깊게 분석하는 능력을 보여줄 수 있다.
  - Bug Bounty에도 도움이 된다.
- **준비 방법**
  - WEB-300 과정 수강
  - 소스코드 분석 능력 필요 (PHP, JS, Python 등)
  - 포커스: Auth bypass, SQLi, RCE 등 고급 웹 취약점

---

### 🕵️‍♂️ CRTO (Certified Red Team Operator)
- **목적**: 실전 Red Team 활동 능력 인증
- **특징**: Cobalt Strike, Active Directory, AV/EDR 우회 등
- **왜 필요한가?**
  - OSCP 이후의 실전형 Red Team 자격증.
  - 실제 공격 시나리오를 연습하고 싶은 사람에게 적합.
- **준비 방법**
  - ZeroPoint Security의 CRTO 과정 수강
  - AD 환경 실습 랩 구성 필요 (e.g., LabBuildr, DetectionLab)
  - PowerShell, Cobalt Strike에 익숙해질 것

---

### 🧪 CRTL (Certified Red Team Lead)
- **목적**: Red Team 리더십 및 전략 수립 능력 인증
- **특징**: 공격 계획 수립, 목표 기반 침투, 협업/보고 능력 강조
- **왜 필요한가?**
  - 기술적인 역량뿐 아니라 리더십, 전략 수립 능력도 평가됨
  - Red Team을 이끄는 입장에서 필요한 고급 자격증
- **준비 방법**
  - ZeroPoint Security 제공 과정
  - CRTO 경험 이후 준비 권장
  - 실전 보고서 작성 및 팀 협업 사례 공부 필요

---

### 🔍 BSCP (Blue Team Security Certification)
- **목적**: 방어 측면에서의 사이버 위협 탐지 및 대응 능력 인증
- **특징**: 로그 분석, 위협 헌팅, SIEM 운영 능력 포함
- **왜 필요한가?**
  - Red Team을 잘 하려면 Blue Team 입장에서의 이해도 중요함
  - 실무에서 공격 탐지 우회 테스트 수행 시 유용함
- **준비 방법**
  - 보통 로그 분석, EDR/SIEM 툴 경험 필요
  - 커뮤니티 자료나 실습 기반 교육 과정 활용

---

## ☁️ 클라우드 시큐리티 자격증

### ☁️ AWS Certified Security – Specialty
- **목적**: AWS 환경에서의 보안 설계, 운영 능력 검증
- **특징**: IAM, KMS, VPC 보안, CloudTrail/Config 활용 등
- **왜 필요한가?**
  - 클라우드 인프라에 대한 보안 지식을 체계화할 수 있다.
  - 실무에서도 매우 많이 요구됨.
- **준비 방법**
  - AWS 공식 학습 경로 + Whizlabs / TutorialsDojo 모의고사
  - 실제 AWS 환경에서 실습하며 이해할 것

---

### 🛡️ Google Professional Cloud Security Engineer
- **목적**: GCP 환경의 보안 설계, 구현, 대응 능력 검증
- **특징**: GCP IAM, VPC, DLP, SIEM 통합, 사고 대응 시나리오
- **왜 필요한가?**
  - GCP 사용 기업 증가 → 수요 꾸준히 상승 중
  - 멀티클라우드 보안 전문가로 확장할 수 있는 기반
- **준비 방법**
  - Google Cloud Skill Boosts 경로 학습
  - 실전 GCP 프로젝트 실습 필수
  - 모의고사: Udemy, Linux Academy

---

### 🏢 CCSP (Certified Cloud Security Professional)
- **목적**: 클라우드 보안 거버넌스와 정책, 아키텍처 전반 커버
- **특징**: ISC² 제공, 이론 중심 + 정책/법률/규정 커버
- **왜 필요한가?**
  - 클라우드 보안 정책과 컴플라이언스를 다룰 때 필수
  - CISSP의 클라우드 확장형 자격증
- **준비 방법**
  - (ISC)² 공식 교재 + 커뮤니티 요약자료
  - 실무 경험과 함께 이론 정리가 중요함

---

## 📌 정리: 나의 진로에 맞는 우선순위

1. **OSCP** → 실전 침투 테스트 능력 확보
2. **AWS Certified Security** → 클라우드 보안 기초 다지기
3. **CRTO** → 실전 레드팀 기술 쌓기
4. **BSCP** → Blue Team 관점 이해 및 위협 대응
5. **OSWE** → 고급 웹 해킹 역량 강화
6. **Google Cloud Security Engineer** → 멀티 클라우드 대응력
7. **CRTL** → 레드팀 리더 역할 준비
8. **CCSP** → 정책/거버넌스 기반 확장