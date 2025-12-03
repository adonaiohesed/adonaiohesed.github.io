---
title: Payments Industry and Regulatory Concepts
tags: Intermediate-Payments-Cybersecurity
key: page-payments_industry_and_regulatory_concepts
categories: [Cybersecurity, Payment Card Industry Data Security Standard]
author: hyoeun
math: true
mathjax_autoNumber: true
---

# Key Drivers of Industry and Regulatory Compliance: Core Standards and Concepts

Industry and regulatory compliance is complex and requires adherence to various standards and regulations to ensure security, privacy, and operational efficiency. In this post, we’ll explore key regulatory frameworks, privacy concerns, and industry-specific standards.

## **Drivers of Industry and Regulatory Compliance**

Major organizations and standards defining regulations across industries include:

- **PCI DSS**  
- **RBI (Reserve Bank of India)**  
- **Bank of England**  
- **FFIEC (Federal Financial Institutions Examination Council)**  
- **The center bank of European Union**

### **Regulatory Compliance Frameworks**
- **GLBA** (Gramm-Leach-Bliley Act)  
- **GDPR** (General Data Protection Regulation)  
- **CCPA** (California Consumer Privacy Act)  

These frameworks define how personal data must be protected. While penalties may apply for non-compliance in some regions, enforcement is not uniform across all jurisdictions.

## **Privacy vs Personal Information (PI)**

### **Privacy**
Refers to safeguarding personal data and ensuring individuals have the right to decide whether to share their information.

### **Personal Information (PI)**
Refers to data that can identify an individual, such as:
- Name
- Social Security Number
- Date of Birth

## **Sensitive Personal Information (SPI)**

Sensitive personal information requires additional protection. Examples include:
- Government-issued ID numbers  
- Account credentials (username and password)  
- Financial information  
- Health or health insurance data  
- Consumer reporting data, such as credit history or employment background checks  
- Criminal history  
- Special categories of data revealing race, ethnicity, political opinions, biometric data, etc.

## **Know Your Customer (KYC), Anti-Money Laundering (AML), FATCA, and OFAC**

- **KYC Standards**: Verifies customer identity to prevent fraud and corruption.  
- **AML**: Prevents illicit financial activities.  
- **FATCA**: Requires U.S. citizens to report foreign assets.  
- **OFAC**: A U.S. Treasury agency responsible for enforcing trade and economic sanctions.

## **Data Localization**

Some countries require that data concerning their citizens be processed and stored within national borders. This is to maintain stricter control over sensitive information.

## **EMV Standards**

**EMV** stands for Europay, Mastercard, and Visa. Developed in the mid-1990s as a payment standard, it is now managed by JCB, American Express, China UnionPay, and Discover, among others.

## **PCI DSS (Data Security Standards)**

PCI DSS provides cybersecurity controls to protect cardholder data. Organizations processing, storing, or transmitting such data must comply with these standards.

### **Key Features**
- **Cardholder Data Environment (CDE)**: Protects CHD (Cardholder Data) and SAD (Sensitive Authentication Data).  
- **6 Goals and 12 Requirements**: A comprehensive framework to ensure security.

### **Compliance Levels**
1. **Level 1**: 6M+ Transactions / Year – Annual onsite assessment and ROC(Report on Compliance) required.  
2. **Level 2**: 1-6M Transcations / Year – Annual SAQ(Self-assessment questionnaire) and quarterly network scans required.  
3. **Level 3**: 20k-1M Transactions – AOC(Attestation of Completion) and quarterly network scans required.  
4. **Level 4**: <20k Transactions / Year – May needs SAQ, AOC, and network scans.  

## **PCI Software Security Framework**

This framework ensures the secure development of payment applications and includes two key standards:
- **PCI Secure Software Standard**  
- **Secure Software Lifecycle Standard (SSLC)**

### **Key Benefits**
- Covers the entire Software Development Lifecycle (SDLC)  
- Ensures secure design, development, testing, and deployment  
- Reduces vulnerabilities in software systems  

## **15 PCI Security Standards**
### Between Issuer(Cardholder's Bank) and Consumer
- PIN Security
- Card Production - Physical
- Card Production - Logcial
- Token Service Provider (TSP)

### Between Merchant & Service Provider
- PIN Transaction Security Point of Interaction (PTS POI)
- PTS Hardware Security Module(HSM)
- Point-to-Point Encryption (P2PE)
- PCI3-D Security Software Development Kit(3DS SDK)
- Software-based PIN Entry on COTS (SPoC)

### Between Vendor and Solution Provider
- Secure Software Framework consisting of 2 standards
- Secure Software Standard
- Secure Lifecycle Standard
- Contactless Payment on COTS(CPoS)
- Mobile Payments on COTS(MPoC)

Understanding these frameworks and standards is essential for organizations to remain compliant, protect sensitive data, and build trust among stakeholders.

---

## **Industry and regulatory compliance drivers and supervision**

여러 산업에서 규제를 정의하는 주요 조직과 기준은 다음과 같습니다.

- **PCI DSS**  
- **RBI (인도중앙은행)**  
- **Bank of England (영국은행)**  
- **FFIEC (연방 금융기관 검사위원회)**  
- **The center bank of European Union (유럽중앙은행)**

### **규제 준수 프레임워크**
- **GLBA** (Gramm-Leach-Bliley Act)  
- **GDPR** (일반 데이터 보호 규정)  
- **CCPA** (캘리포니아 소비자 프라이버시 법)  

이 규제들은 개인 데이터 보호 방법을 정의합니다. 일부 지역에서는 준수하지 않을 경우 벌금이 부과될 수 있지만, 모든 지역에서 일관되게 시행되지는 않습니다.

## **프라이버시 vs. 개인 정보**

### **프라이버시 (Privacy)**
개인의 데이터를 보호하며, 개인이 자신의 데이터를 공유할지 여부를 스스로 결정할 수 있도록 보장합니다.

### **개인 정보 (Personal Information, PI)**
데이터를 통해 개인을 식별할 수 있는 정보로, 다음이 포함됩니다.
- 이름
- 주민등록번호
- 생년월일

## **민감한 개인 정보 (Sensitive Personal Information, SPI)**

민감한 개인 정보는 추가적인 보호가 필요합니다. 예시는 다음과 같습니다.
- 정부 발급 신분증 번호
- 계정 자격 증명 (아이디 및 비밀번호)
- 금융 정보
- 건강 또는 보험 정보
- 신용 기록 및 배경 조사 데이터
- 범죄 기록
- 인종, 민족, 정치적 견해, 생체 정보 등을 포함한 특수 데이터

## **Know Your Customer(KYC), Anti-money Laundering(AML), FATCA, OFAC**

- **KYC 표준**: 고객의 신원을 확인하여 사기 및 부패를 방지합니다.  
- **Anti-money Laundering(AML)**: 불법 금융 활동을 방지하기 위한 규정입니다.  
- **FATCA**: 미국 시민이 해외 자산을 신고하도록 요구하는 법입니다.
- **OFAC**: 미국 재무부 소속으로, 무역 및 경제 제재를 집행합니다.

## **Data Localization**

일부 국가에서는 자국민의 데이터가 해당 국가 내에서 처리 및 저장되도록 요구합니다. 이는 민감한 정보에 대한 통제를 강화하기 위함입니다.

## **EMV 표준**

**EMV**는 Europay, Mastercard, Visa의 약자로, 1990년대 중반에 결제 표준으로 개발되었습니다. 현재는 JCB, American Express, China UnionPay, Discover 등도 이를 관리하고 있습니다.

## **PCI DSS (데이터 보안 표준)**

PCI DSS는 카드 소유자 데이터 보호를 위해 사이버 보안 통제를 제공합니다. 데이터를 처리, 저장 또는 전송하는 조직은 반드시 준수해야 합니다.

### **주요 특징**
- **카드 소유자 데이터 환경(CDE)**: CHD(카드 소유자 데이터)와 SAD(민감 인증 데이터)를 보호합니다.
- **6개 목표 및 12개 요구사항**: 보안을 보장하기 위한 포괄적 프레임워크입니다.

### **준수 수준**
1. **레벨 1**: 6M+ Transactions / Year – 연간 현장 평가(Annual Onsite Assessment) 및 ROC(Report on Compliance) 필요  
2. **레벨 2**: 1-6M Transcations / Year – 연간 SAQ(Self-assessment questionnaire) 및 분기별 네트워크 스캔 필요  
3. **레벨 3**: 20k-1M Transactions – AOC(Attestation of Completion) 및 분기별 네트워크 스캔 필요  
4. **레벨 4**: <20k Transactions / Year – SAQ, AOC, 네트워크 스캔 필요할 수 있음  

## **PCI 소프트웨어 보안 프레임워크**

안전한 결제 애플리케이션 개발을 보장하며 다음 두 가지 표준으로 구성됩니다.
- **PCI Secure Software Standard**  
- **Secure Software Lifecycle Standard (SSLC)**

### **주요 이점**
- 소프트웨어 개발 수명주기(SDLC) 전체를 포함  
- 안전한 설계, 개발, 테스트 및 배포 보장  
- 소프트웨어 취약점 감소  

## **PCI의 15개 보안 표준**
### Between Issuer(Cardholder's Bank) and Consumer
- PIN Security
- Card Production - Physical
- Card Production - Logcial
- Token Service Provider (TSP)

### Between Merchant & Service Provider
- PIN Transaction Security Point of Interaction (PTS POI)
- PTS Hardware Security Module(HSM)
- Point-to-Point Encryption (P2PE)
- PCI3-D Security Software Development Kit(3DS SDK)
- Software-based PIN Entry on COTS (SPoC)

### Between Vendor and Solution Provider
- Secure Software Framework consisting of 2 standards
- Secure Software Standard
- Secure Lifecycle Standard
- Contactless Payment on COTS(CPoS)
- Mobile Payments on COTS(MPoC)

이러한 프레임워크와 기준을 이해하는 것은 조직이 준수 상태를 유지하고, 민감한 데이터를 보호하며, 이해 관계자 간 신뢰를 구축하는 데 필수적입니다.