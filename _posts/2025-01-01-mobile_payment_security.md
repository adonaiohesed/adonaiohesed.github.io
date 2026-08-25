---
title: Mobile Payment Security - Apple Pay, Google Pay, Samsung Pay, Alipay
author: hyoeun
key: page-mobile_payment_security
categories:
- Security
- Mobile Security
image: "/assets/thumbnails/2025-01-01-mobile_payment_security.png"
date: 2025-01-01 00:00:00
bilingual: true
---

## Overview

Mobile payment systems have become ubiquitous, processing billions of transactions annually. Understanding the security architecture of these systems is essential for mobile security practitioners—both for assessing app security and for understanding the threat landscape.

This post covers **Apple Pay, Google Pay, Samsung Pay**, and **Alipay** from a security and penetration testing perspective.

## Common Architecture: Tokenization

All major mobile payment systems share a core security mechanism: **payment tokenization**. Instead of transmitting the real card number (Primary Account Number / PAN), a **token** (Device Primary Account Number / DPAN) is generated and used for each transaction.

```
Real Card (PAN: 4111-1111-1111-1111)
         ↓
Tokenization Service (TSP: Visa, Mastercard, Amex)
         ↓
Device Token (DPAN: 4895-xxxx-xxxx-xxxx)
         ↓
Used for NFC/in-app payment
```

**The TSP maps tokens to real PANs server-side, so merchants and attackers never see the real card number.**

## Apple Pay

### Architecture
Apple Pay uses two key components:
1. **Secure Element (SE)**: A dedicated chip (or eSE/embedded Secure Element) that stores cryptographic keys and card tokens. Isolated from the main processor.
2. **Apple Pay Servers (TSP bridge)**: Coordinates provisioning with card networks.

### Payment Flow (NFC/In-Store)
1. User authenticates via Face ID / Touch ID.
2. Secure Element generates a **one-time cryptogram** using the stored DPAN.
3. NFC transmits the DPAN + cryptogram to the merchant terminal.
4. Merchant sends to bank → bank validates with Visa/Mastercard TSP → approves.

### Security Features
- **Biometric authentication** required before each payment.
- **No PAN** stored on device or transmitted.
- **Device-specific tokens** — token cannot be used on another device.
- **Jailbreak risk**: On jailbroken devices, SE is still isolated, but Secure Enclave bypasses can expose biometric checks.

### Penetration Testing Considerations
- Verify the app uses **Apple Pay APIs correctly** (PassKit framework).
- Test that the **Merchant Validation** step is properly implemented in in-app purchases (to prevent unauthorized server-to-merchant communication).
- Check that **payment session tokens** are short-lived and not reusable.
- On jailbroken devices, verify that the app detects jailbreak and disables payment.

## Google Pay

### Architecture
Google Pay uses **Host Card Emulation (HCE)** on Android — software-based card emulation that doesn't require a dedicated Secure Element.

### Payment Flow
1. User authenticates via PIN, fingerprint, or face recognition.
2. Google Pay app generates a **Limited Use Key (LUK)** token via Google's TSP.
3. NFC transmits the HCE-generated transaction.
4. Merchant processes via standard payment network.

### Security Features
- **Tokenization** via Google's Token Service Provider.
- **Limited Use Keys**: Each payment token is limited to a specific number of uses.
- **Transaction Cryptogram**: Each NFC transaction includes a unique cryptogram.
- **Knox integration** on Samsung devices for additional hardware isolation.

### HCE vs SE Comparison

| Feature | HCE (Google Pay) | SE (Apple Pay) |
|---|---|---|
| Storage | Cloud / Software | Dedicated chip |
| Key exposure risk | Higher | Lower |
| OTA provisioning | Easier | Requires manufacturer |

### Penetration Testing Considerations
- Test for **payment without authentication** — some implementations bypass auth checks.
- Verify that HCE tokens are **not cacheable or replayable**.
- Test the app's behavior when **Google Play Services are tampered with**.
- Verify certificate pinning on all payment API calls.

## Samsung Pay

### Architecture
Samsung Pay supports **both MST (Magnetic Secure Transmission) and NFC**, making it compatible with virtually all payment terminals.

- **MST**: Emulates the magnetic stripe swipe — works with traditional card readers.
- **NFC**: Standard contactless payment.

Samsung Pay uses Samsung's **Knox** security platform and the **TIMA (TrustZone-based Integrity Measurement Architecture)** for hardware-backed security.

### Security Features
- **ARM TrustZone** for secure storage and cryptographic operations.
- **Knox attestation**: Device integrity verification.
- **Per-transaction tokens** for both MST and NFC.
- **Biometric requirement** (iris, fingerprint) for activation.

### Penetration Testing Considerations
- Test for **Knox attestation bypass** — if Knox detects a rooted device, payments should be disabled.
- Check for **MST relay attacks** — MST signals can theoretically be captured and replayed within the signal's range.
- Verify that **transaction tokens expire** after a short time.

## Alipay / WeChat Pay

### Architecture
Alipay (Ant Group) and WeChat Pay (Tencent) are the dominant mobile payment systems in China and increasingly global.

- Primarily **QR code-based** (static or dynamic) rather than NFC.
- Transactions processed server-side by Alipay/Tencent infrastructure.
- User's wallet is linked directly to bank accounts or credit cards.

### Security Features
- **Dynamic QR codes**: Time-limited (30–60 seconds) to prevent replay.
- **Multi-factor verification** for large transactions.
- **Real-name verification (KYC)**: Required for full functionality.
- **Risk scoring engine**: Real-time fraud detection.

### Security Concerns
- **Static QR code fraud**: Replacing merchant's QR code with attacker's code.
- **QR code phishing**: Malicious QR codes redirecting to fake payment pages.
- **Account takeover**: SIM swap attacks targeting linked phone numbers.

## Common Attack Vectors Across Platforms

### 1. Man-in-the-Middle on Payment APIs
If certificate pinning is absent or bypassed:
```bash
# Bypass pinning with Frida
frida -U -n "Wallet" -e "
var TrustManager = Java.use('javax.net.ssl.X509TrustManager');
..."
```

### 2. Token Leakage via Logs
Payment tokens appearing in device logs or crash reports:
```bash
# Android
adb logcat | grep -i "token\|dpan\|payment\|cryptogram"
```

### 3. Replay Attack on Payment Sessions
If a payment session token is reusable:
```bash
# Capture and replay with Burp Suite
# POST /payment/initiate with captured session
```

### 4. Testing In-App Payment Flows
```bash
# Use mitmproxy to intercept payment API calls
mitmproxy --ssl-insecure --listen-port 8080
# Configure device proxy → intercept payment initiation
```

## Security Recommendations

| Platform | Key Check |
|---|---|
| Apple Pay | Merchant validation, jailbreak detection |
| Google Pay | HCE token lifetime, auth bypass |
| Samsung Pay | Knox attestation, MST relay |
| Alipay | QR code expiry, KYC enforcement |

---

## 개요

모바일 결제 시스템은 연간 수십억 건의 거래를 처리하며 어디서나 볼 수 있게 되었습니다. 이러한 시스템의 보안 아키텍처를 이해하는 것은 모바일 보안 실무자에게 필수적입니다. 이 포스트는 보안 및 침투 테스트 관점에서 **Apple Pay, Google Pay, Samsung Pay, Alipay**를 다룹니다.

## 공통 아키텍처: 토큰화

모든 주요 모바일 결제 시스템은 핵심 보안 메커니즘을 공유합니다: **결제 토큰화**. 실제 카드 번호(PAN) 대신 **DPAN(Device Primary Account Number)**이라는 토큰을 생성하여 각 거래에 사용합니다. **TSP가 서버 측에서 토큰을 실제 PAN에 매핑하므로 가맹점과 공격자는 실제 카드 번호를 볼 수 없습니다.**

## Apple Pay

### 아키텍처
1. **보안 요소(SE)**: 암호화 키와 카드 토큰을 저장하는 전용 칩. 메인 프로세서와 격리.
2. **Apple Pay 서버**: 카드 네트워크와의 프로비저닝 조율.

### 결제 흐름(NFC/오프라인 매장)
1. Face ID / Touch ID로 사용자 인증
2. 보안 요소가 저장된 DPAN으로 **일회용 암호문** 생성
3. NFC로 DPAN + 암호문을 가맹점 단말기에 전송
4. 가맹점이 은행 → Visa/Mastercard TSP로 전송하여 승인

### 보안 기능
- 각 결제 전 **생체 인증** 필요
- 기기에 **PAN 저장 없음** 및 전송 없음
- **기기별 토큰** — 다른 기기에서 토큰 사용 불가

## Google Pay

### 아키텍처
Google Pay는 Android에서 **HCE(Host Card Emulation)**를 사용합니다 — 전용 보안 요소가 필요 없는 소프트웨어 기반 카드 에뮬레이션입니다.

### 보안 기능
- Google의 TSP를 통한 **토큰화**
- **제한된 사용 키(LUK)**: 각 결제 토큰은 특정 횟수의 사용으로 제한
- 각 NFC 거래에 고유한 **거래 암호문** 포함

## Samsung Pay

### 아키텍처
Samsung Pay는 **MST(자기 보안 전송)와 NFC 모두** 지원하여 사실상 모든 결제 단말기와 호환됩니다.

- **MST**: 자기 띠 긁기를 에뮬레이션 — 기존 카드 리더기와 호환
- **Knox**: 하드웨어 기반 보안을 위한 Samsung의 보안 플랫폼

## Alipay / WeChat Pay

### 아키텍처
주로 **QR 코드 기반**(정적 또는 동적)이며 NFC 기반이 아닙니다.

### 보안 우려 사항
- **정적 QR 코드 사기**: 가맹점의 QR 코드를 공격자의 코드로 교체
- **QR 코드 피싱**: 가짜 결제 페이지로 유도하는 악성 QR 코드
- **계정 탈취**: 연결된 전화번호를 대상으로 한 SIM 스와핑

## 플랫폼 전반에 걸친 공통 공격 벡터

1. **결제 API에 대한 중간자 공격**: 인증서 피닝이 없거나 우회된 경우
2. **로그를 통한 토큰 노출**: 기기 로그나 충돌 보고서에 결제 토큰 표시
3. **결제 세션에 대한 리플레이 공격**: 결제 세션 토큰이 재사용 가능한 경우
4. **인앱 결제 흐름 테스트**: 프록시를 통한 결제 API 호출 인터셉트
