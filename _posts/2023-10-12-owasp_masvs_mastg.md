---
title: OWASP MASVS and MASTG
author: hyoeun
key: page-owasp_masvs_mastg
categories:
- Security
- Mobile Security
image: "/assets/thumbnails/2023-10-12-owasp_masvs_mastg.png"
date: 2023-10-12 00:00:00
bilingual: true
---

## Overview

The **OWASP Mobile Application Security Verification Standard (MASVS)** and the **OWASP Mobile Application Security Testing Guide (MASTG)** are the industry-standard frameworks for mobile application security. Understanding and applying these frameworks is essential for any mobile security engineer or penetration tester.

- **MASVS**: Defines the *what* — the security requirements an app should meet.
- **MASTG**: Defines the *how* — the methodology and tests to verify those requirements.

Both were significantly updated with **MASVS v2.0** (released March 2023) and a corresponding MASTG update.

## MASVS v2.0 Structure

MASVS v2.0 restructured the standard into **5 control groups**, moving away from the older L1/L2/R tiered model:

### MAS-C1: Storage
Requirements for securing data at rest, including files, databases, Keychain/Keystore, and backups.

- App must not store sensitive data in plaintext on the filesystem.
- Sensitive data must not be included in device backups.
- The app must not log sensitive data.
- Keychain (iOS) / Keystore (Android) must be used with appropriate protection levels.

### MAS-C2: Crypto
Requirements for cryptographic practices within the app.

- No use of deprecated/weak algorithms (MD5, SHA1, DES, RC4).
- Random number generation must use cryptographically secure PRNGs.
- Encryption keys must not be hardcoded.
- Keys must be properly managed (rotation, storage, destruction).

### MAS-C3: Auth
Requirements for authentication and session management.

- Authentication should happen server-side; local checks are supplementary only.
- Sessions must be invalidated server-side on logout.
- Biometric authentication must fall back to device credentials, not bypass auth.

### MAS-C4: Network
Requirements for securing data in transit.

- All network communication must use TLS 1.2 or higher.
- Certificate validation must not be disabled.
- Certificate pinning should be implemented for high-risk apps.
- No sensitive data in HTTP parameters or cookies without proper protection.

### MAS-C5: Platform
Requirements for secure interaction with the mobile OS.

- No sensitive data in system logs, pasteboard, or screenshots.
- Exported components (Activities, Intent Filters) must be properly protected.
- WebViews must not enable dangerous JavaScript interfaces.
- Deep links and URL schemes must validate input.

### MAS-C6: Code
Requirements for secure coding practices.

- No hardcoded credentials, API keys, or secrets.
- App must not be debuggable in production.
- Anti-tampering and anti-debugging measures (for high-risk apps).
- Obfuscation for sensitive business logic.

### MAS-C7: Resilience (formerly "R" controls)
Requirements for app self-protection and environmental checks. Applicable to high-risk applications (banking, healthcare, payment).

- Jailbreak/root detection
- Emulator detection
- Debugger detection
- Repackaging detection
- Runtime integrity verification

## MASTG Testing Approach

The MASTG provides specific tests for each MASVS control. Tests are categorized as:

- **MSTG-PLATFORM-1 through N**: Platform interaction tests
- **MSTG-STORAGE-1 through N**: Data storage tests
- etc.

### Testing Data Storage (MAS-C1 Examples)

**Android:**
```bash
# Check for sensitive data in SharedPreferences
adb shell cat /data/data/com.target.app/shared_prefs/UserPrefs.xml

# Check SQLite databases
adb shell sqlite3 /data/data/com.target.app/databases/app.db .dump

# Check log output
adb logcat | grep -i "password\|token\|secret"
```

**iOS:**
```bash
# Using Filza or SSH to browse app container
ls ~/Library/Application\ Support/
# Check NSUserDefaults
plutil -p ~/Library/Preferences/com.target.app.plist
# Check keychain (jailbroken device)
./keychain_dumper -a | grep -i "target.app"
```

### Testing Network Security (MAS-C4 Examples)

```bash
# Check TLS version using testssl.sh
testssl.sh https://api.target.com

# Intercept traffic with Burp Suite
# If pinning is implemented, bypass with Frida:
frida -U -n TargetApp -e "$(cat ios-ssl-pinning-bypass.js)"
```

### Testing Platform Interactions (MAS-C5 Examples)

**Android — Check exported components:**
```bash
# Use drozer
dz> run app.package.attacksurface com.target.app
dz> run app.activity.start --component com.target.app com.target.app.AdminActivity
```

**iOS — Check for sensitive data in pasteboard:**
```bash
# Using Objection
objection --gadget TargetApp explore
# ios pasteboard monitor
```

### Testing Resilience (MAS-C7 Examples)

```bash
# Bypass jailbreak detection with Frida script
frida -U -n TargetApp -s jailbreak-bypass.js

# Check if app is debuggable (Android)
adb shell run-as com.target.app ls /data/data/com.target.app/

# Check if app is debuggable (iOS manifest)
codesign -d --entitlements :- TargetApp.ipa | grep -i debug
```

## MASVS Verification Levels vs Risk Tiers

While MASVS v2.0 dropped explicit L1/L2/R labels, the community still uses risk-based classification:

| App Type | Applicable Controls |
|---|---|
| General apps (social, utilities) | MAS-C1 to C6 (baseline) |
| High-risk apps (fintech, healthcare) | All controls including MAS-C7 |
| Apps processing payment data | MAS-C7 + PCI DSS alignment |

## Resources

- **MASVS v2.0**: [mas.owasp.org/MASVS](https://mas.owasp.org/MASVS/)
- **MASTG**: [mas.owasp.org/MASTG](https://mas.owasp.org/MASTG/)
- **MAS Checklist**: [mas.owasp.org/checklists](https://mas.owasp.org/checklists/)
- **MASTG-Hacking-Playground**: Sample vulnerable apps for practice

---

## 개요

**OWASP MASVS(Mobile Application Security Verification Standard)**와 **OWASP MASTG(Mobile Application Security Testing Guide)**는 모바일 애플리케이션 보안을 위한 업계 표준 프레임워크입니다. 이 프레임워크들을 이해하고 적용하는 것은 모바일 보안 엔지니어나 침투 테스터에게 필수적입니다.

- **MASVS**: *무엇을* 정의 — 앱이 충족해야 하는 보안 요구 사항
- **MASTG**: *어떻게를* 정의 — 요구 사항을 검증하는 방법론과 테스트

두 프레임워크 모두 **MASVS v2.0**(2023년 3월 출시)으로 크게 업데이트되었습니다.

## MASVS v2.0 구조

MASVS v2.0은 이전의 L1/L2/R 계층 모델에서 벗어나 **5개 컨트롤 그룹**으로 재구성되었습니다:

### MAS-C1: 저장소
파일, 데이터베이스, Keychain/Keystore, 백업 등 저장된 데이터 보안을 위한 요구 사항입니다.

### MAS-C2: 암호화
앱 내 암호화 관행을 위한 요구 사항입니다.
- 취약한 알고리즘(MD5, SHA1, DES, RC4) 미사용
- 암호학적으로 안전한 PRNG 사용
- 키 하드코딩 금지

### MAS-C3: 인증
인증 및 세션 관리를 위한 요구 사항입니다.

### MAS-C4: 네트워크
전송 중 데이터 보안을 위한 요구 사항입니다.
- TLS 1.2 이상 사용
- 인증서 검증 비활성화 금지
- 고위험 앱에 대한 인증서 피닝 구현

### MAS-C5: 플랫폼
모바일 OS와의 안전한 상호작용을 위한 요구 사항입니다.

### MAS-C6: 코드
안전한 코딩 관행을 위한 요구 사항입니다.
- 자격 증명, API 키, 비밀 정보 하드코딩 금지
- 프로덕션에서 디버그 가능한 앱 금지

### MAS-C7: 복원력
앱 자체 보호 및 환경 점검을 위한 요구 사항입니다 (고위험 앱 적용).
- 탈옥/루팅 탐지
- 에뮬레이터 탐지
- 디버거 탐지
- 재패키징 탐지

## MASTG 테스팅 접근법

MASTG는 각 MASVS 컨트롤에 대한 구체적인 테스트를 제공합니다.

**데이터 저장소 테스팅 예시 (MAS-C1):**
```bash
# Android - SharedPreferences 확인
adb shell cat /data/data/com.target.app/shared_prefs/UserPrefs.xml
# 로그 출력 확인
adb logcat | grep -i "password\|token\|secret"
```

**네트워크 보안 테스팅 (MAS-C4):**
```bash
# Frida로 피닝 우회
frida -U -n TargetApp -e "$(cat ios-ssl-pinning-bypass.js)"
```

**플랫폼 상호작용 테스팅 (MAS-C5 - Android):**
```bash
# drozer로 내보낸 컴포넌트 확인
dz> run app.package.attacksurface com.target.app
dz> run app.activity.start --component com.target.app com.target.app.AdminActivity
```

**복원력 테스팅 (MAS-C7):**
```bash
# Frida 스크립트로 탈옥 탐지 우회
frida -U -n TargetApp -s jailbreak-bypass.js
```

## 참고 자료

- **MASVS v2.0**: [mas.owasp.org/MASVS](https://mas.owasp.org/MASVS/)
- **MASTG**: [mas.owasp.org/MASTG](https://mas.owasp.org/MASTG/)
- **MAS 체크리스트**: [mas.owasp.org/checklists](https://mas.owasp.org/checklists/)
