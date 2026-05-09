---
title: Mobile Code Signing
key: page-mobile_code_signing
categories:
- Security
- Mobile Security
author: hyoeun
math: true
mathjax_autoNumber: true
bilingual: true
image: "/assets/thumbnails/2022-12-02-mobile_code_signing.png"
date: 2022-12-02 10:00:00
---
## Mobile Code Signing: Why Your App's Signature Is a Security Boundary

If you've done any mobile pentesting, you've definitely hit the wall where your repackaged IPA gets rejected, or your patched APK refuses to install. That wall is **code signing**. Understanding it deeply isn't just useful for getting around it — it's essential because signing misconfigurations are a legitimate vulnerability class you'll find on real engagements.

This post breaks down how code signing works on both platforms, why it exists from a security standpoint, and where it actually fails.

## iOS Code Signing

### The Chain of Trust

Apple's security model is a **layered chain of trust** — each link depends on the one above it. If any link is broken or tampered with, the OS rejects the app.

```
┌─────────────────────────────────┐
│        Apple Root CA            │  ← Hardcoded in every Apple device
│   (Built into Secure Enclave)   │
└────────────────┬────────────────┘
                 │ signs
                 ▼
┌─────────────────────────────────┐
│    Apple Intermediate CA        │  ← Apple's internal infrastructure
└────────────────┬────────────────┘
                 │ signs
                 ▼
┌─────────────────────────────────┐
│     Developer Certificate       │  ← Your public key, signed by Apple
│  (stored in macOS Keychain)     │    Generated via: CSR → Apple Dev Portal
└────────────────┬────────────────┘
                 │ embedded in
                 ▼
┌─────────────────────────────────┐
│     Provisioning Profile        │  ← Apple-signed XML bundle containing:
│   (embedded.mobileprovision)    │    • App ID (bundle ID)
│                                 │    • Developer Certificate
│                                 │    • Allowed Device UDIDs
│                                 │    • Entitlements
└────────────────┬────────────────┘
                 │ embedded in + app binary signed with
                 ▼
┌─────────────────────────────────┐
│          IPA Package            │  ← Your private key signs the binary
│   (Payload/AppName.app)         │    Xcode does this automatically
└─────────────────────────────────┘
                 │
                 ▼ (at install time)
┌─────────────────────────────────┐
│      iOS Kernel Verification    │  ← OS validates:
│                                 │    1. Apple's sig on provisioning profile ✓
│                                 │    2. Dev cert matches profile ✓
│                                 │    3. Binary sig matches dev cert ✓
│                                 │    4. Device UDID is in profile (dev/adhoc) ✓
│                                 │    5. Entitlements match profile ✓
└─────────────────────────────────┘
```

**Distribution Types and What They Mean:**

| Type | Who Can Install | Device Restriction | Use Case |
|---|---|---|---|
| Development | Listed UDIDs only | Up to 100 devices | Dev/QA builds |
| Ad Hoc | Listed UDIDs only | Up to 100 devices | External testers |
| App Store | Anyone | None | Public release |
| Enterprise (In-House) | Anyone in org | None (`ProvisionsAllDevices`) | MDM-deployed corporate apps |
| TestFlight | Invited testers | Apple account | Beta testing |

### Entitlements: The Real Attack Surface

Entitlements are XML key-value pairs that declare what privileged capabilities an app is allowed to use:

```xml
<key>com.apple.developer.associated-domains</key>
<array>
    <string>applinks:bank.example.com</string>
</array>
<key>keychain-access-groups</key>
<array>
    <string>TEAMID.com.example.app</string>
</array>
```

**What to look for:**
*   `get-task-allow: true` → The app allows a debugger to attach. Should **never** appear in production. If you find this, you can attach lldb without a jailbreak on that build.
*   `com.apple.security.network.client` on macOS apps, or overly broad `associated-domains` that include staging environments.
*   `keychain-access-groups` that share a group ID with other apps (legitimate cross-app data sharing, but also a lateral movement path).

**How to extract entitlements from an IPA:**
```bash
# Unzip the IPA and look at the binary
unzip appname.ipa -d app_contents
cd app_contents/Payload/AppName.app/
codesign -d --entitlements :- AppName
```

### Provisioning Profiles in the Wild

During a pentest, you can pull the embedded provisioning profile from any IPA:
```bash
security cms -D -i embedded.mobileprovision
```
This shows the plain-text XML. Things to check:
*   `ProvisionsAllDevices: true` → Enterprise/In-house distribution. Means this app was signed to run on any device without the App Store. Classic for MDM-delivered corporate apps and also a common vector for malicious apps.
*   Expiry date of the profile — expired profiles that still somehow run indicate device-level clock manipulation or a bypass.

## Installing an IPA for Pentesting

As a pentester, you'll often receive an IPA directly from the client. Here's how to install it depending on your device situation.

### Option A: Non-Jailbroken Device

On a stock (non-jailbroken) device, you need a valid code signature. You have two main paths:

**1. Re-sign with your own developer certificate (requires Apple Developer account)**
```bash
# Install required tools
brew install ios-deploy
pip3 install frida-tools

# Re-sign using iOS App Installer scripts or manually:
# Step 1 — Unzip and replace provisioning profile
unzip target.ipa -d Payload
# Copy your own embedded.mobileprovision into Payload/Payload/AppName.app/
cp ~/path/to/your.mobileprovision Payload/Payload/AppName.app/embedded.mobileprovision

# Step 2 — Re-sign binary with your cert
codesign -f -s "iPhone Developer: Your Name (TEAMID)" \
  --entitlements entitlements.plist \
  Payload/Payload/AppName.app/AppName

# Step 3 — Repackage and install
cd Payload && zip -qr ../resigned.ipa Payload
ios-deploy --bundle Payload/AppName.app
```

**2. Use a GUI tool (easier for one-off installs)**

| Tool | Platform | Notes |
|---|---|---|
| [AltStore](https://altstore.io) | Mac/Win | Free, uses your Apple ID, 3-app limit |
| [Sideloadly](https://sideloadly.io) | Mac/Win | Free, supports more entitlements |
| [Apple Configurator 2](https://apps.apple.com/app/apple-configurator-2/id1037126344) | Mac only | Enterprise/MDM workflows |

```bash
# Using Sideloadly (CLI mode)
sideloadly --ipa target.ipa --udid <device-udid> --apple-id you@example.com
```

### Option B: Jailbroken Device

On a jailbroken device, signature verification is patched out by the jailbreak itself (e.g., via `appsync unified`). You can install any IPA regardless of signing.

**Install AppSync Unified first** (via Cydia/Sileo — bypasses signature check):
```
Repo: https://cydia.akemi.ai/
Package: AppSync Unified
```

**Then install the IPA directly:**
```bash
# Method 1: ideviceinstaller (libimobiledevice)
brew install libimobiledevice ideviceinstaller
ideviceinstaller -i target.ipa

# Method 2: ios-deploy
brew install ios-deploy
ios-deploy --bundle Payload/AppName.app

# Method 3: Over SSH with dpkg (if app is packaged as .deb)
scp target.deb root@<device-ip>:/tmp/
ssh root@<device-ip> "dpkg -i /tmp/target.deb && uicache"
```

**Check if AppSync is working:**
```bash
ssh root@<device-ip> "dpkg -l | grep appsync"
# Should show: ii  ai.akemi.appsyncunified
```

**Frida setup after install (jailbroken):**
```bash
# Install frida-server on device via Cydia/Sileo, then verify
frida-ps -U   # lists running processes on USB-connected device
frida -U -n AppName --codeshare nowsecure/frida-ios-hooks
```

### Which Method Should You Use?

| Situation | Recommended Method |
|---|---|
| Client gave IPA, you have dev account | Re-sign + `ios-deploy` |
| Need SSL pinning bypass | Jailbroken + Frida |
| Black-box test, no source | AppSync + ideviceinstaller |
| Enterprise IPA (`ProvisionsAllDevices`) | Install directly without re-signing |
| Need to test without jailbreak | Sideloadly with your Apple ID |



## Android APK Signing

### The Signing Schemes (V1, V2, V3, V4)

Android has evolved its signing significantly. Understanding the version matters because they have different security properties and different bypass implications.

| Scheme | Introduced | What It Signs | Key Limitation |
|---|---|---|---|
| V1 (JAR Signing) | Original | Individual files in the ZIP | Files can be added to the APK without breaking the signature |
| V2 (APK Signature) | Android 7.0 | Entire APK blob | Stronger — any change to the APK invalidates the signature |
| V3 (Rotation) | Android 9.0 | APK + signing key rotation support | Adds proof of key ownership chain |
| V4 (Streaming) | Android 11 | Works with ADB incremental install | Requires V2 or V3 |

**Why V1 matters for pentesters:** The V1 weakness (ZIP comment injection, file addition) is theoretically interesting but practically it won't get you a working malicious install on modern Android since V2+ is required. However, some very old targets (pre-7.0) or devices with custom ROMs only support V1, making injection viable.

**For repackaging analysis:**
```bash
# Check which signature schemes an APK uses
apksigner verify --verbose target.apk

# Sign a repackaged APK (required after modifying)
keytool -genkey -v -keystore my.keystore -alias mykey -keyalg RSA -keysize 2048 -validity 10000
apksigner sign --ks my.keystore --out signed.apk unsigned.apk
```

### Keystore Misconfigurations

A common finding in Android apps is hardcoded or improperly managed keystores. If developers accidentally include the signing keystore in the repository or ship it with the app:

```bash
# Search APK for keystore artifacts
unzip target.apk -d apk_contents
find apk_contents/ -name "*.jks" -o -name "*.keystore" -o -name "*.bks"

# Also check for hardcoded passwords
grep -r "keystorePassword\|storePassword\|keyPassword" apk_contents/
```

Finding a keystore + password means an attacker can produce validly signed repackaged APKs that devices will install without warning — because the signature matches the original app.

## Signing and Integrity from a Pentesting Lens

| Scenario | What You Should Test |
|---|---|
| Repackaged APK installs cleanly | App lacks runtime integrity check — check for missing signature validation |
| App refuses to run on rooted device | Root check present, but is it bypassable via Frida? |
| Enterprise IPA runs on any device | Provisioning profile uses `ProvisionsAllDevices` — find the distribution cert |
| App enforces only same-team ID in keychain | Verify cross-app data sharing scope — potential lateral movement |

The takeaway: code signing is the OS-level trust anchor, but it says nothing about what the code *does*. Signing is about **identity and integrity**, not about security policy. Your job as a pentester is to verify that the app correctly enforces its own security policy *after* the signing check passes.

---

## 모바일 코드 사이닝: 앱의 서명이 보안 경계선이 되는 이유

모바일 펜테스트를 하다 보면 반드시 맞닥뜨리는 벽이 있습니다. 리패키징한 IPA가 설치 거부되거나, 패치한 APK가 실행을 거부하는 상황이죠. 그 벽이 바로 **코드 사이닝**입니다. 이것을 깊이 이해하는 것은 단순히 우회하기 위해서만이 아니라, 실제 현장에서 사이닝 설정 오류가 하나의 독립적인 취약점 유형이기 때문에 필수입니다.

## iOS 코드 사이닝

### 신뢰 체인 (Chain of Trust)

Apple의 보안 모델은 **계층적 신뢰 체인** 구조입니다. 각 단계는 바로 위 단계에 의존하며, 체인의 어느 한 부분이 깨지거나 변조되면 OS가 앱 실행을 거부합니다.

```
┌─────────────────────────────────┐
│        Apple Root CA            │  ← 모든 Apple 기기에 하드코딩
│   (Secure Enclave 내장)          │
└────────────────┬────────────────┘
                 │ 서명
                 ▼
┌─────────────────────────────────┐
│    Apple 중간 CA                 │  ← Apple 내부 인프라
└────────────────┬────────────────┘
                 │ 서명
                 ▼
┌─────────────────────────────────┐
│     개발자 인증서                  │  ← 내 공개키를 Apple이 서명
│  (macOS 키체인에 저장)             │    생성 경로: CSR → Apple 개발자 포털
└────────────────┬────────────────┘
                 │ 포함됨
                 ▼
┌─────────────────────────────────┐
│     프로비저닝 프로파일              │  ← Apple이 서명한 XML 번들, 포함 내용:
│   (embedded.mobileprovision)    │    • 앱 ID (번들 ID)
│                                 │    • 개발자 인증서
│                                 │    • 허용된 기기 UDID 목록
│                                 │    • 엔타이틀먼트
└────────────────┬────────────────┘
                 │ 내장 + 앱 바이너리에 개인키로 서명
                 ▼
┌─────────────────────────────────┐
│          IPA 패키지               │  ← 개발자 개인키로 바이너리 서명
│   (Payload/AppName.app)         │    Xcode가 자동으로 처리
└─────────────────────────────────┘
                 │
                 ▼ (설치 시점)
┌─────────────────────────────────┐
│      iOS 커널 검증                │  ← OS가 다음을 순서대로 확인:
│                                 │    1. 프로비저닝 프로파일의 Apple 서명 ✓
│                                 │    2. 프로파일 내 개발자 인증서 일치 ✓
│                                 │    3. 바이너리 서명 ↔ 개발자 인증서 일치 ✓
│                                 │    4. 기기 UDID가 프로파일에 포함 (개발/Ad-hoc) ✓
│                                 │    5. 엔타이틀먼트가 프로파일과 일치 ✓
└─────────────────────────────────┘
```

**배포 유형과 의미:**

| 유형 | 설치 가능 대상 | 기기 제한 | 사용 목적 |
|---|---|---|---|
| Development | UDID 등록 기기만 | 최대 100대 | 개발/QA 빌드 |
| Ad Hoc | UDID 등록 기기만 | 최대 100대 | 외부 테스터 |
| App Store | 누구나 | 없음 | 공개 배포 |
| Enterprise (사내) | 조직 내 누구나 | 없음 (`ProvisionsAllDevices`) | MDM 기반 기업 앱 |
| TestFlight | 초대된 테스터 | Apple 계정 필요 | 베타 테스트 |

### 엔타이틀먼트: 실제 공격 표면

엔타이틀먼트는 앱이 사용할 수 있는 특권 기능을 선언하는 XML 키-값 쌍입니다:

```xml
<key>com.apple.developer.associated-domains</key>
<array>
    <string>applinks:bank.example.com</string>
</array>
```

**주목해야 할 것:**
*   `get-task-allow: true` → 디버거 연결 허용. 프로덕션 빌드에 절대 있어서는 안 됩니다. 이 값이 있으면 탈옥 없이도 lldb를 연결할 수 있습니다.
*   스테이징 환경을 포함하는 지나치게 광범위한 `associated-domains`.
*   다른 앱과 그룹 ID를 공유하는 `keychain-access-groups` (합법적인 앱 간 데이터 공유이지만, 측면 이동 경로가 될 수도 있음).

**IPA에서 엔타이틀먼트 추출하기:**
```bash
unzip appname.ipa -d app_contents
cd app_contents/Payload/AppName.app/
codesign -d --entitlements :- AppName
```

### 실전에서의 프로비저닝 프로파일

펜테스트 중 IPA에서 내장 프로비저닝 프로파일을 추출할 수 있습니다:
```bash
security cms -D -i embedded.mobileprovision
```
확인해야 할 사항:
*   `ProvisionsAllDevices: true` → 엔터프라이즈/사내 배포. App Store 없이 모든 기기에서 실행 가능을 의미합니다.

## 펜테스터를 위한 IPA 설치 방법

클라이언트로부터 IPA를 직접 받는 경우, 기기 상태에 따라 설치 방법이 달라집니다.

### Option A: 일반 폰 (비탈옥)

일반 폰에서는 유효한 코드 서명이 필요합니다. 두 가지 방법이 있습니다.

**1. 개발자 인증서로 재서명 (Apple Developer 계정 필요)**
```bash
# 도구 설치
brew install ios-deploy

# Step 1 — IPA 압축 해제 후 프로비저닝 프로파일 교체
unzip target.ipa -d Payload
cp ~/path/to/your.mobileprovision Payload/Payload/AppName.app/embedded.mobileprovision

# Step 2 — 본인 인증서로 바이너리 재서명
codesign -f -s "iPhone Developer: Your Name (TEAMID)" \
  --entitlements entitlements.plist \
  Payload/Payload/AppName.app/AppName

# Step 3 — 재패키징 및 설치
cd Payload && zip -qr ../resigned.ipa Payload
ios-deploy --bundle Payload/AppName.app
```

**2. GUI 도구 사용 (간편)**

| 도구 | 플랫폼 | 비고 |
|---|---|---|
| [AltStore](https://altstore.io) | Mac/Win | 무료, Apple ID 사용, 앱 3개 제한 |
| [Sideloadly](https://sideloadly.io) | Mac/Win | 무료, 엔타이틀먼트 더 잘 지원 |
| [Apple Configurator 2](https://apps.apple.com/app/apple-configurator-2/id1037126344) | Mac 전용 | 기업/MDM 환경에 적합 |

### Option B: 탈옥 폰

탈옥 폰에서는 탈옥 자체가 서명 검증을 우회합니다 (예: AppSync Unified). 서명 여부에 관계없이 IPA를 설치할 수 있습니다.

**먼저 AppSync Unified 설치** (Cydia/Sileo에서):
```
저장소: https://cydia.akemi.ai/
패키지: AppSync Unified
```

**IPA 직접 설치:**
```bash
# 방법 1: ideviceinstaller
brew install libimobiledevice ideviceinstaller
ideviceinstaller -i target.ipa

# 방법 2: ios-deploy
brew install ios-deploy
ios-deploy --bundle Payload/AppName.app

# 방법 3: SSH로 직접 설치 (.deb 패키지인 경우)
scp target.deb root@<기기-IP>:/tmp/
ssh root@<기기-IP> "dpkg -i /tmp/target.deb && uicache"
```

**AppSync 동작 확인:**
```bash
ssh root@<기기-IP> "dpkg -l | grep appsync"
# 출력 예: ii  ai.akemi.appsyncunified
```

**설치 후 Frida 연동 (탈옥 기기):**
```bash
# Cydia/Sileo에서 frida-server 설치 후 확인
frida-ps -U   # USB 연결 기기의 실행 중 프로세스 목록
frida -U -n AppName --codeshare nowsecure/frida-ios-hooks
```

### 어떤 방법을 선택해야 할까?

| 상황 | 권장 방법 |
|---|---|
| 클라이언트 IPA 받음, 개발자 계정 있음 | 재서명 + `ios-deploy` |
| SSL 핀닝 우회 필요 | 탈옥 폰 + Frida |
| 블랙박스 테스트, 소스 없음 | AppSync + ideviceinstaller |
| Enterprise IPA (`ProvisionsAllDevices`) | 재서명 없이 바로 설치 |
| 탈옥 없이 테스트 필요 | Sideloadly + Apple ID |



## Android APK 사이닝

### 사이닝 스킴 (V1, V2, V3, V4)

Android는 사이닝 방식을 지속적으로 발전시켜 왔습니다. 각 버전은 다른 보안 속성과 우회 가능성을 가집니다:

| 스킴 | 도입 | 서명 대상 | 주요 한계 |
|---|---|---|---| 
| V1 (JAR 서명) | 최초 | ZIP 내 개별 파일 | 서명 유지하면서 파일 추가 가능 |
| V2 (APK 서명) | Android 7.0 | 전체 APK 블롭 | 어떤 변경도 서명 무효화 |
| V3 (키 로테이션) | Android 9.0 | APK + 키 로테이션 지원 | 키 소유권 체인 증명 추가 |
| V4 (스트리밍) | Android 11 | ADB 증분 설치와 연동 | V2 또는 V3 필요 |

**리패키징 분석을 위한 명령어:**
```bash
# APK가 사용하는 사이닝 스킴 확인
apksigner verify --verbose target.apk

# 수정된 APK에 서명 (변경 후 반드시 필요)
keytool -genkey -v -keystore my.keystore -alias mykey -keyalg RSA -keysize 2048 -validity 10000
apksigner sign --ks my.keystore --out signed.apk unsigned.apk
```

### 키스토어 설정 오류

Android 앱에서 흔히 발견되는 것은 하드코딩되거나 부적절하게 관리된 키스토어입니다:

```bash
# APK에서 키스토어 아티팩트 검색
unzip target.apk -d apk_contents
find apk_contents/ -name "*.jks" -o -name "*.keystore"

# 하드코딩된 비밀번호 확인
grep -r "keystorePassword\|storePassword" apk_contents/
```

키스토어와 비밀번호를 찾아내면, 공격자는 기기가 경고 없이 설치할 수 있는 유효하게 서명된 리패키징 APK를 만들 수 있습니다. 서명이 원본과 일치하기 때문입니다.

## 펜테스터 관점의 사이닝과 무결성

| 시나리오 | 테스트해야 할 것 |
|---|---|
| 리패키징 APK가 깨끗하게 설치됨 | 앱이 런타임 무결성 검사 누락 — 서명 검증 부재 확인 |
| 앱이 루팅된 기기에서 실행 거부 | 루트 감지 존재, 하지만 Frida로 우회 가능한가? |
| 엔터프라이즈 IPA가 모든 기기에서 실행 | `ProvisionsAllDevices` 사용 — 배포 인증서 찾기 |
| 앱이 동일 팀 ID 키체인만 허용 | 앱 간 데이터 공유 범위 확인 — 측면 이동 가능성 |

핵심: 코드 사이닝은 OS 수준의 신뢰 앵커이지만, 코드가 *무엇을 하는지*에 대해서는 아무것도 보장하지 않습니다. 사이닝은 **신원과 무결성**에 관한 것이지, 보안 정책에 관한 것이 아닙니다. 펜테스터로서 여러분의 역할은 사이닝 검사가 통과된 *이후* 앱이 자신의 보안 정책을 올바르게 적용하는지 검증하는 것입니다.
