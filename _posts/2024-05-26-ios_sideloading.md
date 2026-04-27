---
title: iOS Sideloading with Xcode
key: page-ios_sideloading
categories:
- Security
- Mobile Security
author: hyoeun
math: true
mathjax_autoNumber: true
bilingual: true
image: "/assets/thumbnails/2024-05-26-ios_sideloading.png"
date: 2024-05-26 10:00:00
---
## iOS Sideloading with Xcode: A Practical Guide for Mobile Pentesters

Sideloading — installing an app onto an iOS device outside of the App Store — is a fundamental capability for mobile pentesters. Whether you need to install a custom Frida gadget, deploy a patched IPA onto a test device, or simply get a client-provided debug build running without TestFlight, understanding the iOS sideloading pipeline is a daily skill.

This guide focuses on the **practical mechanics** of sideloading via Xcode, what actually happens under the hood, and where things go wrong.

## Why You Can't Just Copy an IPA (iOS's Trust Model)

Unlike Android where you enable "Unknown Sources" and install any APK, iOS enforces **mandatory code signing** at the kernel level. The `amfid` daemon (Apple Mobile File Integrity Daemon) verifies every binary's signature before it's allowed to execute. There is no way to bypass this on a non-jailbroken device — it's enforced at the hardware secure boot level.

This means every app on your iOS test device must be signed with a certificate that chains up to Apple. Your options are:

| Method | Requirements | App Validity | Best For |
|---|---|---|---|
| Xcode + Free Apple ID | Apple ID, Xcode | **7 days** | Personal testing |
| Xcode + Paid Developer Acc | $99/yr Apple Developer Program | **1 year** | Pentest lab devices |
| AltStore / Sideloadly | Apple ID | 7 days (re-auto) | User-friendly repeat installs |
| TestFlight | Developer's invite | Varies | Client-provided test builds |
| Enterprise Certificate | Company signing cert | 1 year | Bypassed by attackers (watch for this) |

## Sideloading with Xcode: Step by Step

### Prerequisites

*   Mac with Xcode installed (matching or newer than the iOS version on your device)
*   An Apple ID (free is fine for most pentesting purposes)
*   Your iOS test device connected via USB

### Step 1: Add Your Apple ID to Xcode

Open Xcode → **Preferences (⌘,)** → **Accounts** tab → click **+** → Sign in with Apple ID.

Once added, Xcode will automatically:
*   Create a free **development certificate** for your account
*   Register it with Apple's development backend

### Step 2: Create a Dummy Xcode Project

You need an Xcode project to serve as the signing vehicle. Create a minimal one:

1.  **Xcode** → **Create a new Xcode project**
2.  Choose **iOS → App**, click **Next**
3.  Set **Product Name** to anything (e.g., `Loader`)
4.  Set **Team** to your Apple ID
5.  Set **Bundle Identifier** to something unique: `com.yourname.loader`
6.  **Language**: Swift, **Interface**: Storyboard — keep it simple

### Step 3: Replace the App Binary (For Resigning an Existing IPA)

If you have an IPA you want to install (e.g., a debug build from a client, or a patched version):

```bash
# 1. Unpack the IPA
cp target_app.ipa target_app.zip
unzip target_app.zip -d Payload_extracted

# 2. Navigate to the app bundle
cd Payload_extracted/Payload/TargetApp.app/

# 3. Remove the existing signature
codesign --remove-signature TargetApp
find . -name "*.dylib" -exec codesign --remove-signature {} \;

# 4. Check what entitlements the app originally needed
codesign -d --entitlements :- TargetApp > original_entitlements.xml
```

### Step 4: Get Your Signing Identity and Provisioning Profile

In Xcode, plug in your device and build your dummy project once. This triggers Xcode to:
1.  **Register your device UDID** with your Apple Developer account
2.  **Generate a provisioning profile** tied to your device + your cert
3.  **Download the profile** to `~/Library/MobileDevice/Provisioning Profiles/`

```bash
# List available signing identities
security find-identity -v -p codesigning

# Output example:
# 1) ABC123... "Apple Development: you@example.com (TEAMID)"

# Find your provisioning profile
ls ~/Library/MobileDevice/Provisioning\ Profiles/*.mobileprovision | head -5
security cms -D -i ~/Library/MobileDevice/Provisioning\ Profiles/your_profile.mobileprovision | grep -A1 "Name"
```

### Step 5: Resign and Install

```bash
# 1. Re-sign the main binary with your identity
SIGNING_IDENTITY="Apple Development: you@gmail.com (YOURTEAMID)"
PROVISION_PROFILE="$HOME/Library/MobileDevice/Provisioning Profiles/your_profile.mobileprovision"

# Copy the provisioning profile into the app bundle
cp "$PROVISION_PROFILE" Payload_extracted/Payload/TargetApp.app/embedded.mobileprovision

# 2. Sign any bundled frameworks first (order matters)
find Payload_extracted/Payload/TargetApp.app/Frameworks -name "*.dylib" -o -name "*.framework" | \
    xargs -I{} codesign --force --sign "$SIGNING_IDENTITY" {}

# 3. Sign the main app bundle
codesign --force --sign "$SIGNING_IDENTITY" \
    --entitlements entitlements.plist \
    Payload_extracted/Payload/TargetApp.app

# 4. Repackage
cd Payload_extracted
zip -r resigned.ipa Payload/

# 5. Install via cfgutil or ideviceinstaller
ideviceinstaller -i resigned.ipa
# Or via Xcode Devices window: drag and drop the IPA
```

### Step 6: Trust the Developer on Device

The first time you install via sideloading (not App Store):

**Settings → General → VPN & Device Management → [Your Apple ID] → Trust**

Without this step, the app will launch but immediately crash with a "Untrusted Developer" dialog.

## The 7-Day Problem and Working Around It

Free Apple ID certificates are only valid for **7 days**. After that, the app stops launching. Workarounds:

1.  **Re-sign every 7 days** (build the dummy project again in Xcode — it refreshes automatically)
2.  **AltStore** — keeps a companion app on your Mac that auto-resigns over Wi-Fi/USB when the cert nears expiry
3.  **Paid Developer Account** — $99/year, extends to 1 year, also allows up to 100 device registrations

> [!IMPORTANT]
> For pentest lab devices that you use regularly, invest in the paid developer account. The 7-day cycle on free accounts is operationally painful for anything beyond a one-off test.

## Embedding a Frida Gadget via Sideloading

A critical use case: you have a non-jailbroken device and want to use Frida. The solution is embedding `FridaGadget.dylib` into the app and sideloading it.

```bash
# 1. Download the correct Frida gadget for your device architecture
# From: https://github.com/frida/frida/releases
# File: frida-gadget-16.x.x-ios-universal.dylib → rename to FridaGadget.dylib

# 2. Place it inside the app bundle
cp FridaGadget.dylib Payload_extracted/Payload/TargetApp.app/Frameworks/

# 3. Inject a load command into the binary (using insert_dylib or optool)
optool install -c load \
    -p "@executable_path/Frameworks/FridaGadget.dylib" \
    -t Payload_extracted/Payload/TargetApp.app/TargetApp

# 4. Sign the gadget before resigning the app
codesign --force --sign "$SIGNING_IDENTITY" \
    Payload_extracted/Payload/TargetApp.app/Frameworks/FridaGadget.dylib

# 5. Resign and install as normal
# When the app launches, FridaGadget will pause execution and listen on port 27042
# Connect: frida -H 127.0.0.1:27042 Gadget
```

This gives you full Frida capability on non-jailbroken devices — essential for testing production devices that clients won't jailbreak.

---

## Xcode를 이용한 iOS 사이드로딩: 모바일 펜테스터를 위한 실전 가이드

사이드로딩 — App Store 우회를 통한 iOS 기기 앱 설치 — 은 모바일 펜테스터에게 필수적인 기능입니다. 커스텀 Frida 가젯 설치, 테스트 기기에 패치된 IPA 배포, 또는 TestFlight 없이 클라이언트 제공 디버그 빌드 실행 등 다양한 상황에서 필요합니다.

## 왜 IPA를 그냥 복사할 수 없는가 (iOS 신뢰 모델)

안드로이드와 달리 iOS는 **커널 수준의 필수 코드 사이닝**을 강제합니다. `amfid` 데몬이 모든 바이너리의 서명을 실행 전에 검증합니다. 비탈옥 기기에서는 이를 우회하는 방법이 없습니다.

| 방법 | 요건 | 유효 기간 | 적합한 용도 |
|---|---|---|---|
| Xcode + 무료 Apple ID | Apple ID, Xcode | **7일** | 개인 테스트 |
| Xcode + 유료 개발자 계정 | 연 $99 Apple Developer | **1년** | 펜테스트 랩 기기 |
| AltStore / Sideloadly | Apple ID | 7일 (자동 갱신) | 반복 설치에 편리 |
| 엔터프라이즈 인증서 | 기업 서명 인증서 | 1년 | 공격자가 악용하는 방식 (주목!) |

## Xcode를 이용한 사이드로딩: 단계별 안내

### 전제 조건

*   Xcode가 설치된 Mac (기기 iOS 버전 이상)
*   Apple ID (무료 계정으로도 대부분 작동)
*   USB로 연결된 iOS 테스트 기기

### 1단계: Xcode에 Apple ID 추가

Xcode → **Preferences (⌘,)** → **Accounts** 탭 → **+** 클릭 → Apple ID로 로그인.

### 2단계: 더미 Xcode 프로젝트 생성

1.  **Xcode** → **Create a new Xcode project**
2.  **iOS → App** 선택
3.  **Product Name**: 아무 이름 (예: `Loader`)
4.  **Team**: 자신의 Apple ID 선택
5.  **Bundle Identifier**: 고유한 것으로 설정 (`com.yourname.loader`)

### 3단계: 기존 IPA 리사이닝

```bash
# IPA 압축 해제
cp target_app.ipa target_app.zip
unzip target_app.zip -d Payload_extracted

# 기존 서명 제거
codesign --remove-signature Payload_extracted/Payload/TargetApp.app/TargetApp
```

### 4단계: 서명 ID 및 프로비저닝 프로파일 확보

Xcode에서 더미 프로젝트를 한 번 빌드하면, Xcode가 자동으로 기기 UDID를 등록하고 프로비저닝 프로파일을 생성합니다.

```bash
# 사용 가능한 서명 ID 목록
security find-identity -v -p codesigning

# 프로비저닝 프로파일 확인
ls ~/Library/MobileDevice/Provisioning\ Profiles/*.mobileprovision
```

### 5단계: 리사이닝 및 설치

```bash
SIGNING_IDENTITY="Apple Development: you@gmail.com (YOURTEAMID)"
PROVISION_PROFILE="$HOME/Library/MobileDevice/Provisioning Profiles/your_profile.mobileprovision"

# 프로비저닝 프로파일 복사
cp "$PROVISION_PROFILE" Payload_extracted/Payload/TargetApp.app/embedded.mobileprovision

# 프레임워크 먼저 서명 (순서 중요)
find Payload_extracted/Payload/TargetApp.app/Frameworks -name "*.dylib" | \
    xargs -I{} codesign --force --sign "$SIGNING_IDENTITY" {}

# 메인 앱 번들 서명
codesign --force --sign "$SIGNING_IDENTITY" \
    --entitlements entitlements.plist \
    Payload_extracted/Payload/TargetApp.app

# 재패키징
cd Payload_extracted
zip -r resigned.ipa Payload/

# 설치
ideviceinstaller -i resigned.ipa
```

### 6단계: 기기에서 개발자 신뢰 설정

**설정 → 일반 → VPN 및 기기 관리 → [Apple ID] → 신뢰**

## 7일 문제와 해결책

무료 Apple ID 인증서는 **7일**만 유효합니다. 해결 방법:

1.  7일마다 Xcode에서 더미 프로젝트 빌드 (자동 갱신)
2.  **AltStore** — Wi-Fi/USB를 통해 인증서 만료 전 자동 리사이닝
3.  **유료 개발자 계정** — 1년, 최대 100대 기기 등록

> [!IMPORTANT]
> 정기적으로 사용하는 펜테스트 랩 기기에는 유료 개발자 계정 투자를 권장합니다. 무료 계정의 7일 사이클은 정기적인 테스트에 매우 번거롭습니다.

## 사이드로딩을 통한 Frida 가젯 삽입

비탈옥 기기에서 Frida를 사용하는 핵심 방법입니다: `FridaGadget.dylib`를 앱에 삽입하고 사이드로딩합니다.

```bash
# FridaGadget.dylib 다운로드 후 앱 번들에 배치
cp FridaGadget.dylib Payload_extracted/Payload/TargetApp.app/Frameworks/

# optool로 로드 커맨드 삽입
optool install -c load \
    -p "@executable_path/Frameworks/FridaGadget.dylib" \
    -t Payload_extracted/Payload/TargetApp.app/TargetApp

# 가젯 서명
codesign --force --sign "$SIGNING_IDENTITY" \
    Payload_extracted/Payload/TargetApp.app/Frameworks/FridaGadget.dylib

# 일반 절차대로 리사이닝 후 설치
# 앱 실행 시 FridaGadget이 27042 포트에서 대기
# 연결: frida -H 127.0.0.1:27042 Gadget
```

이 방법으로 탈옥하지 않은 기기에서도 완전한 Frida 기능을 사용할 수 있습니다 — 클라이언트가 탈옥을 허용하지 않는 프로덕션 기기 테스트에 필수적입니다.
