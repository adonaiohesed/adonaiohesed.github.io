---
title: iOS Security Tweaks for Pentesters
author: hyoeun
key: page-ios_security_tweaks
categories:
- Security
- Mobile Security
image: "/assets/thumbnails/2022-01-01-ios_security_tweaks.png"
date: 2022-01-01 00:00:00
bilingual: true
---

## Overview

When performing iOS penetration testing, a jailbroken device equipped with the right tweaks is an essential part of the toolkit. These tweaks allow testers to bypass security controls, inspect runtime behavior, manipulate certificates, and analyze app internals that would otherwise be inaccessible. This post focuses on tweaks relevant to **security research and penetration testing**, not general user customization.

> **Note:** All testing should be performed on **your own devices or with explicit written permission**. Jailbreaking a device may void warranties and expose it to additional risks.

## Essential Jailbreak Tweaks for iOS Pentesters

### 1. SSL Kill Switch 2 / SSL Kill Switch 3
**Purpose:** Bypass SSL certificate pinning at the OS level.

SSL Kill Switch patches the `SecTrustEvaluate` and underlying TLS functions in iOS to always return a success result, effectively disabling certificate validation for all applications. This is one of the most fundamental tools for intercepting HTTPS traffic.

- **Install:** Cydia/Sileo → Repo: `https://julioverne.github.io` (v2) or various repos for v3
- **Usage:** Enable in Settings → SSL Kill Switch → Toggle on
- **Limitation:** Some apps use custom TLS stacks (OpenSSL, BoringSSL) or JNI that bypass this.

### 2. Frida + Frida CodeShare (via SSH)
**Purpose:** Dynamic instrumentation framework — the most powerful tool for iOS analysis.

While Frida itself is installed via pip on your host machine and controlled over SSH/USB, the `frida-server` daemon runs on the jailbroken device. Use Frida for:
- Hooking and modifying any Objective-C/Swift method at runtime
- Dumping decrypted app binaries (with frida-ios-dump)
- Bypassing jailbreak detection, certificate pinning, and root checks
- Tracing function calls

```bash
# Connect to device over USB
frida-ps -U
# Hook an app
frida -U -n "TargetApp" -e "console.log('hooked');"
```

### 3. Liberty Lite / A-Bypass
**Purpose:** Bypass jailbreak detection checks.

Many banking and financial apps detect jailbreak and refuse to run. Liberty Lite and A-Bypass intercept common jailbreak detection APIs:
- File existence checks (`/etc/apt`, `/usr/bin/ssh`, etc.)
- `canOpenURL` for Cydia scheme
- `fork()` availability
- Dynamic library checks

- **Install:** Sileo/Cydia — search for "Liberty Lite" or "A-Bypass"
- **Usage:** Settings → Liberty/A-Bypass → Enable per-app

### 4. Shadow (by jjolano)
**Purpose:** Advanced jailbreak detection bypass with per-process configuration.

Shadow works at a lower level than Liberty Lite, intercepting system calls to hide jailbreak artifacts. More effective against apps that use native code jailbreak detection.

### 5. Filza File Manager
**Purpose:** Full filesystem browser for jailbroken iOS.

Filza allows you to browse the entire iOS filesystem (including protected directories) to:
- Extract app binaries and data containers
- Inspect SQLite databases, plists, and cache files
- View app bundle contents (`/var/containers/Bundle/Application/`)
- Access Keychain data (with additional tools)

- **Install:** BigBoss repo
- **Usage:** Navigate to `/var/containers/Bundle/Application/` for app containers

### 6. Clutch / frida-ios-dump
**Purpose:** Dump decrypted IPA binaries from memory.

Apps on the App Store are FairPlay-encrypted. Clutch and frida-ios-dump decrypt the binary in memory and dump it to disk, enabling static analysis with tools like Hopper, Ghidra, or IDA Pro.

```bash
# Using frida-ios-dump (recommended, more reliable)
python3 dump.py -o TargetApp.ipa TargetApp
```

### 7. tcpdump (via NewTerm/SSH)
**Purpose:** Capture raw network traffic at the device level.

Install `tcpdump` for iOS via Cydia/Sileo and use it to capture traffic that bypasses Burp Suite (e.g., traffic from background processes or system frameworks):

```bash
# Capture all traffic
tcpdump -i any -w /var/root/capture.pcap
# Transfer to Mac for analysis
scp root@<device-ip>:/var/root/capture.pcap ~/Desktop/
```

### 8. Keychain Dumper
**Purpose:** Extract all Keychain items from the device.

Security-sensitive data like tokens, passwords, and certificates are often stored in iOS Keychain. On a jailbroken device, Keychain Dumper can extract all accessible Keychain entries.

```bash
# Run on device
./keychain_dumper -a
```

### 9. Needle / Objection (via Frida)
**Purpose:** Automated iOS security testing framework.

**Objection** (built on Frida) provides a command-line interface for common iOS and Android testing tasks:

```bash
# Start objection session
objection --gadget "TargetApp" explore

# Common commands
ios sslpinning disable
ios jailbreak simulate
ios keychain dump
ios nsuserdefaults get
ios plist cat /path/to/file.plist
```

### 10. AppSync Unified
**Purpose:** Install decrypted/modified IPAs without App Store validation.

AppSync patches iOS's app signing verification to allow installation of unsigned or re-signed IPAs, essential for testing modified versions of apps.

## Recommended Workflow

1. **Install & connect**: Set up Frida server, SSH access.
2. **Bypass detection**: Enable Liberty Lite/A-Bypass for the target app.
3. **Dump binary**: Use frida-ios-dump for static analysis.
4. **Proxy traffic**: Configure Burp Suite + enable SSL Kill Switch.
5. **Runtime analysis**: Use Objection for quick wins, raw Frida scripts for deep hooks.
6. **Filesystem inspection**: Use Filza to explore app data containers.
7. **Keychain extraction**: Run Keychain Dumper for stored secrets.

---

## 개요

iOS 침투 테스트를 수행할 때, 적절한 트윅이 갖춰진 탈옥 기기는 필수적인 도구입니다. 이러한 트윅을 통해 테스터들은 보안 제어를 우회하고, 런타임 동작을 검사하며, 인증서를 조작하고, 그렇지 않으면 접근할 수 없는 앱 내부를 분석할 수 있습니다. 이 포스트는 일반 사용자 커스터마이징이 아닌 **보안 연구 및 침투 테스트**에 관련된 트윅에 초점을 맞춥니다.

## iOS 침투 테스터를 위한 필수 트윅

### 1. SSL Kill Switch 2 / 3
**목적:** OS 수준에서 SSL 인증서 피닝 우회

SSL Kill Switch는 iOS의 `SecTrustEvaluate` 및 기본 TLS 함수를 패치하여 항상 성공 결과를 반환하도록 만들어, 모든 애플리케이션의 인증서 검증을 효과적으로 비활성화합니다. HTTPS 트래픽 인터셉팅을 위한 가장 기본적인 도구 중 하나입니다.

### 2. Frida + Frida CodeShare
**목적:** 동적 계측 프레임워크 — iOS 분석을 위한 가장 강력한 도구

Frida를 사용하면 Objective-C/Swift 메서드를 런타임에 후킹 및 수정하고, 복호화된 앱 바이너리를 덤프하며, 탈옥 탐지, 인증서 피닝, 루트 체크를 우회하고, 함수 호출을 추적할 수 있습니다.

### 3. Liberty Lite / A-Bypass
**목적:** 탈옥 탐지 체크 우회

많은 금융 앱이 탈옥을 탐지하고 실행을 거부합니다. Liberty Lite와 A-Bypass는 일반적인 탈옥 탐지 API를 인터셉트합니다:
- 파일 존재 확인 (`/etc/apt`, `/usr/bin/ssh` 등)
- Cydia 스킴에 대한 `canOpenURL`
- `fork()` 가용성
- 동적 라이브러리 확인

### 4. Filza File Manager
**목적:** 탈옥된 iOS의 전체 파일 시스템 브라우저

Filza를 통해 앱 바이너리와 데이터 컨테이너 추출, SQLite 데이터베이스·plists·캐시 파일 검사, 앱 번들 내용 확인, Keychain 데이터 접근이 가능합니다.

### 5. Clutch / frida-ios-dump
**목적:** 메모리에서 복호화된 IPA 바이너리 덤프

App Store의 앱들은 FairPlay로 암호화되어 있습니다. 이 도구들은 메모리에서 바이너리를 복호화하고 디스크에 덤프하여 Hopper, Ghidra, IDA Pro 등의 도구로 정적 분석이 가능하게 합니다.

### 6. Keychain Dumper
**목적:** 기기에서 모든 Keychain 항목 추출

토큰, 비밀번호, 인증서 같은 보안 민감 데이터는 종종 iOS Keychain에 저장됩니다. 탈옥된 기기에서 Keychain Dumper는 접근 가능한 모든 Keychain 항목을 추출할 수 있습니다.

### 7. Objection (Frida 기반)
**목적:** 자동화된 iOS 보안 테스트 프레임워크

Objection은 일반적인 iOS 및 Android 테스트 작업을 위한 커맨드라인 인터페이스를 제공합니다:
- `ios sslpinning disable` — SSL 피닝 우회
- `ios jailbreak simulate` — 탈옥 시뮬레이션
- `ios keychain dump` — Keychain 덤프
- `ios nsuserdefaults get` — UserDefaults 확인

## 권장 워크플로우

1. **설치 및 연결**: Frida 서버, SSH 접근 설정
2. **탐지 우회**: 대상 앱에 Liberty Lite/A-Bypass 활성화
3. **바이너리 덤프**: 정적 분석을 위해 frida-ios-dump 사용
4. **트래픽 프록시**: Burp Suite 설정 + SSL Kill Switch 활성화
5. **런타임 분석**: 빠른 분석에는 Objection, 심층 후킹에는 Frida 스크립트 사용
6. **파일 시스템 검사**: Filza로 앱 데이터 컨테이너 탐색
7. **Keychain 추출**: 저장된 비밀 정보를 위해 Keychain Dumper 실행
