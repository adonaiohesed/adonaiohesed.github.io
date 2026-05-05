---
title: Bypassing the Client-Side Authentication Mechanism
key: page-client_side_auth
categories:
- Security
- Mobile Security
author: hyoeun
math: true
mathjax_autoNumber: true
bilingual: true
image: "/assets/thumbnails/2023-07-09-client_side_auth.png"
date: 2023-07-09 11:45:36
---
## Mobile App Penetration Testing: Local Data Storage & Extraction

Mobile apps provide convenience to users, but they also store and process a significant amount of sensitive information. One of the core goals of penetration testing is to **verify whether this sensitive information is securely stored on the client side (user's device).** Attackers can access an app's file system, uncover unencrypted or inadequately protected data, and cause severe security breaches.

In this blog post, we will delve deeply into the key folders and files to pay attention to when penetration testing Android and iOS mobile apps, the types of sensitive information that can be found within them, and the useful tools for analyzing this data.

> [!IMPORTANT]
> To access the folders and files described below, a **rooted (Android) or jailbroken (iOS) mobile device** is generally required. This is necessary to bypass the app's sandbox restrictions and access protected app data areas.

## Common Types of Sensitive Information

Regardless of the operating system, the following types of information represent potential vulnerabilities if found in local storage:

*   **Authentication Information:** Usernames, passwords, API keys, Client Secrets, authentication tokens (Session, JWT, OAuth), Certificates, Private Keys.
*   **Personally Identifiable Information (PII):** Names, emails, phone numbers, addresses, dates of birth, financial information.
*   **App Settings and configuration:** Backend server URLs, API endpoint URLs, database connection info, hardcoded encryption keys, Salt values.
*   **Cached Data:** Sensitive JSON/XML responses, user profile pictures, documents, temporary files.
*   **Log Files:** Sensitive information unintentionally included in debug or error logs.

## Android App: Key Folders and Files

Android app data is primarily stored within an app-specific isolated sandbox at `/data/data/<package_name>/`.

### Sandbox Directory Analysis

*   **`/shared_prefs/`**: Stores app preferences in XML format. Managed via `SharedPreferences` API. Often contains login tokens and API keys.
*   **`/databases/`**: Where SQLite databases (`.db`) are stored. Look for account info and cached server responses.
*   **`/files/`**: Arbitrary file storage. Check for logs, documents, and configuration files.
*   **`/cache/`**: Temporary data like web page caches and image caches.
*   **`/lib/`**: Native libraries (`.so`). Check for hardcoded keys or URLs using `strings`.

### The Importance of AndroidManifest.xml

The manifest is the blueprint of the app. Key fields to check:
*   `android:debuggable="true"`: A severe vulnerability in production.
*   `android:allowBackup="true"`: Allows data extraction via `adb backup`.
*   `android:exported="true"`: Indicates if components can be accessed by other apps.
*   `uses-permission`: Look for excessive or dangerous permissions.

## iOS App: Key Folders and Files

iOS apps run in a strict sandbox within directories uniquely identified by UUIDs.

### Sandbox Directory Analysis

Root path on jailbroken devices: `/private/var/mobile/Containers/Data/Application/<UUID>/`

*   **`/Documents/`**: User-generated data and app-specific configuration.
*   **`/Library/Preferences/`**: Stores `.plist` files (managed via `UserDefaults`). Often contains tokens and keys. Use `plistutil` for binary plists.
*   **`/Library/Caches/`**: Web page caches (WKWebView) and media caches.
*   **`/Library/Application Support/`**: Custom databases (SQLite, Realm) and persistent support files.
*   **`/tmp/`**: Temporary files that might leak information during processing.

### iOS Keychain

iOS's secure storage for credentials. It uses hardware-backed encryption. Direct file system access is impossible; use runtime analysis tools like **objection** (`ios keychain dump`) to extract items.

## Bypassing Client-Side Authentication Mechanisms

Client-side authentication (PIN, biometrics) is a convenience feature, not a server-side security replacement. Pentesters assume all client-side verification can be bypassed.

### Biometrics (Fingerprint, Face ID)

*   **Runtime Hooking:** Intercept success/failure callbacks of `BiometricPrompt` (Android) or `LAContext` (iOS) using Frida. Force a "success" return.
*   **Emulator Spoofing:** Use virtual biometric inputs provided by developer tools.

### PIN and Pattern Authentication

*   **Reverse Engineering:** Identify the methods responsible for PIN/Pattern hashing and comparison.
*   **Storage Analysis:** Check if the PIN or its hash is stored in `shared_prefs` or `plist` files.
*   **Local Brute-Force:** Check if the app limits entry attempts or implements lockouts.

## Server-Side Impact & Trust Boundaries

The most critical stage is verifying server-side logic when client-side checks are bypassed. No client-side success signal should be blindly trusted.

### API Call Analysis & Replay Attacks

Intercept network traffic using **Burp Suite** after bypassing local authentication:
*   **Suspicious Parameters:** Check for flags like `biometric_success=true`.
*   **Replay Attack:** Can you perform sensitive operations by replaying the request even after logging out?
*   **Step-up Auth Bypass:** Verify if bypassing local auth allows skipping server-side MFA or re-authentication steps.

### Conclusion

Client-side authentication is for user convenience and local locking. The server must validate every critical operation independently and never blindly trust signals from the client binary.

---

## 모바일 앱 모의해킹: 로컬 데이터 저장소 및 추출 분석

모바일 앱은 사용자에게 편의성을 제공하지만, 그 과정에서 상당한 양의 민감 정보를 저장하고 처리합니다. 모의해킹의 핵심 목표 중 하나는 **이러한 민감 정보가 클라이언트 측(사용자 기기)에 안전하게 저장되어 있는지 확인하는 것**입니다.

이 포스트에서는 Android 및 iOS 앱 모의해킹 시 주의 깊게 살펴봐야 할 주요 폴더와 파일, 그 안에서 발견될 수 있는 민감 정보의 유형, 그리고 데이터 분석에 유용한 도구들에 대해 자세히 알아보겠습니다.

> [!IMPORTANT]
> 아래 설명된 폴더와 파일에 접근하려면 일반적으로 **루팅(Android) 또는 탈옥(iOS)**된 기기가 필요합니다. 이는 앱의 샌드박스 제한을 우회하여 보호된 데이터 영역에 접근하기 위함입니다.

## 주요 민감 정보 유형

운영체제와 관계없이, 로컬 저장소에서 다음과 같은 정보가 발견된다면 이는 잠재적인 취약점이 됩니다:

*   **인증 정보:** 사용자 이름, 비밀번호, API 키, Client Secret, 인증 토큰(Session, JWT, OAuth), 인증서, 개인키.
*   **개인 식별 정보(PII):** 이름, 이메일, 전화번호, 주소, 생년월일, 금융 정보.
*   **앱 설정 및 구성:** 백엔드 서버 URL, API 엔드포인트, 데이터베이스 연결 정보, 하드코딩된 암호화 키 및 솔트(Salt) 값.
*   **캐시 데이터:** 서버로부터 받은 민감한 JSON/XML 응답, 프로필 사진, 문서, 임시 파일.
*   **로그 파일:** 디버깅이나 오류 로그에 의도치 않게 포함된 민감 정보.

## Android 앱: 주요 폴더 및 파일 분석

안드로이드 앱 데이터는 주로 `/data/data/<package_name>/` 경로의 격리된 샌드박스 내에 저장됩니다.

### 샌드박스 디렉터리 분석

*   **`/shared_prefs/`**: XML 포맷의 앱 환경 설정 파일들이 저장됩니다. `SharedPreferences` API를 통해 관리되며, 로그인 토큰이나 API 키가 자주 발견됩니다.
*   **`/databases/`**: SQLite 데이터베이스(`.db`) 파일이 저장되는 곳입니다. 계정 정보나 캐시된 서버 응답을 확인해야 합니다.
*   **`/files/`**: 앱에서 임의로 사용하는 파일 저장 공간입니다. 로그 파일, 문서, 설정 파일 등이 존재할 수 있습니다.
*   **`/cache/`**: 웹 페이지 캐시나 이미지 캐시 등 임시 데이터가 저장됩니다.
*   **`/lib/`**: 앱에서 사용하는 네이티브 라이브러리(`.so`)가 저장됩니다. `strings` 명령어로 하드코딩된 키나 URL을 찾을 수 있습니다.

### AndroidManifest.xml 분석의 중요성

매니페스트는 앱의 설계도와 같습니다. 다음 설정을 주의 깊게 확인해야 합니다:
*   `android:debuggable="true"`: 프로덕션 빌드에 남아있을 경우 디버거 연결을 허용하는 심각한 취약점입니다.
*   `android:allowBackup="true"`: 루팅 없이도 `adb backup` 명령어로 데이터를 추출할 수 있게 합니다.
*   `android:exported="true"`: 구성 요소가 다른 앱에 의해 호출될 수 있는지 나타냅니다. 잘못된 설정은 권한 우회로 이어질 수 있습니다.
*   `uses-permission`: 앱이 과도하거나 위험한 권한을 요구하는지 확인합니다.

## iOS 앱: 주요 폴더 및 파일 분석

iOS 앱은 엄격한 샌드박스 내에서 실행되며, 고유한 UUID로 식별되는 디렉터리에 데이터를 저장합니다.

### 샌드박스 디렉터리 분석

탈옥 장비에서의 기본 경로: `/private/var/mobile/Containers/Data/Application/<UUID>/`

*   **`/Documents/`**: 사용자가 생성한 데이터나 앱의 주요 설정 파일이 저장됩니다.
*   **`/Library/Preferences/`**: `.plist` 파일들이 저장되는 곳입니다(`UserDefaults` 사용). 인증 토큰등이 자주 저장되며, 바이너리 포맷일 경우 `plistutil`로 변환해 확인합니다.
*   **`/Library/Caches/`**: 웹 뷰(WKWebView) 캐시나 미디어 캐시가 저장됩니다.
*   **`/Library/Application Support/`**: 커스텀 데이터베이스(SQLite, Realm)와 앱 실행에 필요한 지원 파일들이 저장됩니다.
*   **`/tmp/`**: 프로세싱 중에 일시적으로 생성되는 파일들이 존재하며, 민감 정보가 남아있을 수 있습니다.

### iOS 키체인 (Keychain)

비밀번호, 인증서 등 최상위 보안 정보를 저장하는 안전한 저장소입니다. 하드웨어 기반 암호화를 사용하므로 파일 시스템에서 직접 읽는 것은 불가능하며, **objection**(`ios keychain dump`) 같은 런타임 분석 도구를 사용해 추출해야 합니다.

## 클라이언트 측 인증 메커니즘 우회

PIN이나 생체 인증은 사용자 편의를 위한 기능일 뿐, 서버 보안을 대체할 수 없습니다. 모의해킹 시 모든 클라이언트 측 검증은 우회 가능하다는 가정을 전제로 합니다.

### 생체 인식 (지문, Face ID)

*   **런타임 후킹**: Frida를 사용하여 `BiometricPrompt`(Android)나 `LAContext`(iOS)의 콜백 함수를 후킹합니다. 실제 인증 결과와 상관없이 "성공"을 반환하도록 강제합니다.
*   **에뮬레이터 스푸핑**: 개발자 도구에서 제공하는 가상 생체 입력을 사용하여 흐름을 통과시킵니다.

### PIN 및 패턴 인증

*   **리버스 엔지니어링**: PIN/패턴의 하싱 및 비교 로직을 담당하는 메서드를 찾아 분석합니다.
*   **저장 방식 분석**: `shared_prefs`나 `plist` 내에 PIN 값이나 해시가 평문으로 저장되어 있는지 확인합니다.
*   **로컬 무차별 대입**: 입력 시도 횟수 제한이나 계정 잠금 정책이 있는지 테스트합니다.

## 서버 측 영향 및 신뢰 경계 테스트

클라이언트 측 인증을 우회했을 때, **서버 측의 인가 로직이 여전히 견고한지** 확인하는 것이 가장 중요합니다.

### API 호출 분석 및 재생 공격 (Replay Attack)

로컬 인증 우회 후 **Burp Suite** 등을 통해 네트워크 트래픽을 가로챕니다:
*   **의심스러운 파라미터**: `biometric_success=true`와 같은 단순 플래그에 서버가 의존하는지 확인합니다.
*   **재생 공격**: 가로챈 요청을 다시 보냈을 때, 로그아웃 상태나 다른 기기에서도 민감한 작업(이체, 비밀번호 변경 등)이 수행되는지 테스트합니다.
*   **스텝업 인증 우회**: 로컬 인증 우회로 인해 서버 측의 추가 인증(MFA, 2단계 인증) 단계가 생략되는지 확인합니다.

### 결론

클라이언트 측 인증은 "로컬 잠금"용이지 서버 보안의 대체재가 될 수 없습니다. 서버는 클라이언트 바이너리로부터 오는 신호를 맹목적으로 믿지 말고, 모든 민감한 작업을 독립적으로 검증해야 합니다.