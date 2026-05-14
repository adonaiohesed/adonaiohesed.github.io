---
title: The Anatomy of Mobile App
key: page-anatomy_mobile
categories:
- Security
- Mobile Security
author: hyoeun
math: true
mathjax_autoNumber: true
image: "/assets/thumbnails/2023-01-29-anatomy_mobile.png"
bilingual: true
date: 2023-01-29 20:02:24
---

## The Anatomy of Mobile App and Penetration Testing

### **Common Types of Sensitive Information to Look For**

Regardless of the operating system, the following types of information, if found in an app's local storage, represent potential vulnerabilities:

*   **Authentication Information:** Usernames, passwords (especially if plaintext or weakly hashed), API keys, Client Secrets, authentication tokens (Session, JWT, OAuth), Certificates, Private Keys.
*   **Personally Identifiable Information (PII):** Names, emails, phone numbers, addresses, dates of birth, social security numbers (or equivalents), financial information (account numbers, card numbers, etc.), health information.
*   **App Settings and Configuration Information:** Backend server URLs, API endpoint URLs (exposed regardless of development/staging/production environments), database connection information, hardcoded encryption keys, Salt values.
*   **Cached Sensitive Data:** Sensitive JSON/XML responses fetched from the server, user profile pictures, documents, and other media files, temporary files.
*   **Log Files:** Sensitive information unintentionally included in debug or error logs.


### **Android App: Anatomy of Key Folders and Files**

Android app data is primarily stored within an app-specific isolated sandbox at the path `/data/data/<package_name>/`. `<package_name>` is the app's unique package name (e.g., `com.chase.mobileapp`).

1.  **`/data/data/<package_name>/`**

    *   **Description:** This is the default path where all of an app's internal storage data is located.
    *   **Access Method:** You can access it on a rooted device using `adb shell` (or `adb pull /data/data/<package_name>/` to extract all data), or via a rooted file explorer.

    *   **`/shared_prefs/`**
        *   **Description:** This directory stores app preferences and simple key-value pair data in XML file format. It's managed via the `SharedPreferences` API.
        *   **Key Analysis Targets:**
            *   Login tokens (JWT, OAuth Access Tokens, Refresh Tokens)
            *   API keys, authentication information (user IDs, security question answers, etc.)
            *   User settings, feature flags (e.g., "Keep me logged in" status)
            *   Sensitive server URLs or API endpoints
        *   **Vulnerability:** XML files are stored in plaintext, so any sensitive information saved here without encryption is immediately exposed.

    *   **`/databases/`**
        *   **Description:** If the app uses an SQLite database, this is where the `.db` file is stored.
        *   **Key Analysis Targets:**
            *   User account information (names, emails, password hashes/plaintext)
            *   User-generated data like message content, contacts, call history
            *   App usage records, cached sensitive server responses
            *   For financial apps, transaction history, account details, etc.
        *   **Vulnerability:** Database files are often unencrypted, allowing direct access to query all data. An unencrypted SQLite DB leads to a very severe exposure of sensitive information.

    *   **`/files/`**
        *   **Description:** An app-specific directory used by the app to store arbitrary data in file format.
        *   **Key Analysis Targets:**
            *   Log files (potential for sensitive info in debug logs)
            *   Downloaded documents, images, media files (especially if containing sensitive content)
            *   Internal cache data, backup files
            *   Hardcoded credentials or configuration files (e.g., `.json`, `.txt`)
        *   **Vulnerability:** Files stored here are often unencrypted, so check file extensions and content for sensitive information.

    *   **`/cache/`**
        *   **Description:** This is where the app stores temporary data. It may be deleted when the app closes or by the system.
        *   **Key Analysis Targets:** Web page caches, image caches, and temporary files may contain sensitive information.

    *   **`/lib/`**
        *   **Description:** This directory stores native libraries (`.so` files) used by the app.
        *   **Key Analysis Targets:** Hardcoded API keys, encryption keys, server URLs, etc., written in native code (C/C++), which can be extracted using tools like `strings`.

2.  **Importance of `AndroidManifest.xml` Analysis**

    The `AndroidManifest.xml` file is like the **blueprint** of an Android app. It defines all critical metadata, including app components, permissions, and security configurations. For a pentester, it's a **starting point for static analysis** and crucial for identifying the app's potential attack surface.

    *   **Settings to Pay Attention To:**
        *   **`android:debuggable="true"`:** If this flag is set to `true` in a production build, it becomes a severe vulnerability, allowing debuggers to attach to the app process, manipulate runtime state, or dump memory.
        *   **`android:allowBackup="true"`:** If `true`, this flag allows `adb backup` command to extract app data without root, increasing the risk of sensitive information exposure.
        *   **`android:exported="true"` (Component Export Status):**
            *   **`<activity android:exported="true">`:** Indicates if other apps can launch this activity. Misconfiguration can lead to intent redirection or unauthorized access.
            *   **`<service android:exported="true">`:** Indicates if other apps can bind to or start this service. Can lead to remote code execution or privilege escalation.
            *   **`<receiver android:exported="true">`:** Indicates if other apps can send broadcasts to this receiver. Poses risks like intent injection.
            *   **`<provider android:exported="true">`:** Indicates if other apps can access data through this content provider. Misconfiguration can lead to sensitive data leakage.
        *   **`uses-permission`:** The list of permissions requested by the app. Check for excessive permissions (e.g., `READ_CALL_LOGS`, `SEND_SMS`) or dangerous permissions (e.g., `SYSTEM_ALERT_WINDOW`, `BIND_ACCESSIBILITY_SERVICE`) to identify potential misuse.
        *   **`android:testOnly="true"`:** A flag indicating a test build of the app. Its presence in a production build can be a security concern.
        *   **Network Security Configuration:** Defined in the `network-security-config` file, specifying TLS settings and whether cleartext traffic is allowed. Check for settings that permit unencrypted traffic.

3.  **Android Core Application Components**

    Android apps are built around four fundamental building blocks defined in `AndroidManifest.xml`. From a security perspective, each component represents a distinct attack surface that must be carefully audited.

    *   **Activities**
        *   **Description:** An `Activity` represents a single screen with a user interface. It is the primary entry point for user interaction with an app.
        *   **Security Risks:**
            *   **Unauthorized Activity Launch:** If `android:exported="true"` is set without proper permission checks, any third-party app can launch the activity directly.
            *   **Intent Data Leakage:** Sensitive data passed via `Intent` extras between activities can be intercepted or logged.
            *   **Task Hijacking / StrandHogg:** A malicious app can hijack a task stack to overlay a phishing UI over a legitimate activity.
        *   **Pentesting Approach:**
            *   Check `AndroidManifest.xml` for exported activities without `android:permission` restrictions.
            *   Use `adb shell am start -n <package>/<activity>` to attempt launching exported activities directly.
            *   Review `onActivityResult()` for improper handling of returned data.

    *   **Broadcast Receivers**
        *   **Description:** A `BroadcastReceiver` responds to system-wide or app-specific broadcast announcements.
        *   **Security Risks:**
            *   **Intent Injection:** If an exported receiver processes Intents without validation, a malicious app can send crafted broadcasts to trigger unintended behavior.
            *   **Sensitive Data in Broadcasts:** App-wide broadcasts (implicit intents) can be intercepted by other apps on the device if not targeted explicitly.
            *   **Sticky Broadcasts (Deprecated):** Historically, sticky broadcasts could be read by any app at any time.
        *   **Pentesting Approach:**
            *   Enumerate exported receivers via `AndroidManifest.xml` or `adb shell dumpsys package <package>`.
            *   Send crafted Intents to exported receivers: `adb shell am broadcast -a <action> -n <package>/<receiver>`.
            *   Monitor broadcasts with tools like **Drozer** (`run app.broadcast.info -a <package>`).

    *   **Services**
        *   **Description:** A `Service` runs in the background to perform long-running operations without a user interface.
        *   **Security Risks:**
            *   **Unauthorized Service Binding:** Exported services without permission checks can be bound by malicious apps to invoke IPC methods.
            *   **Remote Code Execution via AIDL:** Insufficient input validation in AIDL interfaces can lead to logic bugs or RCE.
            *   **Unprotected Started Services:** A malicious app can start an exported service with a crafted Intent, potentially causing data corruption.
        *   **Pentesting Approach:**
            *   Identify exported services in `AndroidManifest.xml`.
            *   Attempt to start or bind to the service: `adb shell am startservice -n <package>/<service>`.
            *   Inspect AIDL interfaces using **Jadx** decompiled source to identify exploitable methods.

    *   **Content Providers**
        *   **Description:** A `ContentProvider` manages shared access to a structured set of app data.
        *   **Security Risks:**
            *   **SQL Injection:** If user-supplied URI parameters are embedded directly into SQL queries without parameterized queries.
            *   **Path Traversal:** Insecure `FileProvider` or `openFile()` implementations can allow reading arbitrary files.
            *   **Unauthorized Data Access:** An exported provider without read/write permissions allows any app to access sensitive data.
            *   **Overly Permissive `grantUriPermissions`:** Misconfigured URI permissions can grant temporary access beyond the intended scope.
        *   **Pentesting Approach:**
            *   Enumerate exported providers: **Drozer** `run app.provider.info -a <package>`.
            *   Query content URIs directly: `adb shell content query --uri content://<authority>/<path>`.
            *   Test for SQL injection: `run app.provider.query content://<authority>/<path> --projection "* FROM <table>--"`.
            *   Test for path traversal with **Drozer**: `run scanner.provider.traversal -a <package>`.

4.  **KeyStore (Hardware/Software-based Secure Storage)**

    *   **Description:** An API and service within the Android OS for securely storing and managing cryptographic keys and credentials.
    *   **Key Analysis Targets:** It's almost impossible to directly read KeyStore content. Instead, analyze **how the app's code uses KeyStore (static analysis)** and attempt **runtime analysis (Frida/Objection)** to intercept data.


### **iOS App: Anatomy of Key Folders and Files**

iOS app data runs within a strict Sandbox. App data is stored in app-specific directories with unique UUIDs.

1.  **`/private/var/mobile/Containers/Data/Application/<UUID>/`**

    *   **Correct Path:** This is the accurate root path for accessing an app's sandbox data container on a jailbroken iOS device.
    *   **Access Method:** On a jailbroken device, use `ssh` or a file manager (like Filza). You can also extract unencrypted backup files using tools like `iMazing`.

    *   **`/Documents/`**
        *   **Description:** Stores important data generated or managed by the user within the app.
        *   **Key Analysis Targets:** User documents, photos, videos, database files (SQLite `.db`), app-specific config files.
        *   **Vulnerability:** If sensitive information is stored here in plaintext, it's immediately exposed.

    *   **`/Library/`**
        *   **Description:** Stores various types of app data, including settings, cache files, and support files.
        *   **`/Library/Preferences/` (Core of Plist File Analysis)**
            *   **Description:** Stores `.plist` files managed via `UserDefaults`.
            *   **Key Analysis Targets:** Login tokens, API keys, authentication information, user settings, feature flags.
            *   **Vulnerability:** If sensitive information is stored in `.plist` files without encryption, it's exposed.
        *   **`/Library/Caches/`**
            *   **Description:** Stores temporary cache data.
        *   **`/Library/Application Support/`**
            *   **Description:** Stores persistent support files, custom databases, and external library data.
        *   **`/Library/WebKit/`**
            *   **Description:** Stores `WKWebView`-related data, including cookies, local storage, and session storage.

    *   **`/tmp/`**
        *   **Description:** Stores temporary files needed for very short durations.

2.  **Keychain (iOS Secure Storage)**

    *   **Description:** A highly secure service in iOS for storing and managing extremely sensitive credentials like passwords, certificates, and encryption keys.
    *   **Key Analysis Targets:** Direct file system access is impossible. Use **runtime analysis (Frida/Objection)** with tools like `objection ios keychain dump`.


### **Static/Dynamic Analysis: Advanced Tooling**

Modern penetration testing heavily relies on combining static and dynamic analysis for efficient data extraction and real-time verification.

#### **1. Android Apps: Live Data Inspection and Extraction**

*   **`android_application_analyzer` (NotSoSecure)**: Specifically for **static analysis** of APK files, analyzing `AndroidManifest.xml` and identifying hardcoded strings.
*   **Objection (Dynamic Analysis Core)**: Built on `Frida`, used for inspecting and extracting data in real-time on a rooted Android device.

```bash
# Attach to App Process
objection -g <com.your.package.name> explore

# Explore Data Directory and Extract Files
android data explore
ls
cd cache
download cached_sensitive_data.json

# Inspect SharedPreferences
android sharedprefs get all

# Inspect SQLite Database
android sqlite list
android sqlite open myapp.db
tables
select * from users;
```

#### **2. iOS Apps: Live Data Inspection and Extraction**

*   **MobSF (Static Analysis)**: Excellent for **static analysis** of iOS IPA files. Automatically parses `Info.plist`, detects hardcoded strings, and identifies insecure API usage.
*   **Objection (Dynamic Analysis Core)**: On a jailbroken iOS device, allows inspecting and extracting data in real-time.

```bash
# Attach to App Process
objection -g <com.your.bundle.id> explore

# Explore Data Directory and Extract Files
ios data explore
ls
cd Documents
download sensitive_document.pdf

# Inspect UserDefaults
ios nsuserdefaults get all

# Inspect SQLite Database
ios sqlite list
ios sqlite open myapp.bundle.id.db

# Dump Keychain Content
ios keychain dump
```

---

## 모바일 폴더 구조와 펜테스팅

### **공통적으로 찾아야 할 민감 정보 유형**

어떤 운영체제의 앱이든, 다음 유형의 정보들이 앱의 로컬 저장소에 있다면 잠재적인 취약점이 됩니다.

*   **인증 정보:** 사용자 이름, 비밀번호, API 키, 클라이언트 시크릿, 인증 토큰 (Session, JWT, OAuth), 인증서, 개인 키.
*   **개인 식별 정보 (PII):** 이름, 이메일, 전화번호, 주소, 생년월일, 주민등록번호, 금융 정보, 건강 정보.
*   **앱 설정 및 구성 정보:** 백엔드 서버 URL, API 엔드포인트 URL, 데이터베이스 연결 정보, 하드코딩된 암호화 키, 솔트(Salt) 값.
*   **캐시된 민감 데이터:** 서버에서 가져온 민감한 JSON/XML 응답, 사용자 프로필 사진, 문서 등 미디어 파일, 임시 파일.
*   **로그 파일:** 디버그 또는 에러 로그에 민감 정보가 의도치 않게 포함된 경우.


### **Android 앱의 주요 폴더 및 파일 해부학**

Android 앱의 데이터는 주로 `/data/data/<package_name>/` 경로 아래에 앱별로 격리된 샌드박스 내에 저장됩니다.

1.  **`/data/data/<package_name>/`**

    *   **설명:** 해당 앱의 모든 내부 저장소 데이터가 위치하는 기본 경로입니다.
    *   **접근 방법:** 루팅된 기기에서 `adb shell` 또는 `adb pull` 명령어를 통해 접근할 수 있습니다.

    *   **`/shared_prefs/`**
        *   **설명:** 앱의 환경 설정 및 간단한 키-값 데이터를 XML 파일 형태로 저장하는 곳입니다.
        *   **주요 분석 대상:** 로그인 토큰, API 키, 인증 정보, 사용자 설정, 기능 플래그 등.
        *   **취약점:** XML 파일은 평문으로 저장되므로, 민감 정보가 암호화 없이 저장되어 있다면 즉시 노출됩니다.

    *   **`/databases/`**
        *   **설명:** 앱이 SQLite 데이터베이스를 사용하는 경우, `.db` 파일 형태로 데이터베이스가 저장되는 곳입니다.
        *   **주요 분석 대상:** 사용자 계정 정보, 메시지 내용, 연락처, 앱 사용 기록, 거래 내역 등.
        *   **취약점:** 암호화되지 않은 DB 파일은 직접 접근하여 SQL 쿼리를 통해 모든 데이터를 쉽게 조회할 수 있습니다.

    *   **`/files/`**
        *   **설명:** 앱이 임의의 데이터를 파일 형태로 저장할 때 사용되는 앱 전용 디렉토리입니다.
        *   **주요 분석 대상:** 로그 파일, 다운로드된 문서, 내부 캐시 데이터, 백업 파일, 설정 파일.

    *   **`/cache/`**
        *   **설명:** 앱이 임시 데이터를 저장하는 곳으로, 앱 종료 시 또는 시스템에 의해 삭제될 수 있습니다.

    *   **`/lib/`**
        *   **설명:** 앱이 사용하는 네이티브 라이브러리(`.so`)가 저장되는 곳입니다.

2.  **`AndroidManifest.xml` 분석의 중요성**

    앱의 구성 요소, 권한, 보안 설정 등 모든 중요한 메타데이터가 정의되어 있는 **청사진(blueprint)**입니다.

    *   **유의하여 살펴볼 설정들:**
        *   **`android:debuggable="true"`:** 디버거를 연결하여 런타임 상태를 조작하거나 메모리를 덤프할 수 있는 심각한 취약점입니다.
        *   **`android:allowBackup="true"`:** `adb backup` 명령을 통해 루팅 없이도 앱의 데이터를 백업할 수 있게 합니다.
        *   **`android:exported="true"`:** 다른 앱이 해당 컴포넌트를 실행할 수 있게 되어 인텐트 리다이렉션 등의 위험이 있습니다.
        *   **`uses-permission`:** 앱이 요청하는 과도하거나 위험한 권한 목록을 확인합니다.

3.  **Android 핵심 애플리케이션 컴포넌트**

    보안 관점에서 각 컴포넌트는 고유한 공격 표면(Attack Surface)을 형성하며, 세밀한 감사가 필요합니다.

    *   **Activities (액티비티)**
        *   **설명:** 사용자가 앱과 상호작용하는 화면(UI)을 나타냅니다.
        *   **보안 위험:** 비인가 액티비티 실행, 인텐트 데이터 유출, 태스크 하이재킹(StrandHogg).
        *   **펜테스팅:** `AndroidManifest.xml`에서 export 여부 확인 후 `adb shell am start`로 직접 실행 테스트.

    *   **Broadcast Receivers (브로드캐스트 리시버)**
        *   **설명:** 시스템 또는 앱 공지에 응답하는 UI 없는 컴포넌트입니다.
        *   **보안 위험:** 인텐트 인젝션, 브로드캐스트 내 민감 데이터 노출.
        *   **펜테스팅:** `adb shell am broadcast`를 통해 조작된 인텐트 전송 테스트.

    *   **Services (서비스)**
        *   **설명:** 백그라운드에서 장시간 실행되는 작업(음악 재생, 네트워크 등)을 수행합니다.
        *   **보안 위험:** 비인가 서비스 바인딩, AIDL을 통한 원격 코드 실행(RCE).
        *   **펜테스팅:** `adb shell am startservice` 및 Jadx를 이용한 IPC 메서드 소스 분석.

    *   **Content Providers (콘텐츠 프로바이더)**
        *   **설명:** 앱 데이터에 대한 공유 접근을 관리하는 인터페이스입니다.
        *   **보안 위험:** SQL 인젝션, 경로 탐색(Path Traversal), 비인가 데이터 접근.
        *   **펜테스팅:** `adb shell content query` 및 Drozer를 이용한 취약점 스캔.

4.  **KeyStore (보안 저장소)**

    *   **설명:** 암호화 키 및 자격 증명을 안전하게 관리하는 Android OS 서비스입니다.
    *   **주요 분석 대상:** 직접 읽기는 불가능하므로, **정적 분석**으로 사용 방식을 파악하고 **런타임 분석**으로 메모리 내 복호화 시점을 포착합니다.


### **iOS 앱의 주요 폴더 및 파일 해부학**

iOS 앱은 각 앱이 엄격한 샌드박스(Sandbox) 내에서 실행됩니다.

1.  **`/private/var/mobile/Containers/Data/Application/<UUID>/`**

    *   **설명:** 탈옥된 iOS 기기에서 앱의 샌드박스 데이터 컨테이너에 접근하는 정확한 루트 경로입니다.
    *   **접근 방법:** 탈옥 기기에서 `ssh` 또는 파일 관리자(Filza)를 통해 접근할 수 있습니다.

    *   **`/Documents/`**
        *   **설명:** 사용자 문서, 사진, 동영상, 데이터베이스 파일 등이 저장되는 곳입니다.
    *   **`/Library/Preferences/` (Plist 분석)**
        *   **설명:** `UserDefaults`를 통해 관리되는 `.plist` 파일이 저장되며, 로그인 토큰 및 설정 정보를 담고 있습니다.
    *   **`/Library/WebKit/`**
        *   **설명:** `WKWebView` 관련 쿠키, 로컬 스토리지, 세션 스토리지 데이터가 저장됩니다.

2.  **Keychain (iOS 보안 저장소)**

    *   **설명:** 비밀번호, 인증서, 암호화 키 등을 안전하게 관리하는 하드웨어 암호화 기반 서비스입니다.
    *   **분석 방법:** `objection ios keychain dump`와 같은 런타임 분석 도구를 사용하여 정보를 추출합니다.


### **정적/동적 분석: 실전 툴 활용 심화**

#### **1. Android 앱: 실행 중인 데이터 확인 및 추출**

*   **`android_application_analyzer` (NotSoSecure)**: 샌드박스 내 저장된 정보들을 확인하는 **정적 검사** 툴입니다.
*   **Objection (동적 분석의 핵심)**: `Frida` 기반으로 실행 중인 앱의 데이터를 실시간으로 조회하고 추출합니다.

```bash
# 앱 프로세스 연결
objection -g <com.your.package.name> explore

# 데이터 디렉토리 탐색 및 파일 추출
android data explore
ls
cd cache
download cached_sensitive_data.json

# SharedPreferences 확인
android sharedprefs get all

# SQLite DB 확인
android sqlite list
android sqlite open myapp.db
tables
select * from users;
```

#### **2. iOS 앱: 실행 중인 데이터 확인 및 추출**

*   **MobSF (정적 분석)**: iOS IPA 파일을 분석하여 `Info.plist` 및 하드코딩된 문자열을 자동으로 탐지합니다.
*   **Objection (동적 분석의 핵심)**: 탈옥 기기에서 실행 중인 iOS 앱의 데이터를 실시간으로 확인합니다.

```bash
# 앱 프로세스 연결
objection -g <com.your.bundle.id> explore

# 데이터 탐색 및 파일 추출
ios data explore
ls
cd Documents
download sensitive_document.pdf

# UserDefaults (Plist) 확인
ios nsuserdefaults get all

# SQLite DB 확인
ios sqlite list
ios sqlite open myapp.bundle.id.db

# Keychain 덤프
ios keychain dump
```