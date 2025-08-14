---
title: The Anatomy of Mobile App
tags: Android IOS
key: page-anatomy_mobile
categories: [Cybersecurity, Mobile Security]
author: hyoeun
math: true
mathjax_autoNumber: true
---

## The Anatomy of Mobile App and Penetration Testing
### **Common Types of Sensitive Information to Look For**

Regardless of the operating system, the following types of information, if found in an app's local storage, represent potential vulnerabilities:

  * **Authentication Information:** Usernames, passwords (especially if plaintext or weakly hashed), API keys, Client Secrets, authentication tokens (Session, JWT, OAuth), Certificates, Private Keys.
  * **Personally Identifiable Information (PII):** Names, emails, phone numbers, addresses, dates of birth, social security numbers (or equivalents), financial information (account numbers, card numbers, etc.), health information.
  * **App Settings and Configuration Information:** Backend server URLs, API endpoint URLs (exposed regardless of development/staging/production environments), database connection information, hardcoded encryption keys, Salt values.
  * **Cached Sensitive Data:** Sensitive JSON/XML responses fetched from the server, user profile pictures, documents, and other media files, temporary files.
  * **Log Files:** Sensitive information unintentionally included in debug or error logs.

-----

### **Android App: Anatomy of Key Folders and Files**

Android app data is primarily stored within an app-specific isolated sandbox at the path `/data/data/<package_name>/`. `<package_name>` is the app's unique package name (e.g., `com.chase.mobileapp`).

1.  **`/data/data/<package_name>/`**

      * **Description:** This is the default path where all of an app's internal storage data is located.

      * **Access Method:** You can access it on a rooted device using `adb shell` (or `adb pull /data/data/<package_name>/` to extract all data), or via a rooted file explorer.

      * **`/shared_prefs/`**

          * **Description:** This directory stores app preferences and simple key-value pair data in XML file format. It's managed via the `SharedPreferences` API.
          * **Key Analysis Targets:**
              * Login tokens (JWT, OAuth Access Tokens, Refresh Tokens)
              * API keys, authentication information (user IDs, security question answers, etc.)
              * User settings, feature flags (e.g., "Keep me logged in" status)
              * Sensitive server URLs or API endpoints
          * **Vulnerability:** XML files are stored in plaintext, so any sensitive information saved here without encryption is immediately exposed.

      * **`/databases/`**

          * **Description:** If the app uses an SQLite database, this is where the `.db` file is stored.
          * **Key Analysis Targets:**
              * User account information (names, emails, password hashes/plaintext)
              * User-generated data like message content, contacts, call history
              * App usage records, cached sensitive server responses
              * For financial apps, transaction history, account details, etc.
          * **Vulnerability:** Database files are often unencrypted, allowing direct access to query all data. An unencrypted SQLite DB leads to a very severe exposure of sensitive information.

      * **`/files/`**

          * **Description:** An app-specific directory used by the app to store arbitrary data in file format.
          * **Key Analysis Targets:**
              * Log files (potential for sensitive info in debug logs)
              * Downloaded documents, images, media files (especially if containing sensitive content)
              * Internal cache data, backup files
              * Hardcoded credentials or configuration files (e.g., `.json`, `.txt`)
          * **Vulnerability:** Files stored here are often unencrypted, so check file extensions and content for sensitive information.

      * **`/cache/`**

          * **Description:** This is where the app stores temporary data. It may be deleted when the app closes or by the system.
          * **Key Analysis Targets:** Web page caches, image caches, and temporary files may contain sensitive information.

      * **`/lib/`**

          * **Description:** This directory stores native libraries (`.so` files) used by the app.
          * **Key Analysis Targets:** Hardcoded API keys, encryption keys, server URLs, etc., written in native code (C/C++), which can be extracted using tools like `strings`.

2.  **Importance of `AndroidManifest.xml` Analysis**
    The `AndroidManifest.xml` file is like the **blueprint** of an Android app. It defines all critical metadata, including app components, permissions, and security configurations. For a pentester, it's a **starting point for static analysis** and crucial for identifying the app's potential attack surface. (This file can be viewed after decompiling the APK with tools like `Apktool`).

      * **Settings to Pay Attention To:**
          * **`android:debuggable="true"`:** If this flag is set to `true` in a production build, it becomes a severe vulnerability, allowing debuggers to attach to the app process, manipulate runtime state, or dump memory.
          * **`android:allowBackup="true"`:** If `true`, this flag allows `adb backup` command to extract app data without root, increasing the risk of sensitive information exposure.
          * **`android:exported="true"` (Component Export Status):**
              * **`<activity android:exported="true">`:** Indicates if other apps can launch this activity. Misconfiguration can lead to intent redirection or unauthorized access.
              * **`<service android:exported="true">`:** Indicates if other apps can bind to or start this service. Can lead to remote code execution or privilege escalation.
              * **`<receiver android:exported="true">`:** Indicates if other apps can send broadcasts to this receiver. Poses risks like intent injection.
              * **`<provider android:exported="true">`:** Indicates if other apps can access data through this content provider. Misconfiguration can lead to sensitive data leakage.
          * **`uses-permission`:** The list of permissions requested by the app. Check for excessive permissions (e.g., `READ_CALL_LOGS`, `SEND_SMS`) or dangerous permissions (e.g., `SYSTEM_ALERT_WINDOW`, `BIND_ACCESSIBILITY_SERVICE`) to identify potential misuse.
          * **`android:testOnly="true"`:** A flag indicating a test build of the app. Its presence in a production build can be a security concern.
          * **Network Security Configuration:** Defined in the `network-security-config` file, specifying TLS settings and whether cleartext traffic is allowed. Check for settings that permit unencrypted traffic.

3.  **KeyStore (Hardware/Software-based Secure Storage)**

      * **Description:** An API and service within the Android OS for securely storing and managing cryptographic keys and credentials. It's designed to be highly secure, potentially leveraging hardware security modules (TEE, StrongBox).
      * **Key Analysis Targets:** It's almost impossible to directly read KeyStore content from the file system. Instead, analyze **how the app's code uses KeyStore (static analysis)** to deduce what sensitive information might be stored there. Then, attempt **runtime analysis (Frida/Objection)** to intercept data as it's brought from KeyStore into memory and decrypted.

-----

### **iOS App: Anatomy of Key Folders and Files**

iOS app data runs within a strict Sandbox. App data is stored in app-specific directories with unique UUIDs (Universally Unique Identifiers).

1.  **`/private/var/mobile/Containers/Data/Application/<UUID>/`**

      * **Correct Path:** Yes, this is the **accurate root path for accessing an app's sandbox data container on a jailbroken iOS device.** `<UUID>` is a unique identifier generated for each app installation.

      * **Access Method:** On a jailbroken device, use `ssh` or a file manager (like Filza). You can also extract unencrypted backup files using tools like `iMazing` for offline analysis.

      * **`/Documents/`**

          * **Description:** Stores important data generated or managed by the user within the app (typically backed up by iCloud).
          * **Key Analysis Targets:** User documents, photos, videos, database files (SQLite `.db` files), app-specific configuration files, backup files.
          * **Vulnerability:** If sensitive information is stored here in plaintext, it's immediately exposed.

      * **`/Library/`**

          * **Description:** Stores various types of app data, including settings, cache files, and support files.
          * **`/Library/Preferences/` (Core of Plist File Analysis)**
              * **Description:** Stores `.plist` files, which hold app settings and simple key-value data, similar to Android's `SharedPreferences`, managed via `UserDefaults`. Plist files can be in XML or binary format.
              * **Key Analysis Targets:**
                  * Login tokens, API keys, authentication information (user IDs, security question answers, etc.)
                  * User settings, feature flags
                  * Sensitive server URLs
              * **Analysis Tools:** Since `.plist` files are often binary, tools to convert them to human-readable XML are crucial.
                  * **`plistutil` (Command-line tool):** Converts binary Plists to XML and vice versa. E.g., `plistutil -i input.plist -o output.xml`.
                  * **Text Editor:** XML Plist files can be opened directly.
                  * **Xcode:** (macOS) Allows visual viewing and editing of Plist files.
              * **Vulnerability:** If sensitive information is stored in `.plist` files without encryption, it's exposed.
          * **`/Library/Caches/`**
              * **Description:** Stores temporary cache data. May be deleted by the system.
              * **Key Analysis Targets:** Web page caches (WKWebView Cache), image/media caches, and temporary files may contain sensitive information.
          * **`/Library/Application Support/`**
              * **Description:** Stores persistent support files, custom databases, and external library data required by the app.
              * **Key Analysis Targets:** Check for sensitive information in SQLite DBs, Realm DBs, or other data file formats.
          * **`/Library/WebKit/`**
              * **Description:** Stores `WKWebView`-related data, including cookies, local storage, and session storage for web content rendered within the app.
              * **Key Analysis Targets:** Check for sensitive information in webview session cookies or webview local storage.

      * **`/tmp/`**

          * **Description:** Stores temporary files needed for very short durations. May be deleted by the system when the app closes.
          * **Key Analysis Targets:** Check if sensitive information is temporarily left here during processing.

2.  **Keychain (iOS Secure Storage)**

      * **Description:** A highly secure service in iOS for storing and managing extremely sensitive credentials like passwords, certificates, and encryption keys. It utilizes hardware-backed encryption.
      * **Key Analysis Targets:** Direct file system access to Keychain content is impossible. During pentesting, **runtime analysis (Frida/Objection)** is used to intercept information as the app retrieves it from Keychain and uses it in memory. Tools like **`objection ios keychain dump`** can extract Keychain items. MobSF can also analyze app code to identify how Keychain is used and spot potential misuse.

-----

### **Static/Dynamic Analysis: Advanced Tooling for Data Extraction and Real-time Verification**

While the tools mentioned above help in file system exploration, modern penetration testing heavily relies on combining static and dynamic analysis with specialized tools for efficient data extraction and real-time verification.

#### **1. Android Apps: Live Data Inspection and Extraction**

For Android apps, while `AndroidManifest.xml` analysis is key for static analysis, dynamic analysis is crucial to verify how data is actually stored and used during runtime.

  * **`android_application_analyzer` (NotSoSecure) - For Static Reconnaissance**
    As previously discussed, `NotSoSecure/android_application_analyzer` is a tool specifically for **static analysis** of APK files. It helps pentesters gain initial insights by analyzing the `AndroidManifest.xml` and identifying hardcoded strings. This reconnaissance is vital for guiding your dynamic analysis efforts, indicating where sensitive data might be stored or processed.

  * **Objection for Real-time (Runtime) Data Inspection and Extraction (Dynamic Analysis Core)**
    `Objection`, built on `Frida`, is the most powerful and modern tool for inspecting and extracting data stored locally in real-time while the app is running on a rooted Android device.

    1.  **Attach to App Process:**

        ```bash
        # Attach to a running app using its package name
        objection -g <com.your.package.name> explore
        ```

        This command connects Objection to the `com.your.package.name` app process.

    2.  **Explore App Data Directory and Extract Files:**
        You can explore the app's sandbox internal directories in real-time and download necessary files to your local machine.

        ```bash
        # Start exploring app data directory
        android data explore

        # List files and folders in the current directory
        ls

        # Change to a specific directory (e.g., cache folder)
        cd cache

        # List files within the cache folder
        ls

        # Download a specific file (e.g., cached_sensitive_data.json)
        download cached_sensitive_data.json
        ```

        These commands are useful for observing and retrieving files as they are created or modified during app execution.

    3.  **Inspect SharedPreferences Content:**
        Query the content of `SharedPreferences` in real-time.

        ```bash
        # Get all key-value pairs from all SharedPreferences files
        android sharedprefs get all

        # Get all key-value pairs from a specific SharedPreferences file (e.g., com.your.package.name.settings)
        android sharedprefs get com.your.package.name.settings
        ```

    4.  **Inspect SQLite Database Content:**
        Open and query SQLite database files used by the app in real-time.

        ```bash
        # List all database files used by the app
        android sqlite list

        # Open a specific database file (e.g., myapp.db)
        android sqlite open myapp.db

        # List all tables in the opened database
        tables

        # Query all data from a specific table (e.g., users table)
        select * from users;
        ```

    5.  **Search for Hardcoded Strings at Runtime (Auxiliary):**
        Search for dynamically loaded or obfuscated strings in memory that might be hard to find via static analysis.

        ```bash
        android hooking search classes "password" # Search for 'password' in class names
        android hooking search methods "secret" # Search for 'secret' in method names
        memory search "API_KEY" # Search for 'API_KEY' string in app memory
        ```

#### **2. iOS Apps: Live Data Inspection and Extraction**

Similar to Android, iOS app analysis involves static analysis (IPA file analysis) followed by dynamic analysis (attaching to the running app) to inspect and extract sensitive data. Objection is also extremely powerful in the iOS environment.

  * **MobSF for Static Analysis (iOS IPA Files)**
    As with Android, MobSF is an excellent choice for **static analysis** of iOS IPA files. It automatically parses `Info.plist` and other `.plist` files, detects hardcoded strings and URLs, and identifies insecure API usage. This stage is crucial for understanding the app's structure and potential vulnerabilities before proceeding to dynamic analysis.

  * **Objection for Real-time (Runtime) Data Inspection and Extraction (Dynamic Analysis Core)**
    On a jailbroken iOS device, `Objection` allows you to inspect and extract sensitive data from a running app in real-time.

    1.  **Attach to App Process:**

        ```bash
        # Attach to a running app using its Bundle ID
        objection -g <com.your.bundle.id> explore
        ```

    2.  **Explore App Data Directory and Extract Files:**
        Explore iOS app's sandbox internal directories and download necessary files to your local machine.

        ```bash
        # Start exploring app data directory
        ios data explore

        # List files and folders in the current directory
        ls

        # Change to a specific directory (e.g., Documents folder)
        cd Documents

        # Download a specific file (e.g., sensitive_document.pdf)
        download sensitive_document.pdf
        ```

    3.  **Inspect UserDefaults (Plist) Content:**
        Query the content of `UserDefaults` (Plist) in real-time.

        ```bash
        # Get all key-value pairs from all UserDefaults domains
        ios nsuserdefaults get all

        # Get all key-value pairs from a specific UserDefaults domain (e.g., com.your.bundle.id)
        ios nsuserdefaults get com.your.bundle.id
        ```

    4.  **Inspect SQLite Database Content:**
        Open and query SQLite database files used by the app in real-time.

        ```bash
        # List all database files used by the app
        ios sqlite list

        # Open a specific database file (e.g., myapp.db)
        ios sqlite open myapp.bundle.id.db

        # List all tables in the opened database
        tables

        # Query all data from a specific table (e.g., messages table)
        select * from messages;
        ```

    5.  **Dump Keychain Content:**
        Dump sensitive credentials (passwords, tokens, etc.) stored in iOS Keychain.

        ```bash
        ios keychain dump
        ```

    6.  **Search for Hardcoded Strings at Runtime (Auxiliary):**
        Similar to Android, search for obfuscated or dynamically loaded strings in memory.

        ```bash
        ios hooking search classes "password"
        ios hooking search methods "secret"
        memory search "API_KEY"
        ```

---

## 모바일 폴더 구조와 펜테스팅
### **공통적으로 찾아야 할 민감 정보 유형**

어떤 운영체제의 앱이든, 다음 유형의 정보들이 앱의 로컬 저장소에 있다면 잠재적인 취약점이 됩니다.

* **인증 정보:** 사용자 이름, 비밀번호 (특히 평문 또는 약하게 해싱된 경우), API 키, 클라이언트 시크릿 (Client Secret), 인증 토큰 (Session, JWT, OAuth), 인증서(Certificates), 개인 키(Private Keys)
* **개인 식별 정보 (PII):** 이름, 이메일, 전화번호, 주소, 생년월일, 주민등록번호, 금융 정보 (계좌 번호, 카드 번호 등), 건강 정보
* **앱 설정 및 구성 정보:** 백엔드 서버 URL, API 엔드포인트 URL (개발/스테이징/운영 환경 구분 없이 노출), 데이터베이스 연결 정보, 하드코딩된 암호화 키, 솔트(Salt) 값
* **캐시된 민감 데이터:** 서버에서 가져온 민감한 JSON/XML 응답, 사용자 프로필 사진, 문서 등 미디어 파일, 임시 파일
* **로그 파일:** 디버그 또는 에러 로그에 민감 정보가 의도치 않게 포함된 경우

---

### **Android 앱의 주요 폴더 및 파일 해부학**

Android 앱의 데이터는 주로 `/data/data/<package_name>/` 경로 아래에 앱별로 격리된 샌드박스 내에 저장됩니다. `<package_name>`은 앱의 고유 패키지 이름(예: `com.chase.mobileapp`)입니다.

1.  **`/data/data/<package_name>/`**
    * **설명:** 해당 앱의 모든 내부 저장소 데이터가 위치하는 기본 경로입니다.
    * **접근 방법:** 루팅된 기기에서 `adb shell` (혹은 `adb pull /data/data/<package_name>/`로 전체 데이터 추출) 명령어를 사용하거나, 루팅된 파일 탐색기를 통해 접근할 수 있습니다.

    * **`/shared_prefs/`**
        * **설명:** 앱의 환경 설정 및 간단한 키-값(key-value) 쌍의 데이터를 XML 파일 형태로 저장하는 곳입니다. `SharedPreferences` API를 통해 관리됩니다.
        * **주요 분석 대상:**
            * 로그인 토큰 (JWT, OAuth Access Token, Refresh Token)
            * API 키, 인증 정보 (사용자 ID, 보안 질문 답변 등)
            * 사용자 설정, 기능 플래그 (예: "로그인 유지" 여부)
            * 민감한 서버 URL 또는 API 엔드포인트
        * **취약점:** XML 파일은 평문(plaintext)으로 저장되므로, 여기에 민감 정보가 암호화 없이 저장되어 있다면 즉시 노출됩니다.

    * **`/databases/`**
        * **설명:** 앱이 SQLite 데이터베이스를 사용하는 경우, `.db` 파일 형태로 데이터베이스가 저장되는 곳입니다.
        * **주요 분석 대상:**
            * 사용자 계정 정보 (이름, 이메일, 비밀번호 해시/평문)
            * 메시지 내용, 연락처, 통화 기록 등 사용자 생성 데이터
            * 앱 사용 기록, 캐시된 민감한 서버 응답
            * 금융 앱의 경우, 거래 내역, 계좌 정보 등
        * **취약점:** 데이터베이스 파일은 암호화되지 않은 경우가 많으므로, 파일에 직접 접근하여 SQL 쿼리를 통해 모든 데이터를 쉽게 조회할 수 있습니다. 암호화되지 않은 SQLite DB는 매우 심각한 민감 정보 노출로 이어집니다.

    * **`/files/`**
        * **설명:** 앱이 임의의 데이터를 파일 형태로 저장할 때 사용되는 앱 전용 디렉토리입니다.
        * **주요 분석 대상:**
            * 로그 파일 (디버그 로그에 민감 정보 포함 가능성)
            * 다운로드된 문서, 이미지, 미디어 파일 (특히 민감한 내용 포함 시)
            * 내부 캐시 데이터, 백업 파일
            * 하드코딩된 자격 증명이나 설정 파일 (`.json`, `.txt` 등)
        * **취약점:** 여기에 저장된 파일들도 암호화되지 않은 경우가 많으므로, 파일 확장자와 내용을 확인하여 민감 정보가 있는지 탐지합니다.

    * **`/cache/`**
        * **설명:** 앱이 임시 데이터를 저장하는 곳입니다. 앱 종료 시 또는 시스템에 의해 삭제될 수 있습니다.
        * **주요 분석 대상:** 웹 페이지 캐시, 이미지 캐시, 임시 파일 등에 민감한 정보가 남겨질 수 있습니다.

    * **`/lib/`**
        * **설명:** 앱이 사용하는 네이티브 라이브러리(`.so` 파일)가 저장되는 곳입니다.
        * **주요 분석 대상:** C/C++ 등으로 작성된 네이티브 코드 안에 하드코딩된 API 키, 암호화 키, 서버 URL 등을 `strings` 명령어 등으로 찾아낼 수 있습니다.

2.  **`AndroidManifest.xml` 분석의 중요성**
    `AndroidManifest.xml` 파일은 Android 앱의 **청사진(blueprint)**과 같습니다. 앱의 구성 요소, 권한, 보안 설정 등 모든 중요한 메타데이터가 정의되어 있습니다. 펜테스터에게는 **정적 분석의 출발점**이자, 앱의 잠재적 공격 표면을 파악하는 데 필수적인 파일입니다. (이 파일은 APK를 `Apktool` 등으로 디컴파일하면 확인할 수 있습니다.)

    * **유의하여 살펴볼 설정들:**
        * **`android:debuggable="true"`:** 프로덕션 빌드에서 이 플래그가 `true`로 설정되어 있다면, 디버거를 앱 프로세스에 연결하여 런타임 상태를 조작하거나 메모리를 덤프하는 것이 가능해져 매우 심각한 취약점이 됩니다.
        * **`android:allowBackup="true"`:** 이 플래그가 `true`이면, `adb backup` 명령을 통해 루팅 없이도 앱의 데이터를 백업하고 분석할 수 있게 되어 민감 정보 노출 위험이 증가합니다.
        * **`android:exported="true"` (컴포넌트 Export 여부):**
            * **`<activity android:exported="true">`:** 다른 앱이 해당 액티비티를 실행할 수 있는지 여부를 나타냅니다. 잘못 설정되면 인텐트(Intent) 리다이렉션, 권한 없는 접근으로 이어질 수 있습니다.
            * **`<service android:exported="true">`:** 다른 앱이 해당 서비스를 바인딩하거나 시작할 수 있는지 나타냅니다. 원격 코드 실행이나 권한 상승으로 이어질 수 있습니다.
            * **`<receiver android:exported="true">`:** 다른 앱이 특정 브로드캐스트를 보낼 때 해당 리시버가 받을 수 있는지 나타냅니다. 인텐트 인젝션 등의 위험이 있습니다.
            * **`<provider android:exported="true">`:** 다른 앱이 해당 콘텐츠 프로바이더를 통해 데이터에 접근할 수 있는지 나타냅니다. 잘못 설정되면 민감한 데이터 유출로 이어집니다.
        * **`uses-permission`:** 앱이 요청하는 권한 목록입니다. 과도한 권한(예: `READ_CALL_LOGS`, `SEND_SMS`)을 요청하는지, 또는 위험한 권한(예: `SYSTEM_ALERT_WINDOW`, `BIND_ACCESSIBILITY_SERVICE`)을 요청하는지 확인하여 잠재적인 악용 가능성을 파악합니다.
        * **`android:testOnly="true"`:** 앱이 테스트 빌드임을 나타내는 플래그로, 프로덕션 빌드에서 발견되면 보안 문제가 될 수 있습니다.
        * **Network Security Configuration:** `network-security-config` 파일을 통해 TLS 설정, 사용자 인증서 허용 여부 등을 정의할 수 있습니다. 클리어텍스트(평문) 트래픽을 허용하는 설정이 있는지 확인합니다.

3.  **KeyStore (하드웨어/소프트웨어 기반 보안 저장소)**
    * **설명:** Android OS에서 암호화 키, 자격 증명 등을 안전하게 저장하고 관리하기 위한 API 및 서비스입니다. 하드웨어 기반의 보안 요소(TEE, StrongBox)를 활용할 수 있어 매우 안전하게 설계되었습니다.
    * **주요 분석 대상:** KeyStore 자체의 내용을 파일 시스템에서 직접 읽어내는 것은 거의 불가능합니다. 대신, **앱 코드가 KeyStore를 어떻게 사용하는지(정적 분석)**를 통해 어떤 민감 정보가 KeyStore에 저장되어 있는지 추정하고, **런타임 분석(Frida/Objection)**을 통해 앱이 KeyStore에서 데이터를 가져와 메모리에서 복호화하는 시점을 포착하여 정보를 덤프하려 시도합니다.

---

### **iOS 앱의 주요 폴더 및 파일 해부학**

iOS 앱은 각 앱이 엄격한 샌드박스(Sandbox) 내에서 실행됩니다. 앱의 데이터는 고유한 UUID(Universally Unique Identifier)를 가진 앱별 디렉토리 아래에 저장됩니다.

1.  **`/private/var/mobile/Containers/Data/Application/<UUID>/`**
    * **정확한 경로:** 네, 이 경로가 **탈옥된 iOS 기기에서 앱의 샌드박스 데이터 컨테이너에 접근하는 정확한 루트 경로**입니다. `<UUID>`는 앱 설치마다 달라지는 고유한 식별자입니다.
    * **접근 방법:** 탈옥된 기기에서 `ssh` 또는 파일 관리자(Filza)를 통해 접근할 수 있습니다. `iMazing`과 같은 도구를 사용한 암호화되지 않은 백업 파일을 추출하여 오프라인 분석을 수행할 수도 있습니다.

    * **`/Documents/`**
        * **설명:** 사용자가 생성하거나 앱 내에서 관리하는 중요한 데이터를 저장하는 곳입니다 (기본적으로 iCloud 백업 대상).
        * **주요 분석 대상:** 사용자 문서, 사진, 동영상 등 미디어 파일, 데이터베이스 파일 (SQLite `.db` 파일), 앱별 설정 파일, 백업 파일.
        * **취약점:** 여기에 평문으로 민감 정보가 저장되어 있다면 즉시 노출됩니다.

    * **`/Library/`**
        * **설명:** 앱의 설정 파일, 캐시 파일, 지원 파일 등 다양한 유형의 데이터를 저장하는 곳입니다.
        * **`/Library/Preferences/` (Plist 파일 분석의 핵심)**
            * **설명:** `UserDefaults`(Android의 SharedPreferences와 유사)를 통해 앱의 설정 및 간단한 키-값 데이터를 저장하는 **`.plist` 파일**이 위치합니다. Plist 파일은 XML 또는 바이너리 형식입니다.
            * **주요 분석 대상:**
                * 로그인 토큰, API 키, 인증 정보 (사용자 ID, 보안 질문 답변 등)
                * 사용자 설정, 플래그
                * 민감한 서버 URL 등
            * **분석 도구:** `.plist` 파일은 바이너리 형태인 경우가 많으므로, 이를 읽기 쉬운 XML 형식으로 변환하는 도구가 유용합니다.
                * **`plistutil` (명령줄 도구):** 바이너리 Plist를 XML로 변환하거나 그 반대로 변환합니다. `plistutil -i input.plist -o output.xml`
                * **텍스트 편집기:** XML Plist 파일은 일반 텍스트 편집기로도 볼 수 있습니다.
                * **Xcode:** 개발 환경에서 `.plist` 파일을 직접 열어볼 수 있습니다.
            * **취약점:** `.plist` 파일에 민감 정보가 암호화 없이 저장되면 노출됩니다.
        * **`/Library/Caches/`**
            * **설명:** 앱의 임시 캐시 데이터를 저장하는 곳입니다. 시스템에 의해 삭제될 수 있습니다.
            * **주요 분석 대상:** 웹 페이지 캐시(WKWebView Cache), 이미지/미디어 캐시, 임시 파일 등에 민감한 정보가 남겨질 수 있습니다.
        * **`/Library/Application Support/`**
            * **설명:** 앱이 필요로 하는 영구적인 지원 파일, 커스텀 데이터베이스, 외부 라이브러리 데이터 등을 저장합니다.
            * **주요 분석 대상:** SQLite DB, Realm DB 등 다른 형식의 데이터 파일에 민감 정보가 있는지 확인합니다.
        * **`/Library/WebKit/`**
            * **설명:** `WKWebView`를 사용하는 앱의 쿠키, 로컬 스토리지, 세션 스토리지 등 웹뷰 관련 데이터가 저장됩니다.
            * **주요 분석 대상:** 웹뷰를 통해 로그인된 세션 쿠키, 웹뷰 로컬 스토리지에 민감 정보가 있는지 확인합니다.

    * **`/tmp/`**
        * **설명:** 앱이 매우 짧은 기간 동안만 필요한 임시 파일을 저장하는 곳입니다. 앱 종료 시 시스템에 의해 삭제됩니다.
        * **주요 분석 대상:** 민감한 정보가 처리되는 과정에서 일시적으로 여기에 남겨지는지 확인합니다.

2.  **Keychain (iOS 보안 저장소)**
    * **설명:** iOS에서 비밀번호, 인증서, 암호화 키 등 매우 민감한 자격 증명을 안전하게 저장하고 관리하기 위한 서비스입니다. 하드웨어 기반의 강력한 암호화가 적용됩니다.
    * **주요 분석 대상:** Keychain 파일 시스템에 직접 접근하여 내용을 읽어내는 것은 거의 불가능합니다. 펜테스팅 시에는 **런타임 분석(Frida/Objection)**을 통해 앱이 Keychain에서 데이터를 가져와 메모리에서 사용하는 순간을 포착하여 정보를 덤프하거나, **`objection`의 `ios keychain dump`**와 같은 내장 기능을 활용합니다. 또한 **MobSF**와 같은 도구로 앱 코드가 Keychain을 어떻게 사용하는지 분석하여 잠재적 오용을 탐지합니다.

-----

### **정적/동적 분석: 데이터 추출 및 실시간 검증을 위한 툴 활용 심화**
#### **1. Android 앱: 실행 중인 데이터 확인 및 추출**

안드로이드 앱의 경우, `AndroidManifest.xml` 분석을 통해 잠재적 취약점을 파악하는 것이 정적 분석의 핵심이라면, 앱이 실제로 데이터를 어떻게 저장하고 활용하는지 확인하는 것은 동적 분석의 영역입니다.

  * **`android_application_analyzer` (NotSoSecure)**
    `NotSoSecure/android_application_analyzer`는 앱을 이용하는동안 샌드박스 안에 저장된 정보들을 확인해볼 수 있는 툴입니다. 이것으로 정적 검사를 하고 이후 objection을 통해서 실시간으로 검사하고 싶은 기능에 관해 동적 분석을 진행하면 됩니다.

  * **Objection을 이용한 실시간(Runtime) 데이터 확인 및 추출 (동적 분석의 핵심)**
    실제로 앱이 실행 중일 때 로컬에 저장되는 데이터(캐시, SharedPreferences, SQLite DB 등)를 확인하고 추출하는 데는 `Objection`이 가장 강력하고 현대적인 툴입니다. `Frida`를 기반으로 하며 루팅된 Android 기기에서 작동합니다.

    1.  **앱 프로세스 연결:**

        ```bash
        # 앱 실행 후 패키지 이름으로 연결
        objection -g <com.your.package.name> explore
        ```

        이 명령으로 `com.your.package.name` 앱의 프로세스에 Objection이 연결됩니다.

    2.  **앱 데이터 디렉토리 탐색 및 파일 추출:**
        앱의 샌드박스 내부 디렉토리를 실시간으로 탐색하고 필요한 파일을 로컬로 다운로드할 수 있습니다.

        ```bash
        # 앱 데이터 디렉토리 탐색 시작
        android data explore

        # 현재 디렉토리의 파일 및 폴더 목록 확인
        ls

        # 특정 디렉토리로 이동 (예: 캐시 폴더)
        cd cache

        # 캐시 폴더 내의 파일 목록 확인
        ls

        # 특정 파일 다운로드 (예: cached_sensitive_data.json)
        download cached_sensitive_data.json
        ```

        이 명령들은 앱이 실행되는 동안 파일이 생성되거나 변경되는 것을 실시간으로 확인하고 가져오는 데 유용합니다.

    3.  **SharedPreferences 내용 확인:**
        `SharedPreferences`에 저장된 민감 정보를 실시간으로 조회합니다.

        ```bash
        # 모든 SharedPreferences 파일의 모든 키-값 쌍 가져오기
        android sharedprefs get all

        # 특정 SharedPreferences 파일의 모든 키-값 쌍 가져오기 (예: com.your.package.name.settings)
        android sharedprefs get com.your.package.name.settings
        ```

    4.  **SQLite 데이터베이스 내용 확인:**
        앱이 사용하는 SQLite 데이터베이스 파일을 실시간으로 열고 SQL 쿼리를 실행하여 데이터 내용을 탐색합니다.

        ```bash
        # 앱의 모든 DB 파일 목록 확인
        android sqlite list

        # 특정 DB 파일 열기 (예: myapp.db)
        android sqlite open myapp.db

        # 열린 DB의 모든 테이블 목록 확인
        tables

        # 특정 테이블의 모든 데이터 조회 (예: users 테이블)
        select * from users;
        ```

    5.  **하드코딩된 문자열 런타임 검색 (보조):**
        정적 분석에서 찾기 어려운 동적으로 로드되거나 난독화된 문자열을 메모리에서 검색할 수 있습니다.

        ```bash
        android hooking search classes "password" # 클래스 이름에서 'password' 검색
        android hooking search methods "secret" # 메서드 이름에서 'secret' 검색
        memory search "API_KEY" # 앱 메모리에서 'API_KEY' 문자열 검색
        ```

#### **2. iOS 앱: 실행 중인 데이터 확인 및 추출**

iOS 앱의 경우에도 Android와 유사하게, 정적 분석(IPA 파일 분석) 후 동적 분석(실행 중인 앱에 연결)을 통해 민감한 데이터를 확인하고 추출합니다. Objection은 iOS 환경에서도 매우 강력합니다.

  * **MobSF를 이용한 정적 분석 (iOS IPA 파일)**
    안드로이드와 마찬가지로, MobSF는 iOS IPA 파일을 업로드하여 앱의 `Info.plist` 및 다른 `.plist` 파일 분석, 하드코딩된 문자열 탐지, URL 추출, 취약한 API 사용 검출 등 **정적 분석**을 자동으로 수행합니다. 이는 동적 분석을 시작하기 전에 앱의 구조와 잠재적 취약점을 파악하는 데 필수적입니다.

  * **Objection을 이용한 실시간(Runtime) 데이터 확인 및 추출 (동적 분석의 핵심)**
    탈옥된 iOS 기기에서 `Objection`을 사용하여 실행 중인 앱의 데이터를 실시간으로 확인하고 추출할 수 있습니다.

    1.  **앱 프로세스 연결:**

        ```bash
        # 앱 실행 후 패키지 이름 (Bundle ID)으로 연결
        objection -g <com.your.bundle.id> explore
        ```

    2.  **앱 데이터 디렉토리 탐색 및 파일 추출:**
        iOS 앱의 샌드박스 내부 디렉토리를 탐색하고 필요한 파일을 로컬로 다운로드합니다.

        ```bash
        # 앱 데이터 디렉토리 탐색 시작
        ios data explore

        # 현재 디렉토리의 파일 및 폴더 목록 확인
        ls

        # 특정 디렉토리로 이동 (예: Documents 폴더)
        cd Documents

        # 특정 파일 다운로드 (예: sensitive_document.pdf)
        download sensitive_document.pdf
        ```

    3.  **UserDefaults (Plist) 내용 확인:**
        `UserDefaults`(Plist)에 저장된 민감 정보를 실시간으로 조회합니다.

        ```bash
        # 모든 UserDefaults 도메인의 모든 키-값 쌍 가져오기
        ios nsuserdefaults get all

        # 특정 UserDefaults 도메인의 모든 키-값 쌍 가져오기 (예: com.your.bundle.id)
        ios nsuserdefaults get com.your.bundle.id
        ```

    4.  **SQLite 데이터베이스 내용 확인:**
        앱이 사용하는 SQLite 데이터베이스 파일을 실시간으로 열고 SQL 쿼리를 실행합니다.

        ```bash
        # 앱의 모든 DB 파일 목록 확인
        ios sqlite list

        # 특정 DB 파일 열기 (예: myapp.db)
        ios sqlite open myapp.bundle.id.db

        # 열린 DB의 모든 테이블 목록 확인
        tables

        # 특정 테이블의 모든 데이터 조회 (예: messages 테이블)
        select * from messages;
        ```

    5.  **Keychain 내용 덤프:**
        iOS의 Keychain에 저장된 민감한 자격 증명(비밀번호, 토큰 등)을 덤프합니다.

        ```bash
        ios keychain dump
        ```

    6.  **하드코딩된 문자열 런타임 검색 (보조):**
        안드로이드와 유사하게, 난독화된 코드나 동적으로 로드되는 문자열을 메모리에서 검색할 수 있습니다.

        ```bash
        ios hooking search classes "password"
        ios hooking search methods "secret"
        memory search "API_KEY"
        ```