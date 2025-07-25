---
title: Bypassing the Client-Side Authentication Mechanism
tags: Client-Side-Authentication
key: page-client_side_auth
categories: [Cybersecurity, Mobile Security]
author: hyoeun
math: true
mathjax_autoNumber: true
---

## Mobile App Penetration Testing: The Anatomy of Local Data Storage & Runtime Extraction on Android & iOS

Mobile apps provide convenience to users, but they also store and process a significant amount of sensitive information. One of the core goals of penetration testing is to **verify whether this sensitive information is securely stored on the client side (user's device).** Attackers can access an app's file system, uncover unencrypted or inadequately protected data, and cause severe security breaches.

In this blog post, we will delve deeply into the key folders and files to pay attention to when penetration testing Android and iOS mobile apps, the types of sensitive information that can be found within them, and the useful tools for analyzing this data.

**Disclaimer:** To access the folders and files described below, a **rooted (Android) or jailbroken (iOS) mobile device** is generally required. This is necessary to bypass the app's sandbox restrictions and access protected app data areas that are not otherwise exposed by developer tools. Actual penetration testing is performed in such specialized environments.

-----

### **Common Types of Sensitive Information to Look For**

Regardless of the operating system an app runs on, the following types of information, if found in an app's local storage, represent potential vulnerabilities:

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

      * **Description:** iOS's secure storage for highly sensitive credentials like passwords, certificates, and encryption keys. It uses hardware-backed encryption.
      * **Key Analysis Targets:** It's almost impossible to directly read Keychain content from the file system. Instead, **runtime analysis (Frida/Objection)** is used to intercept information as the app retrieves it from Keychain and uses it in memory. Tools like **`objection ios keychain dump`** can extract Keychain items. MobSF can also analyze app code to identify how Keychain is used and spot potential misuse.

-----

### **Client-Side Authentication Bypass and Server-Side Impact Testing: PIN, Biometrics, and Other Methods**

Client-side authentication (PINs, biometrics, patterns, etc.) enhances user convenience and local device/app security. However, from a pentester's perspective, all client-side authentication mechanisms can become **potential vulnerabilities that bypass or weaken server-side authentication.** Therefore, thorough bypass testing is essential.

**Core Principle:** It is **presumed that all client-side verification can be bypassed.** The goal is then to **verify that the server-side authentication and authorization logic remains robust.** Client-side authentication is merely the **first layer of local security**; ultimate authentication/authorization must always occur on the server.

#### **I. Bypassing the Client-Side Authentication Mechanism Itself**

This stage aims to understand how the app performs local user verification and then to trick or skip that logic. **For PIN authentication, more software-based bypasses and storage-related vulnerabilities can occur compared to biometrics.**

1.  **Biometrics (Fingerprint, Face ID)**

      * **Description:** Authentication using a user's unique biological information like fingerprints or facial features.
      * **Testing Methods:**
          * **Runtime Hooking (Frida / Objection):**
              * Hook the success/failure callback functions of OS-provided biometric APIs (Android `BiometricPrompt`, iOS `LAContext`) to force a "successful authentication" return regardless of the actual biometric verification result. This involves intercepting the app's biometric method calls and manipulating their return values.
              * **Objection Command Examples:**
                ```bash
                # Android: Watch methods of BiometricPrompt.AuthenticationCallback class to understand flow
                objection explore -j 'android hooking watch class_methods androidx.biometric.BiometricPrompt.AuthenticationCallback --dump-args --dump-backtrace --dump-return'
                # (Actual 'force success' hooking requires a custom Frida script to replace the callback logic)
                ```
                ```bash
                # iOS: Watch evaluatePolicy method of LAContext class
                objection explore -j 'ios hooking watch method "-[LAContext evaluatePolicy:localizedReason:reply:]" --dump-args --dump-backtrace --dump-return'
                # (Actual 'force success' hooking requires a Frida script to manipulate the reply block)
                ```
          * **Emulator/Simulator Spoofing:**
              * Use virtual biometric features provided by Android Emulator or iOS Simulator (virtual fingerprints, virtual Face ID) to pass the app's biometric authentication flow. This is more of a controlled test than a bypass technique.

2.  **PIN Authentication**

      * **Description:** Authentication where the user enters a numerical Personal Identification Number (PIN) to unlock the app.
      * **Testing Methods:**
          * **Runtime Hooking (Frida / Objection):**
              * Reverse engineer the app's binary (decompiled code) to identify methods responsible for PIN input processing, PIN hashing, and comparison with the stored PIN (or hash).
              * Use `Frida` or `Objection` to hook these methods and either bypass the input PIN value or skip the verification logic entirely to force an "authentication success" return.
          * **Client-Side PIN Storage Analysis & Local Brute-Force:**
              * **Filesystem Exploration:** Explore app data directories (Android `/data/data/<package_name>/shared_prefs`, `/databases`, iOS `/Library/Preferences` for `.plist` files, `/Documents/`, etc.) to check if the PIN or its hash/encrypted value is stored in plaintext or in an easily decryptable format.
              * **Hash Algorithm Analysis:** If the PIN is stored as a hash, verify if the hashing algorithm (e.g., MD5, SHA1) is secure, if salt is used, and if the iteration count is sufficient (for algorithms like PBKDF2, bcrypt, Argon2). Weak hashing algorithms and lack of salt make it vulnerable to rainbow table attacks or offline brute-force attacks.
              * **Local Brute-Force:** Test if the app limits the number of local PIN entry attempts or implements measures like app locking or data deletion after a certain number of failed attempts. If not, a short PIN length (e.g., 4-digit numeric PIN) can be brute-forced without limitation.

3.  **Pattern Lock (Primarily Android)**

      * **Description:** An authentication method where the user draws a specific pattern by connecting dots to unlock the app.
      * **Testing Methods:**
          * **Storage Analysis:** Analyze how the pattern data (e.g., sequence of dots) is stored locally. It should be hashed or encrypted.
          * **Local Brute-Force:** Similar to PIN, test for lack of pattern entry attempt limits or if the pattern hash is weak enough for offline cracking.
          * **Visual Exposure:** Check if the app is vulnerable to screen residue or screen recording that could reveal the pattern.

4.  **App-Specific Local Password**

      * **Description:** A separate local password set within a specific app, distinct from the device's lock password or the user's online service password.
      * **Testing Methods:** Similar to PIN, test the local storage method (plaintext, weak hash), local brute-force defenses, and the security of any password recovery logic.

5.  **Passkeys / FIDO (Fast IDentity Online)**

      * **Description:** A modern authentication standard aiming to replace passwords, where the user's device (authenticator) manages public-key cryptography-based credentials (Passkeys). The user unlocks this passkey locally using biometrics or a PIN to complete authentication with the server.
      * **Testing Methods:**
          * **Underlying Authentication Bypass:** Attempt to bypass the fundamental unlock method of the passkey (biometrics or PIN) as described in sections A and B above. If successful, test if the passkey itself can be manipulated.
          * **Protocol Misuse:** Verify that the app/server correctly implements FIDO protocols and does not fall back to less secure alternative authentication methods if passkey authentication fails.
          * **Registration/Deletion Flaws:** Test the security of passkey registration and deletion flows (e.g., unauthorized passkey registration, deletion of another user's passkey).

6.  **Hardware Security Keys (Physical Security Keys - e.g., YubiKey)**

      * **Description:** A physical security key connected to the mobile device to perform local user authentication, typically as a multi-factor authentication method.
      * **Testing Methods:**
          * **Physical Bypass:** Test if the app can be tricked into believing the key is present without it physically being there (e.g., if it only checks for key presence, not proper signature verification).
          * **Software Emulation:** Test if the key's response can be emulated at runtime to deceive the app.
          * **Fallback Mechanisms:** If the hardware key is unavailable or unrecognized, check if the app provides a secure fallback authentication method.
          * **API Call Hooking:** Hook API calls where the key signs data sent to the server. Test if this signed data can be manipulated or is vulnerable to replay attacks.

#### **II. Testing Server-Side Impact & Trust Boundaries**

This crucial stage verifies **how robust the server-side authentication and authorization logic is** when client-side authentication (biometrics, PIN, or any other method) has been bypassed or successfully passed. **No client-side authentication success signal should be blindly trusted by the server.**

1.  **API Call Analysis & Replay Attack - Critical Verification\!**

      * **Objective:** Identify API calls made by the app to the server immediately after successful client-side authentication, and attempt to manipulate or replay these requests to find server-side vulnerabilities.
      * **Method:**
        1.  Use a web proxy tool like `Burp Suite` or `OWASP ZAP` to intercept all network traffic from the mobile app.
        2.  After successfully passing client-side authentication, meticulously analyze all API calls the app sends to the server.
        3.  **Suspicious Parameters:** Check if the request body or headers contain simple flags like "biometric\_success=true" or "pin\_verified" indicating client-side authentication success. It's a risk if the server makes critical decisions based solely on such flags.
        4.  **Replay Attack:** Manipulate the intercepted API request using `Burp Suite Repeater` (or similar tools) and then replay it to the server.
              * **Key Question:** Does the server accept this replayed request and perform sensitive operations (e.g., fund transfers, password changes, profile modifications, privilege escalation) **even if the app has been restarted, logged out, or on a different device?**
              * **Vulnerability:** If the server blindly trusts the 'authentication success' signal from the client and proceeds with operations without sufficient server-side authentication/authorization (e.g., verifying a valid session token, preventing token reuse, re-authenticating privileges, or re-verifying a master password), it indicates a severe vulnerability.

2.  **Session/Token Management & Step-up Authentication Bypass Testing:**

      * **Objective:** Evaluate how client-side authentication success affects server-side session validity, token expiry, and permissions.
      * **Method:**
          * **Session Refresh/Extension:** After successful client-side authentication, check if the server issues a new session token with an extended validity period. Test if this new token can be stolen and used to access the session from an old or unauthorized context.
          * **Step-up Authentication Bypass:** For highly sensitive operations (e.g., financial transactions), multi-factor or step-up authentication (e.g., re-entering password, OTP) is typically required. Test if a client-side authentication bypass allows the server to skip this crucial "step-up authentication" stage and authorize the operation.

3.  **Data Disclosure & Privilege Escalation Testing:**

      * **Objective:** Determine if bypassing client-side authentication leads to the exposure of locally stored sensitive but unencrypted data, or if it results in server-side privilege escalation.
      * **Method:** After bypassing client-side authentication, explore the local file system (Android `/data/data`, iOS `/private/var/mobile/Containers/Data/Application`) and analyze databases (SQLite, Plist) to check for newly unlocked or exposed sensitive information. Additionally, attempt to access higher-privileged server functions or data belonging to other users.

-----

**Conclusion:**

Client-side authentication is valuable for user convenience and enhancing local device security. However, pentesters must understand it as a feature within the **"convenience" and "local locking" domain**, and **never as a replacement for robust server-side authentication.** The server must validate every critical operation with independent and strong authentication and authorization logic, never blindly trusting signals from the client.

-----

### **클라이언트 측 인증 우회 및 서버 측 영향 테스트: PIN, 생체 인식 및 기타 방법들**

모바일 앱의 클라이언트 측 인증(PIN, 생체 인식, 패턴 등)은 사용자의 편의성을 높이고 기기/앱의 로컬 보안을 강화하는 데 기여합니다. 그러나 펜테스터의 관점에서는 이러한 모든 클라이언트 측 인증이 **서버 측 인증을 우회하거나 약화시키는 잠재적 취약점**이 될 수 있으므로, 철저한 우회 테스트가 필요합니다.

**핵심 원칙:** **"클라이언트 측의 모든 검증은 우회될 수 있다"**는 것을 전제하고, **"서버 측의 인증 및 인가(Authorization) 로직이 여전히 견고한지"**를 검증하는 것입니다. 클라이언트 측 인증은 **로컬 보안의 첫 번째 계층**일 뿐, 궁극적인 인증/인가는 항상 서버에서 이루어져야 합니다.

#### **I. 클라이언트 측 인증 메커니즘 자체 우회 (Bypassing the Client-Side Authentication Mechanism Itself)**

이 단계는 앱이 로컬에서 사용자를 어떻게 확인하는지 이해하고, 그 로직을 속이거나 건너뛰는 것을 목표로 합니다. **각 방법별로 소프트웨어적 우회 및 저장 관련 취약점을 집중적으로 분석합니다.**

1.  **생체 인식 (Biometrics: Fingerprint, Face ID)**

      * **설명:** 지문, 얼굴 등 사용자의 고유한 생체 정보를 이용한 인증입니다.
      * **테스트 방법:**
          * **런타임 후킹 (Runtime Hooking) (Frida / Objection 활용):**
              * OS가 제공하는 생체 인식 API(`Android BiometricPrompt`, `iOS LAContext`)의 성공/실패 콜백 함수를 후킹(Hooking)하여, 실제 생체 인증 결과와 관계없이 "인증 성공"을 반환하도록 강제합니다. 이는 앱의 생체 인식 메서드가 호출될 때 중간에 개입하여 리턴 값을 조작하는 방식입니다.
              * **Objection 명령어 예시:**
                ```bash
                # Android: BiometricPrompt.AuthenticationCallback 클래스의 메서드들을 와치(watch)하여 흐름 파악
                objection explore -j 'android hooking watch class_methods androidx.biometric.BiometricPrompt.AuthenticationCallback --dump-args --dump-backtrace --dump-return'
                # (실제 '성공' 강제 후킹은 Frida 스크립트를 통해 콜백 로직을 대체해야 함)
                ```
                ```bash
                # iOS: LAContext 클래스의 evaluatePolicy 메서드 와치
                objection explore -j 'ios hooking watch method "-[LAContext evaluatePolicy:localizedReason:reply:]" --dump-args --dump-backtrace --dump-return'
                # (실제 '성공' 강제 후킹은 Frida 스크립트를 통해 reply 블록을 조작해야 함)
                ```
          * **에뮬레이터/시뮬레이터 스푸핑:**
              * Android Emulator나 iOS Simulator에서 제공하는 가상 생체 인식 기능(가상 지문, 가상 Face ID)을 사용하여 앱의 생체 인식 흐름을 통과시킵니다. 이는 우회라기보다 통제된 환경에서의 테스트입니다.

2.  **PIN 인증 (PIN Authentication)**

      * **설명:** 사용자가 설정한 숫자 비밀번호(PIN)를 입력하여 앱 잠금을 해제하는 방식입니다.
      * **테스트 방법:**
          * **런타임 후킹 (Frida / Objection 활용):**
              * 앱의 바이너리(디컴파일된 코드)를 분석하여 PIN 입력 처리, PIN 해싱, 저장된 PIN(또는 해시)과의 비교를 담당하는 메서드를 식별합니다.
              * `Frida`나 `Objection`을 사용하여 해당 메서드를 후킹하고, 입력된 PIN 값을 우회하거나, 검증 로직 자체를 건너뛰어 항상 "인증 성공"을 반환하도록 조작합니다.
              * **테스트 명령어/접근 방식 (Objection/Frida):**
                ```bash
                # Android: 특정 클래스의 메서드들을 와치하여 PIN 검증 흐름 파악
                objection explore -j 'android hooking watch class_methods com.your.app.security.PinValidator --dump-args --dump-backtrace --dump-return'
                # iOS: 특정 클래스의 메서드 와치
                objection explore -j 'ios hooking watch method "-[YourAppPinValidator checkPin:]" --dump-args --dump-backtrace --dump-return'

                # 예시: checkPin(String pin) 메서드가 항상 true를 반환하도록 강제하는 Frida 스크립트
                # (Objection에서 직접적인 명령이 없을 경우 Frida의 Java.perform이나 ObjC.classes를 활용)
                # Java.perform(function() {
                #     var PinValidator = Java.use('com.your.app.security.PinValidator');
                #     PinValidator.checkPin.implementation = function(pin) {
                #         console.log("PIN check bypassed for: " + pin);
                #         return true; // Always return true
                #     };
                # });
                ```
          * **클라이언트 측 PIN 저장 방식 분석 및 무차별 대입 (PIN Storage Analysis & Local Brute-Force):**
              * **파일 시스템 탐색:** 앱 데이터 디렉토리(Android `/data/data/<package_name>/shared_prefs`, `/databases`, iOS `/Library/Preferences`의 `.plist` 파일, `/Documents/` 등)를 탐색하여 PIN 또는 PIN의 해시/암호화된 값이 평문이거나 쉽게 복호화될 수 있는 형태로 저장되어 있는지 확인합니다.
              * **해시 알고리즘 분석:** 만약 PIN이 해싱되어 저장되어 있다면, 사용된 해싱 알고리즘(예: MD5, SHA1)이 안전한지, 솔트(Salt)가 사용되었는지, 반복 횟수가 충분한지(PBKDF2, bcrypt, Argon2 등) 확인합니다. 약한 해시 알고리즘과 솔트 부재는 레인보우 테이블 공격이나 오프라인 무차별 대입 공격에 취약합니다.
              * **로컬 무차별 대입:** 앱이 로컬 PIN 입력 시도 횟수에 제한을 두지 않거나, 일정 횟수 실패 시 앱을 잠그거나 데이터를 삭제하는 등의 조치가 없는지 테스트합니다. 짧은 길이의 PIN(예: 4자리 숫자 PIN)을 사용하는 경우, 제한 없이 무차별 대입을 시도하여 PIN을 찾아낼 수 있습니다.

3.  **패턴 잠금 (Pattern Lock) (주로 Android)**

      * **설명:** 점들을 순서대로 연결하는 특정 패턴을 그려 앱 잠금을 해제하는 방식입니다.
      * **테스트 방법:**
          * **저장 방식 분석:** 패턴을 나타내는 데이터(예: 점의 순서)가 로컬에 어떻게 저장되어 있는지 분석합니다. 해시되거나 암호화되어야 합니다.
          * **로컬 무차별 대입:** PIN과 유사하게, 패턴 입력 시도 횟수에 제한이 없는지, 또는 패턴 해시가 약해서 오프라인으로 크랙 가능한지 테스트합니다.
          * **시각적 노출:** 앱이 패턴을 그릴 때 화면 잔상이나 녹화에 취약한지 확인합니다.

4.  **앱별 로컬 비밀번호 (App-Specific Local Password)**

      * **설명:** 기기 잠금 비밀번호나 온라인 서비스 비밀번호와는 별개로, 특정 앱 자체에서만 사용되는 비밀번호를 설정하여 로컬 접근을 제어하는 방식입니다.
      * **테스트 방법:** PIN과 동일하게, 비밀번호의 로컬 저장 방식(평문, 약한 해시), 로컬 무차별 대입 방어, 비밀번호 복구 로직의 안전성 등을 테스트합니다.

5.  **패스키 (Passkeys) / FIDO (Fast IDentity Online)**

      * **설명:** 사용자의 기기(인증자)가 공개키 암호화 기반의 자격 증명(Passkey)을 관리하며, 사용자는 생체 인식이나 PIN으로 이 패스키를 로컬에서 잠금 해제하여 서버와 인증을 완료합니다.
      * **테스트 방법:**
          * **기반 인증 우회:** 패스키를 잠금 해제하는 근본적인 방법(생체 인식 또는 PIN)을 위 1, 2항과 동일한 방식으로 우회합니다. 우회가 성공하면 패스키 자체를 조작할 수 있는지 테스트합니다.
          * **프로토콜 오용:** 앱/서버가 FIDO 프로토콜을 올바르게 구현했는지, 예를 들어 패스키 인증 실패 시 안전하지 않은 대체 인증으로 폴백(fallback)하지 않는지 확인합니다.
          * **등록/삭제 흐름:** 패스키 등록 및 삭제 과정의 보안을 확인합니다 (예: 인가되지 않은 패스키 등록, 다른 사용자의 패스키 삭제 시도).

6.  **하드웨어 보안 키 (Physical Security Keys - 예: YubiKey)**

      * **설명:** 물리적인 보안 키를 모바일 기기에 연결하여 로컬에서 사용자 인증을 수행하는 다단계 인증 방식입니다.
      * **테스트 방법:**
          * **물리적 우회:** 하드웨어 키 없이도 앱이 인증을 통과한다고 착각하도록 만들 수 있는지 (예: 키 존재 여부만 확인하고 실제 서명을 검증하지 않는 경우) 테스트합니다.
          * **소프트웨어 에뮬레이션:** 키의 응답을 런타임에서 에뮬레이션하여 앱을 속일 수 있는지 테스트합니다.
          * **폴백 메커니즘:** 하드웨어 키가 없거나 인식되지 않을 때, 앱이 제공하는 대체 인증 방법이 안전한지 확인합니다.
          * **API 호출 후킹:** 키가 서명한 데이터를 서버로 보내는 API 호출을 후킹하여, 해당 데이터가 조작될 수 있는지 또는 재생 공격에 취약한지 확인합니다.

#### **II. 서버 측 영향 및 신뢰 경계 테스트 (Testing Server-Side Impact & Trust Boundaries)**

이 단계는 클라이언트 측 인증(생체 인식, PIN 등 어떤 방식이든)을 우회했거나, 정상적으로 통과했을 때, **서버 측 인증 및 인가 로직이 얼마나 견고한지**를 검증하는 가장 중요한 부분입니다. **클라이언트 측의 모든 인증 성공 신호는 서버 측에서 맹목적으로 신뢰되어서는 안 됩니다.**

1.  **API 호출 분석 및 재생 공격 (API Call Analysis & Replay Attack) - 핵심 검증\!**

      * **목표:** 클라이언트 측 인증 성공 후 앱이 서버로 어떤 API 호출을 하는지 확인하고, 해당 요청을 조작하거나 재전송하여 서버 측 취약점을 찾습니다.
      * **방법:**
        1.  `Burp Suite` 또는 `OWASP ZAP`와 같은 웹 프록시 도구를 사용하여 모바일 앱의 모든 네트워크 트래픽을 가로챕니다.
        2.  클라이언트 측 인증을 성공적으로 통과한 후, 앱이 서버로 보내는 모든 API 호출을 면밀히 분석합니다.
        3.  **의심스러운 파라미터:** 요청 본문이나 헤더에 "biometric\_success=true", "pin\_verified"와 같이 클라이언트 측 인증 성공을 나타내는 **단순한 플래그**가 포함되는지 확인합니다. 이러한 플래그만으로 서버 측에서 중요한 결정을 내린다면 위험합니다.
        4.  **재생 공격:** 가로챈 API 요청을 `Burp Suite Repeater` 등으로 조작하여, **앱을 재시작하거나, 로그아웃하거나, 심지어 다른 기기에서** 해당 요청을 서버로 다시 보냅니다.
              * **핵심 질문:** 서버가 이 요청을 다시 받아들여 민감한 작업(예: 계좌 이체, 비밀번호 변경, 프로필 수정, 권한 상승)을 수행합니까?
              * **취약점:** 만약 서버가 클라이언트로부터 받은 '인증 성공' 신호만을 맹목적으로 신뢰하고, 추가적인 서버 측 인증/인가(예: 유효한 세션 토큰 확인, 토큰의 재사용 방지, 권한 재확인, 마스터 비밀번호 재확인) 없이 작업을 처리한다면 심각한 취약점입니다.

2.  **세션/토큰 관리 및 스텝업 인증(Step-up Authentication) 회피 테스트:**

      * **목표:** 클라이언트 측 인증 성공이 서버 측 세션이나 인증 토큰의 유효 기간, 권한에 어떻게 영향을 미치는지 확인합니다.
      * **방법:**
          * **세션 갱신/연장:** 클라이언트 측 인증 성공 후 서버가 새로운, 더 긴 유효 기간의 세션 토큰을 발급하는지 확인합니다. 이 토큰을 탈취하여 오래된 세션으로 접근 가능한지 테스트합니다.
          * **스텝업 인증 우회:** 금융 거래와 같은 매우 민감한 작업은 일반적으로 추가적인 인증(예: 비밀번호 재입력, OTP)을 요구합니다. 클라이언트 측 인증을 우회한 후, 서버가 이러한 "스텝업 인증" 단계를 건너뛰고 작업을 허용하는지 테스트합니다.

3.  **데이터 노출 및 권한 상승 테스트:**

      * **목표:** 클라이언트 측 인증을 우회함으로써, 로컬에 저장된 민감하지만 암호화되지 않은 데이터에 접근할 수 있게 되는지, 또는 서버 측에서 권한 상승이 발생하는지 확인합니다.
      * **방법:** 클라이언트 측 인증 우회 후 파일 시스템을 탐색하거나 (Android `/data/data`, iOS `/private/var/mobile/Containers/Data/Application`), 데이터베이스(SQLite, Plist)를 분석하여 잠금 해제된 민감 정보가 있는지 확인합니다.

-----

**결론:**

클라이언트 측 인증은 사용자 편의성과 로컬 기기의 보안을 높이는 데 유용합니다. 그러나 펜테스터는 이러한 클라이언트 측 인증을 **"편의성"과 "로컬 잠금"의 영역**으로 이해하고, **절대로 "서버 측 인증"을 대체할 수 없다는 원칙**하에 테스트를 수행해야 합니다. 서버는 모든 중요한 작업에 대해 클라이언트의 신호를 맹목적으로 신뢰하지 않고, 독립적이고 견고한 인증 및 인가 로직을 유지해야 합니다.