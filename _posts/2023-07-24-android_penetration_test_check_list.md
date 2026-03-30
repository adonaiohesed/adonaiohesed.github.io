---
title: Android Penetration Test Check List
key: page-android_penetration_test_check_list
categories:
- Security
- Mobile Security
author: hyoeun
math: true
mathjax_autoNumber: true
bilingual: true
image: "/assets/thumbnails/2023-07-24-android_penetration_test_check_list.png"
date: 2023-07-24 02:16:48
---
-----

### **1. Static Analysis**

| Check Item | Details | Test Cases / Method | Tools |
| :--- | :--- | :--- | :--- |
| **Weak Signer Certificate** | The app is signed with a weak or compromised certificate (e.g., a debug certificate or one using a weak algorithm like SHA1withRSA). | 1. Use `apksigner` or `jarsigner` to verify the certificate's algorithm and details. \<br\> 2. Check for Janus vulnerability. \<br\> 3. Check if the certificate is a known public debug certificate. | `apksigner`, `jarsigner`, `Jadx` |
| **Source Code Obfuscation** | The app's source code is not obfuscated, making it easy to reverse engineer. | 1. Decompile the APK and check if class, method, and variable names are readable or have been renamed to meaningless characters. | `Jadx`, `Ghidra`, `Bytecode-Viewer` |
| **Hardcoded Sensitive Information** | Sensitive data like API keys, tokens, or passwords are hardcoded directly in the source code or resource files. | 1. Decompile the app and search the source code for keywords like `API_KEY`, `token`, `password`, `secret`. | `Jadx`, `MobSF`, `grep` |
| **Insecure Coding Practices** | The app uses insecure functions, weak random number generators, or weak encryption algorithms. | 1. Review code for use of `java.util.Random` instead of `SecureRandom`. \<br\> 2. Look for weak crypto algorithms like MD5, SHA1, or Base64 used for encryption. | `Jadx`, `Ghidra` |
| **Missing Integrity Checks** | The app does not verify its own integrity, allowing for repackaging attacks. | 1. Decompile the app, modify its code (e.g., Smali), recompile, sign it, and check if it still functions properly. | `apktool`, `apksigner` |
| **Insecure Manifest Configuration** | The `AndroidManifest.xml` file has insecure flags set, such as `allowBackup=true` or `debuggable=true`. | 1. Review the manifest file for `android:debuggable="true"`, `android:allowBackup="true"`, and `network_security_config` allowing cleartext traffic. | `Jadx`, `apktool`, `MobSF` |

-----

### **2. Dynamic Analysis**

| Check Item | Details | Test Cases / Method | Tools |
| :--- | :--- | :--- | :--- |
| **SSL Pinning** | The app does not properly verify the server's SSL certificate, allowing for Man-in-the-Middle (MitM) attacks. | 1. Intercept traffic to check if pinning is implemented. \<br\> 2. Use hooking frameworks to bypass pinning logic in common libraries (OkHttp, etc.). | `Burp Suite`, `Frida`, `Objection` |
| **Root Detection** | The app does not properly detect and prevent access by rooted devices, allowing for unauthorized access to data or functionality. | 1. Run the app on a rooted device to check for detection. \<br\> 2. Use hooking frameworks to bypass functions that check for root indicators (e.g., su binary, specific packages). | `Frida`, `Xposed Framework`, `Magisk` |
| **Emulator Detection** | The app does not properly detect and prevent access by emulators, allowing users to bypass security controls. | 1. Run the app on an emulator (Android Studio, Genymotion). \<br\> 2. Use Frida to hook and bypass functions that check for emulator-specific properties. | `Frida`, Android Studio Emulator |
| **Sensitive Data in Application Memory** | Unencrypted sensitive data is stored in the application's memory, making it vulnerable to memory dumping attacks. | 1. While the app is running, use memory dumping scripts to extract the app's memory heap. \<br\> 2. Search the memory dump for sensitive strings. | `Frida`, `fridump.py`, `GameGuardian` |
| **Vulnerable Android Activities** | Activities are improperly configured, leading to auth bypass, hijacking, or Denial of Service. | 1. Use `adb` or `drozer` to directly launch non-exported or protected activities, bypassing login screens. \<br\> 2. Check if activities can be hijacked or cause a crash. | `adb`, `drozer` |
| **WebView Vulnerabilities** | The app's WebView component is insecurely configured, allowing for XSS, LFI, or remote code execution. | 1. Check if JavaScript is enabled (`setJavaScriptEnabled`). \<br\> 2. Test for insecure `addJavascriptInterface` usage. \<br\> 3. Check for insecure file access flags. | `Frida`, `Drozer`, `Burp Suite` |
| **Insecure Intent Handling** | Intent data is not properly filtered or validated, leading to spoofing, sniffing, or redirection vulnerabilities. | 1. Use `drozer` to craft and send malicious intents to exported components. \<br\> 2. Check for vulnerabilities related to `PendingIntent` or sticky broadcasts. | `drozer`, `adb` |
| **Vulnerable Broadcast Receivers** | An exported broadcast receiver without proper permission checks can be triggered by any app on the device. | 1. Identify exported receivers in the manifest. \<br\> 2. Use `drozer` or `adb` to send a broadcast intent and trigger the receiver. | `drozer`, `adb`, `Jadx` |
| **Insecure Content Provider** | Content providers leak information due to missing security controls, leading to SQL Injection or Path Traversal. | 1. Use `drozer` to query content provider URIs. \<br\> 2. Attempt to inject SQL or path traversal sequences into the query. | `drozer`, `SQLmap` |
| **Insecure Deeplinks** | Deeplinks are not properly validated, allowing attackers to access sensitive data or functionality within the app. | 1. Identify URL schemes in the manifest. \<br\> 2. Use `adb` to invoke the deeplink with manipulated parameters to test for vulnerabilities. | `adb`, `drozer`, Web Browser |
| **Biometric/Lock Auth Bypass** | Application logic that relies on biometric or screen lock authentication can be bypassed at runtime. | 1. Use Frida to hook the methods that handle the authentication result and force them to return `true`. | `Frida`, `Xposed Framework` |
| **Task Hijacking** | A malicious app manipulates the Android Task stack to take over a legitimate app's task due to `taskAffinity` misconfigurations. | 1. Check `taskAffinity` and `launchMode` attributes in the manifest. \<br\> 2. Create a PoC app with the same `taskAffinity` to attempt hijacking. | `Jadx`, Custom PoC App |
| **Tapjacking** | A malicious app draws an overlay to trick the user into clicking on the underlying victim app. | 1. Check if `filterTouchesWhenObscured` is set to `true`. \<br\> 2. Create a PoC overlay app to test exploitability. | Custom PoC App, `Jadx` |
| **Custom URL Scheme Abuse** | The app does not safely parse data from custom URL schemes (`myapp://`), leading to data leakage or injection. | 1. Fuzz the parameters and paths of the custom URL scheme. \<br\> 2. Test for injection vulnerabilities (SQLi, XSS) through the URL parameters. | `adb`, `drozer`, `Frida` |

-----

### **3. Data Storage & Network Analysis**

| Check Item | Details | Test Cases / Method | Tools |
| :--- | :--- | :--- | :--- |
| **Sensitive Data in ADB Logcat** | The app logs sensitive data (passwords, tokens, personal info) to the system log, exposing it via ADB. | 1. Run `adb logcat` while using the app, especially during login or data entry. \<br\> 2. Filter logs for keywords like `password`, `token`, `key`. | `adb logcat`, `PIDcat` |
| **Sensitive Data in Local Storage** | Sensitive data is stored in an unencrypted or unsecured manner in SharedPreferences, databases, or other local files. | 1. Access the app's data directory (`/data/data/<package>`) on a rooted device. \<br\> 2. Examine the contents of SharedPreferences XML files and SQLite databases. | `adb shell`, `SQLite Browser` |
| **Background Screen Caching** | The OS takes a screenshot of the app for the task switcher, which could expose sensitive data. | 1. Navigate to a screen with sensitive info. \<br\> 2. Send the app to the background and check the app switcher preview. \<br\> 3. Check if `FLAG_SECURE` is used. | OS Functionality |
| **Insecure File Permissions** | The app creates files with world-readable or world-writable permissions in its internal storage. | 1. Use `adb shell` and `ls -l` in the app's data directory to check file permissions. \<br\> 2. Check for use of `MODE_WORLD_READABLE`/`WRITABLE`. | `adb shell`, `drozer` |
| **Insecure Firebase Database** | The Firebase database has misconfigured security rules, allowing for unauthorized read/write access. | 1. Append `.json` to the end of the Firebase database URL. \<br\> 2. Try to write data using a `curl` PUT request. | Web Browser, `cURL`, `Burp Suite` |
| **API & Network Security** | The APIs used by the app have common web vulnerabilities like broken access control, injection, or data exposure. | 1. Intercept all traffic with a proxy. \<br\> 2. Perform standard web API pentesting (fuzzing, injection, access control checks). | `Burp Suite`, `Postman`, `SQLmap` |

---

### **1. 정적 분석 (Static Analysis)**

| 점검 항목 | 상세 내용 | 테스트 케이스 / 방법 | 도구 |
| :--- | :--- | :--- | :--- |
| **취약한 서명 인증서** | 앱이 취약하거나 손상된 인증서(예: 디버그 인증서 또는 SHA1withRSA와 같은 약한 알고리즘 사용)로 서명됨. | 1. `apksigner` 또는 `jarsigner`로 인증서의 알고리즘과 세부 정보 확인. \<br\> 2. Janus 취약점 확인. \<br\> 3. 알려진 공개 디버그 인증서 여부 확인. | `apksigner`, `jarsigner`, `Jadx` |
| **소스 코드 난독화 부재** | 앱의 소스 코드가 난독화되지 않아 리버스 엔지니어링이 쉬움. | 1. APK를 디컴파일하고 클래스, 메서드, 변수 이름이 읽기 가능하거나 무의미한 문자로 변경되었는지 확인. | `Jadx`, `Ghidra`, `Bytecode-Viewer` |
| **하드코딩된 민감 정보** | API 키, 토큰, 패스워드 같은 민감 데이터가 소스 코드나 리소스 파일에 직접 하드코딩됨. | 1. 앱을 디컴파일하고 `API_KEY`, `token`, `password`, `secret` 같은 키워드로 소스 코드 검색. | `Jadx`, `MobSF`, `grep` |
| **안전하지 않은 코딩 관행** | 앱이 안전하지 않은 함수, 약한 난수 생성기, 또는 약한 암호화 알고리즘 사용. | 1. `SecureRandom` 대신 `java.util.Random` 사용 여부 코드 리뷰. \<br\> 2. 암호화에 MD5, SHA1 또는 Base64 같은 약한 알고리즘 사용 여부 확인. | `Jadx`, `Ghidra` |
| **무결성 검사 부재** | 앱이 자체 무결성을 검증하지 않아 리패키징 공격에 취약. | 1. 앱을 디컴파일하고 코드를 수정(예: Smali)하여 재컴파일, 서명 후 정상 작동 여부 확인. | `apktool`, `apksigner` |
| **안전하지 않은 매니페스트 구성** | `AndroidManifest.xml` 파일에 `allowBackup=true` 또는 `debuggable=true` 같은 안전하지 않은 플래그 설정. | 1. 매니페스트 파일에서 `android:debuggable="true"`, `android:allowBackup="true"`, 평문 트래픽을 허용하는 `network_security_config` 검토. | `Jadx`, `apktool`, `MobSF` |

-----

### **2. 동적 분석 (Dynamic Analysis)**

| 점검 항목 | 상세 내용 | 테스트 케이스 / 방법 | 도구 |
| :--- | :--- | :--- | :--- |
| **SSL 피닝** | 앱이 서버의 SSL 인증서를 제대로 검증하지 않아 중간자 공격(MitM)에 취약. | 1. 트래픽을 인터셉트하여 피닝 구현 여부 확인. \<br\> 2. 후킹 프레임워크로 공통 라이브러리(OkHttp 등)의 피닝 로직 우회. | `Burp Suite`, `Frida`, `Objection` |
| **루팅 탐지** | 앱이 루팅된 기기를 제대로 탐지 및 차단하지 않아 데이터나 기능에 무단 접근 가능. | 1. 루팅된 기기에서 앱을 실행하여 탐지 여부 확인. \<br\> 2. 후킹 프레임워크로 루팅 지표(su 바이너리, 특정 패키지 등)를 확인하는 함수 우회. | `Frida`, `Xposed Framework`, `Magisk` |
| **에뮬레이터 탐지** | 앱이 에뮬레이터를 제대로 탐지 및 차단하지 않아 보안 제어 우회 가능. | 1. 에뮬레이터(Android Studio, Genymotion)에서 앱 실행. \<br\> 2. Frida로 에뮬레이터 특정 속성을 확인하는 함수를 후킹하여 우회. | `Frida`, Android Studio 에뮬레이터 |
| **애플리케이션 메모리의 민감한 데이터** | 암호화되지 않은 민감한 데이터가 애플리케이션 메모리에 저장되어 메모리 덤핑 공격에 취약. | 1. 앱 실행 중 메모리 덤핑 스크립트로 앱의 메모리 힙을 추출. \<br\> 2. 메모리 덤프에서 민감한 문자열 검색. | `Frida`, `fridump.py`, `GameGuardian` |
| **취약한 Android 액티비티** | 액티비티가 부적절하게 구성되어 인증 우회, 하이재킹, 또는 서비스 거부 발생. | 1. `adb` 또는 `drozer`로 내보내지지 않은 또는 보호된 액티비티를 직접 실행하여 로그인 화면 우회. \<br\> 2. 액티비티 하이재킹 또는 충돌 가능 여부 확인. | `adb`, `drozer` |
| **WebView 취약점** | 앱의 WebView 컴포넌트가 안전하지 않게 구성되어 XSS, LFI, 또는 원격 코드 실행 허용. | 1. JavaScript가 활성화되었는지 확인(`setJavaScriptEnabled`). \<br\> 2. 안전하지 않은 `addJavascriptInterface` 사용 테스트. \<br\> 3. 안전하지 않은 파일 접근 플래그 확인. | `Frida`, `Drozer`, `Burp Suite` |
| **안전하지 않은 인텐트 처리** | 인텐트 데이터가 제대로 필터링 또는 검증되지 않아 스푸핑, 스니핑, 또는 리다이렉션 취약점 발생. | 1. `drozer`로 악의적인 인텐트를 만들어 내보내기된 컴포넌트에 전송. \<br\> 2. `PendingIntent` 또는 스티키 브로드캐스트 관련 취약점 확인. | `drozer`, `adb` |
| **취약한 브로드캐스트 리시버** | 권한 확인 없이 내보내기된 브로드캐스트 리시버를 기기의 모든 앱이 트리거 가능. | 1. 매니페스트에서 내보내기된 리시버 식별. \<br\> 2. `drozer` 또는 `adb`로 브로드캐스트 인텐트를 전송하여 리시버 트리거. | `drozer`, `adb`, `Jadx` |
| **안전하지 않은 콘텐츠 프로바이더** | 콘텐츠 프로바이더가 보안 제어 부재로 정보를 노출하여 SQL 인젝션 또는 경로 순회 발생. | 1. `drozer`로 콘텐츠 프로바이더 URI 쿼리. \<br\> 2. 쿼리에 SQL 또는 경로 순회 시퀀스 삽입 시도. | `drozer`, `SQLmap` |
| **안전하지 않은 딥링크** | 딥링크가 제대로 검증되지 않아 공격자가 앱 내 민감한 데이터나 기능에 접근 가능. | 1. 매니페스트에서 URL 스킴 식별. \<br\> 2. `adb`로 조작된 파라미터로 딥링크를 호출하여 취약점 테스트. | `adb`, `drozer`, 웹 브라우저 |
| **생체 인식/잠금 인증 우회** | 생체 인식 또는 화면 잠금 인증에 의존하는 애플리케이션 로직을 런타임에 우회 가능. | 1. Frida로 인증 결과를 처리하는 메서드를 후킹하여 `true`를 반환하도록 강제. | `Frida`, `Xposed Framework` |
| **태스크 하이재킹** | 악의적인 앱이 `taskAffinity` 잘못 구성으로 인해 Android 태스크 스택을 조작하여 합법적인 앱의 태스크를 탈취. | 1. 매니페스트의 `taskAffinity` 및 `launchMode` 속성 확인. \<br\> 2. 동일한 `taskAffinity`의 PoC 앱을 만들어 하이재킹 시도. | `Jadx`, 커스텀 PoC 앱 |
| **탭재킹** | 악의적인 앱이 오버레이를 그려 사용자가 피해 앱을 클릭하도록 속임. | 1. `filterTouchesWhenObscured`가 `true`로 설정되었는지 확인. \<br\> 2. PoC 오버레이 앱을 만들어 악용 가능성 테스트. | 커스텀 PoC 앱, `Jadx` |
| **커스텀 URL 스킴 남용** | 앱이 커스텀 URL 스킴(`myapp://`)의 데이터를 안전하게 파싱하지 않아 데이터 유출 또는 인젝션 발생. | 1. 커스텀 URL 스킴의 파라미터와 경로를 퍼징. \<br\> 2. URL 파라미터를 통한 인젝션 취약점(SQLi, XSS) 테스트. | `adb`, `drozer`, `Frida` |

-----

### **3. 데이터 저장 및 네트워크 분석 (Data Storage & Network Analysis)**

| 점검 항목 | 상세 내용 | 테스트 케이스 / 방법 | 도구 |
| :--- | :--- | :--- | :--- |
| **ADB Logcat의 민감한 데이터** | 앱이 민감한 데이터(패스워드, 토큰, 개인정보)를 시스템 로그에 기록하여 ADB를 통해 노출. | 1. 앱 사용 중(특히 로그인 또는 데이터 입력 시) `adb logcat` 실행. \<br\> 2. `password`, `token`, `key` 같은 키워드로 로그 필터링. | `adb logcat`, `PIDcat` |
| **로컬 저장소의 민감한 데이터** | 민감한 데이터가 SharedPreferences, 데이터베이스 또는 기타 로컬 파일에 암호화되지 않거나 안전하지 않게 저장. | 1. 루팅된 기기에서 앱의 데이터 디렉토리(`/data/data/<package>`) 접근. \<br\> 2. SharedPreferences XML 파일 및 SQLite 데이터베이스 내용 검사. | `adb shell`, `SQLite Browser` |
| **백그라운드 화면 캐싱** | OS가 태스크 전환기를 위해 앱 스크린샷을 찍어 민감한 데이터를 노출할 수 있음. | 1. 민감한 정보가 있는 화면으로 이동. \<br\> 2. 앱을 백그라운드로 보내고 앱 전환기 미리보기 확인. \<br\> 3. `FLAG_SECURE` 사용 여부 확인. | OS 기능 |
| **안전하지 않은 파일 권한** | 앱이 내부 저장소에 전 세계 읽기 또는 쓰기 가능한 권한으로 파일을 생성. | 1. 앱의 데이터 디렉토리에서 `adb shell` 및 `ls -l`로 파일 권한 확인. \<br\> 2. `MODE_WORLD_READABLE`/`WRITABLE` 사용 여부 확인. | `adb shell`, `drozer` |
| **안전하지 않은 Firebase 데이터베이스** | Firebase 데이터베이스에 잘못 구성된 보안 규칙이 있어 무단 읽기/쓰기 접근 허용. | 1. Firebase 데이터베이스 URL 끝에 `.json` 추가. \<br\> 2. `curl` PUT 요청으로 데이터 쓰기 시도. | 웹 브라우저, `cURL`, `Burp Suite` |
| **API 및 네트워크 보안** | 앱이 사용하는 API에 손상된 접근 제어, 인젝션 또는 데이터 노출 같은 일반적인 웹 취약점 존재. | 1. 프록시로 모든 트래픽 인터셉트. \<br\> 2. 표준 웹 API 펜테스팅 수행(퍼징, 인젝션, 접근 제어 확인). | `Burp Suite`, `Postman`, `SQLmap` |