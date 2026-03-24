---
title: Android Penetration Test Check List
tags: Android
key: page-android_penetration_test_check_list
categories:
- Security
- Mobile Security
author: hyoeun
math: true
mathjax_autoNumber: true
image: "/assets/thumbnails/2022-01-22-android_penetration_test_check_list.png"
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