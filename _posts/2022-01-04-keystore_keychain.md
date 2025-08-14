---
title: Android Key Store & iOS Keychain
tags: Android iOS KeyStore Keychain
key: page-keystore_keychain
categories: [Cybersecurity, Mobile Security]
author: hyoeun
math: true
mathjax_autoNumber: true
---

## Fort Knox on Your Phone: Understanding & Pentesting Android KeyStore and iOS Keychain

One of the most critical challenges in mobile app security is **how to securely store and manage sensitive information, especially cryptographic keys and user credentials.** Storing such information in plaintext in common file systems or `UserDefaults`/`SharedPreferences` is highly risky, as it can be easily exposed to malicious apps, rooted/jailbroken devices, or forensic analysis.

To address these issues, Android and iOS operating systems provide powerful built-in secure storage mechanisms: **Android KeyStore** and **iOS Keychain**. In this blog post, we'll delve into the concepts, security mechanisms, and what to focus on from a penetration testing perspective for both technologies.

---

### **Android KeyStore: The App's Secure Vault**

#### **1. Concept and Purpose**

* **Description:** The Android KeyStore system is a secure storage provided by the Android OS for securely storing and managing cryptographic keys, certificates, and other sensitive credentials. Apps access this storage through the `Android Keystore System` API.
* **Purpose:**
    * **Key Protection:** Safely stores symmetric keys, asymmetric keys, etc., used for encryption/decryption, outside of the app's process memory or general file system.
    * **User Authentication Integration:** Can link key usage to user biometric authentication (fingerprint, face) or screen lock (PIN, pattern), enforcing that keys cannot be used without user authentication.
    * **Non-Exportable Keys:** Keys stored in KeyStore can be configured as non-exportable, meaning they cannot be exported out of the app, minimizing the risk of key theft.

#### **2. Security Mechanisms**

* **Hardware Security Module (HSM) Integration:** Modern Android devices (Android 6.0 Marshmallow and later) leverage hardware security modules like **TEE (Trusted Execution Environment)** or **StrongBox Keymaster** to protect keys even more securely. Keys are generated and used within the TEE, designed to prevent access or decryption by malicious software running in the ordinary OS environment (Rich Execution Environment).
* **App-specific Isolation:** Each app is strictly isolated and can only access its own KeyStore area. Other apps cannot directly access keys stored in a specific app's KeyStore.
* **Key Usage Constraints:** When generating a key, specific usage constraints can be set (e.g., "this key can only be used if user authentication occurs within 5 seconds").
* **Lock Screen Integration:** Keys in KeyStore can be bound to the device's lock screen (PIN, pattern, fingerprint), making them invalid until the device is unlocked.

#### **3. Penetration Testing Perspective**

While Android KeyStore itself is designed to be highly secure, vulnerabilities can arise from **developer misimplementation or misuse.**

* **What to Look For (Vulnerability Scenarios):**
    * **Sensitive Information Exposure Before/After KeyStore Use:** If developers temporarily expose sensitive information in plaintext in **memory** or other insecure storage (`SharedPreferences`, logs, etc.) either before storing it in KeyStore or after retrieving it.
    * **Key Management Outside KeyStore:** If cryptographic keys or passwords are hardcoded within the app's code or stored in insecure locations like `SharedPreferences` instead of KeyStore.
    * **Use of Weak Keys:** Even if stored in KeyStore, if the key itself is weak (e.g., too short) or used with insecure cryptographic algorithms.
    * **Insufficient Authentication Integration:** If user biometric authentication is intended to protect a key, but the integration is flawed, allowing the key to be used without proper user authentication.
    * **Hardcoded KeyStore Alias/Password:** If the alias or password needed to access the KeyStore is hardcoded in the app's code, it could be exposed through reverse engineering.
* **How to Test:**
    * **Static Analysis (MobSF, Jadx, Ghidra):**
        * Identify `KeyStore` related API calls (e.g., `KeyStore.getInstance()`, `KeyStore.load()`, `KeyStore.getEntry()`, `KeyStore.setEntry()`) to understand how the app uses KeyStore.
        * Check if key aliases or related configurations are hardcoded.
        * Trace code flow to see if sensitive information is passed to insecure APIs (e.g., `SharedPreferences`, logging) before or after KeyStore usage.
    * **Dynamic/Runtime Analysis (Frida, Objection):**
        * **API Hooking:** Hook `KeyStore` related API calls (e.g., `KeyStore.getEntry()`, `Cipher.doFinal()`) to intercept keys or sensitive data as they are loaded into memory or decrypted, attempting to dump their values.
        * **Memory Search:** Perform memory searches to find if sensitive data exists in plaintext in memory while the app is using data retrieved from KeyStore.
        * **Root Privileges:** While direct dumping of KeyStore itself is impossible, root privileges may be necessary to intercept keys as they are used by the app process.

---

### **iOS Keychain: Secure Storage for Passwords and Certificates**

#### **1. Concept and Purpose**

* **Description:** The iOS Keychain service is a secure storage for securely storing and retrieving passwords, cryptographic keys, certificates, and other sensitive credentials. It's accessed via APIs from the Security Framework (e.g., `SecItemAdd`, `SecItemCopyMatching`).
* **Purpose:**
    * **Credential Protection:** Safely stores app login credentials, website passwords, Wi-Fi passwords, encryption keys, etc., outside the app's sandbox.
    * **App Sharing:** If specific configurations are allowed, Keychain items can be securely shared among multiple apps developed by the same development team.
    * **User Authentication Integration:** Can integrate with biometric authentication (Face ID/Touch ID) to enforce that specific Keychain items can only be accessed after user authentication.

#### **2. Security Mechanisms**

* **Hardware-Backed Encryption (Secure Enclave):** Modern iOS devices (iPhone 5s and later with A7 chip or newer) utilize a separate secure hardware processor called the **Secure Enclave** to protect keys and credentials more robustly. Keys are generated and used within the Secure Enclave, designed to prevent exposure even if the main OS is compromised.
* **Data Protection Classes:** Keychain items can be assigned data protection classes (e.g., `kSecAttrAccessibleAfterFirstUnlock`, `kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly`) that leverage file system encryption to control accessibility based on the device's lock state or passcode setting.
* **Access Control Lists (ACLs):** Each Keychain item has an ACL specifying which apps (by Bundle ID) can access it. Certain items can also be configured to require user authentication (Face ID/Touch ID).
* **Automatic Locking:** When the device is locked, the Keychain automatically locks, preventing unauthorized access.

#### **3. Penetration Testing Perspective**

While iOS Keychain provides strong security, similar to Android KeyStore, it's crucial to test for **potential vulnerabilities due to developer misuse or specific bypass scenarios.**

* **What to Look For (Vulnerability Scenarios):**
    * **Sensitive Information Exposure Before/After Keychain Use:** If developers temporarily expose sensitive information in plaintext in **memory**, `UserDefaults`, `Documents` folder, or other insecure locations either before storing it in Keychain or after retrieving it.
    * **Storing Sensitive Information Outside Keychain:** If passwords, tokens, or other critical data are stored in `UserDefaults` or the file system in plaintext instead of Keychain.
    * **Using Incorrect Data Protection Classes:** Using overly permissive data protection classes (e.g., `kSecAttrAccessibleAlways`) for highly sensitive information, allowing access even when the device is locked or unlocked by an unauthorized user.
    * **Weak Authentication Integration:** If sensitive Keychain items are accessible without proper user biometric authentication, or if unlocking Keychain requires only general app access.
    * **Hardcoded Access Keys/Attributes:** If service names or account names needed to access Keychain items are hardcoded in the app's code, they could be exposed through reverse engineering.
* **How to Test:**
    * **Static Analysis (MobSF, Ghidra, IDA Pro, class-dump):**
        * Identify Keychain API calls (e.g., `SecItemAdd`, `SecItemCopyMatching`, `SecItemUpdate`, `SecItemDelete`) to understand how the app uses Keychain.
        * Verify the data protection classes (`kSecAttrAccessible...`) used for each item to ensure appropriate security levels.
        * Trace code flow to see if sensitive information is passed to other APIs (e.g., `UserDefaults`, file I/O, logging) before or after Keychain usage.
    * **Dynamic/Runtime Analysis (Frida, Objection):**
        * **Keychain Content Dump:** Use `objection explore -j "ios keychain dump"` to attempt to dump Keychain items from a jailbroken device. This is the most direct test.
        * **API Hooking:** Hook Keychain API calls (e.g., `SecItemCopyMatching`) to intercept decrypted data as the app retrieves items into memory.
        * **Memory Search:** Perform memory searches to determine if sensitive data exists in plaintext in memory while the app is using data retrieved from Keychain.
        * **Biometric Bypass Testing:** For Keychain items requiring biometric authentication (Touch ID/Face ID), attempt to bypass the client-side biometric logic and then access the Keychain item.

---

### **Common Vulnerabilities & Best Practices for Both (Developer Perspective)**

* **Misconception of Secure Storage:** KeyStore/Keychain **only securely store** data; they do **not** protect the data during processing. Information can still be vulnerable in memory before being stored or after being retrieved.
* **Importance of Key Management:** Hardcoding encryption keys or storing them in insecure locations nullifies the benefits of these secure storage mechanisms.
* **Always Encrypt Sensitive Content:** Avoid storing plaintext passwords or PII directly in KeyStore/Keychain if possible. For larger sensitive data, encrypt it with a key stored in KeyStore/Keychain, then store the encrypted blob elsewhere (e.g., database).
* **Clear Purpose:** KeyStore/Keychain are designed for cryptographic keys and small credentials. For large amounts of data, use encrypted databases (e.g., encrypted SQLite DB) with the encryption key stored securely in KeyStore/Keychain.

KeyStore and Keychain are core defense lines in mobile app security. Pentesters must understand their powerful security mechanisms while also focusing on identifying potential weaknesses arising from developer misusage.

---

## Fort Knox on Your Phone: Understanding & Pentesting Android KeyStore and iOS Keychain

모바일 앱의 보안에서 가장 중요한 과제 중 하나는 **민감한 정보(특히 암호화 키와 사용자 자격 증명)를 어떻게 안전하게 저장하고 관리할 것인가**입니다. 일반적인 파일 시스템이나 `UserDefaults`/`SharedPreferences`에 이러한 정보를 평문으로 저장하는 것은 악성 앱, 루팅/탈옥된 기기, 또는 포렌식 분석에 쉽게 노출될 수 있어 매우 위험합니다.

이러한 문제를 해결하기 위해 Android와 iOS는 운영체제 수준에서 강력한 보안 저장소를 제공합니다. 바로 Android의 **KeyStore**와 iOS의 **Keychain**입니다. 이 블로그 글에서는 두 기술의 개념, 보안 메커니즘, 그리고 펜테스팅 관점에서 무엇을 중점적으로 분석해야 하는지에 대해 심층적으로 다루겠습니다.

---

### **Android KeyStore: 앱의 안전 금고**

#### **1. 개념 및 목적**

* **설명:** Android KeyStore 시스템은 암호화 키, 인증서, 그리고 기타 민감한 자격 증명을 안전하게 저장하고 관리하기 위한 Android OS의 보안 저장소입니다. 앱은 `Android Keystore System` API를 통해 이 저장소에 접근합니다.
* **목적:**
    * **키 보호:** 암호화/복호화에 사용되는 대칭 키(Symmetric Keys), 비대칭 키(Asymmetric Keys) 등을 앱 프로세스 메모리나 일반 파일 시스템 외부에 안전하게 보관합니다.
    * **사용자 인증 연동:** 키 사용을 사용자의 생체 인식(지문, 얼굴)이나 화면 잠금(PIN, 패턴)과 연동하여, 사용자 인증 없이는 키가 사용될 수 없도록 강제할 수 있습니다.
    * **비 내보내기(Non-Exportable) 키:** KeyStore에 저장된 키는 앱 외부로 내보내거나 백업할 수 없도록 설정할 수 있어, 키 탈취 위험을 최소화합니다.

#### **2. 보안 메커니즘**

* **하드웨어 보안 모듈 (Hardware Security Module, HSM) 연동:** 최신 Android 기기(Android 6.0 Marshmallow 이상)는 **TEE(Trusted Execution Environment)**나 **StrongBox Keymaster**와 같은 하드웨어 보안 모듈을 활용하여 키를 더욱 안전하게 보호합니다. 키는 TEE 내부에 생성되고 사용되며, 악성 소프트웨어가 실행되는 일반 OS 영역(Rich Execution Environment)에서는 접근하거나 복호화할 수 없도록 설계됩니다.
* **앱별 격리:** 각 앱은 자신의 KeyStore 영역에만 접근할 수 있도록 엄격하게 격리됩니다. 다른 앱이 특정 앱의 KeyStore에 저장된 키를 직접 접근할 수 없습니다.
* **키 사용 제약:** 키를 생성할 때 특정 사용 제약(예: "사용자 인증이 5초 이내에 이루어져야만 이 키를 사용할 수 있음")을 설정할 수 있습니다.
* **잠금 화면 통합:** 사용자가 설정한 잠금 화면(PIN, 패턴, 지문)과 연동하여, 기기 잠금 해제 없이는 KeyStore의 키가 유효하지 않도록 만들 수 있습니다.

#### **3. 펜테스팅 관점**

Android KeyStore 자체는 매우 안전하게 설계되었지만, **개발자의 잘못된 구현이나 오용**으로 인해 취약점이 발생할 수 있습니다.

* **무엇을 찾아야 하는가 (취약점 시나리오):**
    * **KeyStore 사용 전/후의 민감 정보 노출:** 개발자가 민감 정보를 KeyStore에 저장하기 전이나, KeyStore에서 가져온 후 **메모리나 다른 안전하지 않은 저장소(SharedPreferences, 로그 등)에 평문으로 잠시 노출**하는 경우.
    * **KeyStore 외부에 키 관리:** 암호화 키나 비밀번호를 KeyStore에 저장하지 않고, 앱 코드 내부에 하드코딩하거나, `SharedPreferences` 등 안전하지 않은 곳에 저장하는 경우.
    * **약한 키 사용:** KeyStore에 저장된 키를 사용하더라도, 그 키가 자체적으로 약하거나(예: 너무 짧은 길이) 안전하지 않은 암호화 알고리즘과 함께 사용되는 경우.
    * **인증 연동 미흡:** 사용자 생체 인식과 연동하여 키를 보호해야 함에도 불구하고, 이러한 연동을 제대로 구현하지 않아 사용자 인증 없이 키가 사용될 수 있는 경우.
    * **하드코딩된 KeyStore Alias/Password:** KeyStore 접근에 필요한 alias나 password가 앱 코드에 하드코딩되어 있다면, 리버스 엔지니어링을 통해 노출될 수 있습니다.
* **어떻게 테스트하는가:**
    * **정적 분석 (MobSF, Jadx, Ghidra):**
        * `KeyStore` 클래스와 관련된 API 호출(예: `KeyStore.getInstance()`, `KeyStore.load()`, `KeyStore.getEntry()`, `KeyStore.setEntry()`)을 찾아내어 앱이 KeyStore를 어떻게 사용하는지 파악합니다.
        * 키의 Alias 이름이나 관련 설정이 하드코딩되어 있는지 확인합니다.
        * `KeyStore` 사용 전후에 민감 정보가 다른 API(예: `SharedPreferences`, 로깅)로 전달되는지 코드 흐름을 추적합니다.
    * **동적/런타임 분석 (Frida, Objection):**
        * **API 후킹:** `KeyStore` 관련 API 호출(예: `KeyStore.getEntry()`, `Cipher.doFinal()`)을 후킹하여, 키나 민감한 데이터가 메모리에서 로드되거나 복호화되는 시점을 포착하고 그 값을 덤프하려 시도합니다.
        * **메모리 검색:** 앱이 KeyStore에서 가져온 데이터를 메모리에서 사용하는 동안, 해당 데이터가 평문으로 존재하는지 메모리 검색을 수행합니다.
        * **루트 권한:** KeyStore 자체를 직접 덤프하는 것은 불가능하지만, 앱 프로세스에서 키가 사용되는 순간을 가로채기 위해 루트 권한이 필요할 수 있습니다.

---

### **iOS Keychain: 비밀번호와 인증서의 안전한 보관소**

#### **1. 개념 및 목적**

* **설명:** iOS Keychain 서비스는 비밀번호, 암호화 키, 인증서, 그리고 기타 민감한 자격 증명을 안전하게 저장하고 검색하기 위한 iOS의 보안 저장소입니다. `SecItemAdd`, `SecItemCopyMatching` 등 Security Framework의 API를 통해 접근합니다.
* **목적:**
    * **자격 증명 보호:** 앱 로그인 자격 증명, 웹사이트 비밀번호, Wi-Fi 비밀번호, 암호화 키 등을 앱 샌드박스 외부에 안전하게 보관합니다.
    * **앱 간 공유:** 특정 설정이 허용된 경우, 동일한 개발자 팀이 개발한 여러 앱 간에 Keychain 항목을 안전하게 공유할 수 있습니다.
    * **사용자 인증 연동:** Face ID/Touch ID와 같은 생체 인식과 연동하여, 사용자 인증 없이는 특정 Keychain 항목에 접근할 수 없도록 강제할 수 있습니다.

#### **2. 보안 메커니즘**

* **하드웨어 기반 암호화 (Secure Enclave):** 최신 iOS 기기는 **Secure Enclave**라는 별도의 보안 하드웨어 프로세서를 활용하여 키와 자격 증명을 더욱 안전하게 보호합니다. 키는 Secure Enclave 내에서 생성되고 사용되며, 일반 OS가 침해되더라도 키가 노출되지 않도록 설계됩니다.
* **데이터 보호 클래스 (Data Protection Classes):** Keychain 항목은 파일 시스템 암호화와 연동된 데이터 보호 클래스(예: `kSecAttrAccessibleAfterFirstUnlock`, `kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly`)를 사용하여, 기기 잠금 상태나 패스코드 설정 여부에 따라 접근 가능성을 제어합니다.
* **접근 제어 목록 (Access Control Lists, ACLs):** 각 Keychain 항목은 특정 앱(Bundle ID)만 접근할 수 있도록 ACL이 설정됩니다. 특정 항목은 사용자 인증(Face ID/Touch ID)을 요구하도록 설정할 수도 있습니다.
* **자동 잠금:** 기기가 잠기면 Keychain도 자동으로 잠겨 무단 접근을 방지합니다.

#### **3. 펜테스팅 관점**

iOS Keychain은 매우 강력한 보안 기능을 제공하지만, Android KeyStore와 마찬가지로 **개발자의 오용이나 특정 상황에서의 우회 가능성**을 테스트해야 합니다.

* **무엇을 찾아야 하는가 (취약점 시나리오):**
    * **Keychain 사용 전/후의 민감 정보 노출:** Keychain에 저장하기 전이나 가져온 후 **메모리, `UserDefaults`, `Documents` 폴더 등 안전하지 않은 곳에 평문으로 노출**하는 경우.
    * **Keychain 외부에 민감 정보 저장:** 비밀번호, 토큰 등을 Keychain이 아닌 `UserDefaults`나 파일 시스템에 평문으로 저장하는 경우.
    * **잘못된 데이터 보호 클래스 사용:** 매우 민감한 정보임에도 불구하고 `kSecAttrAccessibleAlways`와 같이 너무 허용적인 데이터 보호 클래스를 사용하여, 기기가 잠겨 있거나 잠금이 해제되지 않은 상태에서도 접근 가능하게 만드는 경우.
    * **약한 인증 연동:** 사용자 생체 인식 연동 없이 민감한 Keychain 항목에 접근 가능하게 하거나, 단순히 "앱 접근"만으로 Keychain 잠금을 해제하는 경우.
    * **하드코딩된 접근 키/속성:** Keychain 접근에 필요한 서비스 이름이나 계정 이름이 앱 코드에 하드코딩되어 있다면, 리버스 엔지니어링 시 노출될 수 있습니다.
* **어떻게 테스트하는가:**
    * **정적 분석 (MobSF, Ghidra, IDA Pro, class-dump):**
        * `SecItemAdd`, `SecItemCopyMatching`, `SecItemUpdate`, `SecItemDelete` 등 Keychain API 호출을 찾아 앱이 Keychain을 어떻게 사용하는지 파악합니다.
        * 사용되는 데이터 보호 클래스(`kSecAttrAccessible...`)를 확인하여 적절한 보안 수준이 적용되었는지 검토합니다.
        * Keychain 접근 전후에 데이터가 다른 API(예: `UserDefaults`, 파일 I/O, 로깅)로 전달되는지 코드 흐름을 추적합니다.
    * **동적/런타임 분석 (Frida, Objection):**
        * **Keychain 내용 덤프:** `objection explore -j "ios keychain dump"` 명령을 사용하여 탈옥된 기기에서 앱의 Keychain 항목을 덤프하려 시도합니다. (가장 직접적인 테스트).
        * **API 후킹:** `SecItemCopyMatching`과 같은 Keychain API 호출을 후킹하여, 앱이 Keychain에서 특정 항목을 가져올 때 메모리에서 복호화된 데이터를 가로채려 시도합니다.
        * **메모리 검색:** 앱이 Keychain에서 가져온 데이터를 메모리에서 사용하는 동안, 해당 데이터가 평문으로 존재하는지 메모리 검색을 수행합니다.
        * **생체 인식 우회 테스트:** 생체 인식(`Touch ID`/`Face ID`)이 필요한 Keychain 항목에 대해, 런타임에서 생체 인식을 우회하고 해당 항목에 접근할 수 있는지 테스트합니다.

---

### **두 저장소의 공통적인 취약점 및 모범 사례 (개발자 관점)**

* **보안 저장소 사용의 오해:** KeyStore/Keychain은 데이터를 "안전하게 저장"할 뿐, **데이터 처리 과정의 모든 보안을 책임지지 않습니다.** 데이터가 KeyStore/Keychain에 저장되기 전이나, 가져와서 사용되는 순간(메모리)에는 여전히 취약할 수 있습니다.
* **키 관리의 중요성:** 암호화 키 자체를 하드코딩하거나 안전하지 않은 곳에 저장하는 것은 이들 보안 저장소의 이점을 무력화합니다.
* **항상 암호화된 데이터를 저장:** 평문 비밀번호나 PII를 KeyStore/Keychain에 직접 저장하는 것은 피하고, 가능하다면 사용자의 마스터 비밀번호에 기반한 암호화 키를 사용하여 데이터를 암호화한 후 저장하는 것이 더 안전합니다.
* **명확한 목적:** KeyStore/Keychain은 암호화 키와 소량의 자격 증명 저장을 위한 것이며, 대량의 데이터 저장은 SQLite DB와 같은 곳에서 암호화하여 저장해야 합니다.

KeyStore와 Keychain은 모바일 앱 보안의 핵심 방어선입니다. 펜테스터는 이들 기술의 강력한 보안 메커니즘을 이해하고, 동시에 개발자의 잘못된 사용으로 인한 잠재적 약점을 찾아내는 데 집중해야 합니다.