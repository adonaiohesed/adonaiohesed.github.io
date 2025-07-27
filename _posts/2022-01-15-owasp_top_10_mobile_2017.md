---
title: OWASP Top 10 Mobile- 2017
tags: OWASP Top-10 Mobile-Security
key: page-owasp_top_10_mobile_2017
categories: [Cybersecurity, Mobile Security]
author: hyoeun
math: true
mathjax_autoNumber: true
---

# Hidden Dangers of Mobile Security: A Complete Guide to the Top 10 Risks
## M1: Improper Platform Usage

**Threat Agents**

This threat involves the misuse of platform features or the failure to use platform security controls. Examples include the mishandling of Android Intents, misuse of TouchID, incorrect platform permission settings, and iOS Keychain misuse. It primarily occurs when developers don't properly follow platform guidelines or make unintentional errors.

**Vulnerable and Prevent**

* **Android Intents:** Android Intents are messaging objects that allow communication between various activities within the operating system. These operations include communicating with background services, accessing data stored on the mobile device or another app's server, and starting and stopping activities like opening other apps. Data leakage can occur during message exchange.
    * **Prevention:** Restrict apps that can communicate with others via **permission control**, and block all attempts at unauthorized traffic. You can protect components that don't need to communicate with other apps by setting `android:exported="false"`. To prevent sniffing attacks, clearly define Intent objects using **Explicit Intents**, which prevents all components from accessing the information contained within the Intent.

* **iOS Keychain:** The iOS Keychain helps users securely store third-party account credentials on their mobile devices. iOS developers can use Keychain encryption without needing to implement their own cryptographic methods. If users don't choose the Keychain option, they tend to select easy passwords, making them vulnerable to exploitation by attackers.
    * **Prevention:** It's recommended that Keychain encryption be used to store data only on a single device, rather than synchronizing it via a server. It's best to use the Keychain to store app secrets that should have an **Access Control List (ACL)** to protect the app.

---

## M2: Insecure Data Storage

**Threat Agents**

Attackers can gain physical access by finding or stealing a phone, or they can access the device's internal storage using malware or another repackaged app. With physical access, they can connect the device to a computer to access the file system and use freely available software to access third-party application directories and Personally Identifiable Information (PII).

**Vulnerable and Prevent**

Data stored insecurely in SQL databases, log files, XML data stores, cookies, and SD cards, or even unintentionally in the operating system, frameworks, or compiler environment, can lead to data leakage. This problem also arises when developers are unaware of how cached data, images, key clicks, and buffers are stored on the device.

* **Prevention:** For iOS, using purposefully vulnerable mobile apps like **iGoat** can help developers understand these vulnerabilities. Android developers can use the **ADB Shell (Android Debug Bridge Shell)** to check file permissions for target apps or use commands like `logcat` to see if sensitive information is leaking from Android. Performing **Threat Modeling** from the early development stages is crucial to identify and resolve potential data storage vulnerabilities.

---

## M3: Insecure Communication

**Threat Agents**

Data transmission between mobile apps typically occurs over carrier networks. Threat agents will attempt to intercept sensitive data while it's traversing these wires. Adversaries sharing your local network, carrier or network devices, and malware on your mobile phone are key threats.

**Am I Vulnerable?**

Vulnerabilities can be found in any aspect where data is moved from point A to point B in an insecure manner. This relates to all devices involved in mobile-to-mobile, app-to-server, or mobile-to-something-else communication, and it's associated with all network communication technologies like TCP/IP, Wi-Fi, Bluetooth, NFC, GSM, SMS, and 3G. Problems can arise when transmitting sensitive data such as encryption keys, passwords, personal information, session tokens, metadata, and binaries. This vulnerability exists if data can be altered during transmission and the changes cannot be detected.

**Prevention**

Common prevention methods include:

* Assume the network layer is insecure and vulnerable to eavesdropping.
* Apply **SSL/TLS** when sending sensitive data elsewhere.
* Use **strong cryptographic standards**.
* Don't allow self-signed certificates; only use certificates from trusted CA (Certificate Authority) issuers.
* Verify the SSL chain.
* It's even better to apply additional encryption before sending data over an SSL channel.

**iOS Prevention:** Modern iOS default classes handle SSL cipher strength well. Problems arise when developers temporarily add code to bypass these defaults.

* Ensure all certificates are properly validated.
* Consider using the Secure Transport API to verify trusted user certificates when using `CFNetwork`.
* Check that all `NSURL` calls do not use self-signed or invalid certificates.

**Android Prevention:** For Android, remove code like `org.apache.http.conn.ssl.AllowAllHostnameVerifier`, which might have been included during development to allow all certificates. Otherwise, it creates a vulnerability similar to allowing all certificates. Additionally, if you have classes using `SSLSocketFactory`, you must ensure they are properly verifying the server certificate.

**Attack Scenarios**

* A mobile application establishes a secure channel via a TLS handshake without validating the certificate provided by the server. The application simply accepts the server's certificate if it's provided. This makes it vulnerable to **MITM (Man-In-The-Middle)** attacks through a **TLS proxy server**.
* During the handshake process, negotiation leads to the use of a weak **cipher suite**, compromising the confidentiality between the mobile app and the endpoint.
* A mobile app transmits information over a non-secure channel instead of SSL, exposing sensitive data to the risk of leakage.

---

## M4: Unintended Data Leakage

**Threat Agents**

Sensitive data can be unintentionally exposed due to developer negligence. This includes developer errors, misconfigurations, or a lack of understanding of how the app interacts with the operating system or other app features. It can also occur through malicious apps, device compromise, or when an attacker gains physical access to the device.

**Am I Vulnerable?**

When an app stores or processes user or other sensitive data, that data can be exposed through the file system, cache, clipboard, log files, keyboard caching, screenshots, and even push notifications. Apps can also be vulnerable if developers output sensitive information to logs for debugging purposes or store important data in temporary files without properly deleting them.

**Prevention**

* **No Sensitive Data Logging:** Avoid logging sensitive information in both development and production environments. If absolutely necessary, encrypt or mask the data.
* **File System Permission Management:** Set appropriate access permissions for all files stored by the app to prevent other apps or users from accessing them.
* **Clipboard Data Management:** Implement mechanisms to immediately clear sensitive data from the clipboard when the app closes or moves to the background.
* **Cache Data Protection:** Do not store user authentication information or sensitive session data in the cache, or apply strong encryption if stored.
* **Prevent Screenshots:** Disable screenshot functionality on screens displaying sensitive information or ensure screenshots are not saved. (e.g., Android's `FLAG_SECURE`, iOS's `UIScreen.main.bounds` for view capture prevention).
* **Minimize Push Notification Content:** Include only minimal information in push notifications and prompt users to view sensitive details within the app.

**Attack Scenarios**

* An attacker gains access to a user's device and extracts sensitive information, such as usernames, passwords, or credit card numbers, from the app's **log files**.
* A user copies sensitive information to the **clipboard**, and a malicious app reads the clipboard content, exfiltrating the data.
* When the app runs in debugging mode, if the developer hasn't disabled the **screenshot functionality**, an attacker can capture sensitive screen content.
* The app directly sends OTPs (One-Time Passwords) or financial transaction information via **push notifications**, leading to information leakage if the notification is exposed.

---

## M5: Weak Authentication

**Threat Agents**

Attackers who exploit vulnerabilities in authentication mechanisms, credential stuffing attackers, and hackers attempting brute-force attacks. Developers can also inadvertently create vulnerabilities due to implementation errors or policy non-compliance.

**Am I Vulnerable?**

* If the app allows simple and predictable passwords.
* If password policies are too short or don't enforce special characters/numbers.
* If there's no account lockout policy or it's too lenient.
* If authentication attempts aren't limited, making it vulnerable to brute-force attacks.
* If sensitive error messages (e.g., "username does not exist" or "incorrect password") are exposed on the login page, aiding **account enumeration** attacks.
* If Multi-Factor Authentication (MFA) is not used, or if its implementation is weak (e.g., OTPs are too short or reusable).

**Prevention**

* **Strong Password Policy:** Implement complex password policies that enforce minimum length, uppercase/lowercase letters, numbers, and special character combinations.
* **Account Lockout and Rate Limiting:** Implement account lockout after a certain number of failed login attempts or apply rate limiting to login attempts to prevent brute-force attacks.
* **Multi-Factor Authentication (MFA):** Introduce MFA whenever possible to enhance security.
* **Secure Password Storage:** Do not store passwords in plaintext. Store them using strong hashing algorithms with salt (e.g., bcrypt, scrypt, Argon2).
* **Session Management:** Generate session tokens securely, set short validity periods, and immediately invalidate them upon logout.
* **Use OAuth/OpenID Connect:** Prefer using verified standard authentication protocols (OAuth 2.0, OpenID Connect) over implementing custom authentication systems.
* **Leverage Biometric Authentication:** Use on-device biometric authentication features like TouchID or FaceID to improve both user convenience and security. However, biometric authentication should be a supplementary measure, combined with strong password-based authentication.

**Attack Scenarios**

* An attacker uses weak password policies to launch **brute-force attacks** or uses leaked usernames and passwords from other services to perform **credential stuffing** attacks and hijack user accounts.
* The app's login page returns specific error messages like "username does not exist," allowing an attacker to **enumerate valid usernames**.
* Even with MFA enabled, if OTPs are sent in plaintext via SMS or have very short validity periods, an attacker can **reuse** or intercept them.

---

## M6: Improper Session Handling

**Threat Agents**

Attackers attempting to steal or reuse session tokens, hackers trying **Session Fixation** attacks, and developers who have incorrectly implemented session management code.

**Am I Vulnerable?**

* If session tokens are exposed in URLs or stored elsewhere besides HTTP headers.
* If session tokens have an excessively long lifespan and don't expire.
* If session tokens are not immediately invalidated when a user logs out.
* If session tokens are transmitted over insecure channels vulnerable to network sniffing.
* If a new, unique, and unpredictable session ID is not generated for each new session.
* If session IDs are fixed, making the app vulnerable to **session fixation** attacks where an attacker assigns a pre-generated session ID to a user.

**Prevention**

* **Secure Session Token Generation:** Session tokens must be unpredictable, sufficiently long, and based on cryptographically strong random numbers.
* **Use HTTPS:** All session token transmissions must occur over an encrypted channel using **HTTPS (HTTP Secure)**.
* **Session Lifetime Management:** Sessions should have a short validity period and be automatically expired after a period of inactivity.
* **Immediate Invalidation on Logout:** When a user logs out, the server-side session must be immediately invalidated.
* **Session Token Regeneration:** Generate a new session token after sensitive operations like password changes or critical security setting modifications to prevent session fixation.
* **Secure Session Token Storage:** Store session tokens in **secure cookies with the HttpOnly flag** or in the app's secure storage (e.g., iOS Keychain, Android Keystore) instead of web storage (Local Storage, Session Storage).

**Attack Scenarios**

* An attacker uses packet sniffing on a public Wi-Fi network to intercept **unencrypted session tokens** and uses them to gain unauthorized access to a user's account.
* Even after a user logs out of the app, if the server-side **session is not immediately invalidated**, an attacker can reuse the valid session token to log back into the user's account.
* An attacker delivers a pre-generated session ID to a user, and when the user logs in with this ID, the attacker hijacks the session, performing a **Session Fixation** attack.

---

## M7: Insecure Authorization

**Threat Agents**

Attackers who exploit logical flaws in authorization systems, unauthorized users trying to access functions or data, and developers who have incorrectly implemented authorization logic. They attempt **vertical privilege escalation** or **horizontal privilege escalation**.

**Am I Vulnerable?**

* If access to features or data is granted without properly verifying the user's role or permissions.
* If permissions are checked only client-side and not re-validated on the server-side (client-side controls can be easily bypassed).
* If a regular user can access administrative functions or another user's data.
* If an attacker can manipulate URL parameters or hidden fields to perform actions with the privileges of another user or role (e.g., **IDOR, Insecure Direct Object Reference**).

**Prevention**

* **Server-Side Authorization Checks:** All authorization checks **must occur on the server-side**. Client-side checks should only serve a supplementary role for user experience.
* **Principle of Least Privilege:** Grant only the minimum necessary permissions to each user or role.
* **Clear Role-Based Access Control (RBAC) or Attribute-Based Access Control (ABAC) Implementation:** Clearly define and enforce what functions and data a user can access based on their role.
* **Prevent IDOR:** When exposing object IDs in URL parameters or request bodies, always verify the user's permissions and ownership of that object. If possible, use unpredictable **GUIDs (Globally Unique Identifiers)** or enforce that the server only allows access to objects linked to the user's session.
* **Authorization Logic Testing:** Thoroughly test authorization logic for various user roles and scenarios during the development phase.

**Attack Scenarios**

* A regular user modifies **URL parameters (IDOR)** by changing their profile ID to another user's ID, thereby viewing or modifying another user's sensitive information.
* The app checks administrator privileges only on the client-side and not on the server-side, allowing an attacker to **bypass client-side code** and access administrator functions (e.g., deleting users, changing settings).
* Even if a user doesn't have permission to access a specific resource, the app exposes that resource ID when making a request to the server, allowing an attacker to **access unauthorized resources**.

---

## M8: Code Tampering

**Threat Agents**

Malicious attackers, competitors, or those aiming to infringe on intellectual property. They modify the app's code to add unauthorized features, inject malware, bypass security features, or circumvent license checks.

**Am I Vulnerable?**

* If the app's binary can be easily reverse-compiled (decompiled) or reverse-engineered.
* If there's no code integrity check mechanism.
* If the app fails to detect when it's running on a rooted or jailbroken device.
* If the app's core logic or sensitive information (e.g., API keys, encryption keys) is hardcoded into the code.

**Prevention**

* **Code Obfuscation and Optimization:** Obfuscate the app's binary code to make decompilation and reverse engineering difficult. This includes renaming variables, inserting unnecessary code, and obfuscating control flow.
* **Code Integrity Checks:** Include a mechanism for the app to periodically check if its code has been tampered with when it runs. This can be implemented by comparing code hash values.
* **Root/Jailbreak Detection:** Detect if the app is running on a rooted or jailbroken device and either stop sensitive functionality or display a warning message.
* **Anti-Debugging Techniques:** Detect if a debugger is attached to the app and hinder or stop app execution to make it difficult for attackers to analyze the code.
* **No Hardcoding of Important Data:** Avoid hardcoding sensitive information like API keys and encryption keys directly into the code. Instead, use secure key storage (e.g., dynamically load from a server) or encrypt and store them in the app's secure storage.
* **Runtime Protection:** Continuously monitor the code for tampering during app execution and perform appropriate responses (e.g., app termination) if tampering is detected.

**Attack Scenarios**

* An attacker **decompiles the app's binary** to remove license check logic, distributing the paid app for free.
* A malicious hacker modifies the app's code to inject **malware or a backdoor**, then repackages it for distribution on app stores or use in phishing attacks.
* An attacker modifies specific app functions to **bypass security checks** and access sensitive data or features that were originally inaccessible.

---

## M9: Reverse Engineering

**Threat Agents**

Competitors trying to understand the app's source code or internal logic, intellectual property infringers, or malicious hackers looking for security vulnerabilities. They aim to replicate app functionalities or exploit security weaknesses for other attacks.

**Am I Vulnerable?**

* If the app's code is not obfuscated, making it easy to reverse-compile or decompile.
* If the app stores important algorithms or sensitive data on the client-side.
* If API keys or encryption keys are easily identifiable within the app binary.
* If all critical app logic is handled client-side without server-side validation.

**Prevention**

* **Strong Code Obfuscation:** Actively use code obfuscation (as mentioned in M8) to make the app less readable and harder to analyze. Utilize tools like ProGuard/R8 for Android and LLVM optimization for iOS.
* **Defense in Depth:** Don't rely on a single security mechanism; apply multiple layers of security defenses.
* **Client-Server Separation:** All critical business logic and sensitive data processing **must be performed on the server-side**. The client should only serve as a simple user interface.
* **Separate Keys and Sensitive Information:** Avoid hardcoding API keys, encryption keys, and sensitive configuration information into the app binary. Instead, **dynamically load them from a server** or encrypt and store them in the device's secure storage (iOS Keychain, Android Keystore).
* **Anti-Reverse Engineering Techniques:** Apply various anti-reverse engineering techniques like debugger detection, emulator detection, and anti-hooking to make it difficult for analysis tools to be used.
* **Enhanced Binary Protection:** Use commercial solutions or additional binary protection technologies to further complicate app tampering and analysis.

**Attack Scenarios**

* A competitor **reverse-engineers the app** to steal core algorithms or **business logic**, then develops a similar app and releases it to the market.
* An attacker reverse-engineers the app to **find security vulnerabilities (e.g., API keys)** and uses them to gain unauthorized access to the server or launch other attacks.
* A hacker analyzes the app's internal structure to learn how to manipulate specific features and exploits this knowledge to gain **illegal advantages** (e.g., bypassing in-app purchases).

---

## M10: Extraneous Functionality

**Threat Agents**

Developers (e.g., leaving debugging code, backdoors), malicious attackers (exploiting hidden features), or teams that add functionality without proper security testing.

**Am I Vulnerable?**

* If features inserted for development or debugging purposes (e.g., test accounts, admin backdoors, hidden APIs) remain in the production build.
* If the app requests excessive permissions (e.g., camera, microphone, location) that are not required for its actual functionality.
* If unused or disabled code paths contain sensitive information or vulnerable logic.
* If third-party libraries or SDKs include unnecessary or potentially risky features.

**Prevention**

* **Code Review and Static/Dynamic Analysis:** Before release, perform code reviews to ensure that unnecessary or sensitive debugging code, test code, hidden backdoors, etc., have been removed. Use **Static/Dynamic Application Security Testing (SAST/DAST) tools** to identify potential extraneous functionalities.
* **Request Minimum Necessary Permissions:** Only request the minimum permissions required for the app's functionality. Excessive permission requests can lead to user distrust and expand the attack surface.
* **Remove Unnecessary Code:** In production builds, remove all unused code, libraries, and resources to reduce app size and potential vulnerabilities.
* **API and Feature Restrictions:** Clearly define the APIs that client apps can access and rigorously validate API calls on the server. Disable or remove APIs that are not used by the client.
* **Third-Party Library Validation:** Conduct security audits on all third-party libraries and SDKs used, ensuring they don't contain unnecessary or malicious functionalities.

**Attack Scenarios**

* A **hardcoded administrator account** inserted by a developer for testing purposes remains in the production app, allowing an attacker to gain unauthorized access to the system.
* The app contains a **hidden API for debugging purposes**, which an attacker discovers and uses to manipulate the app's internal state or extract sensitive information.
* The app has a permission to access the user's **location information** unnecessarily, allowing a malicious attacker to track the user's location using this permission.

---

# 모바일 보안의 숨겨진 위험: Top 10 리스크 완벽 가이드
## M1: 부적절한 플랫폼 사용 (Improper Platform Usage)

**Threat Agents (위협 행위자)**

이 위협은 플랫폼 기능의 오용 또는 플랫폼 보안 제어 기능을 사용하지 않아서 발생합니다. 예를 들어, Android 인텐트(Intents), TouchID 오용, 플랫폼 권한 설정 오류, iOS 키체인(Keychain) 오용 등이 포함될 수 있습니다. 주로 개발자가 플랫폼 가이드라인을 제대로 따르지 않거나 의도치 않은 오용으로 인해 발생합니다.

**Vulnerable and Prevent (취약점 및 예방)**

* **Android 인텐트:** 안드로이드 인텐트는 운영 체제 내에서 다양한 활동 간의 통신을 허용하는 메시징 객체입니다. 이러한 작업에는 백그라운드 서비스와의 통신, 모바일 기기 또는 다른 앱의 서버에 저장된 데이터 접근, 다른 앱 열기와 같은 활동의 시작과 종료가 포함됩니다. 메시지 교환 중에 데이터 유출 가능성이 생깁니다.
    * **예방:** 권한 제어를 통해 다른 앱과 통신할 수 있는 앱을 제한하고, 허용되지 않은 트래픽의 모든 시도를 차단해야 합니다. `android:exported="false"` 옵션을 통해 다른 앱과 통신할 이유가 없는 컴포넌트를 보호할 수 있습니다. 또한, 스니핑(Sniffing) 공격을 막기 위해 인텐트 객체의 정의를 명확히 하는 **명시적 인텐트(Explicit Intent)**를 사용하여 제어할 수 있습니다. 이를 통해 모든 컴포넌트가 인텐트에 포함된 정보에 접근하는 것을 차단합니다.

* **iOS 키체인:** iOS 키체인은 사용자가 서드파티 계정을 모바일에서 안전하게 사용할 수 있도록 돕습니다. iOS 개발자는 자체 암호화 방법을 도입할 필요 없이 키체인 암호화를 사용할 수 있습니다. 사용자가 키체인 옵션을 선택하지 않으면 쉬운 암호를 선택하는 경향이 있으며 해커에 의해 악용되기 쉽습니다.
    * **예방:** 키체인 암호화는 서버를 통한 동기화 대신, 하나의 기기에만 보관하여 사용하도록 권장됩니다. **접근 제어 목록(Access Control List, ACL)**을 가져야 하는 앱의 비밀 정보를 저장하기 위해 키체인을 사용하여 앱을 보호하는 것이 좋습니다.

---

## M2: 안전하지 않은 데이터 저장 (Insecure Data Storage)

**Threat Agents (위협 행위자)**

공격자는 휴대폰을 줍거나 훔쳐서 물리적인 접근을 하거나, 악성코드(Malware) 또는 다른 재패키징된 앱(Repackaged App)을 사용하여 기기 내에 접근할 수 있습니다. 물리적 접근의 경우, 기기를 컴퓨터에 연결하여 파일 시스템에 접근할 수 있으며, 무료로 제공되는 소프트웨어를 통해 서드파티 애플리케이션 디렉터리 및 개인 식별 정보(PII)에 접근할 수 있습니다.

**Vulnerable and Prevent (취약점 및 예방)**

SQL 데이터베이스, 로그 파일, XML 데이터 저장소, 쿠키, SD 카드 등에 안전하지 않게 저장된 데이터, 혹은 의도치 않았지만 운영 체제, 프레임워크, 컴파일러 환경 등에서도 데이터 유출이 일어날 수 있습니다. 또한 개발자가 기기 내에서 캐시 데이터, 이미지, 키 클릭 및 버퍼를 어떻게 저장하는지 등을 제대로 알지 못해 발생하는 문제이기도 합니다.

* **예방:** iOS의 경우 iGoat와 같이 의도적으로 취약하게 만들어진 모바일 앱을 사용하여 이러한 취약점에 대한 이해를 높이고, 안드로이드 개발자는 **ADB 쉘(Android Debug Bridge Shell)**을 사용하여 대상 앱의 파일 권한을 확인하거나, `logcat`과 같은 명령을 제공하여 개발자가 안드로이드에 포함된 민감한 정보가 유출되는지 여부를 확인할 수 있습니다. 개발 초기 단계부터 **위협 모델링(Threat Modeling)**을 수행하여 잠재적인 데이터 저장 취약점을 식별하고 해결하는 것이 매우 중요합니다.

---

## M3: 안전하지 않은 통신 (Insecure Communication)

**Threat Agents (위협 행위자)**

모바일 앱 간의 데이터 전송은 일반적으로 통신사 네트워크를 통해 이루어집니다. 위협 행위자는 이러한 네트워크를 가로질러 민감한 데이터를 가로채는 공격을 시도할 것입니다. 로컬 네트워크를 공유하는 공격자, 통신사 또는 네트워크 장비, 그리고 모바일 폰의 악성코드 등이 주요 위협 요소가 됩니다.

**Am I Vulnerable? (취약점 존재 여부 확인)**

데이터가 안전하지 않은 방식으로 한 지점에서 다른 지점으로 이동하는 모든 측면에서 취약점이 발견될 수 있습니다. 모바일-모바일, 앱-서버, 또는 모바일-기타 장치에 해당하는 모든 통신과 관련이 있으며, TCP/IP, Wi-Fi, Bluetooth, NFC, GSM, SMS, 3G 등 모든 네트워크 통신 기술과 연관되어 있습니다. 암호 키, 비밀번호, 개인 정보, 세션 토큰, 메타데이터, 바이너리 등 민감한 데이터를 전송할 때 문제가 생길 수 있습니다. 데이터가 전송 중에 변경될 수 있고 변경 사항을 감지할 수 없는 경우 이 취약점이 존재합니다.

**Prevention (예방)**

일반적인 방법으로는 다음과 같은 방법이 있습니다:

* 네트워크 계층이 안전하지 않고 도청에 취약하다고 가정합니다.
* 민감한 데이터를 다른 곳에 보낼 때는 **SSL/TLS**를 적용합니다.
* **강력한 표준 암호화(Strong Cryptographic Standard)**를 사용합니다.
* 자체 서명된 인증서(Self-Signed Certificate)를 허용하지 말고 신뢰할 수 있는 CA(Certificate Authority) 발행자의 인증서만 사용합니다.
* SSL 체인을 확인합니다.
* SSL 채널에 데이터를 보내기 전에 별도의 암호화를 적용하면 더욱 좋습니다.

**iOS 예방:** iOS 최신 버전의 기본 클래스는 SSL 암호 강도를 잘 처리합니다. 개발자가 이러한 기본값을 우회하는 코드를 일시적으로 추가할 때 문제가 발생합니다.

* 모든 인증서가 제대로 유효한지 확인합니다.
* `CFNetwork`를 사용할 때 신뢰할 수 있는 사용자의 인증서를 확인하는 Secure Transport API 사용을 고려합니다.
* 모든 `NSURL` 호출이 자체 인증서나 유효하지 않은 인증서를 사용하지 않는지 점검합니다.

**Android 예방:** 안드로이드의 경우, 개발 당시 모든 인증서를 허용했던 `org.apache.http.conn.ssl.AllowAllHostnameVerifier`와 같은 코드를 제거해야 합니다. 그렇지 않으면 모든 인증서를 허용하는 것과 같은 취약점을 발생시킵니다. 또한 `SSLSocketFactory`를 사용하는 클래스가 있는 경우 반드시 적절하게 서버 인증서를 확인하고 있는지 체크해야 합니다.

**Attack Scenarios (공격 시나리오)**

* 모바일 애플리케이션이 서버에서 제공하는 인증서를 검사하지 못한 채로 TLS 핸드셰이크를 통해 보안 채널을 구축합니다. 애플리케이션이 단순히 서버에서 인증서를 제공했다면 무조건 수락을 해버립니다. 이럴 경우 **TLS 프록시 서버(TLS proxy server)**를 통한 **MITM(Man-In-The-Middle)** 공격에 취약하게 됩니다.
* 핸드셰이크 과정에서 취약한 암호 스위트(Cipher Suite)를 사용하도록 협상하여 모바일 앱과 엔드포인트 간의 기밀성(Confidentiality)을 위태롭게 만듭니다.
* 모바일 앱이 SSL 대신 비보안 채널로 정보를 주고받아 민감한 데이터 유출에 대한 위험을 드러냅니다.

---

## M4: 의도하지 않은 데이터 유출 (Unintended Data Leakage)

**Threat Agents (위협 행위자)**

개발자의 부주의로 인해 민감한 데이터가 의도치 않게 노출될 수 있습니다. 여기에는 개발자 실수, 잘못된 구성, 또는 운영 체제나 다른 앱의 기능과 상호작용하는 방식에 대한 이해 부족이 포함됩니다. 악성 앱, 장치 감염, 또는 공격자가 물리적으로 장치에 접근하는 경우에도 발생할 수 있습니다.

**Am I Vulnerable? (취약점 존재 여부 확인)**

앱이 사용자 또는 다른 민감한 데이터를 저장하거나 처리할 때, 파일 시스템, 캐시, 클립보드, 로그 파일, 키보드 캐싱, 스크린샷, 그리고 심지어 푸시 알림(Push Notification)을 통해 데이터가 노출될 수 있습니다. 개발자가 디버깅 목적으로 로그에 민감 정보를 출력하거나, 임시 파일에 중요한 데이터를 저장하고 제대로 삭제하지 않는 경우에도 취약해질 수 있습니다.

**Prevention (예방)**

* **민감 데이터 로깅 금지:** 개발 및 운영 환경에서 민감한 정보를 로그에 기록하지 않도록 합니다. 반드시 필요한 경우 암호화하거나 마스킹 처리합니다.
* **파일 시스템 권한 관리:** 앱이 저장하는 모든 파일에 대해 적절한 접근 권한을 설정하여 다른 앱이나 사용자가 접근할 수 없도록 합니다.
* **클립보드 데이터 관리:** 앱이 종료되거나 백그라운드로 전환될 때 클립보드에 남아있는 민감한 데이터를 즉시 삭제하도록 구현합니다.
* **캐시 데이터 보호:** 사용자 인증 정보나 민감한 세션 데이터는 캐시에 저장하지 않거나, 저장 시 강력한 암호화를 적용합니다.
* **스크린샷 방지:** 민감한 정보가 표시되는 화면에서는 스크린샷 기능을 비활성화하거나, 스크린샷이 저장되지 않도록 처리합니다. (예: Android의 `FLAG_SECURE`, iOS의 `UIScreen.main.bounds`를 이용한 뷰 캡처 방지)
* **푸시 알림 내용 최소화:** 푸시 알림에는 최소한의 정보만 포함하고, 민감한 내용은 앱 내에서 확인하도록 유도합니다.

**Attack Scenarios (공격 시나리오)**

* 공격자가 사용자의 장치에 접근하여 앱의 **로그 파일**에서 사용자 이름, 비밀번호 또는 신용카드 번호와 같은 민감한 정보를 추출합니다.
* 사용자가 민감한 정보를 **클립보드**에 복사한 후, 악성 앱이 클립보드의 내용을 읽어 데이터를 탈취합니다.
* 디버깅 모드에서 앱이 실행될 때, 개발자가 **화면 스크린샷** 기능을 비활성화하지 않아 공격자가 민감한 화면 내용을 캡처할 수 있습니다.
* 앱이 **푸시 알림**을 통해 OTP(일회성 비밀번호)나 금융 거래 정보를 직접 전송하여, 알림이 노출될 경우 정보가 유출됩니다.

---

## M5: 약한 인증 (Weak Authentication)

**Threat Agents (위협 행위자)**

인증 메커니즘의 취약점을 악용하는 공격자, 크리덴셜 스터핑(Credential Stuffing) 공격자, 무차별 대입 공격(Brute Force Attack)을 시도하는 해커 등이 있습니다. 또한, 구현 오류나 정책 미준수로 인해 개발자가 스스로 취약점을 만들 수도 있습니다.

**Am I Vulnerable? (취약점 존재 여부 확인)**

* 간단하고 예측 가능한 비밀번호 사용을 허용하는 경우
* 너무 짧은 비밀번호 정책 또는 특수문자/숫자 사용을 강제하지 않는 경우
* 계정 잠금 정책이 없거나 너무 관대한 경우
* 인증 시도를 제한하지 않아 무차별 대입 공격에 취약한 경우
* 로그인 페이지에서 민감한 오류 메시지(예: 사용자 이름이 존재하지 않거나, 비밀번호가 틀렸습니다)를 노출하여 계정 열거(Account Enumeration) 공격을 돕는 경우
* 다단계 인증(MFA)을 사용하지 않거나, MFA 구현이 취약한 경우 (예: OTP가 너무 짧거나, 재사용 가능한 경우)

**Prevention (예방)**

* **강력한 비밀번호 정책:** 최소 길이, 대소문자, 숫자, 특수문자 조합을 강제하는 복잡한 비밀번호 정책을 적용합니다.
* **계정 잠금 및 속도 제한:** 일정 횟수 이상 로그인 실패 시 계정을 잠그거나, 로그인 시도에 대한 속도 제한을 적용하여 무차별 대입 공격을 방지합니다.
* **다단계 인증(MFA):** 가능한 모든 경우에 다단계 인증을 도입하여 보안을 강화합니다.
* **안전한 비밀번호 저장:** 비밀번호는 평문으로 저장하지 않고, 솔트(Salt)를 포함한 강력한 해싱(Hashing) 알고리즘(예: bcrypt, scrypt, Argon2)을 사용하여 저장합니다.
* **세션 관리:** 세션 토큰은 안전하게 생성하고, 유효 기간을 짧게 설정하며, 로그아웃 시 즉시 만료시키도록 합니다.
* **OAuth/OpenID Connect 사용:** 직접 인증 시스템을 구현하기보다는 검증된 표준 인증 프로토콜(OAuth 2.0, OpenID Connect)을 사용합니다.
* **생체 인증(Biometric Authentication) 활용:** TouchID, FaceID와 같은 기기 내 생체 인증 기능을 활용하여 사용자 편의성과 보안을 동시에 높입니다. 단, 생체 인증은 보조적인 수단으로 활용하고, 강력한 비밀번호 기반의 인증을 병행해야 합니다.

**Attack Scenarios (공격 시나리오)**

* 공격자가 취약한 비밀번호 정책을 이용하여 무차별 대입 공격을 시도하거나, 유출된 다른 서비스의 사용자 이름과 비밀번호를 이용하여 **크리덴셜 스터핑** 공격을 통해 사용자 계정을 탈취합니다.
* 앱의 로그인 페이지가 "사용자 이름이 존재하지 않습니다"와 같은 구체적인 오류 메시지를 반환하여, 공격자가 유효한 사용자 이름을 **열거**할 수 있도록 합니다.
* MFA가 설정되어 있음에도 불구하고, OTP가 SMS로 평문 전송되거나, 너무 짧은 유효 시간을 가지고 있어 공격자가 **재사용**하거나 가로챌 기회를 얻습니다.

---

## M6: 부적절한 세션 관리 (Improper Session Handling)

**Threat Agents (위협 행위자)**

세션 토큰을 탈취하거나 재사용하려는 공격자, 세션 고정(Session Fixation) 공격을 시도하는 해커, 그리고 세션 관리를 위한 코드를 잘못 구현한 개발자가 포함됩니다.

**Am I Vulnerable? (취약점 존재 여부 확인)**

* 세션 토큰이 URL에 노출되거나, HTTP 헤더가 아닌 다른 곳에 저장되는 경우
* 세션 토큰의 수명이 너무 길어 만료되지 않는 경우
* 사용자 로그아웃 시 세션 토큰이 즉시 무효화되지 않는 경우
* 네트워크 스니핑에 취약한 비보안 채널을 통해 세션 토큰이 전송되는 경우
* 새로운 세션이 시작될 때마다 고유하고 예측 불가능한 세션 ID를 생성하지 않는 경우
* 세션 ID가 고정되어 공격자가 미리 생성된 세션 ID를 사용자에게 할당하는 세션 고정 공격에 취약한 경우

**Prevention (예방)**

* **안전한 세션 토큰 생성:** 세션 토큰은 예측 불가능하고 충분히 긴 길이로 생성되어야 하며, 암호학적으로 강력한 난수를 기반으로 해야 합니다.
* **HTTPS 사용:** 모든 세션 토큰 전송은 **HTTPS(HTTP Secure)**를 통해 암호화된 채널로 이루어져야 합니다.
* **세션 수명 관리:** 세션은 짧은 유효 기간을 가지고, 일정 시간 동안 활동이 없으면 자동으로 만료되도록 설정합니다.
* **로그아웃 시 즉시 무효화:** 사용자가 로그아웃하면 서버 측에서 즉시 해당 세션을 무효화해야 합니다.
* **세션 토큰 재생성:** 비밀번호 변경, 중요한 보안 설정 변경 등 민감한 작업 후에는 새로운 세션 토큰을 발급하여 세션 고정을 방지합니다.
* **세션 토큰 저장 방식:** 세션 토큰은 웹 스토리지(Local Storage, Session Storage) 대신 **HttpOnly 속성이 설정된 보안 쿠키**에 저장하거나, 앱의 보안 저장소(예: iOS Keychain, Android Keystore)에 저장합니다.

**Attack Scenarios (공격 시나리오)**

* 공격자가 공개 Wi-Fi 네트워크에서 패킷 스니핑을 통해 **암호화되지 않은 세션 토큰**을 가로채고, 이를 이용하여 사용자의 계정에 무단으로 접근합니다.
* 사용자가 앱에서 로그아웃했음에도 불구하고, 서버 측에서 **세션이 즉시 무효화되지 않아** 공격자가 유효한 세션 토큰을 재사용하여 사용자 계정에 다시 로그인합니다.
* 공격자가 미리 생성된 세션 ID를 사용자에게 전달하고, 사용자가 이 세션 ID로 로그인하면 공격자가 해당 세션을 탈취하여 **세션 고정(Session Fixation)** 공격을 수행합니다.

---

## M7: 안전하지 않은 권한 부여 (Insecure Authorization)

**Threat Agents (위협 행위자)**

인가 시스템의 논리적 오류를 악용하는 공격자, 비인가된 기능이나 데이터에 접근하려는 사용자, 그리고 권한 부여 로직을 잘못 구현한 개발자가 있습니다. 수직적 권한 상승(Vertical Privilege Escalation) 또는 수평적 권한 상승(Horizontal Privilege Escalation)을 시도합니다.

**Am I Vulnerable? (취약점 존재 여부 확인)**

* 사용자의 역할이나 권한을 제대로 확인하지 않고 기능이나 데이터에 대한 접근을 허용하는 경우
* 클라이언트 측에서만 권한을 검사하고 서버 측에서 다시 검증하지 않는 경우 (클라이언트 측 통제는 쉽게 우회될 수 있음)
* 일반 사용자가 관리자 기능에 접근하거나, 다른 사용자의 데이터에 접근할 수 있는 경우
* URL 매개변수나 숨겨진 필드를 조작하여 다른 사용자 또는 역할의 권한으로 작업을 수행할 수 있는 경우 (예: IDOR, Insecure Direct Object Reference)

**Prevention (예방)**

* **서버 측 권한 확인:** 모든 권한 검사는 반드시 **서버 측에서** 이루어져야 합니다. 클라이언트 측 검사는 사용자 경험을 위한 보조적인 역할만 해야 합니다.
* **최소 권한의 원칙:** 각 사용자 또는 역할에게 필요한 최소한의 권한만 부여합니다.
* **명확한 역할 기반 접근 제어(RBAC) 또는 속성 기반 접근 제어(ABAC) 구현:** 사용자의 역할에 따라 접근 가능한 기능과 데이터를 명확히 정의하고 강제합니다.
* **IDOR 방지:** 객체 ID를 URL 매개변수나 요청 본문에 노출할 때는 사용자의 권한과 해당 객체에 대한 소유권을 항상 검증합니다. 가능하면 예측 불가능한 GUID(Globally Unique Identifier)를 사용하거나, 서버에서 사용자 세션에 연결된 객체만 접근하도록 강제합니다.
* **권한 부여 로직 테스트:** 개발 단계에서 다양한 사용자 역할과 시나리오에 대한 권한 부여 테스트를 철저히 수행합니다.

**Attack Scenarios (공격 시나리오)**

* 일반 사용자가 자신의 프로필 ID를 다른 사용자의 ID로 변경하여 **URL 매개변수(IDOR)**를 조작함으로써, 다른 사용자의 민감한 정보를 열람하거나 수정합니다.
* 앱이 클라이언트 측에서만 관리자 권한을 확인하고 서버 측에서 다시 확인하지 않아, 공격자가 **클라이언트 측 코드를 우회**하여 관리자 기능(예: 사용자 삭제, 설정 변경)에 접근합니다.
* 사용자가 특정 리소스에 접근할 수 있는 권한이 없는데도 불구하고, 앱이 서버에 요청을 보낼 때 해당 리소스 ID를 노출하여 공격자가 **비인가된 리소스에 접근**할 수 있도록 합니다.

---

## M8: 코드 변조 (Code Tampering)

**Threat Agents (위협 행위자)**

악의적인 공격자, 경쟁사, 또는 지적 재산을 침해하려는 자 등이 있습니다. 이들은 앱의 코드를 수정하여 무단 기능 추가, 악성코드 삽입, 보안 기능 우회, 라이선스 검사 우회 등을 시도합니다.

**Am I Vulnerable? (취약점 존재 여부 확인)**

* 앱의 바이너리가 쉽게 역컴파일(Decompile)되거나 리버스 엔지니어링될 수 있는 경우
* 코드 무결성 검사(Code Integrity Check) 메커니즘이 없는 경우
* 앱이 루팅(Rooting)되거나 탈옥(Jailbreaking)된 기기에서 실행될 때 이를 감지하지 못하는 경우
* 앱의 핵심 로직이나 민감한 정보(예: API 키, 암호화 키)가 코드에 하드코딩되어 있는 경우

**Prevention (예방)**

* **코드 난독화(Code Obfuscation) 및 최적화:** 앱 바이너리 내의 코드를 난독화하여 역컴파일 및 리버스 엔지니어링을 어렵게 만듭니다. 이는 변수 이름 변경, 불필요한 코드 삽입, 제어 흐름 난독화 등을 포함합니다.
* **코드 무결성 검사:** 앱이 실행될 때 자신의 코드가 변조되었는지 주기적으로 검사하는 메커니즘을 포함합니다. 이는 코드의 해시 값을 비교하는 방식으로 구현할 수 있습니다.
* **루팅/탈옥 감지:** 앱이 루팅되거나 탈옥된 기기에서 실행될 경우 이를 감지하고, 민감한 기능의 실행을 중단하거나 경고 메시지를 표시합니다.
* **안티-디버깅(Anti-Debugging) 기술:** 디버거가 앱에 연결되는 것을 감지하고 앱 실행을 방해하거나 중단하여, 공격자가 코드를 분석하는 것을 어렵게 만듭니다.
* **중요 데이터 하드코딩 금지:** API 키, 암호화 키 등 민감한 정보는 코드에 직접 하드코딩하지 않고, 안전한 키 저장소(예: 서버에서 동적으로 로드)를 사용하거나, 앱의 보안 저장소에 암호화하여 저장합니다.
* **런타임 보호(Runtime Protection):** 앱이 실행되는 동안 지속적으로 코드 변조 여부를 모니터링하고, 변조가 감지되면 적절한 대응(예: 앱 종료)을 수행합니다.

**Attack Scenarios (공격 시나리오)**

* 공격자가 앱의 **바이너리를 역컴파일**하여 라이선스 검사 로직을 제거하고, 유료 앱을 무료로 배포합니다.
* 악성 해커가 앱의 코드를 변조하여 **악성코드나 백도어(Backdoor)**를 삽입한 후, 재패키징하여 앱 스토어에 배포하거나 피싱 공격에 사용합니다.
* 공격자가 앱의 특정 기능을 수정하여 **보안 검사를 우회**하고, 원래는 접근할 수 없었던 민감한 데이터나 기능에 접근합니다.

---

## M9: 리버스 엔지니어링 (Reverse Engineering)

**Threat Agents (위협 행위자)**

앱의 소스 코드나 내부 로직을 이해하려는 경쟁사, 지적 재산 침해자, 또는 보안 취약점을 찾으려는 악의적인 해커 등이 있습니다. 이들은 앱의 기능을 복제하거나, 보안 취약점을 악용하여 다른 공격을 준비합니다.

**Am I Vulnerable? (취약점 존재 여부 확인)**

* 앱의 코드가 난독화되어 있지 않아 쉽게 역컴파일되거나 디컴파일될 수 있는 경우
* 앱이 중요한 알고리즘이나 민감한 데이터를 클라이언트 측에 저장하는 경우
* API 키나 암호화 키가 앱 바이너리에 쉽게 식별될 수 있는 형태로 포함된 경우
* 앱의 중요 로직이 클라이언트 측에서 모두 처리되어 서버 측 검증이 없는 경우

**Prevention (예방)**

* **강력한 코드 난독화:** M8에서 언급된 코드 난독화를 적극적으로 사용하여 앱의 가독성을 떨어뜨리고 분석을 어렵게 만듭니다. 특히 Android의 ProGuard/R8, iOS의 LLVM 최적화와 같은 도구를 활용합니다.
* **심층 방어(Defense in Depth):** 단일 보안 메커니즘에 의존하지 않고, 여러 계층의 보안 방어를 적용합니다.
* **클라이언트-서버 분리:** 중요한 비즈니스 로직과 민감한 데이터 처리는 반드시 **서버 측에서** 수행하도록 합니다. 클라이언트는 단순한 사용자 인터페이스 역할만 하도록 설계합니다.
* **키 및 민감 정보 분리:** API 키, 암호화 키, 민감한 구성 정보 등은 앱 바이너리에 하드코딩하지 않고, **서버에서 동적으로 로드**하거나, 기기 내의 안전한 저장소(iOS Keychain, Android Keystore)에 암호화하여 저장합니다.
* **안티-리버스 엔지니어링 기술:** 디버거 감지, 에뮬레이터 감지, 후킹(Hooking) 방지 등 다양한 안티-리버스 엔지니어링 기술을 적용하여 분석 도구의 사용을 어렵게 만듭니다.
* **강화된 바이너리 보호:** 상업용 솔루션 또는 추가적인 바이너리 보호 기술을 사용하여 앱의 위변조 및 분석을 더욱 어렵게 만듭니다.

**Attack Scenarios (공격 시나리오)**

* 경쟁사가 앱을 리버스 엔지니어링하여 핵심 알고리즘이나 **비즈니스 로직을 탈취**하고, 유사한 기능을 가진 앱을 개발하여 시장에 출시합니다.
* 공격자가 앱을 리버스 엔지니어링하여 **보안 취약점(예: API 키)을 찾아내고**, 이를 이용하여 서버에 무단으로 접근하거나 다른 공격을 시도합니다.
* 해커가 앱의 내부 구조를 분석하여 특정 기능을 조작하는 방법을 알아내고, 이를 악용하여 **불법적인 이득**을 취합니다 (예: 인앱 구매 우회).

---

## M10: 불필요한 기능 (Extraneous Functionality)

**Threat Agents (위협 행위자)**

개발자(디버깅 코드, 백도어 등), 악의적인 공격자(숨겨진 기능 악용), 또는 보안 테스트를 수행하지 않고 기능만 추가하는 팀이 있습니다.

**Am I Vulnerable? (취약점 존재 여부 확인)**

* 개발 또는 디버깅 목적으로 삽입된 기능(예: 테스트 계정, 관리자 백도어, 숨겨진 API)이 프로덕션 빌드에 남아 있는 경우
* 앱이 실제 기능에 필요하지 않은 권한(예: 카메라, 마이크, 위치)을 과도하게 요청하는 경우
* 사용되지 않거나 비활성화된 코드 경로에 민감한 정보가 포함되어 있거나, 취약한 로직이 포함된 경우
* 타사 라이브러리나 SDK에 불필요하거나 잠재적으로 위험한 기능이 포함된 경우

**Prevention (예방)**

* **코드 검토 및 정적/동적 분석:** 릴리스 전에 코드 검토를 통해 불필요하거나 민감한 디버깅 코드, 테스트 코드, 숨겨진 백도어 등이 제거되었는지 확인합니다. **정적/동적 분석 도구(SAST/DAST)**를 사용하여 잠재적인 불필요한 기능을 식별합니다.
* **필요 최소한의 권한 요청:** 앱의 기능에 필요한 최소한의 권한만 요청하도록 합니다. 과도한 권한 요청은 사용자의 불신을 초래하고 공격 표면을 넓힙니다.
* **불필요한 코드 제거:** 프로덕션 빌드에서는 사용되지 않는 모든 코드, 라이브러리, 리소스를 제거하여 앱의 크기를 줄이고, 잠재적인 취약점을 줄입니다.
* **API 및 기능 제한:** 클라이언트 앱이 접근할 수 있는 API를 명확히 정의하고, 서버에서 해당 API 호출에 대한 권한 검증을 철저히 합니다. 클라이언트에서 사용되지 않는 API는 비활성화하거나 제거합니다.
* **타사 라이브러리 검증:** 사용하는 모든 타사 라이브러리 및 SDK에 대한 보안 감사를 수행하고, 불필요하거나 악의적인 기능이 없는지 확인합니다.

**Attack Scenarios (공격 시나리오)**

* 개발자가 테스트 목적으로 삽입한 **하드코딩된 관리자 계정**이 프로덕션 앱에 남아있어, 공격자가 이를 이용하여 시스템에 무단으로 접근합니다.
* 앱에 **디버깅 목적의 숨겨진 API**가 포함되어 있어, 공격자가 이를 발견하고 앱의 내부 상태를 조작하거나 민감한 정보를 추출합니다.
* 앱이 불필요하게 **사용자의 위치 정보**에 접근하는 권한을 가지고 있어, 악의적인 공격자가 해당 권한을 이용하여 사용자 위치를 추적합니다.