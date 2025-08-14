---
title: Mobile Platform Security
tags: Mobile-Security
key: page-mobile_platform_security
categories: [Cybersecurity, Mobile Security]
author: hyoeun
math: true
mathjax_autoNumber: true
---

### Mobile Platform Security: A Comparative Analysis of iOS and Android Strategies

In the modern era, smartphones have become more than just communication devices; they are indispensable tools that handle personal information, financial transactions, and sensitive corporate data. Consequently, mobile platform security has become a critical component for protecting user data and maintaining system integrity. This article explores the core principles and threat models of mobile security, and then compares and analyzes how Apple's **iOS** and Google's **Android** reinforce their platform security.

---

### 1. Core Principles and Threat Models of Mobile Platform Security

Mobile platform security is built through a multi-layered defense mechanism. The main objectives are as follows:
* **Data Protection**: Encrypting sensitive data stored on the device to prevent information leaks even with physical access.
* **App Integrity**: Preventing malicious or tampered applications from running.
* **System Integrity**: Protecting the operating system from being modified by attackers.
* **Network Security**: Ensuring that communication between an app and a server is safe from interception or manipulation.

The main types of attacks that threaten these objectives include:
* **Malware**: Malicious apps disguised as legitimate ones to steal user information or take control of the device.
* **Network Attacks**: Man-in-the-Middle attacks that intercept or manipulate communication between an app and a server.
* **Jailbroken/Rooted Devices**: Bypassing operating system restrictions to neutralize security controls.
* **Social Engineering Attacks**: Tricking users through methods like phishing to get them to input sensitive information.

---

### 2. A Comparison of iOS and Android Security Architectures

iOS and Android have different approaches to mobile security. iOS adopts a closed ecosystem with strict controls, whereas Android provides flexibility while offering robust security features.

#### iOS Security Architecture
Apple builds a strong security framework through a closed ecosystem that tightly integrates hardware and software.
* **Hardware-Based Security**: With **Secure Boot**, a chain of trust starting from the Boot ROM ensures that only trusted operating system software signed by Apple is loaded. This is the first line of defense for maintaining device integrity. The **Secure Enclave**, a dedicated chip separate from the main processor, securely creates and stores biometric authentication data for Touch ID and Face ID, as well as encryption keys, ensuring keys are not leaked even if the main OS is compromised.
* **Sandboxing**: A core security model for iOS, where every app runs in its own isolated environment. This prevents apps from accessing data or system resources of other apps, minimizing the impact of an attack.
* **Code Signing**: All apps must be signed with a certificate issued by Apple to be executed. Unsigned or tampered apps are prevented from running, which guarantees app integrity.
* **App Store Review**: Before an app can be published on the App Store, it must go through Apple's strict security review process.

#### Android Security Architecture
Android maintains an open platform while utilizing the powerful security features of the Linux kernel.
* **Linux Kernel and SELinux**: Android is based on the stable Linux kernel. It uses **SELinux (Security-Enhanced Linux)**, a **Mandatory Access Control (MAC)** mechanism, to finely control interactions between processes. This plays a vital role in preventing malicious code from accessing other parts of the system.
* **App Sandbox**: Similar to iOS, each app is assigned a unique User ID (UID) and runs in an isolated process. This acts as a sandbox, preventing one app from accessing the memory or files of another.
* **Permission Model**: Apps need explicit user permission to access sensitive resources like the camera, contacts, or location data.
* **Google Play Protect**: This feature automatically scans apps published on the Google Play Store to detect and remove malicious apps.

---

### 3. Security Advice for Developers

Mobile app developers should consider security from the design phase. Here are essential tips for enhancing app security:
* **Data Encryption**: Always encrypt user data when storing it to reduce the risk of data leaks.
* **Secure Network Communication**: Use **HTTPS** to encrypt communication and implement **SSL/TLS Certificate Pinning** to prevent Man-in-the-Middle attacks.
* **Code Obfuscation and Integrity Checks**: Make reverse engineering difficult and add logic to detect app tampering to protect app integrity.
* **Input Validation**: Always validate user inputs to prevent attacks like **SQL Injection** or **Cross-Site Scripting (XSS)**.

---

### 모바일 플랫폼 보안: iOS와 Android의 전략 비교 분석

현대 사회에서 스마트폰은 단순한 통신 기기를 넘어 개인 정보, 금융 거래, 그리고 기업의 민감한 데이터까지 다루는 필수적인 도구가 되었습니다. 이에 따라 모바일 플랫폼의 보안은 사용자의 데이터를 보호하고 시스템의 무결성을 유지하는 데 있어 핵심적인 요소로 자리 잡았습니다. 이 글에서는 모바일 보안의 주요 원칙, 위협 모델을 살펴보고, Apple의 **iOS**와 Google의 **Android**가 각각 어떤 접근 방식을 통해 플랫폼 보안을 강화하는지 비교 분석하겠습니다.

---

### 1. 모바일 플랫폼 보안의 핵심 원칙과 위협 모델

모바일 플랫폼 보안은 여러 계층의 방어 메커니즘을 통해 구축됩니다. 주요 목표는 다음과 같습니다.
* **데이터 보호**: 기기에 저장된 민감한 데이터를 암호화하여 물리적 접근 시에도 정보가 유출되지 않도록 합니다.
* **앱 무결성**: 악성 코드가 삽입되거나 변조된 앱이 실행되는 것을 방지합니다.
* **시스템 무결성**: 운영 체제가 공격자에 의해 변조되지 않도록 보호합니다.
* **네트워크 보안**: 앱과 서버 간의 통신이 가로채기나 변조로부터 안전하도록 보호합니다.

이러한 목표를 위협하는 주요 공격 유형은 다음과 같습니다.
* **악성 앱(Malware)**: 합법적인 앱으로 위장하여 사용자 정보를 탈취하거나 기기를 제어합니다.
* **네트워크 공격**: 중간자 공격(Man-in-the-Middle)을 통해 앱과 서버 간의 통신을 가로채거나 조작합니다.
* **탈옥/루팅된 기기**: 운영 체제의 제한을 우회하여 보안 제어를 무력화시킵니다.
* **사회 공학 공격**: 피싱(Phishing)과 같은 방식으로 사용자를 속여 민감한 정보를 입력하게 유도합니다.

---

### 2. iOS와 Android의 보안 아키텍처 비교

iOS와 Android는 모바일 보안을 접근하는 방식에 차이가 있습니다. iOS는 폐쇄적인 생태계와 엄격한 통제를 지향하는 반면, Android는 개방성과 유연성을 유지하면서 강력한 보안 기능을 제공합니다.

#### iOS 보안 아키텍처
Apple은 하드웨어와 소프트웨어를 긴밀하게 통합한 폐쇄형 생태계를 통해 강력한 보안을 구축합니다.
* **하드웨어 기반 보안**: 기기 시동 시 부트 ROM(Read-Only Memory)에서부터 시작되는 신뢰 체인을 통해 Apple이 서명한 신뢰할 수 있는 운영체제 소프트웨어만 로드되도록 하는 **보안 시동(Secure Boot)**과, Touch ID 및 Face ID 생체 인증 데이터와 암호화 키를 안전하게 생성하고 저장하는 전용 칩인 **Secure Enclave**를 통해 하드웨어 수준에서 보안을 강화합니다.
* **샌드박싱(Sandboxing)**: 모든 앱은 자체적인 격리된 환경에서 실행됩니다. 이는 앱이 다른 앱의 데이터나 시스템 리소스에 접근하는 것을 막아 공격의 영향을 최소화하는 핵심적인 방어 기술입니다.
* **코드 서명(Code Signing)**: 모든 앱은 Apple이 발급한 인증서로 서명되어야만 실행됩니다. 서명되지 않거나 변조된 앱은 실행되지 않도록 하여 앱의 무결성을 보장합니다.
* **앱스토어 검토**: 앱스토어에 앱을 게시하기 전 Apple의 엄격한 보안 검토 과정을 거칩니다.

#### Android 보안 아키텍처
Android는 개방성을 유지하면서도 Linux 커널의 강력한 기능을 활용하여 시스템을 보호합니다.
* **리눅스 커널 및 SELinux**: Android는 안정적인 Linux 커널을 기반으로 하며, **강제적 접근 제어(Mandatory Access Control, MAC)** 메커니즘인 **SELinux(Security-Enhanced Linux)**를 통해 프로세스 간의 상호 작용을 세밀하게 제어합니다. 이는 악성 코드가 시스템의 다른 부분에 접근하는 것을 방지하는 중요한 역할을 합니다.
* **앱 샌드박스**: iOS와 유사하게 각 앱은 고유한 사용자 ID(UID) 기반의 격리된 프로세스에서 실행됩니다. 이는 한 앱이 다른 앱의 메모리나 파일에 접근하는 것을 막는 샌드박스 역할을 합니다.
* **권한 모델(Permission Model)**: 앱이 카메라, 연락처, 위치 정보 등 민감한 리소스에 접근하려면 사용자에게 명시적인 권한 요청을 해야 합니다.
* **Google Play 프로텍트**: Google Play 스토어에 게시된 앱을 자동으로 스캔하여 악성 앱을 탐지하고 제거하는 기능을 제공합니다.

---

### 3. 개발자를 위한 보안 조언

모바일 앱 개발자는 보안을 설계 단계부터 고려해야 합니다. 다음은 앱의 보안을 강화하기 위한 필수적인 조언입니다.
* **데이터 암호화**: 사용자 데이터를 저장할 때 항상 암호화하여 데이터 유출 위험을 줄입니다.
* **안전한 네트워크 통신**: **HTTPS**를 사용하여 통신을 암호화하고, **SSL/TLS 인증서 고정(Pinning)**을 구현하여 중간자 공격을 방지합니다.
* **코드 난독화 및 무결성 검사**: 리버스 엔지니어링을 어렵게 만들고, 앱 변조를 감지하는 로직을 추가하여 앱의 무결성을 보호합니다.
* **입력값 유효성 검사**: 사용자 입력값을 항상 검증하여 **SQL 인젝션**이나 **XSS(Cross-Site Scripting)**와 같은 공격을 방지합니다.