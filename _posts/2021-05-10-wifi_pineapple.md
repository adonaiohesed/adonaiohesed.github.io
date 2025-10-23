---
title: WiFi Pineapple
tags: WiFi-Pineapple
key: page-wifi_pineapple
categories: [Cybersecurity, Network Security]
author: hyoeun
math: true
mathjax_autoNumber: true
---

### **WiFi Pineapple Analysis: A Threat Exploiting Fundamental Vulnerabilities in Trust-Based Wireless Networks**

Modern wireless network environments have evolved to maximize user convenience. Smartphones and laptops remember the SSIDs (Service Set Identifiers) of previously connected wireless networks and automatically reconnect when those signals are detected, providing a seamless user experience. However, this "trust" mechanism harbors a fundamental flaw in the 802.11 protocol, and a powerful tool that exploits this to automate Man-in-the-Middle (MITM) attacks is the WiFi Pineapple by Hak5. This article provides a deep technical analysis of the core attack principles of the WiFi Pineapple and corresponding defense strategies.

---

### **Core Operating Principles of the WiFi Pineapple**

The WiFi Pineapple essentially operates as a rogue Access Point (AP), a specialized device designed to trick nearby client devices into voluntarily connecting to it. This process goes beyond simple SSID spoofing; it actively exploits vulnerabilities in 802.11 management frames.

#### **1. Probe Request Spoofing and KARMA/MANA Attacks**

When Wi-Fi is enabled, a client device periodically broadcasts **Probe Request** frames to search for SSIDs stored in its PNL (Preferred Network List). For example, a device that has previously connected to a Starbucks Wi-Fi will continuously broadcast Probe Requests searching for "Starbucks_WiFi."

The WiFi Pineapple passively listens for these Probe Requests and then executes a **KARMA attack**, responding to every SSID the client is looking for, essentially saying, "I am that AP." The client device trusts the AP that responds with the strongest signal and attempts to connect automatically. Newer versions of the Pineapple feature an improved technique called the **MANA (Mana Attack)**, which not only responds to the client's Probe Requests but can also identify a specific client's PNL, allowing for more sophisticated AP impersonation and client-tailored attacks.

#### **2. Forcing Connections via Deauthentication Attacks**

A more severe threat is that an attacker can execute this attack regardless of the client's current connection status. If the target is already legitimately connected to a trusted AP, the WiFi Pineapple can forcibly sever this connection using a **Deauthentication attack**.

This attack exploits a critical design flaw in the 802.11 protocol: management frames are not encrypted or authenticated in most environments (including WPA2-Personal). The attacker spoofs the legitimate AP's MAC address and sends a deauthentication frame to the target client. The client, having no reason to distrust this frame, immediately terminates its current connection. Subsequently, when the client attempts to reconnect to the network, it is highly likely to connect to the WiFi Pineapple, which, through the aforementioned MANA attack, presents a stronger signal than the legitimate AP.

---

### **Possible Attack Scenarios After Achieving MITM**

Once all of the client's traffic is routed through the WiFi Pineapple, the attacker gains a powerful position to not only eavesdrop but also actively manipulate the data.

* **DNS Spoofing**: The Pineapple acts as the client's DNS server. When a user requests a legitimate domain (e.g., `bank.com`), the attacker can respond with the IP address of their phishing server, redirecting the user to a fake website to steal credentials.

* **SSL/TLS Stripping**: When a user attempts to connect to an encrypted HTTPS site, the attack intercepts the connection, strips the 'S' from HTTPS, and forcibly downgrades the session to unencrypted HTTP. As a result, all communication between the user and the server is exposed in plaintext. While HSTS (HTTP Strict Transport Security) is a countermeasure, it can be bypassed if it's the client's first time visiting the site.

* **Malware Injection**: When a user downloads an executable file or document, the attacker can inject a malicious payload into the HTTP traffic in real-time. This can be used to distribute ransomware or information-stealing malware.

---

### **Fundamental Defense Strategies**

To counter these threats, it's essential to recognize the protocol's limitations and implement a multi-layered defense strategy.

* **Use a VPN (Virtual Private Network)**: **This is the most effective countermeasure.** A VPN creates an end-to-end encrypted tunnel from the client device to the VPN server. Therefore, even if traffic is intercepted on the local network (the Wi-Fi controlled by the attacker), the attacker can only see encrypted tunnel data and nothing else.

* **Understand 802.11w (Protected Management Frames, PMF)**: This standard provides integrity for key management frames, such as deauthentication frames, thereby preventing spoofing attacks. While modern operating systems and APs support PMF, it is often disabled in public Wi-Fi environments due to compatibility issues, making it an incomplete solution.

* **Strengthen Client-Side Security Settings**:
    * **Disable Automatic Wi-Fi Connections**: Turn off the 'auto-connect to known networks' feature to ensure your device only connects to APs you manually select.
    * **Clean Up Your PNL**: Periodically delete profiles of public Wi-Fi networks you no longer use. This minimizes the exposure of your device's information through Probe Requests.
    * **Heed HTTPS and Browser Security Warnings**: Always check for the lock icon when visiting a website, and never proceed if your browser displays a security warning, such as 'untrusted certificate'.

In conclusion, the WiFi Pineapple clearly demonstrates the dangers of the trust-based mechanisms hidden behind the convenience of wireless networks. It is crucial for defenders to move beyond the concept of blocking a specific tool and instead adopt a security mindset that applies the **Zero Trust** principle—trusting no network—even in a mobile environment.

---

### **WiFi Pineapple 분석: 신뢰 기반 무선 네트워크의 근본적 취약점을 파고드는 위협**

현대의 무선 네트워크 환경은 사용자의 편의성을 극대화하는 방향으로 발전해왔다. 스마트폰과 노트북은 과거에 접속했던 무선 네트워크의 SSID(Service Set Identifier)를 기억하고, 해당 신호가 감지되면 자동으로 재연결하여 끊김 없는 사용자 경험을 제공한다. 그러나 이러한 '신뢰' 메커니즘은 802.11 프로토콜의 근본적인 허점을 내포하고 있으며, 이를 악용하여 중간자 공격(Man-in-the-Middle)을 자동화하는 강력한 도구가 바로 Hak5의 와이파이 파인애플(WiFi Pineapple)이다. 본 글에서는 와이파이 파인애플의 핵심적인 공격 원리와 방어 전략을 기술적으로 심층 분석하고자 한다.

---

### **와이파이 파인애플의 핵심 작동 원리**

와이파이 파인애플은 본질적으로 악의적인 AP(Access Point)로 동작하며, 주변 클라이언트 기기들이 자발적으로 자신에게 접속하도록 유도하는 데 특화된 장비다. 이 과정은 단순히 SSID를 위조하는 것을 넘어, 802.11 관리 프레임(Management Frame)의 취약점을 적극적으로 활용한다.

#### **1. Probe Request 스푸핑과 KARMA/MANA 공격**

클라이언트 기기는 와이파이 기능이 활성화된 상태에서 PNL(Preferred Network List)에 저장된 SSID를 찾기 위해 주기적으로 **Probe Request** 프레임을 브로드캐스팅한다. 예를 들어, 과거 스타벅스 와이파이에 접속한 적이 있는 기기는 "Starbucks_WiFi"를 찾는 Probe Request를 주변에 계속 전송한다.

와이파이 파인애플은 이 Probe Request를 수동적으로 감청하고 있다가, 클라이언트가 찾는 모든 SSID에 대해 "제가 바로 그 AP입니다"라고 응답하는 **KARMA 공격**을 수행한다. 클라이언트 기기는 가장 강한 신호로 응답하는 AP를 신뢰하고 자동으로 접속을 시도하게 된다. 최신 버전의 파인애플은 이를 개선한 **MANA(Mana Attack)** 기술을 탑재하여, 클라이언트의 Probe Request에 대한 응답뿐만 아니라 특정 클라이언트의 PNL 목록을 파악하여 더 정교한 AP 위장 및 클라이언트별 맞춤형 공격을 수행할 수 있다.

#### **2. 인증 해제(Deauthentication) 공격을 통한 강제 연결 유도**

더욱 심각한 위협은 공격자가 클라이언트의 현재 연결 상태와 무관하게 공격을 감행할 수 있다는 점이다. 만약 공격 대상이 이미 신뢰할 수 있는 AP에 정상적으로 연결되어 있다면, 와이파이 파인애플은 **인증 해제(Deauthentication) 공격**을 통해 이 연결을 강제로 끊어버릴 수 있다.

이 공격은 802.11 프로토콜의 관리 프레임이 대부분의 환경(WPA2-Personal 포함)에서 암호화되거나 인증되지 않는다는 치명적인 설계 결함을 이용한다. 공격자는 실제 AP의 MAC 주소로 위장하여 대상 클라이언트에게 인증 해제 프레임을 스푸핑하여 전송한다. 클라이언트는 이 프레임을 신뢰할 수밖에 없으므로 현재 연결을 즉시 종료한다. 이후 네트워크에 재접속하려는 클라이언트는 앞서 설명한 MANA 공격에 의해 진짜 AP보다 더 강한 신호를 보내는 와이파이 파인애플에 연결될 확률이 매우 높아진다.

---

### **중간자(MITM) 확보 후 가능한 공격 시나리오**

일단 클라이언트의 모든 트래픽이 와이파이 파인애플을 경유하게 되면, 공격자는 데이터를 단순히 엿보는 것을 넘어 능동적으로 조작할 수 있는 강력한 위치를 확보하게 된다.

* **DNS 스푸핑(DNS Spoofing)**: 파인애플은 클라이언트의 DNS 서버 역할을 수행한다. 사용자가 정상적인 도메인(예: `bank.com`)을 요청하면, 공격자는 이를 자신의 피싱 서버 IP 주소로 응답하여 사용자를 가짜 웹사이트로 유도하고 자격 증명을 탈취한다.

* **SSL/TLS 스트리핑(SSL/TLS Stripping)**: 사용자가 암호화된 HTTPS 사이트에 접속하려 할 때, 이 연결을 중간에서 가로채 HTTPS의 'S'를 제거하고 강제로 암호화되지 않은 HTTP 세션으로 다운그레이드한다. 그 결과, 사용자와 서버 간의 모든 통신이 평문으로 노출된다. HSTS(HTTP Strict Transport Security)가 이에 대한 방어책이지만, 클라이언트가 해당 사이트에 처음 접속하는 경우에는 무력화될 수 있다.

* **악성코드 주입(Malware Injection)**: 사용자가 실행 파일이나 문서를 다운로드할 때, HTTP 트래픽에 악성 페이로드를 실시간으로 주입하여 전달할 수 있다. 이를 통해 랜섬웨어나 정보 탈취 악성코드를 유포한다.

---

### **근본적인 방어 전략**

이러한 위협에 대응하기 위해서는 프로토콜의 한계를 인지하고 다층적인 방어 전략을 수립해야 한다.

* **VPN(Virtual Private Network)의 활용**: **가장 효과적인 대응책이다.** VPN은 클라이언트 기기에서부터 VPN 서버까지 End-to-End 암호화 터널을 생성한다. 따라서 로컬 네트워크 구간(공격자가 장악한 와이파이)에서 트래픽이 가로채지더라도, 공격자는 암호화된 터널 데이터 외에는 아무것도 볼 수 없다.

* **802.11w (Protected Management Frames, PMF)의 이해**: 이 표준은 인증 해제와 같은 주요 관리 프레임에 대한 무결성을 제공하여 스푸핑 공격을 방지한다. 최신 운영체제와 AP는 PMF를 지원하지만, 공공 와이파이 환경에서는 호환성 문제로 비활성화된 경우가 많아 완벽한 해결책은 아니다.

* **클라이언트 측 보안 설정 강화**:
    * **와이파이 자동 연결 비활성화**: '알려진 네트워크에 자동 연결' 기능을 비활성화하여, 사용자가 명시적으로 선택한 AP에만 접속하도록 설정한다.
    * **불필요한 PNL 목록 제거**: 더 이상 사용하지 않는 공용 와이파이 프로필은 주기적으로 삭제하여 Probe Request를 통해 내 기기 정보가 노출되는 것을 최소화한다.
    * **HTTPS 및 브라우저 보안 경고 주시**: 웹사이트 접속 시 자물쇠 아이콘을 확인하고, 브라우저가 '신뢰할 수 없는 인증서' 등의 보안 경고를 표시할 경우 절대 접속을 강행해서는 안 된다.

결론적으로, 와이파이 파인애플은 무선 네트워크의 편리함 이면에 숨겨진 신뢰 기반 메커니즘의 위험성을 명확히 보여준다. 방어자는 특정 도구를 막는다는 개념을 넘어, 어떠한 네트워크도 신뢰하지 않는다는 **제로 트러스트(Zero Trust)** 원칙을 모바일 환경에서도 적용하는 보안 의식을 갖추는 것이 무엇보다 중요하다.