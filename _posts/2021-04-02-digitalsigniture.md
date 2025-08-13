---
title: Digital Signatures and Certificates
tags: Digital-Signature Cryptography Cybersecurity PKI
key: page-digital_signature
categories: [Cybersecurity, Cryptography]
author: hyoeun
math: true
mathjax_autoNumber: true
---

## **Everything About Digital Signatures and Certificates: A Complete Guide to PKI**

Today, we exchange vast amounts of information online. But how can we be sure that this data truly comes from a trusted party and hasn't been intercepted or tampered with along the way? The technologies developed to solve this very problem are the **Digital Signature** and the **Digital Certificate**, and the overarching system that governs them is the **Public Key Infrastructure (PKI)**.

In this article, we will take an in-depth look at how these core elements work together organically to build trust in the digital world.

-----

### **1. What is a Digital Signature? - Ensuring Data Integrity and Authenticity**

In the digital realm, a digital signature performs a role similar to a seal or handwritten signature on a physical contract. Through a digital signature, we can guarantee the following three things:

  * **Integrity:** Ensures that the message has not been altered during transmission.
  * **Authentication:** Proves that the sender of the message is who they claim to be.
  * **Non-repudiation:** Prevents the sender from later denying that they sent the message.

**The Process of Creating and Verifying a Digital Signature**

**[Signature Creation Process - The Sender]**

1.  **Generate a Message Digest:** The sender takes the original message and puts it through a **Hash Function** to create a fixed-length summary, known as a **Message Digest**. A key characteristic of a hash function is that even a minuscule change in the input will produce a completely different output.
2.  **Encrypt with a Private Key:** The generated message digest is then encrypted using the **sender's Private Key**. This encrypted digest is the **Digital Signature**.
3.  **Transmit the Message and Signature:** The original message and the newly created digital signature are sent together to the recipient.

**[Signature Verification Process - The Recipient]**

1.  **Decrypt the Signature:** The recipient decrypts the received digital signature using the **sender's Public Key**. If the decryption is successful, it confirms that the signature was encrypted with the private key corresponding to this public key, thus providing an initial verification of the sender's identity. The result of this decryption is the original message digest.
2.  **Generate a New Digest:** The recipient takes the original message they received and puts it through the **exact same hash function** the sender used to generate a new message digest.
3.  **Compare the Digests:** The digest obtained from decrypting the signature (Step 1) is compared to the digest generated directly from the message (Step 2). If the two values match perfectly, it proves both that the message was not tampered with (integrity) and that it was sent by the legitimate sender (authentication).

-----

### **2. What is a Digital Certificate (X.509)? - A Digital ID that Proves Ownership of a Public Key**

Digital signatures alone leave one critical problem unsolved: How can I trust that the **public key I received truly belongs to the person** it claims to? An attacker could distribute their own public key, pretending it belongs to a legitimate user.

This is where the **Digital Certificate** comes in. A certificate is a type of digital ID card, vouched for by a trusted third party called a **Certificate Authority (CA)**, which certifies that "this public key belongs to this specific individual or entity." Most certificates are created using a standard format called **X.509**.

**Core Components of a Certificate**

  * **Subject:** Information about the certificate's owner. This information is represented in a unique format called a **DN (Distinguished Name)**, with the following key attributes:
      * **CN (Common Name):** The name of the subscriber (e.g., [www.example.com](https://www.example.com))
      * **OU (Organizational Unit Name):** The department or unit name (e.g., IT Department)
      * **O (Organization Name):** The name of the organization (e.g., Example Corp)
      * **DC (Domain Component):** The domain address component (e.g., example)
  * **Issuer:** Information about the Certificate Authority (CA) that issued the certificate.
  * **Public Key:** The public key of the certificate's owner.
  * **Key Usage:** The intended purpose of the key (e.g., for digital signature validation, key encipherment).
  * **Validity:** The start and expiration dates during which the certificate is valid.
  * **Signature:** A value created by hashing the entire content of the certificate (excluding the signature field itself) and then encrypting it with the **Issuer's private key**. This signature is used to verify the authenticity and integrity of the certificate itself.

**Certificate Issuance and Verification Process**

1.  **Key Generation and Application:** A server administrator or user generates their own private/public key pair and submits the public key, along with their identity information, to a CA to apply for a certificate.
2.  **Vetting and Issuance:** The CA verifies the applicant's identity. Upon successful verification, it creates a certificate based on the submitted information and then signs the certificate using the **CA's own private key** before issuing it.
3.  **Verification:** When a client, such as a browser, receives a certificate from a server, it first verifies the signature on the certificate using the **Issuer's public key**. If the signature is successfully decrypted and its contents match the rest of the certificate's information, the client can confirm that the certificate was issued by a trusted CA and has not been tampered with.

<!-- end list -->

  * \<img alt="Certificate Chain Example" src="/assets/images/certificate.png" width="600px"\>

-----

### **3. What is Public Key Infrastructure (PKI)? - The Chain of Trust**

**PKI (Public Key Infrastructure)** does not refer to a single technology. It is a comprehensive system of trust that encompasses all the necessary elements—**roles, policies, hardware, software, and procedures**—for securely issuing, managing, distributing, and revoking digital certificates.

The core of PKI lies in the **Certificate Chain** and the **Chain of Trust**.

  * **Root Certificate Authority (Root CA):** This is the starting point for all trust. Companies like Verisign and GeoTrust are in this category. Their public keys are pre-installed and implicitly trusted by our operating systems and web browsers.
  * **Intermediate Certificate Authority (Intermediate CA):** These CAs are certified by a Root CA and act as a bridge. They exist for security and administrative efficiency and can be structured in multiple layers.
  * **End-entity Certificate:** This is the final certificate issued to a website or an individual user.

When a browser verifies a website's certificate, it checks the certificate of the Intermediate CA that signed it, then checks the certificate of the superior CA that signed the intermediate one, and so on, moving up the chain until it reaches a **Root CA**. If every signature in this chain is valid and the final verification is successfully completed using the public key of a Root CA that the browser already trusts, the website is finally recognized as 'trustworthy'.

In addition to this, a browser performs various other verification checks:

  * **Validity Period Check:** Confirms that the certificate has not expired.
  * **Revocation Status Check:** Checks if the certificate was revoked before its expiration date (e.g., due to a key compromise) using protocols like CRL or OCSP.
  * **Name and Policy Constraints Check:** Examines whether the certificate is being used for a permitted domain name and within its designated policies.
  * **Basic Constraints and Key Usage Check:** Meticulously checks parameters like the maximum length of a certificate chain (Path Length) and whether the key is being used for its intended purpose.

In this way, digital signatures, digital certificates, and PKI interact through a complex and sophisticated process, forming the essential security infrastructure that allows us to navigate the digital world safely.

-----

### **4. Key and Certificate Management: Keystores and File Formats**

Now that we understand the concepts, let's explore how these keys and certificates are actually stored and managed in file formats.

**What is a Keystore?**

A **Keystore** is, as the name implies, a repository for keys. It specifically refers to an encrypted file (or hardware module) that holds sensitive information like **private keys**. The most important feature of a Keystore is that it enhances security by preventing direct access to the stored keys; the keys can only be used through defined operations provided by the Keystore.

**Certificate File Formats: PKCS\#12 and PEM**

Certificates and keys exist in various file formats.

  * **PKCS\#12 (.pfx, .p12):** As one of the Public-Key Cryptography Standards (PKCS), this format is used to **store a private key along with its corresponding certificate chain (Root CA, Intermediate CA certificates, etc.) in a single, password-protected file**. It is commonly used to securely bundle and exchange or back up multiple keys and certificates and is also widely used as a format for Java Keystores. It uses the `.pfx` or `.p12` extension.

  * **PEM (.pem, .crt, .key):** This format stores an X.509 v3 certificate in a Base64 encoded text format. The content is wrapped with a header like `-----BEGIN CERTIFICATE-----` and a footer like `-----END CERTIFICATE-----`, making it easy for humans to read and copy. Certificate files often use the `.pem` or `.crt` extension, while private key files frequently use the `.key` extension.

In conclusion, digital signatures, X.509 certificates, PKI, and management technologies like Keystores all interact through a complex and sophisticated process, forming the core security infrastructure that allows us to navigate the digital world safely.

### **References**

  * [https://m.blog.naver.com/alice\_k106/221468341565](https://m.blog.naver.com/alice_k106/221468341565)

---

## **디지털 서명과 인증서의 모든 것: PKI 완전 정복**

오늘날 우리는 온라인에서 수많은 정보를 주고받습니다. 하지만 이 데이터가 정말 내가 신뢰하는 상대방에게서 온 것인지, 중간에 누가 엿보거나 위변조하지는 않았는지 어떻게 확신할 수 있을까요? 바로 이 문제를 해결하기 위해 등장한 기술이 **전자 서명(Digital Signature)**과 **디지털 인증서(Digital Certificate)**이며, 이 모든 시스템을 아우르는 것이 **공개키 기반 구조(PKI, Public Key Infrastructure)**입니다.

이 글에서는 이 세 가지 핵심 요소가 어떻게 유기적으로 동작하여 인터넷 세상의 신뢰를 구축하는지 심도 있게 알아보겠습니다.

---

### **1. 전자 서명이란? - 데이터의 무결성과 신뢰성 확보**

전자 서명은 서면 계약서에 찍는 인감이나 서명과 유사한 역할을 디지털 세계에서 수행합니다. 전자 서명을 통해 우리는 다음 세 가지를 보장할 수 있습니다.

* **무결성 (Integrity):** 메시지가 전송 도중에 변경되지 않았음을 보장합니다.
* **인증 (Authentication):** 메시지를 보낸 사람이 바로 그 사람임을 증명합니다.
* **부인 방지 (Non-repudiation):** 메시지를 보냈다는 사실을 나중에 부인할 수 없도록 합니다.

**전자 서명의 생성 및 검증 과정**

**[서명 생성 과정 - 송신자]**

1.  **메시지 다이제스트 생성:** 송신자는 전달하려는 원본 메시지(Message)를 **해시 함수(Hash Function)**에 넣어 고정된 길이의 요약본, 즉 **메시지 다이제스트(Message Digest)**를 생성합니다. 해시 함수는 아주 작은 입력값의 변화만으로도 전혀 다른 결과값을 만들어내는 특징이 있습니다.
2.  **개인키로 암호화:** 생성된 메시지 다이제스트를 **송신자의 개인키(Private Key)**로 암호화합니다. 이것이 바로 **전자 서명(Digital Signature)**입니다.
3.  **메시지와 서명 전송:** 원본 메시지와 생성된 전자 서명을 함께 수신자에게 전송합니다.

**[서명 검증 과정 - 수신자]**

1.  **서명 복호화:** 수신자는 함께 전송된 전자 서명을 **송신자의 공개키(Public Key)**로 복호화합니다. 성공적으로 복호화된다면, 이 서명은 해당 공개키와 쌍을 이루는 개인키로 암호화된 것이 확실하므로 송신자의 신원을 1차적으로 확인할 수 있습니다. 복호화 결과로 원본 메시지의 다이제스트가 나옵니다.
2.  **새로운 다이제스트 생성:** 수신자는 함께 받은 원본 메시지를 송신자가 사용한 것과 **동일한 해시 함수**에 넣어 새로운 메시지 다이제스트를 직접 생성합니다.
3.  **다이제스트 비교:** 1번 과정에서 복호화하여 얻은 다이제스트와 2번 과정에서 직접 생성한 다이제스트를 비교합니다. 두 값이 완벽하게 일치한다면, 메시지가 중간에 위변조되지 않았음(무결성)과 송신자가 보낸 것이 맞음(인증)을 모두 증명할 수 있습니다.

---

### **2. 디지털 인증서(X.509)란? - 공개키의 진짜 주인을 증명하는 디지털 신분증**

전자 서명만으로는 한 가지 중요한 문제가 남습니다. 내가 받은 이 **공개키가 정말 그 사람의 것이 맞는지** 어떻게 신뢰할 수 있을까요? 공격자가 자신의 공개키를 마치 정상적인 사용자의 공개키인 것처럼 속여 배포할 수도 있습니다.

이때 필요한 것이 바로 **디지털 인증서**입니다. 인증서는 신뢰할 수 있는 제3의 기관인 **인증 기관(CA, Certificate Authority)**이 "이 공개키는 특정 개인/단체의 것이 맞습니다"라고 보증해주는 일종의 디지털 신분증입니다. 대부분의 인증서는 **X.509**라는 표준 형식으로 만들어집니다.

**인증서의 핵심 구성 요소**

<img alt=" " src="/assets/images/x509_1.png" width="600px" style="display: block;margin-left: auto;margin-right: auto;"> 

* 위의 항목 중 DN형식이 있는데 DN의 항목은 다음과 같다.

<img alt=" " src="/assets/images/x509_2.png" width="600px" style="display: block;margin-left: auto;margin-right: auto;"> 

* **주체 (Subject):** 인증서 소유자의 정보입니다. 이 정보는 **DN(Distinguished Name)**이라는 고유한 형식으로 표현되며, 주요 속성은 다음과 같습니다. 
  * **CN (Common Name):** 가입자의 이름 (예: [www.example.com](https://www.example.com))
  * **OU (Organizational Unit Name):** 소속 부서명 (예: IT Department)
  * **O (Organization Name):** 소속 조직명 (예: Example Corp)
  * **DC (Domain Component):** 도메인 주소 (예: example)
* **발급자 (Issuer):** 인증서를 발급한 인증 기관(CA)의 정보
* **공개키 (Public Key):** 인증서 소유자의 공개키
* **키 용도 (Key Usage):** 해당 키의 사용 목적 (예: 디지털 서명 검증용, 키 암호화용 등)
* **유효 기간 (Validity):** 인증서가 유효한 시작 및 만료 날짜
* **서명 (Signature):** **발급자(Issuer)의 개인키**로 인증서 전체 내용(서명란 제외)을 해시하고 암호화한 값. 이 서명을 통해 인증서 자체의 위변조 여부를 검증할 수 있습니다.

**인증서 발급 및 검증 절차**

1.  **키 생성 및 신청:** 서버 관리자 등은 자신의 개인키/공개키 쌍을 생성하고, 공개키와 자신의 신원 정보를 CA에 제출하여 인증서 발급을 신청합니다.
2.  **심사 및 발급:** CA는 신청자의 신원을 검증한 후, 제출된 정보를 바탕으로 인증서를 생성합니다. 그리고 **CA 자신의 개인키**를 사용해 인증서에 서명하여 발급합니다.
3.  **검증:** 브라우저와 같은 클라이언트는 서버로부터 인증서를 받으면, 먼저 인증서에 있는 **발급자(Issuer)의 공개키**를 이용해 서명을 검증합니다. 만약 서명이 성공적으로 복호화되고, 그 내용이 인증서의 나머지 정보와 일치한다면 이 인증서는 신뢰할 수 있는 CA가 발급한 것이며 위변조되지 않았음을 확인하게 됩니다.

* <img alt=" " src="/assets/images/certificate.png" width="600px">
---

### **3. 공개키 기반 구조(PKI)란? - 신뢰의 사슬**

**PKI (Public Key Infrastructure)**는 단순히 기술 하나를 지칭하는 것이 아닙니다. 디지털 인증서를 안전하게 발급, 관리, 배포, 폐기하는 데 필요한 모든 요소, 즉 **역할, 정책, 하드웨어, 소프트웨어, 절차**를 총칭하는 거대한 신뢰 시스템입니다.

PKI의 핵심은 **인증서 체인(Certificate Chain)**과 **신뢰의 계층 구조(Chain of Trust)**입니다.

* **최상위 인증 기관 (Root CA):** 모든 신뢰의 시작점입니다. Verisign, GeoTrust 같은 회사들이 여기에 속하며, 이들의 공개키는 이미 우리 운영체제나 웹 브라우저에 기본적으로 내장되어 있습니다. 우리는 이들을 무조건 신뢰한다고 가정합니다.
* **중간 인증 기관 (Intermediate CA):** 최상위 CA로부터 인증을 받은 중간 다리 역할을 하는 기관입니다. 보안 및 관리의 효율성을 위해 존재하며, 여러 계층으로 구성될 수 있습니다.
* **사용자 인증서 (End-entity Certificate):** 최종적으로 웹사이트나 개인에게 발급되는 인증서입니다.

브라우저가 어떤 웹사이트의 인증서를 검증할 때는 해당 인증서에 서명한 중간 CA의 인증서를 확인하고, 또 그 중간 CA에 서명한 상위 CA의 인증서를 확인하는 식으로 **최상위 CA(Root CA)에 도달할 때까지** 거슬러 올라갑니다. 이 체인에 속한 모든 서명이 유효하고, 마지막에 브라우저가 이미 신뢰하고 있는 최상위 CA의 공개키로 검증이 완료되면, 해당 웹사이트는 비로소 '신뢰할 수 있음'으로 인정받게 됩니다.

이 외에도 브라우저는 다음과 같은 다양한 검증 절차를 수행합니다.

* **유효 기간 확인:** 인증서의 유효 기간이 지났는지 확인합니다.
* **폐지 여부 확인 (Revocation Status):** 인증서가 만료 전 (예: 키 유출) 폐지되었는지 CRL, OCSP 등의 프로토콜로 확인합니다.
* **이름 및 정책 제약 조건 확인:** 인증서가 허가된 도메인 이름, 정책 내에서 사용되는지 검사합니다.
* **기본 제약 및 키 용도 확인:** 인증서 체인의 최대 길이(Path Length)나 키의 본래 용도에 맞게 사용되는지 등을 꼼꼼히 체크합니다.

이처럼 전자 서명, 디지털 인증서, 그리고 PKI는 복잡하고 정교한 과정을 통해 상호 작용하며, 우리가 안전하게 디지털 세상을 항해할 수 있도록 지켜주는 핵심적인 보안 인프라입니다.



### **4. 키와 인증서의 관리: Keystore와 파일 형식**

개념을 이해했다면, 실제로 이 키와 인증서들이 어떻게 파일 형태로 저장되고 관리되는지 알아볼 차례입니다.

**Keystore란 무엇인가?**

**Keystore**는 이름 그대로 키를 저장하는 창고입니다. 특히 **개인키(Private Key)**와 같이 민감한 정보를 담고 있는 암호화된 파일(또는 하드웨어 모듈)을 의미합니다. Keystore의 가장 중요한 특징은 저장된 키에 직접 접근하는 것을 막고, 오직 Keystore가 제공하는 정해진 연산(operation)을 통해서만 키를 사용할 수 있도록 하여 보안을 강화한다는 점입니다.

**인증서 파일 형식: PKCS\#12와 PEM**

인증서와 키는 다양한 파일 형식으로 존재합니다.

  * **PKCS\#12 (.pfx, .p12):** 공개 키 암호 표준(PKCS) 중 하나로, **개인키와 그에 해당하는 인증서 체인(Root CA, Intermediate CA 인증서 등)을 하나의 파일에 담아 비밀번호로 보호**하는 형식입니다. 여러 개의 키와 인증서를 안전하게 묶어서 교환하거나 백업할 때 주로 사용되며, Java의 Keystore 형식으로도 널리 쓰입니다. `.pfx` 또는 `.p12` 확장자를 가집니다.

  * **PEM (.pem, .crt, .key):** X.509 v3 인증서를 Base64로 인코딩하여 텍스트 형태로 저장하는 형식입니다. `-----BEGIN CERTIFICATE-----`와 같은 머리글과 `-----END CERTIFICATE-----` 같은 꼬리글로 내용이 감싸여 있어 사람이 쉽게 읽고 복사할 수 있습니다. 인증서 파일은 `.pem`이나 `.crt` 확장자를, 개인키 파일은 `.key` 확장자를 사용하는 경우가 많습니다.

이처럼 전자 서명, X.509 인증서, PKI, 그리고 Keystore와 같은 관리 기술들은 복잡하고 정교한 과정을 통해 상호 작용하며, 우리가 안전하게 디지털 세상을 항해할 수 있도록 지켜주는 핵심적인 보안 인프라입니다.

### **참고 자료**

* [https://m.blog.naver.com/alice_k106/221468341565](https://m.blog.naver.com/alice_k106/221468341565)