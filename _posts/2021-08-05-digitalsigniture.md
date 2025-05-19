---
title: Digital Signiture
tags: Digital-Signature Cryptography Cybersecurity
key: page-digital_signature
categories: [Cybersecurity, Cryptography]
author: hyoeun
math: true
mathjax_autoNumber: true
---

## 전자서명 방식
1. 보내는 사람이 메시지를 자신의 private key로 해시한 digest를 message와 함께 보낸다. (message + H(message + key))
1. 받는 사람은 signature(H(message + key))를 보낸 사람의 public key로 decrypt하고 그것을 받은 message의 해시값과 비교한다.
1. 두개가 동일하면 보낸 사람으로 부터 메시지가 왔다는 것이 인증이 된다.

## Certificate
* 인증서 안에는 다음 값이 존재한다.
  * Subject: 해당 인증서를 발급 받은 대상(소유주)
  * Issuer: 인증서를 발행한 대상
  * Key usage: 키의 사용 처(digital signature validation, key encipherment, signing ...)
  * Public key: 해당 Subject의 공개키
  * Signature: Issuer의 private key로 생성한 서명 값(인증서의 내용을 종합해 해시화한 값)
* 인증서를 받기 위해서는 다음과 같은 절차가 필요하다.
  1. 공개키와 비밀키를 만든다.
  1. 공개 키와 자신의 정보를 인증기관에 보내서 인증서 발급 신청을 한다.
  1. 인증기관은 그 정보를 토대로 확인 한 뒤 인증서를 만든다. 이때 인증기관의 비밀키로 서명을 한다.
  1. 인증기관으로부터 인증서를 발급 받았으면 그것을 자신의 서버에 저장한다.
* 인증서를 verification 하는 절차는 다음과 같다. 루트에서부터 검색을 시작한다.
  1. The browser가 인증서의 integrity를 먼저 verifies한다. Normal public key cryptography로 인증서의 signature를 verify할 수 있다.
  1. 다음으로 인증서의 validity(시간 관련)를 확인한다. 인증시간이 지난 것은 reject한다.
  1. The browser checks the certificate's revocation status. 인증서가 자연 만료되기 전 손상이 있을 수 있기에 revocation에 대한 대책이 있는데 이거의 status를 확인한다.
  1. The issuer를 verify한다. 
  1. 다음으로 name constraints를 verify한다. Intermediate CA들은 특정 domain name이나 company name만 이용하도록 limite 걸어 놓은 경우가 있으니깐 그것을 통해서 verify한다.
  1. Policy constraints를 check한다. A certificate policy는 CA에 의해 발행된 법적인 문서이고 어떻게 certificates들을 관리하고 발행하는지에 대한 절차가 적혀 있는 것이다. 하나 이상의 policy를 특정 certificate에 발행 할 수 있는데 certificate를 trust하기전에 이것들을 점검해야한다. 하지만 real world에서 이러한 policy는 잘 없는 편이다.
  1. 기본적인 constraints를 체크한다. 예를들어 path length가 있을 수 있다. X.509 v3 format에는 maximum path length를 설정해놓았는데 사실 이러한 점들은 꽤나 중요하다. 2009년 발표에 따르면 이 길이의 변경으로 certificate를 위조하는데 성공했고 많은 브라우저들이 이것을 확인 하지 않기 때문이다.
  1. key usage도 확인을 해야 한다. Key usage란 인증서가 사용될 목적을 나타내는데 encipherment, signatures, certificate signing과 같은 목적에 부합하지 않는 사용으로 인증서를 쓰려고 한다면 validate해서는 안 될 것이다.
  1. 마지막으로 남은 모든 extensions를 확인한다. leaf certificate까지 error없이 진행된다면 path는 valid하다고 accept한다. 
* 만약 인증서가 신뢰할 수 없는 것이라면(인증 기관의 공개키로 복호화가 불가능 혹은 값이 다름) 키가 유출 되었을 가능성이 있으므로 다른 사람이 복호화 가능 할 가능성이 크다.
* <img alt=" " src="/assets/images/certificate.png" width="600px">
* root CA로써 Verisign, Geotrust 등의 회사가 있다.

### X.509
* [X.509](https://adonaiohesed.github.io/2019/05/18/certificates.html)

## PKI(Public Key Infrastructure)
* 공개키에서 가장 중요한 역할이 신뢰할만한 곳에서 발급되고 관리되는 키가 맞느냐이다. 이러한 것을 보장해주는 인프라가 PKI이다.
* 디지털 증명서의 생성, 관리, 배포, 사용, 저장 및 파기, 공개키 암호화의 관리에 필요한 역할, 정책 등 일련의 절차들을 집합한 것이다.
* CA(Certification Authority)는 인증기관으로 공개키가 진짜라는 것을 보증해주는 곳이다.
* 여러 인증기관들이 있는데 인증기관끼리 서로 신뢰하며 인증서 체인을 구성한다.

## Reference
* https://m.blog.naver.com/alice_k106/221468341565