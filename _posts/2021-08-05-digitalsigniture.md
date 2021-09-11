---
title: Metasploit2
tags: metasploit hacking
key: page-metasploit
cover: /assets/cover/metasploit.png
mathjax: true
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
  1. 다음으로 인증서의 validity를 확인한다. 인증시간이 지난 것은 reject한다.
  1. 
* 만약 인증서가 신뢰할 수 없는 것이라면(인증 기관의 공개키로 복호화가 불가능 혹은 값이 다름) 키가 유출 되었을 가능성이 있으므로 다른 사람이 복호화 가능 할 가능성이 크다.
* <img src="/assets/images/certificate.png" width="600px">
* root CA로써 Verisign, Geotrust 등의 회사가 있다.

### X.509
* 

## PKI(Public Key Infrastructure)
* 공개키에서 가장 중요한 역할이 신뢰할만한 곳에서 발급되고 관리되는 키가 맞느냐이다. 이러한 것을 보장해주는 인프라가 PKI이다.
* 디지털 증명서의 생성, 관리, 배포, 사용, 저장 및 파기, 공개키 암호화의 관리에 필요한 역할, 정책 등 일련의 절차들을 집합한 것이다.
* CA(Certification Authority)는 인증기관으로 공개키가 진짜라는 것을 보증해주는 곳이다.
* 여러 인증기관들이 있는데 인증기관끼리 서로 신뢰하며 인증서 체인을 구성한다.
* 

## Reference
* https://m.blog.naver.com/alice_k106/221468341565