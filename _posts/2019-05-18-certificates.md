---
title: 인증서
tags: Certificate Cryptography Cybersecurity
key: page-certificate
categories: [Cybersecurity, Cryptography]
author: hyoeun
---

## Keystore란 무엇인가?

* priavate key가 담겨있는 정보(텍스트 파일)를 의미한다.
* keystore에서 제공하는 operation으로만 key 접근이 가능하다.

<br>
## PKCS#12

* 공개 키 암호 표준(Public-Key Cryptography Standard, PKCS)은 RSA 시큐리티에서 정한, 공개 키 암호에 대한 사용 방식에 대한 표준 프로토콜이다.
* 공개 키 인증서 교환 문법 표준(Personal Information exchange syntax standard)	
* 비밀번호로 보호된, 대칭키와 공개 키 인증서에 동봉된 개인 키들을 저장하는 데 일반적으로 사용되는 파일 형식을 정의한다. .pfx는 pkcs #12 파일형식 확장자이다.
이 파일 형식은 여러 개의 개체(예: 다중 인증서, 다중 키)를 포함할 수 있으며 보통, 비밀번호로 보호되거나 암호화된,. java keystore의 형식으로 사용된다.

<br>
## 인증서

* 인증서 안에는 public information, public key가 들어있다.
* CA로부터 받은 public key가 있다.

<br>
## 인증서 관련 용어 정리 
[전자서명인증관리체계 DN 규격](https://www.rootca.or.kr/kcac/down/TechSpec/1.3-KCAC.TS.DN.pdf) 참고
* CN (Common Name): 가입자의 이름을 나타내는 속성
* OU (Organizational Unit Name): 가입자가 속한 하위 조직명을 나타내기 위한 속성, 공인인증기관일 경우 CA를 사용
* O (Organization Name): 가입자가 속한 조직명을 나타내기 위한 속성
* DC (Domain Component): 가입자의 도메인 주소를 나타내기 위한 속성

## 인증서 확장자

* .pem: X.509 v3 파일의 한 형태

## X.509란

* 공개키 인증서를 사용하기 위해서는 어떤 표준이 있어야 되는 것인데 현재 널리 사용하고 있는 표준이 X.509이다.
* X.509의 표준을 사용하여 만든 인증서를 X.509 인증서라고 부른다.
* Extensino항목은 중요한 것만 기입했다.
<img src="/assets/images/x509_1.png" width="600px" style="display: block;margin-left: auto;margin-right: auto;"> 
* 위의 항목 중 DN형식이 있는데 DN의 항목은 다음과 같다.
<img src="/assets/images/x509_2.png" width="600px" style="display: block;margin-left: auto;margin-right: auto;"> 
