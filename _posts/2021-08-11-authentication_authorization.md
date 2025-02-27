---
title: Authentication and Authorization - JWT
tags: JWT Authentication Cybersecurity
key: page-jwt_authentication
categories: [Cybersecurity, IAM]
author: hyoeun
mathjax: true
mathjax_autoNumber: true
---

## Authentication
* 로그인과 같이 사용자 또는 프로세스의 신원을 확인하는 프로세스
* 가장 일반적인 인증 방법으로는 비밀번호가 있고 API 인증, 생체 인증 등이 있습니다.
* 지식기반(비밀번호, 주민번호 등), 소유기반(인증서, OTP, 휴대폰 인증, USB 토큰 인증 등), 속성기반(지문, 홍체, 얼굴 등) factor가 있습니다.
* 2개 이상의 인증 방식을 사용하는 경우 Multi Factor Authentication이라고 합니다.

### YubiKey
* 하드웨어 보안 키이다. 
* U2F(Universal Second Factor)로 사용되며 아이디 비밀번호 방식으로 1차 인증 한 뒤 보안키를 저장한 dongle을 USB 포트에 꽂아 2차 인증을 하는 방식이다.
* 하드웨어 방식이라서 소프트웨어방식의 취약점에 강한 면이 있다. 키 관리가 물리적인 방식으로 바뀜으로 취약 방식 자체가 달라졌다고 보면 된다.

## Authorization
* 권한
* 권한 부여는 사용자의 신원이 성공적으로 인증 된 후에 발생합니다. 누가 무엇을 할 수 있는지 결정하는 규칙입니다.
* 역할 기반 액세스 제어, JSON 웹 토큰, SAML, OpenID 권한 부여, OAuth등이 있습니다.

## JWT
* 토큰 기반의 인증 시스템에서 주로 사용한다. Json 포맷을 이용하여 사용자에 대한 속성을 저장하는 Claim 기반의 web token이다.

### 구조
* Header, Payload, Signature의 3부분으로 이루어져있고 각 부분은 Base64로 인코딩 되어 표현된다. 각 사이의 구분자는 '.'로 이용된다.
* Header: signature 해싱하기 위한 알고리즘을 지정한다.
  ```jwt
  {
    "alg": "HS256",
    "typ": JWT
  }
  ```
  * typ: 토큰의 타입을 지정
  * alg: 알고리즘 방식을 지정하며, signature 및 토큰 검증에 사용
* Payload: 토큰의 페이로드에는 토큰에서 사용할 Claim이 담겨 있다. claim은 3가지로 나뉘어지며 json(key/value) 형태로 다수의 정보를 넣을 수 있다.
  * Registered claim: 토큰 정보를 표현하기 위해 이미 정해진 종류의 데이터이며 key길이는 3이다.
    * iss: 토큰 발급자(issuer)
    * sub: 토큰 제목(subject)
    * aud: 토큰 대상자(audience)
    * exp: 토큰 만료 시간(expiration), numericdata 데이터 형식으로 되어 있어야함 ex) 14808491473070
    * nbf: 토큰 활성 날짜(not before), 이 날이 지나기 전의 토큰은 활성화되지 않음
    * iat: 토큰 발급 시간(issued at), 토큰 발급 이후의 경과 시간을 알 수 있음
    * jti: 식별자(JWT ID), 중복 방지를 위해 사용
  * Public claim: 사용자 정의 클레임으로, 공개용 정보를 위해 사용. 충돌 방지를 위해 URI 포맷을 이용.
  * Private claim: 사용자 정의 클레임으로, 서버와 클라이언트 사이에 임의로 지정한 정보를 저장.
* Signature: 토큰을 인코딩하거나 유효성 검증을 할 때 사용하는 고유한 암호화 코드. 헤더와 페이로드의 값을 base64로 인코딩 한 후 인코딩한 값에 비밀키를 가지고 헤더에서 정의한 알고리즘으로 해킹하고 그 값을 다시 base64로 인코딩해서 생성한다.
  ```
  eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c
  ```

### 단점
* self-contained: 토큰 자체에 정보를 담고 있으므로 양날의 검이 될 수 있다.
* 토큰 길이: 정보가 많을수록 토큰 길이가 늘어나 네트워크에 부하를 줄 수 있다.
* Payload 인코딩: 페이로드 자체는 암호화 된 것이 아니라 base64로 인코딩 된 것이다. 중간에 페이로드를 탈취하여 데이터를 확인 할 수 있게 된다. 따라서 페이로드에 중요한 데이터를 넣으면 안되고 아니면 JWE로 암호화를 해야한다.
* Stateless: JWT는 상태를 저장하지 않기 때문에 한 번 만들어지면 제어가 불가능하다. 토큰 만료 기간이 꼭 필요하다.
* Tore Token: 토큰은 클라이언트 측에서 관리해야 하기 때문에 토큰을 저장해야한다.