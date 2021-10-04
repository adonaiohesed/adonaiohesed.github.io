---
title: Authentication and Authorization
tags: authentication authorization
key: page-authentication_authorization
cover: /assets/cover/cyber_security.png
mathjax: true
mathjax_autoNumber: true
---

## Authentication
* 로그인
* 로그인과 같이 사용자 또는 프로세스의 신원을 확인하는 프로세스
* 가장 일반적인 인증 방법으로는 비밀번호가 있고 API 인증, 생체 인증 등이 있습니다.
* 지식기반(비밀번호, 주민번호 등), 소유기반(인증서, OTP, 휴대폰 인증, USB 토큰 인증 등), 속성기반(지문, 홍체, 얼굴 등) factor가 있습니다.
* 2개 이상의 인증 방식을 사용하는 경우 Multi Factor Authentication이라고 합니다.

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