---
title: Cross-Site Request Forgery
tags: CSRF Web-Hacking Cybersecurity
key: page-csrf_attack
categories: [Cybersecurity, Web Security]
author: hyoeun
math: true
mathjax_autoNumber: true
---

## Introduction

* Victim이 malicious page를 보고 있을 때 공격자가 target website에 victim 신분으로 forged request를 보낼 수 있는 공격법이다.
* Target website가 적절한 countermeasure가 없다면 third-party에 의해 들어온 request인지 authentic one이 보낸건지 구분 할 수가 없다.
- 서버가 특정 클라이언트로부터 request를 받으면 거기에 대해 unique한 id를 부여한다. 그 Id를 세션이라고 부른다.
- 클라이언트가 재접속하거나 할때 클라이언트를 인식할 수 있는 유일한 수단이다.
- 서버와 연결을 끝내는 시점까지 세션이라고 부른다.

## Cross-Site Requests and Its Problems

* Cross-Site Request란 한 서버로부터 받은 페이지에서 같은 서버에 request를 날리는 것이 아니라 다른 서버에 request를 날리는 것을 의미한다. 쉽게말해서 어떤 웹 페이지를 보고 있는데 그 웹 페이지에서 image파일을 불러올때 자기 서버가 아닌 다른 웹 서버의 image를 url로 요청해서 받아오는 상황이 cross-site request라고 한다.
* 웹 브라우저는 cross-site request인지 아닌지 알지만 그 정보를 server에게 전달하지는 않는다. 왜냐하면 해당 페이지에 대한 모든 request들을 하나의 쿠키로 만들어 서버로 보내기 때문이다. 이러한 브라우저의 behaviros가 문제를 일으키는 것이다.
* 서버 입장에서 자신의 웹페이지에서 오는 리퀘스트는 신뢰할 수 있지만 다른 곳에서 오는 리퀘스트는 신뢰할 수 없다. 서버는 세션 쿠기로 신뢰 여부를 결정하는데 하필 브라우저가 same site request, cross-site request 모두에게 동일한 쿠키를 날려버려서 서버는 신뢰할 수 있는 정보인지 아닌지 구분할 수 없다.

## Cross-Site Request Forgery Attack
* attacker가 자신의 변조된 웹사이트로 victim user를 끌여들여서 victim user신분으로 target website에 request를 날리는 것이 CSRF 공격이다.
* victim user는 먼저 target site에 로그인이 되어 있어야지 성공적으로 공격할 수 있다. 왜냐하면 공격자가 CSRF 공격을 실행할 때 로그인 페이지로 redirect되어서 victim user에게 발각될 수 있기 때문이다.

## CSRF Attacks on HTTP GET Services
* GET 방식은 URL에 데이터를 실어 보낸다.

## CSRF Attacks on HTTP POST Services
* POST 방식은 body에 데이터를 실어 보낸다.

## Countermeasures
* 많은 웹사이트들이 CSRF 취약점을 가지고 있는데 개발자들이 이것에 대한 피해를 신경쓰지 않기 때문에 이런일이 발생하는 것이다.
* Defeating CSRF attacks은 쉽다.
### Using the referer Header
  * cross-site 인지 아닌지 알려주는 filed가 헤더 안에 존재하지만 이거는 browsing의 history를 알 수 있기 때문에 개인정보 보호에 의해 주로 사용하지 않는다.
  * 이런 방식은 사실 개인 정보가 드러날 수 있는 부분을 없애버리고 cross-site인지 아닌지만 확인 할 수 있도록 하고 새로운 필드를 만들면 되지만 아직까지 만들어지지는 않았다.
### Same-Site Cookies
  * 위의 방식을 해결할 부분과 비슷한 방식이 크롬과 오페라에 implemented되긴 했다.
  * 서버에 의해서 설정되며 value값이 Strict면 cross-site request가 없다는 것이고 Lax면 cross-site request가 있다는 것이다.
### Secret Token
  * 위의 방식은 대다수 브라우저에서 지원하지만 web application스스로도 대책이 있어야 하는 것이다.
  * 서버측에서 자기만 아는 비밀 토큰을 부여해서 same-site request에서 이 토큰을 가지고 있지 않다면 cross-site request라고 판단하면 되는 것이다.
  * page를 initiated하는 request에다가 랜덤 넘버를 부여하는 방법이 있다.
  * 또 다른 방법으로는 쿠키 안에 secret value를 넣는 방법이다.
### Same-Origin Policy
  * 웹브라우저들이 자바스크립트로 다른 도메인의 웹페이지에 접근하는 것을 못하도록 막아놓은 제약조건이다.
  * 프로토콜, 호스트, 포트가 동일한 요청만 가능하도록 제한 하는 정책이다. 이러한 제한으로 CSRF 공격을 막을 수도 있을 것이다.
  * 하지만 외부 API를 사용하는 경우도 많고 클라이언트와 서버를 분리하여 개발하는 경우도 많은데 이 정책으로 불편함을 겪어 CORS정책을 이용하기도 한다.
### Cross-Origin Resoures Sharing(CORS)
  * SOP의 불편함을 해소하기 위한 것으로 CORS는 추가 헤더를 통해 다른 출처의 자원을 현재 실행중인 웹 애플리케이션에 허용 시켜주는 메커니즘이다.
  * 이것은 사실상 CSRF를 막는것과 상관이 없다. 외부 API를 사용하고 클라이언트와 서버를 분리하여 개발하는  환경이 많연한 요즘 시대에는 SOP가 많은 불편함을 가져다 주어 CORS를 통해 그 불편함을 해소한다.
### How to work CORS
  * CORS는 서버가 추가 헤더를 통해 자원 공유에 대한 정의를 브라우저에게 보낸다. 이 때, preflight가 있는 preflight request 혹은 simple request가 존재한다.
  * Preflight가 없는 simple request인 경우: 클라리언트가 서버에 Origin을 포함하여 request를 보내면 서버측에서는 origin header를 통해 이것이 Access-Control-Allo-Origin에 해당하는 것인지 확인을 하고 그것에 해당하면 접근을 허용하고 아니면 거부합니다.
  * Preflight request의 경우: Simple request와 달리 먼저 OPTIONS 메서드를 통해 다른 도메인의 리소스로 HTTP 요청을 보내 실제 요청이 전송하기에 안전한지 확인합니다. Cross-site 요청은 유저 데이터에 영향을 줄 수 있기 때문에 preflighted를 합니다. 이 때, Access-Control-Request-Method와 Access-Control-Request-Headers를 포함하여 보내고 서버는 Access-Control-Allow-Origin, Access-Control-Allow-Methods, Access-Control-Max-Age등 Access-Control-*-* 계열의 Response Header를 선언하여 응답을 보냅니다. 이를 통해 해당 Origin이 허용되었다는 것을 preflight request를 통해 파악되면 그제서야 브라우저는 본 요청을 보내고 simple request의 Response와 동일하게 처리됩니다.

### 생각해볼 문제
* 만약 CSRF 토큰 1개로 여러가지 Request를 사용 할 수 있는 방식과 각 request마다 1개의 CSRF토큰이 필요한 방식이 있다면 무엇이 더 safe한가? 후자이다.

## References
* [COMPUTER SECURITY: A Hands-on Approach by Wenliang Du](https://www.amazon.com/Computer-Security-Hands-Approach-Wenliang/dp/154836794X)