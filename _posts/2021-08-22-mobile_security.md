---
title: Mobile Security
tags: mobile clickjacking
key: page-mobile_security
cover: /assets/cover/cyber_security.png
mathjax: true
mathjax_autoNumber: true
---

## Clickjacking이란?
* 클릭재킹이란 보이지 않는 버튼으로 사용자의 클릭을 유도해 공격자가 원하는 것을 하도록 속이는 해킹 기법.
* iframe 태그 안에 악의적인 js코드를 삽입하여 보이지 않는 레이어를 누르도록 하여 피싱 사이트로 접근하게 만든다.
* 방어 기법으로는 X-Frame-Options 속성 중에서 DENY나 SAMEORIGN 옵션을 통해서 동일한 출처의 프레임만 표시될 수 있도록 도와준다.


