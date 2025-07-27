---
title: Code Review
tags: Static-Analysis Cybersecurity
key: page-static_analysis
categories: [Cybersecurity, Web Security]
author: hyoeun
math: true
mathjax_autoNumber: true
---

## Secrutiy Code Review시 중요한 사항

* 리뷰 할 objectives를 명확히 설정해라.
    * 어딘가에 초점을 맞추고 리뷰하는 것은 효과적이다.  
* 리뷰할 시간을 정해놓고 시작하라.
    * 시간 관리하는데에 있어도 한정된 시간을 정해놓는 것이 도움이 된다.
* 질문지를 작성하고 리뷰를 시작하라.
    * 이 코드는 버퍼 오버 플로우 공격에 취약한가? 중요한 자료가 암호화 되지 않은채로 접근할 수 있게 되어 있지는 않은가? 라는 질문지를 만들어 놓으면 좋다.
* 적절한 scope를 정해서 반복적으로 리뷰를 하라.
* 성능, 가독성, 기능적인 면에 대한 리뷰를 하는 것이 아니라 오직 security 관점에서만 집중해서 리뷰를 해라.
* Application architecture를 알고 리뷰를 하라.
    * 적어도 한 사람은 dataflow, component architecture와 같은 것을 알고 리뷰를 해야한다.
* 너만의 coding standard를 업데이트 하라.
    * 과거 리뷰를 해오면서 필요했던 것들을 체크하면서 더 필요한 것들을 추가하면서 리뷰하라.

## Security code review techiniques

### Preliminary scan

#### Automatic scan using tools
* 자동화 scan 툴을 사용함으로써 manual review때 놓치는 것들을 잡는데 목적이 있다.
* Manual review에서 잡을 수 있는 것들을 못잡을 수 있다.

#### Manual scan
* Input data validation
    * Does the application have an input validation architecture? 
    * Is validation performed on the client, on the server, or both? 
    * Is there a centralized validation mechanism, or are validation routines spread through the code base?
* Code that authenticates and authorizes users
    * Does the application authenticate users? 
    * What roles are allowed and how do they interact? Is there custom authentication or authorization code?
* Error handling code 
    * Is there a consistent error handling architecture? 
    * Does the application catch and throw structured exceptions? Are there areas of the code with especially dense or sparse error handling?
* Complex code
    * Are there areas of the code that appear especially complex?
* Cryptography
    * Does the application use cryptography?
* Interop 
    * Does the application use interop to call into native code?