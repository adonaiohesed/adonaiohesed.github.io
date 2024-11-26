---
title: Burp Setting
tags: Burp
key: page-burp_setting
categories: [Tools, Penetration Testing]
author: hyoeun
mathjax: true
mathjax_autoNumber: true
---

내가 평소에 해두는 셋팅 방식이다.

## 원치 않는 트래픽을 수집하지 않는 방법
1. Target -> Scope 에 가서 "Use advanced scope control을 체크한다.
1. Include in scope란에 Add를 눌러 빈칸을 놔둔채로 OK를 눌러 모든 트래픽을 scope안에 두도록 한다.
1. Exclude from scope에 내가 제외하고 싶은 URL를 Add를 통해 추가한다.