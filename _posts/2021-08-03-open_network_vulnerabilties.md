---
title: Open network vulnerabilities
tags: Network-Vulnerabilities Cybersecurity
key: page-open_network_vulnerabilities
categories: [Cybersecurity, Network Security]
author: hyoeun
mathjax: true
mathjax_autoNumber: true
---

## 취약한 이유
* 와이파이에 비밀번호로 로그인한다고 온라인 activities가 encrypt되는 것은 아니다.
* 오픈 와이파이 중에는 Wireless Encryption Protocol(WEP)을 사용할 수 있는데 이것은 이미 취약점이 있다. WEP를 대체하기 위해 Wi-Fi Protected Access(WPA)가 나왔지만 이것 역시 취약하다. 이런 outdated encryption protocols을 쓴다면 안전하지 않게 된다.
* 오픈 와이파이 중에는 rogue(도적) Wi-Fi hotspot이 있을 수 있는데 fake hotspot으로 man-in-the-middle attack을 할 수 있다.
* 그 경우에는 skill이 없는 해커도 sensetive data를 가로채고 변형하고 다 할 수가 있게 된다.

## 안전하게 사용하는 방법
* 전용 vpn을 사용해서 암호화 채널을 통한 커뮤니케이션을 한다. 또한 다른 사이트에 접속할때 https로 암호화 기술을 사용한 웹을 이용한다.

## 공격 방식
* MITM 공격을 시도합니다.
  1. 신호 강도가 낮고 카페 이름과 비슷한 이름으로 SSID를 변경한다.
  1. 노트북에는 세션정보를 가로채기 위한 와이어 샤크를 작동시키고 누군가 연결하기를 기다립니다. 연결에 성공하면 이후 패킷들을 가로챌 수 있습니다. 
  1. 만약 공격자가 노리는 타겟이 정확하게 있으면 타겟의 로그인 사이트와 똑같은 페이지를 만들어서 라우터의 DNS를 조작하여 상대방이 타겟 URL에 접속할때 공격자가 만든 페이지를 보게 하여 로그인 정보를 빼돌릴 수 있습니다.
