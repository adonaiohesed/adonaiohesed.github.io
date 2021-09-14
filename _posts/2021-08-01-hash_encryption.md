---
title: Hash & Encryption
tags: hash encryption
key: page-hash_encryption
cover: /assets/cover/cyber_security.png
mathjax: true
mathjax_autoNumber: true
---

## Hash and encryption
* 해시 알고리즘을 거쳐 생성된 결과물을 digest라고 부른다.
* Hash는 단방향이고 encryption은 양방향이다.
* Hash의 종류에는 

## HMAC
* 인증에 관해 key가 필요한 keyed-hashing이라고 할 수 있다.
* MD5, SHA-1과 같은 해시기반 함수를 이용해서 만든다.
* 서로 공유하고 있는 shared key로 message를(key + message) HMAC 알고리즘으로 해시값을 생성하고 digest를 메시지와 같이 보낸다. 받는 측에서는 받은 messsaged와 본인이 가지고 있는 key로 다시 해시값을 생성하여 받은 digest와 비교한다.
* <img src="/assets/images/hmac.png" width="600px">
* key 없이 메시지의 위변조가 불가능하지만 원문 message를 보호하기 위해서 HTTPS와 같은 안전한 전송채널을 사용하는 것이 좋다.
* 취약점으로는 메시지를 가로채서 목적지로 다시 보내는 reply 공격에 취약하다. 이런 공격은 차량에서 unlock신호를 캡쳐했다가 나중에 다시 보내서 unlock을 시켜버릴 수도 있는 공격이다.
* 취약점을 보안하기 위해 timestamp를 메시지 안에 넣고 HMAC 알고리즘을 진행한뒤 마지막에 verficiation을 통과하면 시간이 지금 초과한건지 아닌지 체크해서 reply attack을 막는다.

## References
