---
title: Base64, Hex encoding and ecoding
tags: Base64 Hex Encoding Decoding
key: page-base64_hex_encoding_decoding
categories: [Cybersecurity, Cryptography]
author: hyoeun
mathjax: true
mathjax_autoNumber: true
---

## Base64 and Hex encoding & decoding
* 주로 url과 관련된 문제, 즉 웹과 관련해서 많이 나오는 것 같다.
* 문자가 a-zA-Z0-9,space,/ 구성된 긴 string이면 base64를 의심하면 좋다.
* Base 64란 binary data를 text로 바꾸는 인코딩이다. Binary data를 6bit씩 자른 뒤 해당하는 문자를 base64 색인표에 따라 바꿔준다.
* 인코딩시 패딩은 bit로는 0, 문자로는 = 으로 채워진다.

## 좋은 사이트
* 아래 것은 decoding 혹은 encoding을 할때 좋다. 
* https://gchq.github.io/CyberChef/#recipe=From_Base64('A-Za-z0-9%2B/%3D',true)From_Hex('Auto')From_Base64('A-Za-z0-9%2B/%3D',true)[https://gchq.github.io/CyberChef/#recipe=From_Base64('A-Za-z0-9%2B/%3D',true)From_Hex('Auto')From_Base64('A-Za-z0-9%2B/%3D',true)]
