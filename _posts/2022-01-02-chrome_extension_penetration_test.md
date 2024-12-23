---
title: Chrome Extension Penetration Test
tags: Chrome-Extension
key: page-chorme_extension_penetration_test
categories: [Cybersecurity, Web Security]
author: hyoeun
mathjax: true
mathjax_autoNumber: true
---

브라우저 Extension은 JavaScript로 짜여져 있습니다. DOM 기반으로 작동합니다. Chrome extension은 .crx 파일 확장자로 가지고 있고 manifest.json이 코어 파일입니다.

## Mac에서 파일 위치
~/Library?Application Support/Google/Chrome/Default/[ID]

## Permissions
* localStorage는 extension이 지워져야지만 사라지는 공간이다.

* host_permission은 cookies, webRequest, and tabs와 같은 apis들과 Interact 할 수 있는 것이다.

