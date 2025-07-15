---
title: FTK Imager
tags: FTK-Imager Cybersecurity Forensics Tools
key: page-ftk_imager
categories: [Tools, Forensics Tools]
author: hyoeun
math: true
mathjax_autoNumber: true
---

## Image
* Physical image: bit-for-bit copy로 media에 있는 모든 것들을 copy한다. "deleted" data와 no longer accessible data도 포함하는 것이다.
* Logical image: viewable data(logical data)만 복사하는 것이다. 따라서 실제 데이터 사이즈보다 적은 사이즈로 만들어질 것이다.

## Write-blocking
* 항상 증거 자료가 의도적이든 아닌든 변형되지 않도록 해야 되는데 이때 write-blocker가 필요하다.
* software program도 있고 hardware device도 있다.
* 이거를 작동하지 않으면 컴퓨터에서 evidence hard drive의 자료를 지우거나 변형해버릴 수 있다.

## Usage
* 우선 wirte-blocker와 연결 한 후에 프로그램을 실행시킨다.
* 새로운 이미지 만들기를 시도한다.
* 어떤 타입(physical, logical)의 형태로 imaging할지 정하고 case number, examiner과 같은 정보들을 기입한다.
* 이미징 작업이 끝나면 MD5, SHA1 값이 나오는데 만약 imaging한 drive의 내용이 바뀌면 이 값들도 바뀌게 되는 것이다.

## Software blocker
* [https://www.forensicsoft.com/safeblock.php](https://www.forensicsoft.com/safeblock.php)에서 7일 무료 버전을 써볼 수 있다.
* SAFE Block은 많이 사용하는 tool 중에 하나이다.