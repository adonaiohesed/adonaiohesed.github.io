---
title: Metasploit
tags: Metasploit Cybersecurity Penetration-Testing Tools
key: page-metasploit
categories: [Tools, Penetration Testing]
author: hyoeun
math: true
mathjax_autoNumber: true
---

## 사용법

### 사용 흐름
* msfconsole -> search -> use -> info -> show options -> set -> exploit -> meterpreter
* exploit을 할 때에는 플랫폼 -> 서비스 -> 코드를 선택하는 단계로 진행한다.

### 사용 명령어
* use exploit/windows/...[모듈 위치]
    * 모듈 사용
    * 이후 option을 치면 해당하는 option이 나온다.
    * exploit를 통해 원하는 모듈을 실행시킨다.
* search type: platform: 으로 모듈들을 조사해 나간다.
* info: 모듈 세부 정보 확인
* back: 이전 모드로 돌아간다.
* show options: 모듈에 관한 옵션을 확인
* set rhost(옵션) 1.2.3.4: 옵션 값을 설정
* exploit: 설정된 정보들로 exploit 시작 
* 모듈들은 /usr/share/metasploit-framework/modules에 존재한다.

### modules 폴더 정보
* auxiliary: 페이로드를 필요로 하지 않는 공격 또는 정보 수집을 목적으로 하는 코드 모음. scanner와 gather를 많이 사용.
* encoder: 안걸리기 위해 페이로드의 형태를 변형 시키는 다양한 알고리즘의 코드 모음.
* payload: 쉘코드이자 최종 공격목적코드라고 생각하면된다.
    * singles: 단 하나의 기능을 가지거나 사전 단계 없이 직접 쉘 획득에 참여하는 페이로드.
    * stagers: 공격자와 대상 시스템을 연결 후 2단계 페이로드를 불러오는 역할을 하는 페이로드. bind, reverse를 나누는 기능이 있다.
    * stages: stage 페이로드가 로드해 주는 2단계 페이로드(ex 실제 공격 코드 삽입)
    * stagers, stages는 한 묶음이다. single을 사용하는 것보다 탐지가 덜 되기 때문에 2단계로 나눠서 사용한다.
* post: exploit 성공 후 대상 시스템에 대한 추가 공격을 위한 코듬 모음.

### Script 사용법
```msfconsole -r script.rc```

## Reference

* 1.메타스플로잇 구조, 모듈 사용법 \[Rnfwoa\]신동환 PDF
