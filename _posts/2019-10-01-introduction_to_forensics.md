---
title: Introduction to Forensics
tags: Introduction-Forensics Cybersecurity
key: page-introduction_to_forensics
categories: [Cybersecurity, Forensics]
author: hyoeun
mathjax: true
mathjax_autoNumber: true
---

## Intoruction
* Forensics란? the use of science and technology to investigate and establish facts in criminal or civil courts of law. 즉 법정에서 효력이 있는 fact들을 만들어가는 작업들이다.
* computer forensics이란 말보다 cyber forensics이란 표현이 좀 더 적절하다.
* forensics는 과학으로 가설을 세우고 테스트를 하고 거기에 따른 결과를 기록해야한다.
* 범죄의 요소에는 1) Law을 깨야 할 것이고 2) 의도가 있어야 한다. 이 중에 하나라도 성립하지 못한다면 범죄라고 할 수 없다.

## Hardware에 관한 전문 지식
* 파일 확장자를 바꾸더라도 파일 헤더 안의 첫번째 바이트를 보면 그것이 본래 어떤 확장자였는지 알 수 있다.
* 모든 NIC마다 고유의 MAC address가 존재한다. MAC address spoofing은 IP spoofing보다 어렵고 따라서 MAC address를 모으는 것은 포렌식에서 매우 중요하다.

## 사건현장에서 해야 될 일
* 사건 현장에서 가장 중요한것은 현장 보존이다. 따라서 현장 보존을 먼저 한 다음 증거들이 contaminating되지 않도록 한다.
* 범죄현장에서 컴퓨터를 바로 끄면 안되고 live memory를 확보하는 것이 매우 중요하다. 보통 메모리 안에 forensics에 관한 중요한 자료들이 있을 수 있기 때문이다.
* 휴대폰같은 것은 외부와의 통신을 더 이상 하지 못하도록 통신 신호 차단 백에 넣어서 보관한다.
* 컴퓨터의 경우 offline상태로 만들지 말고 그 자리에서 공격을 분석하는것이 Federal 가이드라인이다.
* 만약 컴퓨터에서 증거들을 지우고 있다고 생각하면 컴퓨터를 끄고 아니면 컴퓨터를 끄지 않고 보존한다.
* 컴퓨터가 있었던 위치 같은 것을 기록해두는 것도 중요하다.
* 켜진 컴퓨터는 바로 거기서 searching을 시작하는 것이 아니라 적절한 방법을 거친 다음 조사에 착수한다. 증거물을 원본 상태로 보존하는 것이 가장 중요하다.

## 법과 문서
* 미국의 경우 federal laws가 모든 states에 적용되는 것은 아니기 때문에 포렌식 작업을 하는 장소의 법을 잘 이해하고 있어야 한다.
* 포렌식에서 모든 것은 반드시 document형태로 남겨져야 한다.
* document를 남길때 Chani of Custody를 항상 유지해야되는데 언제 누구에 의해서 이 문서들이 기록되었는지에 대한 히스토리가 기록되어져야 된다.
* 법의 경우 Civil Law와 Criminal Law로 나눌 수 있다.
    * Civil Law: 이거는 incarceration(투옥)은 포함하지 않는다. 법적 책임을 묻는다.
    * Criminal Law: intentional violations of law를 다루고 벌금과 투옥형을 받을 수 있다.
* 포렌식을 하는 사람의 역할은 litigant(소송 당사자)중 누구의 편에 서는 것이 아니라 단지 진실을 찾는 것이다. 따라서 항상 중립성을 유지하고 어떠한 의도나 자신의 유죄에 관한 판단이 포렌식 안에 포함되어서는 안 된다.
