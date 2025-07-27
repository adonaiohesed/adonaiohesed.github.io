---
title: SolarWinds hack
tags: SolarWinds Hack Cybersecurity
key: page-solarwinds_hack
categories: [Cybersecurity, Vulnerabilities]
author: hyoeun
math: true
mathjax_autoNumber: true
---

## 개요
* SolarWinds는 네트워크, 시스템 및 정보 기술 인프라 관리를 지원하는 기업용 소프트웨어 회사이다. 이 회사 제품 중 Solarwinds Orion이라는 제품의 공급망 서버가 해킹을 당해 본 제품에 악성 플러그인이 숨겨진 채로 배포되었다. 피해 대상은 미 국토안보부, 재무부 등 미국 정부기관과 많은 기업들이 사용해서 그 피해 규모가 엄청났다. 이 공격은 Supply Chain Attack으로 볼 수 있다.
* 악성 코드는 주로 SUNSPOT, SUNBURST, TEARDROP로 볼 수 있다. 악성 코드 사용 순서는 SUNSPOT -> SUNBURST -> TEARDROP이 될것이다.

## SUNBURST
* 닷넷으로 개발되어 있어서 마치 main인 것 처럼 작동하는 DLL 악성코드이다.

## SUNSPOT
* 빌드중인 환경을 감시하고 있다가 빌드를 시작할때 프로세스를 훔쳐 SUNBURST 코드를 심고 빌드가 완성되게한다.

## TEARDROP
* 