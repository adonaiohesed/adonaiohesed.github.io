---
title: Registry Analysis
tags: Registry-Analysis Cybersecurity Forensics Tools
key: page-registry_analysis
categories: [Tools, Forensics]
author: hyoeun
math: true
mathjax_autoNumber: true
---

## RegRipper
* Windows registry files에서 데이터를 추출하는 오픈소스 포렌식 도구이다.

## Registry Files
* Windows/system32/config에 파일들이 존재한다.
* SAM
    * Security Account Manager라고 개인 계정에 관련한 정보를 다룬다. 
* SECURITY
    * 보안에 관련된 Group polices와 같은 것을 다룬다.
* SOFTWARE
    * 설치된 프로그램 목록, 라이센스, expiration data와 같이 소프트웨어와 관련된 정보를 담고 있다.
* SYSTEM
    * configuration과 같은 시스템 정보를 담고 있다.
* NTUSER.dat
    * Document and Setting/\<User\>에 있는 파일로 Most Recently Used(MRU)와 같은 개인적인 정보들에 대해 담고 있다.


