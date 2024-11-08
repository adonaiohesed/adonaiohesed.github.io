---
title: Nodejs 설치 및 사용 방법
tags: Nodejs
author: Hyoeun-Choi
pageview: true
key: page-nodejs_installation_usage
categories: [Software Engineering, NodeJs]
author: hyoeun
---

### NodeJS의 특징
* Javascript를 사용한다. (따라서 front, back이 모두 같은 언어로 작업 할 수 있다.)
* Single thread 기반으로 동작한다.
* Event 기반의 프로그래밍 모델을 사용한다.
* 개발 구조가 단순하여 빠르게 개발이 가능하다.

### CentOS7 기준 설치방법
* ```shell
$ curl -sL https://rpm.nodesource.com/setup_11.x | bash -
$ sudo yum install -y nodejs
```

* [공식 사이트 안내](https://github.com/nodesource/distributions/blob/master/README.md#rpminstall)