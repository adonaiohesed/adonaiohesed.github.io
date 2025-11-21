---
title: 리눅스 리다이렉션 파일디스크립터
tags: Linux
key: page-linux_redirection_file_descriptors
categories: [Development, SysOps & Infrastructure]
author: hyoeun
---

## 쉘 커맨드 창에 보이는 기호 분석
* ```guest@linux:~$(#)``` 
  * $: normal user
  * #: system administrator (root) 
  * guest - username
  * linux - machine hostname
  * ~ - current working directory
<br>

## 리다이렉션과 파일 디스크립터

* 파일디스크립터 : 파일 디스크립터(FD)는 프로세스가 파일에 접근하기 위해 제공되는 고유 식별자입니다. UNIX에서는 모든 객체를 파일로 관리합니다. 프로세스가 특정 파일에 접근하기 위해서 특정 파일의 디스크립터를 이용하면 해당 파일에 접근할 수 있게 됩니다.
* 출력과 오류를 다르게 파일로 출력하고 싶다면 리다이렉션과 파일 디스크립터를 함께 활용할 수 있습니다.
사용 방법은 명령어 [방향을 바꿀 FD]>[방향으로 설정될 파일의 FD] 파일로 리다이렉션 기호를 중심으로 좌측에는 스트림의 방향을 바꿀 파일 디스크립터를 명시하고 우측에는 방향으로 지정될 파일의 파일 디스크립터를 명시하면 됩니다. 만약 파일 디스크립터를 생략한다면 기본적으로 파일의 출력 스트림으로 지정됩니다. 예를 들어, myscript.sh를 실행시 출력은 stdout.txt라는 파일에 쓰고 오류는 stderr.txt라는 파일에 쓰고 싶다면 아래와 같이 사용하면 됩니다.
```shell
$ ./myscript.sh > stdout.txt 2> stderr.txt
(=$ ./myscript.sh 1> stdout.txt 2> stderr.txt)
```
* /dev/null은 아무 것도 존재하지 않는 특별한 파일입니다. 이 파일에 쓰여지는 데이터는 모두 버려지지만, 정상적으로 쓰기 작업이 종료됐다고 인식됩니다. 이러한 빈 파일을 비트 버킷 또는 블랙홀이라고 부릅니다.
```shell
$ ./myscript 2> stderr.txt > /dev/null
```


## 출처

1. [https://hongsii.github.io/2018/06/25/linux-standard-streams/](https://hongsii.github.io/2018/06/25/linux-standard-streams/)