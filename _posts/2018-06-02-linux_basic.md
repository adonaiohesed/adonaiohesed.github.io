---
title: 리눅스 기본 지식
tags: Linux
key: page-linux_basics
categories: [Development, Linux]
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

## 컴퓨터 재부팅, 끄기
* shutdown [옵션] [시간] [메시지]
```console
# shutdown -r now
```
#### options

    |옵션|설명|
    |:--:|:--:|
    |-t n|경고 메시지를 보낸 후 n초 후에 kill 시그널 보낸다.
    |-h|shutdown시 halt를 실행하게 한다.
    |-n|디스크 동기화 동작의 수행을 금지한다.
    |-r|시스템을 재부팅한다.
    |-f|다음 부팅시 파일시스템 검사를 하지 않는다.
    |-c|이미 예약되어 있는 shutdown를 취소한다.
    |-k|모든 동작을 제대로 수행하지만, 실제로 시스템을 종료하지는 않는다.

<br>

## 사용자 계정
* 계정 생성
```console
# useradd hyoeun
```
* 계정 확인
```console
# cat /etc/passwd
```
* 계정 삭제(-r은 홈 디렉토리까지 삭제 해줍니다.)
```console
# userdel -r hyoeun 
```
* 비밀번호 설정
```console
# passwd hyoeun
```
* 계정 전환
```console
# su hyoeun
```

<br>

## sudo 권한 주기
* root 계정으로 접속한 다음 두개 중 하나의 명령어 실행

<div class="grid">
  <div class="cell cell--1"></div>
  <div class="cell cell--4">
{% highlight console %}
# sudo visudo
{% endhighlight %}
  </div>
  <div class="cell cell--1"></div>
  <div class="cell cell--4">
{% highlight console %}
# sudo vim /etc/sudoers
{% endhighlight %}
  </div>
  <div class="cell cell--2"></div>
</div>

* hyoeun 사용자에게 sudo 권한 부여하고 패스워드 없이 sudo를 쓰기 위해 아래와 같이 ```hyoeun ALL=(ALL)       NOPASSWD: ALL```을 추가합니다. 
```bash
## Next comes the main part: which users can run what software on
## which machines (the sudoers file can be shared between multiple
## systems).
## Syntax:
##
##      user    MACHINE=COMMANDS
##
## The COMMANDS section may have other options added to it.
##
## Allow root to run any commands anywhere
root    ALL=(ALL)       ALL
hyoeun ALL=(ALL)        NOPASSWD: ALL
```
  * sudo vim으로 접속했을 시 /etc/sudoers가 읽기전용 파일로 되어 있기에 :!w 로 저장 혹은 쓰기 권한 변경 후 저장 합니다.

* whell 그룹에게 sudo 권한을 부여하는 방법
```bash
## Allows people in group wheel to run all commands
%wheel  ALL=(ALL)       ALL
```

<br>

## tar.gz 압축
1. tar 압축 풀기
```console
$ tar -xvf [파일명.tar]
```
2. tar.gz 압축 풀기
```console
$ tar -zxvf [파일명.tar.gz]
```
#### options

    |옵션|설명|
    |:--:|:--:|
    |-c|파일을 tar로 묶음|
    |-p|파일 권한을 저장|
    |-v|묶거나 파일을 풀 때 과정을 화면으로 출력|
    |-f|파일 이름을 지정|
    |-C|경로를 지정|
    |-x|tar 압축을 풂|
    |-z|gzip으로 압축하거나 해제함|

<br>

## chmod
* 파일, 폴더에대한 권한을 변경할 때 사용한다.
* chmod [options] mode[,mode] file
#### options

    |옵션|설명|
    |:--:|:--:|
    |-R|하위 디렉토리의 모든 권한을 변경|
    |-v|실행되고 있는 모든 파일을 출력|
    |-c|실제로 권한이 바뀐 파일만 출력|
    |-f|파일의 권한이 바뀔 수 없어도 에러 메시지를 없이 실행|

  #### mode
  
  * r(4),w(2),x(1)에 관한 값을 더한 것으로 user, group, other에 권한을 부여한다.
    * 705의 경우 user 모든 권한, group 권한 없음, other 읽기 쓰기 권한을 부여한 것이다.

<br>

## 파일 시스템 구조
* /etc/hosts : DNS 설정 파일

<br>

## 실시간으로 로그 보기
* 파일에 계속 추가되는 내용들을 실시간 모니터링 가능하다.
```console
$ tail -f [파일경로]
```
#### options

  |옵션|설명|
  |:--:|:--:|
  |n | 마지막으로부터 몇 줄 출력
  |c | 마지막으로부터 몇 Byte까지 출력
  |f | 로그파일 실시간 모니터링 

<br>

## more
* more 명령어는 특정파일의 내용을 확인하는 그 페이지에서 바로 vi 로 파일을 열어서 편집을 할 수도 있으며 텍스트 파일의 내용을 한 페이지씩 차례대로 확인할 수 있다.
``` console
$ more file
$ ls -l /etc | more
```
#### options

    |옵션|설명|
    |:--:|:--:|
    |h | more 명령어상태에서 사용할 수 있는 키 도움말 확인
    |Space Bar | 한 화면씩 뒤로 이동하기 (f와 동일)
    |Enter | 현재행에서 한 행씩 뒤로 이동하기
    |q | more 명령어 종료하기
    |f | 한 페이지씩 뒤로 이동하기(Space Bar 와 동일)
    |b | 한 페이지씩 앞으로 이동하기
    |= | 현재 위치의 행번호 표시하기
    |/문자열 | 지정한 문자열을 검색하기
    |n | /문자열로 검색한 문자열을 차례대로 계속해서 찾기
    |!쉘명령어 | more 명령어상태에서 쉘명령어를 실행하기
    |v | more 명령어로 열려있는 파일의 현재위치에서 vi를 실행하기

<br>

## 정규식을 이용하여 파일 삭제하기

``` console
$ find . -regex "expr" -exec rm {} \;
```
* regex의 "expr"안에는 폴더 경로까지 신경써야 합니다.
  * 예를 들어, 파일 이름 중간에 _Info_가 들어가는 파일을 찾기 위해서는 ```"./\w+_info_.*"```로 작성해주셔야 합니다.
* {}: find에서 찾은 파일들을 의미합니다.
* \;: -exec 옵션 내용의 끝을 나타냅니다.

<br>

## 참고 사이트

1. https://webdir.tistory.com/142