---
title: SET-UID Program
tags: security set_uid
key: page-set_uid_program
cover: /assets/cover/cyber_security.png
mathjax: true
mathjax_autoNumber: true
---

* privileged program: 접근 권한이 적용되어 있는 프로그램
* 이런 프로그램에 접근하기 위해서는 2가지 방법이 필요하다. 
1. Set-UID program.
    * 사용자가 필요에 따라 privilege변환이 필요할때 이용하는 프로그램이다.
2. Daemons(Services in Windows)
    * 데몬으로 항상 띄워 놓으면 normal user가 daemon에 request를 날려서 그 프로그램을 통해 privileged program을 실행 시킬 수 있을 것이다.

## 3가지 유저의 형태

* real user ID: 실행되고 있는 프로세스의 진짜 주인.
* effective user ID: access control 안에서 사용되고 있는 ID. 즉 root권한으로 설정된 프로세스를 실행시키면 real user ID는 5000이지만 effective suer ID는 0이 된다.
* saved user ID

## Attack Surfaces of Set-UID Programs

### User Inputs: Explicit Inputs
* Buffer overflow vulnerability
* format string vulnerability
* earlier version of chsh - shell program의 기본값을 바꾸는 프로그램인데 공격자가 새로운 루트 어카운트를 만들수 있도록 허용해버린다.

### System Inputs
* 다른 사용자에 의해 시스템 input 자체가 변조되어버리면 system input은 system에서 왔다고 하더라도 믿을 수 없게 된다. 이런 취약점을 이용한 것이 race condition attack이다.

### Environment Variables: Hidden Inputs
* developer가 직접 만들지 않았지만 프로그램을 실행할때 들어가는 것으로써 여러가지 위험이 도사리고 있는 부분이다.

### Capability Leaking
* su의 작동원리와 마찬가지로 privileged process에서 non-privileged process과정으로 넘어갈때 흔히 발생하는 실수이다.
* 특정 파일을 열고 그것을 close하지 않는다면 열려 있는 정보를 사용할 수도 있게 된다.

## Invoking Other Programs

* 프로그램을 작동하다보면 외부 프로그램을 실행할 수 밖에 없는 경우가 생긴다. 하지만 이런 경우들로 인해 취약점이 발생한다.
* system()함수는 안 쓰는게 좋다. External commmand를 실행 시킬 수 있게 하고 ;을 통해 shell 같은 것을 실행 시킬 수 있게 하기 때문이다.
* execve()함수를 쓰는게 나은데 shell program이 아니라 os에게 바로 specifeid command를 실행시켜달라고 하니 ;를 통한 공격같은 것을 할 수 없게 된다. 왜냐하면 첫번째 인자를 실행시키고 두번째 argument에 관한 인자를 정확히 그 프로그램의 파라미터로 보내기 때문에 ;로 이어지는 실행이 되지 않는다.
* 따라서 exec() family of functions를 쓰는게 좋다.
* 보안에서 기본이 되는 원칙은 priciple of data/code isolation이다.
    * input data에서 code가 실행되면 안 된다. system()의 파라미터는 data로 써야되지만 ;로 또 다른 program을 시킬 수 있게 되면서 코드로 사용되어 보안의 기본 원칙에서 벗어난 잘못된 함수이다.
    * cross-site scripting attack, SQL-injection, buffer-overflow attack 모두 위의 원칙을 어김으로써 가능한 공격 방식들이다.

## Refrence

* [COMPUTER SECURITY: A Hands-on Approach by Wenliang Du](https://www.amazon.com/Computer-Security-Hands-Approach-Wenliang/dp/154836794X)