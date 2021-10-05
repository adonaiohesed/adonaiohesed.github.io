---
title: SQL Injection Attack
tags: security sql_injection
key: page-sql_injection_attack
cover: /assets/cover/cyber_security.png
mathjax: true
mathjax_autoNumber: true
---

## Introduction
* 이것도 data와 code가 분리되지 않아서 생기는 문제이다.
* 이런 공격들의 문제는 보통 untrusted data(input data from user)와 trusted data(by program)이 mixed되면서 그 둘간의 경계선이 분명했던 것이 불분명하게 바뀌면서 허점들이 생긴다.
* 두번째로 mixed된 것들이 parser로 가면서 speial charater를 처리하지 않으면 code로써 실행이 되어 문제가 생기는 것이다.
* C에서는 컴파일 과정을 거치면서 code와 data가 분리되기 때문에 웹 application보다 공격이 어려운 것이다.
* web application은 인터프리터이기 때문에 dynamic하게 코드를 생산할 수 있어서 더 취약한 것이다.
* C 같은 경우는 return address를 통해서 data쪽으로 code를 돌릴 수 있어서 code와 data가 섞인 공격인 BOF가 존재한다.
* [SQL Injection 기초](https://adonaiohesed.github.io/2018/03/01/sql_injection.html)에 많은 것들이 설명되어 있으니 자세한 공격법은 생략한다.
* GUI보다 cRUL로 공격을 시도하면 더 쉽게 자동화 공격을 할 수 있다.
* 공격을 할때에는 해당 DB프로그램에서 먼저 공격하려는 statement를 실행해봐야한다. 서버에서는 보통 에러메시지를 return하지 않기 때문에 문법상 오류가 있는지 없는지 확인 한 후에 공격을 시도해야한다.
<br><br>

## MySQL Usage
```sql
SELECT Name, Slary, SSN
FROM employee
WHERE eid='EDI5002' and password='1234';
```
```sql
UPDATE employee
SET password='paswd456', salary=100000
WHERE eid='EID4000' and password='passwd123';
```
```sql
SELECT Name, Slary, SSN
FROM employee
WHERE eid='EDI5002' and password='1234'; DROP DATABASE dbtest;
```
<br><br>

## Countermeasure
### Filtering and Encoding Data
* 가장 처음 user input을 받을 때에는 data와 code가 분리된 상태이기 때문에 data가 무엇인지 정확히 안다.
* 이 때 data를 encoding하여 NULL, \r, \n, \b, \t, Control-Z, \, ', ", %, _와 같은 특수 문자들을 코드로 사용할 수 없도록 encoding시킨다.
* 하지만 이 방법은 안 하는 것보다는 안전하지만 완벽하게 SQL injection을 막을수 없다. 여전히 코드로 사용 가능할 수 있는 여지가 있기 때문이다.

### Prepared Statement
* 이 방법은 code와 data를 완전히 분리하는 방법으로써 system()의 취약점을 execve()로 해결했던것과 동일한 원리이다.
* SQL도 마지막에는 파싱을 한 후 binary로 만들어져야될텐데 이 방법을 쓴다면 먼저 SQL statement를 만들어 놓고(template) the template는 바뀌지 않은 상태로 단순히 데이터만 나중에 여기에 bind시킨다. 이미 컴파일이 되고 최적화가 끝마친 것이고 재사용도 가능하게 되는 것이다.
* 이런 구조가 security를 위해 만들어진 것은 아니지만 굉장히 secure하게 만든다.
* 이것이 효과가 있는 이유는 code는 code channel로 들어오게 되고 data는 data channel로 들어와서 code와 data사이의 경계가 분명하고 data가 code로 실행되는 일이 없기 때문이다.
* template들은 execution 직전까지 optimization을 끝내고 cache에 담겨서 binary로 나와있는 상태이고 이후 data는 컴파일 단계 없이 바로 data공간으로 가서 execution이 되기 때문에 안전하고 빠르게 실행될 수 있는 것이다.
<br><br>

## Refrence
* [COMPUTER SECURITY: A Hands-on Approach by Wenliang Du](https://www.amazon.com/Computer-Security-Hands-Approach-Wenliang/dp/154836794X)