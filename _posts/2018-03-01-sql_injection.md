---
title: SQL Injection 기초
tags: SQL-Injection
key: page-sql_injection_basics
categories: [Cybersecurity, Web Security]
author: hyoeun
---

* SQL에서 대소문자는 구분하지 않는다.
* length(pw)=8은 pw의 길이가 8인지 확인하는 구문이다.
* str_replace("admin",'',<something>)은 something부분에서 admin이 있다면 공백으로 바꾸고 남은 <something>을 표현하는 것이다.
* 문자열을 ASCII로 바꾸는 함수는 ascii(str)이다.
* '과 "은 동일하다.
* where 구문 뒤에 여러가지 조건이 오지만 중간에 정보들은 뒤에 정보에 의해 덮어씌어질 수 있다.
* LIKE '' 구문 안에는 %가 들어갈 수 있다. %는 wilde card 느낌이다. %영 이라고 하면 영으로 끝나는 것을 찾고 김%이라면 김으로 시작하는 것을 찾고 김%수 라면 김x수에 해당하는 모든 것을 찾는다.
* LIKE 안에 _는 한글자를 의미한다.
* [a-e]%는 a부터 e사이의 알파벳중 하나로 시작하는 모든 것을 의미한다. []안에 !(NOT)을 포함 시킬 수 있다.

### =과 동일한 기능
* ```like``` : id like 'admin'
* ```in``` : id in ('admin') # in 뒤에는 여러개의 value가 ,로 이어져서 올 수 있다.

### 주석처리
* ```#``` == ```%23```
* ```-- ```
* ```/* */```

### 스페이스
* ```SP``` == ```%20```
* ```\t``` == ```%09```
* ```\n``` == ```%0a``` # Line Feed
* ```VT``` == ```%0b``` # 6줄 스페이스를 의미
* ```FF``` == ```%0c``` # 프린트에 이 문자를 보내면 종이를 그냥 내보낸다. (Form Feed)
* ```\r``` == ```%0d``` # Carriage Return

### 논리 연산자
* ```and``` == ```&&``` == ```%26%26```
* ```or``` == ```||``` == ```%7c%7c```

### 문자열 자르기
* ```substr()``` == ```substring()``` == ```mid()```
  * * substr(pw,2,1)='1'은 pw 두번째부터 1개의 문자로 짜른것을 의미하기에 즉 두번째 pw 문자가 1인지 확인하는 구문이다.

## URL encoding에 관련하여서
<img alt=" " src="/assets/images/url_encoding.png">

## ASCII CODE
<img alt=" " src="/assets/images/asciicode.jpg">

## 했던 공격 예시
* username=sadcowboy&password=' +OR '1'='1
* name=' OR '1'='1&password=' OR '2'>'1
  * => SELECT * FROM users WHERE login = '' OR '1'='1' AND password ='' OR '2'>'1' LIMIT 1
  * 위의 경우에 데이터 베이스에 있는 첫 번째 유저로 로그인이 가능하게 될 것이다.



