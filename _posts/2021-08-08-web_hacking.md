---
title: Web hacking
tags: Web-Hacking Cybersecurity
key: page-web_hacking
categories: [Cybersecurity, Web Security]
author: hyoeun
math: true
mathjax_autoNumber: true
---

## Index checks
1. /robots.txt
1. /sitemap.xml
1. /crossdomain.xml
1. /clientaccesspolicy.xml
1. /.well-known/
1. Check also comments in the main and secondary pages.

# 300 Error
1. 301 Moved Permanently
1. 302 Found
1. 304 Not Modified

# 400 Error
1. 400 Bad Request로써, 요청 실패-문법상 오류가 있어서 서버가 요청 사항을 이해하지 못함
1. 401 Unauthorized, 이 요청은 인증이 필요하다. 서버는 로그인이 필요한 페이지에 대해 이 요청을 제공할 수 있다. 상태 코드 이름이 권한 없음(Unauthorized)으로 되어 있지만 실제 뜻은 인증 안됨(Unauthenticated)에 더 가깝다.
1. 403 Forbidden, 서버가 요청을 거부하고 있다. 예를 들자면, 사용자가 리소스에 대한 필요 권한을 갖고 있지 않다. (401은 인증 실패, 403은 인가 실패라고 볼 수 있음)
1. 404 Not Found, 문서를 찾을 수 없음->클라이언트가 요청한 문서를 찾지 못한 경우에 발생함 (URL을 잘 살펴보기)
1. 405 Method not allowed, 메소드 허용 안됨-> Request 라인에 명시된 메소드를 수행하기 위한 해당 자원의 이용이 허용되지 않았을 경우 발생함.    (페이지는 존재하나, 그걸 못보게 막거나 리소스를 허용안함)
1. 415, 지원되지 않는 형식으로 클라이언트가 요청을 해서 서버가 요청에 대한 승인을 거부한 오류를 의미한다. (ContentType,Content Encoding 데이터를 확인할 필요가 있다.)

# 500 Error
1. 500 Internal Server Error, 서버 에러를 총칭하며 서버가 예상하지 못한 상황에 놓였다는 의미.

# PHP eval()
* eval()함수는 () 안에 있는 것을 실행시키는 것을 의미한다. 따라서 안에 해커가 exploit할 수 있는 확률이 매우 높다.

## dirsearch
* python3 dirsearch -u http://xxx.com:4514
 
## XSS 공격
* url 뒤에 ```abc.com/<img alt=" " src=x onerror="alert('xss')">``` 을 넣어서 xss 확인을 해볼 수 있다.

## Flask/Jinja 관련 공격
* 우선 \{\{3*'6'\}\}와 같은 방식으로 넣었을 때 숫자로 결과가 나오면 Twig이고 3이 6번 나오면 Jinja2이다. 
* 다음 코드로 공격을 시도한다. \{\{"".\_\_class__.\_\_mro__[1].\_\_subclasses__()[186].\_\_init__.\_\_globals__["\_\_builtins__"]\["\_\_import__"]\("os").popen("ls").read()}}

* 세션이 .으로 시작하면 zlib으로 compression이 된 것이다. 그냥 e로 시작하면 base64로만 인코딩 된 것이다.
* 세션은 특정 키 없이 decode가 가능하지만 encode할때에는 key가 필요하다. JWT와 비슷한 구조로 되어 있는데 .으로 구분이 된다. 첫번째 공간은 메시지가 담겨 있고 그 다음은 timestamp 마지막은 signing에 관한 것이다. flask-session-cooke-manager 오픈소스를 사용하면 좋다.

* MRO(Method Resolution Order)은 파이썬에 있는 classes의 hierarchy안에 있는 method를 보여주는 역할을 한다. 위에서 __mro__가 그 역할을 하고 첫번째 것을 보겠다는 것이다.
* \__maro__\[1]은 object 클래스에 관한 것이다.
* \__subclasses__()\[186]은 class warnings.catch_warnings이다.
* 뒤에 os까지에는 모듈 os가 작동된다. 이후에 popen을 통해 os의 명령어를 실행한다. 마지막 read를 통해 그 안의 명령어 실행 결과를 읽는다.

## References
* [https://book.hacktricks.xyz/pentesting/pentesting-web](https://book.hacktricks.xyz/pentesting/pentesting-web)
* [Hash took kit](https://hashtoolkit.com/)
* [Baking the code](https://gchq.github.io/CyberChef/)