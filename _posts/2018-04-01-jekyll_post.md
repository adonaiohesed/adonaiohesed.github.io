---
title: Jekyll posting 관련
tags: Jekyll
key: page-jekyll_posting
categories: [Tools, Jekyll]
author: hyoeun
---

## 지킬 포스팅 규칙
1. 댓글에 관한 key값을 page-제목 으로 할 것이기 때문에 제목은 가능하면 상세하게 기술하여 중복을 피한다.

<br>

## escape 가 필요한 특수 문자
```
\   backslash
`   backtick
*   asterisk
_   underscore
{}  curly braces
[]  square brackets
()  parentheses
#   hash mark
+   plus sign
-   minus sign (hyphen)
.   dot
!   exclamation mark
```
<br>

## Code Highlight 사용
* 기본 사용법은 4가지가 있다.

````
```ruby

code... 

```
````

~~~~
~~~php

code...

~~~
~~~~

```html
<pre><code class="html">

code...

</code></pre>
```

{% highlight md %}

{% raw %}{% highlight md %}

code...

{% endhighlight %}{% endraw %}

{% endhighlight %}

* [위에서 class에 해당하는 다른 것들은 뭐가 있는지 알 수 있는 사이트](http://rouge.jneen.net/)

<br>

## 들여 쓰기

* 리스트 안에서 \`\`\` 코드 블락을 쓸 때, 엔터가 존재하면 깨질 때가 있다.<br>그럴 때 \`\`\` 블락 전체에 space 2 혹은 4를 주면 정렬이 된다.
  
  ````
  1. BOOTPROTO의 값을 static으로 변경시켜줍니다.
  2. 이후 자신이 고정하고자 하는 IP, Gateway, DNS 서버 설정을 해줍니다.
      ```conf
      TYPE="Ethernet"
      PROXY_METHOD="none"
      BROWSER_ONLY="no"
      #BOOTPROTO="dhcp"
      DEFROUTE="yes"
      IPV4_FAILURE_FATAL="no"
      IPV6INIT="yes"
      IPV6_AUTOCONF="yes"
      IPV6_DEFROUTE="yes"
      IPV6_FAILURE_FATAL="no"
      IPV6_ADDR_GEN_MODE="stable-privacy"
      NAME="enp0s3"
      UUID="91af51db-7cf0-4069-9433-77d356b31bca"
      DEVICE="enp0s3"
      ONBOOT="yes"

      BOOTPROTO="static"
      IPADDR="192.168.0.123"
      GATEWAY="192.168.0.1"
      DNS1="168.126.63.1"
      DNS2="168.126.63.2"
      ```
  ````

* \* 나 1. 을 쓰고 표를 들여쓰기 하기 위해서는 엔터 하나와 들여쓰기 4개가 필요하다.
    
  ```
  * 테스트

      |옵션|설명|
      |:--:|:--:|
      |-c|파일을 tar로 묶음|
      |-p|파일 권한을 저장|

  1. 리스트

      |옵션|설명|
      |:--:|:--:|
      |-c|파일을 tar로 묶음|
      |-p|파일 권한을 저장|
  ```

<br>

## list안에 \<p> 가 들어가서 한 칸이 띄어지는 현상

* 이럴때는 리스트들 사이에 엔터 2번이 들어가서 그렇다. 따라서 엔터 1개를 지우면 된다.

<br>

## 강조

* \*\***굵은 글씨**\*\*
* \**이텔릭체*\* 

  

## 다른 문단 만들기

1. 스페이스 2개
2. \\\\

## 정의하기

``` 
단어
: 뜻
```

## 수평선 추가

```
* * *
***
*****
- - -
----------
```
