---
title: Cross-Site Request Forgery
tags: CSRF Web-Hacking Cybersecurity
key: page-csrf_attack
categories: [Cybersecurity, Web Security]
author: hyoeun
math: true
mathjax_autoNumber: true
---

## The Cross-Site Request Forgery (CSRF) Attack

Let's dive deep into **Cross-Site Request Forgery (CSRF)**, one of the most subtle and dangerous attacks in web application security. CSRF is an attack that tricks a user into unknowingly sending malicious web requests, causing them to perform critical actions they never intended.

### Understanding the CSRF Attack: When Your Application is at Risk

To understand CSRF attacks, it's crucial to look at the problem from the perspective of **your web application—the one you manage and must protect.**

When a user interacts with your web application, your server assigns them a unique identifier called a **session** to track their activities. This session (often stored as a **session cookie**) is the sole means by which your server recognizes the user when they revisit your site or navigate between pages. This session remains valid until the user logs out or closes their browser. CSRF attacks exploit the very **trust placed in these sessions.**

Here's the rub: Web browsers are designed to **automatically include all cookies associated with a specific domain** when sending a request to that domain, **regardless of where the request originated.** This applies equally to requests coming from your own website (same-site requests) and potentially malicious websites (cross-site requests). When your server receives a request with a valid session cookie, it **cannot distinguish** whether this request was genuinely intended by your user or was forged from another site.

### Why Does the Browser Use My Cookies for Cross-Site Requests from Malicious Pages?

This is the most critical aspect of how CSRF attacks work, and it's a point that can easily confuse developers. The reason why the browser automatically includes your web application's session cookies even in **cross-site requests initiated by a malicious web page** stems from the browser's fundamental **cookie management policy.**

This policy was originally designed to provide user convenience and maintain the basic functionality of the web. However, ironically, it becomes the very point exploited by CSRF attacks.

Here are the core principles:

1.  **Cookies are managed based on their Domain.**

      * Browsers store cookies issued by a specific domain (e.g., `bank.com`, `mywebapp.com`) by associating them with that domain.
      * When a user logs in to `mywebapp.com`, the `mywebapp.com` server issues a cookie containing the session ID to the browser. The browser then stores this cookie, linked to the `mywebapp.com` domain.

2.  **The browser automatically includes cookies for all HTTP requests to their associated domain.**

      * Regardless of which page the user is currently viewing (whether `malicious.com` or `mywebapp.com`), the browser will **automatically find and include any cookies associated with the `mywebapp.com` domain in the request headers for every HTTP request sent to `mywebapp.com`.**
      * For example, if a `malicious.com` page contains an `<img>` tag with a URL like `mywebapp.com/action`, the browser, upon attempting to load this image, will send a request to `mywebapp.com`, **automatically attaching all cookies associated with `mywebapp.com` (including the login session cookie).**

3.  **Servers tend to judge the origin of a request solely by its cookie.**

      * From the perspective of your `mywebapp.com` server, there's no inherent way to directly know if a request originated from `mywebapp.com` or `malicious.com`. The HTTP request itself doesn't inherently include clear information stating "this request originated from here" (though headers like `Referer` exist, they can be manipulated).
      * Therefore, if a request contains a **valid session cookie, your server will likely interpret it as a legitimate request sent by an authenticated user.** Since the browser automatically attached the cookie, your server simply recognizes the user as being "already authenticated."

**In summary:**

Browsers adhere to the rule of automatically attaching cookies for a given domain to every request destined for that domain, all in the name of user convenience. Due to this rule, even if a forged request is sent from a malicious page, as long as its destination is your web application, the browser will automatically and unknowingly attach your web application's session cookie. This is the core operational principle that makes CSRF attacks possible.

Therefore, the defense against CSRF, given that browsers' fundamental behavior cannot be changed, **must involve additional verification mechanisms on your server-side (like CSRF tokens or Same-Site cookie settings) to identify and block forged requests.**

### The Attack Flow: How Your Application Gets Targeted (Revisited)

1.  **Your User is Logged In:** A user has an **active, valid session** (and thus a session cookie) with **your web application** (the target website).
2.  **The Attacker's Malicious Page:** An attacker creates a **malicious web page.** This could be a website specifically crafted by the attacker, or it could be a legitimate website that the attacker has compromised and injected with malicious code (e.g., via an XSS vulnerability).
3.  **The User Visits the Malicious Page:** Your user, while still logged into your application in another browser tab or window, **visits this malicious page.**
4.  **The Forged Request is Sent:** The malicious page subtly tricks the user's browser into **sending a forged request to your web application**—without the user's knowledge or consent. This might happen through a hidden form that auto-submits, a hidden image tag, or a JavaScript-triggered request.
5.  **The Browser Sends the User's Session Cookie:** **(As explained by the browser's cookie management policy above)** The user's browser automatically includes the active session cookie with this forged request.
6.  **Your Server Trusts the Request:** Your web application (the server), upon receiving the request with a valid session cookie, **mistakenly believes it's a legitimate request from your authenticated user.** Consequently, your application performs the unintended action (e.g., changes the user's password, transfers funds, deletes data).

This flow clearly illustrates why **CSRF defenses must be implemented on your server-side.** The client (the user's browser) is merely the unwitting vehicle for the attack, not the entity responsible for defending against it.

### CSRF Attacks on HTTP GET Services

Services that handle sensitive operations via HTTP GET methods can be particularly vulnerable to CSRF.

  * GET requests **transmit data directly in the URL (as query string parameters).**
  * An attacker can easily craft a forged GET request URL. For instance, if a banking website processes transfers with a GET request like `GET /transfer?to=attacker_account&amount=1000`, the attacker could embed an HTML tag such as `<img src="http://bank.com/transfer?to=attacker_account&amount=1000">` on their malicious page.
  * When the victim visits this malicious page, their browser attempts to load the `<img>` tag by sending a request to `bank.com`. If the victim is logged into `bank.com`, their browser automatically includes the session cookie, and the bank's server will process this as a legitimate transfer request.
  * In addition to image tags, `<iframe>` and `src` attributes in `<script>` tags can also easily trigger GET requests.

### CSRF Attacks on HTTP POST Services

While HTTP POST services are also susceptible to CSRF, they generally require slightly more complex techniques than GET.

  * POST requests **transmit data in the request body.**

  * Attackers typically forge POST requests by using **hidden `<form>` tags that are automatically submitted.**

  * For example, if a service changes passwords via a `POST /change_password` request, an attacker could create a hidden form on their malicious page:

    ```html
    <form action="http://target.com/change_password" method="POST" id="csrfForm">
        <input type="hidden" name="new_password" value="attacker_password">
        <input type="hidden" name="confirm_password" value="attacker_password">
    </form>
    <script>document.getElementById('csrfForm').submit();</script>
    ```

  * When the victim visits this page, the form is automatically submitted via JavaScript. If the victim is logged into the target website, their session cookie is included, and their password could be changed to the attacker's chosen value.

  * POST requests are less visible to the user when forged than GET requests. However, unlike GET requests, they cannot be triggered by simply clicking a URL link without other vulnerabilities like XSS. This is because POST requests require specific user interaction or script execution; without a vulnerability like XSS to run arbitrary JavaScript, triggering a POST-based CSRF attack is difficult.

### Countermeasures: Protecting Your Application

Many websites suffer from CSRF vulnerabilities, often because developers don't adequately consider the potential damage from this attack. However, **defending against CSRF attacks is relatively straightforward** when correctly implemented on your server-side. It's crucial to understand that while many security policies operate at the browser level, the core responsibility for **Referer validation and Secret Token implementation lies with your server (web application).**

#### 1\. Using the Referer Header

  * The HTTP request header includes a `Referer` field, which indicates the URL of the previous web page from which the request originated. Your server can check this `Referer` header to determine if the request came from your own domain or from another website (cross-site).
  * If the `Referer` is not your domain, you can treat that request as a CSRF attack and block it.
  * **Drawbacks:** This method has limitations due to privacy concerns. Many browsers allow users to disable or limit the transmission of the `Referer` header to avoid disclosing Browse history. Furthermore, if an attacker can manipulate the `Referer` header (e.g., by combining with XSS), this defense can be bypassed, making it insufficient for standalone protection.
  * Theoretically, it would be beneficial to create a new field that removes privacy-sensitive information from the `Referer` header while still indicating the cross-site status, but such a standard has not yet been widely adopted.

#### 2\. Same-Site Cookies

  * `Same-Site` cookies are a relatively new defense mechanism designed to mitigate CSRF attacks at the browser level. They are already widely implemented in major browsers like Chrome and Opera.
  * The `Same-Site` attribute is set on a cookie by your server and can have one of three values:
      * **`Strict`:** The cookie is sent **only with same-site requests.** It is not sent with any cross-site requests, providing strong protection against CSRF attacks. (e.g., `Set-Cookie: sessionid=abcdef; SameSite=Strict`)
      * **`Lax`:** The cookie is sent with **same-site requests and with top-level navigation requests** initiated from cross-site contexts (like clicking an `<a href="...">` link). However, it is not sent with other cross-site requests (including non-safe HTTP methods) such as those from `<img>` or `<iframe>` tags. This provides significant protection while maintaining user experience.
      * **`None`:** This behaves identically to having no `Same-Site` attribute, meaning the cookie is sent with all cross-site requests. In this case, it **must** be used in conjunction with the `Secure` attribute (meaning it's only sent over HTTPS).
  * `Same-Site` cookies are automatically applied by the browser, offering the advantage that developers don't need to manage separate CSRF tokens. However, they are not universally supported by all browsers, and there's a possibility of bypass in specific scenarios, so combining them with other defenses is safer.

#### 3\. Secret Token

While `Same-Site` cookies are a browser-driven defense, the **Secret Token method is one of the most effective CSRF defense techniques that enables your web application itself to identify and defend against CSRF requests.**

  * **Synchronizer Token Pattern:**

      * Your server issues an **unpredictable random value (CSRF token)** to the client.
      * This token is **uniquely generated for each session** and embedded in the web page provided to the user (e.g., as a hidden field in an HTML form or a JavaScript variable).
      * When the client (user's browser) sends a request to your server, this token is also included in the request.
      * Your server validates the request by checking if the transmitted token matches the token stored on the server side for the current user's session. If they don't match, the server identifies it as a forged cross-site request and blocks it.
      * Due to the Same-Origin Policy, an attacker cannot read the HTML of your target website to directly extract this token value, making it impossible for them to include a valid token in their forged request.

  * **CSRF Token Storage and Transmission Methods:**

      * **Hidden Form Field:** The most common method involves including the token as a hidden field inside an HTML form: `<input type="hidden" name="csrf_token" value="RANDOM_TOKEN">`.
      * **Custom HTTP Header:** For AJAX requests, the token can be included in a custom header like `X-CSRF-Token`. Client-side JavaScript can read the token from a cookie and add it to the header (Double Submit Cookie Pattern).

#### 4\. Same-Origin Policy (SOP)

  * The **Same-Origin Policy (SOP)** is a fundamental security constraint built into web browsers that prevents JavaScript from accessing web pages from different domains.
  * This policy **restricts script access to resources only if they originate from the same protocol, host, and port.** These restrictions help mitigate XSS attacks and partially aid in CSRF defense. For example, when an attacker tries to send a forged request via a malicious script, SOP prevents them from reading the target website's response or directly extracting CSRF tokens.
  * **Limitations:** In modern web development, it's common to use external APIs and separate client (frontend) and server (backend) development. In such environments, SOP can cause many inconveniences, leading to the use of **CORS (Cross-Origin Resource Sharing) policy** to overcome these limitations.

#### 5\. Cross-Origin Resource Sharing (CORS)

**Cross-Origin Resource Sharing (CORS)** is a **standard mechanism introduced to alleviate the inconveniences of SOP.** CORS allows a web application running at one origin to access selected resources from a different origin using additional HTTP headers.

  * **Important: CORS is not directly related to preventing CSRF.** CORS is less a security mechanism and more a **mechanism that enables legitimate cross-site requests that would otherwise be blocked by SOP.** It's a way of saying, "I'm allowing external requests, but I'll first check if they're safe."
  * As modern web development increasingly involves external API usage and separated client/server architectures, SOP's restrictions can be inconvenient. Your application often uses CORS to permit legitimate requests from other domains.

#### How CORS Works

CORS involves the server sending additional HTTP headers to the browser to define its resource-sharing policy. This process involves either a **Preflight Request** or a **Simple Request.**

  * **Simple Request (without Preflight):**

      * The client (browser) sends a request to your server including an `Origin` header.
      * Your server checks this `Origin` header to see if the requesting origin matches what's allowed in the `Access-Control-Allow-Origin` response header.
      * If the origin is allowed, access is granted; otherwise, it's denied. The browser then blocks or allows the response based on the server's CORS policy.
      * Simple Requests typically use `GET`, `HEAD`, or `POST` methods, allow only specific HTTP headers, and have a `Content-Type` that is one of a few allowed values (e.g., `application/x-www-form-urlencoded`, `multipart/form-data`, `text/plain`).

  * **Preflight Request:**

      * Unlike a Simple Request, the browser first sends an `OPTIONS` method HTTP request to the resource on a different domain to **check if the actual request is safe to send.**
      * **A `Preflight Request` is performed when a cross-site request could affect user data** (e.g., using `PUT` or `DELETE` methods, including custom headers, or having a `Content-Type` other than the allowed simple ones).
      * In a `Preflight Request`, headers like `Access-Control-Request-Method` and `Access-Control-Request-Headers` are included.
      * Your server responds with `Access-Control-*` family headers such as `Access-Control-Allow-Origin`, `Access-Control-Allow-Methods`, `Access-Control-Allow-Headers`, and `Access-Control-Max-Age`.
      * Once the browser determines from this `Preflight Request` that the origin is allowed, it then sends the actual request, which is processed identically to a Simple Request's response.

### CSRF Token Strategy: Single Token vs. Per-Request Token

  * **If you have a choice between using a single CSRF token for multiple requests (session-based token) and requiring a unique CSRF token for each request (per-request token), which is safer?**

      * **The latter (a unique CSRF token for each request) is generally safer.**
      * **Per-request token method:** Because a new CSRF token is generated and validated for each request, even if an attacker manages to steal a token, it's only valid for that single request. This prevents replay attacks and minimizes the chances of a successful attack. However, it can incur higher server resource consumption and implementation complexity for your application.
      * **Session-based token method:** The same CSRF token is reused throughout the session. While simpler to implement, if an attacker steals this single token, there's a risk that they could send multiple forged requests as long as the session remains valid.

    Considering the balance between security and user experience, it's generally recommended to use session-based tokens but **require a separate, one-time token or additional authentication (e.g., re-entering the password) for critical operations** like password changes or fund transfers.

## References

  * [COMPUTER SECURITY: A Hands-on Approach by Wenliang Du](https://www.amazon.com/Computer-Security-Hands-Approach-Wenliang/dp/154836794X)

-----

## The Cross-Site Request Forgery (CSRF) Attack

웹 애플리케이션 보안에서 가장 교묘하고 위험한 공격 중 하나인 **크로스-사이트 요청 위조(Cross-Site Request Forgery, CSRF)**에 대해 심층적으로 알아보겠습니다. CSRF는 사용자가 의도치 않게 악의적인 웹 요청을 보내도록 유도하여 중요한 작업을 수행하게 만드는 공격입니다.

### CSRF 공격 이해하기: 여러분의 애플리케이션이 위험에 처할 때

CSRF 공격을 이해하려면 **여러분이 관리하고 보호해야 할 바로 그 웹 애플리케이션**의 관점에서 문제를 파악하는 것이 중요합니다.

사용자가 여러분의 웹 애플리케이션과 상호작용할 때, 여러분의 서버는 사용자에게 고유한 식별자인 **세션(Session)**을 부여하여 그들의 활동을 추적합니다. 이 세션(종종 **세션 쿠키** 형태로 저장됨)은 사용자가 여러분의 사이트를 재방문하거나 페이지를 이동할 때, 여러분의 서버가 사용자를 인식할 수 있는 유일한 수단입니다. 이 세션은 사용자가 로그아웃하거나 브라우저를 닫는 시점까지 유효하게 유지됩니다. CSRF 공격은 바로 이러한 **세션의 신뢰성**을 악용합니다.

문제는 여기에 있습니다. 웹 브라우저는 요청이 어디에서 시작되었는지에 관계없이, 특정 도메인으로 요청을 보낼 때 **해당 도메인과 관련된 모든 쿠키를 자동으로 포함하여 전송하도록 설계**되어 있습니다. 이는 여러분 자신의 웹사이트에서 오는 요청(동일 사이트 요청)뿐만 아니라, 잠재적으로 악의적인 다른 웹사이트에서 시작된 요청(교차 사이트 요청)에도 동일하게 적용됩니다. 여러분의 서버는 유효한 세션 쿠키가 포함된 요청을 받았을 때, 이 요청이 실제로 여러분의 사용자에 의해 의도된 것인지, 아니면 다른 사이트에서 위조된 것인지 **구분할 수 없게 됩니다.**

### 브라우저는 왜 악의적인 페이지의 크로스 사이트 요청에 내 쿠키를 이용하는가?

이 점이 CSRF 공격의 가장 핵심적인 작동 원리이자, 개발자가 혼란스러워할 수 있는 부분입니다. 브라우저가 악의적인 웹 페이지로부터 시작된 **크로스 사이트 요청에도 여러분의 웹 애플리케이션에서 사용한 세션 쿠키를 자동으로 포함하여 보내는 이유**는 브라우저의 근본적인 **쿠키 관리 정책** 때문입니다.

이러한 정책은 본래 사용자에게 웹 사용의 편의성을 제공하고 웹의 기본 작동 방식을 유지하기 위해 고안되었습니다. 하지만 역설적으로 CSRF 공격에 악용되는 지점이 됩니다.

핵심 원리는 다음과 같습니다.

1.  **쿠키는 도메인(Domain) 기반으로 관리됩니다.**

      * 브라우저는 특정 도메인(예: `bank.com`, `mywebapp.com`)이 발행한 쿠키를 해당 도메인에 연결하여 저장합니다.
      * 사용자가 `mywebapp.com`에 로그인하면, `mywebapp.com` 서버는 세션 ID를 포함하는 쿠키를 브라우저에게 발행합니다. 브라우저는 이 쿠키를 `mywebapp.com` 도메인과 연결하여 저장합니다.

2.  **모든 HTTP 요청에 해당 도메인의 쿠키를 자동으로 포함합니다.**

      * 사용자가 어떤 페이지(`malicious.com`이든, `mywebapp.com`이든)를 보고 있든 상관없이, 브라우저는 **`mywebapp.com` 도메인으로 보내는 모든 HTTP 요청에 대해, `mywebapp.com`과 연결된 쿠키를 자동으로 찾아서 요청 헤더에 포함**시킵니다.
      * 예를 들어, `malicious.com` 페이지에 `<img>` 태그로 `mywebapp.com/action` 이라는 URL을 요청하는 코드가 있다면, 브라우저는 이 `<img>`를 로드하기 위해 `mywebapp.com`으로 요청을 보내면서, `mywebapp.com`과 관련된 모든 쿠키(로그인 세션 쿠키 포함)를 자동으로 첨부합니다.

3.  **서버는 요청의 출처를 쿠키로만 판단하는 경향이 있습니다.**

      * `mywebapp.com` 서버 입장에서는, 이 요청이 `mywebapp.com`에서 시작되었는지 `malicious.com`에서 시작되었는지 직접적으로 알 수 있는 방법이 없습니다. HTTP 요청 자체에는 "이 요청은 어디에서 시작되었다"는 명확한 정보가 기본적으로 포함되지 않습니다 (물론 `Referer` 헤더 같은 것은 있지만 조작될 수 있습니다).
      * 따라서 서버는 요청에 **유효한 세션 쿠키가 포함되어 있다면, 이를 로그인된 사용자가 보낸 합법적인 요청이라고 판단**하게 됩니다. 브라우저가 자동으로 쿠키를 보내줬으니, 서버 입장에서는 해당 사용자가 "이미 인증된 상태"라고만 인식하는 것이죠.

**정리하자면:**

브라우저는 사용자의 편의를 위해 "이 도메인에 대한 쿠키는 해당 도메인으로 가는 모든 요청에 자동으로 붙여줘야 해"라는 규칙을 따릅니다. 이 규칙 때문에 악의적인 페이지에서 위조된 요청을 보내더라도, 그 요청의 목적지가 여러분의 웹 애플리케이션이라면, 브라우저는 여러분의 웹 애플리케이션 세션 쿠키를 아무 의심 없이 자동으로 붙여주게 되는 것입니다. 이것이 CSRF 공격이 가능한 핵심적인 작동 원리입니다.

따라서 CSRF 방어는 브라우저의 이러한 기본 동작을 변경할 수 없다는 전제 하에, **여러분의 서버 측에서 추가적인 검증 메커니즘(CSRF 토큰, Same-Site 쿠키 설정 등)을 통해 위조된 요청을 식별하고 차단하는 것**이 필수적입니다.

### 공격 흐름: 여러분의 애플리케이션이 어떻게 타겟이 되는가

1.  **여러분의 사용자가 로그인되어 있습니다:** 사용자가 **여러분의 웹 애플리케이션(타겟 웹사이트)**에 **로그인하여 활성화된 유효한 세션(세션 쿠키)**을 가지고 있습니다.
2.  **공격자의 악성 페이지:** 공격자가 **악의적인 웹 페이지**를 만듭니다. 이 페이지는 공격자가 직접 만든 웹사이트일 수도 있고, 공격자가 XSS(Cross-Site Scripting) 취약점을 통해 합법적인 다른 웹사이트에 악성 코드를 주입하여 변조한 페이지일 수도 있습니다.
3.  **사용자가 악성 페이지를 방문합니다:** 여러분의 사용자는 다른 브라우저 탭이나 창에 여러분의 애플리케이션이 로그인된 상태로 열려있는 동안, **이 악성 페이지를 방문**합니다.
4.  **위조된 요청이 전송됩니다:** 악성 페이지는 사용자도 모르게, 사용자의 브라우저가 **여러분의 웹 애플리케이션에 위조된 요청을 보내도록 교묘하게 유도**합니다. 이는 자동으로 제출되는 숨겨진 폼, 숨겨진 이미지 태그, 또는 JavaScript에 의해 트리거되는 요청 등을 통해 발생할 수 있습니다.
5.  **브라우저가 사용자의 세션 쿠키를 보냅니다:** **(앞서 설명한 브라우저의 쿠키 관리 정책에 따라)** 사용자의 브라우저는 활성화된 세션 쿠키를 이 위조된 요청에 **자동으로 포함하여 전송**합니다.
6.  **여러분의 서버가 요청을 신뢰합니다:** 여러분의 웹 애플리케이션(서버)은 유효한 세션 쿠키가 포함된 요청을 받으면, **이것이 인증된 사용자의 합법적인 요청이라고 착각**합니다. 결과적으로 여러분의 애플리케이션은 사용자가 의도하지 않은 작업(예: 비밀번호 변경, 자금 이체, 데이터 삭제)을 수행하게 됩니다.

이러한 흐름은 **CSRF 방어가 반드시 여러분의 서버 측에서 구현되어야 하는 이유**를 명확히 보여줍니다. 클라이언트(사용자의 브라우저)는 공격에 의도치 않게 이용되는 수단일 뿐, 방어의 주체가 될 수 없습니다.

### HTTP GET 서비스에 대한 CSRF 공격

HTTP GET 메서드를 사용하는 서비스는 CSRF 공격에 특히 취약할 수 있습니다.

  * GET 요청은 **데이터를 URL에 포함하여(쿼리 문자열 형태로) 서버에 전송합니다.**
  * 공격자는 위조된 GET 요청 URL을 매우 쉽게 생성할 수 있습니다. 예를 들어, 은행 웹사이트에 `GET /transfer?to=attacker_account&amount=1000`와 같은 요청으로 송금을 처리하는 기능이 있다고 가정해 봅시다. 공격자는 자신의 악성 페이지에 `<img src="http://bank.com/transfer?to=attacker_account&amount=1000">`와 같은 HTML 태그를 삽입할 수 있습니다.
  * 피해자가 이 악성 페이지를 방문하면, 브라우저는 `<img>` 태그를 로드하기 위해 `bank.com`으로 요청을 보냅니다. 이때 피해자가 `bank.com`에 로그인되어 있다면, 브라우저는 해당 세션 쿠키를 자동으로 포함하여 전송하고, 은행 서버는 이를 정당한 송금 요청으로 처리하게 됩니다.
  * 이미지 태그 외에도 `<iframe>`, `<script>` 태그의 `src` 속성 등을 이용하여 GET 요청을 쉽게 트리거할 수 있습니다.

### HTTP POST 서비스에 대한 CSRF 공격

HTTP POST 메서드를 사용하는 서비스도 CSRF 공격에 취약할 수 있지만, GET 방식보다는 약간 더 복잡한 기법을 사용합니다.

  * POST 요청은 **데이터를 요청 본문(body)에 포함하여 서버에 전송합니다.**

  * 공격자는 일반적으로 자동으로 제출되는 **숨겨진 `<form>` 태그**를 사용하여 POST 요청을 위조합니다.

  * 예를 들어, `POST /change_password` 요청으로 비밀번호를 변경하는 서비스가 있다면, 공격자는 자신의 악성 페이지에 다음과 같은 숨겨진 폼을 만들 수 있습니다.

    ```html
    <form action="http://target.com/change_password" method="POST" id="csrfForm">
        <input type="hidden" name="new_password" value="attacker_password">
        <input type="hidden" name="confirm_password" value="attacker_password">
    </form>
    <script>document.getElementById('csrfForm').submit();</script>
    ```

  * 피해자가 이 페이지를 방문하면, JavaScript를 통해 폼이 자동으로 제출됩니다. 피해자가 타겟 웹사이트에 로그인되어 있다면 세션 쿠키가 포함되어 전송되고, 결과적으로 비밀번호가 공격자가 원하는 값으로 변경될 수 있습니다.

  * POST 요청은 GET 요청보다 사용자 눈에 띄지 않게 위조하기 쉽지만, XSS와 같은 취약점이 함께 존재해야 트리거가 가능합니다. POST 요청은 GET 요청과 달리 특정 사용자 상호작용이나 스크립트 실행이 필요하기에 XSS와 같은 취약점이 없다면 POST 서비스에 대한 CSRF 공격은 어렵습니다.

### 보안 대책: 여러분의 애플리케이션 보호하기

많은 웹사이트가 CSRF 취약점을 가지고 있는 것은 주로 개발자들이 이 공격으로 인한 잠재적 피해를 충분히 신경 쓰지 않기 때문입니다. 하지만 **CSRF 공격을 방어하는 것은 여러분의 서버 측에서 올바르게 구현된다면 비교적 쉽습니다.** 대다수의 보안 정책은 브라우저 단에서 이루어지고 Referer, Secret Token은 서버(웹 애플리케이션)에서 이루어지는거다.

#### 1\. Referer 헤더 사용 (`Referer` Header)

  * HTTP 요청 헤더에는 `Referer` 필드가 존재하며, 이 필드는 요청이 시작된 이전 웹 페이지의 URL을 알려줍니다. 여러분의 서버는 이 `Referer` 헤더를 확인하여 요청이 자신의 도메인에서 온 것인지, 아니면 다른 웹사이트(크로스-사이트)에서 온 것인지 판단할 수 있습니다.
  * 만약 `Referer`가 여러분의 도메인이 아니라면, 해당 요청을 CSRF 공격으로 간주하고 차단할 수 있습니다.
  * **단점:** 이 방식은 브라우징 기록을 노출할 수 있다는 개인 정보 보호 문제로 인해 `Referer` 헤더를 사용하지 않도록 설정하거나, 제한적으로만 전송하는 브라우저가 많습니다. 또한, 공격자가 `Referer` 헤더를 조작할 수 있는 경우(예: XSS와 결합하여) 우회될 수 있으므로, 단독으로 사용하기에는 충분하지 않습니다.
  * 이론적으로는 `Referer` 헤더에서 개인 정보가 드러날 수 있는 부분을 제거하고 cross-site 여부만 확인할 수 있는 새로운 필드를 만들면 좋겠지만, 아직까지 표준화되어 널리 사용되지는 않고 있습니다.

#### 2\. Same-Site 쿠키 (`Same-Site` Cookies)

  * `Same-Site` 쿠키는 브라우저 수준에서 CSRF 공격을 완화하기 위해 고안된 비교적 새로운 방어 메커니즘입니다. Chrome 및 Opera와 같은 주요 브라우저에서 이미 구현되어 널리 사용되고 있습니다.
  * `Same-Site` 속성은 여러분의 서버에 의해 쿠키에 설정되며, 세 가지 값 중 하나를 가질 수 있습니다:
      * **`Strict`:** 쿠키가 **동일 사이트 요청(Same-Site Request)에서만 전송**됩니다. 크로스-사이트 요청에서는 쿠키가 전송되지 않아 CSRF 공격을 강력하게 방어할 수 있습니다. (예: `Set-Cookie: sessionid=abcdef; SameSite=Strict`)
      * **`Lax`:** 쿠키가 **동일 사이트 요청과 함께, `<a href="...">`와 같은 최상위 탐색(top-level navigation) 요청에는 전송**되지만, `<img src="...">`나 `<iframe>`과 같은 다른 크로스-사이트 요청(비안전 HTTP 메서드 포함)에는 전송되지 않습니다. 이는 사용자 경험을 해치지 않으면서도 상당한 보호를 제공합니다.
      * **`None`:** `Same-Site` 속성이 없는 것과 동일하게 작동하며, 모든 크로스-사이트 요청에 쿠키가 전송됩니다. 이 경우 반드시 `Secure` 속성(HTTPS에서만 전송)과 함께 사용되어야 합니다.
  * `Same-Site` 쿠키는 브라우저에 의해 자동적으로 적용되므로 개발자가 별도의 CSRF 토큰을 관리할 필요가 없다는 장점이 있습니다. 그러나 모든 브라우저에서 완벽하게 지원되는 것은 아니며, 특정 상황에서 우회될 가능성도 있으므로 다른 방어책과 병행하는 것이 안전합니다.

#### 3\. 비밀 토큰 (Secret Token)

`Same-Site` 쿠키가 브라우저에 의해 자동적으로 적용되는 방어책이라면, **비밀 토큰(Secret Token) 방식은 여러분의 웹 애플리케이션 스스로가 CSRF 요청을 식별하고 방어할 수 있도록 하는 가장 효과적인 CSRF 방어 기법 중 하나**입니다.

  * **동기화 토큰 패턴 (Synchronizer Token Pattern):**

      * 여러분의 서버는 클라이언트에게 예측 불가능한 **랜덤 값(CSRF 토큰)**을 부여합니다.
      * 이 토큰은 **세션마다 고유하게 생성**되며, 사용자에게 제공하는 웹 페이지(HTML 폼의 숨겨진 필드, JavaScript 변수 등)에 포함됩니다.
      * 클라이언트(사용자의 브라우저)가 여러분의 서버로 요청을 보낼 때, 이 토큰도 함께 전송하도록 합니다.
      * 여러분의 서버는 요청된 토큰이 현재 사용자의 세션에 저장된 토큰과 일치하는지 확인합니다. 만약 일치하지 않는다면 크로스-사이트에서 위조된 요청으로 판단하고 차단합니다.
      * 공격자는 피해자 브라우저의 동일 출처 정책(Same-Origin Policy) 때문에 타겟 웹사이트의 HTML을 읽어서 이 토큰 값을 직접 추출할 수 없으므로, 위조된 요청에 유효한 토큰을 포함할 수 없습니다.

  * **CSRF 토큰 저장 및 전송 방법:**

      * **숨겨진 폼 필드:** 가장 흔한 방법으로, HTML 폼 내부에 `<input type="hidden" name="csrf_token" value="RANDOM_TOKEN">`과 같이 숨겨진 필드로 토큰을 포함시킵니다.
      * **커스텀 HTTP 헤더:** AJAX 요청의 경우 `X-CSRF-Token`과 같은 커스텀 헤더에 토큰을 포함시켜 보냅니다. 클라이언트 측 JavaScript에서 쿠키에 저장된 토큰을 읽어 헤더에 추가하는 방식도 있습니다(Double Submit Cookie Pattern).

#### 4\. Same-Origin Policy (동일 출처 정책, SOP)

  * **동일 출처 정책(Same-Origin Policy, SOP)**은 웹 브라우저가 JavaScript로 다른 도메인의 웹 페이지에 접근하는 것을 막아 놓은 핵심적인 보안 제약 조건입니다.
  * 이 정책은 **프로토콜, 호스트, 포트가 모두 동일한 출처(origin)에서만 요청된 리소스에 대한 스크립트 접근이 가능하도록 제한**합니다. 이러한 제한은 XSS 공격뿐만 아니라 CSRF 공격도 부분적으로 완화하는 데 도움을 줍니다. 예를 들어, 공격자가 악성 스크립트를 통해 위조된 요청을 보낼 때, SOP 때문에 타겟 웹사이트의 응답을 읽거나, CSRF 토큰을 직접 추출하는 것이 불가능해집니다.
  * **한계:** 현대 웹 개발 환경에서는 외부 API를 사용하는 경우가 많고, 클라이언트(프론트엔드)와 서버(백엔드)를 분리하여 개발하는 경우도 많습니다. 이러한 환경에서 SOP는 많은 불편함을 가져다주어, 이를 해소하기 위해 **CORS(Cross-Origin Resource Sharing) 정책**을 이용하기도 합니다.

#### 5\. Cross-Origin Resource Sharing (CORS)

**Cross-Origin Resource Sharing (CORS)**는 **SOP의 불편함을 해소하기 위해 도입된 표준 메커니즘**입니다. CORS는 추가 HTTP 헤더를 통해 다른 출처의 자원(resource)을 현재 실행 중인 웹 애플리케이션에 허용시켜주는 메커니즘입니다.

  * **중요: CORS는 CSRF를 막는 것과는 직접적인 관련이 없습니다.** CORS는 보안 메커니즘이라기보다는 **동일 출처 정책으로 인해 발생하는 합법적인 크로스-사이트 요청을 가능하게 하는 메커니즘**입니다. 이는 "외부 요청을 허용하되, 그 요청이 안전한지 먼저 확인"하는 방식입니다.
  * 현대 웹 개발에서는 외부 API 사용 및 클라이언트/서버 분리 개발 환경이 많아 SOP가 많은 불편함을 가져다주므로, 여러분의 애플리케이션은 CORS를 통해 다른 도메인으로부터의 합법적인 요청을 허용하는 경우가 많습니다.

#### CORS 작동 방식

CORS는 서버가 추가 HTTP 헤더를 통해 자원 공유에 대한 정의를 브라우저에게 보냅니다. 이 때, **Preflight Request** 또는 **Simple Request**가 존재합니다.

  * **Preflight가 없는 Simple Request인 경우:**

      * 클라이언트(브라우저)가 여러분의 서버에 `Origin` 헤더를 포함하여 요청을 보냅니다.
      * 여러분의 서버는 이 `Origin` 헤더를 통해 요청이 `Access-Control-Allow-Origin` 응답 헤더에 해당하는 출처(origin)인지 확인합니다.
      * 만약 해당하는 출처라면 접근을 허용하고, 그렇지 않으면 거부합니다. 브라우저는 서버의 CORS 정책에 따라 응답을 차단하거나 허용합니다.
      * Simple Request는 `GET`, `HEAD`, `POST` 메서드 중 하나를 사용하고, 특정 HTTP 헤더만을 허용하며, `Content-Type`이 특정 값(예: `application/x-www-form-urlencoded`, `multipart/form-data`, `text/plain`) 중 하나인 경우에만 발생합니다.

  * **Preflight Request인 경우:**

      * Simple Request와 달리, 브라우저는 먼저 `OPTIONS` 메서드를 통해 다른 도메인의 리소스에 HTTP 요청을 보내 **실제 요청(actual request)이 전송하기에 안전한지 확인**합니다.
      * **크로스-사이트 요청이 사용자 데이터에 영향을 줄 수 있는 경우(예: `PUT`, `DELETE` 메서드 사용, 커스텀 헤더 포함, `Content-Type`이 특정 값 외의 다른 값인 경우)에는 `Preflight Request`를 수행합니다.**
      * `Preflight Request` 시에는 `Access-Control-Request-Method`와 `Access-Control-Request-Headers` 헤더를 포함하여 보냅니다.
      * 여러분의 서버는 이에 대해 `Access-Control-Allow-Origin`, `Access-Control-Allow-Methods`, `Access-Control-Allow-Headers`, `Access-Control-Max-Age` 등 `Access-Control-*` 계열의 응답 헤더를 선언하여 응답을 보냅니다.
      * 이를 통해 해당 Origin이 허용되었다는 것을 `Preflight Request`를 통해 파악되면, 그제서야 브라우저는 본 요청을 보내고, 이는 Simple Request의 응답과 동일하게 처리됩니다.

### CSRF 토큰 전략: 단일 토큰 vs. 요청별 토큰

  * **만약 CSRF 토큰 1개로 여러 가지 요청을 사용(세션 기반 토큰)할 수 있는 방식과 각 요청마다 1개의 CSRF 토큰이 필요한 방식(요청별 토큰)이 있다면 무엇이 더 안전한가?**

      * **후자(각 요청마다 1개의 CSRF 토큰이 필요한 방식)가 일반적으로 더 안전합니다.**
      * **요청별 토큰(Per-request token) 방식:** 각 요청마다 새로운 CSRF 토큰을 생성하고 검증하기 때문에, 공격자가 특정 토큰을 탈취하더라도 그 토큰은 단 한 번의 요청에만 유효합니다. 이는 토큰 재사용 공격을 방지하고, 공격 성공의 기회를 최소화합니다. 그러나 여러분의 서버 자원 소모가 크고 구현 복잡도가 높을 수 있습니다.
      * **세션 기반 토큰(Session-based token) 방식:** 세션 기간 동안 동일한 CSRF 토큰을 재사용합니다. 구현이 더 간단하다는 장점이 있지만, 만약 공격자가 이 하나의 토큰을 탈취한다면, 해당 세션이 유효한 동안 여러 위조 요청을 보낼 수 있다는 위험이 있습니다.

    보안과 사용자 경험 사이의 균형을 고려하여, 일반적으로는 세션 기반 토큰을 사용하되, **비밀번호 변경, 계좌 이체와 같은 중요한 작업에 대해서는 별도의 1회용 토큰이나 추가적인 인증(예: 비밀번호 재확인)을 요구하는 방식**을 채택하는 것이 좋습니다.

## References

  * [COMPUTER SECURITY: A Hands-on Approach by Wenliang Du](https://www.amazon.com/Computer-Security-Hands-Approach-Wenliang/dp/154836794X)