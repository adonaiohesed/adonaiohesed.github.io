---
title: Dissecting HTTP Headers
tags: HTTP-Headers
key: page-dissecting_http_headers
categories: [Cybersecurity, Web Security]
author: hyoeun
math: true
mathjax_autoNumber: true
---

## Web Penetration Testing: Dissecting HTTP Headers

When performing web penetration testing, HTTP headers are the backbone of communication between the client and server. They provide crucial clues for understanding an application's security posture, misconfigurations, and potential vulnerabilities. Properly configured headers can be a strong defense, but misconfigured or missing ones expose significant attack surfaces.

In this blog post, we will delve deeply into the **key HTTP headers to pay close attention to** during web penetration testing, including their **security implications, vulnerability scenarios, and what a pentester should look for.**

---

### **I. Response Headers for Security Enhancement and Defense Mechanisms**

These headers are included in the responses sent by the server to the client. They enforce specific security policies on the browser, helping to mitigate various client-side attacks.

1.  **`Strict-Transport-Security` (HSTS)**
    * **Purpose:** Forces the browser to exclusively use HTTPS for a website. Even if a user attempts to connect via HTTP, the browser automatically converts it to HTTPS. It also blocks HTTP connection attempts from users who have previously accessed the site via HTTPS.
    * **Security Relevance:** Prevents SSL Stripping attacks (downgrading HTTPS to HTTP) via Man-in-the-Middle (MITM) attacks, thereby preventing traffic interception.
    * **What Pentesters Should Look For:**
        * **Absence of Header:** If the HSTS header is missing, the site is vulnerable to SSL Stripping.
        * **`max-age` Value:** Ensure it's set to a sufficiently long duration (e.g., one year or more). Too short a period reduces its effectiveness.
        * **`includeSubDomains`:** Verify that HSTS applies to subdomains as well.
        * **`preload`:** Check if it's eligible to be included in the HSTS Preload List, which hardcodes the policy into browsers.

2.  **`Content-Security-Policy` (CSP)**
    * **Purpose:** Mitigates XSS (Cross-Site Scripting) and data injection attacks by defining and restricting, via a whitelist approach, the origins from which the browser is allowed to load and execute various resources (scripts, stylesheets, images, etc.) on a given web page.
    * **Security Relevance:** Significantly reduces the success rate of XSS attacks by blocking inline script execution and loading of malicious scripts from external domains.
    * **What Pentesters Should Look For (Bypass Techniques):**
        * **Absence of Header:** If CSP is missing, the site is highly vulnerable to XSS.
        * **Use of `'unsafe-inline'` / `'unsafe-eval'`:** If these directives are present, inline JavaScript or `eval()`-based code execution is allowed, neutralizing CSP's primary defense.
        * **Overly Permissive Origins:** If `*` (wildcard), `http://` is allowed, or too many domains are included in `script-src`, the policy can be bypassed through vulnerabilities within those allowed domains (e.g., JSONP endpoints).
        * **Missing/Misused `base-uri`:** Check if an attacker can inject `<base href="...">` to change the base URL for relative script paths.
        * **Unset `object-src` / `plugin-types`:** May allow code execution via plugins.
        * **`report-uri` / `report-to` Analysis:** Verify that the CSP violation reporting feature itself isn't vulnerable to information leakage or other exploits.

3.  **`X-Content-Type-Options`**
    * **Purpose:** Prevents MIME type sniffing by the browser. It stops the browser from ignoring the server's `Content-Type` header and attempting to deduce the MIME type based on content.
    * **Security Relevance:** When set to `nosniff`, it prevents scenarios where an uploaded malicious file (e.g., a script disguised as a `.jpg` image) might be misinterpreted and executed by the browser as JavaScript, even if the server sent it with an `image/jpeg` `Content-Type`.
    * **What Pentesters Should Look For:**
        * **Absence of Header:** If `X-Content-Type-Options: nosniff` is missing, the site is vulnerable to MIME sniffing attacks, particularly if it allows file uploads.

4.  **`X-Frame-Options`**
    * **Purpose:** Prevents a web page from being framed within `<iframe>`, `<frame>`, or `<object>` tags, thereby preventing clickjacking attacks.
    * **Security Relevance:** Blocks attacks where users are tricked into clicking invisible UI elements to perform sensitive actions.
    * **What Pentesters Should Look For:**
        * **Absence of Header:** If `X-Frame-Options` is missing, the site is vulnerable to clickjacking.
        * **Value Check:** Ensure it's set to `DENY` (no framing allowed from any domain) or `SAMEORIGIN` (framing allowed only from the same domain). `ALLOW-FROM uri` can be a security risk and should be avoided.

5.  **`Referrer-Policy`**
    * **Purpose:** Controls how the `Referer` header is sent (what content it includes, under what conditions) to the next request.
    * **Security Relevance:** Prevents sensitive information (e.g., session IDs, tokens, PII) that might be in the URL from leaking to other websites. It can also affect CSRF defense strategies relying on the `Referer` header.
    * **What Pentesters Should Look For:**
        * **Use of Strict Policies:** Ensure policies like `no-referrer`, `same-origin`, or `strict-origin-when-cross-origin` are used, rather than permissive ones like `unsafe-url` that expose sensitive data.
        * **CSRF Defense Interaction:** If the server uses the `Referer` header for CSRF defense, check if `Referrer-Policy` can be manipulated to block the `Referer`, potentially exposing a weakness in the server's `Referer` validation logic.

6.  **`Set-Cookie` Attributes (HttpOnly, Secure, SameSite)**
    * **Purpose:** Define security-related behavior for cookies when set by the server.
    * **Security Relevance:**
        * **`HttpOnly`:** Prevents XSS attackers from stealing session cookies via JavaScript (`document.cookie`).
        * **`Secure`:** Forces the cookie to be sent only over HTTPS (encrypted connections), protecting it from exposure via MITM attacks.
        * **`SameSite`:** Mitigates CSRF attacks by controlling how cookies are automatically included in cross-site requests (`Strict`, `Lax`, `None` values).
    * **What Pentesters Should Look For:**
        * **Presence of `HttpOnly` and `Secure`:** Verify that all sensitive cookies (especially session and authentication token cookies) have these flags set.
        * **Appropriate `SameSite` Setting:** Ensure `Strict` or `Lax` is used correctly. (`None` requires `Secure` and offers no direct CSRF defense).
        * **Missing Attributes:** The absence of any of these security attributes makes the cookie vulnerable to attacks (XSS, MITM, CSRF).

### **II. Response Headers for Information Disclosure and Server/Technology Stack Identification**

These headers, included in server responses, expose information about the server or the technologies used. Attackers can leverage this information to identify specific version vulnerabilities or narrow down their attack surface.

1.  **`Server`**
    * **Purpose:** Identifies the web server software and its version (e.g., `Apache/2.4.6`, `Nginx/1.18.0`).
    * **Security Relevance:** If the version is exposed, attackers can search for known vulnerabilities (CVEs) specific to that version to launch targeted attacks.
    * **What Pentesters Should Look For:** Check if detailed server version information is exposed. Recommend changing to a generic name or removing it if possible.

2.  **`X-Powered-By`**
    * **Purpose:** Indicates the technology (e.g., `ASP.NET`, `PHP/7.4.3`, `Express`) powering the web application.
    * **Security Relevance:** Similar to the `Server` header, exposing the version of the web framework or language allows attackers to find known vulnerabilities for that specific version.
    * **What Pentesters Should Look For:** Check for exposed technology stack information. Recommend removing or changing it to a generic value.

3.  **`Via`**
    * **Purpose:** Indicates that the request has passed through proxy servers and includes information about those proxies.
    * **Security Relevance:** Can provide hints about internal network configurations or reveal information through misconfigured proxies.
    * **What Pentesters Should Look For:** Check if detailed information about internal proxy servers is exposed.

4.  **`X-AspNet-Version`, `X-AspNetMvc-Version`, `X-Drupal-Cache`, etc. (Specific Technology Stack Headers)**
    * **Purpose:** Explicitly indicates the version of a specific framework or CMS.
    * **Security Relevance:** Exposing precise version information makes it easier for attackers to find exploit tools or exploits for that specific version.
    * **What Pentesters Should Look For:** Verify that these version-identifying headers have been removed.

### **III. Request Headers with High Exploitation Potential**

These headers are included by the client when sending requests to the server. Attackers can manipulate them to launch various types of attacks.

1.  **`Cookie`**
    * **Purpose:** Transmits client-side stored cookies (session IDs, user settings, etc.) to the server.
    * **Security Relevance:** Used in authentication and authorization bypass attacks like Session Hijacking and IDOR (Insecure Direct Object Reference).
    * **What Pentesters Should Look For:**
        * **Cookie Manipulation:** Test if manipulating `Cookie` header values can impersonate other user sessions or gain administrative privileges.
        * **Sensitive Information Disclosure:** Check if cookies contain sensitive information (like username or privilege levels) in plaintext besides just the session ID.
        * **Exploitation if `HttpOnly`, `Secure`, `SameSite` are missing:** Use these cookies in XSS, MITM, or CSRF attacks if proper attributes are missing.

2.  **`Authorization`**
    * **Purpose:** Provides client authentication information to the server (e.g., `Bearer Token` for JWTs or OAuth Access Tokens, `Basic Auth`).
    * **Security Relevance:** Used in authentication bypass, token theft, token replay attacks, and privilege escalation.
    * **What Pentesters Should Look For:**
        * **Token Validity:** Test if the server accepts expired or tampered tokens.
        * **Token Replay:** Check if a stolen token can be reused for subsequent requests (Replay Attack).
        * **Authorization Flaws:** Verify if the token grants excessive permissions or allows access to resources belonging to other users/roles (Broken Access Control).
        * **Token Scope:** Check if the token's scope is too broad for the requested operation.

3.  **`Referer` (Note: standard header name is `Referer`, not `Referrer`)**
    * **Purpose:** Informs the server of the URL of the previous web page that linked to the current request.
    * **Security Relevance:**
        * **Information Leakage:** If the `Referer` header is sent from a URL containing sensitive information (e.g., PII, session IDs), that information can be exposed in logs or analytics tools of the visited external website.
        * **CSRF Defense Bypass:** If the server uses the `Referer` header for CSRF defense, an attacker might bypass it by manipulating the header (e.g., using `no-referrer` policies, protocol downgrades).
    * **What Pentesters Should Look For:** Check for sensitive information leakage in the `Referer` header or if CSRF defense can be bypassed by manipulating it.

4.  **`X-Forwarded-For` / `X-Real-IP`**
    * **Purpose:** Non-standard headers used to identify the client's original IP address when a request passes through proxy servers or load balancers.
    * **Security Relevance:** Can be exploited to spoof IP addresses, bypassing IP-based access controls (ACLs) or rate limits.
    * **What Pentesters Should Look For:**
        * **IP Spoofing:** Test if manipulating these headers allows impersonation of different IP addresses to bypass IP-based security controls (e.g., allowing access only from specific IPs).
        * **Multiple Headers:** Check how the server handles multiple `X-Forwarded-For` headers or manipulated values.

5.  **`Host`**
    * **Purpose:** Identifies the intended destination domain when a single IP address hosts multiple websites (virtual hosts).
    * **Security Relevance:** Used in various Host header injection attacks, such as web cache poisoning, exploiting password reset functionalities, and bypassing specific web application features.
    * **What Pentesters Should Look For:** Test if manipulating the `Host` header leads to unexpected server behavior or returns content from a different virtual host. Specifically, if password reset links are dynamically generated using the `Host` header value, test if manipulating it can redirect reset links to an attacker-controlled domain.

6.  **`Origin`**
    * **Purpose:** In cross-origin requests, this header informs the server of the origin (scheme, host, port) from which the request was initiated. It's primarily used for CORS (Cross-Origin Resource Sharing) security policies.
    * **Security Relevance:** If the server improperly validates the `Origin` header (e.g., `Access-Control-Allow-Origin: *` or incorrect regex use) or allows `null` Origins, it can lead to CORS bypass. This allows malicious scripts from other origins to make unauthorized requests or read responses.
    * **What Pentesters Should Look For:** Test how the server responds with the `Access-Control-Allow-Origin` header when the `Origin` header is manipulated (e.g., sending `null` or unauthorized domains).

---

### **Conclusion**

HTTP headers, though often overlooked in web communication, contain hidden information and policies that profoundly impact web security. Pentesters should not view these headers merely as communication data but as **evidence of security configurations, conduits for information disclosure, and vectors for manipulation by attackers.** By identifying missing headers, misconfigurations, or exploitable manipulation possibilities, security professionals can strengthen the overall security posture of web applications.

---

## 웹 펜테스팅: HTTP 헤더 분석

HTTP 헤더는 웹 통신에서 클라이언트와 서버가 서로에게 보내는 메타데이터입니다. 이들은 단순히 정보 교환을 넘어, 웹 애플리케이션의 보안을 강화하거나 약화시키는 중요한 역할을 합니다. 펜테스터는 이러한 헤더를 분석하여 애플리케이션의 보안 구성을 평가하고, 잘못된 설정으로 인한 취약점을 찾아내야 합니다.

### **I. 보안 강화 및 방어 메커니즘 관련 응답 헤더 (Response Headers)**

이 헤더들은 서버가 클라이언트에게 보내는 응답에 포함되며, 브라우저에게 특정 보안 정책을 강제하여 다양한 클라이언트 측 공격을 완화하는 역할을 합니다.

1.  **`Strict-Transport-Security` (HSTS)**
    * **목적:** 웹사이트가 HTTPS만을 사용하도록 브라우저에게 강제합니다. 사용자가 HTTP로 접속하려 해도 브라우저가 자동으로 HTTPS로 변환하여 접속하며, 이전에 HTTPS로 접속했던 기록이 있는 사용자의 HTTP 접속 시도를 차단합니다.
    * **보안 관련성:** 중간자 공격(MITM)을 통한 SSL Stripping(HTTPS -> HTTP 다운그레이드) 공격을 방지하여 트래픽 가로채기를 막습니다.
    * **펜테스팅 시 확인 사항:**
        * **헤더 존재 여부:** HSTS 헤더가 없는 경우, SSL Stripping 공격에 취약합니다.
        * **`max-age` 값:** 충분히 긴 기간(예: 1년 이상)으로 설정되어 있는지 확인합니다. 너무 짧으면 효과가 미미합니다.
        * **`includeSubDomains`:** 서브도메인에도 HSTS가 적용되는지 확인합니다.
        * **`preload`:** HSTS Preload List에 등록되어 브라우저에 하드코딩될 수 있는지 확인합니다.

2.  **`Content-Security-Policy` (CSP)**
    * **목적:** XSS(Cross-Site Scripting) 및 데이터 주입 공격을 완화하기 위해 브라우저가 특정 웹 페이지에서 로드하고 실행할 수 있는 리소스(스크립트, 스타일시트, 이미지 등)의 출처를 화이트리스트 방식으로 정의하고 제한합니다.
    * **보안 관련성:** 인라인 스크립트 실행, 외부 악성 도메인에서 스크립트 로드 등을 차단하여 XSS 공격의 성공 가능성을 크게 낮춥니다.
    * **펜테스팅 시 확인 사항 (우회 기법):**
        * **헤더 존재 여부:** CSP가 없는 경우, XSS 공격에 매우 취약합니다.
        * **`'unsafe-inline'` / `'unsafe-eval'` 사용:** 이 지시문들이 포함되어 있다면, 인라인 스크립트나 `eval()`을 통한 코드 실행이 가능해져 CSP의 주요 방어 기능이 무력화됩니다.
        * **광범위한 출처 허용:** `*` (와일드카드)나 `http://` 허용, 또는 너무 많은 도메인을 `script-src`에 포함하는 경우, 해당 도메인 내의 취약점(예: JSONP 엔드포인트)을 통해 우회될 수 있습니다.
        * **`base-uri` 누락/오용:** 공격자가 `<base href="...">`를 주입하여 상대 경로 스크립트의 로드 출처를 변경할 수 있는지 확인합니다.
        * **`object-src` / `plugin-types` 미설정:** 플러그인을 통한 코드 실행을 막지 못할 수 있습니다.
        * **`report-uri` / `report-to` 분석:** CSP 위반 보고 기능이 자체적으로 취약하지 않은지, 또는 정보 유출을 유발하지 않는지 확인합니다.

3.  **`X-Content-Type-Options`**
    * **목적:** 브라우저의 MIME 타입 스니핑(MIME Type Sniffing)을 방지합니다. 브라우저가 서버가 보낸 `Content-Type` 헤더를 무시하고 콘텐츠 내용을 기반으로 MIME 타입을 추론하여 실행하는 것을 막습니다.
    * **보안 관련성:** `nosniff` 값으로 설정되면, 업로드된 악성 파일(예: `.jpg` 확장자를 가진 스크립트)이 서버가 `image/jpeg`로 보내더라도 브라우저가 이를 `text/javascript`로 잘못 추론하여 실행하는 것을 방지합니다.
    * **펜테스팅 시 확인 사항:**
        * **헤더 존재 여부:** `X-Content-Type-Options: nosniff`가 없는 경우, MIME 스니핑 공격에 취약합니다. 특히 파일 업로드 기능이 있는 경우 중요합니다.

4.  **`X-Frame-Options`**
    * **목적:** 웹 페이지가 `<iframe>`, `<frame>`, `<object>` 태그 내에서 프레이밍(framing)되는 것을 방지하여 클릭재킹(Clickjacking) 공격을 막습니다.
    * **보안 관련성:** 사용자가 보이지 않는 UI를 클릭하도록 유도하여 민감한 작업을 수행하게 하는 공격을 차단합니다.
    * **펜테스팅 시 확인 사항:**
        * **헤더 존재 여부:** `X-Frame-Options`가 없는 경우, 클릭재킹에 취약합니다.
        * **값 확인:** `DENY` (어떤 도메인에서도 프레이밍 불가) 또는 `SAMEORIGIN` (동일 도메인에서만 허용)으로 설정되어 있는지 확인합니다. `ALLOW-FROM uri`는 보안상 취약할 수 있으므로 피해야 합니다.

5.  **`Referrer-Policy`**
    * **목적:** `Referer`(오타 아님, HTTP 표준 헤더 이름) 헤더가 다음 요청으로 어떻게 전송될지(포함될 내용, 전송 조건)를 제어합니다.
    * **보안 관련성:** URL에 포함될 수 있는 민감한 정보(예: 세션 ID, 토큰, PII)가 다른 웹사이트로 유출되는 것을 방지합니다. CSRF 방어 시 `Referer` 헤더 검증에 영향을 미칠 수 있습니다.
    * **펜테스팅 시 확인 사항:**
        * **`no-referrer` / `same-origin` / `strict-origin-when-cross-origin` 등 엄격한 정책 사용 여부:** `unsafe-url`처럼 민감 정보를 모두 노출하는 정책이 아닌지 확인합니다.
        * **CSRF 방어와의 연관성:** 서버가 `Referer` 헤더를 CSRF 방어에 사용한다면, `Referrer-Policy`가 `Referer`를 차단하여 합법적인 요청을 막을 수 있습니다. 이는 서버의 `Referer` 검증 로직이 견고하지 못함을 의미할 수도 있습니다.

6.  **`Set-Cookie` 속성 (HttpOnly, Secure, SameSite)**
    * **목적:** 서버가 클라이언트에 쿠키를 설정할 때, 쿠키의 보안 관련 동작을 정의합니다.
    * **보안 관련성:**
        * **`HttpOnly`:** XSS 공격자가 `document.cookie`를 통해 세션 쿠키를 탈취하는 것을 방지합니다.
        * **`Secure`:** 쿠키가 HTTPS(암호화된 연결)를 통해서만 전송되도록 강제하여 MITM(중간자 공격)으로부터 쿠키 노출을 방지합니다.
        * **`SameSite`:** CSRF 공격을 완화하기 위해 크로스 사이트 요청 시 쿠키가 자동으로 포함되는 방식을 제어합니다 (`Strict`, `Lax`, `None` 값).
    * **펜테스팅 시 확인 사항:**
        * **모든 민감한 쿠키에 `HttpOnly`, `Secure` 플래그가 설정되어 있는지 확인.** 특히 세션 쿠키, 인증 토큰 쿠키.
        * **`SameSite` 플래그의 적절한 설정:** `Strict` 또는 `Lax`가 적절히 사용되었는지 확인합니다. (`None`은 `Secure`와 함께 사용되어야 하며, CSRF 방어에는 직접적인 기여 없음).
        * **누락된 속성:** 이러한 보안 속성 중 하나라도 누락되면 해당 쿠키를 이용한 공격(XSS, MITM, CSRF)에 취약해집니다.

### **II. 정보 노출 및 서버/기술 스택 식별 관련 응답 헤더**

이 헤더들은 서버나 사용 중인 기술 스택에 대한 정보를 노출하여, 공격자가 특정 버전의 취약점을 찾거나 공격 대상을 좁히는 데 활용될 수 있습니다.

1.  **`Server`**
    * **목적:** 웹 서버 소프트웨어의 이름과 버전(예: `Apache/2.4.6`, `Nginx/1.18.0`)을 식별합니다.
    * **보안 관련성:** 버전이 노출되면 해당 버전에 알려진 취약점(CVE)을 검색하여 공격을 시도할 수 있습니다.
    * **펜테스팅 시 확인 사항:** 서버 버전 정보가 과도하게 상세하게 노출되는지 확인하고, 가능하다면 일반적인 이름으로 변경하거나 완전히 제거하도록 권장합니다.

2.  **`X-Powered-By`**
    * **목적:** 웹 애플리케이션이 어떤 기술(예: `ASP.NET`, `PHP/7.4.3`, `Express`)로 구동되는지 나타냅니다.
    * **보안 관련성:** `Server` 헤더와 유사하게, 사용 중인 웹 프레임워크나 언어의 버전이 노출되어 해당 버전에 알려진 취약점을 찾을 수 있습니다.
    * **펜테스팅 시 확인 사항:** 기술 스택 정보가 노출되는지 확인하고, 제거하거나 일반적인 값으로 변경하도록 권장합니다.

3.  **`Via`**
    * **목적:** 요청이 프록시 서버를 통해 전달되었음을 나타내고, 프록시 서버의 정보를 포함합니다.
    * **보안 관련성:** 내부 네트워크 구성에 대한 힌트를 제공하거나, 잘못 설정된 프록시를 통해 정보가 유출될 수 있습니다.
    * **펜테스팅 시 확인 사항:** 내부 프록시 서버의 상세 정보가 노출되는지 확인합니다.

4.  **`X-AspNet-Version`, `X-AspNetMvc-Version`, `X-Drupal-Cache` 등 특정 기술 스택 헤더**
    * **목적:** 특정 프레임워크나 CMS의 버전을 명시적으로 나타냅니다.
    * **보안 관련성:** 매우 구체적인 버전 정보를 노출하여, 해당 버전에 대한 공격 도구나 익스플로잇을 찾기 쉽게 만듭니다.
    * **펜테스팅 시 확인 사항:** 이러한 버전 식별 헤더가 제거되었는지 확인합니다.

### **III. 공격 활용 가능성 높은 요청 헤더 (Request Headers)**

이 헤더들은 클라이언트가 서버에 요청을 보낼 때 포함되며, 공격자가 이를 조작하여 다양한 공격을 시도할 수 있습니다.

1.  **`Cookie`**
    * **목적:** 클라이언트 측에 저장된 쿠키(세션 ID, 사용자 설정 등)를 서버로 전송합니다.
    * **보안 관련성:** 세션 하이재킹(Session Hijacking), IDor(Insecure Direct Object Reference) 등 인증 및 인가 우회 공격에 사용됩니다.
    * **펜테스팅 시 확인 사항:**
        * **쿠키 조작:** `Cookie` 헤더의 값을 조작하여 다른 사용자의 세션을 흉내 내거나, 관리자 권한을 획득할 수 있는지 테스트합니다.
        * **민감 정보 노출:** 쿠키에 세션 ID 외에 사용자 이름, 권한 등 민감한 정보가 평문으로 포함되어 있는지 확인합니다.
        * **`HttpOnly`, `Secure`, `SameSite` 속성 부재 시 공격 시도:** 이 속성들이 없는 쿠키를 XSS, MITM, CSRF 공격에 활용합니다.

2.  **`Authorization`**
    * **목적:** 클라이언트가 사용자 인증 정보를 서버에 제공합니다. (예: `Bearer Token` - JWT, OAuth Access Token, `Basic Auth`)
    * **보안 관련성:** 인증 우회, 토큰 탈취, 토큰 재사용(Replay Attack), 권한 상승 공격에 사용됩니다.
    * **펜테스팅 시 확인 사항:**
        * **토큰 유효성:** 토큰이 만료되었거나 변조된 경우에도 서버가 이를 수락하는지 테스트합니다.
        * **토큰 재사용:** 탈취한 토큰을 사용하여 다른 요청을 보낼 수 있는지 테스트합니다 (Replay Attack).
        * **권한 부여:** 토큰이 부여하는 권한이 과도한지, 또는 다른 사용자/역할의 자원에 접근할 수 있는지 확인합니다 (Broken Access Control).
        * **토큰 스코프:** 토큰의 스코프가 요청하는 작업에 비해 너무 넓은지 확인합니다.

3.  **`Referer` (오타 아님)**
    * **목적:** 현재 요청을 발생시킨 이전 웹 페이지의 URL을 서버에 알려줍니다.
    * **보안 관련성:**
        * **정보 유출:** `Referer` 헤더가 민감한 정보를 포함하는 URL(예: 개인 식별 정보, 세션 ID가 포함된 URL)에서 전송되면, 해당 정보가 방문한 외부 웹사이트의 로그나 분석 도구에 노출될 수 있습니다.
        * **CSRF 방어 우회:** 서버가 `Referer` 헤더를 CSRF 방어에 사용한다면, 공격자가 이를 조작(`no-referrer` 정책, 프로토콜 다운그레이드)하여 우회할 수 있습니다.
    * **펜테스팅 시 확인 사항:** `Referer` 헤더에 민감한 정보가 노출되는지, 또는 `Referer` 검증을 우회하여 CSRF 공격을 시도할 수 있는지 확인합니다.

4.  **`X-Forwarded-For` / `X-Real-IP`**
    * **목적:** 요청이 프록시 서버나 로드 밸런서를 통해 전달될 때, 클라이언트의 실제 IP 주소를 서버에 알려주는 비표준 헤더입니다.
    * **보안 관련성:** IP 기반의 접근 제어(ACL), 속도 제한(Rate Limiting), 지리적 제한 등을 우회하는 데 악용될 수 있습니다.
    * **펜테스팅 시 확인 사항:**
        * **IP 스푸핑:** 이 헤더를 조작하여 다른 IP 주소인 것처럼 위장하여 IP 기반의 보안 제어(예: 특정 IP만 접근 허용)를 우회할 수 있는지 테스트합니다.
        * **다중 헤더:** 여러 `X-Forwarded-For` 헤더를 보내거나 값을 조작했을 때 서버가 어떻게 처리하는지 확인합니다.

5.  **`Host`**
    * **목적:** 단일 IP 주소에서 여러 웹사이트(가상 호스트)를 호스팅할 때, 클라이언트가 어떤 웹사이트에 접속하려는지 서버에 알려줍니다.
    * **보안 관련성:** 웹 캐시 포이즈닝(Web Cache Poisoning), 비밀번호 재설정 기능 악용, 웹 애플리케이션의 특정 기능 우회 등 다양한 Host 헤더 인젝션 공격에 사용됩니다.
    * **펜테스팅 시 확인 사항:** `Host` 헤더를 조작하여 서버가 예상치 못한 동작을 하는지, 또는 다른 가상 호스트의 콘텐츠를 반환하는지 테스트합니다. 특히 비밀번호 재설정 링크의 도메인 부분이 `Host` 헤더 값으로 동적으로 생성되는 경우, 이를 조작하여 공격자 도메인으로 재설정 링크를 보낼 수 있는지 확인합니다.

6.  **`Origin`**
    * **목적:** 크로스 오리진 요청 시 요청을 시작한 출처(스키마, 호스트, 포트)를 서버에 알려주는 헤더입니다. 주로 CORS(Cross-Origin Resource Sharing)와 관련된 보안 정책을 위해 사용됩니다.
    * **보안 관련성:** 서버가 `Origin` 헤더를 잘못 검증하거나(`Access-Control-Allow-Origin: *` 또는 잘못된 정규 표현식 사용) `null` Origin을 허용할 경우, CORS 우회로 이어져 다른 출처의 악성 스크립트가 인가되지 않은 요청을 보내거나 응답을 읽을 수 있게 됩니다.
    * **펜테스팅 시 확인 사항:** `Origin` 헤더를 조작하여 `null`이나 허용되지 않는 도메인을 보냈을 때 서버가 `Access-Control-Allow-Origin` 헤더를 어떻게 응답하는지 확인합니다.

---

### **결론**

HTTP 헤더는 웹 애플리케이션과 브라우저 간의 통신에서 눈에 잘 띄지 않지만, 그 안에 숨겨진 정보와 정책들은 웹 보안에 지대한 영향을 미칩니다. 펜테스터는 이 헤더들을 단순히 통신 정보로만 볼 것이 아니라, **보안 구성의 증거, 정보 노출의 통로, 그리고 공격자가 조작할 수 있는 벡터**로서 심층적으로 분석해야 합니다. 헤더의 부재, 잘못된 설정, 또는 조작 가능성을 통해 잠재적인 취약점을 식별하고, 이를 바탕으로 웹 애플리케이션의 보안 강도를 높일 수 있습니다.