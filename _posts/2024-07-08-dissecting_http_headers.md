---
title: Dissecting HTTP Headers
key: page-dissecting_http_headers
categories:
- Security
- Web Security
author: hyoeun
math: true
mathjax_autoNumber: true
image: "/assets/thumbnails/2024-07-08-dissecting_http_headers.png"
bilingual: true
date: 2024-07-08 14:45:36
---
## Analyzing HTTP Headers in Web Penetration Testing

When performing web penetration testing, HTTP headers are the backbone of communication between the client and server. For a security professional, these headers are not just metadata; they are crucial clues for understanding an application's architecture, security posture, and hidden misconfigurations. Properly configured headers act as a primary line of defense, while missing or weak ones often expose significant attack surfaces.

In this post, we will walk through the **key HTTP headers you must analyze** during a pentest. I'll explain them from the perspectives of an engineer (how to build), an attacker (how to exploit), and a defender (how to fix).

## Response Headers: Hardening the Client-Side Defense

These headers are sent by the server to instruct the browser on how to enforce security policies. As a mentor, I always emphasize that these are your "silent guardians."

### 1. Strict-Transport-Security (HSTS)
*   **Engineering Perspective:** Forces the browser to use HTTPS exclusively. It's like telling the browser, "Don't even think about using plain HTTP with me for the next year."
*   **Offensive Perspective:** If this header is missing, we can attempt **SSL Stripping** attacks to downgrade a victim's connection to HTTP and intercept sensitive traffic.
*   **Pentesting Focus:**
    *   Check for the `max-age` value (should be at least 1 year / 31536000 seconds).
    *   Look for `includeSubDomains` and `preload` flags for maximum coverage.

### 2. Content-Security-Policy (CSP)
*   **Engineering Perspective:** A powerful whitelist that tells the browser exactly which scripts, styles, and images are allowed to run. It's the ultimate defense against XSS.
*   **Offensive Perspective:** We look for weak directives like `'unsafe-inline'`, `'unsafe-eval'`, or overly broad wildcards (`*`). These are "holes" in the shield that we can exploit to inject malicious scripts.
*   **Pentesting Focus:**
    *   Verify the absence of the header (high risk).
    *   Analyze for bypasses: Are there any JSONP endpoints allowed? Is `base-uri` missing?

### 3. X-Content-Type-Options
*   **Engineering Perspective:** Setting this to `nosniff` prevents the browser from "guessing" the file type. This ensures that a `.jpg` uploaded by a user isn't accidentally executed as a `.js` file.
*   **Offensive Perspective:** If `nosniff` is missing, we can try to upload a malicious script with an image extension and trick the browser into executing it via MIME sniffing.
*   **Pentesting Focus:** Ensure `X-Content-Type-Options: nosniff` is present on all responses, especially those handling file uploads.

### 4. X-Frame-Options
*   **Engineering Perspective:** Prevents your site from being embedded in an `<iframe>`. This is the primary defense against **Clickjacking**.
*   **Offensive Perspective:** If missing, we can overlay your site with a transparent UI on our own malicious page, tricking users into clicking buttons they can't see.
*   **Pentesting Focus:** Look for `DENY` or `SAMEORIGIN`. Avoid `ALLOW-FROM` as it is largely deprecated and insecure.

### 5. Referrer-Policy
*   **Engineering Perspective:** Controls how much information is shared in the `Referer` header when navigating away. It prevents leaking internal URLs or sensitive tokens.
*   **Offensive Perspective:** We check if the policy is too lax (e.g., `unsafe-url`), which might reveal session tokens or private user data contained in the URL parameters.
*   **Pentesting Focus:** Aim for strict policies like `strict-origin-when-cross-origin`.

### 6. Set-Cookie Attributes (HttpOnly, Secure, SameSite)
*   **Engineering Perspective:** These flags define the security boundaries of your session data.
    *   `HttpOnly`: JavaScript cannot read the cookie (stops XSS-based theft).
    *   `Secure`: Only sent over HTTPS.
    *   `SameSite`: Prevents CSRF by controlling cross-site transmission.
*   **Offensive Perspective:** Any missing flag is an opportunity. No `HttpOnly`? We steal the session via XSS. No `SameSite`? We launch a CSRF attack.
*   **Pentesting Focus:** Audit all sensitive cookies. The absence of these attributes is a critical finding.

## Fingerprinting Headers: Avoiding Information Disclosure

These headers reveal details about the server or technology stack. As an engineer, you should minimize this footprint to make the attacker's job harder.

### 1. Server & X-Powered-By
*   **Offensive Perspective:** These tell us exactly what version of Nginx, PHP, or ASP.NET you are running. We can then look up specific **CVEs** for those versions to find a "shortcut" for exploitation.
*   **Defensive Perspective:** Remove these headers or set them to generic values. Don't give away your blueprints for free.

### 2. Via & X-AspNet-Version
*   **Offensive Perspective:** These reveal internal proxy configurations or specific framework versions. Every detail helps us narrow down the attack vector.
*   **Pentesting Focus:** Flag any header that discloses internal IP addresses, specific versions, or infrastructure details.

## Request Headers: The Attacker's Playground

These headers are sent by the client. Since attackers have full control over the client, these are primary vectors for manipulation.

### 1. Host
*   **Security Relevance:** Manipulation can lead to **Host Header Injection**, Web Cache Poisoning, or misdirecting password reset links.
*   **Pentesting Focus:** Try changing the `Host` header to an attacker-controlled domain and see if the application uses it to generate absolute URLs (e.g., in emails).

### 2. X-Forwarded-For / X-Real-IP
*   **Security Relevance:** Often used for IP-based access control. If the server trusts these headers blindly, we can **Spoof our IP** to bypass rate limits or ACLs.
*   **Pentesting Focus:** Test if adding these headers allows you to bypass restrictions or impersonate internal IP ranges.

### 3. Authorization & Cookie
*   **Security Relevance:** The core of session management.
*   **Pentesting Focus:** 
    *   **Authorization:** Test for token replay, lack of expiration, and Broken Access Control (Bole/BOPA).
    *   **Cookie:** Check for IDOR by changing user-identifying values and see if you can access other users' data.

### 4. Origin
*   **Security Relevance:** Crucial for **CORS** security. 
*   **Pentesting Focus:** Send an arbitrary `Origin` and check if the server responds with `Access-Control-Allow-Origin: *` or echoes back the malicious origin.

---

## 웹 펜테스팅: HTTP 헤더 심층 분석

웹 펜테스팅을 수행할 때, HTTP 헤더는 클라이언트와 서버 간 통신의 중추 역할을 합니다. 보안 전문가에게 이 헤더들은 단순한 메타데이터가 아닙니다. 애플리케이션의 아키텍처, 보안 상태, 그리고 숨겨진 설정 오류를 파악할 수 있는 결정적인 단서입니다. 잘 설정된 헤더는 강력한 1차 방어선이 되지만, 누락되거나 잘못 설정된 헤더는 공격자에게 넓은 공격 표면을 제공합니다.

이번 포스팅에서는 웹 펜테스팅 과정에서 **반드시 분석해야 할 핵심 HTTP 헤더**들을 살펴보겠습니다. 엔지니어링(구축), 공격(취약점), 그리고 방어(수정)의 관점에서 각각의 의미를 짚어보겠습니다.

## 응답 헤더 (Response Headers): 클라이언트 측 방어 강화

서버가 브라우저에게 보안 정책을 어떻게 강제할지 지시하는 헤더들입니다. 제가 후배들에게 항상 강조하듯, 이들은 웹 앱의 "보이지 않는 수호자"입니다.

### 1. Strict-Transport-Security (HSTS)
*   **엔지니어링 관점:** 브라우저가 오직 HTTPS만 사용하도록 강제합니다. "향후 1년 동안 나랑 통신할 때는 HTTP는 꿈도 꾸지 마"라고 브라우저에게 명령하는 것과 같습니다.
*   **공격 관점:** 이 헤더가 없다면 **SSL Stripping** 공격을 통해 사용자의 연결을 HTTP로 다운그레이드하고 통신 내용을 가로챌 수 있습니다.
*   **펜테스팅 핵심:** 
    *   `max-age` 값이 충분히 긴지(최소 1년 / 31536000초) 확인하세요.
    *   보안 범위를 극대화하기 위해 `includeSubDomains`와 `preload` 플래그가 있는지 체크합니다.

### 2. Content-Security-Policy (CSP)
*   **엔지니어링 관점:** 브라우저가 실행할 수 있는 스크립트, 스타일, 이미지 등의 출처를 정의하는 강력한 화이트리스트입니다. XSS를 막는 궁극적인 방어책이죠.
*   **공격 관점:** `'unsafe-inline'`, `'unsafe-eval'` 또는 광범위한 와일드카드(`*`)와 같은 취약한 지시문을 찾습니다. 이는 방패에 뚫린 "구멍"과 같으며, 이를 통해 악성 스크립트를 주입할 수 있습니다.
*   **펜테스팅 핵심:** 
    *   헤더 자체가 누락되었는지 확인하세요(매우 위험).
    *   우회 가능성을 분석하세요. 허용된 도메인 중에 JSONP 엔드포인트가 있나요? `base-uri` 설정이 빠져 있지는 않나요?

### 3. X-Content-Type-Options
*   **엔지니어링 관점:** `nosniff` 설정을 통해 브라우저가 파일 형식을 "추측"하지 못하게 합니다. 사용자가 올린 `.jpg` 파일이 실수로 `.js` 파일처럼 실행되는 사고를 방지합니다.
*   **공격 관점:** 이 설정이 없다면 이미지 확장자로 위장한 악성 스크립트를 업로드한 뒤, MIME 스니핑을 통해 브라우저가 이를 실행하도록 유도할 수 있습니다.
*   **펜테스팅 핵심:** 모든 응답, 특히 파일 업로드를 처리하는 곳에 `X-Content-Type-Options: nosniff`가 있는지 확인하세요.

### 4. X-Frame-Options
*   **엔지니어링 관점:** 여러분의 사이트가 다른 사이트의 `<iframe>` 안에 삽입되는 것을 막습니다. **클릭재킹(Clickjacking)** 공격에 대한 핵심 방어책입니다.
*   **공격 관점:** 이 헤더가 없다면, 공격자 페이지 위에 여러분의 사이트를 투명하게 띄워 놓고 사용자가 보이지 않는 버튼을 클릭하게 유도할 수 있습니다.
*   **펜테스팅 핵심:** `DENY` 또는 `SAMEORIGIN` 설정을 확인하세요. `ALLOW-FROM`은 구형 브라우저 전용이며 보안상 취약하므로 피해야 합니다.

### 5. Referrer-Policy
*   **엔지니어링 관점:** 페이지 이동 시 `Referer` 헤더에 얼마나 많은 정보를 담을지 제어합니다. 내부 URL이나 민감한 토큰이 외부로 유출되는 것을 방지합니다.
*   **공격 관점:** 정책이 너무 느슨하다면(`unsafe-url` 등), URL 파라미터에 포함된 세션 토큰이나 사용자 개인 정보가 공격자 서버 로그에 남을 수 있습니다.
*   **펜테스팅 핵심:** `strict-origin-when-cross-origin`과 같은 엄격한 정책을 권장합니다.

### 6. Set-Cookie 속성 (HttpOnly, Secure, SameSite)
*   **엔지니어링 관점:** 쿠키 데이터의 보안 경계를 정의합니다.
    *   `HttpOnly`: JavaScript가 쿠키를 읽지 못하게 함 (XSS를 통한 탈취 방지).
    *   `Secure`: HTTPS에서만 전송됨.
    *   `SameSite`: 크로스 사이트 전송을 제어하여 CSRF 방지.
*   **공격 관점:** 하나라도 빠져 있다면 기회입니다. `HttpOnly`가 없다면 XSS로 세션을 훔치고, `SameSite`가 없다면 CSRF 공격을 시도합니다.
*   **펜테스팅 핵심:** 모든 민감한 쿠키를 전수 조사하세요. 이 속성들이 누락된 것은 그 자체로 중요한 보안 결함입니다.

## 정보 노출 헤더: 서버 식별(Fingerprinting) 방지

서버나 기술 스택의 상세 정보를 노출하는 헤더들입니다. 엔지니어라면 이러한 흔적을 최소화하여 공격자가 정보를 수집하기 어렵게 만들어야 합니다.

### 1. Server 및 X-Powered-By
*   **공격 관점:** Nginx, PHP, ASP.NET의 정확한 버전을 알려줍니다. 버전만 알면 해당 버전에 공지된 **CVE(취약점)**를 검색해 공격의 "지름길"을 찾을 수 있습니다.
*   **방어 관점:** 이 헤더들을 제거하거나 범용적인 값으로 변경하세요. 공격자에게 설계도를 공짜로 줄 필요는 없습니다.

### 2. Via 및 X-AspNet-Version
*   **공격 관점:** 내부 프록시 설정이나 특정 프레임워크 버전을 노출합니다. 아주 작은 정보라도 공격 벡터를 좁히는 데 큰 도움이 됩니다.
*   **펜테스팅 핵심:** 내부 IP 주소, 구체적인 버전, 인프라 세부 정보를 노출하는 모든 헤더를 보고서에 기록하세요.

## 요청 헤더 (Request Headers): 공격자의 놀이터

클라이언트가 보내는 헤더들입니다. 공격자는 클라이언트를 완전히 제어할 수 있으므로, 이 헤더들은 조작을 통한 공격의 주된 경로가 됩니다.

### 1. Host
*   **보안 관련성:** 조작 시 **Host 헤더 인젝션**, 웹 캐시 포이즈닝, 혹은 비밀번호 재설정 링크의 도메인을 변조하는 공격이 가능합니다.
*   **펜테스팅 핵심:** `Host` 헤더를 공격자 도메인으로 바꿔보고, 애플리케이션이 이 값을 이용해 절대 경로 URL(예: 이메일 링크)을 생성하는지 테스트하세요.

### 2. X-Forwarded-For / X-Real-IP
*   **보안 관련성:** 주로 IP 기반 접근 제어에 사용됩니다. 서버가 이 값을 맹목적으로 신뢰한다면, 공격자가 **IP를 스푸핑(Spoofing)**하여 차단이나 속도 제한을 우회할 수 있습니다.
*   **펜테스팅 핵심:** 이 헤더를 추가했을 때 제한이 풀리거나 내부 IP 대역으로 인식되는지 확인하세요.

### 3. Authorization 및 Cookie
*   **보안 관련성:** 세션 관리의 핵심입니다.
*   **펜테스팅 핵심:** 
    *   **Authorization:** 토큰 재사용, 만료 미흡, 권한 관리 결함(Bole/BOPA)을 테스트하세요.
    *   **Cookie:** 사용자 식별 값을 변경하여 타인의 데이터에 접근할 수 있는지(IDOR) 확인하세요.

### 4. Origin
*   **보안 관련성:** **CORS** 보안의 핵심입니다.
*   **펜테스팅 핵심:** 임의의 `Origin`을 보냈을 때 서버가 `Access-Control-Allow-Origin: *`로 응답하거나 공격자의 오리진을 그대로 반사(Echo)하는지 체크하세요.