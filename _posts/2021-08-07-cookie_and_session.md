---
title: Cookie & Seession Security
tags: Cookies Sessions Web-Security
key: page-cookie_session_security
categories: [Cybersecurity, Web Security]
author: hyoeun
math: true
mathjax_autoNumber: true
---

# **Differences Between Cookies and Sessions**

## **Cookies**
Cookies are small pieces of data stored in the client's local storage in key-value pairs. They are primarily used in web applications to identify users or maintain state information.

- **Persistence**: Cookies remain until explicitly deleted if no expiration date is set.  
- **Security Risks**: Cookies can be easily accessed and tampered with on the client side. Sensitive data must be encrypted for security.  
- **Usage Purpose**: Cookies address the limitations of HTTP's **Connectionless** and **Stateless** characteristics by enabling state maintenance.  
  - **Connectionless**: The connection is terminated once the server responds to the client's request.  
  - **Stateless**: HTTP does not maintain information about previous requests.  
- **Example**: Without cookies, users might need to log in repeatedly to purchase items on an online store.  
- **Components**: Cookies consist of attributes such as name, value, expiration date, domain, and path, which allow for their differentiation and management.

## **Session**
A session maintains the state of requests between a client and server until the browser is closed. Managed on the server side, sessions have distinct features compared to cookies.

- **How It Works**:  
  1. The server generates a random session ID when the client sends a request.  
  2. The session ID is stored on the server and sent to the client in the form of a cookie.  
  3. When the client makes subsequent requests with the session ID, the server uses it to verify session information and maintain the state.  
- **Differences from Cookies**:  
  - Cookies store information on the client side and compare values during requests.  
  - Sessions process information on the server side, with the client only transmitting the session ID.  
- **Pros and Cons**:  
  - **Security**: Sessions are safer than cookies as sensitive information is not stored on the client side.  
  - **Performance**: Storing data on the server can increase server load as the number of requests grows. Cookies, processed on the client side, are relatively faster.

---

## **Cookie Options Explanation**

### Name
- Used to identify the cookie.
- Names should be unique and not directly related to sensitive user data.

### Value
- Stores the data associated with the cookie.
- Sensitive data should be encrypted or processed with **HMAC**.

### Domain
- Specifies the domain where the cookie is valid.
- Default: the domain where the cookie was created.  
- **Caution**: Proper configuration is required for cross-subdomain sharing.  
  Example: `.example.com` applies to `sub.example.com` as well.

### Path
- Defines the URL path where the cookie is valid. For example, to request `https://www.example.com/users/login`, the path must be set to `/users/login` or `/`.  
- Default: the path where the cookie was created.  
- Limiting the cookie's usage by narrowing the path is recommended.

### Expires/Max-Age
- Specifies the expiration time of the cookie.  
  - **Expires**: Sets a specific date/time (e.g., `Tue, 19 Jan 2038 03:14:07 GMT`).  
  - **Max-Age**: Sets the duration in seconds (e.g., `3600` for 1 hour).  
- Without these, it becomes a session cookie, deleted when the browser closes.  
- Cookies with these attributes are called **Persistent Cookies**.

### HttpOnly
- Prevents the cookie from being accessed via JavaScript.  
- Protects against **XSS attacks**.

### Secure
- Restricts cookie transmission to HTTPS connections only.  
- Prevents cookie transmission over unencrypted HTTP.

### SameSite
- Controls cross-site cookie transmission.  
  - **Strict**: Cookies are sent only on the same site.  
  - **Lax**: Allows cookies for safe cross-site requests (e.g., GET links/forms).  
  - **None**: Allows all cross-site requests (requires `Secure`).  
- Effective against CSRF attacks.

---

## Example of Secure Cookie Configuration

### Python (Flask) Example
```python
from flask import Flask, make_response

app = Flask(__name__)

@app.route('/')
def set_cookie():
    response = make_response("Setting a secure cookie!")
    response.set_cookie(
        'session_id', 
        'encrypted_value', 
        httponly=True, 
        secure=True, 
        samesite='Strict', 
        max_age=3600
    )
    return response
```
### Java (Spring Boot) Example
```java
import org.springframework.http.ResponseCookie;

ResponseCookie cookie = ResponseCookie.from("session_id", "encrypted_value")
        .httpOnly(true)
        .secure(true)
        .sameSite("Strict")
        .path("/")
        .maxAge(3600)
        .build();

response.addHeader("Set-Cookie", cookie.toString());
```

## **Cookie-Related Security Vulnerabilities and Countermeasures**

Below is an explanation of key security vulnerabilities related to cookies, along with examples of Request/Response and corresponding countermeasures. Examples for Python (Flask) and Java (Spring Boot) implementations are also included.

## 1. Cookie Theft

### Vulnerability Explanation  
If a cookie is stolen, an attacker can intercept the user's session or exploit sensitive information to attack the account. The risk is higher in environments without HTTPS.

### Vulnerable Request/Response Example  
**Request**
```http
GET /dashboard HTTP/1.1
Host: example.com
Cookie: session_id=abcd1234; user_id=12345
```
**Response**
```
Set-Cookie: session_id=abcd1234; Path=/; HttpOnly
```

- Problem: The `Secure` attribute is missing, so the cookie is transmitted without HTTPS.

### Countermeasure  
- Use HTTPS to encrypt the transmitted data.
- Set the `Secure` attribute to ensure that cookies are transmitted only over encrypted connections.

**Countermeasure Example**
```
Set-Cookie: session_id=abcd1234; Path=/; HttpOnly; Secure
```

**Python (Flask) Example**
```python
response.set_cookie(
    'session_id', 
    'abcd1234', 
    httponly=True, 
    secure=True, 
    samesite='Strict', 
    max_age=24 * 60 * 60
)
```

**Java (Spring Boot) Example**
```java
ResponseCookie cookie = ResponseCookie.from("session_id", "abcd1234")
        .httpOnly(true)
        .secure(true)
        .path("/")
        .sameSite("Strict")
        .maxAge(24 * 60 * 60)
        .build();
```
## 2. Cookie Exposure through XSS (Cross-Site Scripting)

### Vulnerability Explanation  
Through XSS, an attacker can inject client-side scripts that expose the cookie values.

### Vulnerable Request/Response Example  
**Request**
```http
GET /search?q=<script>document.write(document.cookie)</script> HTTP/1.1
Host: example.com
```

**Response**
```html
<body>session_id=abcd1234; user_id=12345</body>
```

- Problem: The `HttpOnly` attribute is missing, so the cookie value is accessible via JavaScript.

### Countermeasure  
- Set the `HttpOnly` attribute to block JavaScript access to the cookie.
- Thoroughly validate user inputs and perform HTML encoding.

**Countermeasure Example**
```
Set-Cookie: session_id=abcd1234; Path=/; HttpOnly; Secure; SameSite=Strict
```

**Python(Flask) Example**
```python
response.set_cookie(
    'session_id', 
    'abcd1234', 
    httponly=True, 
    secure=True, 
    samesite='Strict'
)
```

**Java(Spring Boot) Example**
```java
ResponseCookie cookie = ResponseCookie.from("session_id", "abcd1234")
        .httpOnly(true)
        .secure(true)
        .path("/")
        .sameSite("Strict")
        .build();
```

## 3. Cookie Tampering

### Vulnerability Explanation  
An attacker may manipulate cookie data to bypass server authorization checks or gain unauthorized access to sensitive information.

### Vulnerable Request/Response Example  
**Request**
```http
GET /admin HTTP/1.1
Host: example.com
Cookie: role=user
```

- The attacker changes `role=user` to `role=admin` to attempt administrative access.

**Response**
```http
HTTP/1.1 200 OK
```

- Problem: Cookie data is stored in plaintext and can be manipulated without integrity checks.

### Countermeasure  
- Encrypt cookie data or use HMAC to verify integrity.


**Countermeasure Example**
```
Set-Cookie: role=eyJ1c2VyIjoiYWRtaW4ifQ==; Path=/; HttpOnly; Secure
```

**Python(Flask) Example**
```python
import jwt
secret_key = 'your_secret_key'
encrypted_cookie = jwt.encode({"role": "admin"}, secret_key, algorithm="HS256")
response.set_cookie('role', encrypted_cookie, httponly=True, secure=True)
```

**Java(Spring Boot) Example**
```java
String encryptedCookie = Base64.getEncoder().encodeToString("role=admin".getBytes());
ResponseCookie cookie = ResponseCookie.from("role", encryptedCookie)
        .httpOnly(true)
        .secure(true)
        .path("/")
        .sameSite("Strict")
        .build();
```

## 4. CSRF (Cross-Site Request Forgery)

### Vulnerability Explanation  
CSRF is an attack where an attacker sends a malicious request while the user is authenticated, causing the server to perform actions on behalf of the attacker.

### Vulnerable Request/Response Example  
**Request**
```http
POST /transfer HTTP/1.1
Host: bank.com
Cookie: session_id=abcd1234
Content-Type: application/x-www-form-urlencoded

amount=1000&to_account=12345678
```

- The attacker induces the victim to execute this request to steal funds.

### Countermeasure  
- Include a CSRF protection token in the request for validation.
- Set the `SameSite` attribute to prevent cookies from being sent with cross-site requests.


**Countermeasure Example**
```
Set-Cookie: session_id=abcd1234; Path=/; HttpOnly; Secure; SameSite=Strict
```

**Python(Flask) Example**
```python
csrf_token = generate_csrf_token()
response.set_cookie('csrf_token', csrf_token, httponly=True, secure=True, samesite='Strict')
```

**Java(Spring Boot) Example**
```java
ResponseCookie csrfCookie = ResponseCookie.from("csrf_token", "generated_csrf_token")
        .httpOnly(true)
        .secure(true)
        .sameSite("Strict")
        .build();
```

---
# **쿠키와 세션의 차이**

## **Cookies**
쿠키는 클라이언트의 로컬 저장소에 key-value 쌍의 형태로 저장되는 작은 데이터입니다. 주로 웹 애플리케이션에서 사용자를 식별하거나 상태 정보를 유지하는 데 사용됩니다.

- **지속성**: 쿠키는 유효 기간이 설정되지 않으면 반영구적으로 남아있습니다. 이를 방지하려면 명시적으로 쿠키를 삭제해야 합니다.  
- **보안 위험**: 쿠키는 클라이언트에서 쉽게 접근 및 위변조될 수 있으므로, 민감한 정보는 반드시 암호화하여 저장해야 안전합니다.  
- **사용 이유**: HTTP는 기본적으로 **Connectionless**와 **Stateless** 특성을 가지기 때문에 사용자 식별이 어렵습니다. 쿠키는 이러한 한계를 극복하여 상태 유지를 가능하게 합니다.  
  - **Connectionless**: 클라이언트가 요청을 보내고 서버가 응답을 반환하면 연결이 끊깁니다.  
  - **Stateless**: 이전 요청과 상태 정보를 유지하지 않습니다.  
- **사용 예시**: 쿠키를 사용하지 않는 경우, 쇼핑몰에서 로그인 후 상품을 구매하려고 할 때마다 다시 로그인을 요구받을 수 있습니다.  
- **구성 요소**: 쿠키에는 이름, 값, 유효 기간, 도메인, 경로 등의 정보가 포함됩니다. 이를 통해 각 쿠키를 구분하고 관리합니다.

## **Session**
세션은 브라우저가 종료될 때까지 클라이언트와 서버 간의 요청 상태를 유지해주는 기술입니다. 세션은 클라이언트 측이 아닌 서버 측에서 관리되며, 쿠키와 다른 몇 가지 특징이 있습니다.

- **동작 방식**:  
  1. 클라이언트가 서버에 요청을 보내면, 서버는 랜덤한 세션 ID를 생성합니다.  
  2. 이 세션 ID는 서버에 저장되며, 동시에 클라이언트에 쿠키의 형태로 전달됩니다.  
  3. 이후 클라이언트가 요청을 보낼 때 세션 ID를 포함하면, 서버는 해당 ID를 통해 세션 정보를 확인하고 상태를 유지합니다.  
- **쿠키와의 차이점**:  
  - 쿠키는 클라이언트 단에서 정보를 저장하고 요청 시 값을 비교합니다.  
  - 세션은 서버 측에서 정보를 처리하며, 클라이언트는 단순히 세션 ID만 전달합니다.  
- **장단점**:  
  - **보안**: 세션은 클라이언트에 민감한 정보를 저장하지 않으므로 위변조 가능성이 낮아 쿠키보다 안전합니다.  
  - **성능**: 서버에 데이터를 저장하기 때문에 요청이 많아질수록 서버 부하가 증가할 수 있습니다. 반면 쿠키는 클라이언트 측에서 처리되므로 상대적으로 속도가 빠릅니다.

---

## **쿠키 옵션 설명**

### Name
- 쿠키를 식별하기 위한 이름입니다.
- 쿠키 이름은 고유해야 하며, 사용자 데이터와 관련된 의미를 포함하지 않는 것이 좋습니다.

### Value
- 쿠키에 저장되는 데이터 값입니다.
- 중요한 데이터는 **암호화** 또는 **HMAC** 처리하여 저장해야 합니다.

### Domain
- 쿠키가 유효한 도메인을 지정합니다.
- 기본값은 쿠키가 생성된 도메인입니다.
- **주의**: 서브도메인 간 공유가 필요한 경우, 반드시 정확한 설정이 필요합니다.  
  예: `.example.com`은 `sub.example.com`에도 적용됩니다.

### Path
- 쿠키가 유효한 URL 경로를 지정합니다. 예를들어, https://www.example.com/users/login으로 요청하기 위해서는 Path의 경로를 /users/login 혹은 / 으로 설정하여야 합니다. 만약 Path가 /users로 설정되어 있고 요청하는 경로가 /posts/content 로 하면 Path옵션에 만족하지 못하기 때문에 서버로 쿠키를 전송할 수 없게 됩니다.
- 기본값은 쿠키가 생성된 경로입니다.
- 좁은 범위의 경로를 설정하여 쿠키 사용을 제한하는 것이 권장됩니다.

### Expires/Max-Age
- 쿠키의 만료 시간을 지정합니다.
  - **Expires**: 특정 날짜/시간을 설정 (예: `Tue, 19 Jan 2038 03:14:07 GMT`).
  - **Max-Age**: 현재 시간부터의 초 단위 경과 시간 (예: `3600`은 1시간).
- Max-Age 또는 Expires 옵션이 없으면 Session Cookei이고 브라우저를 종료하면 해당 쿠키는 삭제됩니다.
- 브라우저의 종료와 상관없이 Max-Age 또는 Expires에 지정된 유효시간만큼 사용가능한 쿠키를 Persistent Cookei로 부릅니다.

### HttpOnly
- 설정 시, 쿠키가 클라이언트의 JavaScript에서 접근할 수 없습니다.
- **XSS 공격**으로부터 쿠키를 보호합니다.

### Secure
- HTTPS 연결에서만 쿠키가 전송되도록 설정합니다.
- 암호화되지 않은 HTTP에서 쿠키 전송을 방지합니다.

### SameSite
- 쿠키가 크로스사이트 요청에 전송되는 방식을 제어합니다.
  - **Strict**: 동일 사이트에서만 쿠키 전송.
  - **Lax**: 안전한 크로스사이트 요청(GET 링크/폼) 허용.
  - **None**: 모든 크로스사이트 요청 허용 (단, `Secure` 필수).
- CSRF를 막는데 매우 효과적인 옵션입니다.
---

## 쿠키 주요 보안 옵션 설정 예시

아래는 쿠키를 안전하게 설정하기 위한 샘플 코드입니다.

### Python (Flask) 예제
```python
from flask import Flask, make_response

app = Flask(__name__)

@app.route('/')
def set_cookie():
    response = make_response("Setting a secure cookie!")
    response.set_cookie(
        'session_id', 
        'encrypted_value', 
        httponly=True, 
        secure=True, 
        samesite='Strict', 
        max_age=3600
    )
    return response
```
### Java (Spring Boot) 예제
```java
import org.springframework.http.ResponseCookie;

ResponseCookie cookie = ResponseCookie.from("session_id", "encrypted_value")
        .httpOnly(true)
        .secure(true)
        .sameSite("Strict")
        .path("/")
        .maxAge(3600)
        .build();

response.addHeader("Set-Cookie", cookie.toString());
```

## **쿠키 관련 보안 취약점과 대응 방안**

아래는 쿠키와 관련된 주요 보안 취약점에 대한 설명과 함께 Request/Response 예시 및 대응 방안을 정리한 내용입니다. Python(Flask)와 Java(Spring Boot)에서의 구현 예제도 포함되어 있습니다.

## 1. 쿠키 탈취 (Cookie Theft)

### 취약점 설명  
쿠키가 탈취되면 공격자는 사용자의 세션을 가로채거나 민감한 정보를 활용해 계정을 공격할 수 있습니다. HTTPS가 없는 환경에서는 위험이 더욱 커집니다.

### 취약한 Request/Response 예시  
**Request**
```http
GET /dashboard HTTP/1.1
Host: example.com
Cookie: session_id=abcd1234; user_id=12345
```
**Response**
```
Set-Cookie: session_id=abcd1234; Path=/; HttpOnly
```

- 문제: `Secure` 속성이 없어 HTTPS 없이 쿠키가 전송됩니다.

### 대응 방안  
- HTTPS를 사용하여 전송 데이터를 암호화합니다.
- `Secure` 속성을 설정해 쿠키가 암호화된 연결에서만 전송되도록 합니다.

**대응 방안 예시**
```
Set-Cookie: session_id=abcd1234; Path=/; HttpOnly; Secure
```

**Python(Flask) 코드 예제**
```python
response.set_cookie(
    'session_id', 
    'abcd1234', 
    httponly=True, 
    secure=True, 
    samesite='Strict', 
    max_age=24 * 60 * 60
)
```

**Java(Spring Boot) 코드 예제**
```java
ResponseCookie cookie = ResponseCookie.from("session_id", "abcd1234")
        .httpOnly(true)
        .secure(true)
        .path("/")
        .sameSite("Strict")
        .maxAge(24 * 60 * 60)
        .build();
```

## 2. XSS(Cross-Site Scripting) 취약점을 통한 쿠키 노출

### 취약점 설명  
XSS를 통해 공격자가 클라이언트 측 스크립트를 삽입하고 이를 통해 쿠키 값을 노출시킬 수 있습니다.

### 취약한 Request/Response 예시  
**Request**
```http
GET /search?q=<script>document.write(document.cookie)</script> HTTP/1.1
Host: example.com
```

**Response**
```html
<body>session_id=abcd1234; user_id=12345</body>
```

- 문제: `HttpOnly` 속성이 없어 쿠키 값이 JavaScript에서 접근 가능합니다.

### 대응 방안  
- `HttpOnly` 속성을 설정해 JavaScript에서 쿠키 접근을 차단합니다.
- 사용자 입력 값을 철저히 검증하고 HTML 엔코딩을 수행합니다.

**대응 방안 예시**
```
Set-Cookie: session_id=abcd1234; Path=/; HttpOnly; Secure; SameSite=Strict
```

**Python(Flask) 코드 예제**
```python
response.set_cookie(
    'session_id', 
    'abcd1234', 
    httponly=True, 
    secure=True, 
    samesite='Strict'
)
```

**Java(Spring Boot) 코드 예제**
```java
ResponseCookie cookie = ResponseCookie.from("session_id", "abcd1234")
        .httpOnly(true)
        .secure(true)
        .path("/")
        .sameSite("Strict")
        .build();
```

## 3. 쿠키 위변조 (Cookie Tampering)

### 취약점 설명  
클라이언트가 쿠키 데이터를 조작하여 서버의 권한 검증을 우회하거나 민감한 정보에 접근하려는 공격입니다.

### 취약한 Request/Response 예시  
**Request**
```http
GET /admin HTTP/1.1
Host: example.com
Cookie: role=user
```

- 공격자가 `role=user`를 `role=admin`으로 변경해 관리자 권한을 시도.

**Response**
```http
HTTP/1.1 200 OK
```

- 문제: 쿠키 데이터가 평문으로 저장되어 조작 가능하며, 무결성 검증이 없습니다.

### 대응 방안  
- 쿠키 데이터를 암호화하거나 HMAC으로 무결성을 검증합니다.

**대응 방안 예시**
```
Set-Cookie: role=eyJ1c2VyIjoiYWRtaW4ifQ==; Path=/; HttpOnly; Secure
```

**Python(Flask) 코드 예제**
```python
import jwt
secret_key = 'your_secret_key'
encrypted_cookie = jwt.encode({"role": "admin"}, secret_key, algorithm="HS256")
response.set_cookie('role', encrypted_cookie, httponly=True, secure=True)
```

**Java(Spring Boot) 코드 예제**
```java
String encryptedCookie = Base64.getEncoder().encodeToString("role=admin".getBytes());
ResponseCookie cookie = ResponseCookie.from("role", encryptedCookie)
        .httpOnly(true)
        .secure(true)
        .path("/")
        .sameSite("Strict")
        .build();
```

## 4. CSRF(Cross-Site Request Forgery)

### 취약점 설명  
CSRF는 사용자가 인증된 세션을 가진 상태에서 공격자가 악의적인 요청을 전송하게 하여 서버 작업을 수행하게 만드는 공격입니다.

### 취약한 Request/Response 예시  
**Request**
```http
POST /transfer HTTP/1.1
Host: bank.com
Cookie: session_id=abcd1234
Content-Type: application/x-www-form-urlencoded

amount=1000&to_account=12345678
```

- 공격자는 피해자가 이 요청을 실행하도록 유도하여 자금을 탈취.

### 대응 방안  
- CSRF 방지 토큰을 요청에 포함해 검증합니다.
- `SameSite` 속성을 설정해 외부 요청에서 쿠키가 전송되지 않도록 합니다.

**대응 방안 예시**
```
Set-Cookie: session_id=abcd1234; Path=/; HttpOnly; Secure; SameSite=Strict
```

**Python(Flask) 코드 예제**
```python
csrf_token = generate_csrf_token()
response.set_cookie('csrf_token', csrf_token, httponly=True, secure=True, samesite='Strict')
```

**Java(Spring Boot) 코드 예제**
```java
ResponseCookie csrfCookie = ResponseCookie.from("csrf_token", "generated_csrf_token")
        .httpOnly(true)
        .secure(true)
        .sameSite("Strict")
        .build();
```