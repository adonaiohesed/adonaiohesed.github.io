---
title: HTTP Status Codes
tags: HTTP-Status-Codes
key: page-http_status_codes
categories: [Cybersecurity, Web Security]
author: hyoeun
math: true
mathjax_autoNumber: true
---

### HTTP Status Codes

HTTP status codes are more than just numbers indicating success or failure; they are a critical source of intelligence for a penetration tester. Each code, especially within the error ranges, can reveal hidden server behavior, security configurations, and potential vulnerabilities. Here's a breakdown of what each status code range means from a security perspective.

### **1xx (Informational)**

These codes indicate that a request has been received and is being processed. They are not a primary focus in penetration testing, but understanding them helps in diagnosing complex interactions, such as those involving proxies. A common example is **100 Continue**, which a client uses to check if a server will accept a large request body before sending it.

### **2xx (Success)**

These codes confirm that the request was successfully received, understood, and accepted. The most frequent code is **200 OK**. In penetration testing, a **200** response to a request for a potentially sensitive path (e.g., `/admin`) is a strong signal that the resource exists and is accessible. This is a key finding during directory and file enumeration.

### **3xx (Redirection)**

These codes instruct the client to take additional action to complete the request, typically by redirecting to a new URL. Examples include **301 Moved Permanently** and **302 Found**. From a security standpoint, redirection chains can be a source of vulnerabilities. An improperly configured redirect can lead to an **Open Redirect** vulnerability, allowing an attacker to redirect users to a malicious site.

### **4xx (Client Error)**

This is the most crucial range for a penetration tester, as these codes often reveal flaws in a web application's input validation and access control.

* **400 Bad Request**: Indicates that the server could not understand the request due to syntax errors. This is a good starting point for fuzzing and malformed request testing to see how the server handles unexpected data.
* **401 Unauthorized**: Despite its name, this code means "unauthenticated." It is returned when a client tries to access a resource that requires authentication without providing valid credentials. This helps in mapping out the application's authentication mechanisms.
* **403 Forbidden**: This signifies an "authorization failure." The server understands who the client is but denies access to the requested resource. This is a goldmine for testers, as it points to potential sensitive directories (e.g., `/admin`) that exist but are protected, making them targets for **directory brute-forcing** and access control bypass attempts. The key difference from **401** is that the client is already known to the server.
* **404 Not Found**: The requested resource does not exist. While seemingly uninteresting, this code is invaluable for eliminating invalid paths during enumeration, helping to narrow down the search for live resources.
* **405 Method Not Allowed**: The HTTP method used in the request (e.g., GET, POST) is not supported for the requested resource. This provides a clue for testers to try other HTTP methods (e.g., PUT, DELETE) to find functionality that might be improperly secured.

### **5xx (Server Error)**

These codes indicate that the server failed to fulfill a valid request.

* **500 Internal Server Error**: A generic server-side error. While not a vulnerability itself, it can expose critical debug information like stack traces, which may contain sensitive details such as server paths, database queries, or the versions of underlying frameworks. Testers often intentionally trigger **500** errors to gain this valuable intelligence.
* **502 Bad Gateway**: A proxy or gateway server received an invalid response from an upstream server.
* **504 Gateway Timeout**: A gateway server did not receive a timely response from an upstream server.

---

### **HTTP 상태 코드 분석**

HTTP 상태 코드는 웹 서버가 클라이언트의 요청에 대해 어떤 응답을 반환했는지 알려주는 세 자리 숫자입니다. 일반적인 웹 개발자에게는 에러를 파악하는 용도지만, 웹 모의 해킹 전문가에게는 서버의 숨겨진 정보를 드러내는 중요한 단서가 됩니다. 각 상태 코드 그룹별로 그 의미와 보안적 함의를 깊이 있게 살펴보겠습니다.

#### **1xx (Informational)**

이 상태 코드는 요청이 수신되어 처리 중임을 나타내며, 모의 해킹 시에는 자주 마주치지 않습니다. 대표적인 코드는 **100 Continue**로, 클라이언트가 큰 요청 본문(body)을 보내기 전에 서버의 수용 가능 여부를 확인하는 용도로 사용됩니다.

#### **2xx (Success)**

요청이 성공적으로 처리되었음을 의미합니다. 가장 흔한 코드는 **200 OK**입니다. 모의 해킹 시에는 성공적인 응답을 통해 숨겨진 경로를 찾거나, 특정 파라미터가 유효하게 작동하는지 확인하는 데 사용됩니다.

#### **3xx (Redirection)**

클라이언트가 요청을 완료하기 위해 추가적인 조치를 취해야 함을 나타냅니다.
* **301 Moved Permanently**: 리소스의 URL이 영구적으로 변경되었음을 의미합니다.
* **302 Found**: 리소스의 URL이 일시적으로 변경되었음을 의미합니다.
* **307 Temporary Redirect**: 302와 유사하지만, 원래 요청의 HTTP 메소드(예: POST)를 유지해야 함을 명시합니다.

보안 관점에서는 **리디렉션 체인(redirection chain)**이 공격 표면이 될 수 있습니다. 특히, 잘못된 리디렉션 설정은 사용자를 악성 사이트로 유도하는 **오픈 리디렉션(Open Redirect)** 취약점으로 이어질 수 있습니다.

#### **4xx (Client Error)**

클라이언트의 요청에 오류가 있어 서버가 요청을 처리할 수 없음을 나타냅니다. 모의 해킹 시 가장 중요한 단서가 되는 코드 그룹입니다.

* **400 Bad Request**: 클라이언트의 요청 문법이 잘못되었을 때 발생합니다. 서버가 예상치 못한 형식의 데이터를 받을 경우 이 코드를 반환하며, 이는 **데이터 유효성 검사** 로직의 허점을 찾기 위한 시작점이 될 수 있습니다.
* **401 Unauthorized**: 이 코드는 이름과 달리 **"인증 안 됨(Unauthenticated)"**에 더 가깝습니다. 로그인이 필요한 페이지에 인증 정보 없이 접근했을 때 발생합니다. 공격자는 이 코드를 통해 인증 메커니즘이 존재하는 페이지를 식별할 수 있습니다.
* **403 Forbidden**: **"인가 실패(Authorization Failure)"**를 의미합니다. 서버는 클라이언트가 누구인지 알지만, 해당 리소스에 접근할 권한이 없다고 판단했을 때 반환됩니다. **401이 "로그인하세요"라면, 403은 "당신은 볼 수 없습니다"**라는 의미입니다. 403은 숨겨진 관리자 페이지나 민감한 파일 경로를 열거하는 **디렉터리 브루트포싱(directory brute-forcing)** 공격 시 중요한 신호가 됩니다.
* **404 Not Found**: 요청한 리소스를 찾을 수 없을 때 발생합니다. 공격자는 이 코드를 기반으로 유효하지 않은 URL을 걸러내고, 유효한 경로를 탐색하는 데 사용합니다.
* **405 Method Not Allowed**: 요청에 사용된 HTTP 메소드(GET, POST 등)가 해당 리소스에 허용되지 않을 때 발생합니다. 예를 들어, 특정 API 엔드포인트가 POST 메소드만 허용하는데 GET 메소드로 요청을 보내면 이 코드가 반환됩니다. 이를 통해 공격자는 서버가 특정 메소드만 처리하도록 설계된 부분을 찾아내고, 다른 메소드를 사용해 우회 공격을 시도할 수 있습니다.
* **415 Unsupported Media Type**: 클라이언트가 서버가 지원하지 않는 데이터 타입(Content-Type)으로 요청을 보냈을 때 발생합니다. 이는 서버의 입력값 처리 로직을 파악하는 데 유용하며, XML, JSON 등 다양한 데이터 타입으로 입력값을 조작하여 취약점을 찾을 수 있는 단서가 됩니다.

#### **5xx (Server Error)**

서버가 요청을 처리하는 과정에서 오류가 발생했음을 나타냅니다.

* **500 Internal Server Error**: 서버 측에서 발생한 일반적인 오류입니다. **이 코드 자체가 취약점은 아니지만**, 종종 디버깅 정보(스택 트레이스 등)가 노출되어 서버의 내부 구조, 경로, 사용 중인 라이브러리 버전 등을 파악하는 데 결정적인 정보를 제공할 수 있습니다.
* **502 Bad Gateway**: 게이트웨이나 프록시 서버가 상위 서버로부터 유효하지 않은 응답을 받았을 때 발생합니다.
* **504 Gateway Timeout**: 게이트웨이가 상위 서버로부터 제때 응답을 받지 못했을 때 발생합니다. 이들은 서버의 아키텍처나 네트워크 지연 문제를 진단하는 데 유용합니다.