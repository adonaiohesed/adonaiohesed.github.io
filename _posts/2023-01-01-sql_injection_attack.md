---
title: SQL Injection
tags: SQL-Injection Web-Hacking Cybersecurity
key: page-sql_injection_attack
categories: [Cybersecurity, Web Security]
author: hyoeun
math: true
mathjax_autoNumber: true
---

## SQL Injection: When Data Becomes Code

### Introduction

SQL Injection (SQLi) is one of the oldest yet persistently dangerous web application vulnerabilities. At its core, SQLi stems from a fundamental failure to **properly separate data from code.**

  * The problem typically arises when **untrusted data (input data from the user)** and **trusted data (program logic)** are mixed within a single context, blurring the clear boundary that should exist between them. This ambiguity creates exploitable loopholes.
  * Secondly, when this mixed data is passed to an interpreter (like an SQL database engine), if **special characters** within the untrusted data are not properly handled, this string is then **interpreted and executed as code**, leading to a vulnerability.
  * In compiled languages like C, the compilation process inherently separates code and data, making direct code injection attacks (like SQLi in web apps) more challenging. However, even in C, vulnerabilities like **Buffer Overflow (BOF)** exist where code and data can mix, potentially allowing an attacker to manipulate the return address to execute injected code within the data area.
  * Web applications, being interpreter-based, are capable of generating code dynamically. This dynamic nature makes them inherently **more susceptible** to injection attacks like SQL Injection.
  * Attempting attacks via command-line tools like `curl` often facilitates **automation** more easily than manual interaction through a GUI-based web browser.
  * Before launching an attack, it's crucial to **execute the intended SQL statement directly within the target DB program (e.g., MySQL client)** to check for syntax errors. Servers typically do not return detailed error messages for security reasons, so verifying syntactic correctness is vital before attempting an actual attack against a live server.

### **MySQL Usage Examples and Problem**

Let's look at some basic SQL statements to understand how SQL Injection occurs.

  * **Typical SELECT Statement:**

    ```sql
    SELECT Name, Salary, SSN
    FROM employee
    WHERE eid='EDI5002' and password='1234';
    ```

    This query retrieves the name, salary, and SSN for an employee where `eid` is 'EDI5002' and `password` is '1234'. Here, `eid` and `password` are values typically received from user input.

  * **Typical UPDATE Statement:**

    ```sql
    UPDATE employee
    SET password='paswd456', salary=100000
    WHERE eid='EID4000' and password='passwd123';
    ```

    This statement updates an employee's password and salary.

  * **Example with Malicious Input (Demonstrating the SQL Injection Problem):**
    If user input is directly concatenated into the SQL query string, and an attacker inserts a malicious string like `'1234'; DROP DATABASE dbtest;` into the `password` field, the final query executed on the server could be transformed as follows:

    ```sql
    SELECT Name, Salary, SSN
    FROM employee
    WHERE eid='EDI5002' and password='1234'; DROP DATABASE dbtest;
    ```

    In this case, the database might execute the `SELECT` query followed by the `DROP DATABASE dbtest;` command, leading to the **catastrophic deletion of the entire database.** This is a classic SQL Injection problem where user input (data) is interpreted and executed as part of the SQL statement (code).

### **Types of SQL Injection**

SQL Injection attacks can be categorized into several types based on how data is extracted or how the system is affected. Pentesters must understand the characteristics of each type and apply appropriate detection and exploitation techniques.

#### **1. In-band SQL Injection**

This type of attack occurs when data is extracted via SQL Injection through the **same communication channel as the web application's normal HTTP response.** It is the most common and often easiest to detect.

  * **UNION-based SQL Injection (UNION-based SQLi):**

      * **Description:** An attacker uses the `UNION SELECT` statement to **combine the results of a malicious `SELECT` query with the results of the original SQL query**, making them appear together on the web page.
      * **Mechanism:** `UNION SELECT` requires both `SELECT` statements to have the same number of columns and compatible data types. Attackers often guess the number of columns using clauses like `ORDER BY`, then match column counts with `UNION SELECT NULL, NULL, ...`. Subsequently, they inject desired data using `UNION SELECT version(), database(), user()`, etc., to be displayed on the web page.
      * **Detection:** Observe if query results are appended to the normal content of the web page.
      * **Impact:** Retrieval of arbitrary data from other tables, database user information, version information, etc.
      * **Pentesting:** Use `ORDER BY` to guess column count, then attempt `UNION SELECT` to retrieve database version, user, database name, and other information.

  * **Error-based SQL Injection (Error-based SQLi):**

      * **Description:** An attacker intentionally causes an SQL syntax error, leading the database to return **detailed error messages** that include sensitive information like query results or database structure.
      * **Mechanism:** Exploits specific functions that generate errors while embedding query results (e.g., `UPDATEXML()`, `EXTRACTVALUE()` in MySQL; `xp_cmdshell` in MSSQL).
      * **Detection:** Look for verbose database error messages displayed on the web page.
      * **Impact:** Database information disclosure, arbitrary data extraction.
      * **Pentesting:** Inject common error-inducing SQL payloads and analyze the error messages included in the response.


#### **2. Out-of-band SQL Injection**

This type of attack occurs when the attacker extracts data from the database via an **external channel (e.g., DNS queries, HTTP requests)**, rather than through the web application's HTTP response channel. It is used when direct display of errors or data on the web page is not possible.

  * **Description:** The database is forced to directly send data to an external system controlled by the attacker (e.g., the attacker's web server or DNS server).
  * **Mechanism:** Leverages specific database system functions that can initiate external network requests (e.g., Oracle's `UTL_HTTP`, MySQL's `LOAD_FILE` for SMB/WebDAV requests, MSSQL's `xp_cmdshell` for outbound connections). The attacker monitors their server logs (DNS, HTTP) to observe the data transmitted from the database.
  * **Detection:** Requires monitoring logs on external servers (DNS, HTTP) for abnormal requests originating from the database.
  * **Impact:** Enables arbitrary data extraction even when direct output to the web page is impossible.
  * **Pentesting:** Set up a controlled external server (e.g., `ngrok`, Burp Collaborator) and inject OOB payloads that induce the database to send requests to the external server.

#### **3. Inferential SQL Injection (Blind SQL Injection)**

Also known as **Blind SQL Injection**, this occurs when the attacker does not receive direct data back from the database but **infers information by observing the application's response (e.g., changes in page content, response time)** based on true/false conditions within the injected query. This method is very time-consuming and requires the assistance of automated tools (like SQLmap).

  * **Boolean-based Blind SQL Injection (Boolean-based SQLi):**

      * **Description:** An attacker injects an SQL condition that returns True or False, and infers information by observing subtle changes in the web page's content or behavior based on the result.
      * **Mechanism:** When a condition like `WHERE id='X' AND (SUBSTRING(password,1,1)='a')` is injected, if the condition is true, the web page appears normal; if false, an error page might appear, or the content might differ. By observing these changes, individual characters can be guessed.
      * **Detection:** Requires meticulous observation of web page content changes or analysis of response length differences.
      * **Impact:** Enables arbitrary data extraction, but at a very slow pace.
      * **Pentesting:** Analyze web page responses when specific conditions (e.g., is the first character of the password 'a'?) are true versus false, and use automated scripts to try all possible characters.

  * **Time-based Blind SQL Injection (Time-based SQLi):**

      * **Description:** An attacker injects an SQL condition that returns True or False, and infers information by observing **delays in the database's response time** based on the result. This is a last resort when even content changes are not observable.
      * **Mechanism:** Inject a condition like `WHERE id='X' AND IF((SUBSTRING(password,1,1)='a'), SLEEP(5), 0)`. If the condition is true, the database delays the response by 5 seconds; if false, it responds immediately without delay. This time difference allows for guessing individual characters.
      * **Detection:** Requires precise measurement and analysis of the web application's response times.
      * **Impact:** Similar to boolean-based, enables arbitrary data extraction, but at an even slower pace.
      * **Pentesting:** Use automated tools to send numerous requests and measure the response time of each to infer information.

-----

### **SQL Injection Defense and Mitigation**

Effectively defending against SQL Injection attacks requires a comprehensive approach across multiple layers, rather than relying on a single defense mechanism.

#### **1. Core Defenses (Most Important)**

* **Prepared Statements (Parameterized Queries):**
    * **Principle:** This is the **most effective and recommended method** to fundamentally prevent SQL Injection by completely separating code from data. The SQL statement (code) is first sent to the database server for compilation, and user input (data) is then bound separately through a "data channel." The data is never interpreted as code.
    * **Application:** It must be enforced to use Prepared Statements for all database queries. Most programming languages and frameworks support this.

* **Input Validation:**
    * **Principle:** Before processing user input in the application, it is validated to ensure it conforms to the expected format and content.
    * **Application:**
        * **Whitelist Approach:** Clearly define and allow only specific characters, numbers, patterns, and lengths, rejecting all other input. (e.g., an email address field allows only email format, a numeric field allows only numbers).
        * Data Type Validation: Inputs expected to be numbers or dates, rather than strings, must be rigorously validated for their respective data types.
    * **Effectiveness:** This acts as the first line of defense, preventing malicious data from even reaching the database query construction stage.

* **Output Encoding/Escaping:**
    * **Principle:** Before concatenating user input into an SQL query string, **all special characters** that the SQL interpreter could interpret as code must be **encoded (escaped).**
    * **Application:** Use APIs that correctly escape characters like `NULL`, `\r`, `\n`, `\`, `'`, `"`, `%`, `_` according to the specific database system.
    * **Effectiveness:** While safer than taking no action, this method is only a supplementary defense in extremely rare legacy environments where Prepared Statements cannot be used. It is not foolproof, and Prepared Statements should always be prioritized.

#### **2. Auxiliary and Reinforcing Defenses (Defense in Depth)**

* **Principle of Least Privilege:**
    * **Application:** Database users should be configured with the minimum necessary privileges required for the application's needs. For example, an account that only needs to query data should not have permissions to modify or delete data.
    * **Effectiveness:** Minimizes the scope of damage and privileges an attacker can obtain even if an SQL Injection occurs.

* **Robust Error Handling:**
    * **Application:** In a production environment, detailed database error messages should **never be exposed to the user.** Return generic error messages (e.g., "A service issue occurred. Please try again later.") and log detailed error information only in backend logs to prevent attackers from gaining insights into database structure or vulnerabilities.

* **Web Application Firewall (WAF) Usage:**
    * **Application:** A WAF helps detect and block common web attack patterns like SQL Injection. It can act as a first line of defense at the application layer.
    * **Effectiveness:** Automatically blocks a large volume of known attack patterns, reducing the amount of malicious traffic reaching the application server. However, it cannot block all attacks (especially sophisticated bypass techniques) and must be used in conjunction with application-code level defenses.

* **Regular Security Audits and Penetration Testing:**
    * **Application:** Conduct continuous code reviews, utilize SAST (Static Analysis Security Testing)/DAST (Dynamic Analysis Security Testing) tools, and perform regular penetration tests to proactively discover and fix potential SQL Injection vulnerabilities.
    * **Effectiveness:** Ensures ongoing defense against new vulnerabilities or bypass techniques and reduces the likelihood of mistakes during development.

* **Database Security Hardening:**
    * **Application:** Keep the database software itself patched to the latest version to remove known vulnerabilities. Unnecessary functions (e.g., file system access functions, shell command execution functions) should be disabled or their access restricted.
    * **Effectiveness:** Increases the security level of the database system itself, making it harder for attackers to cause further damage even after successful Injection.

-----

### **SQL Query Specifics & Common Bypass/Attack Techniques (Re-emphasized)**

The various types of SQL Injection described above utilize the SQL query specifics and common attack/bypass techniques detailed below to construct actual payloads.

  * SQL is generally **case-insensitive** for keywords (SELECT, WHERE, etc.) and function names, but case sensitivity for string data or table/column names might vary based on database configuration.
  * `length(pw)=8`: The `length()` function returns the length of a string. `length(pw)=8` checks if the length of the `pw` column is 8. This can be used in Blind SQL Injection to guess password lengths.
  * `str_replace("admin",'',<something>)`: The `str_replace()` function replaces a specific part of a string with another. In bypass attempts, `adADMINmin` might become `admin` after replacement, potentially leading to a successful bypass of filtering that targets literal "admin."
  * `ascii(str)`: Returns the ASCII code of the first character of a string. Used in Blind SQL Injection to infer characters (e.g., `WHERE ascii(substr(pw,1,1))=97` checks if the first character of the password is 'a').
  * **Single Quotes (`'`) and Double Quotes (`"`):** In some databases like MySQL, both single and double quotes can be used interchangeably to define string literals. If one is filtered, the other might be used to bypass.
  * **`WHERE` Clause Overwrites:** When multiple conditions are chained with `AND` or `OR` in the `WHERE` clause, injecting `' OR 1=1 --` can neutralize or overwrite the original authentication conditions that follow.
  * **`LIKE` Clause and Wildcards:**
      * `%` (wildcard): Represents zero or more characters. `LIKE 'Kim%'` finds anything starting with 'Kim'; `LIKE '%Young'` finds anything ending with 'Young'; `LIKE '%Su%'` finds anything containing 'Su'.
      * `_` (wildcard): Represents exactly one character. `LIKE 'Kim_Su'` finds three-letter words starting with 'Kim' and ending with 'Su'.
  * **Character Ranges:** `[a-e]%` means anything starting with one of the alphabets from 'a' to 'e'. `[^a-e]%` or `[!a-e]%` means anything starting with a character *not* from 'a' to 'e'.

### **Operators Equivalent to `=` (Used in Filtering Bypass)**

  * `like`: Can be used instead of `=`, e.g., `id like 'admin'`. When `LIKE` is allowed, it can open doors for injection attempts using wildcards.
  * `in`: Can be used instead of `=`, e.g., `id in ('admin')`. `in` allows multiple values separated by commas. If `IN` clauses are poorly filtered, list injection attacks may be possible.

### **Comment Characters**

In SQL Injection attacks, comment characters are crucial for neutralizing the remainder of the original query, allowing only the attacker's injected query to execute.

  * `#` == `%23` (MySQL single-line comment)
  * ` --  ` (two hyphens followed by a space): SQL standard single-line comment. A space is essential.
  * `/* */`: Multi-line comment delimiters.

### **Space Character Bypass Techniques**

If spaces are filtered, other characters can be used to replace them in SQL queries.

  * `SP` (Space, URL encoded: `%20`)
  * `\t` (Tab, URL encoded: `%09`)
  * `\n` (Newline, Line Feed, URL encoded: `%0a`)
  * `VT` (Vertical Tab, URL encoded: `%0b`): May be recognized as a space in some SQL environments.
  * `FF` (Form Feed, URL encoded: `%0c`): May be recognized as a space in some SQL environments.
  * `\r` (Carriage Return, URL encoded: `%0d`)

### **Logical Operators Bypass Techniques**

If `AND` or `OR` logical operators are filtered, equivalent symbols can be used for bypass.

  * `and` == `&&` (URL encoded: `%26%26`)
  * `or` == `||` (URL encoded: `%7c%7c`)

### **Substring Functions**

Used in Blind SQL Injection to guess specific characters of a database string (e.g., a password) one by one.

  * `substr()`, `substring()`, `mid()`: Function names may vary by database system.
      * `substr(pw,2,1)='1'` checks if the single character extracted from the `pw` string, starting at the second position, is '1'. This is used to infer individual characters of a password.

### **URL Encoding (Refer to Image)**

URL Encoding is the process of converting special characters or non-ASCII characters into `%` (percent) followed by their hexadecimal value for safe transmission over the web. It is essential when embedding SQL Injection payloads in URLs.

  * \<img alt=" " src="/assets/images/url\_encoding.png"\>

### **ASCII Code (Refer to Image)**

In SQL Injection attacks, particularly Blind SQL Injection, ASCII values of characters are used to construct queries for guessing specific characters.

  * \<img alt=" " src="/assets/images/asciicode.jpg"\>

### **Attack Examples (SQL Injection Scenarios)**

Based on the fundamental knowledge mentioned above, let's look at real-world SQL Injection attack scenarios.

  * **Scenario \#1: Authentication Bypass**

      * **Input:** `username=sadcowboy&password=' OR '1'='1`
      * **Transformed Query (Hypothetical):** `SELECT * FROM users WHERE username = 'sadcowboy' AND password = '' OR '1'='1'`
      * **Explanation:** By injecting `' OR '1'='1` into the `password` field, the original condition like `password = '1234'` is changed to `password = '' OR '1'='1'`. The `OR '1'='1'` part always evaluates to true, potentially bypassing authentication if the `username` condition is also true. Comment characters like `--` or `#` could also be used to neutralize the rest of the original SQL query.
      * **Result:** It may be possible to log in as the `sadcowboy` account without a valid password.

  * **Scenario \#2: Login as Admin & Data Extraction**

      * **Input:** `name=' OR '1'='1-- &password=' OR '2'>'1`
      * **Transformed Query (Hypothetical):** `SELECT * FROM users WHERE login = '' OR '1'='1' -- ' AND password ='' OR '2'>'1' LIMIT 1`
      * **Explanation:** Injecting ` ' OR '1'='1--  ` into the `login` field makes the `login = '' OR '1'='1'` condition always true. The `--` then comments out the subsequent `AND password =''` part. The injection `' OR '2'>'1'` in the `password` field also evaluates to true. `LIMIT 1` restricts the database to return only the first found record.
      * **Result:** This attack can potentially lead to logging in as the **first user found in the database (who is often an administrator account).** If successful, the attacker gains administrative privileges and can then attempt further attacks (e.g., data extraction, privilege escalation) by exploiting other vulnerabilities in the application.

SQL Injection involves complex attack patterns and bypass techniques. Therefore, it's crucial to implement fundamental defense mechanisms like `Prepared Statements`, perform thorough input validation, and conduct regular penetration testing to continuously strengthen security.

### **Automating SQL Injection Attacks: Tools and Techniques**

Due to their complexity and time-consuming nature, most SQL Injection attacks are performed using automated tools. Automation is essential, especially for Blind SQL Injection and Time-based SQL Injection, which require numerous requests and response analyses.

#### **1. Primary Automation Tool: SQLmap**

  * **Description:** SQLmap is an open-source penetration testing tool written in Python, specialized in detecting and exploiting SQL Injection vulnerabilities. It is widely recognized as the de facto standard for automating SQL Injection attacks.
  * **Key Features:**
      * **Detects and Exploits Various SQLi Types:** It can automatically detect and exploit almost all types of SQL Injection, including error-based, UNION-based, blind (boolean-based, time-based), and out-of-band.
      * **Database Fingerprinting:** Automatically identifies the type, version, and OS of the database system (MySQL, PostgreSQL, Oracle, MSSQL, etc.) used by the target web application.
      * **Data Dumping:** Can dump and extract all databases, tables, columns, and records within the database. It can also dump specific tables or columns.
      * **File Access and OS Command Execution:** If permitted by certain database systems (e.g., MySQL's `LOAD_FILE`, MSSQL's `xp_cmdshell`), it can read local files on the database server or execute OS commands to gain control over the server.
      * **Web Application Firewall (WAF) Bypass:** Includes various bypass techniques (e.g., encoding, obfuscation, comment usage, HTTP header manipulation) to attempt to evade WAF detection.
      * **Session Management:** Can utilize authenticated sessions to test for SQL Injection while logged in.
  * **Basic Usage Examples:**
    ```bash
    # Detect SQL Injection vulnerability and list databases from a specific URL
    sqlmap -u "http://target.com/page.php?id=1" --dbs

    # List tables within a specific database
    sqlmap -u "http://target.com/page.php?id=1" -D "mydb" --tables

    # Dump columns and data from a specific table
    sqlmap -u "http://target.com/page.php?id=1" -D "mydb" -T "users" --dump
    ```

#### **2. Auxiliary and Manual Verification Tools**

While automated tools like SQLmap are powerful, they cannot cover all scenarios, and manual verification of discovered vulnerabilities is essential.

  * **Web Proxy Tools (Burp Suite, OWASP ZAP):**
      * **Description:** Essential tools for intercepting and manipulating web traffic.
      * **Utility:**
          * **Manual Exploration and Initial Discovery:** Observe how parameters are processed during web application exploration to identify potential SQL Injection points.
          * **Request Manipulation (Repeater):** Repeatedly send specific requests and manually manipulate parameters to verify SQL Injection.
          * **Fuzzing (Intruder):** Automatically inject various payloads into specific parameters and observe responses to detect SQL Injection.
          * **Scanner:** Automated scanners in Burp Suite Pro or OWASP ZAP can automatically scan for various web vulnerabilities, including SQL Injection.
          * **Blind SQLi Response Analysis:** Useful for accurately recording and analyzing response times in time-based blind SQLi, and content/length changes in boolean-based SQLi.
  * **Custom Scripting (Python, etc.):**
      * **Description:** Used to write custom scripts for very specific or complex SQL Injection scenarios that off-the-shelf tools might not cover.
      * **Utility:**
          * **Implementing Advanced Bypass Techniques:** E.g., specific WAF bypasses, obfuscated SQLi, exploiting non-standard functions of particular databases.
          * **Workflow Integration:** Integrating SQL Injection detection and exploitation processes into larger automated penetration testing workflows.
          * **Library Examples:** Using Python's `requests` library for HTTP requests, `BeautifulSoup` for parsing HTML responses, and `re` (regular expression) library for extracting specific patterns from responses.

#### **Considerations for Automation**

Automated SQL Injection tools are very powerful, so always keep the following in mind when using them:

  * **Ethical Use:** These tools **must never be used on unauthorized systems.** Use them only against targets for which you have explicit permission.
  * **Understanding the Target System:** Before running automated tools, try to understand the target web application's and database's structure as much as possible. Incorrect usage can lead to service outages.
  * **Rate Limiting and Traffic:** Automated tools can send many requests very quickly. This can lead to Denial of Service (DoS) or get you blocked by WAFs. Adjust the request rate as needed.
  * **False Positives and False Negatives:** Automated tool results are not always 100% accurate. False positives (reporting a vulnerability that doesn't exist) or false negatives (failing to detect an existing vulnerability) can occur. Therefore, **manual verification of all findings** is crucial.

### **References**

  * [COMPUTER SECURITY: A Hands-on Approach by Wenliang Du](https://www.amazon.com/Computer-Security-Hands-Approach-Wenliang/dp/154836794X)

-----

## SQL Injection

### 서론

SQL Injection (SQLi)은 가장 오래되었지만 여전히 가장 위험한 웹 애플리케이션 취약점 중 하나입니다. SQLi의 핵심은 **데이터와 코드를 적절히 분리하지 못하는 근본적인 실패**에서 비롯됩니다.

  * 이러한 공격의 문제는 일반적으로 **신뢰할 수 없는 데이터(사용자로부터의 입력 데이터)**와 **신뢰할 수 있는 데이터(프로그램 로직)**가 혼합되면서, 원래는 분명했던 둘 사이의 경계선이 불분명해지는 지점에서 허점들이 생깁니다.
  * 두 번째로, 이렇게 혼합된 데이터가 파서(Parser)로 전달될 때, 특수 문자(Special Character)를 적절히 처리하지 않으면, 이 문자열이 데이터가 아닌 **코드로 해석되어 실행**되면서 문제가 발생합니다.
  * C와 같은 컴파일 언어에서는 컴파일 과정을 거치면서 코드와 데이터가 명확히 분리되기 때문에, 웹 애플리케이션에 비해 직접적인 코드 주입 공격이 더 어렵습니다. 하지만 C에서도 리턴 주소(Return Address)를 통해 데이터 영역으로 코드를 돌려 실행시킬 수 있는 **버퍼 오버플로우(Buffer Overflow, BOF)**와 같이 코드와 데이터가 섞여 발생하는 공격이 존재합니다.
  * 웹 애플리케이션은 인터프리터(Interpreter) 기반으로 동작하기 때문에, 코드를 동적으로(Dynamic) 생성할 수 있는 특성상 SQL Injection과 같은 주입 공격에 더욱 취약합니다.
  * GUI 기반의 웹 브라우저를 통한 수동 공격보다는 `curl`과 같은 명령줄 도구를 사용하여 공격을 시도하면 **자동화된 공격**을 더 쉽게 구현할 수 있습니다.
  * 공격을 시도하기 전에는, 먼저 **공격하려는 SQL 구문(Statement)을 해당 DB 프로그램(예: MySQL 클라이언트)에서 직접 실행**하여 문법적인 오류가 없는지 확인해야 합니다. 서버는 보안상 보통 자세한 에러 메시지를 반환하지 않기 때문에, 실제 공격 전에 문법적 정확성을 확인하는 것이 중요합니다.

### **MySQL 사용 예시 및 문제점**

SQL Injection이 어떻게 발생하는지 이해하기 위해 MySQL의 기본 SQL 구문을 살펴보겠습니다.

  * **일반적인 SELECT 구문:**

    ```sql
    SELECT Name, Salary, SSN
    FROM employee
    WHERE eid='EDI5002' and password='1234';
    ```

    이 쿼리는 `eid`가 'EDI5002'이고 `password`가 '1234'인 직원의 이름, 급여, SSN(주민등록번호)을 조회합니다. 여기서 `eid`와 `password`는 사용자로부터 입력받는 값입니다.

  * **일반적인 UPDATE 구문:**

    ```sql
    UPDATE employee
    SET password='paswd456', salary=100000
    WHERE eid='EID4000' and password='passwd123';
    ```

    이 구문은 `eid`가 'EID4000'이고 `password`가 'passwd123'인 직원의 비밀번호와 급여를 업데이트합니다.

  * **악의적인 입력이 포함된 예시 (SQL Injection 문제점 시연):**
    만약 사용자 입력값이 SQL 쿼리 문자열에 직접 연결될 때, 공격자가 `password` 필드에 `'1234'; DROP DATABASE dbtest;`와 같은 악의적인 문자열을 삽입한다면, 최종적으로 서버에서 실행될 쿼리는 다음과 같이 변형될 수 있습니다:

    ```sql
    SELECT Name, Salary, SSN
    FROM employee
    WHERE eid='EDI5002' and password='1234'; DROP DATABASE dbtest;
    ```

    이 경우, 데이터베이스는 `SELECT` 쿼리 실행 후 뒤따라오는 `DROP DATABASE dbtest;` 명령까지 실행하여 **데이터베이스 전체를 삭제**하는 치명적인 결과를 초래할 수 있습니다. 이는 사용자 입력(데이터)이 SQL 구문(코드)의 일부로 해석되어 실행되는 전형적인 SQL Injection의 문제입니다.

### **SQL Injection의 종류**

SQL Injection 공격은 데이터를 추출하거나 시스템에 영향을 미치는 방식에 따라 크게 몇 가지 유형으로 나눌 수 있습니다. 펜테스터는 이러한 유형별 특성을 이해하고 적절한 탐지 및 익스플로잇 기법을 적용해야 합니다.

#### **1. 인밴드 SQL Injection (In-band SQL Injection)**

공격자가 SQL Injection을 통해 데이터를 추출할 때, **데이터가 웹 애플리케이션의 일반적인 통신 채널(즉, 동일한 HTTP 응답)을 통해 반환되는 방식**입니다. 가장 흔하고 탐지하기 쉬운 유형입니다.

   * **유니온 기반 SQL Injection (UNION-based SQLi):**

      * **설명:** 공격자가 `UNION SELECT` 문을 사용하여 원래의 SQL 쿼리 결과에 악의적인 `SELECT` 쿼리 결과를 **결합하여 웹 페이지에 함께 출력**되도록 하는 방식입니다.
      * **작동 원리:** `UNION SELECT`는 두 `SELECT` 문의 컬럼 수와 데이터 타입이 일치해야 합니다. 공격자는 `ORDER BY` 절 등을 사용하여 원래 쿼리의 컬럼 수를 추측한 후, `UNION SELECT NULL, NULL, ...`과 같이 컬럼 수를 맞춥니다. 이후 원하는 데이터를 `UNION SELECT version(), database(), user()` 등과 같이 주입하여 웹 페이지에 출력되도록 합니다.
      * **탐지:** 쿼리 결과가 웹 페이지의 정상적인 콘텐츠에 추가되어 출력되는지 관찰합니다.
      * **영향:** 데이터베이스 내의 임의의 테이블로부터 데이터 추출, 데이터베이스 사용자 정보, 버전 정보 등 획득.
      * **펜테스팅:** `' ORDER BY 1--` 또는 `'UNION SELECT NULL,NULL--` 절을 이용한 컬럼 수 추측, `'UNION SELECT NULL,NULL--`를 이용한 데이터베이스 버전, 사용자, 데이터베이스 이름 등 정보 획득 시도.

  * **에러 기반 SQL Injection (Error-based SQLi):**

      * **설명:** 공격자가 의도적으로 SQL 구문 오류를 발생시켜, 데이터베이스가 반환하는 **상세한 에러 메시지**에 쿼리 결과나 데이터베이스 구조 등 민감한 정보가 포함되도록 유도하는 방식입니다.
      * **작동 원리:** `UPDATEXML()`, `EXTRACTVALUE()` (MySQL), `xp_cmdshell` (MSSQL)과 같이 에러를 발생시키면서 쿼리 결과를 삽입할 수 있는 특정 함수를 활용합니다.
      * **탐지:** 웹 페이지에 상세한 데이터베이스 에러 메시지가 노출되는지 확인합니다.
      * **영향:** 데이터베이스 정보 노출, 임의의 데이터 추출.
      * **펜테스팅:** 에러를 유발하는 일반적인 SQL 페이로드를 주입하여 응답에 포함된 에러 메시지를 분석합니다.

#### **2. 아웃오브밴드 SQL Injection (Out-of-band SQL Injection)**

공격자가 데이터를 웹 애플리케이션의 HTTP 응답 채널이 아닌, **다른 외부 채널(예: DNS 쿼리, HTTP 요청)을 통해 데이터베이스로부터 받아내는 방식**입니다. 웹 페이지에 직접적으로 에러나 데이터가 출력되지 않을 때 사용됩니다.

  * **설명:** 데이터베이스가 공격자가 제어하는 외부 시스템(예: 공격자의 웹 서버, DNS 서버)으로 데이터를 직접 전송하도록 강제합니다.
  * **작동 원리:** 데이터베이스 시스템의 특정 함수(예: Oracle의 `UTL_HTTP`, MySQL의 `LOAD_FILE`을 이용한 SMB/WebDAV 요청, MSSQL의 `xp_cmdshell`을 이용한 외부 연결)를 활용하여 외부 네트워크 요청을 보냅니다. 공격자는 자신의 서버 로그를 모니터링하여 데이터베이스로부터 전송된 정보를 확인합니다.
  * **탐지:** 외부 서버(DNS, HTTP)의 로그를 모니터링하여 데이터베이스로부터의 비정상적인 요청을 확인해야 합니다.
  * **영향:** 웹 페이지에 직접 데이터를 출력할 수 없는 상황에서도 임의의 데이터 추출이 가능해집니다.
  * **펜테스팅:** `ngrok`이나 `Burp Collaborator`와 같은 도구를 사용하여 외부 서버를 구축하고, 데이터베이스가 외부로 요청을 보내도록 유도하는 OOB 페이로드를 주입합니다.

#### **3. 추론 기반 SQL Injection (Inferential SQL Injection / Blind SQL Injection)**

**블라인드 SQL Injection**이라고도 불리며, 공격자가 데이터베이스로부터 직접적인 데이터를 반환받지 않고, **웹 애플리케이션의 응답(예: 페이지 내용 변화, 응답 시간)을 관찰하여 정보를 추론하는 방식**입니다. 매우 시간이 오래 걸리고 자동화된 도구(SQLmap 등)의 도움이 필수적입니다.

  * **불리언 기반 블라인드 SQL Injection (Boolean-based Blind SQLi):**

      * **설명:** 공격자가 참(True) 또는 거짓(False)을 반환하는 SQL 조건을 주입하고, 그 결과에 따라 웹 페이지의 내용이나 동작이 미묘하게 변화하는 것을 관찰하여 정보를 추론합니다.
      * **작동 원리:** `WHERE id='X' AND (SUBSTRING(password,1,1)='a')`와 같은 조건을 주입했을 때, 조건이 참이면 웹 페이지가 정상적으로 보이고, 거짓이면 에러 페이지가 나타나거나 내용이 달라지는 것을 관찰합니다. 이러한 변화를 통해 문자 하나하나를 추측합니다.
      * **탐지:** 웹 페이지의 콘텐츠 변화를 면밀히 관찰하거나, 응답 길이의 차이를 분석합니다.
      * **영향:** 직접적인 데이터 추출은 불가능하지만, 매우 느린 속도로 임의의 데이터 추출이 가능합니다.
      * **펜테스팅:** 특정 조건(예: 비밀번호의 첫 글자가 'a'인지)이 참일 때와 거짓일 때의 웹 페이지 응답을 분석하고, 자동화된 스크립트를 통해 모든 가능한 문자를 시도합니다.

  * **시간 기반 블라인드 SQL Injection (Time-based Blind SQLi):**

      * **설명:** 공격자가 참(True) 또는 거짓(False)을 반환하는 SQL 조건을 주입하고, 그 결과에 따라 데이터베이스가 **응답 시간을 지연시키도록 유도**하여 정보를 추론하는 방식입니다. 웹 페이지의 내용 변화조차 없을 때 사용되는 최후의 수단입니다.
      * **작동 원리:** `WHERE id='X' AND IF((SUBSTRING(password,1,1)='a'), SLEEP(5), 0)`와 같은 조건을 주입합니다. 만약 조건이 참이면 데이터베이스가 5초 동안 지연되어 응답이 늦어지고, 거짓이면 지연 없이 즉시 응답합니다. 이러한 시간 차이를 통해 문자 하나하나를 추측합니다.
      * **탐지:** 웹 애플리케이션의 응답 시간을 정확하게 측정하고 분석해야 합니다.
      * **영향:** 불리언 기반과 마찬가지로 임의의 데이터 추출이 가능하지만, 훨씬 더 느립니다.
      * **펜테스팅:** 자동화된 도구를 사용하여 수많은 요청을 보내고 각 요청의 응답 시간을 측정하여 정보를 추론합니다.

-----

### **SQL Injection 방어 및 완화 (Remediation & Mitigation)**

SQL Injection 공격을 효과적으로 방어하기 위해서는 단일 방어책에 의존하기보다, 여러 계층에 걸친 포괄적인 접근 방식이 필수적입니다.

#### **1. 핵심 방어 (가장 중요)**

  * **Prepared Statement (매개변수화된 쿼리):**

      * **원리:** 이것은 코드와 데이터를 완전히 분리하는 **가장 효과적이고 권장되는 방법**으로, SQL Injection을 근본적으로 방지합니다. SQL 구문(코드)은 먼저 데이터베이스 서버로 전송되어 컴파일되고, 사용자 입력(데이터)은 나중에 별도의 "데이터 채널"을 통해 바인딩됩니다. 데이터는 절대로 코드로 해석되지 않습니다.
      * **적용:** 모든 데이터베이스 쿼리에 Prepared Statement를 사용하도록 강제해야 합니다. 대부분의 프로그래밍 언어와 프레임워크는 이를 지원합니다.

  * **입력 유효성 검사 (Input Validation):**

      * **원리:** 사용자 입력을 애플리케이션에서 처리하기 전에, 예상하는 형식과 내용에 맞는지 검증하는 것입니다.
      * **적용:**
          * **화이트리스트(Whitelist) 방식:** 허용되는 문자, 숫자, 패턴, 길이 등을 명확히 정의하고, 그 외의 모든 입력을 거부합니다. (예: 이메일 주소는 이메일 형식만 허용, 숫자 필드는 숫자만 허용)
          * 데이터 타입 검증: 문자열이 아닌 숫자나 날짜 등으로 예상되는 입력은 해당 데이터 타입으로 엄격하게 검증합니다.
      * **효과:** 악의적인 데이터가 아예 데이터베이스 쿼리 구성 단계까지 도달하지 못하도록 막는 1차 방어선입니다.

  * **출력 인코딩/이스케이핑 (Output Encoding/Escaping):**

      * **원리:** 사용자 입력을 SQL 쿼리 문자열에 연결하기 전에, SQL 인터프리터가 코드로 해석할 수 있는 **모든 특수 문자를 인코딩(escaping)**해야 합니다.
      * **적용:** `NULL`, `\r`, `\n`, `\`, `'`, `"`, `%`, `_` 와 같은 문자를 데이터베이스 시스템에 맞게 이스케이프하는 API를 사용합니다.
      * **효과:** Prepared Statement를 사용할 수 없는 극히 드문 레거시 환경에서 보조적인 방어 수단으로 사용될 수 있지만, 완벽하지 않으므로 Prepared Statement가 항상 우선되어야 합니다.

#### **2. 보조 및 보강 방어 (방어 심층화)**

  * **최소 권한의 원칙 (Principle of Least Privilege):**

      * **적용:** 데이터베이스 사용자가 애플리케이션의 필요에 맞는 최소한의 권한만을 가지도록 구성해야 합니다. 예를 들어, 데이터 조회만 필요한 계정은 데이터 변경이나 삭제 권한을 가지지 않도록 합니다.
      * **효과:** SQL Injection이 발생하더라도, 공격자가 획득할 수 있는 권한과 피해 범위를 최소화합니다.

  * **강력한 에러 핸들링 (Robust Error Handling):**

      * **적용:** 운영 환경에서는 절대 상세한 데이터베이스 에러 메시지를 사용자에게 노출해서는 안 됩니다. 일반적인 에러 메시지(예: "서비스에 문제가 발생했습니다. 잠시 후 다시 시도해주세요.")를 반환하고, 상세한 에러 정보는 **백엔드 로그에만 기록**하여 공격자가 데이터베이스 구조나 취약점 정보를 얻지 못하도록 방지합니다.

  * **Web Application Firewall (WAF) 사용:**

      * **적용:** WAF는 SQL Injection과 같은 일반적인 웹 공격 패턴을 탐지하고 차단하는 데 도움이 됩니다. 이는 애플리케이션 계층 방어의 첫 번째 방어선 역할을 할 수 있습니다.
      * **효과:** 잘 알려진 공격 패턴을 대규모로 자동 차단하여, 애플리케이션 서버에 도달하는 악성 트래픽의 양을 줄입니다. 하지만 모든 공격(특히 정교한 우회 기법)을 막을 수는 없으므로 애플리케이션 코드 레벨의 방어와 반드시 병행해야 합니다.

  * **정기적인 보안 감사 및 펜테스팅:**

      * **적용:** 지속적인 코드 리뷰, SAST(Static Analysis Security Testing)/DAST(Dynamic Analysis Security Testing) 도구 활용, 그리고 정기적인 모의 침투 테스트를 통해 잠재적인 SQL Injection 취약점을 사전에 발견하고 수정해야 합니다.
      * **효과:** 새로운 취약점이나 우회 기법에 대한 방어를 지속적으로 업데이트하고, 개발 과정에서 발생할 수 있는 실수를 줄입니다.

  * **데이터베이스 보안 강화:**

      * **적용:** 데이터베이스 소프트웨어 자체를 최신 버전으로 패치하여 알려진 취약점을 제거하고, 불필요한 기능(예: 파일 시스템 접근을 허용하는 함수, 셸 명령 실행 함수)은 비활성화하거나 접근을 제한해야 합니다.
      * **효과:** 데이터베이스 시스템 자체의 보안 수준을 높여 공격자가 Injection 후에도 추가적인 피해를 입히기 어렵게 만듭니다.

-----

### **SQL 쿼리 특성 및 공통 우회/공격 기법 (재차 강조)**

위에서 설명한 다양한 SQL Injection 유형은 아래에서 설명하는 SQL 쿼리 특성 및 공통 공격/우회 기법들을 활용하여 실제 페이로드를 구성합니다.

  * SQL에서 대소문자는 구분하지 않는다.
  * `length(pw)=8`은 `pw`의 길이가 8인지 확인하는 구문이다. 블라인드 SQL Injection 시 활용될 수 있다.
  * `str_replace("admin",'',<something>)`은 `something` 부분에서 `admin`이 있다면 공백으로 바꾸고 남은 `<something>`을 표현하는 것이다. 필터링 우회 시 `adADMINmin` 등으로 활용될 수 있다.
  * 문자열을 ASCII로 바꾸는 함수는 `ascii(str)`이다. 블라인드 SQLi에서 문자를 추론할 때 활용된다.
  * `'` (작은따옴표)과 `"` (큰따옴표)은 MySQL과 같은 일부 DB에서 동일하게 문자열 리터럴을 감싸는 데 사용될 수 있다.
  * `WHERE` 구문 뒤에 여러 조건이 올 때, `' OR 1=1 --`와 같은 주입을 통해 뒤의 원래 조건을 무력화할 수 있다.
  * `LIKE ''` 구문 안에는 `%` (0개 이상의 문자)와 `_` (한 글자)가 와일드카드로 들어갈 수 있다. (예: `LIKE '%영'`, `LIKE '김%'`, `LIKE '김_수'`).
  * `[a-e]%`는 'a'부터 'e' 사이의 알파벳 중 하나로 시작하는 것을 의미하며, `[^a-e]%` 또는 `[!a-e]%`는 'a'부터 'e' 사이의 알파벳이 아닌 문자로 시작하는 것을 의미한다.

### **`=`과 동일한 기능의 연산자 (필터링 우회에 활용)**

  * `like` : `id = 'admin'` 대신 `id like 'admin'`을 사용할 수 있다. 와일드카드와 결합 시 더 많은 공격 기회를 제공한다.
  * `in` : `id = 'admin'` 대신 `id in ('admin')`을 사용할 수 있다. `in` 뒤에는 여러 개의 value가 쉼표(`,`)로 이어져서 올 수 있다.

### **주석 처리 (Comment Characters) 기법**

SQL Injection 공격에서 원래 쿼리의 나머지 부분을 무력화하는 데 사용됩니다.

  * `#` == `%23` (MySQL의 한 줄 주석)
  * ` --  ` (두 개의 하이픈 뒤에 공백): SQL 표준의 한 줄 주석
  * `/* */`: 여러 줄 주석

### **공백 문자 (Space Characters) 우회 기법**

공백이 필터링될 경우, 다른 형태로 공백을 대체하여 우회할 수 있습니다.

  * `SP` (Space, URL 인코딩: `%20`)
  * `\t` (탭, URL 인코딩: `%09`)
  * `\n` (줄 바꿈, Line Feed, URL 인코딩: `%0a`)
  * `VT` (Vertical Tab, URL 인코딩: `%0b`): 일부 환경에서 공백으로 인식
  * `FF` (Form Feed, URL 인코딩: `%0c`): 일부 환경에서 공백으로 인식
  * `\r` (캐리지 리턴, URL 인코딩: `%0d`)

### **논리 연산자 (Logical Operators) 우회 기법**

`AND`나 `OR`와 같은 논리 연산자가 필터링될 경우, 동등한 기호를 사용하여 우회할 수 있습니다.

  * `and` == `&&` (URL 인코딩: `%26%26`)
  * `or` == `||` (URL 인코딩: `%7c%7c`)

### **문자열 자르기 (Substring) 함수**

블라인드 SQL Injection 시 데이터베이스의 특정 문자열을 한 글자씩 추측하는 데 사용됩니다.

  * `substr()`, `substring()`, `mid()`: 데이터베이스 시스템에 따라 함수 이름이 다를 수 있습니다.
      * `substr(pw,2,1)='1'`은 `pw` 문자열의 두 번째 위치부터 1개의 문자를 잘라낸 값이 '1'인지 확인하는 구문입니다.

### **URL Encoding 관련 (이미지 참조)**

URL Encoding은 특수 문자나 비 ASCII 문자를 웹에서 안전하게 전송하기 위해 `%(퍼센트)`와 16진수 값으로 변환하는 과정입니다. SQL Injection 페이로드를 URL에 포함할 때 필수적으로 사용됩니다.

  * <img alt=" " src="/assets/images/url_encoding.png">

### **ASCII 코드 (이미지 참조)**

SQL Injection 공격, 특히 블라인드 SQL Injection에서 특정 문자를 추측할 때, 해당 문자의 ASCII 값을 활용하여 쿼리를 구성합니다.

  * <img alt=" " src="/assets/images/asciicode.jpg">

### **공격 예시 (SQL Injection Scenarios)**

이전에 언급된 기초 지식을 바탕으로 실제 SQL Injection 공격 시나리오를 살펴보겠습니다.

  * **Scenario \#1: 인증 우회 (Authentication Bypass)**

      * **입력:** `username=sadcowboy&password=' OR '1'='1`
      * **변형된 쿼리 (가정):** `SELECT * FROM users WHERE username = 'sadcowboy' AND password = '' OR '1'='1'`
      * **설명:** `password` 필드에 `' OR '1'='1`을 주입하여 `password = '1234'`와 같은 원래의 조건문을 `password = '' OR '1'='1'`으로 변경합니다. `OR '1'='1'` 부분은 항상 참(True)이 되므로, 원래의 `username` 조건이 참이라면 인증을 우회할 수 있습니다. `--`나 `#`을 사용하여 뒤따라오는 SQL 부분을 주석 처리할 수도 있습니다.
      * **결과:** 유효한 비밀번호 없이도 `sadcowboy` 계정으로 로그인될 가능성이 있습니다.

  * **Scenario \#2: 관리자 계정으로 로그인 및 추가 정보 추출 (Login as Admin & Data Extraction)**

      * **입력:** `name=' OR '1'='1-- &password=' OR '2'>'1`
      * **변형된 쿼리 (가정):** `SELECT * FROM users WHERE login = '' OR '1'='1' -- ' AND password ='' OR '2'>'1' LIMIT 1`
      * **설명:** `login` 필드에 ` ' OR '1'='1--  `를 주입합니다. `login = '' OR '1'='1'`은 항상 참이 되고, `--`는 그 뒤의 `AND password =''` 부분을 주석 처리하여 무효화합니다. `password` 필드에 주입된 `' OR '2'>'1'` 역시 항상 참이 됩니다. `LIMIT 1`은 데이터베이스에서 첫 번째로 발견되는 레코드 하나만 반환합니다.
      * **결과:** 이 공격은 데이터베이스에 있는 사용자 중 **첫 번째 유저(종종 관리자 계정일 가능성이 높음)**로 로그인이 가능하게 만들 수 있습니다. 성공적으로 로그인되면, 공격자는 관리자 권한을 획득하고 앱의 다른 취약점을 찾아 추가적인 공격(예: 데이터 추출, 권한 상승)을 시도할 수 있습니다.

SQL Injection은 복잡한 공격 패턴과 우회 기법이 존재하므로, `Prepared Statement`와 같은 근본적인 방어 메커니즘을 적용하고, 철저한 입력 유효성 검사 및 정기적인 펜테스팅을 통해 지속적으로 보안을 강화하는 것이 중요합니다.

### **SQL Injection 공격 자동화: 도구 및 기술**

SQL Injection 공격은 그 복잡성과 시간 소모성 때문에 대부분 자동화된 도구를 사용하여 수행됩니다. 특히 블라인드(Blind) SQL Injection이나 시간 기반(Time-based) SQL Injection과 같이 수많은 요청과 응답 분석이 필요한 경우 자동화는 필수적입니다.

#### **1. 주력 자동화 도구: SQLmap**

  * **설명:** SQLmap은 Python으로 작성된 오픈소스 침투 테스트 도구로, SQL Injection 취약점을 탐지하고 익스플로잇하는 데 특화되어 있습니다. 업계에서 SQL Injection 공격 자동화의 사실상 표준으로 인정받고 있습니다.
  * **주요 기능:**
      * **다양한 SQLi 유형 탐지 및 익스플로잇:** 에러 기반, 유니온 기반, 블라인드(불리언 기반, 시간 기반), 아웃오브밴드 등 거의 모든 유형의 SQL Injection을 자동으로 탐지하고 익스플로잇할 수 있습니다.
      * **데이터베이스 지문 인식 (Database Fingerprinting):** 타겟 웹 애플리케이션이 사용하는 데이터베이스 시스템(MySQL, PostgreSQL, Oracle, MSSQL 등)의 종류, 버전, OS 등을 자동으로 식별합니다.
      * **데이터 덤프:** 데이터베이스 내의 모든 데이터베이스, 테이블, 컬럼, 레코드 등을 덤프하여 추출할 수 있습니다. 특정 테이블이나 컬럼만 덤프하는 것도 가능합니다.
      * **파일 접근 및 OS 명령어 실행:** 일부 데이터베이스 시스템(예: MySQL의 `LOAD_FILE`, MSSQL의 `xp_cmdshell`)에서 허용하는 경우, 데이터베이스 서버의 로컬 파일을 읽거나, OS 명령어를 실행하여 서버를 제어할 수 있습니다.
      * **웹 방화벽(WAF) 우회:** 다양한 우회 기술(예: 인코딩, 난독화, 주석 활용, HTTP 헤더 조작)을 내장하여 WAF 탐지를 회피하려 시도합니다.
      * **세션 관리:** 인증된 세션을 활용하여 로그인된 상태에서 SQL Injection을 테스트할 수 있습니다.
  * **기본 사용법 예시:**
    ```bash
    # 특정 URL에서 SQL Injection 취약점 탐지 및 데이터베이스 목록 확인
    sqlmap -u "http://target.com/page.php?id=1" --dbs

    # 특정 데이터베이스 내의 테이블 목록 확인
    sqlmap -u "http://target.com/page.php?id=1" -D "mydb" --tables

    # 특정 테이블 내의 컬럼 및 데이터 덤프
    sqlmap -u "http://target.com/page.php?id=1" -D "mydb" -T "users" --dump
    ```

#### **2. 보조 및 수동 검증 도구**

SQLmap과 같은 자동화 도구는 강력하지만, 모든 상황을 커버할 수는 없으며, 발견된 취약점을 수동으로 검증하는 것이 필수적입니다.

  * **웹 프록시 도구 (Burp Suite, OWASP ZAP):**
      * **설명:** 웹 트래픽을 가로채고 조작하는 데 사용되는 필수적인 도구입니다.
      * **유용성:**
          * **수동 탐색 및 초기 발견:** 웹 애플리케이션을 탐색하면서 각 요청의 파라미터가 어떻게 처리되는지 관찰하여 SQL Injection의 잠재적인 지점을 식별합니다.
          * **요청 조작 (Repeater):** 특정 요청을 반복적으로 보내며 파라미터를 수동으로 조작하여 SQL Injection을 검증합니다.
          * **퍼징 (Intruder):** 특정 파라미터에 대해 다양한 페이로드(payload)를 자동으로 주입하며 응답을 관찰하여 SQL Injection을 자동화된 방식으로 탐지합니다.
          * **스캐너 (Scanner):** Burp Suite Pro나 OWASP ZAP의 자동화된 스캐너는 SQL Injection을 포함한 다양한 웹 취약점을 자동으로 스캔하여 보고합니다.
          * **블라인드 SQLi 응답 분석:** 시간 기반 블라인드 SQLi의 응답 시간, 불리언 기반 SQLi의 응답 길이/내용 변화를 정확하게 기록하고 분석하는 데 유용합니다.
  * **커스텀 스크립트 (Python 등):**
      * **설명:** SQLmap이나 다른 도구로 커버하기 어려운 매우 특정적이거나 복잡한 SQL Injection 시나리오를 위해 직접 스크립트를 작성합니다.
      * **유용성:**
          * **고급 우회 기법 구현:** 특정 WAF 우회, 난독화된 SQLi, 특정 데이터베이스의 비표준 함수 익스플로잇 등.
          * **워크플로우 통합:** SQL Injection 탐지 및 익스플로잇 과정을 더 큰 자동화된 펜테스팅 워크플로우에 통합할 때 사용됩니다.
          * **라이브러리 예시:** Python의 `requests` 라이브러리로 HTTP 요청을 보내고, `BeautifulSoup`으로 HTML 응답을 파싱하며, `re` (정규 표현식) 라이브러리로 응답에서 특정 패턴을 추출하는 방식입니다.

### **참고 자료**

  * [COMPUTER SECURITY: A Hands-on Approach by Wenliang Du](https://www.amazon.com/Computer-Security-Hands-Approach-Wenliang/dp/154836794X)