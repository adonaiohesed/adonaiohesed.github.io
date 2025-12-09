---
title: Secure Code Review
tags: Static-Analysis Cybersecurity
key: page-secure_code_review
categories: [Cybersecurity, Web Security]
author: hyoeun
math: true
mathjax_autoNumber: true
---

## Secure Code Review: Reading Code Through an Attacker's Eyes in JavaScript and Node.js

While a typical code review focuses on functional correctness and code quality, a **Secure Code Review** goes a step further, concentrating on identifying and eliminating potential attack vectors and security vulnerabilities. In a dynamic and asynchronous environment like JavaScript and Node.js, a developer's small mistake can lead to a critical security flaw. Although Static Application Security Testing (SAST) tools can report numerous potential issues, they often miss design-level flaws hidden in complex business logic or subtle, context-based vulnerabilities that can only be found by the sharp eye of a skilled security professional.

This article, written from the perspective of a senior security professional, covers practical methodologies for strengthening a system's defenses through code review, complete with specific examples.

### The Mindset for a Secure Code Review

An effective security review doesn't start with aimlessly reading code. Its effectiveness is maximized when approached with clear goals and a defined strategy.

  * **Clarify Review Objectives**: Instead of trying to review the entire codebase at once, it's more effective to set specific goals, such as "Review user authentication and session management logic" or "Analyze all API endpoints that handle external input." Focusing on a specific area allows for a deeper analysis.

  * **Set Time Limits and Scope**: A review can go on endlessly. Therefore, it's crucial to set a time limit, such as "I will review the access control logic for this specific module for two hours." This helps maintain focus and ensures meaningful results are achieved within a set timeframe.

  * **Focus Solely on Security**: During a review, you might notice various areas for improvement related to performance, readability, or functional bugs. However, the sole purpose of a secure code review is to **find security vulnerabilities**. Defer other issues to separate review sessions and maintain a strict focus on security.

  * **Understand the Application Architecture**: If code is the trees, then architecture is the forest. For an effective review, at least one reviewer must understand the system's overall structure, including its data flow, component architecture, and trust boundaries. Without understanding the architecture, you might find individual code-level vulnerabilities but miss critical design flaws.

  * **Continuously Improve Your Checklist**: It’s good practice to start a review with a basic questionnaire, asking questions like, "Is this code vulnerable to a buffer overflow attack?" or "Is sensitive data accessed or transmitted without encryption?" As you conduct reviews, you should continuously add new types of vulnerabilities and mistakes to this checklist, creating your own powerful review standard over time.

### Security Code Review Techniques: A Systematic Approach

A phased approach that combines automated and manual analysis is recommended for an efficient review.

#### Phase 1: Automated Scan

Using automated scanning tools like SAST (Static Application Security Testing) is a very useful first step.

  * **Purpose**: Automated tools can quickly find well-known patterns of vulnerabilities like SQL Injection and Cross-Site Scripting (XSS). This filters out the low-hanging fruit, allowing the human reviewer to focus on more complex and subtle logical flaws during the manual review phase.
  * **Limitations**: Automated tools do not understand the complex context of business logic and therefore fail to detect most design-level flaws or authorization-related vulnerabilities. Thus, you should not blindly trust the tool's results but use them as a supplement to the manual review.

#### Phase 2: Manual Scan

After the automated scan is complete, begin the manual analysis, diving deep into key areas of the code from an attacker's perspective.

  * **Input Validation**: Does the application have a consistent input validation architecture? Is validation performed on the client, on the server, or both? Is there a centralized validation mechanism, or are validation routines spread throughout the codebase?
  * **Authentication and Authorization**: How does the application authenticate users? What user roles exist, and how are their permissions managed? Is there custom-written authentication or authorization code?
  * **Error Handling**: Is there a consistent error-handling architecture? Does the system catch and throw structured exceptions? Are there areas of the code with especially dense or sparse error handling? Does the application expose sensitive system details in its error messages?
  * **Code Complexity**: Are there areas of the code that appear especially complex? Complicated code is where developers are prone to making unintentional mistakes, making it a breeding ground for potential vulnerabilities.
  * **Cryptography**: Does the application use cryptography? Does it use weak, outdated algorithms (e.g., MD5, SHA1), hardcode cryptographic keys, or use flawed, custom-built cryptographic logic?
  * **Interop**: Does the Node.js application call into native code, such as C++ addons? This boundary is where classic native code vulnerabilities, like memory management errors or buffer overflows, can occur.

### Reviewing Vulnerabilities Based on Attack Scenarios

An effective security review goes beyond simply checking off a list of vulnerabilities; it's a process of constantly asking, "If I were an attacker, how would I exploit this code?"

#### 1. Entry Points: The Beginning of All Evil

All data entering the system is a potential attack vector. Identify all entry points, including HTTP request parameters, headers, cookies, and file uploads, and check the following.

  * **SQL Injection**: Are database queries being dynamically constructed with external input? Confirm that parameterized queries from libraries like `node-postgres` (pg) or `mysql2` are used consistently.

      * **Vulnerable Example (Node.js/Express)**:

        ```javascript
        // const { Pool } = require('pg');
        // const pool = new Pool();

        app.get('/users', async (req, res) => {
          const { id } = req.query;
          // This is vulnerable to SQL Injection as input is directly inserted into the query string.
          const query = `SELECT * FROM users WHERE id = '${id}'`;
          try {
            const result = await pool.query(query);
            res.json(result.rows);
          } catch (err) {
            res.status(500).send('Server Error');
          }
        });
        ```

      * **Secure Example (Parameterized Query)**:

        ```javascript
        app.get('/users', async (req, res) => {
          const { id } = req.query;
          // By separating the query template and values, we prevent SQL Injection.
          const query = 'SELECT * FROM users WHERE id = $1';
          try {
            const result = await pool.query(query, [id]);
            res.json(result.rows);
          } catch (err) {
            res.status(500).send('Server Error');
          }
        });
        ```

  * **Command Injection**: If the application executes shell commands using user input, you must use functions like `execFile` or `spawn` to clearly separate arguments, instead of string-based functions like `child_process.exec`.

      * **Vulnerable Example**:

        ```javascript
        // const { exec } = require('child_process');

        app.get('/api/dns-lookup', (req, res) => {
            const { host } = req.query;
            // A user could provide malicious input like "example.com; rm -rf /"
            exec(`nslookup ${host}`, (error, stdout, stderr) => {
                res.send(`<pre>${stdout}</pre>`);
            });
        });
        ```

      * **Secure Example**:

        ```javascript
        // const { execFile } = require('child_process');

        app.get('/api/dns-lookup', (req, res) => {
            const { host } = req.query;
            // The command and arguments are separated, preventing shell interpretation.
            execFile('nslookup', [host], (error, stdout, stderr) => {
                res.send(`<pre>${stdout}</pre>`);
            });
        });
        ```

  * **Path Traversal**: When constructing file system paths from user input, an attacker can use characters like `../../` to access files in unintended parent directories. Always use `path.normalize` and `path.join`, and verify that the final path is within the intended base directory.

#### 2. Processing Logic: Flaws in Permissions and Logic

  * **Broken Access Control / IDOR**: This occurs when the application correctly verifies that a user is authenticated but fails to verify that they are **authorized** to access the specific object they have requested.

      * **Vulnerable Example (IDOR)**:

        ```javascript
        // Assume user authentication (req.user) is completed by middleware.
        app.get('/invoices/:invoiceId', async (req, res) => {
          const { invoiceId } = req.params;
          // The code does not check if the logged-in user has permission to access this invoiceId.
          const invoice = await Invoice.findById(invoiceId);
          res.json(invoice);
        });
        ```

      * **Secure Example (Authorization Check)**:

        ```javascript
        app.get('/invoices/:invoiceId', async (req, res) => {
          const { invoiceId } = req.params;
          const invoice = await Invoice.findById(invoiceId);

          // Add an authorization check to verify the current user owns the invoice.
          if (!invoice || invoice.ownerId !== req.user.id) {
            return res.status(404).send('Not Found'); // Or 403 Forbidden
          }
          res.json(invoice);
        });
        ```

#### 3. Data Storage and Output: Preventing Information Disclosure

  * **Cross-Site Scripting (XSS)**: When outputting data from a database or external source to a web page, you must apply proper output encoding for the given context. Modern frameworks like React, Vue, and Angular provide auto-encoding by default, but you must carefully review any use of functions that intentionally bypass it, like `dangerouslySetInnerHTML`.

      * **Vulnerable Example (EJS Template)**:

        ````html
        <p>Search Results: <%- searchTerm %></p> ```
        ```javascript
        app.get('/search', (req, res) => {
            // If a user enters <script>alert(1)</script>, the script will execute.
            res.render('search_results', { searchTerm: req.query.q });
        });
        ````

      * **Secure Example (EJS Template)**:

        ````html
        <p>Search Results: <%= searchTerm %></p> ```

        ````

  * **Sensitive Data Exposure**: Check whether sensitive information like passwords, API keys, or personal data is being stored in plaintext or written to logs. The habit of logging entire objects can be especially dangerous.

      * **Vulnerable Example**:

        ```javascript
        const user = await User.findById(id);
        // The user object might contain sensitive data like a passwordHash or PII.
        console.log(`User object for ID ${id}:`, user);
        ```

      * **Secure Example**:

        ```javascript
        const user = await User.findById(id);
        // Create a sanitized object for logging that only contains safe information.
        const sanitizedUser = { id: user.id, username: user.username, email: user.email };
        console.log(`User object for ID ${id}:`, sanitizedUser);
        ```

### Beyond Tools: The Role of Intuition

The true value of a secure code review lies in finding what automated tools miss. Understanding the overall system architecture, grasping how each component interacts, and discovering potential logical flaws hidden behind a developer's intent are tasks that can only be accomplished through the intuition and experience of a skilled professional. Therefore, a code review should be approached not as a simple act of following a checklist, but as a creative process of building the system's defenses.

---

## Secure Code Review: JavaScript와 Node.js 환경에서 공격자의 시선으로 코드 읽기

일반적인 코드 리뷰가 기능의 정확성과 코드의 품질에 초점을 맞춘다면, **보안 코드 리뷰(Secure Code Review)**는 한 걸음 더 나아가 잠재적인 공격 벡터와 보안 취약점을 식별하고 제거하는 데 집중합니다. 특히 동적이고 비동기적인 특성을 가진 JavaScript와 Node.js 환경에서는 개발자의 작은 실수가 치명적인 보안 허점으로 이어질 수 있습니다. 정적 분석 도구(SAST)가 수많은 잠재적 이슈를 보고할 수 있지만, 복잡한 비즈니스 로직에 숨어있는 설계 결함이나 미묘한 컨텍스트 기반의 취약점은 숙련된 보안 전문가의 날카로운 시선을 통해서만 발견될 수 있습니다.

이 글은 시니어 보안 전문가의 관점에서, 코드 리뷰를 통해 시스템의 방어벽을 견고히 구축하는 실질적인 방법론을 구체적인 예시와 함께 다룹니다.

### 보안 코드 리뷰를 위한 준비 자세

효과적인 보안 리뷰는 무작정 코드를 읽는 것에서 시작되지 않습니다. 명확한 목표와 전략을 가지고 접근할 때 그 효과가 극대화됩니다.

  * **리뷰 목표의 명확화**: 전체 코드를 한 번에 보려고 하기보다 "사용자 인증 및 세션 관리 로직 검토", "외부 입력값을 처리하는 모든 API 엔드포인트 분석"과 같이 구체적인 목표를 설정하는 것이 효과적입니다. 특정 영역에 초점을 맞추면 더 깊이 있는 분석이 가능합니다.

  * **시간 관리 및 범위 설정**: 리뷰는 끝없이 이어질 수 있습니다. 따라서 "2시간 동안 특정 모듈의 접근 제어 로직을 리뷰한다"와 같이 시간을 정해두고 시작하는 것이 중요합니다. 이는 집중력을 유지하고, 정해진 시간 내에 의미 있는 결과를 도출하는 데 도움이 됩니다.

  * **보안 관점에만 집중**: 코드 리뷰 중에는 성능, 가독성, 기능적 오류 등 다양한 개선점이 보일 수 있습니다. 하지만 보안 코드 리뷰의 목적은 오직 **보안 취약점을 찾는 것**입니다. 다른 문제들은 별도의 리뷰 세션으로 넘기고, 현재 리뷰에서는 보안의 관점을 벗어나지 않도록 집중해야 합니다.

  * **아키텍처에 대한 이해**: 코드를 나무라고 한다면, 아키텍처는 숲입니다. 효과적인 리뷰를 위해서는 최소 한 명의 리뷰어는 데이터 흐름(Dataflow), 컴포넌트 아키텍처, 신뢰 경계(Trust Boundary) 등 시스템의 전체적인 구조를 이해하고 있어야 합니다. 아키텍처를 모르면 개별 코드의 취약성은 발견할 수 있어도, 설계상의 중대한 결함은 놓치기 쉽습니다.

  * **지속적인 체크리스트 개선**: 리뷰를 시작하기 전에 "이 코드는 버퍼 오버플로우 공격에 취약한가?", "중요한 자료가 암호화되지 않은 채로 전송되거나 저장되지는 않는가?"와 같은 기본적인 질문지를 준비하면 좋습니다. 그리고 리뷰를 진행하면서 발견한 새로운 유형의 취약점이나 실수들을 이 체크리스트에 지속적으로 추가하고 업데이트하여 자신만의 강력한 리뷰 표준을 만들어나가야 합니다.

### 보안 코드 리뷰 기법: 체계적인 접근법

효율적인 리뷰를 위해 자동화된 분석과 수동 분석을 결합하는 단계적 접근이 권장됩니다.

#### 1단계: 자동화된 스캔 (Automatic Scan)

SAST(Static Application Security Testing)와 같은 자동화된 스캔 도구를 사용하는 것은 리뷰의 첫 단계로 매우 유용합니다.

  * **목적**: 자동화된 도구는 SQL 인젝션, 크로스 사이트 스크립팅(XSS) 등 잘 알려진 패턴의 취약점을 빠르게 찾아냅니다. 이를 통해 수동 리뷰 단계에서 사람이 직접 찾아야 할 기본적인 취약점들을 걸러내고, 리뷰어는 더 복잡하고 미묘한 논리적 결함에 집중할 수 있습니다.
  * **한계**: 자동화된 도구는 비즈니스 로직의 복잡한 맥락을 이해하지 못하므로, 설계상의 결함이나 접근 통제(Authorization)와 관련된 취약점은 대부분 탐지하지 못합니다. 따라서 도구의 결과를 맹신해서는 안 되며, 수동 리뷰를 보조하는 수단으로 활용해야 합니다.

#### 2단계: 수동 스캔 (Manual Scan)

자동화된 스캔이 끝난 후, 공격자의 시선으로 코드의 핵심 영역을 집중적으로 파고드는 수동 분석을 시작합니다.

  * **입력 유효성 검사 (Input Validation)**: 애플리케이션에 일관된 입력값 검증 아키텍처가 존재하는가? 검증은 클라이언트에서만 이루어지는가, 아니면 서버 측에서도 수행되는가? 중앙화된 검증 메커니즘이 있는가, 아니면 검증 로직이 코드베이스 전체에 흩어져 있는가?
  * **인증 및 인가 (Authentication and Authorization)**: 애플리케이션의 인증 방식은 무엇인가? 어떤 사용자 역할이 존재하며, 역할별 권한은 어떻게 관리되는가? 직접 구현한 커스텀 인증/인가 코드가 있는가?
  * **에러 처리 (Error Handling)**: 일관된 에러 처리 아키텍처가 있는가? 시스템이 구조화된 예외(Exception)를 발생시키고 처리하는가? 특정 부분에 에러 처리 로직이 지나치게 많거나 부족하지는 않은가? 상세한 시스템 정보가 에러 메시지를 통해 외부에 노출되지는 않는가?
  * **코드 복잡도 (Code Complexity)**: 유독 이해하기 어렵고 복잡한 코드가 있는가? 복잡한 코드는 개발자가 의도치 않은 실수를 저지르기 쉬운 곳이며, 잠재적 취약점의 온상이 될 수 있다.
  * **암호화 (Cryptography)**: 애플리케이션이 암호화 로직을 사용하는가? 안전하지 않은 오래된 알고리즘(예: MD5, SHA1)을 사용하거나, 암호화 키를 하드코딩하거나, 직접 구현한 불완전한 암호화 로직을 사용하지는 않는가?
  * **네이티브 코드 연동 (Interop)**: Node.js 애플리케이션이 C++ 애드온과 같이 네이티브 코드를 호출하는 부분이 있는가? 이 경계에서는 메모리 관리 오류나 버퍼 오버플로우와 같은 네이티브 코드의 고전적인 취약점이 발생할 수 있다.

### 공격 시나리오 기반의 취약점 검토

효과적인 보안 리뷰는 단순히 취약점 목록을 확인하는 것을 넘어, "내가 공격자라면 이 코드를 어떻게 악용할까?"라는 질문을 끊임없이 던지는 과정입니다.

#### 1. 입력 지점: 모든 악의 시작

시스템으로 들어오는 모든 데이터는 잠재적인 공격 벡터입니다. HTTP 요청 파라미터, 헤더, 쿠키, 파일 업로드 등 모든 입력 지점을 식별하고 다음을 확인해야 합니다.

  * **SQL 주입 공격 (SQL Injection)**: 데이터베이스 쿼리가 외부 입력값으로 동적으로 생성되고 있습니까? `node-postgres` (pg)나 `mysql2`와 같은 라이브러리의 파라미터화된 쿼리(Parameterized Queries) 기능을 일관되게 사용하고 있는지 확인합니다.

      * **취약한 예시 (Node.js/Express)**:

        ```javascript
        // const { Pool } = require('pg');
        // const pool = new Pool();

        app.get('/users', async (req, res) => {
          const { id } = req.query;
          // 입력값을 검증 없이 쿼리문에 직접 삽입하여 SQL Injection에 취약
          const query = `SELECT * FROM users WHERE id = '${id}'`;
          try {
            const result = await pool.query(query);
            res.json(result.rows);
          } catch (err) {
            res.status(500).send('Server Error');
          }
        });
        ```

      * **안전한 예시 (파라미터화된 쿼리)**:

        ```javascript
        app.get('/users', async (req, res) => {
          const { id } = req.query;
          // 쿼리 템플릿과 값을 분리하여 SQL Injection을 원천적으로 방지
          const query = 'SELECT * FROM users WHERE id = $1';
          try {
            const result = await pool.query(query, [id]);
            res.json(result.rows);
          } catch (err) {
            res.status(500).send('Server Error');
          }
        });
        ```

  * **명령어 주입 공격 (Command Injection)**: 사용자 입력을 받아 서버에서 셸 명령어를 실행하는 기능이 있다면, `child_process.exec`와 같이 문자열 기반의 함수 대신 `execFile`이나 `spawn`을 사용하여 인자를 명확히 분리해야 합니다.

      * **취약한 예시**:

        ```javascript
        // const { exec } = require('child_process');

        app.get('/api/dns-lookup', (req, res) => {
            const { host } = req.query;
            // 사용자가 "example.com; rm -rf /"와 같은 악의적인 입력을 할 수 있음
            exec(`nslookup ${host}`, (error, stdout, stderr) => {
                res.send(`<pre>${stdout}</pre>`);
            });
        });
        ```

      * **안전한 예시**:

        ```javascript
        // const { execFile } = require('child_process');

        app.get('/api/dns-lookup', (req, res) => {
            const { host } = req.query;
            // 명령어와 인자를 명확히 분리하여 셸 해석을 방지
            execFile('nslookup', [host], (error, stdout, stderr) => {
                res.send(`<pre>${stdout}</pre>`);
            });
        });
        ```

  * **경로 조작 (Path Traversal)**: 사용자 입력으로 파일 시스템 경로를 구성할 때, `../../`와 같은 문자를 사용하여 의도치 않은 상위 디렉터리의 파일에 접근할 수 있습니다. `path.normalize`와 `path.join`을 사용하고, 최종 경로가 허용된 기본 디렉터리 내에 있는지 반드시 확인해야 합니다.

#### 2. 처리 로직: 권한과 논리의 허점

  * **접근 통제 실패 (Broken Access Control / IDOR)**: 사용자가 특정 객체나 기능에 접근할 때, 단순히 인증 여부만 확인하고 해당 객체에 대한 **소유권**이나 **권한**을 확인하지 않는 경우입니다.

      * **취약한 예시 (IDOR)**:

        ```javascript
        // 미들웨어에서 사용자 인증(req.user)은 완료되었다고 가정
        app.get('/invoices/:invoiceId', async (req, res) => {
          const { invoiceId } = req.params;
          // 현재 로그인한 사용자가 이 invoiceId에 접근할 권한이 있는지 확인하지 않음
          const invoice = await Invoice.findById(invoiceId);
          res.json(invoice);
        });
        ```

      * **안전한 예시 (권한 확인)**:

        ```javascript
        app.get('/invoices/:invoiceId', async (req, res) => {
          const { invoiceId } = req.params;
          const invoice = await Invoice.findById(invoiceId);

          // 현재 사용자(req.user.id)가 송장의 소유자인지 확인하는 인가 로직 추가
          if (!invoice || invoice.ownerId !== req.user.id) {
            return res.status(404).send('Not Found'); // 혹은 403 Forbidden
          }
          res.json(invoice);
        });
        ```

#### 3. 데이터 저장 및 출력: 정보 노출 방어

  * **크로스 사이트 스크립팅 (XSS)**: 데이터베이스나 외부 소스에서 온 데이터를 웹 페이지에 출력할 때, 적절한 컨텍스트에 맞는 출력 인코딩(Output Encoding)을 적용해야 합니다. React, Vue, Angular와 같은 최신 프레임워크는 대부분 자동 인코딩을 지원하지만, `dangerouslySetInnerHTML`과 같이 이를 의도적으로 우회하는 기능의 사용을 주의 깊게 봐야 합니다.

      * **취약한 예시 (EJS 템플릿)**:

        ````html
        <p>검색 결과: <%- searchTerm %></p> ```
        ```javascript
        app.get('/search', (req, res) => {
            // 사용자가 <script>alert(1)</script>를 입력하면 스크립트가 실행됨
            res.render('search_results', { searchTerm: req.query.q });
        });
        ````

      * **안전한 예시 (EJS 템플릿)**:

        ````html
        <p>검색 결과: <%= searchTerm %></p> ```

        ````

  * **민감 정보 노출 (Sensitive Data Exposure)**: 비밀번호, API 키, 개인정보 등이 평문으로 로그에 기록되는지 확인합니다. 특히 객체 전체를 로깅하는 습관은 위험할 수 있습니다.

      * **취약한 예시**:

        ```javascript
        const user = await User.findById(id);
        // user 객체에는 passwordHash, ssn 등 민감 정보가 포함될 수 있음
        console.log(`User object for ID ${id}:`, user);
        ```

      * **안전한 예시**:

        ```javascript
        const user = await User.findById(id);
        const sanitizedUser = { id: user.id, username: user.username, email: user.email };
        // 로깅을 위해 필요한 정보만 담은 안전한 객체를 생성하여 출력
        console.log(`User object for ID ${id}:`, sanitizedUser);
        ```

### 도구를 넘어선 직관의 영역

보안 코드 리뷰의 진정한 가치는 자동화된 도구가 놓치는 부분을 찾아내는 데 있습니다. 시스템의 전체적인 아키텍처를 이해하고, 각 컴포넌트가 어떻게 상호작용하는지 파악하며, 개발자의 의도 뒤에 숨겨진 잠재적 논리 오류를 발견하는 것은 오직 숙련된 전문가의 직관과 경험을 통해서만 가능합니다. 따라서 코드 리뷰는 단순히 체크리스트를 따르는 행위가 아니라, 시스템의 방어 체계를 구축하는 창의적인 과정으로 접근해야 합니다.