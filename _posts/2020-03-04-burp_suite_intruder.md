---
title: Brup Suite - Intruder
tags: Burp-Suite
key: page-burp_suite_intruder
categories: [Tools, Exploitation]
author: hyoeun
math: true
mathjax_autoNumber: true
---

# Burp Intruder

## Strategic Selection of Attack Types and Payload Positioning

Intruder's efficiency starts with the accurate mapping of the Attack Position and Attack Type. When dealing with complex parameter combinations, you must accurately understand the behavior mechanism of each type.

## Intruder Workflow and Configuration

The basic workflow begins by capturing a request in the Proxy or Repeater and sending it to Intruder (Send to Intruder, shortcut `Ctrl+I`).

### Positions Tab: Setting Attack Points

The first task is to designate the position where the parameter to be modified, or the payload, will be injected. Burp selects all parameter values by default, but for precise testing, you should press the `Clear §` button to initialize, then drag only the specific parts you want to test and mark them with `Add §`.

![](assets/images/burp_intruder_type.png)

#### Sniper

Uses a single payload set and tests one position at a time.

  * **Mechanism**: When positions A and B are designated, it first sequentially substitutes payloads into A while keeping B at its original value. Once testing for A is complete, it restores A to its original value and substitutes payloads into B.
  * **Scenario**: Identifying which parameter is vulnerable to SQL Injection in a form with 5 parameters. Intruder tests the first parameter while maintaining the original values for the rest, then moves to the second parameter.
  * **Application**: Suitable for individually isolating and testing which of several parameters is vulnerable.

#### Battering ram

Uses a single payload set but injects the same value into all positions simultaneously.

  * **Mechanism**: Payload 'X' is inserted into positions A and B simultaneously, and the request is sent.
  * **Scenario**: When a User ID must exist in both the URL path and the POST Body XML data simultaneously, and the logic proceeds only if the two values match.
  * **Application**: Useful for testing integrity verification logic where the same value must be included in the HTTP request header and body, or when an identifier is distributed across multiple locations.

#### Pitchfork

Uses multiple payload sets and iterates through each set in parallel.

  * **Mechanism**: Payload Set 1 is assigned to position A, and Payload Set 2 is assigned to position B. The first value of Set 1 is combined with the first value of Set 2 for the request. (1:1 mapping)
  * **Scenario**: Performing Credential Stuffing using an obtained `username:password` dump list. Since Password A only needs to be tried for User A, unnecessary combinations can be reduced.
  * **Application**: Used when there is a clear correlation between data (e.g., an ID and the correct token pair for that ID).

#### Cluster bomb

Attempts all combinations (Cartesian Product) of multiple payload sets.

  * **Mechanism**: For the first value of Payload Set 1, all values of Payload Set 2 are substituted sequentially. Then, it moves to the next value of Set 1.
  * **Scenario**: Attempting Brute Force using a list of User IDs and a common password dictionary file when the administrator account password is unknown. (Try all passwords for User A, try all passwords for User B...)
  * **Application**: Used when an exhaustive search of all input possibilities for form data is required. Note that the number of requests increases exponentially, so care must be taken with range settings.

### Correlation Between Payload Sets and Attack Types

The Payload Sets section at the top of the Payloads tab is closely linked to the Attack Type set in the Positions tab. You must accurately understand this structure to design complex attack scenarios involving multiple variables.

  * **Activation of Payload Sets**: The number of active Sets is determined by the number of markers (`§`) designated in the Positions tab and the selected Attack Type. For example, if `Pitchfork` or `Cluster bomb` is selected and two parameters are marked, the Payload Sets are divided into 1 and 2, and each must be configured independently.
  * **Independent Configuration per Set**: Different Payload types can be applied to each Set. For instance, a hybrid configuration is possible where the first Set (Username) is set to `Simple list` and the second Set (Password) is set to `Runtime file` for large-scale processing.

### Key Payload Types and Advanced Usage Strategies

Burp offers various Payload Types, and selecting the appropriate type for the situation determines the efficiency of the test.

#### Simple list and Runtime file

While most basic, there is a significant difference in terms of memory management.

  * **Simple list**: Used when pasting values directly into the text box or loading relatively small dictionary files. All items are loaded into memory.
  * **Runtime file**: Essential when using huge dictionary files (e.g., the entire rockyou.txt) exceeding hundreds of megabytes. Burp does not load the entire file into memory but reads it line by line in a streaming manner at runtime, preventing Out Of Memory (OOM) issues during large-scale brute forcing.

#### Custom iterator

Powerful when you need to combine multiple string sets to create a single sophisticated payload. You can create complex string combinations even while using a single Position (Sniper mode, etc.).

  * **Structure**: Create virtual slots like Position 1, 2, 3..., and assign separate lists to each slot. Then, specify the Separator that goes between each slot.
  * **Usage Example**: Useful when combining [Filename List] + [Separator] + [Extension List] to test for `admin.bak`, `admin_old`, etc. This allows for a combination effect similar to Cluster bomb while maintaining easier request management.

#### Recursive grep

A method that extracts specific data from a previous response and uses it immediately as the payload for the next request.

  * **Core Use**: Essential when Anti-CSRF tokens are renewed with every request or when testing multi-step authentication flows.
  * **Constraints**: Since the result of the preceding request becomes the input for the succeeding request, concurrency is not possible. You must strictly set it to **single thread (Maximum concurrent requests: 1 in Resource Pool)** for it to work correctly. The 'Grep - Extract' setting in the Options tab must be configured beforehand to activate this.

#### Null payloads

Generates empty values instead of actual payloads to repeat requests.

  * **Core Use**:
      * When sending the same request simultaneously to identify Race Condition vulnerabilities.
      * When exploiting loopholes in business logic, such as manipulating view counts or vote counts.
      * You can specify the number of repetitions via the **Generate payload count** option or set **Continue indefinitely** for an infinite loop.

#### Character frobber & Bit flipper

Systematically modifies specific characters or bits of the input value.

  * **Usage Example**: Useful when analyzing encrypted session tokens or serialized data. Used to diagnose cryptographic vulnerabilities like CBC Bit Flipping by observing whether the application returns a decryption error or authenticates as a different user when specific bytes of the token are changed.

### Payload Processing: WAF Bypass and Data Refinement

Simple list substitution has a high probability of being blocked by WAFs or application input validation logic. The 'Payload Processing' section defines transformation rules to be applied immediately before the payload is transmitted. Rules are applied sequentially in the set order (Top-down).

  * **Add prefix / Add suffix**: Automatically appends `'`, `)`, ` --  `, etc., to the front or back of the payload during SQL Injection attacks. This allows you to complete the query syntax without modifying the original dictionary file.
  * **Encode / Decode**: Converts specific special characters to Base64, URL encoding, Hex, etc. For example, if a WAF blocks the `<script>` keyword, you can automate bypass attempts by encoding it in Base64.
  * **Hash**: Hashes the payload using MD5, SHA256, etc., before transmission. Used when testing logic where passwords are hashed on the client side, allowing you to use a plaintext dictionary but convert it to hash values right before sending.
  * **Invoke Burp extension**: Calls Python or Java extensions written by the user when complex logic not solvable by default rules (e.g., custom encryption, digital signature generation) is required.

### Payload Encoding Considerations

The 'Payload Encoding' section located at the bottom of the Payloads tab is enabled by default and automatically URL-encodes characters that have special functions in URLs (`&`, `=`, `?`, spaces, etc.).

  * **Default Behavior**: Characters like `/`, `?`, `=`, `&`, `+`, `\`, `"`, `'`, `;`, `<` , `>` `(space)` are checked, so if these characters are included in the payload, they are converted to the `%xx` format.
  * **When to Disable**:
      * **JSON/XML API Testing**: When injecting payloads into a JSON body (`{"key": "§payload§"}`), applying URL encoding may break the syntax or cause the server to fail to recognize the value properly. You must check this option carefully and disable it if necessary during API pentesting.
      * **Double Encoding Prevention**: If URL encoding was already applied in Payload Processing rules, this section might encode it again, causing double encoding. Disable it if this is not the intended attack vector.

### Resource Pool: Request Control and Stability Assurance

The Resource Pool tab is the control center that manages the load Intruder attacks place on the target server and the local network environment. Increasing scan speed is not always the answer; precise settings are required to prevent network bottlenecks, avoid server DoS (Denial of Service) states, and evade detection by security equipment (WAF/IPS).

![](assets/images/burp_intruder_resource_pool.png)

#### Maximum concurrent requests (Thread Control)

This setting determines the number of threads for HTTP requests sent simultaneously.

  * **Default Settings and Optimization**: Burp's default is usually set around 10. However, if the target server's processing capacity is small or network bandwidth is narrow, a high thread count can frequently cause Timeouts or connection errors, slowing down the overall diagnosis. Conversely, when targeting high-performance servers within an internal network, you can increase threads to speed up the process.
  * **Mandatory Setting for Recursive Grep**: When using the `Recursive grep` type in the Payloads tab, since the previous response value must be used for the next request, parallel processing is logically impossible. In this case, you must set this value to **1** to force sequential request transmission.
  * **Race Condition Testing**: To trigger race condition vulnerabilities, you need to push many requests momentarily. In this case, set the thread count high (20\~50 or more), but using the Turbo Intruder extension is more effective than the Java-based Intruder.

#### Throttle (Delay between requests)

Assigns an intentional delay between requests. This has two main purposes:

1.  **Prevent Server Overload**: Adjusts requests per second (RPS) to continue scanning stably without exhausting server resources.
2.  **Security Detection Evasion (Stealth)**: If a large number of requests occur in a short time, firewalls or IPS may block the IP. Adding a delay makes the traffic look like general user traffic.

<!-- end list -->

  * **Fixed delay**: Waits for a fixed amount of time (milliseconds) between every request.
  * **Variable delay (Randomness)**: Security monitoring systems use heuristic algorithms to detect mechanical patterns (e.g., requests exactly every 0.5 seconds) and flag them as bots. Enabling the `Add random variations to delay` option adds randomness (Jitter) to the delay time, helping to hide these mechanical patterns. For example, if you add 50% variation to a 1000ms delay, the request interval will be randomly determined between 500ms and 1500ms.

#### Strategic Resource Pool Configuration Examples

  * **Create new resource pool**: You can create independent pools for each Intruder tab. It is recommended to separate and manage them so that running different attacks simultaneously (e.g., one brute force, one fuzzing) does not affect each other's speed.
  * **System-wide pool**: Selecting `Use default resource pool` follows Burp's global settings. Use this option if you want to control the overall network bandwidth when running multiple scans simultaneously.

Senior testers prefer 'uninterrupted connections' over unconditional high speed. It is an expert habit to check the target server's response speed in Repeater or a separate terminal before starting the attack, and then configure the Resource Pool by calculating threads and delay accordingly. Especially in environments with strict WAFs, a **1 Thread + Variable Delay** combination is a valid strategy to extract data slowly over time (Low and Slow).

### Turbo Intruder: Extreme Speed and Flexibility

Burp Intruder is powerful, but due to its Java GUI-based architecture and memory management methods, it has limitations in handling massive requests (millions or more) or attacks requiring microsecond (µs) level precise timing control. Turbo Intruder, developed by PortSwigger researcher James Kettle, is an extension designed to overcome these constraints, combining a custom HTTP stack and Python scripting to offer incomparable speed and flexibility.

#### Architecture and Working Principle

Turbo Intruder defines attack logic via **Python scripts** instead of GUI settings. Internally, it uses a high-performance HTTP stack written in Go, capable of achieving speeds dozens to hundreds of times faster (tens of thousands of RPS depending on the environment) than the existing Intruder. Additionally, it natively supports HTTP Pipelining and HTTP/2 Multiplexing to test server processing limits to the extreme.

#### Core Components: Python Interface

Turbo Intruder scripts consist largely of two functions:

1.  **`queueRequests(target, wordlists)`**: Responsible for starting the attack and stacking requests into the engine queue. Here, you configure the `RequestEngine` which controls connection counts, pipelining settings, request rates, etc.
2.  **`handleResponse(req, interesting)`**: A callback function invoked whenever a response returns from the server. Here, you analyze the response code or search for specific strings to decide whether to display it in the results table (`interesting`).

#### Key Use Cases and Code Strategies

**1. Race Condition Testing**
Turbo Intruder's most powerful feature is triggering Race Conditions using the **Gate** mechanism. While general multi-threading has slightly different server arrival times due to network latency, Turbo Intruder sends requests right up to the server, holds the last byte, and then sends the last byte on all connections simultaneously when the signal (gate) drops, implementing perfect concurrency.

```python
def queueRequests(target, wordlists):
    # Engine config: pipelining=1 is standard, can be higher for Race Conditions
    engine = RequestEngine(endpoint=target.endpoint,
                           concurrentConnections=30,
                           requestsPerConnection=100,
                           pipeline=False
                           )

    # 1. Normal request queuing
    for word in open('/usr/share/dict/words'):
        engine.queue(target.req, word.rstrip())

    # 2. Gate setup example for Race Condition
    # Group 10 requests under a gate named 'race'
    for i in range(10):
        engine.queue(target.req, gate='race')
    
    # Open the gate to send 10 requests simultaneously
    engine.openGate('race')

def handleResponse(req, interesting):
    # Record only 200 OK responses to the table
    if req.status == 200:
        table.add(req)
```

**2. High-Speed Fuzzing and Brute Force**
When targeting servers that support HTTP Pipelining, you can maximize throughput by using pipelining technology, which sends consecutive requests without waiting for responses within a single TCP connection. Using the `pipeline=True` option and appropriate `requestsPerConnection` settings allows you to substitute huge dictionary files in a short time.

**3. Complex Signature Bypassing**
If a dynamically generated hash value (HMAC) or timestamp must be included in the header for each request, setting this up with the standard Intruder's Macro feature is very difficult. In Turbo Intruder, you can import Python libraries to calculate the signature immediately at the time of request generation and modify the header before transmission.

#### Result Analysis and Filtering

Turbo Intruder does not save all responses. For memory efficiency, it only saves requests where `table.add(req)` is called in the `handleResponse` function. Therefore, when writing scripts, you must filter precisely using code based on response size, status codes, inclusion of specific keywords, etc. This allows you to retain only meaningful vulnerability data without gigabytes of log files.

#### Senior Engineer's Tips

  * **Use Decorators**: You can use decorators to easily apply custom headers or payload variations.
  * **Consider Server Stability**: Turbo Intruder's speed can place a fatal load on the server. For live targets, start with low `concurrentConnections` and increase gradually.
  * **Utilize External Libraries**: If necessary, you can modify `sys.path` to load locally installed Python libraries. This allows you to perform complex encryption logic or data processing.

### Settings Tab: Precision Control and Stability Assurance

The Settings tab (including sub-items of the Options tab in older versions) is where the technical details of the attack are fine-tuned. Beyond simply executing an attack, it controls network connection methods, error recovery strategies, and memory management to guarantee the stability of large-scale scans that last for long periods. We analyze key setting items that a Senior Engineer must check.

#### Request Headers: Communication Protocol Control

Defines how HTTP request headers generated by Burp are handled.

  * **Update Content-Length header**: Checked by default. When a payload is inserted, the length of the body changes; this option must be active for Burp to recalculate the exact `Content-Length` value and insert it into the header. If disabled, the server may determine that the request is incomplete or excessive, returning a Timeout or 400 Bad Request. Unless it is a special case like HTTP Smuggling testing, leave this on.
  * **Set Connection: close**: Forcibly adds `Connection: close` to the request header. HTTP/1.1 uses Keep-Alive by default, but when sending large volumes of short requests with multiple threads like Intruder, closing sockets immediately can be advantageous for resource management. However, disable this when using pipelining or when server overhead needs to be reduced.

![](assets/images/burp_intruder_settings_request_header.png)

#### Error Handling: Network Instability Response

When sending thousands of requests, connection failures can occur due to temporary network disconnections or momentary server overload. This section sets the resilience to continue the attack without interruption.

  * **Number of retries on network failure**: The number of retries upon connection failure. The default is 3. Increase this value when routing through unstable networks or overseas networks to prevent False Negatives.
  * **Pause before retry**: The wait time before retrying. If a WAF has logic to temporarily block an IP and then release it, giving this a generous time (e.g., 2000ms or more) can induce a retry after the block is lifted.

#### Attack Results: Memory and Storage Optimization

Intruder basically saves all request and response data to memory (or temporary files). If this setting is incorrect when processing tens of thousands of requests, Burp may freeze or force close due to OOM (Out Of Memory) errors.

  * **Make a full grep**: Uncheck to save memory for result table performance. However, keep it on for detailed analysis.
  * **Discard response bodies**: **The most important option for large-scale scans**. It saves only headers and metadata, discarding the response body. Since the body is discarded after the Grep - Extract function operates, data extraction occurs normally while memory usage is drastically reduced. If you only need to check status codes or extracted values, this must be enabled.

![](assets/images/burp_intruder_attack_result.png)

#### Auto-pause attack: Conditional Automatic Suspension Strategy

When performing large-scale attacks, continuing to send meaningless requests even after a specific event has occurred is a waste of time and a major cause of log pollution. The **Auto-pause attack** feature analyzes the content of the response body in real-time and pauses the attack immediately when set conditions are met. This is very useful for senior pentesters to monitor the attack process and secure control.

  * **Core Purpose of the Feature**:

      * **Stop Immediately on Success**: For example, if a login succeeds during a brute force attack, there is no need to proceed further. Detecting the success indicator and stopping immediately prevents unnecessary traffic.
      * **Block Detection and Protection**: If the attack is not stopped when a WAF block page or "Rate Limit Exceeded" message appears, the IP may be permanently blocked. Detecting this and stopping helps protect the IP.
      * **Session Expiration Response**: If the session is disconnected during the attack and redirects to the login page, all subsequent attacks are recorded as failures (False Negative). This detects the event to time session re-establishment.

  * **Setting Options Details**:

      * **Pause if an expression... appears**: Pauses when a specific string (e.g., "Welcome", "Error: 500", "Captcha required") *appears* in the response. Mainly used when a vulnerability is found or blocking has started.
      * **Pause if an expression... is missing**: Pauses when a specific string (e.g., "Logged in as", normal footer text) *disappears* from the response. Useful when the server goes down or the page structure changes due to session expiration.

  * **Match type**:

      * **Simple string**: Simple text matching.
      * **Regex**: Powerful for detecting dynamic patterns. Used to catch changing success messages like `User ID: \d{4}` or specific error code formats.

Using this feature allows for immediate response (resuming or changing settings) after grasping the situation, as the attack will be paused upon the occurrence of critical events even if you leave your seat after queuing tens of thousands of requests.

![](assets/images/burp_intruder_auto_pause_attack.png)

#### Redirections: Redirection Tracking Policy and Analysis Strategy

Web browsers automatically follow 3xx responses (Redirection) from servers to show the final destination, but in security testing, especially automated attacks using Intruder, this behavior can rather hinder vulnerability identification. This section defines Intruder's behavior when encountering 3xx responses.

  * **Follow redirections (Tracking Policy)**

      * **Never (Default and Recommended)**: Does not follow redirections and immediately shows the 3xx response as the result.
          * **Expert Usage**: Essential for most Fuzzing and Brute Force scenarios. For example, the surest indicator distinguishing 'Failure (200 OK)' from 'Success (302 Found -\> Dashboard)' during login attempts is the status code. If redirections are followed, success also returns a final '200 OK (Dashboard)', making it indistinguishable from failure responses by status code alone. Also, when checking for Open Redirect vulnerabilities, you must verify the `Location` header value directly, so set this to `Never`.
      * **On-site only**: Follows redirections only within the same host (domain/port). Stops if redirected to an external site.
      * **In-scope only**: Follows redirections only to URLs defined in the Scope of the Target tab. Useful for preventing requests outside the attack target range.
      * **Always**: Follows all redirections regardless of destination. Beware of falling into infinite redirection loops.

  * **Process cookies in redirections (Session Maintenance)**

      * Enabled only when configured to follow redirections (`On-site`, `Always`, etc.).
      * **Working Principle**: Servers often issue Session IDs via the `Set-Cookie` header when giving a redirection response (302). If this option is unchecked, Intruder will not include the cookie just issued when sending the redirected next request, causing the session to break (resulting in bouncing back to the login page). Must be checked when deeply attacking pages with complex authentication flows.

![](assets/images/burp_intruder_redirections.png)

#### HTTP Connection & Version Control: Protocol-Level Optimization and Bypass

This section deals with strategic settings to verify the target server's protocol processing logic and bypass security equipment, beyond simple "connection speed".

  * **HTTP/1 connection reuse (TCP Keep-Alive)**

      * **Function**: Reuses the single TCP connection (Socket) after establishing it to send multiple HTTP requests without disconnecting. Significantly increases scan speed by reducing 3-way handshake overhead.
      * **Strategic Usage**:
          * **Speed Optimization (Default Recommended)**: It is absolutely advantageous to keep this option on when transmitting large volumes of payloads.
          * **When to Disable**: When testing the behavior of Load Balancers (L4/L7). For example, to check if routing is done to different backend servers for every connection, you must disconnect (Connection teardown) every time instead of reusing the connection. Also, some WAFs block if too many requests occur in a single session, so connections are intentionally dropped to evade this.

  * **HTTP version (HTTP/2 Force & Downgrade)**

      * **Function**: Forces the HTTP version to be used in this attack, regardless of Burp's project-wide settings.
      * **Core Use Case (WAF Bypass)**: Many WAFs and security devices strictly inspect HTTP/1.1 traffic but often have flawed parsing logic or loose inspection rules for HTTP/2 traffic.
          * **HTTP/2 Force**: Even if it appeared as HTTP/1.1 in Repeater or Proxy, if the server supports it, force HTTP/2 transmission to test if WAF detection can be bypassed.
          * **Protocol Downgrade**: Conversely, even if the server uses HTTP/2 by default, force downgrade to HTTP/1.1 to diagnose `Host` header parsing differences or Request Smuggling vulnerabilities.

![](assets/images/burp_intruder_http.png)

### Grep: Precise Analysis and Filtering Strategy for Response Data

In an Intruder attack sending tens of thousands of requests, the simple fact that "it was sent" is not important. What matters is identifying "which response is different". The Grep functions located in the Settings tab (or Options tab in older versions) are filters and detectors that find meaningful signals within numerous response data. Senior Pentesters do not rely on visual inspection but data-fy attack results through Grep settings.

#### Grep - Match: Anomaly Detection (Flagging)

Inspects whether a specific string is included in the response body and displays it as a checkbox in the results table. This becomes the most critical indicator when success/failure cannot be judged by HTTP Status Code alone.

  * **Overcoming Functional Limits**: Many web applications return 200 OK even on login failure, or output error messages on a 200 OK page instead of a 302 redirection when an error occurs. In these cases, sorting by status code is meaningless.
  * **Key Use Cases**:
      * **Error Message Detection**: Register keywords like `SQL syntax`, `ORA-`, `Exception`, `stack trace` during Fuzzing to identify SQL Injection or information disclosure vulnerabilities.
      * **Success/Failure Discrimination**: During Brute Force attacks, register keywords that appear only upon login success like `Welcome`, `Logout`, `My Page`, or conversely, `Invalid password` which appears on failure, to find items with different patterns.
  * **Setting Tips**:
      * **Case sensitive match**: Distinguishes case. Checking this increases accuracy, but if you don't know how the developer wrote the error message, unchecking it increases versatility.
      * **Exclude HTTP headers**: Generally set to inspect only the Body to reduce False Positives caused by strings coincidentally included in headers (cookie values, etc.).

![](assets/images/burp_intruder_match.png)

#### Grep - Extract: Data Extraction and Mining

Extracts a specific part of the response data and creates it as a separate column in the results table. Essential when going beyond simple detection to harvest data or use it as material for the next attack.

  * **Working Principle**: Press the 'Define' button and drag the area you want to extract from the response sample; Burp automatically designates the start (Start delimiter) and end (End delimiter) strings. For complex patterns, you can write Regular Expressions (Regex) directly.
  * **Key Use Cases**:
      * **Information Leak Check**: List DB version information, internal IP addresses, file paths, etc., included inside error messages for use in reporting.
      * **Token Harvesting**: Extract Session IDs, CSRF Tokens, API Keys, etc., issued after login.
      * **Recursive Grep Integration**: Link the data extracted here with the 'Recursive grep' type in the Payloads tab to automate scenarios requiring CSRF tokens, like posting on a bulletin board or changing passwords.
  * **Caution**: Set a Maximum length for data extraction to restrict unnecessarily long HTML codes from loading into the table and wasting memory.

![](assets/images/burp_intruder_extract.png)

#### Grep - Payloads: Reflection Verification

Verifies if the payload I sent returns included as-is in the response value.

  * **Key Use Case**: Most powerful when finding **Reflected XSS (Cross-Site Scripting)** vulnerabilities. For example, if `<script>alert(1)</script>` is sent as a payload and this string exists as-is in the response body, the possibility of XSS is very high.
  * **Working Principle**: It dynamically inspects whether *the payload used in that request* exists in the response, rather than looking for a fixed string.
  * **Match against pre-URL-encoded payloads**: Even if the payload was transmitted URL-encoded, it may appear decoded in the response. Enabling this option attempts matching based on the original string before encoding to increase accuracy.

![](assets/images/burp_intruder_payloads.png)

#### Senior Engineer's Grep Strategy

The core of Grep settings is "Noise Reduction".

1.  Before the attack, analyze normal responses and error responses in Repeater.
2.  Find a Unique String that clearly distinguishes the two responses and register it in Grep - Match.
3.  Techniques are also frequently used that not only check for existence but utilize 'Invert match' (checks if the string is *missing*) to find abnormal responses where footer or copyright text common to all pages is broken or missing.

---

# Burp Intruder 
## Attack Type과 페이로드 포지셔닝의 전략적 선택

Intruder의 효율성은 공격 지점(Position)과 공격 유형(Attack Type)의 정확한 매핑에서 시작됩니다. 복잡한 매개변수 조합을 다룰 때 각 유형의 동작 방식을 정확히 이해해야 합니다.

## Intruder 워크플로우 및 구성

기본적인 워크플로우는 Proxy나 Repeater 등에서 요청을 캡처하여 Intruder로 전송(Send to Intruder, 단축키 `Ctrl+I`)하는 것으로 시작됩니다.

### Positions 탭: 공격 지점 설정

가장 먼저 수행해야 할 작업은 변조할 파라미터, 즉 페이로드(Payload)가 주입될 위치를 지정하는 것입니다. Burp는 기본적으로 모든 파라미터 값을 자동으로 선택하지만, 정밀한 테스트를 위해서는 `Clear §` 버튼을 눌러 초기화한 후, 테스트하려는 특정 부분만 드래그하여 `Add §`로 마킹해야 합니다.

![](assets/images/burp_intruder_type.png)

#### Sniper
단일 페이로드 세트를 사용하며, 한 번에 하나의 위치만 테스트합니다.
* **동작 방식**: 포지션 A, B가 지정되었을 때, 먼저 A에 페이로드를 순차 대입하고 B는 원본 값을 유지합니다. A 테스트가 끝나면, A를 원본 값으로 복구하고 B에 페이로드를 대입합니다.
* **시나리오**: 5개의 파라미터가 있는 폼에서 어느 파라미터가 SQL Injection에 취약한지 식별할 때. Intruder는 첫 번째 파라미터를 테스트하고 나머지는 원본 값을 유지하며, 그 후 두 번째 파라미터로 이동합니다.
* **적용**: 여러 파라미터 중 어느 것이 취약한지 개별적으로 격리하여 테스트할 때 적합합니다.
#### Battering ram

단일 페이로드 세트를 사용하지만, 모든 포지션에 동일한 값을 동시에 주입합니다.
* **동작 방식**: 페이로드 'X'를 포지션 A와 B에 동시에 넣고 요청을 보냅니다.
* **시나리오**: 사용자 ID가 URL 경로와 POST Body XML 데이터 내부에 동시에 존재해야 하며, 두 값이 일치해야만 로직이 진행되는 경우.
* **적용**: HTTP 요청 내 헤더와 바디에 동일한 값이 포함되어야 하는 무결성 검증 로직을 테스트하거나, 식별자가 여러 곳에 분산된 경우 유용합니다.

#### Pitchfork
다중 페이로드 세트를 사용하며, 각 세트를 병렬로 순회합니다.
* **동작 방식**: 포지션 A에는 Payload Set 1, 포지션 B에는 Payload Set 2를 할당합니다. 1번 세트의 첫 번째 값과 2번 세트의 첫 번째 값을 조합하여 요청합니다. (1:1 매핑)
* **시나리오**: 이미 확보한 `username:password` 덤프 리스트를 이용해 Credential Stuffing을 수행할 때. User A에게는 Password A만 대입하면 되므로 불필요한 조합을 줄일 수 있습니다.
* **적용**: 데이터 간의 연관 관계가 명확한 경우(예: ID와 해당 ID의 올바른 토큰 쌍)에 사용합니다.

#### Cluster bomb
다중 페이로드 세트의 모든 조합(Cartesian Product)을 시도합니다.
* **동작 방식**: Payload Set 1의 첫 번째 값에 대해 Payload Set 2의 모든 값을 순차적으로 대입한 후, Set 1의 다음 값으로 넘어갑니다.
* **시나리오**: 관리자 계정의 비밀번호를 모르고, 사용자 ID 목록과 일반적인 비밀번호 사전 파일을 이용해 무차별 대입(Brute Force)을 시도할 때. (User A에 대해 모든 비번 시도, User B에 대해 모든 비번 시도...)
* **적용**: 폼 데이터의 모든 입력 가능성을 전수 조사해야 할 때 사용합니다. 요청 수가 폭발적으로 증가하므로 범위 설정에 주의가 필요합니다.

### Payload Sets와 공격 유형의 상관관계

Payloads 탭의 최상단에 위치한 Payload Sets 섹션은 Positions 탭에서 설정한 Attack Type과 밀접하게 연동됩니다. 이 구조를 정확히 이해해야 다중 변수를 다루는 복잡한 공격 시나리오를 설계할 수 있습니다.

* **Payload Set의 활성화**: Positions 탭에서 지정한 마킹(`§`)의 개수와 선택한 Attack Type에 따라 활성화되는 Set의 개수가 결정됩니다. 예를 들어, `Pitchfork`나 `Cluster bomb`을 선택하고 두 개의 파라미터를 마킹했다면, Payload Set은 1번과 2번으로 나뉘며 각각 독립적으로 설정해야 합니다.
* **Set별 독립 구성**: 각 Set마다 서로 다른 Payload type을 적용할 수 있습니다. 예를 들어, 첫 번째 Set(Username)은 `Simple list`로 설정하고, 두 번째 Set(Password)은 대용량 처리를 위해 `Runtime file`로 설정하는 식의 하이브리드 구성이 가능합니다.

![](assets/images/burp_intruder_payloads.png)
### 주요 Payload Types 및 고급 활용 전략

Burp는 다양한 Payload Type을 제공하며, 상황에 맞는 적절한 타입을 선택하는 것이 테스트의 효율성을 결정합니다.

#### Simple list와 Runtime file
가장 기본적이지만 메모리 관리 측면에서 큰 차이가 있습니다.
* **Simple list**: 텍스트 박스에 직접 값을 붙여넣거나 비교적 작은 크기의 사전 파일을 로드할 때 사용합니다. 모든 항목이 메모리에 로드됩니다.
* **Runtime file**: 수백 메가바이트 이상의 거대한 사전 파일(예: rockyou.txt 전체)을 사용할 때 필수적입니다. Burp가 파일을 메모리에 모두 올리지 않고, 실행 시점에 한 줄씩 스트리밍 방식으로 읽어들이므로 대규모 브루트 포싱 시 메모리 부족(OOM) 현상을 방지할 수 있습니다.

#### Custom iterator
여러 문자열 세트를 조합하여 하나의 정교한 페이로드를 생성해야 할 때 강력합니다. 단일 Position(Sniper 모드 등)을 사용하면서도 복합적인 문자열 조합을 만들어낼 수 있습니다.
* **구조**: Position 1, 2, 3... 등 가상의 슬롯을 만들고 각 슬롯에 별도의 리스트를 할당합니다. 그 후 각 슬롯 사이에 들어갈 Separator(구분자)를 지정합니다.
* **활용 예시**: `admin.bak`, `admin_old` 등을 테스트하기 위해 [파일명 리스트] + [구분자] + [확장자 리스트]를 조합할 때 유용합니다. Cluster bomb을 쓰지 않고도 유사한 조합 효과를 낼 수 있어 요청 관리가 용이합니다.

#### Recursive grep
이전 응답에서 특정 데이터를 추출하여 바로 다음 요청의 페이로드로 사용하는 방식입니다.
* **핵심 용도**: Anti-CSRF 토큰이 매 요청마다 갱신되거나, 다단계 인증 흐름을 테스트할 때 필수적입니다.
* **제약 사항**: 선행 요청의 결과가 후행 요청의 입력값이 되므로, 동시성을 가질 수 없습니다. 반드시 **단일 스레드(Resource Pool에서 Maximum concurrent requests: 1)**로 설정해야 정상 동작합니다. Options 탭의 'Grep - Extract' 설정이 선행되어야 활성화됩니다.

#### Null payloads
실질적인 페이로드를 생성하지 않고 빈 값만 생성하여 요청을 반복할 때 사용합니다.
* **핵심 용도**:
    * Race Condition 취약점을 확인하기 위해 동일한 요청을 동시다발적으로 전송할 때.
    * 조회수 조작, 투표 수 조작 등 비즈니스 로직의 허점을 파고들 때.
    * **Generate payload count** 옵션을 통해 반복 횟수를 지정하거나, **Continue indefinitely**로 무한 루프를 돌릴 수 있습니다.

#### Character frobber & Bit flipper
입력값의 특정 문자나 비트를 체계적으로 변조합니다.
* **활용 예시**: 암호화된 세션 토큰이나 직렬화된 데이터를 분석할 때 유용합니다. 토큰의 특정 바이트를 변경했을 때 애플리케이션이 복호화 에러를 반환하는지, 혹은 다른 사용자로 오인증되는지를 관찰하여 CBC Bit Flipping 같은 암호학적 취약점을 진단할 때 사용합니다.

### Payload Processing: WAF 우회 및 데이터 정제

단순한 리스트 대입은 WAF나 애플리케이션의 입력값 검증 로직에 의해 차단될 확률이 높습니다. 'Payload Processing' 섹션에서는 페이로드가 전송되기 직전에 적용될 변환 규칙(Rule)을 정의합니다. 규칙은 설정된 순서대로(Top-down) 순차 적용됩니다.

* **Add prefix / Add suffix**: SQL Injection 공격 시 페이로드 앞뒤에 `'` , `)`, `-- ` 등을 자동으로 붙여줍니다. 이를 통해 원본 사전 파일을 수정하지 않고도 쿼리 문법을 완성할 수 있습니다.
* **Encode / Decode**: 특정 특수문자를 Base64, URL encoding, Hex 등으로 변환합니다. 예를 들어, WAF가 `<script>` 키워드를 차단할 때, 이를 Base64로 인코딩하여 우회 시도를 자동화할 수 있습니다.
* **Hash**: 페이로드를 MD5, SHA256 등으로 해싱하여 전송합니다. 클라이언트 사이드에서 패스워드를 해싱하여 보내는 로직을 테스트할 때, 평문 사전을 사용하면서 전송 직전에 해시값으로 변환할 수 있습니다.
* **Invoke Burp extension**: 기본 제공 규칙으로 해결되지 않는 복잡한 로직(예: 커스텀 암호화, 전자서명 생성)이 필요한 경우, 사용자가 작성한 Python이나 Java 확장을 호출하여 처리합니다.

### Payload Encoding 주의사항

Payloads 탭 하단에 위치한 'Payload Encoding' 섹션은 기본적으로 활성화되어 있으며, URL에서 특수기능을 하는 문자(`&`, `=`, `?`, 공백 등)를 자동으로 URL 인코딩합니다.

* **기본 동작**: `/`, `?`, `=`, `&`, `+`, `\`, `"`, `'`, `;`, `<` , `>` `(space)` 등의 문자가 체크되어 있어, 해당 문자가 페이로드에 포함되면 `%xx` 형태로 변환됩니다.
* **비활성화가 필요한 경우**:
    * **JSON/XML API 테스트**: JSON 바디 내(`{"key": "§payload§"}`)에 페이로드를 주입할 때 URL 인코딩이 적용되면 문법이 깨지거나 서버가 값을 제대로 인식하지 못할 수 있습니다. API 펜테스팅 시에는 이 옵션을 주의 깊게 확인하고 필요시 체크를 해제해야 합니다.
    * **이중 인코딩 방지**: Payload Processing 규칙에서 이미 URL 인코딩을 적용했다면, 이 섹션에 의해 한 번 더 인코딩되어 이중 인코딩이 발생할 수 있습니다. 의도한 공격 벡터가 아니라면 해제해야 합니다.

### Resource Pool: 요청 제어와 안정성 확보

Resource Pool 탭은 Intruder 공격이 대상 서버와 로컬 네트워크 환경에 미치는 부하를 관리하는 제어 센터입니다. 단순히 스캔 속도를 높이는 것이 능사가 아니며, 네트워크 병목 현상 방지, 서버의 DoS(Denial of Service) 상태 예방, 그리고 보안 장비(WAF/IPS)의 탐지 회피를 위해 정교한 설정이 요구됩니다.

![](assets/images/burp_intruder_resource_pool.png)

#### Maximum concurrent requests (동시 요청 수 제어)

이 설정은 동시에 전송할 HTTP 요청의 스레드 수를 결정합니다.

* **기본 설정과 최적화**: Burp의 기본값은 보통 10개 내외로 설정되어 있습니다. 하지만 대상 서버의 처리 용량이 작거나 네트워크 대역폭이 좁은 경우, 스레드가 많으면 타임아웃(Timeout)이나 커넥션 에러가 빈번하게 발생하여 오히려 전체적인 진단 속도가 저하됩니다. 반대로, 사내망의 고성능 서버를 대상으로 할 때는 스레드를 늘려 속도를 높일 수 있습니다.
* **Recursive Grep 시 필수 설정**: Payloads 탭에서 `Recursive grep` 타입을 사용하는 경우, 이전 응답 값을 다음 요청에 사용해야 하므로 논리적으로 병렬 처리가 불가능합니다. 이 경우 반드시 이 값을 **1**로 설정하여 순차적으로 요청이 전송되도록 강제해야 합니다.
* **Race Condition 테스트**: 경쟁 상태 취약점을 유발하기 위해서는 순간적으로 많은 요청을 밀어넣어야 합니다. 이 경우 스레드 수를 20~50 이상으로 높게 설정하지만, Java 기반의 Intruder보다는 Turbo Intruder 확장을 사용하는 것이 더 효과적입니다.

#### Throttle (Delay between requests)

요청과 요청 사이에 의도적인 지연 시간을 부여합니다. 이는 두 가지 주된 목적을 가집니다.

1.  **서버 과부하 방지**: 초당 요청 수(RPS)를 조절하여 서버 리소스를 고갈시키지 않고 안정적으로 스캔을 지속합니다.
2.  **보안 탐지 회피 (Stealth)**: 짧은 시간에 다량의 요청이 발생하면 방화벽이나 IPS가 IP를 차단할 수 있습니다. 지연 시간을 두어 일반적인 사용자 트래픽처럼 보이게 합니다.

* **Fixed delay**: 모든 요청 사이에 고정된 시간(밀리초)만큼 대기합니다.
* **Variable delay (Randomness)**: 보안 관제 시스템은 기계적인 패턴(예: 정확히 0.5초 간격의 요청)을 탐지하여 봇으로 간주하는 휴리스틱 알고리즘을 사용합니다. `Add random variations to delay` 옵션을 활성화하면 지연 시간에 무작위성(Jitter)을 부여하여 이러한 기계적 패턴을 숨길 수 있습니다. 예를 들어 1000ms 딜레이에 50% 변동을 주면, 요청 간격이 500ms에서 1500ms 사이에서 무작위로 결정됩니다.

#### 전략적 Resource Pool 구성 예시

* **Create new resource pool**: 각 Intruder 탭마다 독립적인 풀을 생성할 수 있습니다. 서로 다른 공격(예: 하나는 무차별 대입, 하나는 퍼징)을 동시에 돌릴 때 서로의 속도에 영향을 주지 않도록 분리하여 관리하는 것이 좋습니다.
* **System-wide pool**: `Use default resource pool`을 선택하면 Burp 전체의 글로벌 설정을 따릅니다. 여러 스캔을 동시에 돌릴 때 전체 네트워크 대역폭을 통제하고 싶다면 이 옵션을 사용합니다.

시니어 테스터는 무조건 빠른 속도보다는 '끊기지 않는 연결'을 선호합니다. 공격 시작 전, Repeater나 별도의 터미널에서 대상 서버의 응답 속도를 체크하고, 이에 맞춰 스레드 수와 딜레이를 계산하여 Resource Pool을 설정하는 것이 전문가의 습관입니다. 특히 WAF가 엄격한 환경에서는 **1 Thread + Variable Delay** 조합을 사용하여 시간을 들여 천천히 데이터를 추출(Low and Slow)하는 전략이 유효합니다.

### Turbo Intruder: 극한의 속도와 유연성

Burp Intruder는 강력하지만, Java GUI 기반의 아키텍처와 메모리 관리 방식으로 인해 대량의 요청(수백만 건 이상)을 처리하거나 마이크로초(µs) 단위의 정밀한 타이밍 제어가 필요한 공격에는 한계가 있습니다. PortSwigger의 연구원 James Kettle이 개발한 Turbo Intruder는 이러한 제약을 극복하기 위해 설계된 확장 프로그램으로, 커스텀 HTTP 스택과 Python 스크립팅을 결합하여 비교할 수 없는 속도와 유연성을 제공합니다.

#### 아키텍처 및 작동 원리

Turbo Intruder는 GUI 설정 대신 **Python 스크립트**를 통해 공격 로직을 정의합니다. 내부적으로는 Go로 작성된 고성능 HTTP 스택을 사용하여, 기존 Intruder 대비 수십 배에서 수백 배 빠른 속도(환경에 따라 초당 수만 RPS)를 낼 수 있습니다. 또한, HTTP Pipelining과 HTTP/2의 다중화(Multiplexing) 기능을 네이티브로 지원하여 서버의 처리 한계를 극한까지 테스트할 수 있습니다.

#### 핵심 구성 요소: Python 인터페이스

Turbo Intruder의 스크립트는 크게 두 가지 함수로 구성됩니다.

1.  **`queueRequests(target, wordlists)`**: 공격을 시작하고 요청을 엔진 큐에 쌓는 역할을 합니다. 여기서 연결 수, 파이프라이닝 설정, 요청 속도 등을 제어하는 `RequestEngine`을 설정합니다.
2.  **`handleResponse(req, interesting)`**: 서버로부터 응답이 돌아올 때마다 호출되는 콜백 함수입니다. 여기서 응답 코드를 분석하거나 특정 문자열을 검색하여 결과 테이블에 표시할지 여부를 결정(`interesting`)합니다.

#### 주요 활용 사례 및 코드 전략

**1. Race Condition (경쟁 상태) 테스트**
Turbo Intruder의 가장 강력한 기능은 **Gate** 메커니즘을 이용한 Race Condition 유발입니다. 일반적인 멀티 스레딩은 네트워크 지연으로 인해 서버 도달 시간이 미세하게 다르지만, Turbo Intruder는 요청을 서버 바로 앞단까지 전송한 후 마지막 바이트를 홀딩하고 있다가, 신호(gate)가 떨어지면 모든 연결에서 동시에 마지막 바이트를 전송하여 완벽한 동시성을 구현합니다.

```python
def queueRequests(target, wordlists):
    # 엔진 설정: pipelining=1은 일반적인 경우, Race Condition 시에는 더 높일 수 있음
    engine = RequestEngine(endpoint=target.endpoint,
                           concurrentConnections=30,
                           requestsPerConnection=100,
                           pipeline=False
                           )

    # 1. 일반적인 요청 큐잉
    for word in open('/usr/share/dict/words'):
        engine.queue(target.req, word.rstrip())

    # 2. Race Condition을 위한 Gate 설정 예시
    # 'race'라는 이름의 게이트에 10개의 요청을 묶음
    for i in range(10):
        engine.queue(target.req, gate='race')
    
    # 게이트를 개방하여 10개 요청 동시 전송
    engine.openGate('race')

def handleResponse(req, interesting):
    # 200 OK 응답만 테이블에 기록
    if req.status == 200:
        table.add(req)
```

**2. 고속 Fuzzing 및 Brute Force**
HTTP Pipelining을 지원하는 서버를 대상으로 할 경우, 단일 TCP 연결 내에서 응답을 기다리지 않고 연속으로 요청을 보내는 파이프라이닝 기술을 사용하여 처리량을 극대화할 수 있습니다. `pipeline=True` 옵션과 적절한 `requestsPerConnection` 설정을 통해 짧은 시간 안에 거대한 사전 파일을 대입할 수 있습니다.

**3. 복잡한 서명 우회 (Signature Bypassing)**
요청마다 동적으로 생성되는 해시값(HMAC)이나 타임스탬프가 헤더에 포함되어야 하는 경우, 일반 Intruder의 Macro 기능으로는 설정이 매우 까다롭습니다. Turbo Intruder에서는 Python 라이브러리를 임포트하여 요청 생성 시점에 즉시 서명을 계산하고 헤더를 수정하여 전송할 수 있습니다.

#### 결과 분석 및 필터링

Turbo Intruder는 모든 응답을 저장하지 않습니다. 메모리 효율성을 위해 `handleResponse` 함수에서 `table.add(req)`가 호출된 요청만 저장합니다. 따라서 스크립트 작성 시 응답 크기, 상태 코드, 특정 키워드 포함 여부 등을 코드로 정교하게 필터링해야 합니다. 이는 수 기가바이트의 로그 파일 없이도 유의미한 취약점 데이터만 남길 수 있게 해 줍니다.

#### 시니어 엔지니어의 사용 팁

  * **Decorator 사용**: 데코레이터를 사용하여 사용자 정의 헤더나 페이로드 변형을 손쉽게 적용할 수 있습니다.
  * **서버 안정성 고려**: Turbo Intruder의 속도는 서버에 치명적인 부하를 줄 수 있습니다. 실제 서비스 중인 타겟에 대해서는 `concurrentConnections`를 낮게 시작하여 점진적으로 올려야 합니다.
  * **외부 라이브러리 활용**: 필요하다면 `sys.path`를 수정하여 로컬에 설치된 Python 라이브러리를 불러와 사용할 수 있습니다. 이를 통해 복잡한 암호화 로직이나 데이터 처리를 수행할 수 있습니다.

### Settings Tab: 정밀 제어와 안정성 확보

Settings 탭(구버전의 Options 탭 하위 항목 포함)은 공격의 기술적 세부 사항을 미세 조정하는 곳입니다. 단순히 공격을 실행하는 것을 넘어, 네트워크 연결 방식, 에러 복구 전략, 그리고 메모리 관리를 제어하여 장시간 이어지는 대규모 스캔의 안정성을 보장합니다. 시니어 엔지니어가 반드시 확인해야 할 주요 설정 항목들을 분석합니다.

#### Request Headers: 통신 규약 제어

Burp가 생성하는 HTTP 요청 헤더의 처리 방식을 정의합니다.

* **Update Content-Length header**: 기본적으로 체크되어 있습니다. 페이로드가 삽입되면 본문의 길이가 달라지는데, 이 옵션이 활성화되어 있어야 Burp가 정확한 `Content-Length` 값을 다시 계산해서 헤더에 넣습니다. 이를 해제하면 서버는 요청이 덜 왔거나 더 왔다고 판단하여 Timeout이나 400 Bad Request를 반환할 수 있으므로, HTTP Smuggling 테스트 같은 특수한 경우가 아니라면 항상 켜두어야 합니다.
* **Set Connection: close**: 요청 헤더에 `Connection: close`를 강제로 추가합니다. 기본적으로 HTTP/1.1은 Keep-Alive를 사용하지만, Intruder처럼 다중 스레드로 짧은 요청을 대량으로 보낼 때는 소켓을 즉시 닫는 것이 리소스 관리에 유리할 수 있습니다. 반면, 파이프라이닝을 사용하는 경우나 서버의 오버헤드를 줄여야 할 때는 해제해야 합니다.

![](assets/images/burp_intruder_settings_request_header.png)

#### Error Handling: 네트워크 불안정성 대응

수천 건의 요청을 보내다 보면 네트워크 일시 단절이나 서버의 순간적인 과부하로 연결이 실패할 수 있습니다. 이 섹션은 스캔 중단 없이 공격을 지속하기 위한 회복 탄력성을 설정합니다.

* **Number of retries on network failure**: 연결 실패 시 재시도 횟수입니다. 기본값은 3회입니다. 불안정한 네트워크나 해외망을 경유할 때는 이 값을 늘려 거짓 부정(False Negative)을 방지해야 합니다.
* **Pause before retry**: 재시도 전 대기 시간입니다. WAF가 일시적으로 IP를 차단했다가 푸는 로직을 가지고 있다면, 이 시간을 넉넉히(예: 2000ms 이상) 주어 차단이 풀린 후 재시도하도록 유도할 수 있습니다.

#### Attack Results: 메모리 및 저장소 최적화

Intruder는 기본적으로 모든 요청과 응답 데이터를 메모리(또는 임시 파일)에 저장합니다. 수만 건 이상의 요청을 처리할 때 이 설정이 잘못되면 Burp가 멈추거나 OOM(Out Of Memory) 오류로 강제 종료될 수 있습니다.

* **Make a full grep**: 결과 테이블의 성능을 위해, 체크를 해제하면 메모리를 절약할 수 있습니다. 하지만 상세 분석을 위해서는 켜두는 것이 좋습니다.
* **Discard response bodies**: **대용량 스캔 시 가장 중요한 옵션**입니다. 응답 본문(Body)을 저장하지 않고 헤더와 메타데이터만 남깁니다. Grep - Extract 기능이 동작한 후 본문은 버려지므로, 데이터 추출은 정상적으로 이루어지면서 메모리 점유율을 획기적으로 낮출 수 있습니다. 단순히 상태 코드나 추출된 값만 확인하면 되는 경우 반드시 활성화해야 합니다.

![](assets/images/burp_intruder_attack_result.png)

#### Auto-pause attack: 조건부 자동 중단 전략

대규모 공격을 수행할 때, 특정 이벤트가 발생했음에도 불구하고 무의미한 요청을 계속 보내는 것은 시간 낭비이자 로그 오염의 주원인입니다. **Auto-pause attack** 기능은 응답 본문의 내용을 실시간으로 분석하여, 설정한 조건이 충족되는 즉시 공격을 일시 정지시킵니다. 이는 시니어 펜테스터가 공격 과정을 모니터링하고 제어권을 확보하는 데 매우 유용합니다.

* **기능의 핵심 목적**:
    * **성공 시 즉시 중단**: 예를 들어, 무차별 대입 공격 중 로그인이 성공했다면 더 이상 공격을 진행할 필요가 없습니다. 성공 지표를 감지하여 즉시 멈춤으로써 불필요한 트래픽을 방지합니다.
    * **차단 감지 및 보호**: WAF 차단 페이지나 "Rate Limit Exceeded" 메시지가 떴을 때 공격을 멈추지 않으면, 해당 IP는 영구 차단될 수 있습니다. 이를 감지해 멈추게 함으로써 IP를 보호할 수 있습니다.
    * **세션 만료 대응**: 공격 도중 세션이 끊겨 로그인 페이지로 리다이렉트되는 경우, 이후의 모든 공격은 실패(False Negative)로 기록됩니다. 이를 감지하여 세션을 재수립할 타이밍을 잡습니다.

* **설정 옵션 상세 (Options)**:
    * **Pause if an expression... appears**: 응답에 특정 문자열(예: "Welcome", "Error: 500", "Captcha required")이 *나타나면* 멈춥니다. 주로 취약점이 발견되었거나, 차단이 시작되었을 때 사용합니다.
    * **Pause if an expression... is missing**: 응답에 특정 문자열(예: "Logged in as", 정상적인 푸터 텍스트)이 *사라지면* 멈춥니다. 서버가 다운되거나 세션이 만료되어 페이지 구조가 바뀌었을 때 유용합니다.

* **Match type (매칭 방식)**:
    * **Simple string**: 단순 텍스트 매칭입니다.
    * **Regex (정규표현식)**: 동적인 패턴을 감지할 때 강력합니다. 예를 들어, `User ID: \d{4}`와 같이 변화하는 성공 메시지나, 특정 포맷의 에러 코드를 잡아낼 때 사용합니다.

이 기능을 활용하면 수만 건의 요청을 걸어두고 자리를 비우더라도, 중요한 이벤트 발생 시 공격이 멈춰 있으므로 상황 파악 후 즉각적인 대응(재개 또는 설정 변경)이 가능해집니다.

![](assets/images/burp_intruder_auto_pause_attack.png)

#### Redirections: 리다이렉션 추적 정책과 분석 전략

웹 브라우저는 기본적으로 서버의 3xx 응답(Redirection)을 자동으로 따라가 최종 목적지를 보여주지만, 보안 테스팅, 특히 Intruder를 이용한 자동화 공격에서는 이러한 동작이 오히려 취약점 식별을 방해하는 요소가 될 수 있습니다. 이 섹션은 Intruder가 3xx 응답을 만났을 때의 행동 양식을 정의합니다.

* **Follow redirections (추적 정책)**
    * **Never (기본값 및 권장)**: 리다이렉션을 따라가지 않고, 즉시 3xx 응답을 결과로 보여줍니다.
        * **전문가 활용**: 대부분의 Fuzzing 및 Brute Force 시나리오에서 필수적입니다. 예를 들어, 로그인 시도 시 '실패(200 OK)'와 '성공(302 Found -> 대시보드)'을 구분하는 가장 확실한 지표는 상태 코드입니다. 만약 리다이렉션을 따라간다면 성공 시에도 최종적으로 '200 OK(대시보드)'가 반환되어, 실패 응답과 상태 코드로 구분할 수 없게 됩니다. 또한, Open Redirect 취약점 점검 시 `Location` 헤더 값을 직접 확인해야 하므로 `Never`로 설정해야 합니다.
    * **On-site only**: 동일한 호스트(도메인/포트) 내의 리다이렉션만 따라갑니다. 외부 사이트로 리다이렉트되는 경우 멈춥니다.
    * **In-scope only**: Target 탭의 Scope에 정의된 URL로의 리다이렉션만 따라갑니다. 공격 대상 범위를 벗어나는 요청을 방지할 때 유용합니다.
    * **Always**: 목적 불문하고 모든 리다이렉션을 따라갑니다. 무한 리다이렉션 루프에 빠질 위험이 있어 주의해야 합니다.

* **Process cookies in redirections (세션 유지)**
    * 리다이렉션을 따라가도록 설정(`On-site`, `Always` 등)한 경우에만 활성화됩니다.
    * **동작 원리**: 서버가 리다이렉션 응답(302)을 줄 때 `Set-Cookie` 헤더를 통해 세션 ID를 발급하는 경우가 많습니다. 이 옵션을 체크하지 않으면, Intruder는 리다이렉트된 다음 요청을 보낼 때 방금 발급받은 쿠키를 포함하지 않아 세션이 끊기게 됩니다(다시 로그인 페이지로 튕기는 현상 발생). 복잡한 인증 흐름을 가진 페이지를 깊이 있게 공격해야 할 때 반드시 체크해야 합니다.

![](assets/images/burp_intruder_redirections.png)

#### HTTP Connection & Version Control: 프로토콜 레벨의 최적화와 우회

이 섹션은 단순히 "연결 속도"를 넘어, 대상 서버의 프로토콜 처리 로직을 검증하고 보안 장비를 우회하기 위한 전략적 설정을 다룹니다.

* **HTTP/1 connection reuse (TCP Keep-Alive)**
    * **기능**: 단일 TCP 연결(Socket)을 맺은 후, 이를 끊지 않고 재사용하여 여러 개의 HTTP 요청을 전송합니다. 3-way handshake 오버헤드를 줄여 스캔 속도를 비약적으로 높일 수 있습니다.
    * **전략적 활용**:
        * **속도 최적화 (기본 권장)**: 대량의 페이로드를 전송할 때는 이 옵션을 켜두는 것이 절대적으로 유리합니다.
        * **비활성화가 필요한 경우**: 로드 밸런서(L4/L7)의 동작을 테스트할 때입니다. 예를 들어, 매 연결마다 다른 백엔드 서버로 라우팅되는지 확인하려면, 연결을 재사용하지 않고 매번 끊어야(Connection teardown) 합니다. 또한, 특정 WAF는 단일 세션에서 너무 많은 요청이 발생하면 차단하므로, 이를 회피하기 위해 의도적으로 연결을 끊기도 합니다.

* **HTTP version (HTTP/2 Force & Downgrade)**
    * **기능**: Burp의 프로젝트 전역 설정과 무관하게, 이번 공격에서 사용할 HTTP 버전을 강제합니다.
    * **핵심 활용 사례 (WAF Bypass)**: 많은 WAF 및 보안 장비가 HTTP/1.1 트래픽은 엄격하게 검사하지만, HTTP/2 트래픽에 대해서는 파싱 로직이 미비하거나 검사 규칙이 느슨한 경우가 많습니다.
        * **HTTP/2 강제**: Repeater나 Proxy에서는 HTTP/1.1로 보였더라도, 서버가 지원한다면 HTTP/2로 강제 전송하여 WAF 탐지를 우회할 수 있는지 테스트합니다.
        * **Protocol Downgrade**: 반대로 서버가 기본적으로 HTTP/2를 사용하더라도, 강제로 HTTP/1.1로 다운그레이드하여 전송했을 때 발생하는 `Host` 헤더 파싱 차이나 Request Smuggling 취약점을 진단할 때 사용합니다.

![](assets/images/burp_intruder_http.png)

### Grep: 응답 데이터 정밀 분석 및 필터링 전략

수만 건의 요청을 보내는 Intruder 공격에서, 단순히 "보냈다"는 사실은 중요하지 않습니다. 중요한 것은 "어떤 응답이 다른가"를 식별하는 것입니다. Settings 탭(또는 구버전의 Options 탭)에 위치한 Grep 기능들은 수많은 응답 데이터 속에서 유의미한 신호(Signal)를 찾아내는 필터이자 탐지기입니다. 시니어 펜테스터는 육안 검사에 의존하지 않고, Grep 설정을 통해 공격 결과를 데이터화합니다.

#### Grep - Match: 이상 징후 탐지 (Flagging)

응답 본문에 특정 문자열이 포함되어 있는지를 검사하여 결과 테이블에 체크박스 형태로 표시합니다. HTTP 상태 코드(Status Code)만으로는 성공/실패 여부를 판단하기 어려울 때 가장 핵심적인 지표가 됩니다.

* **기능적 한계 극복**: 많은 웹 애플리케이션이 로그인 실패 시에도 200 OK를 반환하거나, 에러 발생 시 302 리다이렉션 대신 200 OK 페이지에 에러 메시지를 출력합니다. 이때 상태 코드 정렬은 무의미합니다.
* **핵심 활용 사례**:
    * **에러 메시지 탐지**: Fuzzing 시 `SQL syntax`, `ORA-`, `Exception`, `stack trace` 등의 키워드를 등록하여 SQL Injection이나 정보 노출 취약점을 식별합니다.
    * **성공/실패 판별**: 무차별 대입(Brute Force) 공격 시, 로그인 성공 시에만 나타나는 `Welcome`, `Logout`, `My Page` 등의 키워드를 등록하거나, 반대로 실패 시 나타나는 `Invalid password`를 등록하여 패턴이 다른 항목을 찾아냅니다.
* **설정 팁**:
    * **Case sensitive match**: 대소문자를 구분합니다. 정확도를 높이려면 체크하는 것이 좋지만, 개발자가 에러 메시지를 어떻게 작성했는지 모를 때는 해제하여 범용성을 높입니다.
    * **Exclude HTTP headers**: 헤더(쿠키 값 등)에 우연히 포함된 문자열로 인한 오탐(False Positive)을 줄이기 위해, 본문(Body)에서만 검사하도록 설정하는 것이 일반적입니다.

![](assets/images/burp_intruder_match.png)

#### Grep - Extract: 데이터 추출 및 마이닝

응답 데이터의 특정 부분을 추출하여 결과 테이블에 별도 컬럼으로 생성합니다. 단순한 탐지를 넘어 데이터를 수집(Harvesting)하거나 다음 공격의 재료로 사용할 때 필수적입니다.

* **동작 방식**: 'Define' 버튼을 눌러 응답 샘플에서 추출하고 싶은 영역을 드래그하면, Burp가 자동으로 시작(Start delimiter)과 끝(End delimiter) 문자열을 지정합니다. 복잡한 패턴의 경우 정규표현식(Regex)을 직접 작성할 수 있습니다.
* **핵심 활용 사례**:
    * **정보 유출 확인**: 에러 메시지 내부에 포함된 DB 버전 정보, 내부 IP 주소, 파일 경로 등을 목록화하여 보고서 작성 시 활용합니다.
    * **토큰 탈취**: 로그인 후 발급되는 Session ID, CSRF Token, API Key 등을 추출합니다.
    * **Recursive Grep 연동**: 여기서 추출한 데이터를 Payloads 탭의 'Recursive grep' 타입과 연동하여, 게시판 글쓰기나 비밀번호 변경처럼 CSRF 토큰이 필요한 시나리오를 자동화합니다.
* **주의사항**: 추출할 데이터의 최대 길이(Max length)를 설정하여, 불필요하게 긴 HTML 코드가 테이블에 로드되어 메모리를 낭비하지 않도록 제한해야 합니다.

![](assets/images/burp_intruder_extract.png)

#### Grep - Payloads: 반사(Reflection) 여부 검증

내가 보낸 페이로드가 응답 값에 그대로 포함되어 돌아오는지 확인합니다.

* **핵심 활용 사례**: **Reflected XSS (Cross-Site Scripting)** 취약점을 찾을 때 가장 강력합니다. 예를 들어, `<script>alert(1)</script>`를 페이로드로 보냈을 때, 응답 본문에 이 문자열이 그대로 존재한다면 XSS 가능성이 매우 높습니다.
* **동작 방식**: 고정된 문자열을 찾는 것이 아니라, *해당 요청에 사용된 페이로드*가 응답에 있는지를 동적으로 검사합니다.
* **Match against pre-URL-encoded payloads**: 페이로드가 URL 인코딩되어 전송되었더라도, 응답에는 디코딩되어 나타날 수 있습니다. 이 옵션을 켜면 인코딩 전의 원본 문자열을 기준으로 매칭을 시도하여 정확도를 높입니다.

![](assets/images/burp_intruder_payloads.png)

#### 시니어 엔지니어의 Grep 전략

Grep 설정은 "노이즈 제거"가 핵심입니다.

1.  공격 전, Repeater에서 정상 응답과 에러 응답을 미리 분석합니다.
2.  두 응답을 명확히 구분 짓는 유니크한 문자열(Unique String)을 찾아 Grep - Match에 등록합니다.
3.  단순히 존재 여부만 보는 것이 아니라, 'Invert match'(해당 문자열이 *없는* 경우 체크) 기능을 활용하여, 모든 페이지에 공통적으로 존재하는 푸터(Footer)나 카피라이트 문구가 깨지거나 사라지는 비정상적인 응답을 찾아내는 기법도 자주 사용됩니다.