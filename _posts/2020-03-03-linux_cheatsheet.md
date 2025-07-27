---
title: Linux Cheatshhe
tags: Linux
key: page-linux_cheatsheet
categories: [Tools, Penetration Testing]
author: hyoeun
math: true
mathjax_autoNumber: true
---

## 1\. File and Directory Navigation

Understanding the system's structure and finding important configuration files or hidden information is the most fundamental step.

### find

A powerful file search tool. It can find files based on various conditions such as name, permissions, and modification time.

  * **Find a file with a specific name**
    ```bash
    # Search for a file named "config.php" under the / path.
    # All error messages (2) are discarded (/dev/null) to cleanly see only the successful results.
    find / -name "config.php" 2>/dev/null
    ```
  * **Find files with SUID permissions set (can be exploited for privilege escalation)**
    ```bash
    # Find all files with the SUID bit set and output, ignoring errors.
    find / -perm -4000 -type f 2>/dev/null
    ```
  * **Find files modified within the last 24 hours**
    ```bash
    find / -mtime 0 2>/dev/null
    ```

### grep

Searches for specific strings (patterns) within file contents or command output. It is very useful for finding passwords in configuration files or tracing specific IPs in log files.

  * **Search for the 'password' string in configuration files (case-insensitive)**
    ```bash
    grep -i "password" /etc/nginx/*.conf
    ```
  * **View content excluding a specific word**
    ```bash
    # Output all logs from access.log excluding the IP 127.0.0.1
    grep -v "127.0.0.1" /var/log/access.log
    ```

-----

## 2\. Process Management

Used to check which programs are running on the current system with what permissions and to terminate suspicious processes.

### ps

Shows a list of currently running processes.

  * **Check all running processes on the system (including detailed information)**
    ```bash
    # e:"every" selects all processes, f:"full-format" displays all information
    ps -ef
    # Or BSD style (style that doesn't use a hyphen -), both serve the same purpose
    # a:"all" shows processes of all users, u:"user-oriented" displays detailed information, x: includes processes not connected to a terminal (daemons)
    ps aux
    ```
  * **Filter for specific application processes only**
    ```bash
    ps -ef | grep "apache2"
    ```

### kill

Terminates a specific process.

  * **Terminate a process normally using its PID**
    ```bash
    kill [PID]
    ```
  * **Forcibly terminate a process**
    ```bash
    kill -9 [PID]
    ```

-----

## 3\. Network Analysis

Used to check ports or connection statuses communicating with the outside and to perform simple data transfer tests.

### ss (or netstat)

Shows network sockets and connection statuses. It's a more modern tool than `netstat` and offers faster performance.

  * **Check all currently open TCP/UDP ports**
    ```bash
    # -l (listening), -n (numeric), -t (tcp), -u (udp), -p (process)
    ss -lntup
    ```

### curl / wget

Transfers data or downloads files through various protocols like HTTP/HTTPS.

  * **Check only the header information of a web page**
    ```bash
    curl -I http://example.com
    ```
  * **Attempt to download a vulnerable configuration file from a web server**
    ```bash
    wget http://example.com/backup/db_backup.sql
    ```

### nc (netcat)

Known as the "Swiss Army knife of networking," it can perform various tasks such as creating TCP/UDP connections, port scanning, and data transfer.

  * **Simple port scan**
    ```bash
    # Check if ports 80 and 443 are open on host 192.168.1.100
    # z:"zero-I/O mode" to check if the port is open, v:"verbose" to display detailed output
    nc -zv 192.168.1.100 80 443
    ```
  * **Set up a Reverse Shell listener (run on the attacker's PC)**
    ```bash
    # Wait for a connection on port 4444
    nc -lvnp 4444
    ```

-----

## 4\. User and Privilege Information

Essential for checking the current user's permissions and finding clues for privilege escalation.

### id / whoami

Shows the current user's ID and group memberships.

```bash
id
whoami
```

---

## 1. 파일 및 디렉터리 탐색

시스템의 구조를 파악하고 중요한 설정 파일이나 숨겨진 정보를 찾는 것은 가장 기본적인 단계입니다.

### find

강력한 파일 검색 도구입니다. 이름, 권한, 수정 시간 등 다양한 조건으로 파일을 찾을 수 있습니다.

* **특정 이름의 파일 찾기**
    ```bash
    # / 경로 아래에서 이름이 "config.php" 인 파일 검색
    # 오류 메시지(2)는 모두 버리고(/dev/null), 성공적인 결과만 깔끔하게 볼 수 있습니다.
    find / -name "config.php" 2>/dev/null
    ```
* **SUID 권한이 설정된 파일 찾기 (권한 상승에 악용될 수 있음)**
    ```bash
    # SUID 비트가 설정된 모든 파일을 찾아 에러는 무시하고 출력
    find / -perm -4000 -type f 2>/dev/null
    ```
* **최근 24시간 내에 수정된 파일 찾기**
    ```bash
    find / -mtime 0 2>/dev/null
    ```

### grep

파일 내용이나 명령어 출력 결과에서 특정 문자열(패턴)을 검색합니다. 설정 파일에서 비밀번호를 찾거나 로그 파일에서 특정 IP의 흔적을 찾을 때 매우 유용합니다.

* **설정 파일에서 'password' 문자열 검색 (대소문자 무시)**
    ```bash
    grep -i "password" /etc/nginx/*.conf
    ```
* **특정 단어를 제외한 내용 보기**
    ```bash
    # access.log에서 127.0.0.1 IP를 제외한 모든 로그 출력
    grep -v "127.0.0.1" /var/log/access.log
    ```

---

## 2. 프로세스 관리

현재 시스템에서 어떤 프로그램이 어떤 권한으로 실행되고 있는지 확인하고, 의심스러운 프로세스를 종료하는 데 사용됩니다.

### ps

현재 실행 중인 프로세스의 목록을 보여줍니다.

* **시스템에서 실행 중인 모든 프로세스 확인 (상세 정보 포함)**
    ```bash
    # e:"every"로 모든 프로세스 선택, f:"full-format"으로 모든 정보 표시
    ps -ef
    # 또는 BSD 스타일(하이픈 - 사용하지 않는 스타일), 둘다 같은 형식
    # a:"all" 모든 사용자의 프로세스 u:"user-oriented" 상세 정보 표시 x: 터미널에 연결되지 않은(데몬)까지 표시
    ps aux
    ```
* **특정 애플리케이션 프로세스만 필터링**
    ```bash
    ps -ef | grep "apache2"
    ```

### kill

특정 프로세스를 종료시킵니다.

* **PID를 이용하여 정상적으로 프로세스 종료**
    ```bash
    kill [PID]
    ```
* **프로세스 강제 종료**
    ```bash
    kill -9 [PID]
    ```

---

## 3. 네트워크 분석

외부와 통신하는 포트나 연결 상태를 확인하고, 간단한 데이터 전송 테스트를 수행할 수 있습니다.

### ss (또는 netstat)

네트워크 소켓 및 연결 상태를 보여줍니다. `netstat`보다 최신 도구이며 더 빠른 성능을 보입니다.

* **현재 열려있는 모든 TCP/UDP 포트 확인**
    ```bash
    # -l (listening), -n (numeric), -t (tcp), -u (udp), -p (process)
    ss -lntup
    ```

### curl / wget

HTTP/HTTPS 등 다양한 프로토콜을 통해 데이터를 전송하거나 파일을 다운로드합니다.

* **웹 페이지의 헤더 정보만 확인**
    ```bash
    curl -I http://example.com
    ```
* **웹 서버의 취약한 설정 파일 다운로드 시도**
    ```bash
    wget http://example.com/backup/db_backup.sql
    ```

### nc (netcat)

"네트워크의 스위스 아미 나이프"로 불리며, TCP/UDP 연결의 생성, 포트 스캔, 데이터 전송 등 다양한 작업을 수행할 수 있습니다.

* **간단한 포트 스캔**
    ```bash
    # 192.168.1.100 호스트의 80, 443 포트가 열려있는지 확인
    # z:"zero-I/O mode"로 포트 열렸는것 확인, v:"verbose" 디테일한 output 표시
    nc -zv 192.168.1.100 80 443
    ```
* **리버스 셸(Reverse Shell) 리스너 설정 (공격자 PC에서 실행)**
    ```bash
    # 4444 포트에서 연결을 기다림
    nc -lvnp 4444
    ```

---

## 4. 사용자 및 권한 확인

현재 사용자의 권한을 확인하고, 권한 상승의 실마리를 찾는 데 필수적입니다.

### id / whoami

현재 사용자의 ID와 소속 그룹 정보를 보여줍니다.

```bash
id
whoami
```