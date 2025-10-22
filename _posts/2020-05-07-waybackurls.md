---
title: Waybackurls
tags: Waybackurls
key: page-waybackurls
categories: [Tools, Reconnaissance]
author: hyoeun
math: true
mathjax_autoNumber: true
---

## Waybackurls: Discovering Forgotten Paths for Reconnaissance

### Introduction to Waybackurls

During the reconnaissance phase of a penetration test, gathering as much information as possible about a target's web presence is crucial. While active scanning reveals the current state of an application, historical data can uncover forgotten assets, hidden endpoints, and sensitive information. **`waybackurls`** is a powerful Go-based tool designed for this exact purpose. It fetches known URLs for a given domain from various historical archives, including the Wayback Machine, Common Crawl, and VirusTotal.

For penetration testers and bug bounty hunters, `waybackurls` is an essential tool for expanding the attack surface by identifying legacy files, old API endpoints, and forgotten parameters that may still be vulnerable.

### Installation

Installing `waybackurls` is straightforward, provided you have the Go programming language environment set up.

```bash
go install github.com/tomnomnom/waybackurls@latest
```

Ensure that your Go bin directory (`$HOME/go/bin`) is included in your system's `PATH` to run the tool from anywhere.

### Basic Usage

The tool is designed to work with standard input and output, making it highly versatile for integration with other command-line utilities.

The most basic way to use it is by piping a domain name to the tool:

```bash
echo "example.com" | waybackurls
```

This command will output a list of all URLs associated with `example.com` and its subdomains that have been archived.

### Practical Reconnaissance Techniques

While a raw list of URLs is useful, the real power of `waybackurls` comes from filtering and analyzing its output to find actionable intelligence.

#### 1\. Discovering Sensitive Files and Endpoints

Historical archives often contain direct links to files that were never intended to be public or have since been forgotten. You can use `grep` to filter for interesting file extensions.

  * **Finding JavaScript files:** Old JS files can contain hardcoded API keys, outdated logic, or references to other hidden endpoints.

    ```bash
    echo "example.com" | waybackurls | grep "\.js$" | uniq
    ```

  * **Searching for documents and backups:** Look for potentially sensitive documents or configuration file backups.

    ```bash
    echo "example.com" | waybackurls | grep -E "\.(json|xml|txt|bak|zip|conf)$"
    ```

#### 2\. Identifying Potentially Vulnerable Parameters

Old URLs can reveal query parameters that are no longer used in the front-end application but might still be processed by the back-end. These parameters can be a goldmine for finding vulnerabilities like XSS, SQL injection, or open redirects.

```bash
echo "example.com" | waybackurls | grep "=" | uniq
```

After obtaining a list of URLs with parameters, you can use tools like `gf` to search for patterns indicative of specific vulnerabilities.

### Integration with Other Security Tools

The true strength of `waybackurls` is realized when you chain it with other tools in your workflow.

#### 1\. Checking for Live URLs with `httpx`

Many URLs found in archives may no longer be active. The `httpx` tool can quickly probe a list of URLs to see which ones are still live and return a valid response.

```bash
echo "example.com" | waybackurls | httpx -status-code -mc 200,301,302
```

This command filters the results to show only URLs that return a `200 OK`, `301 Moved Permanently`, or `302 Found` status code.

#### 2\. Pattern Matching for Vulnerabilities with `gf`

`gf` (grep from files) is a tool that allows you to search for common vulnerability patterns in text. By combining it with `waybackurls`, you can quickly identify potential weak points.

First, ensure you have `gf` and its patterns set up. Then, you can run commands like:

  * **Finding potential Open Redirects:**

    ```bash
    echo "example.com" | waybackurls | gf redirect
    ```

  * **Finding potential XSS vulnerabilities:**

    ```bash
    echo "example.com" | waybackurls | gf xss
    ```

  * **Finding potential SQL Injection points:**

    ```bash
    echo "example.com" | waybackurls | gf sqli
    ```

This automated approach allows you to efficiently sift through thousands of historical URLs to find promising targets for further investigation.

---

## Waybackurls: 정찰을 위한 잊혀진 경로 탐색

### Waybackurls 소개

침투 테스트의 정찰 단계에서는 대상의 웹 존재에 대한 최대한 많은 정보를 수집하는 것이 중요합니다. 능동적 스캐닝은 애플리케이션의 현재 상태를 보여주지만, 과거 데이터는 잊혀진 자산, 숨겨진 엔드포인트 및 민감한 정보를 발견할 수 있습니다. **`waybackurls`**는 바로 이러한 목적을 위해 설계된 강력한 Go 기반 도구입니다. 이 도구는 Wayback Machine, Common Crawl, VirusTotal 등 다양한 과거 아카이브에서 주어진 도메인에 대해 알려진 URL을 가져옵니다.

침투 테스터와 버그 바운티 헌터에게 `waybackurls`는 여전히 취약할 수 있는 레거시 파일, 오래된 API 엔드포인트, 잊혀진 매개변수를 식별하여 공격 표면을 확장하는 데 필수적인 도구입니다.

### 설치

Go 프로그래밍 언어 환경이 설정되어 있다면 `waybackurls` 설치는 간단합니다.

```bash
go install github.com/tomnomnom/waybackurls@latest
```

어디서든 도구를 실행할 수 있도록 Go bin 디렉터리(`$HOME/go/bin`)가 시스템의 `PATH`에 포함되어 있는지 확인하십시오.

### 기본 사용법

이 도구는 표준 입력 및 출력과 함께 작동하도록 설계되어 다른 명령줄 유틸리티와 통합하기에 매우 다재다능합니다.

가장 기본적인 사용 방법은 도메인 이름을 도구에 파이핑하는 것입니다.

```bash
echo "example.com" | waybackurls
```

이 명령은 `example.com` 및 그 하위 도메인과 관련된 아카이브된 모든 URL 목록을 출력합니다.

### 실용적인 정찰 기법

원시 URL 목록도 유용하지만, `waybackurls`의 진정한 힘은 실행 가능한 정보를 찾기 위해 출력을 필터링하고 분석하는 데서 나옵니다.

#### 1\. 민감한 파일 및 엔드포인트 발견

과거 아카이브에는 공개될 의도가 없었거나 잊혀진 파일에 대한 직접적인 링크가 포함된 경우가 많습니다. `grep`을 사용하여 흥미로운 파일 확장자를 필터링할 수 있습니다.

  * **자바스크립트 파일 찾기:** 오래된 JS 파일에는 하드코딩된 API 키, 오래된 로직 또는 다른 숨겨진 엔드포인트에 대한 참조가 포함될 수 있습니다.

    ```bash
    echo "example.com" | waybackurls | grep "\.js$" | uniq
    ```

  * **문서 및 백업 검색:** 잠재적으로 민감한 문서나 설정 파일 백업을 찾아보십시오.

    ```bash
    echo "example.com" | waybackurls | grep -E "\.(json|xml|txt|bak|zip|conf)$"
    ```

#### 2\. 잠재적으로 취약한 매개변수 식별

오래된 URL은 프런트엔드 애플리케이션에서는 더 이상 사용되지 않지만 백엔드에서는 여전히 처리될 수 있는 쿼리 매개변수를 드러낼 수 있습니다. 이러한 매개변수는 XSS, SQL 인젝션 또는 오픈 리디렉션과 같은 취약점을 찾는 데 금광이 될 수 있습니다.

```bash
echo "example.com" | waybackurls | grep "=" | uniq
```

매개변수가 있는 URL 목록을 얻은 후에는 `gf`와 같은 도구를 사용하여 특정 취약점을 나타내는 패턴을 검색할 수 있습니다.

### 다른 보안 도구와의 통합

`waybackurls`의 진정한 강점은 작업 흐름에서 다른 도구와 연계할 때 실현됩니다.

#### 1\. `httpx`로 활성 URL 확인

아카이브에서 발견된 많은 URL은 더 이상 활성 상태가 아닐 수 있습니다. `httpx` 도구는 URL 목록을 신속하게 탐색하여 어떤 URL이 여전히 활성 상태이고 유효한 응답을 반환하는지 확인할 수 있습니다.

```bash
echo "example.com" | waybackurls | httpx -status-code -mc 200,301,302
```

이 명령은 `200 OK`, `301 Moved Permanently` 또는 `302 Found` 상태 코드를 반환하는 URL만 표시하도록 결과를 필터링합니다.

#### 2\. `gf`로 취약점 패턴 매칭

`gf`(grep from files)는 텍스트에서 일반적인 취약점 패턴을 검색할 수 있는 도구입니다. 이를 `waybackurls`와 결합하면 잠재적인 약점을 신속하게 식별할 수 있습니다.

먼저, `gf`와 그 패턴이 설정되었는지 확인하십시오. 그런 다음 다음과 같은 명령을 실행할 수 있습니다.

  * **잠재적인 오픈 리디렉션 찾기:**

    ```bash
    echo "example.com" | waybackurls | gf redirect
    ```

  * **잠재적인 XSS 취약점 찾기:**

    ```bash
    echo "example.com" | waybackurls | gf xss
    ```

  * **잠재적인 SQL 인젝션 지점 찾기:**

    ```bash
    echo "example.com" | waybackurls | gf sqli
    ```

이러한 자동화된 접근 방식을 통해 수천 개의 과거 URL을 효율적으로 선별하여 추가 조사를 위한 유망한 대상을 찾을 수 있습니다.