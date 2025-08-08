---
title: Browser Extension Penetration Test
tags: Browser-Extension
key: page-browser_extension_penetration_test
categories: [Cybersecurity, Web Security]
author: hyoeun
math: true
mathjax_autoNumber: true
---

## Browser Extension Security

Browser Extensions are powerful tools that extend the functionality of web browsers and enhance the user experience. From ad blockers to productivity tools and developer utilities, their variety is immense. However, behind these extensive capabilities lies the potential for **very high privileges** that can deeply interact with a user's web activities, simultaneously leading to significant security risks.

In this blog post, we will delve into the basic structure and operation of browser extensions (especially Chrome extensions), their core security element **Permissions**, and from a penetration testing perspective, their **main security risks and analysis considerations.**

### **1. Anatomy of a Browser Extension**

A browser extension is fundamentally a small web application composed of **JavaScript, HTML, and CSS.**

  * **Core File: `manifest.json`**
      * This is the **blueprint** and core configuration file of the extension.
      * It defines all components of the extension, such as its name, version, description, icon, and most importantly, the **required permissions**, background scripts, content scripts, and user interface (UI) files (popups, options pages).
  * **Background Scripts:**
      * These are JavaScript files responsible for the extension's core logic.
      * They respond to browser events (e.g., tab creation, page loading, network requests) and can directly access browser APIs (if permissions allow).
      * They can run persistently in the background, unseen by the user.
  * **Content Scripts:**
      * These are JavaScript files injected into the context of specific web pages.
      * They can access and manipulate the DOM (Document Object Model) of the injected web page and interact with the web page's JavaScript.
      * However, they run in an "Isolated World" from the web page's own JavaScript, meaning they cannot directly access each other's variables. Communication is only possible through message passing (`chrome.runtime.sendMessage`).
  * **User Interface (UI) Elements:**
      * **Popup:** A small HTML/CSS/JS page that appears when the extension icon in the browser toolbar is clicked.
      * **Options Page:** An HTML/CSS/JS page used to configure the extension's settings.
      * **Override Pages:** Replace default browser pages (e.g., New Tab page, Bookmarks page) with extension-specific pages.
  * **Packaging and File Location:**
      * Chrome extensions are typically distributed with a `.crx` file extension. This is a compressed package containing all the extension's files.
      * Installed extension files are stored in specific paths on the local computer. On Mac, a common location is:
        ```
        ~/Library/Application Support/Google/Chrome/Default/[Extension ID]/
        ```
        Here, `[Extension ID]` is a unique string ID assigned to each extension. Similar paths exist on Windows and Linux.

### **2. Permissions: The Heart of Extension Security**

Extension permissions define what operations the extension can perform on the browser and the system, making them the most critical security element. Users must explicitly review and consent to the requested permissions during extension installation.

  * **`host_permissions`:**
      * Grants the extension broad privileges over **specific websites (Hosts)**.
      * This allows interaction with powerful APIs like `cookies` (read/modify cookies for specific websites), `webRequest` (intercept, modify, block network requests), and `tabs` (access tab information, create/update tabs).
      * **Example:** `["https://*.example.com/*"]` grants access to all subdomains of `example.com`.
      * `"<all_urls>"`: The most powerful and dangerous permission, granting `host_permission` over all websites.
  * **`cookies`:**
      * Allows the extension to read, write, and delete HTTP/HTTPS cookies for specified hosts. Can be exploited for session hijacking or tracking.
  * **`webRequest`:**
      * One of the most powerful network-related permissions. Allows the extension to monitor, modify, block, or redirect network requests. Essential for ad blockers or VPN extensions, but can be misused to intercept or manipulate user traffic.
  * **`tabs`:**
      * Allows the extension to access information about browser tabs (URLs, titles, etc.), create new tabs, or update existing ones.
  * **`storage`:**
      * Used by the extension to persistently store its own data. `chrome.storage.local` stores data locally and persists even after the browser is closed. `chrome.storage.sync` synchronizes data across devices associated with the user's account.
      * **Difference from `localStorage`:** A webpage's `localStorage` is tied to that webpage's origin and does not disappear when the extension is removed; it remains tied to the page. In contrast, `chrome.storage.local` is the extension's own persistent storage, and by default, its data persists even if the extension is removed (so it can be restored upon reinstallation), unless the user explicitly clears extension data.
  * **`activeTab`:**
      * Grants temporary `host_permission` to the currently active tab when the user clicks the extension icon. This permission is much more limited in scope than requesting full `host_permissions`.

### **3. Potential Security Risks & Penetration Testing Considerations**

The powerful permissions of browser extensions make them attractive targets for attackers. Pentesters must understand the extension's security model and look for the following risk factors.

  * **Over-privileged Extensions:**
      * **Risk:** If an extension requests more permissions than its actual functionality requires (e.g., full access to all URLs, ability to modify all network requests), its compromise could lead to greater damage.
      * **Pentesting:** Analyze the `permissions` section of `manifest.json` to assess if requested permissions are excessive and devise scenarios to exploit such privileges.
  * **Insecure Data Storage (`chrome.storage` Misuse):**
      * **Risk:** If sensitive information (e.g., user credentials, API keys, PII) is stored unencrypted in `chrome.storage.local`, an attacker might extract these files and steal the information.
      * **Pentesting:** Locate the extension's local storage path (e.g., `~/Library/Application Support/Google/Chrome/Default/[ID]/Local Storage` for SQLite DB files or other storage files) and analyze them for plaintext sensitive data.
  * **Sensitive Data Leakage:**
      * **Risk:** If the extension collects user data and transmits it to malicious external servers, or inadvertently exposes sensitive network requests intercepted via the `webRequest` API.
      * **Pentesting:** Intercept the extension's network activity using a proxy (Burp Suite, etc.) and analyze all outgoing requests and their content (especially for PII, credentials).
  * **XSS/CSRF Vulnerabilities within the Extension Itself:**
      * **Risk:** If the extension's own UI pages (popup, options page), which are composed of HTML/JavaScript, have XSS or CSRF vulnerabilities, an attacker could exploit them to leverage the extension's privileges or launch phishing attacks against the user.
      * **Pentesting:** Apply general web application penetration testing techniques (input injection, CSRF token verification, etc.) to the extension's own UI pages.
  * **Privilege Escalation & Code Injection:**
      * **Risk:** If the extension's code has a vulnerability (e.g., arbitrary code execution), an attacker could exploit it to execute code within the extension's context, thereby gaining all of the extension's powerful permissions (e.g., `<all_urls>` permission).
      * **Pentesting:** Statically and dynamically analyze the extension's JavaScript code to find code injection vulnerabilities or logical flaws.
  * **Supply Chain Attacks:**
      * **Risk:** Malicious code could be injected into an extension through a compromised update, or a legitimate extension could be acquired by an attacker and transformed into a malicious one.
      * **Pentesting:** Analyze the extension's update mechanism and check its external libraries/dependencies for known vulnerabilities.
  * **Cross-Extension Communication Vulnerabilities:**
      * **Risk:** If there are security flaws in communication between multiple extensions or between an extension and a web page (via message passing), a malicious extension could intercept or manipulate sensitive information.
      * **Pentesting:** Verify if sensitive information is passed through `chrome.runtime.sendMessage` (or similar mechanisms) or if message origin validation is insufficient.

### **4. Best Practices for Secure Extension Development and Usage**

  * **Principle of Least Privilege:** Design the extension to request **only the minimum necessary permissions** for its functionality.
  * **Input Validation and Output Escaping:** When handling user input in the extension's own UI pages or content scripts, perform thorough validation and escaping to prevent web vulnerabilities like SQLi and XSS.
  * **Sensitive Data Encryption:** Any sensitive data stored in `chrome.storage.local` must be **encrypted** before storage.
  * **Secure Communication:** Always use HTTPS for communication with servers and ensure there's no logic to intercept or manipulate sensitive data via APIs like `webRequest`.
  * **Regular Security Audits and Penetration Testing:** Like any web application, extensions should undergo regular security reviews to identify and mitigate vulnerabilities.

-----

## 브라우저 확장 프로그램 보안

브라우저 확장 프로그램(Browser Extension)은 웹 브라우저의 기능을 확장하고 사용자 경험을 향상시키는 강력한 도구입니다. 광고 차단부터 생산성 도구, 개발자 유틸리티에 이르기까지 그 종류는 무궁무진합니다. 하지만 이러한 막강한 기능 뒤에는 사용자의 웹 활동에 깊숙이 개입할 수 있는 **매우 높은 권한**이 숨어 있으며, 이는 동시에 심각한 보안 위험으로 이어질 수 있습니다.

이 블로그 글에서는 브라우저 확장 프로그램(특히 Chrome 확장 프로그램)의 기본 구조와 작동 방식, 핵심 보안 요소인 **권한(Permissions)**, 그리고 펜테스팅 관점에서 **주요 보안 위험과 분석 고려 사항**을 심층적으로 다루겠습니다.

### **1. 브라우저 확장 프로그램의 해부학**

브라우저 확장 프로그램은 기본적으로 **JavaScript, HTML, CSS**로 구성된 작은 웹 애플리케이션입니다.

  * **핵심 파일: `manifest.json`**
      * 확장 프로그램의 **청사진(blueprint)**이자 코어 설정 파일입니다.
      * 확장 프로그램의 이름, 버전, 설명, 아이콘, 그리고 가장 중요한 **필요한 권한(Permissions)**, 배경 스크립트(Background Scripts), 콘텐츠 스크립트(Content Scripts), 사용자 인터페이스(UI) 파일(팝업, 옵션 페이지) 등의 모든 구성 요소를 정의합니다.
  * **배경 스크립트 (Background Scripts):**
      * 확장 프로그램의 핵심 로직을 담당하는 JavaScript 파일입니다.
      * 브라우저 이벤트(탭 생성, 페이지 로드, 네트워크 요청 등)에 반응하며, 브라우저 API(권한이 허용된 경우)에 직접 접근할 수 있습니다.
      * 사용자에게 보이지 않고 백그라운드에서 지속적으로 실행될 수 있습니다.
  * **콘텐츠 스크립트 (Content Scripts):**
      * 특정 웹 페이지의 컨텍스트(Context)에 주입되는 JavaScript 파일입니다.
      * 주입된 웹 페이지의 DOM(Document Object Model)에 접근하고 조작하며, 웹 페이지의 JavaScript와 상호작용할 수 있습니다.
      * 하지만 웹 페이지의 JavaScript와는 "격리된 세계(Isolated World)"에서 실행되므로, 직접적으로 서로의 변수에 접근할 수는 없습니다. 통신은 메시지 전달(`chrome.runtime.sendMessage`)을 통해서만 가능합니다.
  * **사용자 인터페이스 (UI) 요소:**
      * **팝업(Popup):** 브라우저 툴바의 확장 프로그램 아이콘을 클릭했을 때 나타나는 작은 HTML/CSS/JS 페이지입니다.
      * **옵션 페이지(Options Page):** 확장 프로그램의 설정을 변경하는 데 사용되는 HTML/CSS/JS 페이지입니다.
      * **오버라이드 페이지(Override Pages):** 기본 브라우저 페이지(예: 새 탭 페이지, 북마크 페이지)를 확장 프로그램 페이지로 대체합니다.
  * **패키지 및 파일 위치:**
      * Chrome 확장 프로그램은 보통 `.crx` 파일 확장자로 배포됩니다. 이는 확장 프로그램의 모든 파일을 포함하는 압축된 패키지입니다.
      * 설치된 확장 프로그램의 파일은 로컬 컴퓨터의 특정 경로에 저장됩니다. Mac의 경우 일반적인 위치는 다음과 같습니다.
        ```
        ~/Library/Application Support/Google/Chrome/Default/[확장 프로그램 ID]/
        ```
        여기서 `[확장 프로그램 ID]`는 각 확장 프로그램에 할당된 고유한 문자열 ID입니다. 윈도우즈나 리눅스에도 유사한 경로에 저장됩니다.

### **2. 권한 (Permissions): 확장 프로그램 보안의 심장**

확장 프로그램의 권한은 해당 확장 프로그램이 브라우저와 시스템에 대해 어떤 작업을 수행할 수 있는지를 정의하는 가장 중요한 보안 요소입니다. 사용자는 확장 프로그램 설치 시 요청하는 권한 목록을 명확히 확인하고 동의해야 합니다.

  * **`host_permissions`:**
      * 확장 프로그램이 **특정 웹사이트(Host)**에 대해 광범위한 권한을 가질 수 있게 합니다.
      * 이는 `cookies` (특정 웹사이트의 쿠키를 읽거나 수정), `webRequest` (네트워크 요청을 가로채거나 수정, 차단), `tabs` (탭 정보에 접근하거나 생성/업데이트)와 같은 강력한 API와 상호작용할 수 있도록 해줍니다.
      * **예시:** `["https://*.example.com/*"]`는 `example.com`의 모든 서브도메인에 접근 권한을 부여합니다.
      * `"<all_urls>"`: 모든 웹사이트에 대한 `host_permission`을 부여하는 가장 강력하고 위험한 권한입니다.
  * **`cookies`:**
      * 확장 프로그램이 지정된 호스트의 HTTP/HTTPS 쿠키를 읽고, 쓰고, 삭제할 수 있도록 합니다. 세션 하이재킹이나 트래킹에 악용될 수 있습니다.
  * **`webRequest`:**
      * 가장 강력한 네트워크 관련 권한 중 하나입니다. 확장 프로그램이 네트워크 요청을 모니터링하고, 수정하고, 차단하거나, 리다이렉션할 수 있도록 합니다. 광고 차단기, VPN 확장 프로그램 등에 필수적이지만, 악용될 경우 사용자 트래픽을 가로채거나 조작할 수 있습니다.
  * **`tabs`:**
      * 확장 프로그램이 브라우저의 탭 정보(URL, 제목 등)에 접근하거나, 새 탭을 생성하거나, 기존 탭을 업데이트할 수 있도록 합니다.
  * **`storage`:**
      * 확장 프로그램 자체의 데이터를 영구적으로 저장하는 데 사용되는 API입니다. `chrome.storage.local`은 로컬에 저장되며 브라우저를 닫아도 데이터가 유지됩니다. `chrome.storage.sync`는 사용자 계정에 동기화되어 여러 기기에서 데이터를 공유합니다.
      * **`localStorage`와의 차이점:** 일반 웹 페이지의 `localStorage`는 해당 웹 페이지의 출처(origin)에 종속되어 저장되며, 확장 프로그램이 제거되면 사라지는 것이 아니라 페이지에 남아있습니다. 반면 `chrome.storage.local`은 확장 프로그램 자체의 영구 저장 공간이며, 확장 프로그램이 제거되더라도 데이터는 기본적으로 유지되므로 (재설치 시 복원될 수 있도록), 사용자가 명시적으로 확장 프로그램 데이터를 지우지 않는 한 남아있을 수 있습니다.
  * **`activeTab`:**
      * 사용자가 확장 프로그램 아이콘을 클릭했을 때 현재 활성화된 탭에 대해 일시적으로 `host_permission`을 부여합니다. `host_permission` 전체를 요구하는 것보다 권한 범위가 훨씬 제한적입니다.

### **3. 잠재적 보안 위험 및 펜테스팅 고려 사항**

확장 프로그램의 강력한 권한은 공격자에게도 매력적인 목표가 됩니다. 펜테스터는 확장 프로그램의 보안 모델을 이해하고 다음과 같은 위험 요소들을 찾아내야 합니다.

  * **과도한 권한 (Over-privileged Extensions):**
      * **위험:** 확장 프로그램이 실제 기능에 필요하지 않은 권한(예: 모든 URL에 대한 접근, 모든 네트워크 요청 수정)을 요청하는 경우, 해당 확장 프로그램이 손상되면 더 큰 피해를 초래할 수 있습니다.
      * **펜테스팅:** `manifest.json`의 `permissions` 섹션을 분석하여 요청하는 권한이 과도한지 평가하고, 해당 권한을 악용할 수 있는 시나리오를 구상합니다.
  * **안전하지 않은 데이터 저장 (`chrome.storage` 오용):**
      * **위험:** `chrome.storage.local`에 민감한 정보(예: 사용자 자격 증명, API 키, PII)가 암호화되지 않은 채 저장되는 경우, 공격자가 해당 파일을 추출하여 정보를 탈취할 수 있습니다.
      * **펜테스팅:** 확장 프로그램의 로컬 저장소 경로를 찾아내어 (`~/Library/Application Support/Google/Chrome/Default/[ID]/Local Storage` 등) SQLite DB 파일이나 기타 저장 파일을 분석하여 민감 정보가 평문으로 저장되어 있는지 확인합니다.
  * **민감 정보 유출 (Data Leakage):**
      * **위험:** 확장 프로그램이 사용자 데이터를 수집하여 악의적인 외부 서버로 전송하는 경우, 또는 `webRequest` API를 통해 가로챈 민감한 네트워크 요청을 의도치 않게 외부에 노출하는 경우.
      * **펜테스팅:** 확장 프로그램의 네트워크 활동을 프록시(Burp Suite 등)로 가로채고, 외부로 전송되는 모든 요청과 그 내용(특히 PII, 자격 증명 등)을 분석합니다.
  * **확장 프로그램 자체의 XSS/CSRF 취약점:**
      * **위험:** 확장 프로그램의 팝업, 옵션 페이지 등 HTML/JavaScript로 구성된 자체 UI에 XSS나 CSRF 취약점이 있다면, 공격자가 이를 통해 확장 프로그램의 권한을 탈취하거나 사용자에게 피싱 공격을 수행할 수 있습니다.
      * **펜테스팅:** 확장 프로그램 자체의 UI 페이지에 대해 일반적인 웹 애플리케이션 펜테스팅 기법(입력값 주입, CSRF 토큰 확인 등)을 적용합니다.
  * **권한 상승 (Privilege Escalation) 및 코드 주입:**
      * **위험:** 확장 프로그램의 코드에 취약점(예: 임의 코드 실행)이 있다면, 공격자가 이를 통해 확장 프로그램의 컨텍스트 내에서 코드를 실행하고, 확장 프로그램이 가진 모든 강력한 권한(예: `<all_urls>` 권한)을 획득할 수 있습니다.
      * **펜테스팅:** 확장 프로그램의 JavaScript 코드를 정적/동적으로 분석하여 코드 주입 취약점이나 논리적 오류를 찾습니다.
  * **공급망 공격 (Supply Chain Attacks):**
      * **위험:** 악의적인 업데이트를 통해 확장 프로그램에 악성 코드가 삽입되거나, 합법적인 확장 프로그램이 공격자에게 인수되어 악성 코드로 변환되는 경우.
      * **펜테스팅:** 확장 프로그램의 업데이트 메커니즘을 분석하고, 외부 라이브러리/의존성에 알려진 취약점이 있는지 확인합니다.
  * **크로스-확장 프로그램 통신 취약점:**
      * **위험:** 여러 확장 프로그램 간의 통신이나 웹 페이지와의 메시지 통신에 보안 허점이 있다면, 악의적인 확장 프로그램이 민감한 정보를 가로채거나 조작할 수 있습니다.
      * **펜테스팅:** `chrome.runtime.sendMessage` 등을 통한 통신에 민감 정보가 포함되거나, 메시지 출처 검증이 미흡한지 확인합니다.

### **4. 안전한 확장 프로그램 개발 및 사용을 위한 모범 사례**

  * **최소 권한 원칙 (Principle of Least Privilege):** 확장 프로그램이 필요한 **최소한의 권한**만을 요청하도록 설계합니다.
  * **입력 유효성 검사 및 출력 인코딩:** 확장 프로그램의 자체 UI 페이지나 콘텐츠 스크립트에서 사용자 입력을 처리할 때, SQLi, XSS 등의 웹 취약점을 방지하기 위해 철저한 유효성 검사와 인코딩을 수행합니다.
  * **민감 정보 암호화:** `chrome.storage.local`에 저장되는 민감한 데이터는 반드시 암호화하여 저장합니다.
  * **안전한 통신:** 서버와의 통신은 항상 HTTPS를 사용하고, `webRequest` API 등을 통해 민감한 데이터를 가로채거나 조작하는 로직이 없는지 확인합니다.
  * **정기적인 보안 감사 및 펜테스팅:** 확장 프로그램도 일반 웹 애플리케이션과 마찬가지로 정기적인 보안 점검을 통해 취약점을 식별하고 개선해야 합니다.