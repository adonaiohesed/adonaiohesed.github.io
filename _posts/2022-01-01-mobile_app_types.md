---
title: Types of Mobile App
tags: Mobile
key: page-mobile_app_types
categories: [Cybersecurity, Mobile Security]
author: hyoeun
math: true
mathjax_autoNumber: true
---

The three main approaches to mobile application development are **Native**, **Cross-Platform**, and **Hybrid** apps. Each method has its unique characteristics, advantages, disadvantages, and security considerations.

## Native Apps

Native apps are applications developed for a specific operating system (OS), such as iOS (Swift or Objective-C) and Android (Kotlin or Java).

**Technical Characteristics:**

  * **Performance:** They offer the best performance and user experience by directly leveraging the OS's native features.
  * **Accessibility:** They have full access to and control over all of the device's hardware and software features (e.g., camera, GPS, sensors).
  * **Development:** A separate codebase must be maintained for each platform, meaning iOS and Android apps are developed independently.

**Security Vulnerability Types:**

  * **Insufficient Obfuscation:** The source code can be exposed through **decompilation**, which can easily reveal sensitive logic or **API keys**.
  * **Local Data Storage Security:** If sensitive information (e.g., user authentication tokens) is stored unencrypted in local storage like SQLite databases or Shared Preferences, it can be stolen by an attacker with root privileges.
  * **JNI/NDK Security Issues:** Native code written in C/C++ can be vulnerable to memory management errors (like buffer overflows), which can lead to application crashes or remote code execution.

-----

## Cross-Platform Apps

Cross-platform apps are developed using a single codebase to run on multiple operating systems. Examples include **Flutter** (Dart) and **React Native** (JavaScript).

**Technical Characteristics:**

  * **Development Efficiency:** A single codebase allows for simultaneous development of both iOS and Android apps, reducing development time and costs.
  * **Performance:** They offer performance that is very similar to native apps, although some overhead may occur with complex graphics or when using deep OS features.
  * **Accessibility:** While they support most device features, there can be a delay in supporting new OS features until the native SDKs are updated.

**Security Vulnerability Types:**

  * **Third-Party Library Dependencies:** The use of various libraries means the entire app can be exposed to risks from vulnerabilities or malicious code within the libraries themselves.
  * **Obfuscation and Encryption Issues:** Frameworks like JavaScript-based React Native can be more difficult to obfuscate than native code, making sensitive information like API keys easier to expose.
  * **Cross-Platform Logic Errors:** Because a single codebase is used, bugs or security vulnerabilities that only occur on a specific OS can be overlooked.

-----

## Hybrid Apps

Hybrid apps are developed using web technologies (HTML, CSS, JavaScript) and are executed within a native application container, a **WebView**. Examples include Apache Cordova and Ionic.

**Technical Characteristics:**

  * **Ease of Development:** Web developers can easily create mobile apps.
  * **Code Reusability:** Most of the code for a website and a mobile app can be shared.
  * **Performance:** Because they use a WebView, performance is generally lower and the user experience can be more limited compared to native or cross-platform apps.

**Security Vulnerability Types:**

  * **WebView Vulnerabilities:** Web vulnerabilities such as JavaScript injection and **XSS** (Cross-Site Scripting) can occur within the WebView. These can be exploited by attackers to access user data or execute malicious scripts.
  * **Insufficient Local File Access Control:** If the WebView is configured to access the local file system, an attacker could exploit a web vulnerability to access files.
  * **Authentication and Session Management:** Due to the use of web-based authentication, they can be more susceptible to attacks like **session hijacking** compared to native apps.

-----

## The Relationship Between Native Apps and Web Vulnerabilities

### Unique Mobile App Vulnerabilities

Mobile apps, by their nature, do not directly rely on web technologies and are therefore inherently free from web vulnerabilities like XSS and CSRF. While web security focuses on vulnerabilities that arise from server communication (e.g., **SQL Injection**, **XSS**), mobile apps are more susceptible to attacks that exploit data and logic present on the user's device itself. This section delves into the unique vulnerabilities of mobile apps and provides examples of real-world threats.

### The Root Cause of Mobile App's Unique Vulnerabilities

Mobile app vulnerabilities stem from the following characteristics:

  * **Client-Side Environment:** A mobile app is installed and runs on the user's device. This means an attacker can directly access the app's file system, memory, and internal logic.
  * **Offline Functionality:** Many apps can perform some functions without a network connection. During this process, critical business logic or sensitive data is stored client-side, making it a target for attackers.
  * **File System Access:** An app can store data on the device's local file system and access various hardware features (GPS, camera, etc.).

These characteristics expose mobile apps to a different set of attacks compared to web applications.

### Key Unique Mobile App Vulnerabilities

#### 1\. Insecure Data Storage

This is one of the most common vulnerabilities. It occurs when an app stores sensitive data like usernames, passwords, API tokens, and session information in local storage without proper encryption. An attacker with a rooted or jailbroken device can access the file system and steal this information.

**Android Example (Java)**

This is an example of vulnerable code that stores a user token in `SharedPreferences` in plaintext.

```java
SharedPreferences sharedPref = getSharedPreferences("MyPrefs", Context.MODE_PRIVATE);
SharedPreferences.Editor editor = sharedPref.edit();
editor.putString("user_token", "MySecretToken12345");
editor.apply();
```

The value stored by this code is easily exposed in the `/data/data/com.example.myapp/shared_prefs/MyPrefs.xml` file as plaintext XML.

#### 2\. Reverse Engineering and Code Tampering

Attackers can decompile an app's APK (Android) or IPA (iOS) file to analyze its source code. This process, known as **reverse engineering**, can reveal hardcoded API keys, sensitive business logic, or weak encryption algorithms.

For example, an attacker can use a tool like JADX to decompile an Android app's DEX file into Java code, understand its key logic, and then bypass or modify the app's behavior.

**Android Reverse Engineering Scenario**

1.  **Obtain the APK File:** Download the app's APK file from an app store.
2.  **Decompile:** Use JADX to convert the APK file into Java code.
3.  **Analyze the Code:** Analyze the converted code to identify payment logic, ad removal logic, permission validation logic, and more.
4.  **Tamper:** Use a dynamic analysis tool like **Frida** to change the return value of a specific method at runtime or skip logic to **tamper with the code**.

#### 3\. Client-Side Logic Vulnerabilities

Some apps handle critical business logic on the client side without server-side validation. For instance, if an app changes a value like `isPremium = true` on the client side when a user purchases premium content, an attacker can manipulate this value to access paid features for free.

#### 4\. Weak Cryptography

While mobile apps use encryption to protect data, improper implementation can lead to serious vulnerabilities.

  * **Hardcoded Encryption Keys:** If the encryption key is hardcoded in the source code, it can be exposed through reverse engineering.
  * **Weak Cryptographic Algorithms:** Using outdated hash functions like MD5 or SHA1, or weak encryption modes like ECB (Electronic Codebook), can make encrypted data easy to decrypt.
  * **Improper Key Management:** Mistakes can occur, such as storing the encryption key in a general file on the device instead of in a secure key store.

-----

## Web Vulnerabilities Applicable to Mobile Apps

However, when a mobile app uses a **WebView** to display web content, web vulnerabilities can arise within that WebView. Since mobile apps also communicate with a backend server, server-side web vulnerabilities can apply to the mobile environment as well.

  * **SQL Injection:** If user input is not handled securely in a query, it can lead to attacks on the database.
  * **OS Command Injection:** If user input is used directly in OS commands, it can be exploited to gain control of the server.
  * **Authentication and Session Management Vulnerabilities:** If server-side session management is improper, the app can be exposed to attacks like **session hijacking**.
  * **XXE (XML External Entity) Injection:** If an app uses XML to communicate with a server, insecure XML parser settings can lead to file system access or Denial-of-Service (DoS) attacks.

## How to Identify if a Mobile App Uses a WebView

Determining whether a mobile app uses a WebView is a critical first step in security analysis. The presence of a WebView dictates the scope and focus of the penetration test. This article covers both static and dynamic analysis methods to identify WebView usage in Android and iOS apps.

### 1\. Static Analysis

Static analysis involves analyzing the app package file (APK or IPA) without running the app.

#### Android

You can check for WebView usage in an Android app by analyzing its manifest file and code.

  * **Analyze AndroidManifest.xml:** Check the app's `AndroidManifest.xml` file for any declared activities or permissions related to `WebView`. Apps that use a WebView often request the internet permission (`android.permission.INTERNET`).

    ```xml
    <uses-permission android:name="android.permission.INTERNET" />
    ```

  * **Analyze Decompiled Code:** Use a decompiler like JADX to analyze the app's source code. Search for the use of the `android.webkit.WebView` class. Finding any of the following keywords indicates a high probability of WebView usage:

      * `new WebView(...)`
      * `WebView.loadUrl(...)`
      * `addJavascriptInterface(...)`
      * `setWebViewClient(...)`
      * `WebSettings`

    Example:

    ```java
    import android.webkit.WebView;
    import android.webkit.WebViewClient;
    ...
    WebView myWebView = (WebView) findViewById(R.id.webview);
    myWebView.loadUrl("https://www.example.com");
    ```

#### iOS

For iOS apps, you can find traces of WebView usage in the binary file and project structure.

  * **Analyze the Binary:** Use command-line tools like `otool` or `nm` to search the app's binary for references to WebView-related frameworks or classes. iOS uses the `UIWebView` (older) or `WKWebView` (newer) class.

    ```bash
    otool -L /path/to/app/binary | grep -E 'WebKit|WebCore'
    ```

  * **Search Class and Method Names:** Use tools like `class-dump` or `ghidra` to search the list of classes and methods in the app's binary for keywords like `UIWebView` or `WKWebView`.

    ```objective-c
    // Example: UIWebView usage
    @interface UIWebView : UIView
    - (void)loadRequest:(NSURLRequest *)request;
    @end
    ```

### 2\. Dynamic Analysis

Dynamic analysis involves running the app on an actual device or emulator and observing its behavior.

#### Traffic Analysis

While using a proxy tool (Burp Suite, OWASP ZAP) to intercept the app's network traffic is a useful method, not all HTTP/HTTPS communication indicates a WebView. The key is to distinguish between native API communication and WebView communication.

  * **URL Pattern and Content Type Analysis:** A WebView communicates with a standard web server and often displays URL patterns that represent a webpage structure, such as `/login.html`, `/product.css`, or `/script.js`. If the `Content-Type` header in the traffic is `text/html`, `text/css`, or `application/javascript`, it's highly likely a WebView is being used. In contrast, native app API communication typically uses content types like `application/json` or `application/x-www-form-urlencoded` and follows a specific API endpoint pattern, such as `/api/v1/users` or `/data/sync`.

#### Runtime Analysis

Using a dynamic instrumentation tool like Frida to hook the app's runtime behavior is the most reliable way to confirm WebView usage.

  * **Method Hooking:** You can check if WebView-related methods (`WebView.loadUrl()`, `WKWebView loadRequest:`) are actually called during the app's runtime. It's possible to write a hooking script for these methods to capture the moment a specific URL is loaded. This is highly effective as it can detect WebView usage even if it's running in the background.

    **Android (Frida)**

    ```javascript
    Java.perform(function() {
        var WebView = Java.use("android.webkit.WebView");
        WebView.loadUrl.overload('java.lang.String').implementation = function(url) {
            console.log("[*] WebView.loadUrl() called with URL: " + url);
            this.loadUrl(url);
        };
    });
    ```

    **iOS (Frida)**

    ```javascript
    var WKWebView = ObjC.classes.WKWebView;
    if (WKWebView) {
        Interceptor.attach(WKWebView['- loadRequest:'].implementation, {
            onEnter: function(args) {
                var request = new ObjC.Object(args[2]);
                var url = request.URL().toString();
                console.log("[*] WKWebView.loadRequest() called with URL: " + url);
            }
        });
    }
    ```

---

모바일 애플리케이션 개발 방식은 크게 세 가지로 나눌 수 있습니다: **네이티브(Native) 앱**, **크로스 플랫폼(Cross-Platform) 앱**, 그리고 **하이브리드(Hybrid) 앱**입니다. 각 방식은 고유한 특징, 장단점, 그리고 보안적 고려 사항을 가집니다.

## 네이티브(Native) 앱

네이티브 앱은 iOS(Swift 또는 Objective-C)와 안드로이드(Kotlin 또는 Java)와 같은 특정 운영 체제(OS)를 위해 개발된 애플리케이션입니다.

**기술적 특징:**

* **성능:** OS의 기능을 직접적으로 활용하므로 최고의 성능과 사용자 경험을 제공합니다.
* **접근성:** 디바이스의 모든 하드웨어 및 소프트웨어 기능(예: 카메라, GPS, 센서)에 완벽하게 접근하고 제어할 수 있습니다.
* **개발:** 각 플랫폼별로 별도의 코드베이스를 유지해야 합니다. 즉, iOS 앱과 안드로이드 앱을 따로 개발해야 합니다.

**보안 취약점 유형:**

* **코드 난독화(Obfuscation) 미흡:** 디컴파일(decompile)을 통해 소스 코드가 노출될 수 있으므로, 민감한 로직이나 API 키가 쉽게 드러날 수 있습니다.
* **로컬 데이터 저장소 보안:** SQLite 데이터베이스나 Shared Preferences와 같은 로컬 저장소에 민감한 정보(사용자 인증 토큰 등)를 암호화하지 않고 저장할 경우, 루트(root) 권한이 있는 공격자에게 탈취될 수 있습니다.
* **JNI/NDK 보안 문제:** C/C++로 작성된 네이티브 코드는 메모리 관리 오류(버퍼 오버플로우 등)에 취약할 수 있으며, 이는 애플리케이션 충돌 또는 원격 코드 실행으로 이어질 수 있습니다.

---

## 크로스 플랫폼(Cross-Platform) 앱

크로스 플랫폼 앱은 단일 코드베이스를 사용하여 여러 OS에서 실행되는 애플리케이션을 개발하는 방식입니다. 대표적인 예시로는 Flutter(Dart)와 React Native(JavaScript)가 있습니다.

**기술적 특징:**

* **개발 효율성:** 하나의 코드로 iOS와 안드로이드 앱을 동시에 개발할 수 있어 개발 시간과 비용을 절감할 수 있습니다.
* **성능:** 네이티브 앱과 거의 유사한 성능을 제공하지만, 복잡한 그래픽 처리나 OS 심층 기능 사용 시 약간의 오버헤드가 발생할 수 있습니다.
* **접근성:** 대부분의 디바이스 기능을 지원하지만, 새로운 OS 기능이 출시될 경우 네이티브 SDK 업데이트까지 시간이 소요될 수 있습니다.

**보안 취약점 유형:**

* **제3자 라이브러리 의존성:** 다양한 라이브러리를 사용하기 때문에, 라이브러리 자체의 취약점이나 악성 코드로 인해 앱 전체가 위험에 노출될 수 있습니다.
* **난독화(Obfuscation) 및 암호화 문제:** JavaScript 기반의 React Native와 같은 프레임워크는 네이티브 코드보다 난독화가 어려울 수 있으며, API 키와 같은 민감 정보가 쉽게 노출될 수 있습니다.
* **플랫폼 간 로직 오류:** 단일 코드베이스를 사용하기 때문에 특정 OS에서만 발생하는 버그나 보안 취약점을 놓칠 수 있습니다.

---

## 하이브리드(Hybrid) 앱

하이브리드 앱은 웹 기술(HTML, CSS, JavaScript)을 사용하여 개발하며, 이를 네이티브 애플리케이션 컨테이너(WebView)에 담아 실행합니다. 대표적인 예시로는 Apache Cordova, Ionic 등이 있습니다.

**기술적 특징:**

* **개발 용이성:** 웹 개발자가 쉽게 모바일 앱을 만들 수 있습니다.
* **코드 재사용:** 웹사이트와 모바일 앱의 코드 대부분을 공유할 수 있습니다.
* **성능:** 웹뷰(WebView)를 사용하기 때문에 네이티브 앱이나 크로스 플랫폼 앱에 비해 성능이 낮고, 사용자 경험이 제한적일 수 있습니다.

**보안 취약점 유형:**

* **웹뷰(WebView) 취약점:** 웹 콘텐츠가 로드되는 WebView에서 JavaScript 인젝션, XSS(Cross-Site Scripting) 등의 웹 취약점이 발생할 수 있습니다. 이는 공격자가 사용자 데이터에 접근하거나 악성 스크립트를 실행하는 데 악용될 수 있습니다.
* **로컬 파일 접근 제어 미흡:** 웹뷰가 로컬 파일 시스템에 접근할 수 있도록 설정된 경우, 공격자가 웹 취약점을 통해 파일에 접근할 수 있습니다.
* **인증 및 세션 관리:** 웹 기반 인증 방식을 사용하기 때문에, 네이티브 앱에 비해 세션 하이재킹과 같은 공격에 더 취약할 수 있습니다.

---

## 네이티브 앱과 웹 취약점의 관계

## 모바일 앱 고유의 취약점

**모바일 앱**은 기본적으로 웹 기술에 의존하지 않으므로, **XSS**나 **CSRF** 같은 웹 취약점에서 직접적으로 자유롭습니다. 웹은 주로 서버와의 통신 과정에서 발생하는 취약점(예: SQL 인젝션, XSS)에 집중하는 반면, 모바일 앱은 사용자의 기기 자체에 존재하는 데이터와 로직을 악용하는 공격에 더 취약합니다. 이 글에서는 모바일 앱만이 가지는 고유한 취약점들을 심층적으로 분석하고, 실제 보안 위협의 예시를 제시합니다.

## 모바일 앱 고유 취약점의 근본 원인

모바일 앱의 취약점은 다음과 같은 특성에서 기인합니다.

  * **클라이언트 측 환경**: 모바일 앱은 사용자의 기기에 설치되어 동작합니다. 이는 공격자가 앱의 파일 시스템, 메모리, 내부 로직에 직접 접근할 수 있음을 의미합니다.
  * **오프라인 작동 가능성**: 많은 앱이 네트워크 연결 없이도 일부 기능을 수행합니다. 이 과정에서 중요한 비즈니스 로직이나 민감 데이터가 클라이언트 측에 저장되는데, 이는 공격의 대상이 됩니다.
  * **파일 시스템 접근**: 앱은 기기 내의 로컬 파일 시스템에 데이터를 저장하고, 디바이스의 다양한 하드웨어 기능(GPS, 카메라 등)에 접근할 수 있습니다.

이러한 특성으로 인해 모바일 앱은 웹과는 다른 형태의 공격에 노출됩니다.

## 주요 모바일 앱 고유 취약점

### 1\. 부적절한 데이터 저장 (Insecure Data Storage)

가장 흔하게 발견되는 취약점 중 하나입니다. 앱이 사용자 이름, 비밀번호, API 토큰, 세션 정보와 같은 민감 데이터를 암호화하지 않거나, 쉽게 접근 가능한 형태로 로컬 저장소에 저장할 때 발생합니다. 공격자는 루팅되거나 탈옥된 기기에서 파일 시스템에 접근하여 이 정보를 탈취할 수 있습니다.

**안드로이드 예시 (Java)**

다음은 `SharedPreferences`에 사용자 토큰을 평문으로 저장하는 취약한 코드입니다.

```java
SharedPreferences sharedPref = getSharedPreferences("MyPrefs", Context.MODE_PRIVATE);
SharedPreferences.Editor editor = sharedPref.edit();
editor.putString("user_token", "MySecretToken12345");
editor.apply();
```

위 코드로 저장된 값은 `/data/data/com.example.myapp/shared_prefs/MyPrefs.xml` 경로에 평문 XML 파일로 저장되어 쉽게 노출됩니다.

### 2\. 역공학 (Reverse Engineering) 및 코드 변조 (Code Tampering)

공격자는 앱의 APK(Android) 또는 IPA(iOS) 파일을 디컴파일하여 소스 코드를 분석할 수 있습니다. 이를 **역공학**이라 부르며, 이 과정을 통해 하드코딩된 API 키, 민감한 비즈니스 로직, 취약한 암호화 알고리즘 등을 찾아낼 수 있습니다.

예를 들어, 공격자는 JADX와 같은 도구를 사용하여 안드로이드 앱의 DEX 파일을 Java 코드로 디컴파일하고, 중요한 로직을 파악하여 앱의 동작을 우회하거나 변조할 수 있습니다.

**안드로이드 역공학 시나리오**

1.  **APK 파일 획득**: 앱 스토어에서 앱의 APK 파일을 다운로드합니다.
2.  **디컴파일**: JADX를 사용하여 APK 파일을 Java 코드로 변환합니다.
3.  **코드 분석**: 변환된 코드를 분석하여 결제 로직, 광고 제거 로직, 권한 검증 로직 등을 파악합니다.
4.  **변조**: Frida와 같은 동적 분석 도구를 사용하여 런타임에 특정 메서드의 반환값을 변경하거나, 로직을 건너뛰도록 **코드 변조**를 시도합니다.

### 3\. 클라이언트 측 로직 취약점 (Client-Side Logic Vulnerabilities)

일부 앱은 서버의 검증 없이 클라이언트 앱 자체에서 중요한 비즈니스 로직을 처리합니다. 예를 들어, 사용자가 유료 콘텐츠를 구매할 때, 클라이언트 앱에서 단순히 `isPremium = true`와 같은 값을 변경하는 로직이 있다면, 공격자는 이 값을 조작하여 유료 기능을 무단으로 사용할 수 있습니다.

### 4\. 취약한 암호화 (Weak Cryptography)

모바일 앱은 데이터 보호를 위해 암호화를 사용하지만, 부적절한 방식으로 구현될 경우 심각한 취약점이 될 수 있습니다.

  * **하드코딩된 암호화 키**: 암호화에 사용되는 키가 코드 내에 하드코딩되어 있다면, 역공학을 통해 키가 노출될 수 있습니다.
  * **약한 암호화 알고리즘**: MD5나 SHA1과 같이 이미 안전하지 않은 해시 함수나 ECB(Electronic Codebook) 모드와 같은 취약한 암호화 모드를 사용하는 경우, 암호화된 데이터를 쉽게 해독할 수 있습니다.
  * **적절하지 않은 키 관리**: 키를 안전하게 저장하지 않고, 기기 내의 일반 파일에 저장하는 등의 실수가 발생할 수 있습니다.

---

## 모바일 앱에 적용되는 웹 취약점

그러나 모바일 앱 내에서 웹 콘텐츠를 표시하기 위해 **WebView**를 사용하는 경우, 해당 WebView 영역에서는 웹 취약점이 발생할 수 있습니다. 모바일 앱도 백엔드 서버와 통신하므로, 서버 측에서 발생하는 웹 취약점은 모바일 환경에서도 동일하게 적용될 수 있습니다.

* **SQL Injection:** 사용자 입력 값을 포함한 쿼리를 안전하게 처리하지 않으면 데이터베이스에 대한 공격이 가능해집니다.
* **OS Command Injection:** 사용자 입력 값을 OS 명령어에 직접 사용하는 경우, 서버를 제어하는 데 악용될 수 있습니다.
* **인증 및 세션 관리 취약점:** 서버 측의 세션 관리가 부적절할 경우, **세션 하이재킹**과 같은 공격에 노출될 수 있습니다.
* **XXE(XML External Entity) Injection:** 앱이 XML을 사용하여 서버와 통신할 때, 안전하지 않은 XML 파서 설정은 시스템 파일 접근이나 DoS 공격으로 이어질 수 있습니다.

## 모바일 앱 웹뷰 사용 여부 확인 방법

모바일 앱이 웹뷰를 사용하는지 여부를 확인하는 것은 보안 분석의 첫 단계에서 중요합니다. 웹뷰의 존재 여부에 따라 테스트 범위와 중점이 달라지기 때문입니다. 이 글에서는 안드로이드와 iOS 앱을 대상으로 웹뷰 사용을 식별하는 정적 및 동적 분석 방법을 다룹니다.

### 1\. 정적 분석 (Static Analysis)

정적 분석은 앱을 실행하지 않고 패키지 파일(APK 또는 IPA)을 분석하는 방법입니다.

#### 안드로이드 (Android)

안드로이드 앱은 웹뷰 사용 여부를 Manifest 파일과 코드에서 확인할 수 있습니다.

  * **AndroidManifest.xml 분석**: 앱의 `AndroidManifest.xml` 파일을 확인하여 `WebView`와 관련된 액티비티나 권한이 선언되었는지 찾습니다. 웹뷰를 사용하는 앱은 종종 인터넷 권한(`android.permission.INTERNET`)을 요청합니다.

    ```xml
    <uses-permission android:name="android.permission.INTERNET" />
    ```

  * **디컴파일된 코드 분석**: JADX와 같은 디컴파일러를 사용하여 앱의 소스 코드를 분석합니다. 코드에서 `android.webkit.WebView` 클래스의 사용 여부를 검색합니다. 다음과 같은 키워드를 찾으면 웹뷰를 사용하고 있을 가능성이 매우 높습니다.

      * `new WebView(...)`
      * `WebView.loadUrl(...)`
      * `addJavascriptInterface(...)`
      * `setWebViewClient(...)`
      * `WebSettings`

    예시:

    ```java
    import android.webkit.WebView;
    import android.webkit.WebViewClient;
    ...
    WebView myWebView = (WebView) findViewById(R.id.webview);
    myWebView.loadUrl("https://www.example.com");
    ```

#### iOS (iOS)

iOS 앱의 경우, 바이너리 파일과 프로젝트 구조에서 웹뷰 사용 흔적을 찾을 수 있습니다.

  * **바이너리 분석**: `otool` 또는 `nm`과 같은 명령줄 도구를 사용하여 앱 바이너리에서 웹뷰 관련 프레임워크나 클래스 참조를 검색합니다. iOS에서는 `UIWebView` (구형) 또는 `WKWebView` (신형) 클래스를 사용합니다.

    ```bash
    otool -L /path/to/app/binary | grep -E 'WebKit|WebCore'
    ```

  * **클래스 및 메서드 이름 검색**: `class-dump`나 `ghidra`와 같은 도구를 사용하여 앱 바이너리의 클래스 및 메서드 목록에서 `UIWebView` 또는 `WKWebView`와 같은 키워드를 검색합니다.

    ```objective-c
    // 예시: UIWebView 사용 흔적
    @interface UIWebView : UIView
    - (void)loadRequest:(NSURLRequest *)request;
    @end
    ```

### 2\. 동적 분석 (Dynamic Analysis)

동적 분석은 앱을 실제 기기나 에뮬레이터에서 실행하여 동작을 관찰하는 방법입니다.

#### 트래픽 분석 (Traffic Analysis)

프록시 도구(Burp Suite, OWASP ZAP)를 사용하여 앱의 네트워크 트래픽을 가로채는 것은 매우 유용한 방법이지만, 모든 HTTP/HTTPS 통신이 웹뷰를 의미하는 것은 아닙니다. 네이티브 API 통신과 웹뷰 통신을 구분하는 것이 핵심입니다.

  * **URL 패턴 및 콘텐츠 유형 분석**: 웹뷰는 일반적인 웹 서버와 통신하며, 종종 `/login.html`, `/product.css`, `/script.js`와 같이 웹 페이지 구조를 나타내는 URL 패턴을 보입니다. 트래픽의 `Content-Type` 헤더가 `text/html`, `text/css`, `application/javascript`와 같이 웹 콘텐츠를 나타낸다면 웹뷰를 사용하고 있을 가능성이 높습니다. 반면, 네이티브 앱의 API 통신은 보통 `application/json` 또는 `application/x-www-form-urlencoded`와 같은 콘텐츠 유형을 사용하며, `/api/v1/users`, `/data/sync`와 같이 특정 API 엔드포인트 패턴을 따릅니다.

#### 런타임 분석 (Runtime Analysis)

Frida와 같은 동적 계측 도구를 사용하여 앱의 런타임 동작을 후킹(Hooking)하는 것은 웹뷰 사용을 가장 확실하게 확인하는 방법입니다.

  * **메서드 후킹**: 앱의 런타임에서 웹뷰 관련 메서드(`WebView.loadUrl()`, `WKWebView loadRequest:`)가 실제로 호출되는지 확인할 수 있습니다. 이러한 메서드에 대한 후킹 스크립트를 작성하여 특정 URL이 로드되는 순간을 포착하는 것이 가능합니다. 이는 웹뷰가 백그라운드에서 동작할 때도 감지할 수 있어 매우 효과적입니다.

    **안드로이드 (Frida)**

    ```javascript
    Java.perform(function() {
        var WebView = Java.use("android.webkit.WebView");
        WebView.loadUrl.overload('java.lang.String').implementation = function(url) {
            console.log("[*] WebView.loadUrl() called with URL: " + url);
            this.loadUrl(url);
        };
    });
    ```

    **iOS (Frida)**

    ```javascript
    var WKWebView = ObjC.classes.WKWebView;
    if (WKWebView) {
        Interceptor.attach(WKWebView['- loadRequest:'].implementation, {
            onEnter: function(args) {
                var request = new ObjC.Object(args[2]);
                var url = request.URL().toString();
                console.log("[*] WKWebView.loadRequest() called with URL: " + url);
            }
        });
    }
    ```