---
title: Bypass pinning by repackaging - Android
tags: Android
key: page-pinning_bypass
categories: [Cybersecurity, Mobile Security]
author: hyoeun
math: true
mathjax_autoNumber: true
---

Here's the English translation of the provided text:

---

### 1. Overview of Bypassing through Package Repackaging

Package repackaging proceeds through the following steps:

1.  **APK Extraction:** Extract the APK file of the target Android application.
2.  **APK Decompilation:** Decompile the extracted APK into Smali code. Smali is a form similar to the assembly language of the Dalvik/ART virtual machine.
3.  **Smali Code Modification:** Locate the SSL Pinning-related code and inject bypass logic or disable existing logic.
4.  **APK Recompilation:** Recompile the modified Smali code back into an APK file.
5.  **APK Signing:** Sign the recompiled APK with a new signature. The Android system does not allow the installation of unsigned apps.
6.  **APK Installation:** Install the signed APK on the target device or emulator.

Through this process, we can modify the app's internal logic to neutralize SSL Pinning and successfully intercept the app's network traffic via a proxy.

---

### 2. Prerequisites (macOS Environment)

This guide assumes that **JDK**, **Android SDK Platform-Tools**, and **APKTool** are already installed. Additional tools required are:

* **Uber-APK-Signer:** A tool that simplifies the APK signing process.
    ```bash
    brew install uber-apk-signer
    ```
* **Text Editor:** A convenient tool for modifying Smali code, such as Visual Studio Code or Sublime Text.

---

### 3. Step-by-Step SSL Pinning Bypass: Package Repackaging

This guide assumes we're using a hypothetical `VulnerableApp.apk` file with SSL Pinning applied.

#### 3.1. Step 1: Extract the Target APK

First, you need to extract the APK file of the application you want to test. If the app is already installed on the device, you can extract it using `adb`.

1.  **Confirm the app's package name:**
    ```bash
    adb shell pm list packages | grep -i 'vulnerable' # Use part of the app name instead of 'vulnerable'
    # Example output: package:com.example.vulnerableapp
    ```
    Let's assume the package name is `com.example.vulnerableapp`.

2.  **Find the APK path:**
    ```bash
    adb shell pm path com.example.vulnerableapp
    # Example output: package:/data/app/~~xxxxx/com.example.vulnerableapp-yyyyyy==/base.apk
    ```
    Let's assume the path is `/data/app/~~xxxxx/com.example.vulnerableapp-yyyyyy==/base.apk`.

3.  **Extract the APK:**
    ```bash
    adb pull /data/app/~~xxxxx/com.example.vulnerableapp-yyyyyy==/base.apk VulnerableApp.apk
    ```
    Now you have the `VulnerableApp.apk` file in your current directory.

#### 3.2. Step 2: Decompile the APK

Use `APKTool` to decompile the extracted APK file into Smali code.

```bash
apktool d VulnerableApp.apk -o VulnerableApp_decompiled
```
Executing this command will create a new directory named `VulnerableApp_decompiled`, and the app's resources and Smali code (in the `smali/` directory) will be extracted into it.

#### 3.3. Step 3: Modify Smali Code (SSL Pinning Bypass)

This step can be the most critical and challenging. SSL Pinning logic is implemented differently in each app, so you'll need to locate and modify the relevant code. Common bypass strategies include:

* **Bypassing the `checkServerTrusted` method:** The `checkServerTrusted` method of the `X509TrustManager` interface validates server certificates. By modifying this method to always return `void` (i.e., not throw an exception), you can force it to trust any certificate.
* **Modifying Network Security Configuration:** On Android 7.0 (API 24) and above, apps can define trust anchors via an XML file for network security configuration. You can modify this file to trust all user-installed certificates.

**Example 1: Bypassing `checkServerTrusted` Smali Code**

In the `VulnerableApp_decompiled/smali/` directory, search for Smali files related to `checkServerTrusted` or `TrustManager`. You'll typically find code similar to this:

```smali
.method public checkServerTrusted([Ljava/security/cert/X509Certificate;Ljava/lang/String;)V
    .locals 0
    .param p1, "chain"    # [Ljava/security/cert/X509Certificate;
    .param p2, "authType"    # Ljava/lang/String;
    .annotation system Ldalvik/annotation/Throws;
        value = {
            Ljava/security/cert/CertificateException;
        }
    .end annotation

    .line 123
    # Original SSL Pinning logic (omitted)
    # If the pinning fails, it might throw a CertificateException

    return-void # This line is crucial.
.end method
```

Remove any logic within this method that throws a `CertificateException`, and simply add `return-void` at the beginning of the method or ensure it's at the end to always ensure normal termination. This will cause `checkServerTrusted` to always pass, regardless of the certificate.

**Example 2: Modifying Network Security Configuration (AndroidManifest.xml and network_security_config.xml)**

1.  Open the `VulnerableApp_decompiled/AndroidManifest.xml` file.
2.  Check if the `<application>` tag contains the `android:networkSecurityConfig` attribute.
    ```xml
    <application
        android:allowBackup="true"
        android:icon="@mipmap/ic_launcher"
        android:label="@string/app_name"
        android:roundIcon="@mipmap/ic_launcher_round"
        android:supportsRtl="true"
        android:theme="@style/AppTheme"
        android:networkSecurityConfig="@xml/network_security_config"> </application>
    ```
    If this attribute is missing, you must add it:
    ```xml
    android:networkSecurityConfig="@xml/network_security_config"
    ```
3.  Create or modify the `network_security_config.xml` file in the `VulnerableApp_decompiled/res/xml/` directory. (Create it if it doesn't exist.)

    ```xml
    <?xml version="1.0" encoding="utf-8"?>
    <network-security-config>
        <base-config>
            <trust-anchors>
                <certificates src="system" />
                <certificates src="user" />
            </trust-anchors>
        </base-config>
        </network-security-config>
    ```
    By adding `src="user"`, the app will trust user-installed certificates (e.g., Burp Suite's CA certificate), allowing you to bypass SSL Pinning.

**Tip: Smali Code Analysis Strategies**

* **Using `grep`:** Search for keywords like `X509TrustManager`, `checkServerTrusted`, `hostnameVerifier`, and `CertificatePinner` within the `VulnerableApp_decompiled/smali` directory using `grep` to find relevant code.
    ```bash
    grep -r "checkServerTrusted" VulnerableApp_decompiled/smali/
    grep -r "TrustManager" VulnerableApp_decompiled/smali/
    ```
* **Analyzing Open-Source Libraries:** Popular networking libraries like OkHttp and Retrofit often have built-in SSL Pinning functionalities. Analyze their Smali code to locate the pinning logic.
* **Static Analysis Tools:** Using reverse engineering tools like Ghidra and Jadx to decompile the code into Java/Kotlin, then mapping it back to Smali code, can also aid understanding.
* **Dynamic Analysis (Frida):** Hooking specific function calls to precisely identify where pinning occurs, and then modifying the Smali code based on this information, is also an effective strategy.

#### 3.4. Step 4: Recompile the APK

Once you've finished modifying the Smali code, use `APKTool` to recompile the modified directory back into an APK file.

```bash
apktool b VulnerableApp_decompiled -o VulnerableApp_repacked_unsigned.apk
```
At this point, note that the `-o` flag should be followed by the **folder name of the decompiled APK** (`VulnerableApp_decompiled`), not the name of the recompiled APK file (e.g., `VulnerableApp_repacked_unsigned.apk`). The `VulnerableApp_repacked_unsigned.apk` file is still unsigned and cannot be installed.

#### 3.5. Step 5: Sign the APK (Using Uber-APK-Signer)

For an app to be installed on an Android system, it must be signed. Use `uber-apk-signer` to sign the recompiled APK. This tool can automatically generate a new key or use an existing one to sign the APK.

```bash
java -jar /opt/homebrew/Cellar/uber-apk-signer/VERSION/libexec/uber-apk-signer-VERSION.jar --apks VulnerableApp_repacked_unsigned.apk
```
Replace `VERSION` with the actual installed version of `uber-apk-signer` (e.g., `1.3.0`). Running this command will generate a new signed APK file, such as `VulnerableApp_repacked_unsigned-aligned-signed.apk`.

---

### 1. 패키지 리패키징을 통한 우회 개요

패키지 리패키징은 다음과 같은 단계로 진행됩니다.

1.  **APK 추출:** 대상 안드로이드 애플리케이션의 APK 파일을 추출합니다.
2.  **APK 디컴파일:** 추출된 APK를 Smali 코드로 디컴파일합니다. Smali는 Dalvik/ART 가상 머신의 어셈블리 언어와 유사한 형태입니다.
3.  **Smali 코드 수정:** SSL Pinning 관련 코드를 찾아 우회 로직을 삽입하거나 기존 로직을 비활성화합니다.
4.  **APK 리컴파일:** 수정된 Smali 코드를 다시 APK 파일로 리컴파일합니다.
5.  **APK 서명:** 리컴파일된 APK에 새로운 서명을 합니다. 안드로이드 시스템은 서명되지 않은 앱의 설치를 허용하지 않습니다.
6.  **APK 설치:** 서명된 APK를 대상 기기 또는 에뮬레이터에 설치합니다.

이 과정을 통해 우리는 앱의 내부 로직을 변경하여 SSL Pinning을 무력화하고, 프록시를 통해 앱의 네트워크 트래픽을 성공적으로 가로챌 수 있게 됩니다.

### 2. 준비물 (macOS 환경)

이 가이드에서는 **JDK**, **Android SDK Platform-Tools**, **APKTool**이 이미 설치되어 있다고 가정합니다. 추가적으로 필요한 도구는 다음과 같습니다.

* **Uber-APK-Signer:** APK 서명을 간편하게 처리해 주는 도구입니다.
    ```bash
    brew install uber-apk-signer
    ```
* **텍스트 편집기:** Visual Studio Code, Sublime Text 등 Smali 코드 수정에 편리한 도구.

### 3. 단계별 SSL Pinning 우회: 패키지 리패키징

이 가이드에서는 가상의 SSL Pinning이 적용된 `VulnerableApp.apk` 파일을 사용한다고 가정합니다.

#### 3.1. 1단계: 대상 APK 추출

먼저 테스트할 애플리케이션의 APK 파일을 추출해야 합니다. 앱이 이미 기기에 설치되어 있다면 `adb`를 사용하여 추출할 수 있습니다.

1.  **앱의 패키지 이름 확인:**
    ```bash
    adb shell pm list packages | grep -i 'vulnerable' # 'vulnerable' 대신 앱 이름의 일부 사용
    # 예시 출력: package:com.example.vulnerableapp
    ```
    패키지 이름은 `com.example.vulnerableapp`이라고 가정합니다.

2.  **APK 경로 찾기:**
    ```bash
    adb shell pm path com.example.vulnerableapp
    # 예시 출력: package:/data/app/~~xxxxx/com.example.vulnerableapp-yyyyyy==/base.apk
    ```
    경로는 `/data/app/~~xxxxx/com.example.vulnerableapp-yyyyyy==/base.apk`라고 가정합니다.

3.  **APK 추출:**
    ```bash
    adb pull /data/app/~~xxxxx/com.example.vulnerableapp-yyyyyy==/base.apk VulnerableApp.apk
    ```
    이제 현재 디렉토리에 `VulnerableApp.apk` 파일이 있습니다.

#### 3.2. 2단계: APK 디컴파일

추출된 APK 파일을 `APKTool`을 사용하여 Smali 코드로 디컴파일합니다.

```bash
apktool d VulnerableApp.apk -o VulnerableApp_decompiled
```
이 명령을 실행하면 `VulnerableApp_decompiled`라는 새 디렉터리가 생성되고, 그 안에 앱의 리소스 및 Smali 코드(`smali/` 디렉터리)가 추출됩니다.

#### 3.3. 3단계: Smali 코드 수정 (SSL Pinning 우회)

이 단계가 가장 중요하고 어려울 수 있습니다. SSL Pinning 로직은 앱마다 구현 방식이 다르므로, 해당 로직을 찾아 수정해야 합니다. 일반적인 우회 전략은 다음과 같습니다.

* **`checkServerTrusted` 메서드 우회:** `X509TrustManager` 인터페이스의 `checkServerTrusted` 메서드는 서버 인증서의 유효성을 검사합니다. 이 메서드가 항상 `void`를 반환(즉, 예외를 발생시키지 않음)하도록 수정하면 어떤 인증서든 신뢰하게 만들 수 있습니다.
* **네트워크 보안 구성(Network Security Configuration) 수정:** Android 7.0 (API 24) 이상에서는 앱 내에서 네트워크 보안 구성 XML 파일을 통해 트러스트 앵커를 설정할 수 있습니다. 이 파일을 수정하여 모든 사용자 인증서를 신뢰하도록 할 수 있습니다.

**예시 1: `checkServerTrusted` Smali 코드 우회**

`VulnerableApp_decompiled/smali/` 디렉터리에서 `checkServerTrusted` 또는 `TrustManager`와 관련된 Smali 파일을 검색합니다. 일반적으로 다음과 유사한 코드를 찾을 수 있습니다.

```smali
.method public checkServerTrusted([Ljava/security/cert/X509Certificate;Ljava/lang/String;)V
    .locals 0
    .param p1, "chain"    # [Ljava/security/cert/X509Certificate;
    .param p2, "authType"    # Ljava/lang/String;
    .annotation system Ldalvik/annotation/Throws;
        value = {
            Ljava/security/cert/CertificateException;
        }
    .end annotation

    .line 123
    # 기존 SSL Pinning 로직 (생략)
    # If the pinning fails, it might throw a CertificateException

    return-void # 이 줄이 중요합니다.
.end method
```

이 메서드 내에서 `CertificateException`을 던지는 모든 로직을 제거하고, 단순히 메서드 시작 부분에 `return-void`를 추가하거나, 마지막에 `return-void`가 있는지 확인하여 항상 정상 종료되도록 만듭니다. 이렇게 하면 어떤 인증서가 오든 관계없이 `checkServerTrusted`가 항상 통과하게 됩니다.

**예시 2: 네트워크 보안 구성 수정 (AndroidManifest.xml 및 network_security_config.xml)**

1.  `VulnerableApp_decompiled/AndroidManifest.xml` 파일을 엽니다.
2.  `<application>` 태그 내에 `android:networkSecurityConfig` 속성이 있는지 확인합니다.
    ```xml
    <application
        android:allowBackup="true"
        android:icon="@mipmap/ic_launcher"
        android:label="@string/app_name"
        android:roundIcon="@mipmap/ic_launcher_round"
        android:supportsRtl="true"
        android:theme="@style/AppTheme"
        android:networkSecurityConfig="@xml/network_security_config"> </application>
    ```
    만약 이 속성이 없다면, 추가해야 합니다.
    ```xml
    android:networkSecurityConfig="@xml/network_security_config"
    ```
3.  `VulnerableApp_decompiled/res/xml/` 디렉터리에 `network_security_config.xml` 파일을 생성하거나 기존 파일을 수정합니다. (파일이 없다면 새로 만듭니다.)

    ```xml
    <?xml version="1.0" encoding="utf-8"?>
    <network-security-config>
        <base-config>
            <trust-anchors>
                <certificates src="system" />
                <certificates src="user" />
            </trust-anchors>
        </base-config>
        </network-security-config>
    ```
    `src="user"`를 추가함으로써, 앱이 사용자 설치 인증서(예: Burp Suite의 CA 인증서)를 신뢰하게 되어 SSL Pinning을 우회할 수 있습니다.

**팁: Smali 코드 분석 전략**

* **`grep` 사용:** `VulnerableApp_decompiled/smali` 디렉터리에서 `X509TrustManager`, `checkServerTrusted`, `hostnameVerifier`, `CertificatePinner` 같은 키워드를 `grep`으로 검색하여 관련 코드를 찾습니다.
    ```bash
    grep -r "checkServerTrusted" VulnerableApp_decompiled/smali/
    grep -r "TrustManager" VulnerableApp_decompiled/smali/
    ```
* **오픈소스 라이브러리 분석:** OkHttp, Retrofit 등 많이 사용되는 네트워크 라이브러리는 SSL Pinning 기능을 내장하고 있는 경우가 많습니다. 해당 라이브러리의 Smali 코드를 분석하여 Pinning 로직을 찾습니다.
* **정적 분석 도구:** Ghidra, Jadx 등의 역공학 도구를 사용하여 Java/Kotlin 코드로 디컴파일한 후, Smali 코드로 다시 매핑하여 이해를 돕는 것도 좋은 방법입니다.
* **동적 분석(Frida):** 특정 함수 호출을 후킹하여 Pinning이 발생하는 지점을 정확히 파악하고, 이를 바탕으로 Smali 코드를 수정하는 전략도 효과적입니다.

#### 3.4. 4단계: APK 리컴파일

Smali 코드 수정이 완료되었다면, 이제 `APKTool`을 사용하여 수정된 디렉터리를 다시 APK 파일로 리컴파일합니다.

```bash
apktool b VulnerableApp_decompiled -o VulnerableApp_repacked_unsigned.apk
```
이때 `-o` 뒤에는 리컴파일될 APK 파일의 이름(예: `VulnerableApp_repacked_unsigned.apk`)이 아닌, **디컴파일된 APK 파일의 폴더 이름**(`VulnerableApp_decompiled`)이 와야 함을 명심하세요. `VulnerableApp_repacked_unsigned.apk` 파일은 아직 서명되지 않았으므로 설치할 수 없습니다.

#### 3.5. 5단계: APK 서명 (Uber-APK-Signer 사용)

안드로이드 시스템에 앱을 설치하려면 반드시 서명이 필요합니다. `uber-apk-signer`를 사용하여 리컴파일된 APK에 서명합니다. 이 도구는 자동으로 새 키를 생성하거나 기존 키를 사용하여 APK에 서명해 줍니다.

```bash
java -jar /opt/homebrew/Cellar/uber-apk-signer/VERSION/libexec/uber-apk-signer-VERSION.jar --apks VulnerableApp_repacked_unsigned.apk
```
`VERSION` 부분은 `uber-apk-signer`가 설치된 실제 버전을 입력해야 합니다. (예: `1.3.0`). 이 명령을 실행하면 `VulnerableApp_repacked_unsigned-aligned-signed.apk`와 같이 서명된 새 APK 파일이 생성됩니다.