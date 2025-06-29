---
title: Bypass pinning by repackaging - Android
tags: Android
key: page-pinning_bypass
categories: [Cybersecurity, Mobile Security]
author: hyoeun
math: true
mathjax_autoNumber: true
---

## Mastering SSL Pinning Bypass: From Package Repackaging to Automated Tools

One of the first obstacles encountered during mobile app penetration testing is **SSL Pinning**. SSL Pinning forces an app to trust only a predefined server certificate, neutralizing attempts to intercept network traffic through a Man-in-the-Middle (MITM) attack. However, for security analysts and penetration testers, bypassing this barrier is necessary to analyze the app's communications and find vulnerabilities.

This article covers both the traditional manual bypass method through **Package Repackaging** and how to automate this process using a powerful tool called `objection`.

-----

### 1\. Overview of Bypassing with Package Repackaging

Package repackaging proceeds through the following steps:

1.  **Extract the APK:** Extract the APK file of the target Android application.
2.  **Decompile the APK:** Decompile the extracted APK into Smali code. Smali is an assembly-like language for the Dalvik/ART virtual machine.
3.  **Modify Smali Code:** Find the SSL Pinning-related code and inject bypass logic or disable the existing logic.
4.  **Recompile the APK:** Recompile the modified Smali code back into an APK file.
5.  **Sign the APK:** Sign the recompiled APK with a new signature. The Android system does not allow the installation of unsigned apps.
6.  **Install the APK:** Install the signed APK on the target device or emulator.

Through this process, we can modify the app's internal logic to neutralize SSL Pinning and successfully intercept the app's network traffic via a proxy.

-----

### 2\. Prerequisites (macOS Environment)

This guide assumes that **JDK** and **Android SDK Platform-Tools** are already installed. The additional tools required are as follows:

  * **Manual Analysis Tools:**
      * **APKTool:** An essential tool for decompiling and recompiling APKs.
      * **Uber-APK-Signer:** A tool that simplifies the APK signing process.
        ```bash
        brew install uber-apk-signer
        ```
      * **Text Editor:** A convenient tool for modifying Smali code, such as Visual Studio Code or Sublime Text.
  * **Automated Analysis Tools:**
      * **Objection:** A dynamic analysis and patching tool based on Frida.
        ```bash
        pip3 install objection
        ```

-----

### 3\. [Method 1] Step-by-Step Manual Bypass: Package Repackaging

This guide assumes we are using a hypothetical `VulnerableApp.apk` file with SSL Pinning applied.

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

  * **Bypassing the `checkServerTrusted` method:** The `checkServerTrusted` method of the `X509TrustManager` interface validates server certificates. By modifying this method to always return normally (i.e., not throw an exception), you can force it to trust any certificate.
  * **Modifying Network Security Configuration:** On Android 7.0 (API 24) and above, apps can define trust anchors via a Network Security Configuration XML file. You can modify this file to trust all user-installed certificates.

**Example: Modifying Network Security Configuration**

1.  Open the `VulnerableApp_decompiled/AndroidManifest.xml` file and add the following attribute to the `<application>` tag:
    ```xml
    android:networkSecurityConfig="@xml/network_security_config"
    ```
2.  Create a file named `network_security_config.xml` in the `VulnerableApp_decompiled/res/xml/` directory and add the following content:
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
    By adding `src="user"`, the app will trust user-installed certificates (such as a proxy tool's CA certificate, e.g., Burp Suite), allowing you to bypass SSL Pinning.

#### 3.4. Step 4: Recompile the APK

Once you've finished modifying the Smali code, use `APKTool` to recompile the modified directory back into an APK file.

```bash
apktool b VulnerableApp_decompiled -o VulnerableApp_repacked_unsigned.apk
```

#### 3.5. Step 5: Sign the APK (Using Uber-APK-Signer)

The recompiled APK cannot be installed because it's unsigned. Sign it using `uber-apk-signer`.

```bash
java -jar /path/to/uber-apk-signer.jar --apks VulnerableApp_repacked_unsigned.apk
```

Running this command will generate a new signed APK file (e.g., `VulnerableApp_repacked_unsigned-aligned-signed.apk`). You can now install this file on your device.

-----

### 4\. [Method 2] Automated Bypass: Using Objection

The process of decompiling, modifying XML, recompiling, and signing described above is complex and time-consuming. **Objection** simplifies SSL Pinning bypass by automating this entire process into a single command.

#### 4.1. Patching an APK with Objection

Objection's `patchapk` command automatically injects SSL Pinning bypass logic into an APK. Specifically, the `-N` or `--network-security-config` option automatically applies the **Network Security Configuration** method we performed manually above.

1.  **Prepare the APK file:** Have the original APK file you want to bypass (`original.apk`) ready.

2.  **Execute the patch command:**

    ```bash
    objection patchapk --source original.apk -N
    ```

    When you run this command, Objection automatically performs the following tasks internally:

      * Decompiles `original.apk` using `apktool`.
      * Adds the `networkSecurityConfig` attribute to `AndroidManifest.xml`.
      * Creates the `network_security_config.xml` file configured to trust user certificates.
      * Recompiles the modified files back into an APK.
      * Signs the APK with a new key.

3.  **Check the result:**
    Once the command is complete, a new APK file named something like `original.objection.apk` will be created in your current directory. This file already has the SSL Pinning bypass logic applied and is signed, so you can immediately install it on your device for testing.

    ```bash
    # Install the generated APK
    adb install original.objection.apk
    ```

---

## SSL Pinning 우회 완전 정복: 패키지 리패키징부터 자동화 도구까지

모바일 앱 모의 해킹 시 가장 먼저 마주치는 장애물 중 하나는 바로 **SSL Pinning**입니다. SSL Pinning은 앱이 미리 지정된 서버의 인증서만 신뢰하도록 강제하여, 중간자 공격(MITM)을 통해 네트워크 트래픽을 가로채려는 시도를 무력화합니다. 하지만 보안 분석가와 모의 해커에게는 이 장벽을 우회해야만 앱의 통신 내용을 분석하고 취약점을 찾을 수 있습니다.

이 글에서는 가장 전통적인 우회 기법인 \*\*패키지 리패키징(Package Repackaging)\*\*을 통한 수동 우회 방법과, `objection`이라는 강력한 도구를 사용하여 이 과정을 자동화하는 방법을 모두 다룹니다.

### 1\. 패키지 리패키징을 통한 우회 개요

패키지 리패키징은 다음과 같은 단계로 진행됩니다.

1.  **APK 추출:** 대상 안드로이드 애플리케이션의 APK 파일을 추출합니다.
2.  **APK 디컴파일:** 추출된 APK를 Smali 코드로 디컴파일합니다. Smali는 Dalvik/ART 가상 머신의 어셈블리 언어와 유사한 형태입니다.
3.  **Smali 코드 수정:** SSL Pinning 관련 코드를 찾아 우회 로직을 삽입하거나 기존 로직을 비활성화합니다.
4.  **APK 리컴파일:** 수정된 Smali 코드를 다시 APK 파일로 리컴파일합니다.
5.  **APK 서명:** 리컴파일된 APK에 새로운 서명을 합니다. 안드로이드 시스템은 서명되지 않은 앱의 설치를 허용하지 않습니다.
6.  **APK 설치:** 서명된 APK를 대상 기기 또는 에뮬레이터에 설치합니다.

이 과정을 통해 우리는 앱의 내부 로직을 변경하여 SSL Pinning을 무력화하고, 프록시를 통해 앱의 네트워크 트래픽을 성공적으로 가로챌 수 있게 됩니다.

### 2\. 준비물 (macOS 환경)

이 가이드에서는 **JDK**, **Android SDK Platform-Tools**가 이미 설치되어 있다고 가정합니다. 추가적으로 필요한 도구는 다음과 같습니다.

  * **수동 분석용 도구:**

      * **APKTool:** APK를 디컴파일하고 리컴파일하는 데 필수적인 도구입니다.
      * **Uber-APK-Signer:** APK 서명을 간편하게 처리해 주는 도구입니다.
        ```bash
        brew install uber-apk-signer
        ```
      * **텍스트 편집기:** Visual Studio Code, Sublime Text 등 Smali 코드 수정에 편리한 도구.

  * **자동 분석용 도구:**

      * **Objection:** Frida를 기반으로 하는 동적 분석 및 패치 도구입니다.
        ```bash
        pip3 install objection
        ```

-----

### 3\. [방법 1] 단계별 수동 우회: 패키지 리패키징

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

  * **`checkServerTrusted` 메서드 우회:** `X509TrustManager` 인터페이스의 `checkServerTrusted` 메서드는 서버 인증서의 유효성을 검사합니다. 이 메서드가 항상 정상 종료되도록 수정하면 어떤 인증서든 신뢰하게 만들 수 있습니다.
  * **네트워크 보안 구성(Network Security Configuration) 수정:** Android 7.0 (API 24) 이상에서는 앱 내에서 네트워크 보안 구성 XML 파일을 통해 트러스트 앵커를 설정할 수 있습니다. 이 파일을 수정하여 모든 사용자 인증서를 신뢰하도록 할 수 있습니다.

**예시: 네트워크 보안 구성 수정**

1.  `VulnerableApp_decompiled/AndroidManifest.xml` 파일을 열고 `<application>` 태그에 다음 속성을 추가합니다.
    ```xml
    android:networkSecurityConfig="@xml/network_security_config"
    ```
2.  `VulnerableApp_decompiled/res/xml/` 디렉터리에 `network_security_config.xml` 파일을 생성하고 다음 내용을 추가합니다.
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
    `src="user"`를 추가함으로써, 앱이 프록시 도구(예: Burp Suite)의 CA 인증서와 같이 사용자가 설치한 인증서를 신뢰하게 되어 SSL Pinning을 우회할 수 있습니다.

#### 3.4. 4단계: APK 리컴파일

Smali 코드 수정이 완료되었다면, `APKTool`을 사용하여 수정된 디렉터리를 다시 APK 파일로 리컴파일합니다.

```bash
apktool b VulnerableApp_decompiled -o VulnerableApp_repacked_unsigned.apk
```

#### 3.5. 5단계: APK 서명 (Uber-APK-Signer 사용)

리컴파일된 APK는 서명이 없으므로 설치가 불가능합니다. `uber-apk-signer`를 사용하여 서명합니다.

```bash
java -jar /path/to/uber-apk-signer.jar --apks VulnerableApp_repacked_unsigned.apk
```

이 명령을 실행하면 서명된 새 APK 파일(`VulnerableApp_repacked_unsigned-aligned-signed.apk`)이 생성됩니다. 이제 이 파일을 기기에 설치하면 됩니다.

-----

### 4\. [방법 2] 자동화된 우회: Objection 사용

위에서 설명한 디컴파일, XML 수정, 리컴파일, 서명 과정은 복잡하고 시간이 많이 소요됩니다. **Objection**은 이 모든 과정을 단 하나의 명령어로 자동화하여 SSL Pinning 우회를 매우 간단하게 만들어 줍니다.

#### 4.1. Objection을 이용한 APK 패치

Objection의 `patchapk` 명령어는 SSL Pinning 우회 로직을 APK에 자동으로 삽입합니다. 특히 `-N` 또는 `--network-security-config` 옵션은 위에서 수동으로 했던 **네트워크 보안 구성(Network Security Configuration)** 방식을 자동으로 적용해 줍니다.

1.  **APK 파일 준비:** 우회하려는 원본 APK 파일(`original.apk`)을 준비합니다.

2.  **패치 명령어 실행:**

    ```bash
    objection patchapk --source original.apk -N
    ```

    이 명령어를 실행하면 Objection이 내부적으로 다음 작업을 자동으로 수행합니다.

      * `apktool`을 사용하여 `original.apk`를 디컴파일합니다.
      * `AndroidManifest.xml`에 `networkSecurityConfig` 속성을 추가합니다.
      * 사용자 인증서를 신뢰하도록 설정된 `network_security_config.xml` 파일을 생성합니다.
      * 수정된 내용을 다시 APK로 리컴파일합니다.
      * 새로운 키로 APK에 서명합니다.

3.  **결과 확인:**
    명령 실행이 완료되면 현재 디렉터리에 `original.objection.apk` 와 같이 이름이 변경된 새로운 APK 파일이 생성됩니다. 이 파일은 이미 SSL Pinning 우회 로직이 적용되고 서명까지 완료된 상태이므로, 바로 기기에 설치하여 테스트할 수 있습니다.

    ```bash
    # 생성된 APK 설치
    adb install original.objection.apk
    ```