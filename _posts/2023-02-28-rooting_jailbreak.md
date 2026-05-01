---
title: Rooting & Jailbreak
key: page-tag
categories:
- Security
- Mobile Security
author: hyoeun
math: true
mathjax_autoNumber: true
image: "/assets/thumbnails/2023-02-28-rooting_jailbreak.png"
bilingual: true
date: 2023-02-28 01:04:48
---
## The Art of Breaking System Locks: Everything About Rooting and Jailbreaking

When you buy a smartphone, are you truly the owner of the device? Manufacturers and operating system developers, under the pretext of stability and security, restrict numerous functions and confine users within a 'safe wall'. However, for those of us who seek to explore the system's limits and see beyond them, that wall is nothing more than a frustrating prison.

**Rooting** and **Jailbreaking** are the acts of breaking the locks of this digital prison and reclaiming true ownership of the device. In this article, we will discuss what these two technologies are, why we seek to unlock our devices, and what we can do with that power.


### The Liberation of Android: Rooting

Rooting is the process of obtaining **superuser (root) privileges** on the Android operating system. In Android, which is based on Linux, 'root' is an all-powerful user who can access and modify all files and processes. By default, manufacturers hide this immense power from the user.

### **Why We Want Root Access (A Hacker's Perspective)**

Beyond simple customization, root access becomes a powerful weapon for analyzing and attacking a system.

  * **System File Access and Modification:** You can inject code into system apps, disable security settings, and manipulate log files to erase traces.
  * **Execution of Powerful Analysis Tools:** You can enable the full functionality of reversing and dynamic analysis tools like Frida and Ghidra to dissect an app's internal logic.
  * **Network Traffic Sniffing:** You can intercept and analyze system-wide network traffic to extract sensitive unencrypted information or analyze communication protocols.
  * **Kernel Exploitation:** You can directly attack kernel-level vulnerabilities to gain deeper system control and install persistent backdoors.

### **Rooting Guide (General Procedure)**

**⚠️ Warning: This process may void your device's warranty. Performing steps incorrectly can result in your device becoming unusable (bricked). Before you begin, you must back up all your data. Proceed at your own risk.**

**Step 1: Unlock the Bootloader**
The bootloader is the initial software that runs before the Android OS boots. You must unlock it to install custom software.

  * **PC Preparation:** Install ADB and Fastboot tools on your PC.
  * **Device Setup:** Enable 'Developer Options' and, within that menu, turn on **'OEM unlocking'** and **'USB debugging'**.
  * **Execution:** Connect the device to your PC, enter bootloader mode with the command `adb reboot bootloader`, and then execute `fastboot flashing unlock`. **This process will wipe all data on your device.**

**Step 2: Install a Custom Recovery (e.g., TWRP)**
A custom recovery is a special recovery environment that allows you to install (flash) custom software like rooting packages. **TWRP** is the most widely used.

  * Download the TWRP image file (`*.img`) specific to your device model.
  * Reboot your device into bootloader mode again and install TWRP using the command `fastboot flash recovery twrp.img`.

**Step 3: Install the Rooting Package (Magisk)**
**Magisk** is the current standard rooting tool that enables root access via a 'Systemless' method, which doesn't directly modify the system partition.

  * Download the latest Magisk installation file (`*.zip`) and copy it to your device's storage.
  * Boot into TWRP recovery mode and install the Magisk zip file from the 'Install' menu.
  * After the installation is complete and the device has rebooted, the presence of the Magisk app signifies a successful root.


### The Escape from iOS: Jailbreaking

Jailbreaking is the act of escaping from Apple's closed ecosystem, the so-called **'Walled Garden'**. It's the process of breaking all the shackles that prohibit app installation outside of the App Store and block access to system files.

### **Why We Escape the Prison (A Hacker's Perspective)**

A jailbroken iPhone is no longer a toy that follows the path set by Apple; it becomes a powerful **research tool** for dissecting its internal structure.

  * **Sandbox Bypass and Filesystem Access:** You can bypass app sandbox restrictions to access data from other apps or read and write files across the entire system.
  * **Execution of Powerful Analysis Tools:** You can use dynamic analysis tools like Frida and Cycript to analyze the internal behavior of running apps and hook methods to manipulate logic in real-time.
  * **SSH Remote Access:** You can remotely connect to the iOS device from a PC via a terminal to execute shell commands, freely navigate the internal system, and build an analysis environment.
  * **Sideloading and Analysis of Apps:** You can install repackaged or analysis-purposed apps (`*.ipa`) without the App Store to analyze vulnerabilities.

### **Jailbreaking Guide (Based on `palera1n`)**

`palera1n` targets older devices with A8 to A11 chipsets (iPhone 6s to iPhone X) and utilizes a **hardware vulnerability (`checkm8`)**, making it a powerful jailbreak method that cannot be patched by Apple's software updates. It supports iOS 15 up to the latest versions of iOS 17.

**⚠️ Warning: This process may void your device's warranty and can make it highly vulnerable to security threats. Before you begin, you must back up all your data. Proceed at your own risk.**

**Step 1: Prepare `palera1n` on Your PC**

This jailbreak requires a PC running **macOS or Linux**.

  * **Clone the Git Repository:** Open a terminal and download `palera1n` with the following command:
    ```bash
    git clone --recursive https://github.com/palera1n/palera1n && cd palera1n
    ```
  * **Run the Script:** Execute the script with the following command. The `--tweaks` flag is essential for installing package managers like Sileo and enabling tweaks.
    ```bash
    sudo ./palera1n.sh --tweaks
    ```

**Step 2: Enter DFU Mode and Proceed with Jailbreak**

Once the script is running, it will prompt you to put your device into **DFU (Device Firmware Update) mode**. DFU mode is a special state where the screen is completely black, but the PC recognizes the device.

  * **Follow Prompts:** Press the buttons according to the on-screen timer. (e.g., for an iPhone 8/X, you would press a combination of the Volume Down and Side buttons for a specific duration).
  * **Automatic Process:** Upon successful entry into DFU mode, the `palera1n` script will automatically handle the rest of the process. Do not disconnect the cable until it is finished.

**Step 3: Finalize the Setup on the Device**

Once the jailbreak is complete and you're back on the home screen, you will see the **palera1n loader app**.

  * Open the `palera1n` loader app and install a package manager like **Sileo** or **Zebra**.
  * Once Sileo is installed on your home screen, you can use it to install tweaks and utilize your newly liberated device.

**Note: Re-Jailbreaking After a Reboot**
`palera1n` is a **semi-tethered** jailbreak, meaning the jailbroken state is lost upon reboot. To re-enable it, you must reconnect the device to your PC and repeat **Steps 1 and 2**. Your existing data and tweaks will be preserved.

## Why App Developers Must Implement Root/Jailbreak Detection

So far, we've explored rooting and jailbreaking from an **attacker's perspective** — the power these techniques unlock. But there is an equal and opposite side to this story: the perspective of the **app developer** and **business owner** who must protect their users and their products.

Why does a banking app refuse to launch on a jailbroken device? Why does a DRM-protected streaming service check for root? This section answers those questions by examining the specific threat scenarios that make root detection a **non-negotiable security control** for any serious mobile application.

### The Hostile Environment Assumption

A mobile device is fundamentally different from a server you control. Your app is deployed into the wild, onto hardware owned by users — hardware that could be in the hands of an adversary. The moment root or jailbreak is present on a device, your app's **entire security model changes**:

*   The **operating system's sandbox** — the primary isolation mechanism between apps — is compromised or bypassable.
*   **Memory protection** mechanisms can be circumvented, allowing other processes to read your app's memory.
*   **Filesystem protections** are removed, making private app data directories accessible.
*   **Kernel-level hooks** can intercept any system call your app makes.

This is why the OWASP Mobile Top 10 (both 2017 and 2024) consistently lists missing root/jailbreak detection as a critical vulnerability under binary protections and environment checks.

### Threat Scenario 1: The Attacker Who Roots Their Own Device

The most common scenario. A user — or more likely, a malicious actor — intentionally roots or jailbreaks their **own device** to attack your app. This is not theoretical; it is the standard methodology for mobile penetration testing and for real-world fraud.

**What the attacker gains:**

*   **Full filesystem access:** The attacker reads your app's private `SharedPreferences`, SQLite databases, and `plist` files. Authentication tokens, session keys, and API credentials stored on the device are directly accessible without any hooking needed.
*   **Dynamic instrumentation (Frida/Objection):** With root, the attacker can inject Frida into your app's process and hook any function in real time — bypassing certificate pinning, overriding license checks, dumping decrypted memory, and manipulating return values of critical functions.
*   **Binary extraction and repackaging:** The actual APK or IPA can be pulled from the device, decompiled, modified (e.g., removing payment walls, anti-cheat logic, or watermarks), and repackaged and redistributed.
*   **Traffic interception without certificate pinning workarounds:** On a rooted device, system-level SSL pinning interception (via Magisk modules or `/etc/hosts` manipulation) can be performed, making Burp Suite proxy setup trivial.

**Real-world business impact:**
*   Competitors reverse-engineer proprietary algorithms.
*   In-app purchases are bypassed, resulting in direct revenue loss.
*   Authentication tokens are stolen and replayed from other infrastructure.
*   API abuse from extracted keys drives up infrastructure costs.

> [!WARNING]
> Implementing root detection does **not** prevent a determined attacker — they can hook and bypass your detection logic. But it **dramatically raises the bar**, forcing attackers to invest significant time and expertise, which eliminates the vast majority of opportunistic threats.

### Threat Scenario 2: The Customer's Device Remotely Compromised Without Their Knowledge

This is the more dangerous and less understood scenario. The **customer does not know their device has been rooted**. This can happen through:

*   **Malicious apps with escalation exploits:** A seemingly innocent app (often a game or utility from a third-party store) exploits an unpatched kernel vulnerability to silently acquire root privileges. This is how malware families like **Ztorg**, **Ghost Push**, and **Hummingbad** infected millions of devices.
*   **Pre-rooted devices from unofficial supply chains:** Devices purchased from gray markets or third-party sellers sometimes arrive pre-rooted with backdoored firmware. The user has no idea.
*   **Enterprise MDM compromise:** In BYOD (Bring Your Own Device) environments, a compromised Mobile Device Management profile can grant elevated access. This has been exploited in nation-state spyware campaigns (e.g., Pegasus).
*   **Supply chain attacks on firmware:** Modified firmware distributed through unofficial OTA update channels can persist root access without the user's knowledge.

**What this means for your app:**

Your legitimate user is a **victim**. Malware on their device can:
*   Read your app's decrypted data from memory while the user is authenticated and actively using the app.
*   Intercept network calls at the kernel level, bypassing your certificate pinning.
*   Capture screenshots or audio via accessibility hooks while the user interacts with your app.
*   Exfiltrate session tokens in **real time**, performing account takeover on behalf of the legitimate user.

From your server's perspective, this attack **looks completely legitimate** — same user, same device fingerprint, valid session token. Without your app detecting the hostile environment and refusing to operate, or alerting the backend, there is nothing you can do to defend against it.

> [!CAUTION]
> This threat scenario is the primary justification used by regulators and compliance frameworks (e.g., PCI-DSS for mobile payment apps, FIDO Alliance guidelines) for mandating root detection in financial and healthcare applications.

### Threat Scenario 3: Business Logic Manipulation via Modified Binaries

This scenario targets **the integrity of your app's logic**, not just its data. On a rooted or jailbroken device, an attacker can modify your app binary and run the modified version. This is sometimes called "repackaging" or a "patch attack."

**What attackers modify:**

*   **Payment and subscription logic:** Remove code that verifies a paid subscription or in-app purchase receipt with the server. The app behaves as if the user has a premium account.
*   **Anti-cheat and anti-fraud logic in games:** Disable speed limits, item count checks, or leaderboard submission validation. The modified app sends fraudulent high scores or game states to your backend.
*   **Loyalty and points systems:** Manipulate point calculation logic or coupon generation code in apps with rewards programs. Attackers can fraudulently accumulate points or generate unlimited discount codes.
*   **Digital watermarking and DRM:** Strip watermark injection code from media apps so that pirated content can be distributed without tracing back to the attacker's account.
*   **Risk scoring bypass:** Remove or neuter fraud-detection logic embedded directly in the client (e.g., device fingerprinting, behavior analysis), making fraudulent transactions appear legitimate.

**The deeper danger — server trust:**

Many apps perform critical logic on the client and send the **result** (not the raw inputs) to the server. If an attacker modifies your client to always send `"transaction_type": "bonus"` instead of `"purchase"`, and your server trusts this client-supplied value, the attacker has effectively stolen from you. This is an architectural vulnerability that root detection alone cannot fix, but root detection is the **first line of defense** that signals to your backend that the environment is untrusted.

### Detection Strategies and Their Limitations

| Technique | What It Checks | Bypass Difficulty |
|---|---|---|
| Check for `su` binary | Common superuser binaries | Low — file can be hidden |
| Check for known root apps (Magisk, Superuser) | Installed package names | Low — MagiskHide renames packages |
| `SafetyNet` / `Play Integrity API` (Android) | Attestation from Google servers | Medium — requires custom ROMs |
| `DeviceCheck` / `AppAttest` (iOS) | Apple-signed hardware attestation | High |
| Check `BUILD_TAGS` for `test-keys` | Unofficial Android builds | Medium |
| Detect Frida / Cydia ports | Known analysis tool artifacts | Medium |
| Behavioral analysis (runtime RASP) | Anomalous memory access patterns | High |

> [!TIP]
> The most robust approach combines **multiple layers**: client-side checks (easily bypassed but cheap), server-side behavioral analysis (hard to bypass), and hardware attestation APIs (Google Play Integrity / Apple AppAttest) which are extremely difficult to spoof on modern hardware.

---

## 시스템의 자물쇠를 부수는 기술: 루팅과 탈옥의 모든 것

스마트폰을 구매했을 때, 당신은 정말 그 기기의 완전한 주인일까요? 제조사와 운영체제 개발자는 안정성과 보안이라는 명목 아래 수많은 기능을 제한하고 사용자를 '안전한 울타리' 안에 가두어 둡니다. 하지만 우리, 즉 시스템의 한계를 탐험하고 그 너머를 보려는 이들에게 그 울타리는 답답한 감옥에 불과합니다.

**루팅(Rooting)**과 **탈옥(Jailbreak)**은 바로 이 디지털 감옥의 자물쇠를 부수고, 기기의 진정한 소유권을 되찾는 행위입니다. 이 글에서는 이 두 가지 기술이 무엇이며, 우리가 왜 기기의 봉인을 해제하려 하는지, 그리고 그 힘으로 무엇을 할 수 있는지에 대해 이야기해 보겠습니다.


### 안드로이드의 해방: 루팅(Rooting)

루팅은 안드로이드 운영체제의 **최고 관리자(root) 권한**을 획득하는 과정을 의미합니다. 리눅스(Linux)에 기반한 안드로이드에서 'root'는 모든 파일과 프로세스에 접근하고 수정할 수 있는 전능한 사용자입니다. 기본적으로 제조사는 이 막강한 권한을 사용자에게서 숨겨 놓습니다.

### **우리가 루트 권한을 원하는 이유 (해커의 관점)**

루트 권한은 단순한 커스터마이징을 넘어, 시스템을 분석하고 공격하기 위한 강력한 무기가 됩니다.

  * **시스템 파일 접근 및 변조:** 시스템 앱에 코드를 주입하거나, 보안 설정을 무력화하고, 로그 파일을 조작하여 흔적을 지울 수 있습니다.
  * **강력한 분석 도구 실행:** Frida, Ghidra와 같은 리버싱 및 동적 분석 도구의 모든 기능을 활성화하여 앱의 내부 로직을 낱낱이 파헤칠 수 있습니다.
  * **네트워크 트래픽 감청:** 시스템 전반의 네트워크 트래픽을 가로채고 분석하여 암호화되지 않은 민감 정보를 추출하거나 통신 프로토콜을 분석할 수 있습니다.
  * **커널 익스플로잇:** 커널 수준의 취약점을 직접 공략하여 더욱 깊은 시스템 제어권을 획득하고 영구적인 백도어를 설치할 수 있습니다.

### **루팅 실행 가이드 (일반적인 절차)**

**⚠️ 경고: 이 과정은 기기의 보증을 무효화할 수 있으며, 잘못된 단계를 수행할 경우 기기가 부팅 불능 상태(벽돌)가 될 수 있습니다. 시작하기 전에 반드시 모든 데이터를 백업하고, 모든 책임은 본인에게 있음을 명심하십시오.**

**1단계: 부트로더 언락 (Bootloader Unlock)**
부트로더는 OS가 부팅되기 전 실행되는 초기 단계의 소프트웨어입니다. 이를 풀어야 커스텀 소프트웨어를 설치할 수 있습니다.

  * **PC 준비:** ADB 및 Fastboot 도구를 PC에 설치합니다.
  * **기기 설정:** '개발자 옵션'을 활성화하고, 해당 메뉴에서 **'OEM 잠금 해제'**와 **'USB 디버깅'**을 켭니다.
  * **언락 실행:** 기기를 PC에 연결하고 `adb reboot bootloader` 명령어로 부트로더 모드에 진입한 뒤, `fastboot flashing unlock` 명령어를 실행합니다. 이 과정에서 **기기의 모든 데이터가 삭제됩니다.**

**2단계: 커스텀 리커버리 설치 (TWRP 등)**
커스텀 리커버리는 루팅 패키지 등 커스텀 소프트웨어를 설치(flashing)하게 해주는 특별한 복구 환경입니다. **TWRP**가 가장 널리 쓰입니다.

  * 자신의 기기 모델에 맞는 TWRP 이미지 파일(`*.img`)을 다운로드합니다.
  * 기기를 다시 부트로더 모드로 부팅하고, `fastboot flash recovery twrp.img` 명령어로 TWRP를 설치합니다.

**3단계: 루팅 패키지 설치 (Magisk)**
**Magisk**는 시스템 파티션을 직접 건드리지 않는 'Systemless' 방식으로 루트 권한을 활성화하는 현재 가장 표준적인 루팅 도구입니다.

  * 최신 Magisk 설치 파일(`*.zip`)을 다운로드하여 기기 저장소에 복사합니다.
  * TWRP 리커버리 모드로 부팅하여 'Install' 메뉴에서 Magisk zip 파일을 선택하고 설치합니다.
  * 설치가 완료되고 재부팅한 뒤, Magisk 앱이 보이면 루팅이 성공적으로 완료된 것입니다.


### iOS의 탈출: 탈옥(Jailbreak)

탈옥은 애플이 구축한 폐쇄적인 생태계, 이른바 **'벽으로 둘러싸인 정원(Walled Garden)'**에서 탈출하는 행위입니다. App Store를 통하지 않은 앱 설치를 금지하고 시스템 파일 접근을 원천적으로 차단하는 모든 족쇄를 풀어버리는 과정입니다.

### **우리가 감옥을 탈출하는 이유 (해커의 관점)**

탈옥한 아이폰은 애플이 정해준 길을 따르는 장난감이 아니라, 내부 구조를 속속들이 파헤치고 분석할 수 있는 강력한 **연구 장비**가 됩니다.

  * **샌드박스 우회 및 파일 시스템 접근:** 앱의 샌드박스 제한을 넘어 다른 앱의 데이터에 접근하거나, 시스템 전역의 파일을 읽고 쓸 수 있게 됩니다.
  * **강력한 분석 도구 실행:** Frida, Cycript 등 동적 분석 도구를 사용하여 실행 중인 앱의 내부 동작을 분석하고 메서드를 후킹하여 실시간으로 로직을 조작할 수 있습니다.
  * **SSH 원격 접속:** PC에서 터미널을 통해 iOS 기기에 원격으로 접속하여 셸 명령어를 실행하고, 시스템 내부를 자유롭게 탐색하며 분석 환경을 구축할 수 있습니다.
  * **비공식 앱 설치 및 분석:** 리패키징된 앱이나 분석용으로 제작된 앱(`*.ipa`)을 App Store 없이 설치하여 취약점을 분석할 수 있습니다.

### **탈옥 실행 가이드 (`palera1n` 기준)**

`palera1n`은 A8부터 A11 칩셋을 사용하는 구형 기기(아이폰 6s \~ 아이폰 X)를 대상으로 하며, **하드웨어 취약점 (`checkm8`)**을 이용하기 때문에 애플이 소프트웨어로 막을 수 없는 강력한 탈옥 방식입니다. iOS 15부터 최신 iOS 17 버전까지 지원합니다.

**⚠️ 경고: 이 과정은 기기의 보증을 무효화할 수 있으며, 보안에 매우 취약해질 수 있습니다. 시작하기 전에 반드시 모든 데이터를 백업하고, 모든 책임은 본인에게 있음을 명심하십시오.**

**1단계: PC에 `palera1n` 준비하기**

이 탈옥은 **macOS 또는 Linux 환경**의 PC가 반드시 필요합니다.

  * **Git 저장소 복제:** 터미널을 열고 아래 명령어를 입력하여 `palera1n`을 다운로드합니다.
    ```bash
    git clone --recursive https://github.com/palera1n/palera1n && cd palera1n
    ```
  * **스크립트 실행:** 아래 명령어로 스크립트를 실행합니다. `--tweaks` 옵션은 Sileo 같은 패키지 매니저를 설치하고 트윅을 사용할 수 있게 해주는 필수 플래그입니다.
    ```bash
    sudo ./palera1n.sh --tweaks
    ```

**2단계: DFU 모드 진입 및 탈옥 진행**

스크립트가 실행되면, 화면의 안내에 따라 기기를 **DFU (Device Firmware Update) 모드**로 진입시켜야 합니다. DFU 모드는 화면이 완전히 꺼진 상태이지만 PC는 기기를 인식하는 특수 모드입니다.

  * **DFU 모드 진입:** 터미널의 타이머에 맞춰 버튼을 누릅니다. (예: 아이폰 8/X의 경우, 볼륨 하(-) 버튼과 측면 버튼을 정해진 시간 동안 조합하여 누름)
  * **자동 진행:** DFU 모드 진입에 성공하면 `palera1n` 스크립트가 자동으로 나머지 과정을 진행합니다. 과정이 끝날 때까지 케이블을 절대 분리하지 마세요.

**3단계: 기기에서 마무리 설정**

탈옥이 완료되고 홈 화면으로 돌아오면, **palera1n 로더 앱**이 설치된 것을 볼 수 있습니다.

  * `palera1n` 로더 앱을 실행하여 **Sileo** 또는 **Zebra** 같은 패키지 매니저를 설치합니다.
  * 홈 화면에 Sileo가 설치되면, 이를 통해 원하는 트윅을 설치하며 자유로워진 기기를 활용할 수 있습니다.

**참고: 재부팅 후 다시 탈옥하기**
`palera1n`은 **반탈옥(Semi-tethered)** 방식이므로, 기기를 재부팅하면 탈옥 상태가 풀립니다. 이때는 다시 PC에 연결하여 위 **1, 2단계**를 반복하면 기존 데이터는 유지된 채로 탈옥 상태만 다시 활성화됩니다.

## 앱 개발자가 루트/탈옥 감지를 반드시 구현해야 하는 이유

지금까지는 **공격자의 관점**에서 루팅과 탈옥이 열어주는 가능성을 살펴보았습니다. 그러나 이 이야기에는 동등하게 중요한 반대편이 있습니다. 바로 자신의 앱과 사용자를 보호해야 하는 **앱 개발자와 비즈니스 오너**의 관점입니다.

은행 앱이 왜 탈옥된 기기에서 실행을 거부할까요? DRM으로 보호된 스트리밍 서비스가 왜 루트 여부를 검사할까요? 이 섹션에서는 루트/탈옥 감지가 모든 진지한 모바일 앱에서 **핵심 보안 통제**가 되어야 하는 이유를 구체적인 위협 시나리오를 통해 살펴봅니다.

### 적대적 환경이라는 전제

모바일 기기는 운영자가 완전히 통제하는 서버와 근본적으로 다릅니다. 앱은 사용자가 소유한 하드웨어에 배포되며, 그 하드웨어는 잠재적 공격자의 손에 있을 수 있습니다. 기기에 루트나 탈옥이 존재하는 순간, 앱의 **전체 보안 모델이 달라집니다**:

*   앱 간의 핵심 격리 메커니즘인 **운영체제의 샌드박스**가 우회 가능하게 됩니다.
*   다른 프로세스가 앱의 메모리를 읽을 수 있도록 **메모리 보호** 메커니즘이 무력화됩니다.
*   **파일 시스템 보호**가 제거되어 앱의 프라이빗 데이터 디렉터리에 접근 가능해집니다.
*   **커널 수준의 후킹**으로 앱이 수행하는 모든 시스템 콜을 가로챌 수 있습니다.

이것이 OWASP 모바일 Top 10(2017년 및 2024년 버전 모두)이 루트/탈옥 감지 부재를 바이너리 보호 및 환경 검사 항목에서 지속적으로 심각한 취약점으로 분류하는 이유입니다.

### 위협 시나리오 1: 자신의 폰을 스스로 루팅한 공격자

가장 흔한 시나리오입니다. 사용자 또는 악의적인 행위자가 **자신의 기기**를 의도적으로 루팅하거나 탈옥시켜 앱을 공격합니다. 이는 가설이 아니라 모바일 모의해킹과 실제 사기 범죄의 표준 방법론입니다.

**공격자가 얻는 것:**

*   **파일 시스템 전체 접근:** 앱의 `SharedPreferences`, SQLite 데이터베이스, `plist` 파일을 직접 읽습니다. 기기에 저장된 인증 토큰, 세션 키, API 키는 후킹 없이도 바로 획득 가능합니다.
*   **동적 계측 (Frida/Objection):** 루트 권한으로 Frida를 앱 프로세스에 주입하여 실시간으로 어떤 함수든 후킹합니다. 인증서 피닝 우회, 라이선스 검사 무력화, 복호화된 메모리 덤프, 중요 함수의 반환값 조작이 모두 가능해집니다.
*   **바이너리 추출 및 리패키징:** 기기에서 실제 APK나 IPA를 추출하고, 디컴파일하여 수정(결제 로직, 안티치트 로직, 워터마크 제거 등)한 뒤 재배포합니다.
*   **간편한 트래픽 가로채기:** 루팅된 기기에서는 Magisk 모듈이나 `/etc/hosts` 조작으로 Burp Suite 프록시 설정이 매우 쉬워지며, 인증서 피닝도 무력화하기 쉬워집니다.

**비즈니스 관점의 실제 피해:**
*   경쟁사가 독점적인 핵심 알고리즘을 역공학으로 탈취합니다.
*   인앱 결제가 우회되어 직접적인 매출 손실이 발생합니다.
*   추출된 인증 토큰이 다른 인프라에서 재사용됩니다.
*   노출된 API 키를 통한 무단 API 남용으로 인프라 비용이 급증합니다.

> [!WARNING]
> 루트 감지를 구현하더라도 결단력 있는 공격자는 감지 로직 자체를 후킹하여 우회할 수 있습니다. 그러나 루트 감지는 **공격의 난이도를 극적으로 높여**, 상당한 시간과 전문 지식이 필요하게 만들어 기회주의적 위협의 대부분을 차단합니다.

### 위협 시나리오 2: 고객이 모르는 사이 원격으로 루팅된 기기

이것이 더 위험하고 덜 알려진 시나리오입니다. **고객 자신은 자신의 기기가 루팅되었다는 사실을 모릅니다.** 이는 다음과 같이 발생할 수 있습니다:

*   **권한 상승 익스플로잇이 포함된 악성 앱:** 겉으로 보이기에 무해한 앱(주로 서드파티 마켓의 게임이나 유틸리티)이 패치되지 않은 커널 취약점을 악용하여 조용히 루트 권한을 획득합니다. **Ztorg**, **Ghost Push**, **Hummingbad**와 같은 악성코드 계열이 수백만 대의 기기를 이런 식으로 감염시켰습니다.
*   **비공식 유통망의 사전 루팅 기기:** 비공식 채널이나 중고 판매점에서 구매한 기기가 백도어가 심어진 펌웨어와 함께 사전 루팅된 상태로 도착하는 경우가 있습니다. 사용자는 전혀 알 수 없습니다.
*   **기업용 MDM 침해:** BYOD(개인 기기 업무 사용) 환경에서 침해된 MDM(모바일 기기 관리) 프로파일이 관리자 수준 접근을 부여할 수 있습니다. 이는 Pegasus 스파이웨어와 같은 국가 수준의 사이버 공격에서 악용된 사례가 있습니다.
*   **펌웨어 공급망 공격:** 비공식 OTA 업데이트 채널을 통해 배포된 변조 펌웨어가 사용자 몰래 루트 접근 권한을 유지하도록 설계될 수 있습니다.

**이것이 여러분의 앱에 미치는 영향:**

여러분의 정상 사용자가 **피해자**가 됩니다. 기기에 심어진 악성코드는:
*   사용자가 앱을 실제로 사용하는 동안 메모리에서 복호화된 데이터를 실시간으로 읽습니다.
*   커널 수준에서 네트워크 호출을 가로채어 인증서 피닝을 우회합니다.
*   사용자가 앱과 상호작용하는 동안 접근성 훅을 통해 스크린샷이나 음성을 캡처합니다.
*   세션 토큰을 **실시간으로** 탈취하여 정상 사용자인 것처럼 위장한 계정 탈취를 수행합니다.

서버 입장에서는 이 공격이 **완전히 정상적으로 보입니다** — 동일한 사용자, 동일한 기기 지문, 유효한 세션 토큰. 앱이 적대적인 환경을 감지하고 작동을 거부하거나 백엔드에 경보를 보내지 않는다면, 이 공격에 대응할 방법이 없습니다.

> [!CAUTION]
> 이 위협 시나리오는 금융 및 헬스케어 앱에서 루트 감지를 의무화하는 규제 및 컴플라이언스 프레임워크(예: 모바일 결제 앱의 PCI-DSS, FIDO Alliance 가이드라인)가 제시하는 핵심 근거입니다.

### 위협 시나리오 3: 변조된 바이너리를 통한 비즈니스 로직 조작

이 시나리오는 데이터가 아닌 **앱 로직의 무결성**을 표적으로 삼습니다. 루팅되거나 탈옥된 기기에서 공격자는 앱 바이너리를 수정하고 수정된 버전을 실행할 수 있습니다. 이를 "리패키징" 또는 "패치 공격"이라고도 합니다.

**공격자가 수정하는 것들:**

*   **결제 및 구독 로직:** 서버와 유료 구독이나 인앱 구매 영수증을 검증하는 코드를 제거합니다. 조작된 앱은 사용자가 프리미엄 계정을 가진 것처럼 동작합니다.
*   **게임의 안티치트 및 사기 방지 로직:** 속도 제한, 아이템 수량 검사, 리더보드 제출 검증을 비활성화합니다. 조작된 앱이 부정한 고점수나 게임 상태를 백엔드로 전송합니다.
*   **포인트 및 리워드 시스템:** 리워드 프로그램이 있는 앱에서 포인트 계산 로직이나 쿠폰 생성 코드를 조작합니다. 공격자는 포인트를 부정하게 적립하거나 무제한 할인 코드를 생성할 수 있습니다.
*   **디지털 워터마킹 및 DRM:** 미디어 앱에서 워터마크 삽입 코드를 제거하여, 피해자의 계정으로 추적 불가능한 불법 복제 콘텐츠를 배포합니다.
*   **위험도 점수 우회:** 클라이언트에 직접 내장된 사기 탐지 로직(예: 기기 지문, 행동 분석)을 제거하거나 무력화하여 부정 거래가 정상처럼 보이게 만듭니다.

**더 깊은 위험 — 서버의 클라이언트 신뢰:**

많은 앱들이 클라이언트에서 핵심 로직을 수행하고 그 **결과**(원시 입력값이 아닌)만 서버로 전송합니다. 공격자가 클라이언트를 조작하여 항상 `"purchase"` 대신 `"bonus"`를 전송하도록 만들고, 서버가 이 클라이언트 제공 값을 신뢰한다면 공격자는 사실상 기업의 돈을 훔친 것입니다. 이는 루트 감지 만으로는 해결할 수 없는 구조적 취약점이지만, 루트 감지는 백엔드에 "이 환경을 신뢰하지 마라"는 신호를 보내는 **1차 방어선**입니다.

### 감지 전략과 그 한계

| 기법 | 검사 대상 | 우회 난이도 |
|---|---|---|
| `su` 바이너리 존재 확인 | 주요 슈퍼유저 바이너리 | 낮음 — 파일 경로 숨기기 가능 |
| 알려진 루트 앱 패키지명 확인 | Magisk, Superuser 등 | 낮음 — MagiskHide로 패키지명 위장 가능 |
| `SafetyNet` / `Play Integrity API` (Android) | Google 서버 기반 증명 | 중간 — 커스텀 ROM 필요 |
| `DeviceCheck` / `AppAttest` (iOS) | Apple 하드웨어 증명 | 높음 |
| `BUILD_TAGS` 검사 (`test-keys` 여부) | 비공식 안드로이드 빌드 | 중간 |
| Frida / Cydia 관련 포트 및 파일 탐지 | 알려진 분석 도구의 흔적 | 중간 |
| 런타임 행동 분석 (RASP) | 비정상적인 메모리 접근 패턴 | 높음 |

> [!TIP]
> 가장 견고한 접근법은 **여러 계층의 조합**입니다. 클라이언트 측 검사(우회하기 쉽지만 비용이 저렴), 서버 측 행동 분석(우회하기 어려움), 그리고 최신 하드웨어에서 위조가 극히 어려운 Google Play Integrity / Apple AppAttest 같은 하드웨어 증명 API를 함께 사용하는 것이 권장됩니다.