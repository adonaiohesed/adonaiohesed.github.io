---
title: Rooting & Jailbreak
tags: Rooting Jailbreak
key: page-tag
categories: [Cybersecurity, Mobile Security]
author: hyoeun
math: true
mathjax_autoNumber: true
---

## The Art of Breaking System Locks: Everything About Rooting and Jailbreaking

When you buy a smartphone, are you truly the owner of the device? Manufacturers and operating system developers, under the pretext of stability and security, restrict numerous functions and confine users within a 'safe wall'. However, for those of us who seek to explore the system's limits and see beyond them, that wall is nothing more than a frustrating prison.

**Rooting** and **Jailbreaking** are the acts of breaking the locks of this digital prison and reclaiming true ownership of the device. In this article, we will discuss what these two technologies are, why we seek to unlock our devices, and what we can do with that power.

-----

### The Liberation of Android: Rooting

Rooting is the process of obtaining **superuser (root) privileges** on the Android operating system. In Android, which is based on Linux, 'root' is an all-powerful user who can access and modify all files and processes. By default, manufacturers hide this immense power from the user.

#### **Why We Want Root Access (A Hacker's Perspective)**

Beyond simple customization, root access becomes a powerful weapon for analyzing and attacking a system.

  * **System File Access and Modification:** You can inject code into system apps, disable security settings, and manipulate log files to erase traces.
  * **Execution of Powerful Analysis Tools:** You can enable the full functionality of reversing and dynamic analysis tools like Frida and Ghidra to dissect an app's internal logic.
  * **Network Traffic Sniffing:** You can intercept and analyze system-wide network traffic to extract sensitive unencrypted information or analyze communication protocols.
  * **Kernel Exploitation:** You can directly attack kernel-level vulnerabilities to gain deeper system control and install persistent backdoors.

#### **Rooting Guide (General Procedure)**

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

-----

### The Escape from iOS: Jailbreaking

Jailbreaking is the act of escaping from Apple's closed ecosystem, the so-called **'Walled Garden'**. It's the process of breaking all the shackles that prohibit app installation outside of the App Store and block access to system files.

#### **Why We Escape the Prison (A Hacker's Perspective)**

A jailbroken iPhone is no longer a toy that follows the path set by Apple; it becomes a powerful **research tool** for dissecting its internal structure.

  * **Sandbox Bypass and Filesystem Access:** You can bypass app sandbox restrictions to access data from other apps or read and write files across the entire system.
  * **Execution of Powerful Analysis Tools:** You can use dynamic analysis tools like Frida and Cycript to analyze the internal behavior of running apps and hook methods to manipulate logic in real-time.
  * **SSH Remote Access:** You can remotely connect to the iOS device from a PC via a terminal to execute shell commands, freely navigate the internal system, and build an analysis environment.
  * **Sideloading and Analysis of Apps:** You can install repackaged or analysis-purposed apps (`*.ipa`) without the App Store to analyze vulnerabilities.

#### **Jailbreaking Guide (Based on `palera1n`)**

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

---

## 시스템의 자물쇠를 부수는 기술: 루팅과 탈옥의 모든 것

스마트폰을 구매했을 때, 당신은 정말 그 기기의 완전한 주인일까요? 제조사와 운영체제 개발자는 안정성과 보안이라는 명목 아래 수많은 기능을 제한하고 사용자를 '안전한 울타리' 안에 가두어 둡니다. 하지만 우리, 즉 시스템의 한계를 탐험하고 그 너머를 보려는 이들에게 그 울타리는 답답한 감옥에 불과합니다.

\*\*루팅(Rooting)\*\*과 \*\*탈옥(Jailbreak)\*\*은 바로 이 디지털 감옥의 자물쇠를 부수고, 기기의 진정한 소유권을 되찾는 행위입니다. 이 글에서는 이 두 가지 기술이 무엇이며, 우리가 왜 기기의 봉인을 해제하려 하는지, 그리고 그 힘으로 무엇을 할 수 있는지에 대해 이야기해 보겠습니다.

-----

### 안드로이드의 해방: 루팅(Rooting)

루팅은 안드로이드 운영체제의 **최고 관리자(root) 권한**을 획득하는 과정을 의미합니다. 리눅스(Linux)에 기반한 안드로이드에서 'root'는 모든 파일과 프로세스에 접근하고 수정할 수 있는 전능한 사용자입니다. 기본적으로 제조사는 이 막강한 권한을 사용자에게서 숨겨 놓습니다.

#### **우리가 루트 권한을 원하는 이유 (해커의 관점)**

루트 권한은 단순한 커스터마이징을 넘어, 시스템을 분석하고 공격하기 위한 강력한 무기가 됩니다.

  * **시스템 파일 접근 및 변조:** 시스템 앱에 코드를 주입하거나, 보안 설정을 무력화하고, 로그 파일을 조작하여 흔적을 지울 수 있습니다.
  * **강력한 분석 도구 실행:** Frida, Ghidra와 같은 리버싱 및 동적 분석 도구의 모든 기능을 활성화하여 앱의 내부 로직을 낱낱이 파헤칠 수 있습니다.
  * **네트워크 트래픽 감청:** 시스템 전반의 네트워크 트래픽을 가로채고 분석하여 암호화되지 않은 민감 정보를 추출하거나 통신 프로토콜을 분석할 수 있습니다.
  * **커널 익스플로잇:** 커널 수준의 취약점을 직접 공략하여 더욱 깊은 시스템 제어권을 획득하고 영구적인 백도어를 설치할 수 있습니다.

#### **루팅 실행 가이드 (일반적인 절차)**

**⚠️ 경고: 이 과정은 기기의 보증을 무효화할 수 있으며, 잘못된 단계를 수행할 경우 기기가 부팅 불능 상태(벽돌)가 될 수 있습니다. 시작하기 전에 반드시 모든 데이터를 백업하고, 모든 책임은 본인에게 있음을 명심하십시오.**

**1단계: 부트로더 언락 (Bootloader Unlock)**
부트로더는 OS가 부팅되기 전 실행되는 초기 단계의 소프트웨어입니다. 이를 풀어야 커스텀 소프트웨어를 설치할 수 있습니다.

  * **PC 준비:** ADB 및 Fastboot 도구를 PC에 설치합니다.
  * **기기 설정:** '개발자 옵션'을 활성화하고, 해당 메뉴에서 \*\*'OEM 잠금 해제'\*\*와 \*\*'USB 디버깅'\*\*을 켭니다.
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

-----

### iOS의 탈출: 탈옥(Jailbreak)

탈옥은 애플이 구축한 폐쇄적인 생태계, 이른바 \*\*'벽으로 둘러싸인 정원(Walled Garden)'\*\*에서 탈출하는 행위입니다. App Store를 통하지 않은 앱 설치를 금지하고 시스템 파일 접근을 원천적으로 차단하는 모든 족쇄를 풀어버리는 과정입니다.

#### **우리가 감옥을 탈출하는 이유 (해커의 관점)**

탈옥한 아이폰은 애플이 정해준 길을 따르는 장난감이 아니라, 내부 구조를 속속들이 파헤치고 분석할 수 있는 강력한 **연구 장비**가 됩니다.

  * **샌드박스 우회 및 파일 시스템 접근:** 앱의 샌드박스 제한을 넘어 다른 앱의 데이터에 접근하거나, 시스템 전역의 파일을 읽고 쓸 수 있게 됩니다.
  * **강력한 분석 도구 실행:** Frida, Cycript 등 동적 분석 도구를 사용하여 실행 중인 앱의 내부 동작을 분석하고 메서드를 후킹하여 실시간으로 로직을 조작할 수 있습니다.
  * **SSH 원격 접속:** PC에서 터미널을 통해 iOS 기기에 원격으로 접속하여 셸 명령어를 실행하고, 시스템 내부를 자유롭게 탐색하며 분석 환경을 구축할 수 있습니다.
  * **비공식 앱 설치 및 분석:** 리패키징된 앱이나 분석용으로 제작된 앱(`*.ipa`)을 App Store 없이 설치하여 취약점을 분석할 수 있습니다.

#### **탈옥 실행 가이드 (`palera1n` 기준)**

`palera1n`은 A8부터 A11 칩셋을 사용하는 구형 기기(아이폰 6s \~ 아이폰 X)를 대상으로 하며, \*\*하드웨어 취약점 (`checkm8`)\*\*을 이용하기 때문에 애플이 소프트웨어로 막을 수 없는 강력한 탈옥 방식입니다. iOS 15부터 최신 iOS 17 버전까지 지원합니다.

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