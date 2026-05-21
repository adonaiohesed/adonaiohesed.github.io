---
title: Anti-Tamper
key: page-anti_tamper
categories:
- Security
- Mobile Security
author: hyoeun
math: true
mathjax_autoNumber: true
image: "/assets/thumbnails/2023-05-12-anti_tamper.png"
bilingual: true
date: 2023-05-12 01:40:48
---

## Anti-Tamper: Defending Your App Against Reverse Engineers

A mobile app binary (`APK` for Android, `IPA` for iOS) can be downloaded by anyone, decompiled, analyzed, modified, and repacked. Unlike server-side code that stays safely behind a firewall, your app lives on a device that could be fully controlled by an attacker who has root or jailbreak access. This is why **Anti-Tamper** protection is one of the most critical security concerns in mobile development.

Anti-Tamper is a category of defensive techniques designed to detect and respond to unauthorized modification of an app — whether the attacker is patching the binary, hooking at runtime, or running the app in an untrusted environment. In this post, we'll cover the core Anti-Tamper techniques across Android and iOS, how each one works under the hood, and why they matter.

## 1. Code Signing Verification

The first and most fundamental layer of Anti-Tamper is verifying that the app binary has not been altered since it was originally signed by the developer.

### Android

Android uses `META-INF/` directory inside the APK to store the signature files (`.SF`, `.RSA`/`.DSA`/`.EC`). Every entry in the APK is hashed and signed.

- **APK Signature Scheme v2/v3** introduced in Android 7.0+ signs the entire APK file, including the `META-INF/` block. This means even modifying a single byte outside the original manifest will invalidate the signature.
- Apps can verify their own signature at runtime using `PackageManager`:

```java
PackageInfo info = getPackageManager().getPackageInfo(
    getPackageName(), PackageManager.GET_SIGNATURES);
Signature[] signatures = info.signatures;
// Compare with expected hardcoded hash
```

- **Limitation**: This can be bypassed by hooking `getPackageInfo` via Frida or Xposed to return the expected signature.

### iOS

iOS enforces code signing at the OS level using Apple-issued certificates. The `_CodeSignature/CodeResources` file in the IPA contains hashes of every file in the bundle. Before execution, the OS validates these hashes.

- Apps can additionally call `SecStaticCodeCheckValidityWithErrors` or inspect `MachO` load commands like `LC_CODE_SIGNATURE` to verify the in-memory code signature.
- On jailbroken devices, tools like `ldid` can re-sign modified binaries, bypassing this check at the OS level — which is why in-app runtime checks are essential.

## 2. Binary Integrity Checks (Checksum / Hash Verification)

Beyond code signing, an app can explicitly compute and verify the hash of its own critical files at runtime.

### Android

- Compute the **CRC32** or **SHA-256** of `classes.dex` (or its split DEX files in multi-dex setups) and compare it against a value hardcoded at build time.
- For native libraries, similarly hash the `.so` files under `lib/`.

```java
ZipFile apk = new ZipFile(context.getPackageCodePath());
ZipEntry dex = apk.getEntry("classes.dex");
long crc = dex.getCrc();
// Compare against expected constant
```

- An attacker who patches Smali bytecode or recompiles from decompiled source will produce a different CRC, triggering detection.

### iOS

- Compute the hash of the `__TEXT` segment of the Mach-O binary in memory, which contains the executable code.
- Compare it against a pre-computed expected value embedded in the `__DATA` segment.

```c
// Read mach_header, iterate LC_SEGMENT_64 for __TEXT
// SHA-256 the bytes of __TEXT.__text section
// Compare with expected[]
```

- This detects patching of the binary at byte level, which is the most common form of iOS tampering (e.g., cracking in-app purchases by patching branch instructions).

## 3. Anti-Debugging

Tampering attacks are almost always preceded by dynamic analysis with a debugger. Anti-debugging techniques prevent an attacker from attaching a debugger to the running process.

### Android

**`TracerPid` Check**

On Linux, every process has a `/proc/self/status` file. The `TracerPid` field shows the PID of any process tracing the current process. Under normal execution, this is `0`. When a debugger (or Frida) attaches, this value changes.

```c
// Native (JNI)
FILE* f = fopen("/proc/self/status", "r");
char line[256];
while (fgets(line, sizeof(line), f)) {
    if (strncmp(line, "TracerPid:", 10) == 0) {
        int pid = atoi(line + 10);
        if (pid != 0) { /* debugger detected */ }
    }
}
```

**`android_server` / JDWP Port Detection**

IDA Pro's remote debugger (`android_server`) opens a predictable port (23946). Checking open sockets in `/proc/net/tcp` can reveal it. Similarly, checking `ro.debuggable` system property or the presence of JDWP threads exposes debugging sessions.

### iOS

**`ptrace(PT_DENY_ATTACH, ...)`**

This is the classic iOS anti-debug trick. The `ptrace` system call with the `PT_DENY_ATTACH` flag tells the kernel to reject any future `ptrace` request to attach to this process. Called early in `main()` or a `+load` method, it prevents lldb from attaching.

```c
#import <sys/ptrace.h>
ptrace(PT_DENY_ATTACH, 0, 0, 0);
```

**`sysctl` Self-Check**

```c
int mib[4] = { CTL_KERN, KERN_PROC, KERN_PROC_PID, getpid() };
struct kinfo_proc info;
size_t size = sizeof(info);
sysctl(mib, 4, &info, &size, NULL, 0);
bool isDebugged = (info.kp_proc.p_flag & P_TRACED) != 0;
```

This queries the kernel directly for the traced flag, making it harder to bypass than `ptrace` alone.

## 4. Anti-Hooking

Runtime hooking frameworks like **Frida** and **Xposed** are the primary tools attackers use to bypass security checks. Anti-hooking aims to detect or prevent these frameworks from operating.

### Detecting Frida

Frida injects a gadget library (`frida-agent`) into the target process. There are several detection strategies:

**Loaded Library Scan**

```c
// Check /proc/self/maps for frida-related strings
FILE* maps = fopen("/proc/self/maps", "r");
char line[512];
while (fgets(line, sizeof(line), maps)) {
    if (strstr(line, "frida") || strstr(line, "gum-js-loop")) {
        // Frida detected
    }
}
```

**Named Pipe / Port Scan**

Frida's default server listens on TCP port `27042`. Attempting a connection to `localhost:27042` from within the app can reveal it.

**Inline Hook Detection**

Frida modifies the first few instructions of hooked functions (e.g., inserting a `BL` or `B` branch on ARM). You can detect this by reading the bytes of a sensitive function and checking whether the prologue matches what was compiled.

### Detecting Xposed (Android)

Xposed inserts itself into `zygote`, causing all forked app processes to have Xposed's JARs on the classpath and certain stack frames in every exception.

```java
try {
    throw new Exception();
} catch (Exception e) {
    for (StackTraceElement el : e.getStackTrace()) {
        if (el.getClassName().contains("de.robv.android.xposed")) {
            // Xposed detected
        }
    }
}
```

## 5. Environment Checks (Root / Jailbreak Detection)

Most tampering tools only work on rooted (Android) or jailbroken (iOS) devices. Detecting these environments is a key layer of Anti-Tamper.

### Android Root Detection

| Check | Detail |
|---|---|
| `su` binary | Look for `/system/bin/su`, `/system/xbin/su`, `/sbin/su` |
| `busybox` presence | Often bundled with root |
| Test file write to `/system` | Non-rooted devices deny write to system partitions |
| `ro.build.tags` | `test-keys` instead of `release-keys` may indicate a modified system |
| Dangerous app packages | Check for Magisk Manager, SuperSU, KingRoot |

### iOS Jailbreak Detection

| Check | Detail |
|---|---|
| Cydia / Sileo file paths | `/Applications/Cydia.app`, `/usr/sbin/sshd`, `/bin/bash` |
| Sandbox escape test | Try writing to `/private/jailbreak_test.txt` — succeeds on jailbroken devices |
| URL scheme check | `cydia://` scheme resolves on jailbroken devices |
| Dynamic library check | Iterate `dyld_image_count` for suspicious dylibs like `MobileSubstrate.dylib` |

## 6. Response Strategies

Detection alone is not enough — how you respond matters too. Common strategies:

- **Silent termination**: Kill the process quietly without warning, making it harder for the attacker to know what triggered detection.
- **Data corruption**: Subtly corrupt game data or session tokens so the attacker's modified app produces wrong results.
- **Server-side enforcement**: Report the tampered state to the server and block access or flag the account.
- **Delayed response**: Don't react immediately; react after a random delay or at a critical moment (e.g., during payment) to make reverse engineering harder.

## Limitations and the Arms Race

Anti-Tamper is not a silver bullet. Every technique described here can be bypassed with enough effort:

- **Frida** can hook the detection functions themselves before they run.
- **Magisk** offers "MagiskHide" to pass most root checks.
- **Objection** automates bypassing many common Anti-Tamper patterns.

The goal of Anti-Tamper is not to make tampering impossible — it's to make it expensive enough that most attackers give up. Defense in depth, combining multiple independent checks with server-side validation, raises the bar significantly.

---

## Anti-Tamper: 앱을 변조로부터 지키는 방어 기술

모바일 앱의 바이너리(`APK`, `IPA`)는 누구나 다운로드하고, 디컴파일하고, 분석하고, 수정한 뒤 재패키징할 수 있습니다. 서버 코드처럼 방화벽 뒤에 안전하게 숨어있을 수 없죠. 여러분의 앱은 루팅이나 탈옥을 통해 기기를 완전히 장악한 공격자의 손 위에서 실행될 수 있습니다. **Anti-Tamper**가 모바일 보안에서 핵심적인 이유가 바로 여기에 있습니다.

Anti-Tamper는 앱의 무단 변조를 탐지하고 대응하기 위한 방어 기술의 총체입니다. 공격자가 바이너리를 패치하든, 런타임에서 후킹하든, 신뢰할 수 없는 환경에서 실행하든 — 이 모든 시나리오를 막는 것이 목표입니다. 이 글에서는 Android와 iOS의 핵심 Anti-Tamper 기술, 각 기술이 내부에서 어떻게 동작하는지, 그리고 왜 중요한지를 살펴봅니다.

## 1. 코드 서명 검증 (Code Signing Verification)

Anti-Tamper의 가장 기본적인 첫 번째 레이어는, 앱 바이너리가 개발자의 서명 이후 변조되지 않았음을 검증하는 것입니다.

### Android

Android는 APK 내의 `META-INF/` 디렉토리에 서명 파일(`.SF`, `.RSA`/`.DSA`/`.EC`)을 저장합니다. APK의 모든 항목이 해시되어 서명됩니다.

- Android 7.0+에서 도입된 **APK Signature Scheme v2/v3**는 `META-INF/` 블록을 포함한 APK 파일 전체에 서명합니다. 원본 매니페스트 외부의 단 1바이트만 수정해도 서명이 무효화됩니다.
- 앱은 `PackageManager`를 통해 런타임에 자신의 서명을 직접 검증할 수 있습니다:

```java
PackageInfo info = getPackageManager().getPackageInfo(
    getPackageName(), PackageManager.GET_SIGNATURES);
Signature[] signatures = info.signatures;
// 하드코딩된 예상 해시와 비교
```

- **한계**: Frida나 Xposed로 `getPackageInfo`를 후킹해 예상된 서명 값을 반환하도록 속일 수 있습니다.

### iOS

iOS는 Apple이 발급한 인증서를 통해 OS 수준에서 코드 서명을 강제합니다. IPA 내의 `_CodeSignature/CodeResources` 파일에는 번들의 모든 파일 해시가 포함되어 있으며, 실행 전 OS가 이를 검증합니다.

- 앱은 추가로 `SecStaticCodeCheckValidityWithErrors`를 호출하거나 `LC_CODE_SIGNATURE` 같은 MachO load command를 검사하여 메모리 상의 코드 서명을 직접 확인할 수 있습니다.
- 탈옥된 기기에서는 `ldid` 같은 도구가 수정된 바이너리를 재서명하여 OS 수준의 검사를 우회할 수 있습니다. 따라서 앱 내부의 런타임 검사가 필수적입니다.

## 2. 바이너리 무결성 검사 (Binary Integrity Checks)

코드 서명 외에도, 앱은 런타임에 주요 파일의 해시를 직접 계산하여 검증할 수 있습니다.

### Android

- `classes.dex`(또는 멀티덱스 환경의 분할 DEX 파일)의 **CRC32** 또는 **SHA-256**을 계산하여, 빌드 시점에 하드코딩한 값과 비교합니다.
- 네이티브 라이브러리의 경우, `lib/` 아래의 `.so` 파일도 동일하게 해시 검증을 적용합니다.

```java
ZipFile apk = new ZipFile(context.getPackageCodePath());
ZipEntry dex = apk.getEntry("classes.dex");
long crc = dex.getCrc();
// 예상 상수와 비교
```

- 공격자가 Smali 바이트코드를 패치하거나 디컴파일된 소스에서 재컴파일하면 CRC가 달라져 탐지됩니다.

### iOS

- 메모리 상의 Mach-O 바이너리에서 실행 코드를 담고 있는 `__TEXT` 세그먼트의 해시를 계산합니다.
- 이 값을 `__DATA` 세그먼트에 미리 저장해둔 예상 값과 비교합니다.

```c
// mach_header를 읽어 LC_SEGMENT_64 중 __TEXT를 순회
// __TEXT.__text 섹션의 바이트를 SHA-256 해싱
// 예상값 expected[]와 비교
```

- 이는 인앱 결제 잠금 해제 등을 위해 분기 명령어를 패치하는, 가장 흔한 iOS 변조 형태를 탐지합니다.

## 3. 안티 디버깅 (Anti-Debugging)

변조 공격은 거의 항상 디버거를 이용한 동적 분석이 선행됩니다. 안티 디버깅은 공격자가 실행 중인 프로세스에 디버거를 연결하는 것을 막습니다.

### Android

**`TracerPid` 검사**

Linux의 모든 프로세스에는 `/proc/self/status` 파일이 있습니다. `TracerPid` 필드는 현재 프로세스를 추적하는 프로세스의 PID를 나타냅니다. 정상 실행 중에는 `0`이지만, 디버거(또는 Frida)가 연결되면 값이 바뀝니다.

```c
// 네이티브 (JNI)
FILE* f = fopen("/proc/self/status", "r");
char line[256];
while (fgets(line, sizeof(line), f)) {
    if (strncmp(line, "TracerPid:", 10) == 0) {
        int pid = atoi(line + 10);
        if (pid != 0) { /* 디버거 탐지됨 */ }
    }
}
```

**`android_server` / JDWP 포트 탐지**

IDA Pro의 원격 디버거(`android_server`)는 예측 가능한 포트(23946)를 엽니다. `/proc/net/tcp`의 열린 소켓을 확인하면 이를 탐지할 수 있습니다. 마찬가지로 `ro.debuggable` 시스템 속성이나 JDWP 스레드의 존재 여부를 확인하면 디버깅 세션을 노출시킬 수 있습니다.

### iOS

**`ptrace(PT_DENY_ATTACH, ...)`**

이것은 가장 고전적인 iOS 안티 디버깅 기법입니다. `PT_DENY_ATTACH` 플래그를 사용한 `ptrace` 시스템 콜은 커널에게 이 프로세스에 대한 향후 `ptrace` 연결 요청을 거부하도록 지시합니다. `main()` 초반이나 `+load` 메서드에서 호출하면 lldb가 연결되는 것을 원천 차단합니다.

```c
#import <sys/ptrace.h>
ptrace(PT_DENY_ATTACH, 0, 0, 0);
```

**`sysctl` 자가 검사**

```c
int mib[4] = { CTL_KERN, KERN_PROC, KERN_PROC_PID, getpid() };
struct kinfo_proc info;
size_t size = sizeof(info);
sysctl(mib, 4, &info, &size, NULL, 0);
bool isDebugged = (info.kp_proc.p_flag & P_TRACED) != 0;
```

이 방법은 추적 플래그를 커널에 직접 쿼리하므로, `ptrace` 단독보다 우회하기 어렵습니다.

## 4. 안티 후킹 (Anti-Hooking)

**Frida**나 **Xposed** 같은 런타임 후킹 프레임워크는 공격자가 보안 검사를 우회하는 데 사용하는 주요 도구입니다. 안티 후킹은 이러한 프레임워크를 탐지하거나 동작을 막는 것을 목표로 합니다.

### Frida 탐지

Frida는 가젯 라이브러리(`frida-agent`)를 대상 프로세스에 주입합니다. 다음과 같은 탐지 전략이 있습니다:

**로드된 라이브러리 스캔**

```c
// /proc/self/maps에서 frida 관련 문자열 탐색
FILE* maps = fopen("/proc/self/maps", "r");
char line[512];
while (fgets(line, sizeof(line), maps)) {
    if (strstr(line, "frida") || strstr(line, "gum-js-loop")) {
        // Frida 탐지됨
    }
}
```

**네임드 파이프 / 포트 스캔**

Frida의 기본 서버는 TCP 포트 `27042`에서 수신 대기합니다. 앱 내부에서 `localhost:27042`에 연결을 시도하면 Frida의 존재를 알아낼 수 있습니다.

**인라인 후킹 탐지**

Frida는 후킹된 함수의 첫 몇 개 명령어를 수정합니다(ARM에서 `BL` 또는 `B` 분기 삽입 등). 민감한 함수의 바이트를 읽어 프롤로그가 컴파일된 원래 값과 일치하는지 확인하면 탐지할 수 있습니다.

### Xposed 탐지 (Android)

Xposed는 `zygote`에 자신을 삽입하여, 포크된 모든 앱 프로세스의 클래스패스에 Xposed JAR이 포함되고 모든 예외의 스택 프레임에 특정 클래스가 나타납니다.

```java
try {
    throw new Exception();
} catch (Exception e) {
    for (StackTraceElement el : e.getStackTrace()) {
        if (el.getClassName().contains("de.robv.android.xposed")) {
            // Xposed 탐지됨
        }
    }
}
```

## 5. 실행 환경 검사 (Root / Jailbreak Detection)

대부분의 변조 도구는 루팅된(Android) 또는 탈옥된(iOS) 기기에서만 동작합니다. 이런 환경을 탐지하는 것이 Anti-Tamper의 핵심 레이어 중 하나입니다.

### Android 루팅 탐지

| 검사 항목 | 상세 |
|---|---|
| `su` 바이너리 | `/system/bin/su`, `/system/xbin/su`, `/sbin/su` 존재 여부 |
| `busybox` 존재 여부 | 루팅 환경에 흔히 포함됨 |
| `/system` 파티션 쓰기 테스트 | 루팅되지 않은 기기는 시스템 파티션 쓰기를 거부 |
| `ro.build.tags` 속성 | `release-keys` 대신 `test-keys`이면 변조된 시스템일 수 있음 |
| 위험 앱 패키지 | Magisk Manager, SuperSU, KingRoot 등 설치 여부 |

### iOS 탈옥 탐지

| 검사 항목 | 상세 |
|---|---|
| Cydia / Sileo 파일 경로 | `/Applications/Cydia.app`, `/usr/sbin/sshd`, `/bin/bash` 존재 여부 |
| 샌드박스 탈출 테스트 | `/private/jailbreak_test.txt` 쓰기 시도 — 탈옥 기기에서 성공 |
| URL 스킴 확인 | 탈옥 기기에서는 `cydia://` 스킴이 해석됨 |
| 동적 라이브러리 검사 | `dyld_image_count`로 이미지를 순회하며 `MobileSubstrate.dylib` 등 의심 라이브러리 탐지 |

## 6. 대응 전략 (Response Strategies)

탐지만으로는 부족합니다 — 어떻게 반응하느냐도 중요합니다. 일반적인 전략들:

- **조용한 종료**: 경고 없이 프로세스를 조용히 종료하여, 공격자가 무엇이 탐지를 트리거했는지 알기 어렵게 합니다.
- **데이터 오염**: 게임 데이터나 세션 토큰을 미묘하게 오염시켜 변조된 앱이 잘못된 결과를 내도록 합니다.
- **서버 측 강제**: 변조 상태를 서버에 보고하고 접근을 차단하거나 계정을 플래그 처리합니다.
- **지연된 반응**: 탐지 즉시 반응하지 말고, 임의의 지연 후 또는 결제 같은 결정적 순간에 반응하여 리버스 엔지니어링을 더 어렵게 만듭니다.

## 한계와 군비 경쟁

Anti-Tamper는 만병통치약이 아닙니다. 위에 설명된 모든 기법은 충분한 노력을 기울이면 우회할 수 있습니다:

- **Frida**는 탐지 함수 자체를 실행 전에 후킹할 수 있습니다.
- **Magisk**는 대부분의 루팅 검사를 통과하는 "MagiskHide"를 제공합니다.
- **Objection**은 일반적인 많은 Anti-Tamper 패턴 우회를 자동화합니다.

Anti-Tamper의 목표는 변조를 불가능하게 만드는 것이 아닙니다 — 대부분의 공격자가 포기할 만큼 충분히 비용을 높이는 것입니다. 여러 독립적인 검사를 서버 측 검증과 결합하는 **심층 방어(Defense in Depth)** 전략이 방어 수준을 유의미하게 높여줍니다.