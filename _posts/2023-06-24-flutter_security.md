---
title: Flutter App Security & ReFutter
key: page-flutter_security
categories:
- Security
- Mobile Security
author: hyoeun
math: true
mathjax_autoNumber: true
bilingual: true
image: "/assets/thumbnails/2023-06-24-flutter_security.png"
date: 2023-06-24 10:00:00
---
## Flutter App Security: Why It's Different and How to Approach It

You've been handed a Flutter app for a pentest, you open it in Jadx or class-dump, and... nothing useful. Class names like `A`, `B`, `C`. No meaningful Kotlin/Java. This isn't ProGuard obfuscation — it's Flutter's architecture. Understanding *why* Flutter looks this way is the prerequisite to analyzing it effectively.

## Flutter Architecture: What You're Actually Looking At

### The Dart Compilation Model

Flutter apps use the **Dart programming language**, but the way Dart gets compiled is what fundamentally changes the analysis approach:

*   **Debug builds** → Dart runs in a JIT (Just-In-Time) virtual machine called the **Dart VM**. Code is interpreted at runtime, making these builds slower but easy to analyze (classes are visible, source maps available).
*   **Release builds** → Dart is **AOT (Ahead-of-Time) compiled** to native machine code. The result is a native shared library: `libapp.so` (Android) or bundled into the Mach-O binary (iOS). There is no Dart VM, no class structure, no reflection — just raw machine code.

This is the wall you hit. A Flutter release APK's `lib/arm64-v8a/libapp.so` is essentially an ARM64 binary. Jadx won't help you here.

### What Lives Where in a Flutter APK/IPA

For Android:
```
app.apk
├── lib/
│   ├── arm64-v8a/
│   │   ├── libapp.so        ← Compiled Dart code (YOUR TARGET)
│   │   └── libflutter.so    ← Flutter engine (not your business)
├── assets/
│   └── flutter_assets/      ← Assets, fonts, sometimes config
└── classes.dex              ← Android host code (minimal, just launches Flutter)
```

For iOS:
```
Runner.app
├── Frameworks/
│   ├── App.framework/App    ← Compiled Dart code (YOUR TARGET)  
│   └── Flutter.framework/   ← Flutter engine
└── Runner                   ← Host binary (minimal)
```

The `classes.dex` in Android and the `Runner` binary in iOS are thin wrappers. They set up the Flutter engine and hand off execution. **Your analysis target is `libapp.so` or `App.framework/App`.**

### Dart Snapshots and the Snapshot Format

In release mode, what's inside `libapp.so` isn't just compiled Dart; it's a **Dart AOT snapshot**. The snapshot contains:
*   **isolate snapshot data** — heap snapshot of the Dart isolate at startup
*   **vm snapshot data** — pre-initialized VM heap
*   **assembly compiled Dart code** — the actual executable functions

The snapshot is structured in a way that Dart symbols are stripped and method names are not stored as strings in the conventional sense — they're inlined into the snapshot structure. This is why conventional string searching doesn't find your method names.

## Reconnaissance on a Flutter App

Before reaching for ReFutter, do basic recon:

```bash
# 1. Verify it's Flutter
unzip app.apk -d apk_out
file apk_out/lib/arm64-v8a/libapp.so   # Confirms ELF shared library

# 2. Check for debug artifacts
strings apk_out/lib/arm64-v8a/libapp.so | grep -i "dart\|observatory\|debug"
# "observatory" or "Dart VM" strings in a release build = debug build shipped = bad for them, great for you

# 3. Look at assets
ls apk_out/assets/flutter_assets/
cat apk_out/assets/flutter_assets/AssetManifest.json   # Reveals asset structure

# 4. Extract network endpoints from strings
strings apk_out/lib/arm64-v8a/libapp.so | grep -E "https?://"
```

## ReFutter: Restoring Symbols to Flutter Binaries

**ReFutter** is a tool that patches the Flutter snapshot to restore human-readable function names, making subsequent analysis in Ghidra or Radare2 dramatically more productive.

### How ReFutter Works

ReFutter exploits the fact that, even in a stripped release snapshot, the **snapshot object class IDs** are still present. By matching these against the Flutter engine version (which you can identify from `libflutter.so`), ReFutter reconstructs which function belongs to which Dart class.

The output is a patched `libapp.so` with renamed symbols that look like: `dev_example_app_LoginPage_verifyCredentials`.

### Installation and Usage

```bash
# Install ReFutter
pip3 install refutter

# Analyze Flutter app
# Step 1: Extract the engine version from libflutter.so
strings libflutter.so | grep -E "[0-9a-f]{40}"   # Flutter engine commit hash

# Step 2: Run ReFutter against the snapshot
refutter app.apk

# Output: patched_libapp.so and an XREF file for Ghidra/Binary Ninja
```

After running ReFutter:
```bash
# The patched library will have renamed symbols
nm -D patched_libapp.so | head -50
```

### Loading into Ghidra

```bash
# After refutter analysis, import patched_libapp.so into Ghidra
# ReFutter generates a script for Ghidra to rename functions automatically
# File: refutter_ghidra_script.py

# In Ghidra: Script Manager → Run Script → refutter_ghidra_script.py
# Functions will be renamed to Dart class.method format
```

## Dynamic Instrumentation: Frida with Flutter

Even with ReFutter + Ghidra giving you function names, you'll want to hook at runtime. Flutter's AOT code doesn't use the standard Java/ObjC runtime, so traditional Frida hooks work differently.

### Hooking Native Functions in libapp.so

```javascript
// Frida script: hook a restored Flutter function by address or symbol
const loginValidation = Module.findExportByName("libapp.so", 
    "dev_example_app_AuthService_validateToken");

if (loginValidation) {
    Interceptor.attach(loginValidation, {
        onEnter: function(args) {
            console.log("[*] validateToken called");
            // Dart strings are Dart objects, not C strings
            // Dump surrounding memory to understand argument structure
            console.log(hexdump(args[0], { length: 64 }));
        },
        onLeave: function(retval) {
            console.log("[*] validateToken returns:", retval);
            // Force return true equivalent in Dart snapshot format
        }
    });
}
```

### Detecting Debug vs Release Builds in Flutter

From a defense perspective, apps should ship only release builds. As a pentester, quickly distinguish:

```bash
# Debug build indicator: Dart observatory server
adb shell "netstat -tlnp | grep 8181"   # Dart VM observatory default port

# Another indicator: check for dart_vm_snapshot in assets
ls apk_out/assets/ | grep snapshot
# "kernel_blob.bin" in assets → debug/JIT build (very analyzable)
# No kernel_blob.bin → release/AOT build → need ReFutter approach
```

> [!TIP]
> If you find a debug build in the wild, the Dart Observatory (a web-based VM inspector) may be accessible. With `adb forward tcp:8181 tcp:8181`, you can connect to `http://localhost:8181` and get a live inspector of the running Dart isolate, including all object instances, memory, and even source code if it's a debug build.

## Practical ReFutter Workflow Summary

1. Extract APK → find `libapp.so`
2. Run `refutter app.apk` → get patched library + Ghidra script
3. Import into Ghidra → run ReFutter script to rename functions
4. Identify interesting functions (authentication, validation, crypto operations)
5. Note function offsets
6. Use Frida `Module.findBaseAddress("libapp.so").add(offset)` to hook at runtime

---

## Flutter 앱 보안과 ReFutter: 왜 다른가, 어떻게 접근할 것인가

일반적인 안드로이드 앱과 달리 Flutter 앱의 코드는 Jadx나 class-dump로 분석해도 의미 있는 내용이 거의 나오지 않습니다. 이는 ProGuard 난독화가 아니라 Flutter의 아키텍처 자체 때문입니다. 효과적으로 분석하려면 *왜* Flutter가 이렇게 보이는지를 이해해야 합니다.

## Flutter 아키텍처: 실제로 무엇을 보고 있는가

### Dart 컴파일 모델

Flutter 앱은 **Dart 프로그래밍 언어**를 사용하지만, Dart가 컴파일되는 방식이 분석 방법을 근본적으로 바꿉니다:

*   **디버그 빌드** → Dart가 **Dart VM**이라는 JIT 가상 머신에서 실행됩니다. 코드가 런타임에 해석되어 속도는 느리지만 분석하기 쉽습니다.
*   **릴리즈 빌드** → Dart가 네이티브 기계 코드로 **AOT(사전) 컴파일**됩니다. 결과는 공유 라이브러리: `libapp.so`(Android) 또는 Mach-O 바이너리(iOS)입니다.

이것이 바로 분석이 막히는 지점입니다. Flutter 릴리즈 APK의 `libapp.so`는 본질적으로 ARM64 바이너리입니다. Jadx는 소용이 없습니다.

### Flutter APK/IPA의 구조

Android:
```
app.apk
├── lib/
│   ├── arm64-v8a/
│   │   ├── libapp.so        ← 컴파일된 Dart 코드 (분석 대상)
│   │   └── libflutter.so    ← Flutter 엔진
├── assets/flutter_assets/   ← 에셋, 폰트, 설정 파일
└── classes.dex              ← Android 호스트 코드 (최소한)
```

iOS:
```
Runner.app
├── Frameworks/
│   ├── App.framework/App    ← 컴파일된 Dart 코드 (분석 대상)
│   └── Flutter.framework/   ← Flutter 엔진
└── Runner                   ← 호스트 바이너리 (최소한)
```

`classes.dex`와 `Runner`는 Flutter 엔진을 설정하고 실행을 넘겨주는 얇은 래퍼에 불과합니다. **분석 대상은 항상 `libapp.so` 또는 `App.framework/App`입니다.**

## Flutter 앱 기초 정찰

ReFutter를 사용하기 전 기초 정찰을 먼저 수행합니다:

```bash
# 1. Flutter 앱 여부 확인
unzip app.apk -d apk_out
file apk_out/lib/arm64-v8a/libapp.so

# 2. 디버그 아티팩트 확인
strings apk_out/lib/arm64-v8a/libapp.so | grep -i "observatory\|debug"
# "observatory" 문자열이 릴리즈 빌드에 있으면 → 디버그 빌드가 배포된 것

# 3. 네트워크 엔드포인트 추출
strings apk_out/lib/arm64-v8a/libapp.so | grep -E "https?://"

# 4. 에셋 구조 확인
cat apk_out/assets/flutter_assets/AssetManifest.json
```

## ReFutter: Flutter 바이너리에 심볼 복원하기

**ReFutter**는 Flutter 스냅샷을 패치하여 사람이 읽을 수 있는 함수 이름을 복원하는 도구입니다. Ghidra나 Radare2에서의 후속 분석을 훨씬 더 생산적으로 만들어 줍니다.

### 설치 및 사용법

```bash
pip3 install refutter

# Flutter 엔진 버전 확인
strings libflutter.so | grep -E "[0-9a-f]{40}"

# ReFutter 실행
refutter app.apk
# → patched_libapp.so와 Ghidra 스크립트 생성
```

### Ghidra에 로드하기

```bash
# patched_libapp.so를 Ghidra에 임포트
# ReFutter가 생성한 스크립트로 함수 이름 자동 복원
# Script Manager → Run Script → refutter_ghidra_script.py
```

## Frida를 이용한 동적 분석

```javascript
// libapp.so의 복원된 함수를 Frida로 후킹
const loginValidation = Module.findExportByName("libapp.so", 
    "dev_example_app_AuthService_validateToken");

if (loginValidation) {
    Interceptor.attach(loginValidation, {
        onEnter: function(args) {
            console.log("[*] validateToken 호출됨");
            console.log(hexdump(args[0], { length: 64 }));
        },
        onLeave: function(retval) {
            console.log("[*] 반환값:", retval);
        }
    });
}
```

### 디버그 vs 릴리즈 빌드 구별

```bash
# 디버그 빌드 지표: Dart Observatory 서버
adb shell "netstat -tlnp | grep 8181"

# 에셋 폴더에 kernel_blob.bin이 있으면 → JIT 빌드 (분석 쉬움)
# 없으면 → AOT 빌드 → ReFutter 필요
ls apk_out/assets/ | grep snapshot
```

> [!TIP]
> 디버그 빌드를 발견했다면, Dart Observatory (웹 기반 VM 인스펙터)에 접근할 수 있습니다. `adb forward tcp:8181 tcp:8181` 후 `http://localhost:8181`에 접속하면, 실행 중인 Dart isolate의 모든 객체 인스턴스, 메모리, 소스 코드까지 볼 수 있습니다.

## 실전 ReFutter 워크플로우 요약

1. APK 추출 → `libapp.so` 확보
2. `refutter app.apk` 실행 → 패치된 라이브러리 + Ghidra 스크립트 생성
3. Ghidra에 임포트 → ReFutter 스크립트로 함수 이름 복원
4. 흥미로운 함수 식별 (인증, 검증, 암호화 로직)
5. 함수 오프셋 기록
6. Frida로 런타임 후킹: `Module.findBaseAddress("libapp.so").add(offset)`


