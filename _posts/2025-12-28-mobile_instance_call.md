---
title: Mobile App Internals - Lifecycle, Instant App, IPC & Instance Call
key: page-mobile_instance_call
categories:
- Security
- Mobile Security
author: hyoeun
math: true
mathjax_autoNumber: true
bilingual: true
image: "/assets/thumbnails/2025-12-28-mobile_instance_call.png"
date: 2025-12-28 10:00:00
---
## Mobile App Internals: Lifecycle, Instant App, IPC & Instance Call

Four concepts that trip up mobile pentesters who haven't looked under the hood: **App Lifecycle**, **Instant App**, **IPC (Inter-Process Communication)**, and **Instance Call**. Each one sounds like a development concept — and it is — but each one also defines a distinct attack surface or testing strategy that you'll encounter on real engagements.

## App Lifecycle

The lifecycle is the state machine that governs when your app's code runs, when it pauses, and when it dies. Security controls, token validation, and sensitive data operations all happen at specific lifecycle transitions — which means a pentester who doesn't understand the lifecycle doesn't know *when* to look.

### Android Activity Lifecycle

Android apps are built around **Activities** (screen units), each of which goes through a defined lifecycle:

```
onCreate()   → App first launched or recreated after kill
onStart()    → Activity becoming visible
onResume()   → Activity in foreground, user interacting ← ACTIVE STATE
onPause()    → Losing focus (another activity or dialog appears)
onStop()     → Activity no longer visible
onDestroy()  → Activity being permanently destroyed
```

**Security-relevant lifecycle moments:**

| Callback | What Often Happens | What to Test |
|:----------|:-------------------|:-------------|
| `onCreate()` | SSL context setup, root/jailbreak check, API key load | Are keys stored securely? Is the check bypassable? |
| `onResume()` | Biometric prompt, token refresh, cert pinning re-init | Can you hook this to skip security init? |
| `onPause()` | Clipboard clear, screen content hide | Is sensitive data still accessible after pause? |
| `onStop()` | Session token write to storage | Is the token written in plaintext? |

Hook lifecycle events with Frida to observe what security code runs and when:

```javascript
Java.perform(function() {
    var Activity = Java.use("android.app.Activity");

    Activity.onResume.implementation = function() {
        console.log("[*] onResume: watching for security re-initializations");
        this.onResume();
    };

    Activity.onPause.implementation = function() {
        console.log("[*] onPause: check if sensitive data is persisted or wiped");
        this.onPause();
    };
});
```

### iOS App Lifecycle

iOS lifecycle is managed at the **UIApplication** / **AppDelegate** level, and apps transition through five states:

```
Not Running → Inactive (transitional) → Active ← the foreground state
                                       ↓
                                  Background (limited execution, ~30 sec)
                                       ↓
                                   Suspended (frozen in memory)
                                       ↓
                               Not Running (killed)
```

**Security-relevant AppDelegate callbacks:**

| Method | When | Security Notes |
|:--------|:-----|:---------------|
| `applicationDidBecomeActive:` | App enters foreground | Jailbreak detection, biometric prompt, cert pinning setup |
| `applicationWillResignActive:` | Losing focus | Screenshot prevention (`FLAG_SECURE` equivalent via `ignoresSwitchingApplications`), clipboard wipe |
| `applicationDidEnterBackground:` | Fully backgrounded | Data encryption, sensitive view overlay |
| `applicationWillTerminate:` | App being killed | Session cleanup, token invalidation |

```javascript
// Hook iOS lifecycle via Frida
var AppDelegate = ObjC.classes.AppDelegate;
Interceptor.attach(AppDelegate["- applicationDidBecomeActive:"].implementation, {
    onEnter: function(args) {
        console.log("[*] App became active — trace what security code fires here");
        console.log(Thread.backtrace(this.context, Backtracer.ACCURATE)
            .map(DebugSymbol.fromAddress).join('\n'));
    }
});
```

**App switcher data leakage:** When an iOS app is backgrounded, the OS automatically takes a screenshot for the app switcher animation. Sensitive screens (banking, authentication) should blur or overlay content at `applicationWillResignActive:`. Test by backgrounding the app during a sensitive operation and inspecting the app switcher snapshot.

## Instant App

Android Instant Apps (now **Google Play Instant**) allow users to run a subset of an app's functionality **without installing it**. The user taps a link (URL or Play Store badge), and a lightweight version of the app launches instantly from Google's servers.

### How Instant Apps Work

```
User taps URL → Google Play resolves to Instant App → 
Downloads only required "feature module" (not full APK) →
App runs in restricted sandbox → User can optionally install full app
```

Instant Apps live in a more restricted environment than installed apps:
*   **No persistent storage** — no `SharedPreferences` or SQLite persists between sessions
*   **Limited permissions** — no `READ_CONTACTS`, `ACCESS_FINE_LOCATION`, etc. without explicit grant
*   **Restricted API access** — no background services, no `BOOT_COMPLETED` broadcasts
*   **URL-based entry** — entry points are `<intent-filter>` with URL patterns, not just `MAIN/LAUNCHER`

### Pentesting Instant Apps

Instant Apps are harder to intercept and analyze because they aren't installed in the normal sense. Strategies:

```bash
# Check if an APK is instant-app capable
aapt dump badging target.apk | grep "uses-feature"
# Look for: uses-feature: name='android.hardware.type.instant_app'

# Activate instant app via ADB (if you have the module downloaded)
adb shell am start-activity \
    --activity-brought-to-front \
    -a android.intent.action.VIEW \
    -d "https://example.com/feature" \
    com.example.app

# Pull the instant app's cached APK from Play's cache
adb shell ls /data/user/0/com.android.vending/files/
```

**Security concerns with Instant Apps:**
*   **URI scheme attacks:** Since Instant App entry points are URL-driven, improper URL validation can allow malicious deep links to trigger unexpected functionality
*   **Token handling:** Instant Apps can use the `InstantApps` API to share tokens with the installed version — if misimplemented, sessions may persist when they shouldn't
*   **Phishing abuse:** Attackers can register similar-looking domains and create Instant Apps that mimic legitimate ones — the user sees a legitimate-looking app run without installation, lowering their guard

### Apple App Clips

**App Clips** are Apple's equivalent of Android Instant Apps, introduced in iOS 14. An App Clip is a small part of a full app that can be launched **without installing the full app**, triggered by specific physical or digital entry points.

#### App Clip Entry Points

This is the most important structural difference from Android Instant Apps. App Clips have a richer set of triggers:

| Trigger | How It Works |
|:--------|:-------------|
| **QR Code / NFC Tag** | Physical tag at a location (parking meter, restaurant table) launches the App Clip |
| **Safari Smart App Banner** | Website embeds a banner that invites the user to use the App Clip |
| **iMessage link** | Tapping a link in Messages can launch an App Clip directly |
| **App Clip Code** | Apple's proprietary two-tone visual code (combines QR + NFC in one) |
| **Nearby / Maps** | Businesses registered with Apple can surface App Clips in Maps and Siri suggestions |

This physical-world integration is what makes App Clips interesting for pentesters — the entry points are often in **uncontrolled physical environments** (restaurants, retail, parking lots) where an attacker can place a counterfeit NFC tag or QR code.

#### How App Clips Work Technically

```
User taps App Clip Code / URL →
App Clip Experience registered in App Store Connect is fetched →
OS downloads App Clip binary (max 15 MB) →
Launches with invocation URL passed in →
User can optionally install full app
```

Key technical constraints Apple enforces:
*   **Size limit:** App Clip binary ≤ 15 MB (much smaller than today's full apps)
*   **No background execution** — App Clips cannot run background tasks or use `BGTaskScheduler`
*   **Limited APIs** — no access to `HealthKit`, `Contacts`, `Call History`, `HomeKit`, etc.
*   **Ephemeral notifications** — can request notification permission for 8 hours; does not carry over to the full app install
*   **Storage is deleted** after a period of inactivity or when the OS needs space

**Keychain behavior (important for pentesters):**
Items saved to Keychain by an App Clip **are accessible to the full installed app** if they share the same team ID and App Group. This token continuity is intentional (seamless upgrade experience), but if implemented carelessly:
*   A token created during an unauthenticated App Clip session could be elevated to full app scope
*   Session state from a public/shared device App Clip could persist to a subsequent user's full app install

#### App Clip Configuration: AASA and App Clip Experience

App Clips rely on **two server-side validations** that are worth checking:

1.  **`apple-app-site-association` (AASA) file** — same as Universal Links, must declare the App Clip's entitlement:
```json
{
  "appclips": {
    "apps": ["TEAMID.com.example.app.Clip"]
  },
  "applinks": {
    "apps": [],
    "details": [...]
  }
}
```

2.  **App Clip Experience URL** — registered in App Store Connect. Each App Clip can have multiple experiences tied to different URLs (e.g., a parking app registers per-lot URLs).

```bash
# Verify the AASA file includes the App Clip entry
curl https://example.com/.well-known/apple-app-site-association | python3 -m json.tool
# Look for the "appclips" key — if missing, App Clip invocation may fail or fall back to browser

# Check what App Clip URL the IPA declares
unzip app.ipa -d app_out
cat app_out/Payload/AppName.app/AppClip.appex/Info.plist | plutil -p -
# Look for NSAppClip keys, especially NSAppClipRequestLocationConfirmation and NSAppClipRequestEphemeralUserNotification
```

#### Pentesting App Clips

**1. Test the invocation URL parameter handling:**
App Clips receive their context via an invocation URL. If the App Clip uses URL parameters to determine what to display or what permissions to grant, test for injection and authorization issues:

```bash
# Invoke a simulator App Clip with a manipulated URL
xcrun simctl launch booted com.example.app.Clip \
    --url "https://example.com/appclip?location=1&tier=ADMIN"

# On device via Frida: hook the App Clip invocation delegate method
var AppClipDelegate = ObjC.classes.AppDelegate;
Interceptor.attach(AppClipDelegate["- application:continueUserActivity:restorationHandler:"].implementation, {
    onEnter: function(args) {
        var activity = new ObjC.Object(args[2]);
        var webpageURL = activity.webpageURL();
        console.log("[*] App Clip invoked with URL:", webpageURL.absoluteString());
    }
});
```

**2. Test Keychain continuity (token persistence):**

```javascript
// After using the App Clip, check if sensitive tokens were written to keychain
// These would persist to the full app if installed
var SecItemCopyMatching = new NativeFunction(
    Module.findExportByName('Security', 'SecItemCopyMatching'),
    'int', ['pointer', 'pointer']
);
// Or use objection:
// objection --gadget com.example.app.Clip explore
// ios keychain dump
```

**3. Phishing via counterfeit App Clip triggers:**

This is the attack most relevant to corporate security assessments:
*   Attacker prints a fake NFC sticker or QR code that points to their domain
*   Their domain has a valid AASA file registering their malicious App Clip
*   Users in the target location scan the attacker's code, launching a convincing fake login page as an App Clip
*   Because App Clips appear with the App Store's trust UI (showing the developer name), users are less suspicious than they would be of a plain website

> [!CAUTION]
> In physical-world penetration tests (red team), placing a counterfeit App Clip Code or NFC tag is a realistic and effective social engineering vector. Always confirm explicit written authorization before testing this in physical spaces.

**App Clips vs Instant Apps — Comparison for Pentesters:**

| Dimension | Android Instant App | Apple App Clip |
|:----------|:--------------------|:---------------|
| Entry points | URL / Play Store badge | QR, NFC, Safari, Maps, iMessage, App Clip Code (physical) |
| Size limit | No hard limit per module | 15 MB strict |
| Storage persistence | No SharedPreferences between sessions | Deleted after inactivity; Keychain persists to full app |
| Auth continuity | `InstantApps` shared credential API | Keychain shared via App Group with full app |
| Primary phishing risk | Lookalike domain + Play Instant | Counterfeit NFC/QR in physical locations |

## IPC — Inter-Process Communication

IPC is how apps and system components communicate across process boundaries. It's one of the richest attack surfaces in mobile pentesting because developers routinely misconfigure IPC mechanisms, exposing internal functionality to other apps.

### Android IPC

Android is built on a heavy IPC foundation. The core mechanism is **Binder** — a kernel-level driver that all Android IPC goes through. But developers interact with it through higher-level abstractions:

#### Intents

The most common IPC mechanism. An Intent is a message object used to start Activities, Services, or send Broadcasts.

```java
// Explicit Intent — targets a specific component (safe)
Intent intent = new Intent(this, PaymentActivity.class);

// Implicit Intent — any component can handle it (potential attack surface)
Intent intent = new Intent("com.example.ACTION_PROCESS_PAYMENT");
intent.putExtra("amount", 100);
startActivity(intent);
```

**Attack: Intent Injection / Intent Hijacking**

If an app sends an implicit intent and an attacker has registered an Activity with a matching intent-filter, the attacker's app can intercept the intent:

```xml
<!-- Attacker's malicious app registers to handle the same action -->
<activity android:name=".MaliciousPaymentHandler">
    <intent-filter>
        <action android:name="com.example.ACTION_PROCESS_PAYMENT"/>
        <category android:name="android.intent.category.DEFAULT"/>
    </intent-filter>
</activity>
```

The user sees a system chooser — or worse, if the victim app uses `startActivityForResult`, the attacker's app receives the result with sensitive data.

**Testing with drozer:**
```bash
# List exported activities (accessible from other apps)
run app.activity.info -a com.target.app

# Attempt to start an exported activity directly
run app.activity.start --component com.target.app com.target.app.InternalSettingsActivity

# Inspect what intents an app sends
run app.broadcast.send --action com.target.app.INTERNAL_ACTION
```

#### Content Providers

Content Providers expose structured data (usually SQLite databases) to other apps via a URI-based API.

**Attack: SQL Injection via Content Provider**

```bash
# Query a content provider directly via ADB
adb shell content query --uri content://com.target.app.provider/users

# Attempt SQL injection
adb shell content query --uri content://com.target.app.provider/users \
    --where "1=1 UNION SELECT name,sql,3,4,5 FROM sqlite_master--"
```

A provider exported without a `permission` attribute is accessible to **any app on the device**. Use drozer to automate this:

```bash
run scanner.provider.injection -a com.target.app
run scanner.provider.traversal -a com.target.app    # Path traversal via file provider
```

#### AIDL and Bound Services

AIDL (Android Interface Definition Language) defines a strict interface for cross-process service communication. Bound Services using AIDL are common in payment SDKs and DRM services.

```bash
# Find exported services
run app.service.info -a com.target.app

# Attempt to bind to a service
run app.service.start --action com.target.app.BIND_SERVICE --component com.target.app com.target.app.PaymentService
```

### iOS IPC

iOS has a much stricter IPC model — apps are sandboxed by default and cannot communicate freely. The available mechanisms are more limited:

#### URL Schemes

Custom URL schemes let apps receive data from other apps or web pages:

```swift
// App registers "myapp://action?param=value"
func application(_ app: UIApplication, open url: URL, options: ...) -> Bool {
    // url.host = "action", url.queryItems = ["param": "value"]
}
```

**Attack: URL Scheme Hijacking**

Multiple apps can register the same URL scheme. iOS uses the last-installed app to handle ambiguous schemes — an attacker can register `myapp://` in their malicious app:

```bash
# Test URL scheme invocation via simctl (simulator)
xcrun simctl openurl booted "targetapp://admin?bypass=true"

# On device via Frida
ObjC.classes.UIApplication.sharedApplication()
    .openURL_(ObjC.classes.NSURL.URLWithString_("targetapp://admin?bypass=true"));
```

#### Universal Links

Universal Links are the more secure replacement for URL schemes. They require a server-side `apple-app-site-association` file that proves ownership of the domain. If the AASA file is misconfigured or the association is broken, links fall back to the browser — safe but potentially phishable.

```bash
# Check the AASA file for a domain
curl https://example.com/.well-known/apple-app-site-association

# Test if deep link paths are correctly restricted
# The AASA "paths" array defines what paths the app claims — test unclaimed paths
```

#### XPC Services

XPC is Apple's preferred IPC mechanism for privileged helpers and extensions. It's type-safe, sandboxed, and crash-isolated. From a pentest perspective, you'll encounter XPC in:
*   App Extensions (keyboard extensions, share extensions, notification content extensions)
*   Privileged helper tools installed by macOS apps (less relevant for iOS)

XPC is rarely a direct attack vector in mobile pentesting, but Extension entitlements and App Group shared containers (shared via XPC) can leak data between apps:

```bash
# Check what app groups an app belongs to (from entitlements)
codesign -d --entitlements :- Runner.app/Runner | grep -A5 "application-groups"
```

## Instance Call

An **Instance Call** is the act of invoking a method on a **live, existing object instance** at runtime — not waiting for the app to call the method naturally, but triggering it directly from your analysis tool. This is the difference between *observing* what an app does and *actively driving* it.

### Why Instance Calls Matter in Pentesting

Many protected functions in an app check authentication state, session validity, or user roles before executing. But the *object instance* that actually performs the privileged operation already exists in memory. If you can get a handle to that instance and call its methods directly, you bypass the gating logic that's supposed to prevent you.

### ObjC.chooseSync — iOS Heap Scanning

```javascript
// Scan the heap for live instances of a class
var authManager = ObjC.chooseSync(ObjC.classes.AuthenticationManager);

if (authManager.length > 0) {
    var instance = authManager[0];
    console.log("[*] Found live AuthenticationManager:", instance);

    // Inspect instance variables
    console.log("[*] Current auth state:", instance.isAuthenticated());
    console.log("[*] Current user:", instance.currentUser().toString());

    // Force-call a privileged method that normally requires authentication
    var adminData = instance.fetchAdminDashboard();
    console.log("[*] Admin data returned:", adminData.toString());
}
```

`ObjC.chooseSync` walks the Objective-C heap and returns all instances of the specified class. It's expensive (heap scan) but powerful — it works even for singletons and lazily-initialized objects.

### Java.choose — Android Heap Scanning

```javascript
Java.perform(function() {
    Java.choose("com.example.app.AccountManager", {
        onMatch: function(instance) {
            console.log("[*] Found AccountManager instance:", instance);

            // Actively call methods on the live instance
            var balance = instance.getAccountBalance();
            console.log("[*] Balance:", balance);

            // IDOR test: call with a different user's ID
            var otherBalance = instance.getAccountBalanceForUser("TARGET_USER_ID");
            console.log("[*] Other user's balance:", otherBalance);

            // Try calling admin-only functions
            try {
                var adminResult = instance.resetAllUserPasswords();
                console.log("[*] Admin function accessible:", adminResult);
            } catch(e) {
                console.log("[*] Admin function blocked:", e.message);
            }
        },
        onComplete: function() {
            console.log("[*] Heap scan complete");
        }
    });
});
```

### Combining IPC and Instance Calls

A powerful testing pattern: use IPC to trigger a code path, then use an Instance Call to inspect or manipulate the resulting object state.

```javascript
Java.perform(function() {
    // Step 1: Monitor IPC by hooking the Intent receiver
    var Activity = Java.use("android.app.Activity");
    Activity.onNewIntent.implementation = function(intent) {
        var action = intent.getAction();
        var extras = intent.getExtras();
        console.log("[*] IPC Intent received — action:", action);
        if (extras) {
            console.log("[*] Intent extras:", extras.toString());
        }
        this.onNewIntent(intent);

        // Step 2: After IPC triggers state change, active-call to inspect the result
        Java.choose("com.example.app.SessionManager", {
            onMatch: function(session) {
                console.log("[*] Session state after IPC:", session.getCurrentState().toString());
                console.log("[*] Elevated privileges granted?", session.hasAdminRole());
            },
            onComplete: function() {}
        });
    };
});
```

---

## 모바일 앱 내부 구조: 라이프사이클, 인스턴트 앱, IPC, 인스턴스 콜

모바일 펜테스터가 내부 구조를 제대로 이해하지 못하면 놓치게 되는 네 가지 개념: **앱 라이프사이클**, **인스턴트 앱**, **IPC(프로세스 간 통신)**, 그리고 **인스턴스 콜**. 각각 개발 개념처럼 들리지만, 실제 현장에서 마주치는 독립적인 공격 표면 혹은 테스트 전략을 정의하는 중요한 주제들입니다.

## 앱 라이프사이클

라이프사이클은 앱 코드가 언제 실행되고, 언제 멈추고, 언제 소멸되는지를 규정하는 상태 기계(State Machine)입니다. 보안 통제, 토큰 검증, 민감 데이터 처리는 특정 라이프사이클 전환 시점에 일어납니다. 라이프사이클을 이해하지 못하면 *언제 무엇을 봐야 하는지* 알 수 없습니다.

### Android Activity 라이프사이클

Android 앱은 **Activity**(화면 단위)를 중심으로 구성되며, 각 Activity는 정해진 라이프사이클을 따릅니다:

```
onCreate()   → 앱 최초 실행 또는 재생성 시
onStart()    → Activity가 화면에 보이기 시작
onResume()   → 포그라운드, 사용자 상호작용 중 ← 활성 상태
onPause()    → 포커스 손실 (다른 Activity나 다이얼로그 등장)
onStop()     → Activity가 더 이상 보이지 않음
onDestroy()  → Activity 완전 소멸
```

**보안 관련 라이프사이클 시점:**

| 콜백 | 주로 발생하는 일 | 테스트할 것 |
|:-----|:----------------|:------------|
| `onCreate()` | SSL 컨텍스트 설정, 루트 감지, API 키 로드 | 키가 안전하게 저장되는가? 감지를 우회할 수 있는가? |
| `onResume()` | 생체 인증 프롬프트, 토큰 갱신, 인증서 피닝 재초기화 | 보안 초기화를 후킹으로 건너뛸 수 있는가? |
| `onPause()` | 클립보드 초기화, 화면 내용 숨기기 | 일시 중지 후에도 민감 데이터에 접근 가능한가? |
| `onStop()` | 세션 토큰 저장소에 기록 | 토큰이 평문으로 저장되는가? |

Frida로 라이프사이클 이벤트를 후킹하여 어떤 보안 코드가 언제 실행되는지 관찰합니다:

```javascript
Java.perform(function() {
    var Activity = Java.use("android.app.Activity");

    Activity.onResume.implementation = function() {
        console.log("[*] onResume: 보안 재초기화 코드 관찰 중");
        this.onResume();
    };

    Activity.onPause.implementation = function() {
        console.log("[*] onPause: 민감 데이터 유지/삭제 여부 확인");
        this.onPause();
    };
});
```

### iOS 앱 라이프사이클

iOS 라이프사이클은 **UIApplication / AppDelegate** 수준에서 관리되며, 앱은 다섯 가지 상태를 전환합니다:

```
Not Running → Inactive (전환 중) → Active ← 포그라운드 상태
                                 ↓
                            Background (제한적 실행, 약 30초)
                                 ↓
                             Suspended (메모리에 동결)
                                 ↓
                           Not Running (종료)
```

**보안 관련 AppDelegate 콜백:**

| 메서드 | 시점 | 보안 관련 사항 |
|:-------|:-----|:--------------|
| `applicationDidBecomeActive:` | 포그라운드 진입 | 탈옥 감지, 생체 인증, 인증서 피닝 설정 |
| `applicationWillResignActive:` | 포커스 손실 직전 | 스크린샷 방지, 클립보드 초기화 |
| `applicationDidEnterBackground:` | 완전히 백그라운드 전환 | 데이터 암호화, 민감 화면 오버레이 |
| `applicationWillTerminate:` | 앱 종료 시 | 세션 정리, 토큰 무효화 |

```javascript
// Frida로 iOS 라이프사이클 후킹
var AppDelegate = ObjC.classes.AppDelegate;
Interceptor.attach(AppDelegate["- applicationDidBecomeActive:"].implementation, {
    onEnter: function(args) {
        console.log("[*] 앱 Active 전환 — 실행되는 보안 코드 추적");
        console.log(Thread.backtrace(this.context, Backtracer.ACCURATE)
            .map(DebugSymbol.fromAddress).join('\n'));
    }
});
```

**앱 전환기(App Switcher) 데이터 노출:** 앱이 백그라운드로 전환될 때 iOS는 전환 애니메이션용 스크린샷을 자동으로 촬영합니다. 민감한 화면(뱅킹, 인증 등)은 `applicationWillResignActive:` 시점에 내용을 가려야 합니다. 민감 작업 중 앱을 백그라운드 전환한 뒤 앱 전환기 스냅샷을 확인하여 테스트합니다.

## 인스턴트 앱 (Instant App)

Android 인스턴트 앱(현재: **Google Play Instant**)은 앱을 설치하지 않고도 일부 기능을 실행할 수 있게 해줍니다. 사용자가 링크를 탭하면 Google 서버에서 경량화된 앱 버전이 즉시 실행됩니다.

### 인스턴트 앱의 작동 방식

```
사용자가 URL 탭 → Google Play가 인스턴트 앱으로 연결 → 
필요한 "기능 모듈"만 다운로드 (전체 APK 아님) →
제한된 샌드박스에서 실행 → 사용자가 선택적으로 전체 앱 설치 가능
```

인스턴트 앱은 설치된 앱보다 더 제한된 환경에서 실행됩니다:
*   **영구 저장소 없음** — 세션 간 `SharedPreferences`나 SQLite가 유지되지 않음
*   **제한된 권한** — 명시적 허가 없이는 `READ_CONTACTS`, `ACCESS_FINE_LOCATION` 등 사용 불가
*   **URL 기반 진입** — 진입점이 `MAIN/LAUNCHER`가 아닌 URL 패턴의 `intent-filter`

### 인스턴트 앱 펜테스팅

인스턴트 앱은 일반적인 방식으로 설치되지 않기 때문에 분석이 어렵습니다:

```bash
# APK가 인스턴트 앱 지원 여부 확인
aapt dump badging target.apk | grep "uses-feature"
# 확인: uses-feature: name='android.hardware.type.instant_app'

# ADB를 통한 인스턴트 앱 실행
adb shell am start-activity \
    --activity-brought-to-front \
    -a android.intent.action.VIEW \
    -d "https://example.com/feature" \
    com.example.app
```

**인스턴트 앱의 보안 위험:**
*   **URI 스킴 공격:** 인스턴트 앱의 진입점이 URL 기반이므로, URL 검증 미흡 시 악성 딥링크가 예상치 못한 기능을 트리거할 수 있음
*   **토큰 처리 오류:** 인스턴트 앱이 설치된 버전과 토큰을 공유할 때 잘못된 구현으로 세션이 예상치 않게 유지될 수 있음
*   **피싱 남용:** 공격자가 유사 도메인을 등록하고 합법적인 앱을 모방한 인스턴트 앱을 만들어, 설치 없이 실행된다는 사실로 사용자의 경계심을 낮출 수 있음

### Apple App Clips

**App Clips**는 iOS 14에서 도입된 Apple 버전의 인스턴트 앱입니다. 앱 클립은 전체 앱을 설치하지 않고도 실행할 수 있는 앱의 작은 부분으로, 특정 물리적 또는 디지털 진입점을 통해 실행됩니다.

#### App Clips 진입점

Android 인스턴트 앱과 가장 중요한 구조적 차이점은 진입점이 훨씬 다양하다는 것입니다:

| 진입점 | 작동 방식 |
|:-------|:---------|
| **QR 코드 / NFC 태그** | 물리적 장소의 태그(주차 정산기, 레스토랑 테이블) 스캔 시 앱 클립 실행 |
| **Safari 스마트 앱 배너** | 웹사이트에 앱 클립 사용을 유도하는 배너 삽입 |
| **iMessage 링크** | Messages의 링크 탭으로 앱 클립 직접 실행 |
| **App Clip Code** | Apple 전용 이중 색조 비주얼 코드 (QR + NFC 결합) |
| **지도 / 주변** | App Store Connect에 등록된 비즈니스가 지도 및 Siri 제안에 앱 클립 노출 가능 |

물리 세계와의 통합이 앱 클립을 펜테스터에게 흥미롭게 만드는 요소입니다 — 진입점이 **통제되지 않은 물리적 환경**(레스토랑, 소매점, 주차장)에 있어 공격자가 위조 NFC 태그나 QR 코드를 배치할 수 있습니다.

#### App Clips의 기술적 작동 방식

```
사용자가 App Clip Code / URL 탭 →
App Store Connect에 등록된 App Clip Experience 조회 →
OS가 앱 클립 바이너리 다운로드 (최대 15MB) →
호출 URL을 전달받아 실행 →
사용자가 선택적으로 전체 앱 설치 가능
```

Apple이 강제하는 핵심 제약 사항:
*   **크기 제한:** 앱 클립 바이너리 ≤ 15MB
*   **백그라운드 실행 불가** — 백그라운드 작업이나 `BGTaskScheduler` 사용 불가
*   **제한된 API** — `HealthKit`, `Contacts`, 통화 기록, `HomeKit` 등 접근 불가
*   **임시 알림** — 알림 권한을 8시간 동안만 요청 가능; 전체 앱 설치 시 이어지지 않음
*   **저장소 자동 삭제** — 비활성 기간 후 또는 OS가 공간을 필요로 할 때 삭제됨

**키체인 동작 (펜테스터에게 중요):**
앱 클립이 키체인에 저장한 항목은 동일한 팀 ID와 앱 그룹을 공유하는 경우 **전체 설치된 앱에서 접근 가능**합니다. 이 토큰 연속성은 의도된 것(원활한 업그레이드 경험)이지만, 부주의하게 구현되면:
*   인증되지 않은 앱 클립 세션에서 생성된 토큰이 전체 앱 범위로 확장될 수 있음
*   공용/공유 기기에서의 앱 클립 세션 상태가 이후 사용자의 전체 앱 설치로 유지될 수 있음

#### App Clips 설정: AASA와 App Clip Experience

앱 클립은 두 가지 서버 측 검증에 의존하며, 모두 점검할 가치가 있습니다:

1.  **`apple-app-site-association` (AASA) 파일** — 유니버셜 링크와 동일하게, 앱 클립 엔타이틀먼트를 선언해야 함:
```json
{
  "appclips": {
    "apps": ["TEAMID.com.example.app.Clip"]
  }
}
```

2.  **App Clip Experience URL** — App Store Connect에 등록. 하나의 앱 클립이 다른 URL에 연결된 여러 Experience를 가질 수 있음 (예: 주차 앱이 주차장마다 URL 등록).

```bash
# AASA 파일에 앱 클립 항목 포함 여부 확인
curl https://example.com/.well-known/apple-app-site-association | python3 -m json.tool
# "appclips" 키 확인 — 없으면 앱 클립 호출이 실패하거나 브라우저로 대체됨

# IPA에서 앱 클립이 선언한 URL 확인
unzip app.ipa -d app_out
plutil -p app_out/Payload/AppName.app/AppClip.appex/Info.plist
# NSAppClip 관련 키 확인
```

#### App Clips 펜테스팅

**1. 호출 URL 파라미터 처리 테스트:**
앱 클립은 호출 URL을 통해 컨텍스트를 수신합니다. 앱 클립이 URL 파라미터로 표시 내용이나 권한을 결정한다면, 인젝션 및 인가 취약점을 테스트해야 합니다:

```bash
# 조작된 URL로 시뮬레이터에서 앱 클립 호출
xcrun simctl launch booted com.example.app.Clip \
    --url "https://example.com/appclip?location=1&tier=ADMIN"
```

```javascript
// Frida로 앱 클립 호출 델리게이트 메서드 후킹
var AppClipDelegate = ObjC.classes.AppDelegate;
Interceptor.attach(AppClipDelegate["- application:continueUserActivity:restorationHandler:"].implementation, {
    onEnter: function(args) {
        var activity = new ObjC.Object(args[2]);
        var webpageURL = activity.webpageURL();
        console.log("[*] 앱 클립 호출 URL:", webpageURL.absoluteString());
    }
});
```

**2. 키체인 연속성 테스트 (토큰 지속성):**

앱 클립 사용 후 민감한 토큰이 키체인에 기록되었는지 확인합니다. 이 토큰은 전체 앱 설치 시 이어집니다:

```bash
# objection을 이용한 키체인 덤프
objection --gadget com.example.app.Clip explore
# > ios keychain dump
```

**3. 위조 앱 클립 진입점을 이용한 피싱:**

기업 보안 평가에서 가장 관련성 높은 공격입니다:
*   공격자가 자신의 도메인을 가리키는 위조 NFC 스티커나 QR 코드를 출력
*   악성 앱 클립을 등록한 유효한 AASA 파일을 해당 도메인에 설치
*   목표 장소의 사용자가 공격자 코드를 스캔하면, 설득력 있는 가짜 로그인 페이지가 앱 클립으로 실행됨
*   App Clips는 App Store의 신뢰 UI(개발자 이름 표시)와 함께 나타나므로 사용자는 일반 웹사이트보다 경계심이 낮음

> [!CAUTION]
> 물리적 공간에서의 레드팀 테스트 시, 위조 App Clip Code나 NFC 태그 배치는 현실적이고 효과적인 소셜 엔지니어링 벡터입니다. 물리적 공간에서 테스트하기 전에 반드시 명시적인 서면 승인을 받으십시오.

**App Clips vs 인스턴트 앱 — 펜테스터를 위한 비교:**

| 항목 | Android 인스턴트 앱 | Apple App Clips |
|:-----|:--------------------|:----------------|
| 진입점 | URL / Play Store 배지 | QR, NFC, Safari, 지도, iMessage, App Clip Code (물리적) |
| 크기 제한 | 모듈당 별도 제한 없음 | 15MB 엄격 제한 |
| 저장소 지속성 | 세션 간 SharedPreferences 없음 | 비활성 시 삭제; 키체인은 전체 앱으로 이어짐 |
| 인증 연속성 | `InstantApps` 공유 자격증명 API | 앱 그룹을 통한 키체인 공유 |
| 주요 피싱 위험 | 유사 도메인 + Play Instant | 물리적 장소 위조 NFC/QR |

## IPC — 프로세스 간 통신

IPC는 앱과 시스템 컴포넌트가 프로세스 경계를 넘어 통신하는 방식입니다. 이는 모바일 펜테스팅에서 가장 풍부한 공격 표면 중 하나입니다. 개발자들이 IPC 메커니즘을 잘못 구성하여 내부 기능을 다른 앱에 노출시키는 경우가 흔하기 때문입니다.

### Android IPC

Android는 강력한 IPC 토대 위에 구축되어 있습니다. 핵심 메커니즘은 **Binder** — 모든 Android IPC가 통과하는 커널 수준 드라이버입니다.

#### 인텐트 (Intent)

가장 일반적인 IPC 메커니즘. 인텐트는 Activity 시작, Service 실행, 브로드캐스트 전송에 사용되는 메시지 객체입니다.

```java
// 명시적 인텐트 — 특정 컴포넌트 대상 (안전)
Intent intent = new Intent(this, PaymentActivity.class);

// 암시적 인텐트 — 어떤 컴포넌트든 처리 가능 (공격 표면!)
Intent intent = new Intent("com.example.ACTION_PROCESS_PAYMENT");
intent.putExtra("amount", 100);
startActivity(intent);
```

**공격: 인텐트 인젝션 / 인텐트 하이재킹**

공격자가 동일한 액션을 처리하도록 Activity를 등록하면, 암시적 인텐트를 가로챌 수 있습니다. 피해 앱이 `startActivityForResult`를 사용한다면, 공격자 앱이 결과와 함께 민감한 데이터를 수신하게 됩니다.

**drozer를 이용한 테스트:**
```bash
# 노출된 Activity 목록 (다른 앱에서 접근 가능한 것들)
run app.activity.info -a com.target.app

# 노출된 Activity 직접 실행 시도
run app.activity.start --component com.target.app com.target.app.InternalSettingsActivity

# 컨텐트 프로바이더 SQL 인젝션 스캔
run scanner.provider.injection -a com.target.app
run scanner.provider.traversal -a com.target.app
```

#### 컨텐트 프로바이더 (Content Provider)

컨텐트 프로바이더는 URI 기반 API를 통해 다른 앱에 구조화된 데이터(주로 SQLite)를 노출합니다.

```bash
# ADB로 컨텐트 프로바이더 직접 쿼리
adb shell content query --uri content://com.target.app.provider/users

# SQL 인젝션 시도
adb shell content query --uri content://com.target.app.provider/users \
    --where "1=1 UNION SELECT name,sql,3,4,5 FROM sqlite_master--"
```

`permission` 속성 없이 노출된 프로바이더는 **기기의 모든 앱**에서 접근 가능합니다.

### iOS IPC

iOS는 훨씬 엄격한 IPC 모델을 가집니다 — 앱들은 기본적으로 샌드박스로 격리되어 자유롭게 통신할 수 없습니다.

#### URL 스킴

커스텀 URL 스킴은 다른 앱이나 웹 페이지에서 앱으로 데이터를 전달합니다:

```swift
// 앱이 "myapp://action?param=value" 등록
func application(_ app: UIApplication, open url: URL, options: ...) -> Bool {
    // url.host = "action", url.queryItems = ["param": "value"]
}
```

**공격: URL 스킴 하이재킹**

여러 앱이 동일한 URL 스킴을 등록할 수 있습니다. iOS는 마지막으로 설치된 앱으로 처리합니다 — 공격자가 `myapp://`을 자신의 악성 앱에 등록할 수 있습니다:

```bash
# 시뮬레이터에서 URL 스킴 테스트
xcrun simctl openurl booted "targetapp://admin?bypass=true"
```

#### 유니버셜 링크 (Universal Links)

URL 스킴의 더 안전한 대안. 서버 측 `apple-app-site-association` 파일이 도메인 소유권을 증명해야 합니다. AASA 파일이 잘못 구성된 경우 링크가 브라우저로 대체됩니다.

```bash
# 도메인의 AASA 파일 확인
curl https://example.com/.well-known/apple-app-site-association
# "paths" 배열에 없는 경로로 딥링크 테스트
```

#### XPC 서비스 및 앱 그룹

XPC는 Apple의 선호 IPC 메커니즘입니다. 펜테스팅에서는 주로 앱 익스텐션과 앱 그룹 공유 컨테이너 관련하여 등장합니다:

```bash
# 앱이 속한 앱 그룹 확인 (엔타이틀먼트)
codesign -d --entitlements :- Runner.app/Runner | grep -A5 "application-groups"
# 앱 그룹 간 공유 데이터에서 민감 정보 노출 여부 확인
```

## 인스턴스 콜 (Instance Call)

**인스턴스 콜**은 앱이 자연스럽게 메서드를 호출할 때까지 기다리는 것이 아니라, 메모리에서 살아있는 **기존 객체 인스턴스**를 직접 찾아 메서드를 즉시 호출하는 기법입니다. 이것이 앱을 *관찰*하는 것과 앱을 *능동적으로 조종*하는 것의 차이입니다.

### 인스턴스 콜이 펜테스팅에서 중요한 이유

앱의 많은 보호 함수들은 실행 전 인증 상태, 세션 유효성, 사용자 권한을 확인합니다. 그런데 실제로 특권 작업을 수행하는 *객체 인스턴스*는 이미 메모리에 존재합니다. 그 인스턴스를 찾아 메서드를 직접 호출하면, 접근을 막아야 했던 게이팅 로직을 우회할 수 있습니다.

### ObjC.chooseSync — iOS 힙 스캔

```javascript
// 힙에서 특정 클래스의 라이브 인스턴스를 찾음
var authManager = ObjC.chooseSync(ObjC.classes.AuthenticationManager);

if (authManager.length > 0) {
    var instance = authManager[0];
    console.log("[*] 라이브 AuthenticationManager 발견:", instance);

    // 인스턴스 변수 검사
    console.log("[*] 현재 인증 상태:", instance.isAuthenticated());
    console.log("[*] 현재 사용자:", instance.currentUser().toString());

    // 일반적으로 인증이 필요한 특권 메서드 강제 호출
    var adminData = instance.fetchAdminDashboard();
    console.log("[*] 반환된 관리자 데이터:", adminData.toString());
}
```

`ObjC.chooseSync`는 Objective-C 힙을 탐색하여 지정된 클래스의 모든 인스턴스를 반환합니다. 비용이 크지만(힙 스캔), 싱글톤이나 지연 초기화 객체에도 동작합니다.

### Java.choose — Android 힙 스캔

```javascript
Java.perform(function() {
    Java.choose("com.example.app.AccountManager", {
        onMatch: function(instance) {
            console.log("[*] AccountManager 인스턴스 발견:", instance);

            // 라이브 인스턴스에서 직접 메서드 호출
            var balance = instance.getAccountBalance();
            console.log("[*] 잔액:", balance);

            // IDOR 테스트: 다른 사용자 ID로 호출
            var otherBalance = instance.getAccountBalanceForUser("TARGET_USER_ID");
            console.log("[*] 다른 사용자 잔액:", otherBalance);

            // 관리자 전용 함수 호출 시도
            try {
                var adminResult = instance.resetAllUserPasswords();
                console.log("[*] 관리자 함수 접근 가능:", adminResult);
            } catch(e) {
                console.log("[*] 관리자 함수 차단됨:", e.message);
            }
        },
        onComplete: function() {
            console.log("[*] 힙 스캔 완료");
        }
    });
});
```

### IPC와 인스턴스 콜의 결합

강력한 테스트 패턴: IPC를 트리거하여 코드 경로를 활성화하고, 인스턴스 콜로 결과 객체 상태를 검사하거나 조작합니다.

```javascript
Java.perform(function() {
    // Step 1: 인텐트 수신을 후킹하여 IPC 모니터링
    var Activity = Java.use("android.app.Activity");
    Activity.onNewIntent.implementation = function(intent) {
        var action = intent.getAction();
        console.log("[*] IPC 인텐트 수신 — 액션:", action);
        this.onNewIntent(intent);

        // Step 2: IPC로 상태가 변경된 후, 인스턴스 콜로 결과 검사
        Java.choose("com.example.app.SessionManager", {
            onMatch: function(session) {
                console.log("[*] IPC 후 세션 상태:", session.getCurrentState().toString());
                console.log("[*] 관리자 권한 부여됨?", session.hasAdminRole());
            },
            onComplete: function() {}
        });
    };
});
```
