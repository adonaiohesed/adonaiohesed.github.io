---
title: App Attest & Play Integrity
key: page-app_attest_play_integrity
categories:
- Security
- Mobile Security
author: hyoeun
math: true
mathjax_autoNumber: true
image: "/assets/thumbnails/2023-05-26-app_attest_play_integrity.png"
bilingual: true
date: 2023-05-26 16:12:00
---

## App Attest & Play Integrity: Server-Side Attestation for Mobile Apps

Anti-Tamper checks embedded in the app binary are inherently self-referential — the code that is supposed to detect tampering is itself part of the binary that can be tampered with. The next level of defense is **remote attestation**: asking a trusted third party (Apple or Google) to cryptographically certify that the app and device are genuine, before granting access to sensitive server resources.

**Apple App Attest** (iOS 14+) and the **Google Play Integrity API** (Android) are the platform-native solutions to this problem. They allow your server to ask: *"Is this request coming from an unmodified version of my app, running on a legitimate device?"*

## Core Concepts

### What Is Attestation?

Attestation is the process by which a device generates a cryptographic proof — signed by a hardware-backed key trusted by the platform vendor — that the current software and device state meet a defined baseline. The server validates this proof rather than trusting any claim made by the app itself.

Key properties:
- The signing key is generated inside the device's **Secure Enclave** (iOS) or **StrongBox / TEE** (Android), and cannot be exported.
- The signature covers specific identifiers (App ID, bundle version, device ID hash) so it cannot be replayed across apps or devices.
- Validation happens **server-side**, meaning the attacker cannot influence the result by patching the app.

### Apple App Attest

App Attest uses the **DeviceCheck framework** and the Secure Enclave to produce two types of artifacts:

| Artifact | When Used | Purpose |
|---|---|---|
| **Attestation** | One-time, at first launch | Registers a key with Apple; proves key was generated in a legitimate device |
| **Assertion** | Per-request | Proves a specific request was made by the app that owns the attested key |

**Key identifiers included in the attestation:**
- `appId` = Team ID + Bundle ID
- `receipt` — Apple-signed proof of app distribution
- A hash of the client-generated challenge (prevents replay)

### Google Play Integrity API

Play Integrity replaces the deprecated SafetyNet Attestation API. It returns a **signed JWT** (signed by Google) containing three verdict categories:

| Verdict | Meaning |
|---|---|
| `MEETS_DEVICE_INTEGRITY` | Device passes hardware-backed integrity checks |
| `MEETS_BASIC_INTEGRITY` | Device passes software-level integrity checks (no strong hardware guarantee) |
| `MEETS_STRONG_INTEGRITY` | Highest assurance — hardware-backed key attestation confirmed |
| `appRecognitionVerdict` | Whether the app is distributed via Google Play and unmodified |
| `accountDetails` | Whether the account is licensed to use the app |

## How It Works

### App Attest Flow (iOS)

```
1. App generates a key pair inside the Secure Enclave
   → DCAppAttestService.generateKey()

2. App requests attestation from Apple's servers
   → DCAppAttestService.attestKey(keyId, clientDataHash)
   → Apple verifies the device & app, returns an attestation object

3. App sends attestation object to YOUR server
   → Your server validates it against Apple's root CA

4. For each subsequent sensitive request:
   → App signs the request body with DCAppAttestService.generateAssertion()
   → Server verifies the assertion using the public key from step 3
```

**Server-side validation checklist (App Attest):**
- Verify the attestation certificate chain up to Apple's root CA
- Check `aaguid` matches Apple App Attest production/development
- Confirm `rpIdHash` matches your app's App ID hash
- Verify the challenge hash in `clientDataHash` (prevents replay)
- Store the public key; use it to verify all future assertions

### Play Integrity Flow (Android)

```
1. Your server generates a nonce (challenge) and sends it to the app

2. App requests an integrity token from Google Play
   → IntegrityManager.requestIntegrityToken(nonce)

3. App sends the token to YOUR server

4. Your server sends the token to Google's Integrity API for decryption
   → POST https://playintegrity.googleapis.com/v1/{package}:decodeIntegrityToken
   → Google returns the decrypted verdict JSON

5. Server checks verdicts and grants or denies access
```

**Server-side validation checklist (Play Integrity):**
- Confirm `requestDetails.requestPackageName` matches your app
- Confirm `requestDetails.nonce` matches the challenge you issued
- Check `appIntegrity.appRecognitionVerdict == PLAY_RECOGNIZED`
- Check `deviceIntegrity` verdict meets your required level
- Verify `requestDetails.timestampMillis` is recent (prevent replay)

## Bypass Methods

Understanding how attackers bypass these checks is essential for setting the right server-side thresholds.

### Bypassing App Attest

**1. Using a Jailbroken Device with Patched Frameworks**

On jailbroken devices, the Secure Enclave is still intact, but the OS-level attestation request process can be intercepted. Tools like **Shadow** or custom Substrate tweaks can:
- Hook `DCAppAttestService` methods to return a pre-captured legitimate attestation from a non-jailbroken device.
- Cache a valid attestation object obtained from a clean device and replay it.

**Mitigation:** Embed a fresh server-generated challenge (`clientDataHash`) in every attestation and assertion request. A replayed attestation from a different session will fail challenge verification.

**2. Frida Hooking of the Assertion Flow**

An attacker runs the app on a clean device, hooks `generateAssertion`, and proxies assertion requests. The app runs legitimately on the clean device, but the attacker routes its network traffic through a MITM proxy to observe or replay tokens.

**Mitigation:** Bind assertions to a session token and invalidate after single use. Rate-limit token issuance server-side.

**3. Emulator / Simulator**

Apple's Simulator does not support App Attest. Legitimate requests from a simulator will fail at attestation time. However, if an attacker extracts the app binary and sideloads it onto a non-jailbroken device with a custom provisioning profile, the `appId` in the attestation will differ from the production value.

**Mitigation:** Verify the `appId` in the attestation matches your production Team ID + Bundle ID exactly.

### Bypassing Play Integrity

**1. Strong Integrity Downgrade**

Many apps only check `MEETS_DEVICE_INTEGRITY` (software-level). On a rooted device with **Magisk** and the **Play Integrity Fix** module, it is often possible to pass `MEETS_DEVICE_INTEGRITY` while the device is actually rooted.

**Mitigation:** Require `MEETS_STRONG_INTEGRITY` for the most sensitive operations (payment, account changes). Accept `MEETS_BASIC_INTEGRITY` only for lower-risk actions.

**2. Nonce Reuse / Token Replay**

If the server does not validate the `nonce` field or accept tokens beyond their validity window, an attacker can capture a valid integrity token from a clean device and replay it.

**Mitigation:** Generate a unique, server-side nonce per request; mark tokens as used after validation; reject tokens older than 60 seconds.

**3. Hooking `requestIntegrityToken`**

With Frida on a rooted device, an attacker hooks `IntegrityManager.requestIntegrityToken()` and returns a token captured from a clean device.

**Mitigation:** Bind the nonce to session-specific data (user ID, device fingerprint) so a token captured on a different device cannot pass server-side nonce verification.

**4. Custom ROMs Without Play Services**

Devices running AOSP or custom ROMs without Google Play Services cannot produce Play Integrity tokens at all. Requests from these devices will fail token generation.

**Mitigation:** Treat token generation failure as a risk signal. Decide whether to block or apply step-up authentication for such devices based on your threat model.

## Testing

### Testing App Attest

**Development Environment**

By default, `DCAppAttestService.isSupported` returns `false` in the Simulator. Use `DCAppAttestService.Environment.development` to test against Apple's development attestation environment, which issues lower-assurance but valid attestations on real devices running a debug build.

```swift
// Check support before calling
guard DCAppAttestService.shared.isSupported else {
    // Handle gracefully — simulator or unsupported device
    return
}
```

**Integration Testing Checklist**

- [ ] Attestation succeeds on a physical device with a production build
- [ ] Attestation fails in the Simulator (expected)
- [ ] Server correctly rejects an attestation with a tampered `clientDataHash`
- [ ] Server correctly rejects a replayed assertion (duplicate challenge)
- [ ] Server correctly rejects an assertion with a mismatched `appId`
- [ ] App handles `DCErrorDomain` errors gracefully (network failure, rate limit)

**Simulating Failure Cases**

Use `launchArguments` or environment variables in your Xcode scheme to inject a mode that skips App Attest calls and simulates failure responses, allowing UI testing without live Apple servers.

### Testing Play Integrity

**Test Response Codes**

Google provides a `testingOptions` parameter in the `IntegrityTokenRequest` that returns synthetic verdicts without hitting production Play servers. Use this in CI/CD pipelines.

```kotlin
val request = IntegrityTokenRequest.builder()
    .setNonce(nonce)
    .setCloudProjectNumber(cloudProjectNumber)
    .build()
// For testing, inject test scenario codes via Google Play Console
```

**Integration Testing Checklist**

- [ ] Token decryption succeeds on the server for a Play Store-installed app
- [ ] Server rejects a token with a stale / mismatched nonce
- [ ] Server rejects a token where `requestPackageName` does not match
- [ ] `MEETS_STRONG_INTEGRITY` is verified for high-risk endpoints
- [ ] Server gracefully degrades when no token is provided (based on risk policy)
- [ ] Token generation failure is handled in-app without crash

**Testing on Rooted Devices**

Use a rooted device with Magisk + Play Integrity Fix to verify your server-side threshold logic. Confirm that:
- A rooted device that spoofs `MEETS_DEVICE_INTEGRITY` is blocked on endpoints requiring `MEETS_STRONG_INTEGRITY`.
- Your server logs and alerts fire correctly when integrity verdicts fall below threshold.

## Defense in Depth

App Attest and Play Integrity are powerful but not absolute. Combine them with:

| Layer | Mechanism |
|---|---|
| Runtime checks | Anti-debugging, anti-hooking, root/jailbreak detection (as a speed bump) |
| Network | Certificate pinning to prevent MITM proxy interception |
| Server | Anomaly detection (unusual request rates, geographic jumps) |
| Backend | Treat attestation as a risk signal, not a binary gate — apply adaptive step-up auth |

The platform attestation APIs shift the trust anchor from the app binary (attacker-controlled) to the device's hardware security module and the platform vendor's backend — making bypass significantly more expensive and detectable.

---

## App Attest & Play Integrity: 서버 측 원격 증명

앱 바이너리에 내장된 Anti-Tamper 검사는 본질적으로 자기 참조적입니다. 변조를 탐지해야 하는 코드 자체가 변조될 수 있는 바이너리의 일부이기 때문입니다. 다음 단계의 방어는 **원격 증명(Remote Attestation)**입니다. 신뢰할 수 있는 제3자(Apple 또는 Google)에게 앱과 기기가 진본임을 암호학적으로 인증받은 뒤, 서버의 민감한 리소스에 접근을 허용하는 방식입니다.

**Apple App Attest**(iOS 14+)와 **Google Play Integrity API**(Android)는 이 문제에 대한 플랫폼 네이티브 솔루션입니다. 서버가 다음 질문을 할 수 있게 해줍니다: *"이 요청이 정상적인 기기에서 실행 중인, 변조되지 않은 내 앱에서 오는 것인가?"*

## 핵심 개념

### 증명(Attestation)이란?

증명은 기기가 플랫폼 벤더가 신뢰하는 하드웨어 기반 키로 서명된 암호학적 증명을 생성하는 과정입니다. 이를 통해 현재 소프트웨어와 기기 상태가 정해진 기준을 충족함을 증명합니다. 서버는 앱 자체가 주장하는 것을 신뢰하는 대신, 이 증명을 검증합니다.

핵심 특성:
- 서명 키는 기기의 **Secure Enclave**(iOS) 또는 **StrongBox / TEE**(Android) 내부에서 생성되며 외부로 내보낼 수 없습니다.
- 서명은 특정 식별자(App ID, 번들 버전, 기기 ID 해시)를 포함하므로 다른 앱이나 기기에서 재사용할 수 없습니다.
- 검증은 **서버 측**에서 이루어지므로, 공격자는 앱을 패치하는 방식으로 결과에 영향을 줄 수 없습니다.

### Apple App Attest

App Attest는 **DeviceCheck 프레임워크**와 Secure Enclave를 사용하여 두 가지 유형의 아티팩트를 생성합니다:

| 아티팩트 | 사용 시점 | 목적 |
|---|---|---|
| **Attestation** | 최초 실행 시 1회 | Apple에 키를 등록; 정상 기기에서 키가 생성되었음을 증명 |
| **Assertion** | 요청마다 | 증명된 키를 소유한 앱이 특정 요청을 보냈음을 증명 |

**증명에 포함되는 핵심 식별자:**
- `appId` = Team ID + Bundle ID
- `receipt` — 앱 배포에 대한 Apple 서명 증명
- 클라이언트 생성 챌린지의 해시 (재전송 공격 방지)

### Google Play Integrity API

Play Integrity는 SafetyNet Attestation API를 대체합니다. Google이 서명한 **JWT**를 반환하며, 세 가지 판정 카테고리를 포함합니다:

| 판정 | 의미 |
|---|---|
| `MEETS_DEVICE_INTEGRITY` | 기기가 하드웨어 기반 무결성 검사를 통과 |
| `MEETS_BASIC_INTEGRITY` | 소프트웨어 수준 무결성 검사 통과 (하드웨어 보장 없음) |
| `MEETS_STRONG_INTEGRITY` | 최고 수준 — 하드웨어 기반 키 증명 확인됨 |
| `appRecognitionVerdict` | 앱이 Google Play를 통해 배포되었고 변조되지 않았는지 여부 |
| `accountDetails` | 계정이 앱 사용 라이선스를 보유하고 있는지 여부 |

## 작동 원리

### App Attest 흐름 (iOS)

```
1. 앱이 Secure Enclave 내부에서 키 쌍 생성
   → DCAppAttestService.generateKey()

2. 앱이 Apple 서버에 증명 요청
   → DCAppAttestService.attestKey(keyId, clientDataHash)
   → Apple이 기기 & 앱을 검증하고 증명 객체 반환

3. 앱이 증명 객체를 내 서버로 전송
   → 서버가 Apple 루트 CA를 통해 검증

4. 이후 민감한 요청마다:
   → DCAppAttestService.generateAssertion()으로 요청 본문 서명
   → 서버가 3단계에서 확보한 공개 키로 Assertion 검증
```

**서버 측 검증 체크리스트 (App Attest):**
- 증명 인증서 체인을 Apple 루트 CA까지 검증
- `aaguid`가 Apple App Attest 프로덕션/개발 값과 일치하는지 확인
- `rpIdHash`가 앱의 App ID 해시와 일치하는지 확인
- `clientDataHash`의 챌린지 해시 검증 (재전송 방지)
- 공개 키를 저장하고 이후 모든 Assertion 검증에 활용

### Play Integrity 흐름 (Android)

```
1. 서버가 논스(챌린지)를 생성하여 앱에 전송

2. 앱이 Google Play로부터 무결성 토큰 요청
   → IntegrityManager.requestIntegrityToken(nonce)

3. 앱이 토큰을 내 서버로 전송

4. 서버가 토큰을 Google Integrity API에 전송하여 복호화
   → POST https://playintegrity.googleapis.com/v1/{package}:decodeIntegrityToken
   → Google이 복호화된 판정 JSON 반환

5. 서버가 판정을 확인하고 접근 허용 또는 거부
```

**서버 측 검증 체크리스트 (Play Integrity):**
- `requestDetails.requestPackageName`이 내 앱과 일치하는지 확인
- `requestDetails.nonce`가 발급한 챌린지와 일치하는지 확인
- `appIntegrity.appRecognitionVerdict == PLAY_RECOGNIZED` 확인
- `deviceIntegrity` 판정이 요구 수준을 충족하는지 확인
- `requestDetails.timestampMillis`가 최근 값인지 검증 (재전송 방지)

## 우회 방법

공격자들이 이 검사를 어떻게 우회하는지 이해하는 것이 서버 측 임계값 설정에 필수적입니다.

### App Attest 우회

**1. 패치된 프레임워크를 사용한 탈옥 기기**

탈옥 기기에서도 Secure Enclave는 온전하지만, OS 수준의 증명 요청 과정을 가로챌 수 있습니다. **Shadow** 같은 도구나 커스텀 Substrate 트윅으로:
- `DCAppAttestService` 메서드를 후킹하여 정상 기기에서 미리 캡처한 증명 객체를 반환합니다.
- 클린 기기에서 얻은 유효한 증명 객체를 캐시하여 재전송합니다.

**대응책:** 모든 Attestation 및 Assertion 요청에 서버 생성 챌린지(`clientDataHash`)를 포함시킵니다. 다른 세션에서 재전송된 증명은 챌린지 검증에서 실패합니다.

**2. Assertion 흐름에 대한 Frida 후킹**

공격자가 클린 기기에서 앱을 실행하고 `generateAssertion`을 후킹하여 Assertion 요청을 프록시합니다. 앱은 클린 기기에서 정상 실행되지만, 네트워크 트래픽은 MITM 프록시를 통해 관찰되거나 재전송됩니다.

**대응책:** Assertion을 세션 토큰에 바인딩하고 단 1회 사용 후 무효화합니다. 서버 측에서 토큰 발급에 속도 제한을 적용합니다.

**3. 에뮬레이터 / 시뮬레이터**

Apple Simulator는 App Attest를 지원하지 않습니다. 시뮬레이터에서의 요청은 증명 단계에서 실패합니다. 그러나 공격자가 바이너리를 추출하여 커스텀 프로비저닝 프로파일로 정상 기기에 사이드로딩하면, 증명의 `appId`가 프로덕션 값과 달라집니다.

**대응책:** 증명의 `appId`가 정확히 프로덕션 Team ID + Bundle ID와 일치하는지 검증합니다.

### Play Integrity 우회

**1. Strong Integrity 다운그레이드**

많은 앱이 소프트웨어 수준인 `MEETS_DEVICE_INTEGRITY`만 확인합니다. **Magisk**와 **Play Integrity Fix** 모듈이 설치된 루팅 기기에서는 실제로 루팅된 상태임에도 이 판정을 통과할 수 있습니다.

**대응책:** 결제, 계정 변경 등 민감한 작업에는 `MEETS_STRONG_INTEGRITY`를 요구합니다. 위험도가 낮은 작업에만 `MEETS_BASIC_INTEGRITY`를 허용합니다.

**2. 논스 재사용 / 토큰 재전송**

서버가 `nonce` 필드를 검증하지 않거나 유효 기간이 지난 토큰을 수락하면, 공격자가 클린 기기에서 캡처한 유효한 토큰을 재전송할 수 있습니다.

**대응책:** 요청마다 서버 측에서 고유한 논스를 생성하고, 검증 후 사용된 토큰을 무효화하며, 60초 이상 경과한 토큰을 거부합니다.

**3. `requestIntegrityToken` 후킹**

루팅 기기에서 Frida로 `IntegrityManager.requestIntegrityToken()`을 후킹하여 클린 기기에서 캡처한 토큰을 반환합니다.

**대응책:** 논스에 세션별 데이터(사용자 ID, 기기 핑거프린트)를 바인딩하여, 다른 기기에서 캡처한 토큰이 서버 측 논스 검증을 통과하지 못하도록 합니다.

**4. Play Services가 없는 커스텀 ROM**

AOSP 또는 Google Play Services가 없는 커스텀 ROM이 설치된 기기는 Play Integrity 토큰을 생성할 수 없습니다. 이러한 기기에서의 요청은 토큰 생성 단계에서 실패합니다.

**대응책:** 토큰 생성 실패를 위험 신호로 처리합니다. 위협 모델에 따라 해당 기기를 차단하거나 추가 인증을 적용할지 결정합니다.

## 테스트 방법

### App Attest 테스트

**개발 환경**

기본적으로 `DCAppAttestService.isSupported`는 시뮬레이터에서 `false`를 반환합니다. 실기기의 디버그 빌드에서 `DCAppAttestService.Environment.development`를 사용하면 Apple의 개발 증명 환경을 통해 테스트할 수 있습니다.

```swift
guard DCAppAttestService.shared.isSupported else {
    // 시뮬레이터 또는 지원되지 않는 기기 — 우아하게 처리
    return
}
```

**통합 테스트 체크리스트**

- [ ] 프로덕션 빌드의 실기기에서 Attestation 성공
- [ ] 시뮬레이터에서 Attestation 실패 (예상된 동작)
- [ ] 변조된 `clientDataHash`를 가진 Attestation을 서버가 올바르게 거부
- [ ] 재전송된 Assertion(중복 챌린지)을 서버가 올바르게 거부
- [ ] `appId`가 불일치하는 Assertion을 서버가 올바르게 거부
- [ ] 앱이 `DCErrorDomain` 오류를 우아하게 처리 (네트워크 실패, 속도 제한)

**실패 케이스 시뮬레이션**

Xcode 스킴의 `launchArguments` 또는 환경 변수를 사용하여 App Attest 호출을 건너뛰고 실패 응답을 시뮬레이션하는 모드를 주입하면, 실제 Apple 서버 없이도 UI 테스트가 가능합니다.

### Play Integrity 테스트

**테스트 응답 코드**

Google은 `IntegrityTokenRequest`에 `testingOptions` 파라미터를 제공하여 프로덕션 Play 서버를 거치지 않고 합성 판정을 반환받을 수 있습니다. CI/CD 파이프라인에서 활용합니다.

```kotlin
val request = IntegrityTokenRequest.builder()
    .setNonce(nonce)
    .setCloudProjectNumber(cloudProjectNumber)
    .build()
// 테스트 시나리오 코드는 Google Play Console을 통해 주입
```

**통합 테스트 체크리스트**

- [ ] Play Store 설치 앱의 서버 측 토큰 복호화 성공
- [ ] 오래되거나 불일치하는 논스를 가진 토큰을 서버가 거부
- [ ] `requestPackageName`이 불일치하는 토큰을 서버가 거부
- [ ] 고위험 엔드포인트에서 `MEETS_STRONG_INTEGRITY` 검증
- [ ] 토큰 미제공 시 앱이 위험 정책에 따라 우아하게 처리
- [ ] 토큰 생성 실패 시 앱이 크래시 없이 처리

**루팅 기기에서의 테스트**

Magisk + Play Integrity Fix가 설치된 루팅 기기를 사용하여 서버 측 임계값 로직을 검증합니다:
- `MEETS_DEVICE_INTEGRITY`를 스푸핑하는 루팅 기기가 `MEETS_STRONG_INTEGRITY`를 요구하는 엔드포인트에서 차단되는지 확인
- 무결성 판정이 임계값 이하로 떨어질 때 서버 로그와 알림이 올바르게 작동하는지 확인

## 심층 방어

App Attest와 Play Integrity는 강력하지만 절대적이지 않습니다. 다음과 결합하여 활용하세요:

| 레이어 | 메커니즘 |
|---|---|
| 런타임 검사 | 안티 디버깅, 안티 후킹, 루팅/탈옥 탐지 (속도 장벽용) |
| 네트워크 | 인증서 피닝으로 MITM 프록시 가로채기 방지 |
| 서버 | 이상 감지 (비정상적인 요청 빈도, 지리적 이동 등) |
| 백엔드 | 증명을 이진 게이트가 아닌 위험 신호로 취급 — 적응형 단계적 인증 적용 |

플랫폼 증명 API는 신뢰 앵커를 공격자가 제어할 수 있는 앱 바이너리에서 기기의 하드웨어 보안 모듈과 플랫폼 벤더의 백엔드로 이동시킵니다. 이는 우회를 훨씬 더 어렵고 비용이 많이 들게 만들며, 탐지 가능하게 합니다.
