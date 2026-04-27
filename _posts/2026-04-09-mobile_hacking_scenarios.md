---
title: How Attackers Hack Mobile Devices - Real Scenarios
key: page-mobile_hacking_scenarios
categories:
- Security
- Mobile Security
author: hyoeun
math: true
mathjax_autoNumber: true
bilingual: true
image: "/assets/thumbnails/2026-04-09-mobile_hacking_scenarios.png"
date: 2026-04-09 10:00:00
---
## How Attackers Actually Hack Mobile Devices: Real Scenarios and Defenses

As a mobile pentester, you often focus on analyzing *a specific app* in isolation — hooking its API calls, reviewing its storage. But real attackers don't think in app-scoped terms. They think in **device-scoped** terms. Understanding how attackers approach a mobile device from scratch helps you think like an attacker on engagements and explain risk to clients in terms they care about.

These are realistic attack scenarios — not Hollywood hacking, not theoretical research. These are techniques used in financial fraud, espionage, and opportunistic crime, ordered roughly by how technically sophisticated they are.

## Scenario 1: The Coffee Shop Interception

**Attacker profile:** Someone at a café with a laptop and basic networking knowledge.

**What they do:**

The attacker sets up a **rogue access point** — a Wi-Fi network named "Starbucks_Guest" — using a laptop running hostapd and a tool like bettercap or EvilAP. Nearby phones auto-connect or users manually connect, thinking it's the legitimate café Wi-Fi.

With all traffic routed through the attacker's machine:
1.  **Unencrypted HTTP traffic** is captured directly — credentials, session tokens, API keys transmitted in cleartext are trivially readable.
2.  For **HTTPS traffic**, the attacker attempts SSL stripping: downgrading the connection from HTTPS to HTTP for apps that don't enforce HSTS. The user sees no lock icon, but many don't notice.
3.  Against apps **without certificate pinning**, the attacker presents a self-signed (or Burp Suite-generated) certificate. The OS warns the user, but some apps accept it silently if they've disabled certificate validation in code.

**What breaks this:**
*   Certificate pinning (attacker can't present a valid cert for your pinned key)
*   HSTS preloading + enforced HTTPS
*   VPN on the corporate device policy

**Pentesting angle:** When you test an app for this, you're not just checking certificate pinning. You're checking whether the app falls back to HTTP anywhere, whether it gracefully handles invalid certificates (crashes vs. silent acceptance), and whether it leaks anything in the pre-SSL handshake (SNI reveals hostnames even over encrypted connections).

## Scenario 2: Smishing → Malicious App Install

**Attacker profile:** A fraud operation targeting banking customers.

**The attack chain:**

1.  **SMS phishing (smishing):** Target receives: *"Your Chase account has been locked. Verify now: bit.ly/chase-verify"*
2.  **Fake website:** The link opens a convincing clone of the bank's site. The user is told to install a "security app" or "verification tool."
3.  **Android target:** User is prompted to enable "Install Unknown Apps" for their browser, then install the APK. The APK is a trojan — it requests accessibility service permissions and uses them to:
    *   Read the screen, capturing OTPs and credentials
    *   Automatically dismiss security dialogs
    *   Overlay fake screens on top of legitimate banking apps (overlay attack)
4.  **iOS target:** Because you can't sideload without user effort, the attack route changes: the fake site deploys a **malicious MDM profile**. User is prompted to install a configuration profile (Settings → Profile Downloaded → Install). This MDM profile can restrict device settings, deploy apps, and in some cases read managed data.

**What breaks this:**
*   OS warnings about accessibility permissions (but they're easily dismissed)
*   Google Protect / iOS app notarization for App Store apps
*   For MDM: Supervision mode (locks MDM to authorized management only)

**Pentesting angle:** Corporate devices should be tested for whether they allow arbitrary MDM enrollment, whether security apps can be disabled via accessibility exploits, and whether overlay attacks are possible against the target banking/payment apps.

## Scenario 3: Physical Access — The Unlocked Phone

**Attacker profile:** Anyone with 5 minutes alone with an unlocked (or poorly locked) phone.

This sounds trivial but is one of the most impactful scenarios in real enterprise compromises. An unlocked phone on a desk during a meeting, left in a car for 20 minutes, or surrendered to border security for inspection.

**What an attacker does in 5 minutes:**

*   **adb backup** (if `allowBackup=true` in the app): `adb backup -apk -nosystem -f backup.ab com.targeted.app` — creates an unencrypted backup of the app's data, including SQLite databases and SharedPreferences
*   **Filesystem copy via adb** (non-rooted): Even without root, `adb pull /sdcard/` captures external storage. Banking apps that cache statements to Downloads are exposed.
*   **Screenshot via adb**: `adb shell screencap -p /sdcard/screen.png && adb pull /sdcard/screen.png`
*   **Install monitoring APK**: `adb install stalkerware.apk` — installs in < 30 seconds, completely silent
*   **Pair a new adb device**: Even after removing physical access, a paired adb host can reconnect over Wi-Fi if `adb tcpip` mode is left enabled

**What breaks this:**
*   `adb` disabled in production builds / enterprise MDM policy
*   Screen lock (even basic PIN)
*   Encrypted storage (Android encryption disabled without PIN)
*   Android's "Revoke USB Debugging Authorization" after each session

**Pentesting angle:** This is literally part of your local data storage testing methodology — you use adb backup and filesystem analysis as standard steps. What you're verifying is whether the app leaves any accessible data outside its protected sandbox.

## Scenario 4: Malicious Charging Station (Juice Jacking)

**Attacker profile:** An actor with access to install modified hardware at airports, malls, or hotel business centers.

**What they do:**

A modified USB charging station contains a small computer (a Raspberry Pi or custom hardware) that, when you connect your phone to charge, also attempts to establish an adb connection. With older Android devices without a USB connection dialog, this could silently succeed. With newer devices, the user sees "Allow USB Debugging?" — and in a tired, distracted state, may tap "Allow."

Once adb access is established, everything from Scenario 3 applies.

**On iOS:** A similar attack uses the pairing mechanism. iOS shows a "Trust This Computer?" dialog. If trusted, an attacker gains access to everything a paired host can access: backups, file system (limited, via iFuse or iMazing), crash logs, installed app list.

FBI and FTC have issued public warnings about juice jacking. The mitigation is simple: use USB data-blocking cables ("USB condoms") or AC power adapters.

**Pentesting angle:** Test whether your client's corporate devices have policies that prevent USB pairing (iOS: Supervised mode + USB Accessories restriction). Test whether adb is disabled on Android corporate devices.

## Scenario 5: Zero-Click Exploit via iMessage/WhatsApp

**Attacker profile:** Nation-state or sophisticated criminal group with budget.

**What they do:**

Zero-click exploits require no user interaction. The attacker sends a specially crafted message — an iMessage, WhatsApp message, or MMS — that triggers a vulnerability in the message parsing code. iOS's `ImageIO` framework, for example, has had multiple vulnerabilities that allowed code execution when parsing a malformed image attached to a message.

**Pegasus** (NSO Group) used a chain of vulnerabilities delivered via iMessage to achieve full device compromise: kernel privilege escalation, persistence, and complete data access including Signal messages, GPS history, microphone, and camera.

The attack is sophisticated and expensive. But it's not just state actors — criminal groups purchase these exploits. The target is anyone worth the cost: executives, journalists, lawyers, financial professionals.

**What breaks this:**
*   **Lockdown Mode** (iOS 16+): Restricts risky features (iMessage links, web technologies) to reduce attack surface
*   Keeping iOS/Android fully updated (exploits are patched, attackers need new 0-days)
*   **BlastDoor** (Apple's sandboxed message processing): Contains damage even if parsing fails

**Pentesting angle:** You as a mobile pentester almost certainly won't test 0-click exploits — that's vulnerability research territory. But your client may ask you to assess their exposure to this class of threat. Your role is: evaluate whether executive devices run fully patched OS, whether Lockdown Mode is used where warranted, and whether the mobile device management policy enforces rapid patching.

## Attacker Capability vs. What You Should Test

| Attacker Profile       | Primary Technique               | Mitigation You Test For                        |
|:-------------------------|:---------------------------------|:-----------------------------------------------|
| Opportunistic criminal   | Social engineering, rogue Wi-Fi | Cert pinning, HTTP enforcement                 |
| Fraud operation          | Smishing, malicious apps        | Overlay attack resistance, accessibility abuse |
| Insider threat           | Physical access, adb            | Local data exposure, adb restrictions          |
| Targeted adversary       | Spyware via MDM                 | MDM policy enforcement, profile restrictions   |
| Nation-state             | 0-click exploits                | Patch cadence, Lockdown Mode                   |

The realistic lesson: **most successful mobile attacks against most targets don't use Frida or kernel exploits**. They use social engineering, unencrypted APIs, and poorly configured MDM. Your pentest findings should reflect where the actual risk concentrates for your client's threat model.

---

## 공격자는 실제로 어떻게 모바일 기기를 해킹하는가: 현실적인 시나리오와 방어책

모바일 펜테스터는 보통 특정 앱을 격리된 환경에서 분석합니다 — API 호출 후킹, 저장소 검토 등. 하지만 실제 공격자들은 앱 단위가 아닌 **기기 단위**로 생각합니다. 공격자가 모바일 기기에 처음부터 어떻게 접근하는지 이해하면, 현장에서 공격자의 사고방식으로 테스트하고 클라이언트에게 위험을 실질적으로 설명할 수 있습니다.

## 시나리오 1: 카페 인터셉션

**공격자 프로필:** 노트북과 기초적인 네트워킹 지식을 가진 카페 방문자.

**공격 방법:**

공격자는 hostapd와 bettercap을 이용해 **가짜 액세스 포인트** — "Starbucks_Guest" 같은 이름의 Wi-Fi 네트워크를 만듭니다. 근처 기기들이 자동 연결되거나 사용자가 정상 카페 Wi-Fi로 착각하고 수동 접속합니다.

모든 트래픽이 공격자 기기를 거치면:
1.  **암호화되지 않은 HTTP 트래픽**은 바로 캡처됩니다 — 평문으로 전송되는 자격 증명, 세션 토큰, API 키가 그대로 노출됩니다.
2.  **HTTPS 트래픽**에 대해서는 SSL 스트리핑을 시도합니다 — HSTS를 강제하지 않는 앱의 연결을 HTTPS에서 HTTP로 다운그레이드합니다.
3.  **인증서 피닝이 없는 앱**에 대해서는 자체 서명 인증서를 제시합니다. OS는 경고하지만 일부 앱은 코드에서 검증을 비활성화해 조용히 수락합니다.

**방어:**
*   인증서 피닝 (공격자가 고정된 키에 유효한 인증서 제시 불가)
*   HSTS 사전 로드 + 강제 HTTPS
*   기업 기기 정책상 VPN

**펜테스팅 관점:** 앱이 어디서든 HTTP로 폴백하는지, 잘못된 인증서를 조용히 허용하는지(크래시 vs. 조용한 수락), SSL 핸드셰이크 이전에 무언가를 누출하는지를 확인합니다.

## 시나리오 2: 스미싱 → 악성 앱 설치

**공격자 프로필:** 은행 고객을 표적으로 한 사기 조직.

**공격 체인:**

1.  **SMS 피싱 (스미싱):** *"귀하의 계좌가 잠겼습니다. 즉시 확인하세요: bit.ly/bank-verify"*
2.  **가짜 웹사이트:** 은행 사이트를 그대로 복제한 페이지에서 "보안 앱" 설치를 유도.
3.  **Android 대상:** "알 수 없는 출처" 허용 후 APK 설치. 설치된 트로이 목마가 접근성 서비스 권한을 요청하여:
    *   화면을 읽어 OTP와 자격 증명 캡처
    *   보안 다이얼로그 자동 닫기
    *   합법적인 뱅킹 앱 위에 가짜 화면 오버레이 (오버레이 공격)
4.  **iOS 대상:** 사이드로딩이 어려우므로 **악성 MDM 프로파일**로 방향 전환. "설정 → 다운로드된 프로파일 → 설치" 유도.

**펜테스팅 관점:** 기업 기기에서 임의 MDM 등록이 허용되는지, 접근성 악용으로 보안 앱을 비활성화할 수 있는지, 타겟 뱅킹/결제 앱에 오버레이 공격이 가능한지 테스트합니다.

## 시나리오 3: 물리적 접근 — 잠금 해제된 폰

**공격자 프로필:** 잠금 해제된 폰과 5분의 시간이 있는 누구든.

직장 회의 중 책상 위 폰, 차 안에 두고 내린 20분, 또는 국경 심사에서의 기기 제출.

**5분 안에 공격자가 하는 것:**

*   **adb 백업** (`allowBackup=true`인 경우): 앱의 SQLite DB와 SharedPreferences를 포함한 암호화되지 않은 백업 생성
*   **adb 파일시스템 복사**: 루트 없이도 `adb pull /sdcard/`로 외부 저장소 캡처
*   **모니터링 APK 설치**: `adb install stalkerware.apk` — 30초 이내, 완전히 조용하게

**펜테스팅 관점:** 이것은 실제로 여러분의 로컬 데이터 저장소 테스트 방법론의 일부입니다 — adb 백업 및 파일시스템 분석이 표준 단계입니다. 확인하는 것은 앱이 보호된 샌드박스 외부에 접근 가능한 데이터를 남기는지 여부입니다.

## 시나리오 4: 악성 충전 스테이션 (주스 재킹)

**공격자 프로필:** 공항, 쇼핑몰, 호텔에 수정된 하드웨어를 설치할 수 있는 행위자.

수정된 USB 충전 스테이션에 소형 컴퓨터가 내장되어 있어 충전 시 adb 연결을 시도합니다. 구형 안드로이드는 조용히 허용될 수 있으며, 신형 기기는 "USB 디버깅 허용?" 창이 표시되는데 피로하거나 산만한 상태에서는 "허용"을 탭할 수 있습니다.

iOS에서는 "이 컴퓨터를 신뢰하시겠습니까?" 데이얼로그를 활용합니다. 신뢰 설정 시 페어링된 호스트가 접근할 수 있는 모든 것(백업, 제한된 파일시스템, 충돌 로그 등)에 접근 가능합니다.

**펜테스팅 관점:** 기업 기기에서 USB 페어링을 방지하는 정책이 있는지(iOS: 관리 모드 + USB 액세서리 제한), Android 기업 기기에서 adb가 비활성화되어 있는지 테스트합니다.

## 시나리오 5: iMessage/WhatsApp을 통한 제로 클릭 익스플로잇

**공격자 프로필:** 예산이 있는 국가 수준 또는 정교한 범죄 조직.

제로 클릭 익스플로잇은 사용자 상호작용이 필요 없습니다. 공격자가 특별히 제작된 메시지 — iMessage, WhatsApp 메시지, 또는 MMS — 를 전송하면 메시지 파싱 코드의 취약점이 트리거됩니다. iOS의 `ImageIO` 프레임워크는 잘못된 이미지 파싱 시 코드 실행을 허용하는 여러 취약점이 있었습니다.

**Pegasus** (NSO 그룹)는 iMessage를 통한 취약점 체인으로 완전한 기기 침해를 달성했습니다: 커널 권한 상승, 지속성, Signal 메시지, GPS 이력, 마이크, 카메라를 포함한 완전한 데이터 접근.

**방어:**
*   **잠금 모드** (iOS 16+): 위험한 기능을 제한하여 공격 면을 줄임
*   iOS/Android를 완전히 최신 상태로 유지

**펜테스팅 관점:** 제로 클릭 익스플로잇을 직접 테스트하는 것은 취약점 연구 영역입니다. 하지만 클라이언트가 이 위협 클래스에 대한 노출을 평가하도록 요청할 수 있습니다. 여러분의 역할은: 임원 기기가 완전히 패치된 OS를 실행하는지, 잠금 모드가 적절히 사용되는지, MDM 정책이 신속한 패치를 강제하는지 평가하는 것입니다.

## 공격자 역량 대 테스트해야 할 것

| 공격자 프로필             | 주요 기술                         | 테스트해야 할 방어책                       |
|:-------------------------|:----------------------------------|:---------------------------------------------|
| 기회주의적 범죄자         | 소셜 엔지니어링, 가짜 Wi-Fi         | 인증서 피닝, HTTP 강제                     |
| 사기 조직               | 스미싱, 악성 앱                   | 오버레이 공격 저항성, 접근성 남용            |
| 내부자 위협             | 물리적 접근, adb                   | 로컬 데이터 노출, adb 제한                 |
| 표적화된 공격자           | MDM을 통한 스파이웨어              | MDM 정책 강제, 프로파일 제한               |
| 국가 수준               | 제로 클릭 익스플로잇               | 패치 주기, 잠금 모드                       |

현실적인 교훈: **대부분의 표적에 대한 대부분의 성공적인 모바일 공격은 Frida나 커널 익스플로잇을 사용하지 않습니다**. 소셜 엔지니어링, 암호화되지 않은 API, 잘못 구성된 MDM을 사용합니다. 여러분의 펜테스트 결과는 클라이언트의 위협 모델에 맞는 실제 위험이 집중되는 곳을 반영해야 합니다.
