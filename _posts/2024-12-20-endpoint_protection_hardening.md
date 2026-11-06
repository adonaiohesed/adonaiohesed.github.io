---
title: "Endpoint Protection and Hardening: A Defense-in-Depth Guide"
key: page-endpoint_protection_hardening
categories:
- Security
- Security Operations
author: hyoeun
math: true
mathjax_autoNumber: true
image: "/assets/thumbnails/2024-12-20-endpoint_protection_hardening.png"
bilingual: true
date: 2024-12-20 09:00:00
---

## Endpoint Protection and Hardening: A Defense-in-Depth Guide

Every laptop, workstation, server, and mobile device in your organization is a potential entry point for an attacker. Endpoints are the most targeted layer of any enterprise environment — they sit closest to users, credentials, and data. When an endpoint is compromised, the attacker gains a foothold from which lateral movement, data exfiltration, and privilege escalation begin.

Endpoint security is not a single tool. It is a **layered defense strategy** — often called Defense-in-Depth — where multiple overlapping controls reduce the probability and impact of a breach at every stage of the attack lifecycle.

## The Attack Surface: Why Endpoints Are the Primary Target

Attackers compromise endpoints because:
- **Users interact with them**: Phishing, malicious downloads, and social engineering are all directed at human behavior on endpoints.
- **Credentials live there**: Browsers cache credentials, memory holds session tokens, and keyloggers extract passwords.
- **They have network access**: A compromised endpoint provides a beachhead for internal network reconnaissance.
- **Patch cycles are slow**: Many organizations run months behind on OS and application patches.

Understanding what attackers want from your endpoints is the foundation for knowing what to protect.

## Layer 1: Baseline Hardening (Before Anything Else)

Hardening is the process of reducing the attack surface by removing unnecessary capabilities and enforcing secure configurations. It must happen before you deploy any detection tool.

### Operating System Hardening

**Windows Hardening Essentials:**
```powershell
# Disable SMBv1 (common ransomware vector)
Set-SmbServerConfiguration -EnableSMB1Protocol $false

# Enable Windows Defender Credential Guard
# (prevents credential theft from lsass memory)
# Enable via Group Policy:
# Computer Configuration > Administrative Templates > System > Device Guard

# Disable PowerShell v2 (lacks security logging)
Disable-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2Root

# Enable PowerShell Script Block Logging
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" `
    -Name "EnableScriptBlockLogging" -Value 1
```

**macOS Hardening Essentials:**
```bash
# Enable FileVault full-disk encryption
fdesetup enable

# Enable Gatekeeper (only signed apps from App Store / identified developers)
spctl --master-enable

# Enable the application firewall
/usr/libexec/ApplicationFirewall/socketfilterfw --setglobalstate on

# Disable remote login unless explicitly needed
systemsetup -setremotelogin off
```

### Application Attack Surface Reduction
- **Remove unused software**: Every installed application is a potential vulnerability. Audit and remove what isn't needed.
- **Disable unused services**: LLMNR, NetBIOS, WinRM, Telnet — disable anything not required.
- **Restrict script interpreters**: Block or restrict PowerShell, WScript, CScript, mshta, certutil for standard users. These are among the most commonly abused LOLBins (Living off the Land Binaries).
- **Browser hardening**: Disable unnecessary extensions, enforce Safe Browsing, block mixed content.

### Local Administrator Account Management
Local admin accounts on endpoints are among the most abused attack paths. Every endpoint should have a unique, randomly generated local admin password managed through **LAPS (Local Administrator Password Solution)**:

```
LAPS Architecture:
  AD / Azure AD  ←──────────────  Rotates password automatically
        │                         (default: every 30 days)
        │
        ▼
  [Endpoint 1]: LocalAdmin PW = "xK9#mPq2"
  [Endpoint 2]: LocalAdmin PW = "rT4@vLn8"
  [Endpoint 3]: LocalAdmin PW = "wZ7!cBs1"
```

Pass-the-hash attacks against lateral movement become ineffective when each machine has a unique local admin password.

## Layer 2: Endpoint Detection and Response (EDR)

Traditional antivirus operates on signatures — it can only detect known, catalogued malware. Modern threat actors use fileless malware, living-off-the-land techniques, and polymorphic code specifically designed to evade signatures.

**EDR** is the next generation. Rather than signature-matching, EDR continuously records all process behavior and correlates events to detect *patterns of attack*.

### What EDR Records and Why It Matters

```
Every moment on a monitored endpoint:
  ├── Process creation (who spawned what, with what arguments)
  ├── Network connections (which process to which IP/port)
  ├── File system changes (what was created, modified, deleted)
  ├── Registry modifications (persistence mechanisms)
  ├── DLL loads (injection detection)
  └── Memory operations (process injection, credential dumping)
```

This telemetry feeds into detection rules that correlate across time and processes — catching attack chains that individual events alone wouldn't reveal.

### Key EDR Capabilities

| Capability | What It Detects |
|:---|:---|
| **Behavioral Analysis** | Unusual process trees (e.g., Word spawning PowerShell) |
| **AMSI Integration** | Malicious script execution in memory |
| **Threat Intelligence Matching** | Known C2 IPs, malicious domains, file hashes |
| **Live Response** | Remote shell into endpoint for incident investigation |
| **Rollback** | Undo ransomware file changes on some platforms |

### Common EDR Platforms

| Platform | Vendor | Key Strength |
|:---|:---|:---|
| CrowdStrike Falcon | CrowdStrike | Cloud-native, fastest detection |
| Microsoft Defender for Endpoint | Microsoft | Deep Windows integration |
| SentinelOne | SentinelOne | Autonomous response, rollback |
| Carbon Black | VMware | Process tree visibility |

## Layer 3: Patch Management

Unpatched vulnerabilities are consistently one of the top initial access vectors in breach reports. **MS08-067**, **EternalBlue (MS17-010)**, **Log4Shell (CVE-2021-44228)** — these are not zero-days. They are known, patched vulnerabilities that organizations failed to remediate in time.

### The Patch Management Lifecycle

```
Vulnerability Published
         │
         ▼
  Vendor Patch Released
         │
         ▼
  Internal Testing (7–14 days for critical)
         │
         ▼
  Staged Rollout (pilot group → broader → all)
         │
         ▼
  Compliance Verification (vulnerability scanner confirms closure)
```

**Severity-based SLAs** define how fast patches must be deployed:

| CVSS Score | Severity | Typical SLA |
|:---|:---|:---|
| 9.0–10.0 | Critical | 24–72 hours (emergency patch) |
| 7.0–8.9 | High | 7–14 days |
| 4.0–6.9 | Medium | 30 days |
| 0.1–3.9 | Low | 90 days |

## Layer 4: Disk Encryption

Full disk encryption ensures that physical theft of an endpoint does not result in data breach. Even if an attacker removes the drive, the data is unreadable without the decryption key.

| Platform | Solution | Key Management |
|:---|:---|:---|
| Windows | BitLocker | Keys escrowed to Azure AD or MBAM |
| macOS | FileVault 2 | Keys escrowed to Jamf / MDM |
| Linux | LUKS | Keys managed via enterprise KMS |

**Critical requirement**: Keys must be escrowed to a central management system. Locally-stored recovery keys defeat the purpose.

## Layer 5: Application Control (Allowlisting)

Rather than blocking known-bad (blocklisting), application control allows only pre-approved software to execute. This fundamentally changes the attacker's equation — they can no longer simply drop a new payload.

**Windows**: Windows Defender Application Control (WDAC) or AppLocker
**macOS**: System Integrity Protection (SIP) + configuration profiles via MDM

```xml
<!-- AppLocker example: block script hosts for standard users -->
<FilePublisherRule Id="..." Action="Deny" UserOrGroupSid="S-1-1-0">
  <Conditions>
    <FilePublisherCondition PublisherName="O=MICROSOFT CORPORATION"
      ProductName="WINDOWS SCRIPT HOST" BinaryName="*"/>
  </Conditions>
</FilePublisherRule>
```

## Hardening Benchmark Standards

Don't reinvent the wheel. Use established benchmarks:

| Standard | Provider | Coverage |
|:---|:---|:---|
| **CIS Benchmarks** | Center for Internet Security | OS, browser, application specific configs |
| **DISA STIGs** | US DoD | Government-grade hardening requirements |
| **NIST SP 800-70** | NIST | National checklist program |

Start with the CIS Benchmark Level 1 for any new endpoint deployment — it provides a sensible baseline without impacting usability.

## The Endpoint Security Maturity Checklist

| Control | Status |
|:---|:---|
| Full-disk encryption enabled (BitLocker / FileVault) | ✓ |
| EDR agent deployed and reporting | ✓ |
| LAPS or equivalent managing local admin passwords | ✓ |
| PowerShell script block logging enabled | ✓ |
| SMBv1 / LLMNR / NetBIOS disabled | ✓ |
| Patch SLAs defined and enforced | ✓ |
| CIS Benchmark Level 1 applied | ✓ |
| Application allowlisting for high-risk roles | ✓ |
| USB/removable media policy enforced | ✓ |
| MFA enforced for all endpoint logins | ✓ |

## Conclusion

Endpoint hardening and protection is not a project with a completion date — it is an ongoing operational commitment. Attackers evolve their techniques continuously, and your endpoint security posture must evolve with them.

The layered approach — hardening first, then detection, then response — ensures that no single control failure leads to a breach. Each layer narrows the attacker's options and increases the likelihood of detection before damage is done.

---

## 엔드포인트 보호와 하드닝: 심층 방어 가이드

조직 내의 모든 노트북, 워크스테이션, 서버, 모바일 기기는 공격자에게 잠재적인 진입점이 된다. 엔드포인트는 사용자, 자격 증명, 데이터에 가장 가까이 위치하기 때문에 기업 환경에서 가장 많이 공격받는 레이어이다. 엔드포인트가 침해되면 공격자는 그곳을 발판(Foothold)으로 삼아 내부 이동(Lateral Movement), 데이터 유출, 권한 상승을 시작한다.

엔드포인트 보안은 단일 도구가 아니다. **심층 방어(Defense-in-Depth)** 전략, 즉 여러 겹의 중첩된 통제 수단을 통해 공격 생명 주기의 모든 단계에서 침해의 확률과 영향을 줄이는 전략이다.

## 공격 표면: 왜 엔드포인트가 주요 표적인가

공격자들이 엔드포인트를 노리는 이유:
- **사용자가 직접 상호작용하는 곳**: 피싱, 악성 다운로드, 소셜 엔지니어링은 모두 엔드포인트 위에서 동작하는 사람을 향한다.
- **자격 증명이 있는 곳**: 브라우저는 자격 증명을 캐시하고, 메모리는 세션 토큰을 보유하며, 키로거는 비밀번호를 탈취한다.
- **네트워크 접근이 있는 곳**: 침해된 엔드포인트는 내부 네트워크 정찰을 위한 교두보가 된다.
- **패치 주기가 느린 곳**: 많은 조직이 OS와 애플리케이션 패치를 수개월 지연하고 있다.

## 1단계: 기본 하드닝 (그 어떤 것보다 먼저)

하드닝은 불필요한 기능을 제거하고 보안 설정을 강제함으로써 공격 표면을 줄이는 과정이다. 탐지 도구를 배포하기 전에 반드시 먼저 수행해야 한다.

**OS 하드닝 핵심 사항:**
- Windows: SMBv1 비활성화(일반적인 랜섬웨어 전파 경로), PowerShell v2 비활성화(보안 로깅 미지원), Credential Guard 활성화(lsass 메모리에서의 자격 증명 탈취 방지)
- macOS: FileVault 전체 디스크 암호화, Gatekeeper 활성화(서명된 앱만 실행), 불필요한 원격 로그인 비활성화

**애플리케이션 공격 표면 축소:**
- 사용하지 않는 소프트웨어 제거: 모든 설치된 애플리케이션은 잠재적 취약점이다.
- 불필요한 서비스 비활성화: LLMNR, NetBIOS, WinRM, Telnet 등
- 스크립트 인터프리터 제한: 일반 사용자에게 PowerShell, WScript, mshta(LOLBins) 접근 차단
- LAPS(Local Administrator Password Solution): 각 엔드포인트에 고유한 로컬 관리자 비밀번호를 자동 순환하여 Pass-the-Hash 공격을 통한 내부 이동을 차단한다.

## 2단계: EDR (엔드포인트 탐지 및 대응)

전통적인 백신은 서명(Signature) 기반으로, 알려진 악성코드만 탐지한다. 현대의 공격자들은 서명 기반 탐지를 우회하기 위해 특별히 설계된 파일리스 악성코드(Fileless Malware)와 자생형 기법(Living-off-the-Land)을 사용한다.

**EDR**은 다음 세대이다. 서명 매칭 대신, EDR은 모든 프로세스 동작을 지속적으로 기록하고 이벤트를 상관 분석하여 *공격의 패턴*을 탐지한다.

EDR이 기록하는 정보:
- 프로세스 생성 (어떤 프로세스가 무엇을 어떤 인자로 실행했는가)
- 네트워크 연결 (어떤 프로세스가 어떤 IP/포트로 연결했는가)
- 파일 시스템 변경 (무엇이 생성, 수정, 삭제되었는가)
- 레지스트리 수정 (지속성 메커니즘 탐지)
- DLL 로드 (인젝션 탐지)
- 메모리 작업 (프로세스 인젝션, 자격 증명 덤핑)

## 3단계: 패치 관리

패치되지 않은 취약점은 침해 보고서에서 지속적으로 상위 초기 접근 벡터 중 하나이다. 심각도 기반 SLA 예시:

| CVSS 점수 | 심각도 | 권장 패치 기한 |
|:---|:---|:---|
| 9.0–10.0 | 치명적 | 24~72시간 (긴급 패치) |
| 7.0–8.9 | 높음 | 7~14일 |
| 4.0–6.9 | 보통 | 30일 |
| 0.1–3.9 | 낮음 | 90일 |

## 4단계: 디스크 암호화

전체 디스크 암호화는 엔드포인트의 물리적 도난이 데이터 유출로 이어지지 않도록 보장한다. 드라이브를 분리하더라도 복호화 키 없이는 데이터를 읽을 수 없다. **핵심 요건**: 복구 키는 반드시 중앙 관리 시스템(Azure AD, Jamf, MDM)에 에스크로(위탁 저장)해야 한다. 로컬에 저장된 복구 키는 암호화의 목적을 무력화한다.

## 5단계: 애플리케이션 제어 (허용 목록)

알려진 악성 소프트웨어를 차단(차단 목록)하는 대신, 사전 승인된 소프트웨어만 실행을 허용한다. 이는 공격자의 계산을 근본적으로 바꾼다. 새로운 페이로드를 드롭하는 것만으로는 더 이상 실행이 불가능해진다.

## 엔드포인트 보안 성숙도 체크리스트

| 통제 항목 | 상태 |
|:---|:---|
| 전체 디스크 암호화 활성화 (BitLocker / FileVault) | ✓ |
| EDR 에이전트 배포 및 보고 중 | ✓ |
| LAPS 또는 동급의 로컬 관리자 비밀번호 관리 | ✓ |
| PowerShell 스크립트 블록 로깅 활성화 | ✓ |
| SMBv1 / LLMNR / NetBIOS 비활성화 | ✓ |
| 심각도별 패치 SLA 정의 및 시행 | ✓ |
| CIS Benchmark Level 1 적용 | ✓ |
| 고위험 역할에 애플리케이션 허용 목록 적용 | ✓ |
| USB/이동식 미디어 정책 시행 | ✓ |
| 모든 엔드포인트 로그인에 MFA 강제 | ✓ |

## 결론

엔드포인트 하드닝과 보호는 완료 날짜가 있는 프로젝트가 아니다. 지속적인 운영상의 헌신이다. 공격자들은 기법을 지속적으로 발전시키며, 엔드포인트 보안 태세도 함께 진화해야 한다.

레이어드 접근법 — 하드닝 먼저, 그 다음 탐지, 그 다음 대응 — 은 단일 통제 실패가 침해로 이어지지 않도록 보장한다. 각 레이어는 공격자의 선택지를 좁히고, 피해가 발생하기 전에 탐지될 확률을 높인다.
