---
title: "Assumed Breach Methodology: Building the Technical Controls"
key: page-assumed_breach_methodology
categories:
- Security
- Security Operations
author: hyoeun
math: false
mathjax_autoNumber: false
image: "/assets/thumbnails/2026-03-27-assumed_breach_methodology.png"
bilingual: true
date: 2026-03-27 09:00:00
---
> **Before you start:** This post is the hands-on technical guide. If you're new to the Assumed Breach concept, read [Assumed Breach: Why Your Firewall Is No Longer Enough](/posts/asumed_breach/) first to understand the philosophy before jumping into implementation.

## From Philosophy to Operations

You've accepted the premise: attackers will get in. Now what?

This guide is for security engineers, SOC analysts, and red/blue team practitioners who need to translate the Assumed Breach philosophy into concrete technical controls. We cover four operational stages — lateral movement detection, detection engineering, network segmentation, and adversary simulation — followed by how to build a complete program and the gotchas that kill these programs in practice.

## Stage 1: Understand How Attackers Move After Initial Access

Before you can detect lateral movement, you need to understand exactly what it looks like. After landing on a beachhead host, an attacker's immediate goal is to move from that host to a higher-value target: a domain controller, a database server, a code signing system.

The lateral movement toolkit is almost entirely credential-based:

| Technique | What It Does | Event to Detect |
|---|---|---|
| **Pass-the-Hash (PtH)** | Reuses NTLM hash without cracking | EventID 4624, LogonType 3, Auth: NTLM |
| **Pass-the-Ticket (PtT)** | Abuses stolen Kerberos tickets | EventID 4768/4769, unusual TGT/TGS |
| **Kerberoasting** | Cracks service account passwords offline | EventID 4769, RC4 encryption type |
| **DCSync** | Dumps all AD credentials remotely | EventID 4662, `Replicating Directory Changes` |
| **PSExec / WMI / DCOM** | Remote execution via LOLBins | EventID 7045 (service install), 4688 (process) |
| **Golden Ticket** | Forged TGT using KRBTGT hash | EventID 4769, tickets with 10-year lifetimes |

The critical insight: **detect behaviors, not tools**. Attackers swap tools constantly. The underlying Windows API calls and authentication events stay consistent. Build your detections on those.

## Stage 2: Detection Engineering for Post-Compromise Behavior

### 2-1. Credential Abuse Detection

**Pass-the-Hash indicator:**
```yaml
# Sigma rule — detect Pass-the-Hash lateral movement
title: Lateral Movement via NTLM Pass-the-Hash
status: experimental
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 4624
    LogonType: 3
    AuthenticationPackageName: NTLM
    SubjectUserSid: 'S-1-5-18'
  filter:
    TargetUserName|endswith: '$'  # Exclude machine accounts
  condition: selection and not filter
falsepositives:
  - Legitimate service accounts using NTLM — enumerate and allowlist
level: high
tags:
  - attack.lateral_movement
  - attack.t1550.002
```

**Kerberoasting detection:**
```yaml
title: Kerberoasting — RC4 Downgrade Attack
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 4769
    TicketEncryptionType: '0x17'  # RC4 — weak, preferred by Kerberoasting tools
    ServiceName|endswith: '$'
  condition: selection
level: high
tags:
  - attack.credential_access
  - attack.t1558.003
```

### 2-2. Abnormal Process Execution (LOLBin Abuse)

One of the most common red team techniques is spawning shells from Office apps or browsers — processes that should never create command-line children.

```python
# Detection logic pseudocode — LOLBin parent-child abuse
suspicious_parents = [
    "winword.exe", "excel.exe", "powerpnt.exe",
    "outlook.exe", "chrome.exe", "firefox.exe", "msedge.exe"
]
suspicious_children = [
    "cmd.exe", "powershell.exe", "wscript.exe",
    "cscript.exe", "mshta.exe", "regsvr32.exe"
]

if process.parent_name in suspicious_parents:
    if process.name in suspicious_children:
        create_alert(
            severity="HIGH",
            tactic="Execution",
            technique="T1059",
            message=f"{process.parent_name} spawned {process.name}"
        )
```

### 2-3. Impossible Access / Anomalous Credential Use

Valid credentials behaving abnormally is the hardest pattern for signature-based tools to catch — and the most important one to detect in an assumed breach model.

```python
def detect_anomalous_access(user, resource, timestamp, source_ip):
    baseline = get_access_baseline(user, lookback_days=90)
    signals = []

    # Never-before-accessed sensitive resource
    if resource not in baseline.resources and resource.sensitivity == "HIGH":
        signals.append("first_access_to_sensitive_resource")

    # Unusual hours (based on per-user baseline, not generic 9-5)
    if timestamp.hour not in baseline.active_hours:
        signals.append("off_hours_access")

    # New source IP (not in baseline)
    if source_ip not in baseline.known_ips:
        signals.append("new_source_ip")

    # Alert if 2+ signals — single signals have too many false positives
    if len(signals) >= 2:
        create_alert(severity="MEDIUM", signals=signals, user=user)
```

> **Key principle:** Single anomaly signals generate too many false positives. Combine 2+ weak signals for higher-fidelity alerts.

## Stage 3: Network Segmentation That Actually Stops Lateral Movement

Segmentation in an Assumed Breach model is not about VLANs on a diagram. It's about enforceable controls that stop credential-based lateral movement in practice.

### 3-1. Core Segmentation Rules

| Control | What It Prevents | Implementation |
|---|---|---|
| Block workstation-to-workstation SMB | Direct PtH/lateral movement | Windows Firewall GPO |
| Restrict DC access to PAWs only | Credential dumping from endpoints | AD tier model + firewall |
| Service accounts: network-restrict to single service | Abuse of over-privileged accounts | Firewall + AD attribute |
| Credentials never shared across tiers | Tier-0 creds not usable from Tier-1 hosts | LAPS + credential tiering |

### 3-2. Workstation Lateral Movement Prevention (GPO)

```bash
# Block workstation-to-workstation SMB — deploy via Group Policy
netsh advfirewall firewall add rule `
  name="Block Lateral SMB" `
  dir=in `
  protocol=TCP `
  localport=445 `
  remoteip=192.168.10.0/24 `
  action=block

# Also block WMI lateral movement
netsh advfirewall firewall add rule `
  name="Block Lateral WMI" `
  dir=in `
  protocol=TCP `
  localport=135 `
  remoteip=192.168.10.0/24 `
  action=block
```

### 3-3. AD Credential Tiering Model

The most effective AD control against lateral movement is tier separation. Credentials used at one tier cannot authenticate at another:

```
Tier 0 (Crown Jewels)
├── Domain Controllers
├── ADFS servers
├── PKI/CA infrastructure
└── Admin accounts: ONLY usable from Tier-0 PAWs

Tier 1 (Servers)
├── File servers, app servers, DB servers
└── Admin accounts: ONLY usable from Tier-1 admin workstations

Tier 2 (Endpoints)
├── User workstations, laptops
└── Regular accounts: blocked from Tier 0/1 admin functions
```

If credentials are stolen from a Tier-2 endpoint, they're useless against Tier-0 systems. This doesn't prevent the breach — it prevents the attacker from reaching the crown jewels.

## Stage 4: Adversary Simulation to Validate Your Controls

The only honest way to know if your controls work is to test them under realistic conditions.

### 4-1. Purple Team Exercises

Red team executes specific ATT&CK techniques. Blue team confirms detection in real time. The goal is collaborative — find gaps together, not score points.

**Sample purple team flow:**
1. Red team runs `Invoke-AtomicTest T1003.001` (LSASS credential dump)
2. Blue team watches SIEM for expected alert within 5 minutes
3. If alert fires: document the rule, confirm fidelity, move to next technique
4. If alert doesn't fire: write the detection rule together, then re-test

```bash
# Atomic Red Team — run specific ATT&CK technique to test detection
Invoke-AtomicTest T1003.001  # LSASS credential dump
Invoke-AtomicTest T1550.002  # Pass-the-Hash
Invoke-AtomicTest T1558.003  # Kerberoasting

# Always: run in isolated lab first, confirm blast radius is contained
# Always: have blue team watching live during execution
```

### 4-2. Breach and Attack Simulation (BAS)

Automated tools continuously run attack scenarios and report detection coverage over time.

| Tool | Type | Best For |
|---|---|---|
| Atomic Red Team | Open source | Technique-level testing, purple team |
| Caldera (MITRE) | Open source | Automated adversary emulation |
| AttackIQ | Commercial | Continuous BAS, executive reporting |
| Cymulate | Commercial | Full kill-chain simulation |
| SafeBreach | Commercial | Large-scale continuous validation |

## Building an Assumed Breach Program: Three Workstreams

### Workstream 1: Map Your Detection Coverage

Before building new detections, know what you have. Map every existing SIEM rule to an ATT&CK technique. The unmapped techniques are your risk exposure.

```python
# ATT&CK coverage gap analysis
attack_techniques = load_attack_matrix()
current_detections = load_siem_rules()

coverage = {}
for technique in attack_techniques:
    matched_rules = [r for r in current_detections if technique.id in r.tags]
    coverage[technique.id] = {
        "name": technique.name,
        "tactic": technique.tactic,
        "covered": len(matched_rules) > 0,
        "rule_count": len(matched_rules)
    }

uncovered = [t for t, v in coverage.items() if not v["covered"]]
print(f"Coverage: {len(attack_techniques) - len(uncovered)}/{len(attack_techniques)} techniques")
print(f"Gaps: {len(uncovered)} techniques with no detection")
```

Use ATT&CK Navigator to visualize this as a heatmap. Share it with leadership — it's the most concrete picture of your detection risk.

### Workstream 2: Prioritize by Crown Jewel Reachability

Not every ATT&CK technique is equally dangerous in your environment. Build detections in order of: *what techniques get attackers to your most critical assets fastest?*

1. Map your crown jewels (AD, production DB, code signing, financial systems)
2. For each crown jewel, trace the ATT&CK techniques that reach it from a standard user endpoint
3. Confirm detection coverage for that specific attack path
4. Gaps in that path are Priority 1

### Workstream 3: Drill Incident Response Post-Compromise

Run tabletop exercises that start *after* initial access. Not "attackers are at the gate" — "attackers are already inside." Realistic scenarios:

- *"LSASS access detected on finance-workstation-07. Alert is 4 hours old. The attacker may have lateral moved. What's the playbook?"*
- *"Domain Admin account logged in at 2:17am from an IP not in baseline. How do we investigate without tipping off the attacker or disrupting production?"*
- *"BloodHound shows a path from compromised helpdesk account to Domain Admin in 3 hops. Do we remediate now or monitor?"*

## Quick Reference

### Detection Priority (Post-Initial Access)

```
Priority 1 — Detect within minutes:
  - LSASS credential dumping (T1003.001)
  - DCSync attack (T1003.006)
  - Kerberoasting (T1558.003)
  - Golden/Silver Ticket creation (T1558.001/002)

Priority 2 — Detect within hours:
  - Pass-the-Hash / Pass-the-Ticket (T1550.002/003)
  - Lateral movement via WMI/PSExec/RDP (T1021)
  - Unusual service account network activity

Priority 3 — Detect within a day:
  - Persistence mechanisms (T1053, T1547)
  - Internal reconnaissance — LDAP queries, port scans (T1018, T1049)
  - Data staging (T1074)
```

### Key Tools

| Phase | Tool | Purpose |
|---|---|---|
| Simulation | Atomic Red Team | Technique-level adversary simulation |
| Simulation | Caldera (MITRE) | Automated adversary emulation |
| BAS | AttackIQ / Cymulate | Continuous coverage validation |
| Detection | Sigma | Vendor-agnostic detection rule format |
| Coverage | ATT&CK Navigator | Visualize detection coverage gaps |
| Identity | BloodHound | Map AD attack paths before attackers do |

## Common Failure Modes

**Alert fatigue kills assumed breach programs.**
Teams deploy EDR at maximum sensitivity, drown in 10,000 alerts/day, and start ignoring them. The real lateral movement alert gets buried. Fix: optimize for precision first. A 90% precision rate on 100 alerts beats 50% precision on 10,000. Alert volume is an engineering problem, not a security problem.

**"We have EDR" is not assumed breach.**
EDR is one detection layer. You need detection at: network (east-west traffic), identity (auth events), endpoint (process behavior), and data (DLP, access patterns). Attackers test against your specific EDR and know your blind spots better than you do.

**Segmentation on paper vs. in practice.**
The firewall rule says workstation-to-workstation SMB is blocked. SOC investigates a lateral movement alert and finds the rule only applied to new VLANs — the legacy segment is still flat. Test your segmentation with actual lateral movement simulations quarterly.

**Dwell time is a lagging indicator.**
Teams celebrate "we reduced dwell time from 73 to 14 days." That's good, but it measures how long attackers were in *after* a breach. What matters are the leading indicators: detection *coverage* (do you have rules for the techniques they used?) and *speed* (how fast did the right alert surface?). Optimize the leading indicators.

---

> **시작 전:** 이 글은 실무 기술 가이드입니다. Assumed Breach 개념을 처음 접하신다면, 먼저 [Assumed Breach: 방어선이 더 이상 충분하지 않은 이유](/posts/asumed_breach/)를 읽고 개념을 이해한 후 구현에 들어오시길 권장합니다.

## 철학에서 운영으로

공격자가 침투할 것이라는 전제를 받아들였다. 이제 무엇을 해야 하는가?

이 가이드는 Assumed Breach 철학을 구체적인 기술 통제로 전환해야 하는 보안 엔지니어, SOC 분석가, 레드/블루팀 실무자를 위한 것이다.

## 1단계: 공격자가 초기 접근 후 어떻게 이동하는지 이해하라

측면 이동을 탐지하기 전에, 그것이 어떻게 보이는지를 정확히 이해해야 한다. 공격자의 측면 이동 도구는 거의 항상 자격증명 기반이다:

| 기법 | 하는 일 | 탐지할 이벤트 |
|---|---|---|
| **Pass-the-Hash** | NTLM 해시를 크래킹 없이 재사용 | EventID 4624, LogonType 3, Auth: NTLM |
| **Pass-the-Ticket** | 탈취한 Kerberos 티켓 남용 | EventID 4768/4769 |
| **Kerberoasting** | 서비스 계정 비밀번호 오프라인 크래킹 | EventID 4769, RC4 암호화 타입 |
| **DCSync** | 모든 AD 자격증명을 원격으로 덤프 | EventID 4662 |
| **PSExec / WMI** | LOLBin을 통한 원격 실행 | EventID 7045, 4688 |

핵심 인사이트: **도구가 아닌 행위를 탐지하라.** 공격자는 도구를 자주 바꾼다. 기저의 Windows API 호출과 인증 이벤트는 일정하게 유지된다.

## 2단계: 침해 후 행위 기반 탐지 엔지니어링

### 자격증명 남용 탐지 (Sigma 규칙)

```yaml
title: NTLM Pass-the-Hash를 통한 측면 이동
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 4624
    LogonType: 3
    AuthenticationPackageName: NTLM
    SubjectUserSid: 'S-1-5-18'
  filter:
    TargetUserName|endswith: '$'
  condition: selection and not filter
level: high
tags:
  - attack.lateral_movement
  - attack.t1550.002
```

### 비정상 프로세스 실행 탐지

```python
suspicious_parents = ["winword.exe", "excel.exe", "outlook.exe", "chrome.exe"]
suspicious_children = ["cmd.exe", "powershell.exe", "wscript.exe", "mshta.exe"]

if process.parent_name in suspicious_parents:
    if process.name in suspicious_children:
        create_alert(severity="HIGH", tactic="실행", technique="T1059")
```

### 비정상 접근 탐지

```python
def detect_anomalous_access(user, resource, timestamp, source_ip):
    baseline = get_access_baseline(user, lookback_days=90)
    signals = []

    if resource not in baseline.resources and resource.sensitivity == "HIGH":
        signals.append("민감 리소스 최초 접근")
    if timestamp.hour not in baseline.active_hours:
        signals.append("비정상 시간대 접근")
    if source_ip not in baseline.known_ips:
        signals.append("새로운 소스 IP")

    # 단일 신호는 오탐이 많음 — 2개 이상 조합 시 알람
    if len(signals) >= 2:
        create_alert(severity="MEDIUM", signals=signals)
```

## 3단계: 실제로 측면 이동을 막는 네트워크 세분화

### 워크스테이션 측면 이동 차단 (GPO)

```bash
# 워크스테이션 간 SMB 차단 — GPO로 배포
netsh advfirewall firewall add rule `
  name="Block Lateral SMB" `
  dir=in `
  protocol=TCP `
  localport=445 `
  remoteip=192.168.10.0/24 `
  action=block

# WMI 측면 이동도 차단
netsh advfirewall firewall add rule `
  name="Block Lateral WMI" `
  dir=in `
  protocol=TCP `
  localport=135 `
  remoteip=192.168.10.0/24 `
  action=block
```

### AD 자격증명 계층화 모델

```
Tier 0 (핵심 자산): 도메인 컨트롤러, PKI — Tier-0 PAW에서만 접근 가능
Tier 1 (서버): 파일/앱/DB 서버 — Tier-1 관리 워크스테이션에서만 접근 가능
Tier 2 (엔드포인트): 사용자 워크스테이션 — Tier 0/1 관리 기능 차단
```

Tier-2 엔드포인트에서 자격증명이 탈취되어도 Tier-0 시스템에는 쓸모없다.

## 4단계: 적 시뮬레이션으로 통제 검증

### 퍼플팀 연습 흐름

1. 레드팀이 특정 ATT&CK 기법 실행
2. 블루팀이 5분 내 SIEM 알람 확인
3. 알람 발생 시: 규칙 문서화 후 다음 기법으로
4. 알람 미발생 시: 함께 탐지 규칙 작성 후 재테스트

```bash
Invoke-AtomicTest T1003.001  # LSASS 자격증명 덤핑
Invoke-AtomicTest T1550.002  # Pass-the-Hash
Invoke-AtomicTest T1558.003  # Kerberoasting

# 항상: 먼저 격리된 랩 환경에서 실행
# 항상: 블루팀이 라이브로 모니터링 중인 상태에서 실행
```

## 탐지 우선순위 빠른 참조

```
우선순위 1 (분 단위 탐지):
  - LSASS 자격증명 덤핑 (T1003.001)
  - DCSync 공격 (T1003.006)
  - Kerberoasting (T1558.003)

우선순위 2 (시간 단위 탐지):
  - Pass-the-Hash / Pass-the-Ticket (T1550)
  - WMI/PSExec/RDP를 통한 측면 이동 (T1021)
  - 비정상 서비스 계정 활동

우선순위 3 (일 단위 탐지):
  - 지속성 메커니즘 (T1053, T1547)
  - 내부 정찰 — LDAP 쿼리, 네트워크 스캐닝
  - 데이터 준비 행위 (T1074)
```

## 현장에서 배운 실패 패턴

**알람 피로가 프로그램을 죽인다.** EDR 최대 민감도로 하루 10,000개 알람이 쏟아지면 팀은 무시하기 시작한다. 정밀도 90%에 100개 알람이 정밀도 50%에 10,000개보다 낫다. 알람 볼륨은 보안 문제가 아닌 엔지니어링 문제다.

**"EDR 있잖아요"는 Assumed Breach가 아니다.** 네트워크(동-서 트래픽), 신원(인증 이벤트), 엔드포인트, 데이터 — 다중 레이어 탐지가 필요하다. 공격자는 당신의 EDR을 미리 테스트하고 당신보다 맹점을 더 잘 안다.

**문서상 세분화 vs. 실제 세분화.** 방화벽 규칙이 레거시 세그먼트에 적용되지 않은 경우가 많다. 분기별로 실제 측면 이동 시뮬레이션으로 세분화를 테스트하라.

**체류 시간은 후행 지표다.** "73일에서 14일로 줄었다"는 좋지만 결과를 측정하는 것이다. 탐지 커버리지(몇 %의 ATT&CK 기법이 탐지되는가?)와 탐지 속도(올바른 알람이 얼마나 빨리 뜨는가?)가 진짜 선행 지표다.
