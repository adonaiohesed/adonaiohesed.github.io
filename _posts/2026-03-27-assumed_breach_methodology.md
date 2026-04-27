---
title: Assumed Breach Methodology
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

## The Perimeter Is Already Gone

Your firewall didn't fail. Your EDR didn't miss anything. Your SIEM is humming along. And the attacker has been sitting in your environment for 73 days — the industry median dwell time before detection. They're not at the gate anymore. They're in your Active Directory, they've mapped your network, and they're waiting for the right moment.

**Assumed Breach** is the operational posture that starts from this reality and builds backward. Instead of designing defenses around keeping attackers out, you design them around the question: *When they're in — not if — how quickly do we detect, contain, and eject them?* This mindset shift changes everything from how you architect internal networks to how you write detection rules to what you practice in tabletop exercises.

## What Assumed Breach Actually Means

Assumed breach is not pessimism. It's a design philosophy — the security equivalent of building with earthquake codes in a seismic zone.

The traditional model is **perimeter-focused**: strong outer defenses (firewall, WAF, VPN), with implicit trust inside the network. Once you're in, you're trusted. This model broke completely when:
- Remote work dissolved the network perimeter
- Cloud expanded blast radius beyond any single firewall
- Supply chain attacks (SolarWinds, 3CX) proved that trusted software can be the vector
- Credential phishing bypasses perimeter controls entirely

**Assumed breach flips the trust model**: every user, device, and service is treated as potentially compromised, regardless of where it sits in the network. You build controls and detection that are effective *after* initial access — which is a fundamentally different design target than prevention.

The three operational pillars:

| Pillar | Question It Answers | If You Get It Wrong |
|---|---|---|
| **Segmentation** | How far can they move laterally? | Full network compromise from one endpoint |
| **Detection** | How fast do we see them? | 73+ day dwell time |
| **Response** | How fast can we eject them? | Attacker achieves objective before you act |

## How It Works: The Assumed Breach Lifecycle

### Stage 1: Lateral Movement Is the Kill Zone

After initial access, attackers need to move from their beachhead to their target (crown jewels, AD, financial data). This movement phase is where assumed breach defenders focus most of their detection energy — because prevention already failed.

The attacker's lateral movement toolkit is almost always credential-based:
- **Pass-the-Hash (PtH)**: Reuse NTLM hashes without cracking
- **Pass-the-Ticket (PtT)**: Abuse Kerberos tickets (Golden/Silver Ticket attacks)
- **DCOM / WMI / PSExec**: LOLBin (Living Off the Land) remote execution
- **RDP**: Stolen credentials + open port

Your detection must catch these behaviors, not the tools themselves (tools change; behaviors don't).

### Stage 2: Detection Engineering for Post-Compromise Behavior

Detection in an assumed breach model is behavioral and anomaly-based, not purely signature-based. Key detection categories:

**Credential abuse:**
```yaml
# Sigma rule concept — detect Pass-the-Hash indicators
title: Lateral Movement via NTLM Pass-the-Hash
detection:
  selection:
    EventID: 4624
    LogonType: 3
    AuthPackage: NTLM
    SubjectUserSid: S-1-5-18  # SYSTEM
  condition: selection
falsepositives:
  - Legitimate service accounts using NTLM (enumerate and allowlist)
```

**Abnormal admin tool usage:**
```python
# Detection logic pseudocode for LOLBin abuse
suspicious_parents = ["word.exe", "excel.exe", "outlook.exe", "chrome.exe"]
suspicious_children = ["cmd.exe", "powershell.exe", "wscript.exe", "mshta.exe"]

if process.parent in suspicious_parents and process.name in suspicious_children:
    alert(severity="HIGH", tactic="Execution", technique="T1059")
```

**Impossible travel / impossible access:**
```python
# Flag accounts accessing resources they've never touched
def is_anomalous_access(user, resource, timestamp):
    baseline = get_access_baseline(user, days=90)
    if resource not in baseline.resources:
        if resource.sensitivity == "HIGH":
            return True
    return False
```

### Stage 3: Segmentation Limits Blast Radius

Network segmentation under assumed breach is not about VLANs — it's about **micro-segmentation** and **least-privilege network access**:

- Workstations should not be able to reach each other directly (peer-to-peer lateral movement prevention)
- Service accounts should have network access only to the services they need
- Domain Controllers should only accept connections from specific admin workstations (Privileged Access Workstations / PAWs)
- Credentials used on internet-exposed systems should never work on internal systems

```bash
# Windows Firewall rule to block workstation-to-workstation SMB (lateral movement prevention)
# Deploy via GPO
netsh advfirewall firewall add rule `
  name="Block Lateral SMB" `
  dir=in `
  protocol=TCP `
  localport=445 `
  remoteip=192.168.10.0/24 `
  action=block
```

### Stage 4: Adversary Simulation to Validate Your Assumptions

The only honest way to know if your assumed breach controls work is to test them with simulated breach scenarios. Two approaches:

**Purple Team Exercises**: Red team performs specific ATT&CK techniques; blue team confirms detection in real time. Collaborative, not adversarial. Goal is to close detection gaps together.

**Breach and Attack Simulation (BAS)**: Automated tools (Cymulate, AttackIQ, SafeBreach) continuously run attack scenarios and report on detection coverage. Gives you coverage metrics over time.

```bash
# Atomic Red Team — run a specific ATT&CK technique to test detection
# T1003.001: OS Credential Dumping - LSASS Memory
Invoke-AtomicTest T1003.001

# Verify your SIEM/EDR caught it before running in production
# Always run in an isolated lab environment first
```

## Practical Application: Building an Assumed Breach Program

Moving from philosophy to operational program requires three concrete workstreams:

### 1. Establish Your Detection Baseline

Run a coverage assessment against MITRE ATT&CK before anything else. Map every detection rule you have to an ATT&CK technique. The gaps are your risk:

```python
# ATT&CK coverage matrix concept
attack_techniques = load_attack_matrix()
current_detections = load_siem_rules()

coverage = {}
for technique in attack_techniques:
    matched = [r for r in current_detections if technique.id in r.tags]
    coverage[technique.id] = {
        "name": technique.name,
        "covered": len(matched) > 0,
        "rule_count": len(matched),
        "tactic": technique.tactic
    }

uncovered = [t for t in coverage if not coverage[t]["covered"]]
print(f"Uncovered techniques: {len(uncovered)}/{len(attack_techniques)}")
```

### 2. Prioritize by Blast Radius

Not every ATT&CK technique is equally dangerous in your environment. Prioritize detection development based on what attackers would do in *your* environment to reach *your* crown jewels:

- Map your crown jewels (AD, production databases, code signing infra, financial systems)
- Identify the ATT&CK techniques most commonly used to reach those targets
- Build detections for those techniques first

### 3. Practice Incident Response Under Assumed Breach Conditions

Run tabletop exercises that start *after* initial access — not with "attackers are at the gate." Scenarios like:

- "We've detected suspicious LSASS access on a workstation. The alert is 4 hours old. What's the playbook?"
- "An account with Domain Admin privileges logged in at 2am from an unusual host. How do we investigate without tipping off the attacker?"

## Gotchas: What Assumed Breach Gets Wrong in Practice

**Alert fatigue is the assumed breach killer.** Teams implement EDR, tune it to maximum sensitivity, drown in 10,000 alerts a day, and start ignoring them. One real lateral movement alert gets buried. The fix: tune for precision first, recall second. A 90% precision rate on 100 alerts beats 50% precision on 10,000. Alert volume is an engineering problem, not a security problem.

**"We have an EDR" is not assumed breach.** EDR is one detection layer. Assumed breach requires detection at multiple layers: network (east-west traffic), identity (auth events), endpoint (process behavior), and data (DLP, access patterns). Attackers test against your specific EDR. They know your blind spots better than you do.

**Segmentation on paper vs. in practice.** The firewall rule says workstation-to-workstation SMB is blocked. The SOC responds to a lateral movement alert and finds the rule was only applied to the new VLANs — the legacy segment is still flat. Test your segmentation with actual lateral movement simulations quarterly.

**Assumed breach doesn't mean "don't prevent."** Prevention and detection are not in competition. Reduce your attack surface (patch, disable legacy protocols, enforce MFA) and simultaneously build detection-in-depth. Prevention reduces the number of attacker entry points; assumed breach handles the ones that got through anyway.

**Dwell time is not a detection metric.** Teams celebrate "we reduced dwell time from 73 to 14 days." That's great, but dwell time measures how long they were in after a breach. What matters is your detection *coverage* (do you have rules for the technique they used?) and *speed* (how fast did the right alert surface?). Optimize the leading indicators, not the lagging one.

## Quick Reference

### Core Assumed Breach Controls

| Control | Purpose | Key Metric |
|---|---|---|
| Micro-segmentation | Limit lateral movement radius | % of east-west traffic with allow-list rules |
| Privileged Access Workstations (PAW) | Isolate admin credentials | % of admin tasks performed from PAW |
| Credential tiering | Prevent credential reuse across tiers | % of accounts with tier-appropriate scope |
| EDR behavioral detection | Post-compromise endpoint visibility | Mean time to alert (MTTA) on test techniques |
| Identity anomaly detection | Catch credential abuse | Alert rate on impossible access patterns |
| Purple team cadence | Validate detection coverage | ATT&CK technique coverage % per quarter |

### Detection Priority by Tactic (Post-Initial Access)

```
Priority 1 (Detect within minutes):
  - Credential dumping (LSASS, SAM, NTDS)
  - DCSync attacks
  - Kerberoasting

Priority 2 (Detect within hours):
  - Lateral movement via WMI/PSExec/RDP
  - Unusual service account activity
  - Pass-the-Hash / Pass-the-Ticket

Priority 3 (Detect within a day):
  - Persistence mechanisms (scheduled tasks, registry run keys)
  - Internal reconnaissance (LDAP queries, network scanning)
  - Data staging behaviors
```

### Key Tools for Assumed Breach Programs

| Phase | Tool | Purpose |
|---|---|---|
| Simulation | Atomic Red Team | Technique-level adversary simulation |
| Simulation | Caldera (MITRE) | Automated adversary emulation |
| BAS | AttackIQ / Cymulate | Continuous coverage validation |
| Detection | Sigma | Vendor-agnostic detection rule format |
| Coverage | ATT&CK Navigator | Visualize detection coverage gaps |
| Identity | BloodHound | Map AD attack paths before attackers do |

---

## 이미 뚫렸다는 가정에서 시작하라

방화벽도 정상이고, EDR도 돌아가고, SIEM도 잘 작동한다. 그런데 공격자는 이미 73일째 네트워크 안에서 머물고 있다. 이게 업계 탐지 전 평균 체류 시간이다. 이들은 이미 Active Directory를 장악했고, 내부 네트워크 지도를 완성했으며, 적절한 순간을 기다리고 있다.

**Assumed Breach(침해 가정 방법론)** 는 이 현실에서 출발하는 운영 철학이다. 공격자를 막는 것이 아니라, "이미 들어왔다면 얼마나 빨리 탐지하고, 격리하고, 제거할 수 있는가?"라는 질문에 답하도록 보안을 설계하는 것이다.

## Assumed Breach란 무엇인가

이 방법론은 비관주의가 아니라 설계 철학이다. 지진 발생 지역에서 내진 설계로 건물을 짓는 것과 같다.

전통적인 **경계 중심 모델**은 강력한 외부 방어(방화벽, WAF, VPN)를 구축하고, 내부 네트워크는 묵시적으로 신뢰한다. 이 모델이 완전히 무너진 이유:
- 재택근무로 네트워크 경계가 사라짐
- 클라우드 확산으로 단일 방화벽의 보호 범위 초과
- 소프트웨어 공급망 공격(SolarWinds, 3CX)이 신뢰할 수 있는 소프트웨어도 벡터가 될 수 있음을 증명
- 자격증명 피싱은 경계 방어를 완전히 우회

**Assumed Breach는 신뢰 모델을 뒤집는다**: 모든 사용자, 기기, 서비스는 위치에 상관없이 잠재적으로 침해된 것으로 간주한다.

세 가지 운영 기둥:

| 기둥 | 답해야 할 질문 | 실패 시 결과 |
|---|---|---|
| **세분화(Segmentation)** | 얼마나 멀리 이동할 수 있는가? | 엔드포인트 하나로 전체 네트워크 침해 |
| **탐지(Detection)** | 얼마나 빨리 발견하는가? | 73일 이상 체류 |
| **대응(Response)** | 얼마나 빨리 제거하는가? | 목표 달성 전에 대응 불가 |

## 작동 방식: Assumed Breach 생명주기

### 1단계: 측면 이동이 핵심 전장

초기 접근 후 공격자는 교두보에서 목표(핵심 자산, AD, 금융 데이터)로 이동해야 한다. 이 이동 단계가 탐지 에너지를 집중해야 할 곳이다.

측면 이동 도구는 거의 항상 자격증명 기반이다:
- **Pass-the-Hash(PtH)**: NTLM 해시를 크래킹 없이 재사용
- **Pass-the-Ticket(PtT)**: Kerberos 티켓 남용 (Golden/Silver Ticket)
- **DCOM / WMI / PSExec**: LOLBin(자생 도구) 원격 실행
- **RDP**: 탈취한 자격증명 + 열린 포트

탐지는 도구가 아닌 행위를 잡아야 한다. 도구는 바뀌지만 행위는 바뀌지 않는다.

### 2단계: 침해 후 행위 기반 탐지 엔지니어링

Assumed Breach 환경의 탐지는 시그니처 기반이 아닌 행위 및 이상 기반이다.

**자격증명 남용 탐지:**
```yaml
# Sigma 규칙 개념 — Pass-the-Hash 지표 탐지
title: NTLM Pass-the-Hash를 통한 측면 이동
detection:
  selection:
    EventID: 4624
    LogonType: 3
    AuthPackage: NTLM
    SubjectUserSid: S-1-5-18  # SYSTEM
  condition: selection
falsepositives:
  - NTLM을 사용하는 정상 서비스 계정 (열거 후 허용 목록 등록)
```

**비정상 관리 도구 사용:**
```python
# LOLBin 남용 탐지 로직 의사코드
suspicious_parents = ["word.exe", "excel.exe", "outlook.exe", "chrome.exe"]
suspicious_children = ["cmd.exe", "powershell.exe", "wscript.exe", "mshta.exe"]

if process.parent in suspicious_parents and process.name in suspicious_children:
    alert(severity="HIGH", tactic="실행", technique="T1059")
```

### 3단계: 세분화로 피해 범위 제한

Assumed Breach에서 네트워크 세분화는 VLAN이 아닌 **마이크로 세분화**와 **최소 권한 네트워크 접근**을 의미한다:

- 워크스테이션 간 직접 통신 차단 (P2P 측면 이동 방지)
- 서비스 계정은 필요한 서비스에만 네트워크 접근 허용
- DC(도메인 컨트롤러)는 특권 접근 워크스테이션(PAW)에서만 연결 허용
- 인터넷 노출 시스템의 자격증명은 내부 시스템에서 절대 사용 불가

```bash
# 워크스테이션 간 SMB 차단 (측면 이동 방지) — GPO로 배포
# Windows Firewall 규칙
netsh advfirewall firewall add rule `
  name="Block Lateral SMB" `
  dir=in `
  protocol=TCP `
  localport=445 `
  remoteip=192.168.10.0/24 `
  action=block
```

### 4단계: 적 시뮬레이션으로 가정 검증

Assumed Breach 통제가 실제로 작동하는지 확인하는 유일한 정직한 방법은 시뮬레이션이다.

**퍼플팀 연습**: 레드팀이 특정 ATT&CK 기법을 수행하고, 블루팀이 실시간으로 탐지를 확인한다. 협력적 접근이며 목표는 함께 탐지 공백을 메우는 것이다.

**침해 및 공격 시뮬레이션(BAS)**: Cymulate, AttackIQ, SafeBreach 같은 자동화 도구가 지속적으로 공격 시나리오를 실행하고 탐지 커버리지를 보고한다.

```bash
# Atomic Red Team — 특정 ATT&CK 기법 테스트
# T1003.001: 자격증명 덤핑 - LSASS 메모리
Invoke-AtomicTest T1003.001

# 운영 환경 실행 전 반드시 격리된 랩 환경에서 먼저 검증
```

## 실제 적용: Assumed Breach 프로그램 구축

### 1. 탐지 기준선 수립

먼저 현재 탐지 규칙을 MITRE ATT&CK에 매핑해 커버리지를 평가한다. 빈 곳이 곧 리스크다.

```python
# ATT&CK 커버리지 매트릭스 개념
attack_techniques = load_attack_matrix()
current_detections = load_siem_rules()

uncovered = [t for t in attack_techniques
             if not any(t.id in r.tags for r in current_detections)]
print(f"커버되지 않은 기법: {len(uncovered)}/{len(attack_techniques)}")
```

### 2. 피해 범위 기준 우선순위 설정

핵심 자산에 도달하는 데 가장 많이 사용되는 ATT&CK 기법을 먼저 탐지한다:
- 핵심 자산 식별 (AD, 운영 DB, 코드 서명 인프라, 금융 시스템)
- 해당 자산에 도달하는 기법 매핑
- 해당 기법 탐지 먼저 개발

### 3. 침해 후 조건에서 사고 대응 훈련

"공격자가 문 앞에 있다"가 아닌 초기 접근 이후부터 시작하는 탁상 훈련:
- "워크스테이션에서 의심스러운 LSASS 접근이 탐지됐다. 알람은 4시간 전에 발생했다. 플레이북은?"
- "도메인 어드민 권한 계정이 새벽 2시에 비정상 호스트에서 로그인했다. 공격자에게 들키지 않고 어떻게 조사하나?"

## 전문가가 현장에서 배운 것들

**알람 피로가 Assumed Breach를 죽인다.** EDR을 최대 민감도로 설정해 하루 10,000개 알람이 쏟아지면, 팀은 이를 무시하기 시작한다. 그 속에서 실제 측면 이동 알람 하나가 묻힌다. 해결책: 재현율보다 정밀도를 먼저 최적화하라. 정밀도 90%에 알람 100개가, 정밀도 50%에 알람 10,000개보다 낫다. 알람 볼륨은 보안 문제가 아닌 엔지니어링 문제다.

**"우리 EDR 있잖아요"는 Assumed Breach가 아니다.** EDR은 탐지 레이어 하나다. 네트워크(동-서 트래픽), 신원(인증 이벤트), 엔드포인트(프로세스 행위), 데이터(DLP, 접근 패턴) 등 다중 레이어 탐지가 필요하다. 공격자는 당신의 EDR을 미리 테스트한다. 그들은 당신보다 맹점을 더 잘 안다.

**문서상 세분화 vs. 실제 세분화.** 방화벽 규칙은 워크스테이션 간 SMB를 차단한다고 되어 있다. SOC가 측면 이동 알람에 대응해보니 규칙이 새 VLAN에만 적용되고 레거시 세그먼트는 여전히 평탄한 상태다. 분기별로 실제 측면 이동 시뮬레이션으로 세분화를 테스트하라.

**Assumed Breach는 "예방하지 말라"는 의미가 아니다.** 예방과 탐지는 경쟁하지 않는다. 공격 표면 축소(패치, 레거시 프로토콜 비활성화, MFA 강제)와 탐지-심층 방어를 동시에 구축하라. 예방은 진입점을 줄이고, Assumed Breach는 통과한 것들을 다룬다.

## 빠른 참조

### 핵심 Assumed Breach 통제

| 통제 | 목적 | 핵심 지표 |
|---|---|---|
| 마이크로 세분화 | 측면 이동 범위 제한 | 허용 목록 규칙이 있는 동-서 트래픽 비율 |
| 특권 접근 워크스테이션(PAW) | 관리자 자격증명 격리 | PAW에서 수행된 관리 작업 비율 |
| 자격증명 계층화 | 계층 간 자격증명 재사용 방지 | 계층 적절 범위를 가진 계정 비율 |
| EDR 행위 탐지 | 침해 후 엔드포인트 가시성 | 테스트 기법에 대한 평균 알람 시간(MTTA) |
| 신원 이상 탐지 | 자격증명 남용 포착 | 불가능 접근 패턴 알람율 |
| 퍼플팀 주기 | 탐지 커버리지 검증 | 분기별 ATT&CK 기법 커버리지 % |

### 전술별 탐지 우선순위 (초기 접근 이후)

```
우선순위 1 (분 단위 탐지):
  - 자격증명 덤핑 (LSASS, SAM, NTDS)
  - DCSync 공격
  - Kerberoasting

우선순위 2 (시간 단위 탐지):
  - WMI/PSExec/RDP를 통한 측면 이동
  - 비정상 서비스 계정 활동
  - Pass-the-Hash / Pass-the-Ticket

우선순위 3 (일 단위 탐지):
  - 지속성 메커니즘 (예약 작업, 레지스트리 실행 키)
  - 내부 정찰 (LDAP 쿼리, 네트워크 스캐닝)
  - 데이터 준비 행위
```

### Assumed Breach 프로그램 핵심 도구

| 단계 | 도구 | 목적 |
|---|---|---|
| 시뮬레이션 | Atomic Red Team | 기법 수준 적 시뮬레이션 |
| 시뮬레이션 | Caldera (MITRE) | 자동화 적 에뮬레이션 |
| BAS | AttackIQ / Cymulate | 지속적 커버리지 검증 |
| 탐지 | Sigma | 벤더 중립 탐지 규칙 형식 |
| 커버리지 | ATT&CK Navigator | 탐지 커버리지 공백 시각화 |
| 신원 | BloodHound | 공격자보다 먼저 AD 공격 경로 매핑 |
