---
title: "Zero Trust Security: Never Trust, Always Verify"
key: page-zero_trust_security
categories:
- Security
- Identity and Access Management
author: hyoeun
math: true
mathjax_autoNumber: true
image: "/assets/thumbnails/2024-11-10-zero_trust_security.png"
bilingual: true
date: 2024-11-10 09:00:00
---

## Zero Trust Security: Never Trust, Always Verify

The old security model assumed everything inside the corporate network was safe. You got past the firewall, you were trusted. This assumption held when employees worked from a single office, connected to on-premise servers, using company-managed devices. That world no longer exists.

Today, users connect from coffee shops, home networks, and mobile devices. Applications live in multi-cloud environments. Contractors access internal systems from unmanaged machines. The perimeter has dissolved — and with it, the validity of perimeter-based security.

**Zero Trust** is the architectural response to this reality. Its core tenet: **trust nothing, verify everything.** Not the network. Not the device. Not even the user after they've already authenticated once.

## The Core Principles of Zero Trust

### 1. Verify Explicitly

Every access request must be authenticated and authorized using all available signals — not just a password.

**Signals used for verification:**
- **Identity**: Who is the user? Is MFA enforced?
- **Device health**: Is the device managed? Is it compliant? Is the OS patched?
- **Location**: Is this request coming from an expected geography or IP range?
- **Application**: What resource is being accessed, and is this user authorized?
- **Risk signal**: Is the behavior anomalous compared to historical patterns?

This is why Zero Trust is inseparable from **Conditional Access** policies. A request is not approved by identity alone — it's approved by the combination of multiple signals evaluated at runtime.

```
Request → Identity Verified → Device Evaluated → Risk Score Calculated → Access Granted or Denied
```

### 2. Use Least Privilege Access

Every entity — user, service, device — should have the minimum access required to perform its function. Nothing more.

**In practice this means:**
- Just-In-Time (JIT) access: Elevate permissions only when needed, for a time-limited window
- Just-Enough-Access (JEA): Scope permissions narrowly rather than granting broad roles
- Regular access reviews: Revoke permissions that are no longer actively used

The contrast with traditional access models is stark:

| Traditional Model | Zero Trust Model |
|:---|:---|
| Broad role assigned permanently | Narrow, time-bound permissions |
| Access granted at onboarding, rarely reviewed | Continuous access reviews & revocation |
| Admin accounts used for daily work | PAM (Privileged Access Management) with JIT elevation |
| Lateral movement once inside network is easy | Microsegmentation limits blast radius |

### 3. Assume Breach

Design your systems as if an attacker is already inside. This changes how you think about security controls — they're not just about keeping attackers out, but about limiting what they can do once in.

**Assume Breach engineering implications:**
- **Encrypt everything**: Data in transit and at rest, even within internal networks
- **Microsegmentation**: Divide the network into isolated segments so that compromise of one segment does not cascade
- **Comprehensive logging**: Every access, every API call, every authentication — logged and retained for detection
- **Detection over prevention**: Invest in the ability to detect attacker behavior quickly, not just in controls that attempt to block everything

## Zero Trust Architecture: The Components

### Identity Plane

Identity is the new perimeter. The key infrastructure components:

- **Identity Provider (IdP)**: The authoritative source of identity. Azure AD, Okta, Google Workspace.
- **Multi-Factor Authentication (MFA)**: A mandatory control. Password-only authentication is insufficient.
- **Privileged Identity Management (PIM)**: Controls over who can become a privileged admin, for how long, and with what approval workflow.

```
User authenticates → IdP validates identity + MFA → 
Device compliance checked → Conditional Access policy evaluated → 
Token issued with scoped permissions
```

### Device Trust

Unmanaged devices represent one of the largest sources of risk in modern enterprises. Zero Trust requires device signals to be part of the access decision.

**Device health signals:**
- Is the device enrolled in MDM (Mobile Device Management)?
- Is the OS version current?
- Is disk encryption enabled?
- Does it have an approved EDR (Endpoint Detection & Response) agent running?
- Is the device compliant with corporate security baselines?

A corporate credential presented from a compromised, unmanaged personal device is not trustworthy — even if the credential itself is valid.

### Network Microsegmentation

Traditional networks are flat: once inside, you can reach almost anything. Microsegmentation creates logical boundaries within the network so that even a compromised workload cannot freely communicate with unrelated systems.

**Implementation approaches:**

| Approach | Technology | Granularity |
|:---|:---|:---|
| VLAN-based segmentation | Network hardware | Subnet level |
| Security Groups | AWS/Azure/GCP | Resource level |
| Service Mesh (mTLS) | Istio, Linkerd | Service-to-service |
| Host-based firewalls | Windows Defender Firewall, iptables | Process level |

In a Zero Trust network, the question shifts from "Is this traffic inside the perimeter?" to "Is this specific service allowed to talk to that specific service, with these credentials, for this purpose?"

### Data-Centric Controls

Zero Trust protects data, not just the network. This requires:
- **Data classification**: Know what sensitive data exists and where it lives
- **DLP (Data Loss Prevention)**: Detect and block unauthorized data exfiltration
- **Encryption at rest**: Ensure data is unreadable if storage is compromised
- **Access logging**: Every access to sensitive data is logged and auditable

## Zero Trust Maturity Model (CISA)

CISA (Cybersecurity and Infrastructure Security Agency) defines Zero Trust maturity across five pillars:

| Pillar | Traditional | Advanced | Optimal |
|:---|:---|:---|:---|
| **Identity** | Password auth | MFA enforced | Passwordless + continuous validation |
| **Devices** | Unmanaged | MDM enrolled | Real-time compliance enforcement |
| **Networks** | Flat network | VLANs | Full microsegmentation |
| **Applications** | VPN access | SSO + RBAC | JIT + per-session authorization |
| **Data** | Unclassified | DLP deployed | Full classification + encryption |

Most organizations operate somewhere in the "Traditional" to "Advanced" range. Reaching "Optimal" is a multi-year journey.

## Common Implementation Pitfalls

### 1. Starting with Technology, Not Policy

Zero Trust begins with defining access policies — who needs what, for what purpose — before selecting products. Buying an identity platform without first designing your access model leads to misconfigured, overly permissive policies at scale.

### 2. Treating MFA as the Finish Line

MFA is necessary but not sufficient. SIM-swapping, MFA fatigue attacks (sending repeated push notifications until the user approves out of frustration), and adversary-in-the-middle phishing all bypass basic MFA. Phishing-resistant MFA (FIDO2/WebAuthn hardware keys, passkeys) is the next required step.

### 3. Neglecting Service-to-Service Identity

Human identity gets most of the attention, but service accounts, API keys, and workload identities are often far more privileged and far less protected. Service-to-service authentication must also be part of the Zero Trust model — workload identity, mutual TLS, and short-lived credentials.

### 4. Zero Trust as a Product, Not a Journey

No single vendor delivers Zero Trust. It's an architectural philosophy implemented through a combination of identity, device management, network controls, and data protection — continuously improved over time.

## Conclusion

Zero Trust is not a product you buy or a project you complete. It is a continuous architectural commitment to the principle that access should never be assumed — it must always be earned, scoped, verified, and logged.

The organizations that implement it well don't just have better security postures — they have better visibility into their own environments, which is itself a form of competitive advantage. You cannot protect what you cannot see.

---

## 제로 트러스트 보안: 절대 신뢰하지 말고, 항상 검증하라

과거의 보안 모델은 기업 네트워크 내부에 있는 모든 것을 안전하다고 가정했습니다. 방화벽만 통과하면 신뢰를 받았죠. 직원들이 단일 사무실에서 일하고, 온프레미스 서버에 연결하고, 회사가 관리하는 기기를 사용하던 시절에는 이 가정이 유효했습니다. 하지만 그 세상은 더 이상 존재하지 않습니다.

오늘날 사용자들은 카페, 가정 네트워크, 모바일 기기에서 접속합니다. 애플리케이션은 멀티 클라우드 환경에 배포됩니다. 외주 직원들은 관리되지 않는 기기로 내부 시스템에 접근합니다. 경계(perimeter)는 사라졌고, 그와 함께 경계 기반 보안의 유효성도 사라졌습니다.

**제로 트러스트(Zero Trust)**는 이 현실에 대한 아키텍처적 응답입니다. 핵심 원칙은 하나입니다: **아무것도 신뢰하지 말고, 모든 것을 검증하라.** 네트워크도, 기기도, 심지어 이미 한 번 인증을 마친 사용자도 예외가 아닙니다.

## 제로 트러스트의 3가지 핵심 원칙

### 1. 명시적으로 검증하라 (Verify Explicitly)

모든 접근 요청은 비밀번호 하나가 아닌, 가용한 모든 신호를 종합하여 인증 및 인가되어야 합니다.

**검증에 사용되는 신호:**
- **신원(Identity)**: 사용자가 누구인가? MFA가 강제되고 있는가?
- **기기 상태(Device health)**: 관리되는 기기인가? 보안 정책에 부합하는가? OS는 최신 패치 상태인가?
- **위치(Location)**: 예상되는 지역 또는 IP 범위에서 요청이 들어오는가?
- **애플리케이션(Application)**: 어떤 리소스에 접근하려 하는가? 이 사용자에게 권한이 있는가?
- **위험 신호(Risk signal)**: 과거 패턴과 비교했을 때 이상 행동이 감지되는가?

이것이 제로 트러스트가 **조건부 접근(Conditional Access)** 정책과 불가분의 관계인 이유입니다. 요청은 신원 하나만으로 승인되지 않고, 런타임에 평가되는 복수의 신호 조합에 의해 승인됩니다.

### 2. 최소 권한을 사용하라 (Use Least Privilege Access)

모든 사용자, 서비스, 기기는 자신의 역할을 수행하는 데 필요한 최소한의 접근 권한만 가져야 합니다.

**실제 구현 방법:**
- **JIT(Just-In-Time) 접근**: 필요할 때만, 시간 제한을 두어 권한을 상승시킵니다.
- **JEA(Just-Enough-Access)**: 광범위한 역할을 부여하는 대신 권한 범위를 좁게 한정합니다.
- **정기적인 접근 권한 검토**: 더 이상 사용하지 않는 권한은 회수합니다.

전통적인 모델과의 차이점:

| 전통적 모델 | 제로 트러스트 모델 |
|:---|:---|
| 영구적으로 광범위한 역할 부여 | 시간 제한을 둔 최소 권한 |
| 온보딩 시 권한 부여, 거의 검토 안 함 | 지속적인 접근 권한 검토 및 회수 |
| 일상 업무에도 관리자 계정 사용 | PAM(특권 접근 관리)으로 JIT 권한 상승 |
| 네트워크 내부 접근 시 자유로운 횡적 이동 | 마이크로세그멘테이션으로 피해 범위 제한 |

### 3. 침해를 가정하라 (Assume Breach)

이미 공격자가 내부에 있다는 전제하에 시스템을 설계하세요. 이는 보안 통제에 대한 관점을 바꿉니다. 공격자를 막는 것뿐만 아니라, 일단 침투했을 때 그들이 할 수 있는 것을 제한하는 데 집중합니다.

**'침해를 가정하라' 원칙의 엔지니어링 함의:**
- **모든 것을 암호화**: 내부 네트워크에서도 전송 중 데이터와 저장 데이터를 암호화합니다.
- **마이크로세그멘테이션**: 하나의 세그먼트 침해가 전체로 확산되지 않도록 네트워크를 격리된 구역으로 분할합니다.
- **포괄적인 로깅**: 모든 접근, 모든 API 호출, 모든 인증을 로깅하고 보존합니다.
- **탐지 우선 전략**: 모든 것을 차단하려는 시도보다, 공격자의 행동을 빠르게 탐지하는 능력에 투자합니다.

## 제로 트러스트 아키텍처 구성 요소

### 신원 플레인 (Identity Plane)

신원(Identity)이 새로운 경계입니다. 핵심 인프라 구성 요소:

- **IdP(신원 제공자)**: 신원의 권위 있는 출처. Azure AD, Okta, Google Workspace.
- **MFA(다중 인증)**: 필수 통제 수단. 비밀번호 단독 인증은 불충분합니다.
- **PIM(특권 신원 관리)**: 누가 특권 관리자가 될 수 있는지, 얼마나 오래, 어떤 승인 워크플로우를 거쳐야 하는지 통제합니다.

### 기기 신뢰 (Device Trust)

관리되지 않는 기기는 현대 기업 환경에서 가장 큰 위험 중 하나입니다. 제로 트러스트는 기기 신호가 접근 결정의 일부가 되도록 요구합니다.

**기기 상태 신호:**
- 기기가 MDM(모바일 기기 관리)에 등록되어 있는가?
- OS 버전이 최신 상태인가?
- 디스크 암호화가 활성화되어 있는가?
- 승인된 EDR(엔드포인트 탐지 및 대응) 에이전트가 실행 중인가?
- 기기가 기업의 보안 기준을 준수하는가?

기업 자격 증명이 유효하더라도, 침해되었거나 관리되지 않는 개인 기기에서 제시된다면 신뢰할 수 없습니다.

### 네트워크 마이크로세그멘테이션

전통적인 네트워크는 평평합니다. 한 번 내부에 들어오면 거의 모든 곳에 접근할 수 있습니다. 마이크로세그멘테이션은 네트워크 내에 논리적 경계를 만들어, 침해된 워크로드가 관련 없는 시스템과 자유롭게 통신하지 못하도록 합니다.

네트워크의 핵심 질문이 "이 트래픽이 경계 내에 있는가?"에서 "이 특정 서비스가 저 특정 서비스와, 이 자격 증명으로, 이 목적을 위해 통신하는 것이 허용되는가?"로 바뀝니다.

## CISA 제로 트러스트 성숙도 모델

CISA는 5개의 핵심 축에 걸쳐 제로 트러스트 성숙도를 정의합니다:

| 축 | 전통적 | 고급 | 최적 |
|:---|:---|:---|:---|
| **신원** | 비밀번호 인증 | MFA 강제 | 패스워드리스 + 지속적 검증 |
| **기기** | 미관리 기기 | MDM 등록 | 실시간 컴플라이언스 강제 |
| **네트워크** | 평탄한 네트워크 | VLAN | 완전한 마이크로세그멘테이션 |
| **애플리케이션** | VPN 접근 | SSO + RBAC | JIT + 세션별 인가 |
| **데이터** | 미분류 | DLP 배포 | 완전한 분류 + 암호화 |

대부분의 조직은 '전통적'과 '고급' 사이에 위치합니다. '최적' 수준에 도달하는 것은 수년에 걸친 여정입니다.

## 흔한 구현 함정

### 1. 정책보다 기술을 먼저 생각하기

제로 트러스트는 제품을 선택하기 전에 접근 정책, 즉 누가 무엇에 어떤 목적으로 접근해야 하는지를 먼저 정의하는 것에서 시작합니다. 접근 모델을 먼저 설계하지 않고 신원 플랫폼을 구매하면 대규모로 잘못 설정된, 과도하게 허용적인 정책이 만들어집니다.

### 2. MFA를 종착점으로 여기기

MFA는 필요하지만 충분하지 않습니다. SIM 스와핑, MFA 피로 공격(사용자가 피로감에 승인할 때까지 반복적으로 푸시 알림 전송), 중간자 피싱(Adversary-in-the-Middle phishing)은 모두 기본적인 MFA를 우회합니다. FIDO2/WebAuthn 하드웨어 키, 패스키와 같은 피싱 방지 MFA가 다음 필수 단계입니다.

### 3. 서비스 간 신원 무시하기

사람의 신원이 대부분의 주목을 받지만, 서비스 계정, API 키, 워크로드 신원은 훨씬 더 높은 권한을 가지고 있으면서 보호는 훨씬 덜 받는 경우가 많습니다. 서비스 간 인증 역시 제로 트러스트 모델의 일부가 되어야 합니다.

### 4. 제로 트러스트를 제품으로 여기기

단일 벤더가 제로 트러스트를 완성시켜주지 않습니다. 이것은 신원, 기기 관리, 네트워크 통제, 데이터 보호의 조합을 통해 구현되는 아키텍처 철학이며, 지속적으로 개선되어야 합니다.

## 결론

제로 트러스트는 구매하는 제품도, 완료할 수 있는 프로젝트도 아닙니다. 접근은 결코 가정되어서는 안 된다는 원칙, 즉 항상 획득하고, 범위를 한정하고, 검증하고, 로깅해야 한다는 원칙에 대한 지속적인 아키텍처적 헌신입니다.

제로 트러스트를 잘 구현하는 조직은 더 나은 보안 태세를 갖출 뿐만 아니라, 자신의 환경에 대한 더 나은 가시성을 확보합니다. 이 가시성 자체가 일종의 경쟁 우위입니다. 볼 수 없는 것은 보호할 수 없으니까요.
