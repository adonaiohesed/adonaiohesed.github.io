---
title: "Attribute-Based Access Control: Dynamic Authorization for Modern Systems"
key: page-abac_attribute_based_access_control
categories:
- Security
- Identity and Access Management
author: hyoeun
math: true
mathjax_autoNumber: true
image: "/assets/thumbnails/2024-12-05-abac_attribute_based_access_control.png"
bilingual: true
date: 2024-12-05 09:00:00
---

## Attribute-Based Access Control: Dynamic Authorization for Modern Systems

In the RBAC post, we saw how role-based access provides a clean, scalable way to assign permissions. But RBAC has a fundamental limitation: it is **static**. A user's role doesn't change mid-session, which means RBAC cannot answer questions like:

- "Can this user access this file *right now*, from *this location*, on *this device*?"
- "Should the same `Doctor` role grant full record access at 2 AM from an unrecognized IP?"

**Attribute-Based Access Control (ABAC)** is the evolution beyond roles. Instead of asking "What role do you have?", ABAC asks "What are all of your attributes *at this moment*?" — and then evaluates a policy against the complete context to make an authorization decision.

## The ABAC Formula

Every access decision in ABAC is a policy evaluation across four attribute categories:

```
ALLOW / DENY = f(Subject Attributes, Object Attributes, Environment Attributes, Action)
```

| Attribute Category | Examples |
|:---|:---|
| **Subject (Who)** | department, clearance, role, location |
| **Object (What)** | resource.classification, resource.owner, resource.project |
| **Environment (When/Where)** | time, network.ip_range, device.compliance_status |
| **Action (How)** | read, write, delete, approve, export |

A typical ABAC policy reads like a logical statement:

```
ALLOW IF:
  subject.department == resource.owning_department
  AND subject.clearance >= resource.classification_level
  AND environment.time BETWEEN "09:00" AND "18:00"
  AND environment.device.is_managed == true
```

## ABAC vs. RBAC: When to Use Which

| Dimension | RBAC | ABAC |
|:---|:---|:---|
| **Decision granularity** | Coarse (role-level) | Fine (attribute-level) |
| **Dynamic conditions** | No — static by design | Yes — runtime evaluation |
| **Administrative overhead** | Low once roles are defined | Higher (policy authoring is complex) |
| **Auditability** | Easy (roles are explicit) | Harder (requires policy logs) |
| **Ideal for** | Job function-level access | Context-sensitive or data-level access |

**Practical rule**: Use RBAC for the broad organizational structure, and layer ABAC on top for fine-grained data-level or contextual decisions within those systems.

## Implementing ABAC: The Core Decision Flow

```
Request (Subject + Object + Action + Environment)
        │
        ▼
  PEP (Policy Enforcement Point)   ← Your app / API gateway
        │
        ▼
  PDP (Policy Decision Point)      ← The ABAC engine
        │  evaluates against policies + fetches attributes
        ▼
  PIP (Policy Information Point)   ← IdP, CMDB, HR system
```

- **PEP**: Intercepts every access request — your application code or API gateway.
- **PDP**: Fetches all attributes and evaluates policies. Returns `PERMIT`, `DENY`, `INDETERMINATE`, or `NOT_APPLICABLE`.
- **PIP**: The attribute source. Pulls real-time data — device compliance, user clearance level, current time zone.

### Policy Combining Algorithms

When multiple policies apply to a single request:

| Algorithm | Behavior |
|:---|:---|
| `deny-overrides` | Any DENY wins — most secure default |
| `permit-overrides` | Any PERMIT wins |
| `first-applicable` | Use the first matching policy's result |

## Real-World ABAC Patterns

### 1. Healthcare Data Access
A `Doctor` role can read patient records only if:
- The patient is on their current care roster
- Access occurs within hospital working hours
- The device is a hospital-managed workstation

The same role is denied access to records outside their patient list — a distinction RBAC alone cannot make.

### 2. Multi-Tenant SaaS Isolation
```
ALLOW IF:
  subject.tenant_id == resource.tenant_id
  AND subject.role == "admin"
```
This ensures an admin in Tenant A can never touch Tenant B's data, even if both hold identical roles.

### 3. AWS IAM Tag-Based ABAC
```json
{
  "Effect": "Allow",
  "Action": "ec2:*",
  "Resource": "*",
  "Condition": {
    "StringEquals": {
      "aws:ResourceTag/Environment": "${aws:PrincipalTag/Environment}"
    }
  }
}
```
An engineer tagged `Environment: staging` can only operate on EC2 instances also tagged `Environment: staging`. No role changes needed — just update the tag.

## The Engineering Challenges of ABAC

**Policy Explosion**: Without governance, you end up with hundreds of overlapping, contradictory policies. Always design policies around clear organizational principles, not individual request exceptions.

**Attribute Quality**: An ABAC system is only as reliable as the attributes it evaluates. Stale HR data or inaccurate CMDB entries produce wrong access decisions. Attribute governance — ensuring freshness and authority — is as critical as policy design.

**Performance at Scale**: Evaluating complex policies at request time adds latency. Mitigate through attribute caching with short TTLs, policy pre-compilation, and distributing PDP evaluation close to enforcement points.

## Conclusion

ABAC is the authorization model for complex, dynamic, and data-sensitive environments. Where RBAC gives you organizational clarity, ABAC gives you contextual precision. The most mature enterprise security architectures combine both: RBAC defines the broad landscape of who can access which systems, and ABAC enforces the contextual guardrails that determine *under what exact conditions* that access is permitted.

---

## 속성 기반 접근 제어 (ABAC): 동적 인가 시스템 설계

RBAC의 핵심적인 한계는 **정적(Static)**이라는 점입니다. 역할은 세션 도중에 변하지 않기 때문에, 다음과 같은 질문에 답할 수 없습니다:

- "이 사용자가 *지금 이 순간*, *이 위치에서*, *이 기기로* 이 파일에 접근할 수 있는가?"
- "같은 `Doctor` 역할이 새벽 2시에 알 수 없는 IP에서도 전체 기록에 접근 권한을 주어야 하는가?"

**속성 기반 접근 제어(ABAC)**는 역할을 넘어선 진화된 모델입니다. "당신의 역할은 무엇인가?" 대신 "지금 이 순간 당신의 모든 속성은 무엇인가?"를 묻고, 완전한 맥락에 대해 정책을 평가하여 인가 결정을 내립니다.

## ABAC의 공식

```
허용 / 거부 = f(주체 속성, 객체 속성, 환경 속성, 행위)
```

| 속성 카테고리 | 예시 |
|:---|:---|
| **주체(Subject, 누가)** | 부서, 보안 등급, 역할, 현재 위치 |
| **객체(Object, 무엇을)** | 리소스 분류 등급, 소유 부서, 프로젝트 코드 |
| **환경(Environment, 언제/어디서)** | 현재 시간, IP 대역, 기기 컴플라이언스 상태 |
| **행위(Action, 어떻게)** | 읽기, 쓰기, 삭제, 승인, 내보내기 |

## ABAC vs. RBAC

| 차원 | RBAC | ABAC |
|:---|:---|:---|
| **결정 세분화 수준** | 거칠음 (역할 단위) | 세밀함 (속성 단위) |
| **동적 조건 반영** | 불가 — 설계 자체가 정적 | 가능 — 런타임 평가 |
| **관리 부담** | 역할 정의 후 낮음 | 높음 (정책 작성이 복잡) |
| **감사 용이성** | 쉬움 | 어려움 (정책 로그 필요) |
| **이상적인 케이스** | 직무 기능 수준의 시스템 접근 | 맥락에 민감한 데이터 수준 접근 |

**실용적 원칙**: RBAC는 광범위한 조직 구조에 사용하고, 그 안에서의 세밀한 데이터 수준 결정에는 ABAC를 레이어로 얹으세요.

## ABAC의 핵심 의사결정 흐름

- **PEP (Policy Enforcement Point)**: 모든 접근 요청을 가로채는 실행 지점. 앱 코드나 API 게이트웨이.
- **PDP (Policy Decision Point)**: 모든 속성을 수집하고 정책을 평가하여 `PERMIT` 또는 `DENY`를 반환하는 엔진.
- **PIP (Policy Information Point)**: IdP, CMDB, HR 시스템 등 다양한 소스에서 실시간으로 속성 값을 가져오는 정보 소스.

## 엔지니어링의 주요 도전 과제

**정책 폭발**: 거버넌스 없이는 수백 개의 중복되고 모순되는 정책이 생깁니다. 항상 개인 예외가 아닌 명확한 조직 원칙을 기반으로 정책을 설계하세요.

**속성 품질**: HR 시스템의 데이터가 오래되거나 CMDB가 현재 상태를 반영하지 못하면 접근 결정도 잘못됩니다. 속성의 정확성과 최신성을 보장하는 **속성 거버넌스**가 정책 설계만큼 중요합니다.

**대규모 성능**: 요청 시점에 복잡한 정책을 평가하면 레이턴시가 증가합니다. 짧은 TTL의 속성 캐싱, 정책 사전 컴파일, PDP를 강제 지점 가까이 분산 배치하는 방식으로 완화하세요.

## 결론

ABAC는 복잡하고 동적이며 데이터 민감도가 높은 환경을 위한 인가 모델입니다. RBAC가 조직적 명확성을 제공한다면, ABAC는 맥락적 정밀함을 제공합니다. 가장 성숙한 보안 아키텍처는 두 가지를 결합합니다. RBAC가 누가 어떤 시스템에 접근하는지의 큰 틀을 정의하고, ABAC는 *정확히 어떤 조건 하에서* 그 접근이 허용되는지의 맥락적 경계를 강제합니다.
