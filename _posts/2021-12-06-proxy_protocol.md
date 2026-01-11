---
title: Proxy Protocols
tags:  Blockchain
key: page-proxy_protocol
categories: [Cybersecurity, Blockchain]
author: hyoeun
math: true
mathjax_autoNumber: true
---

## Understanding 'Proxy Protocols': Overcoming the Limitations of Smart Contracts

One of the defining characteristics of blockchain is **Immutability**. However, when a critical bug is discovered or a feature needs improvement during service operation, this permanence can become a double-edged sword. To solve this, **Proxy Protocols** were introduced.

### 1. The Core of the Proxy Pattern: `delegatecall`

The key keyword for understanding proxy structures is **`delegatecall`**. Unlike a standard call, `delegatecall` has the following unique properties:

* **Code:** It executes the code of the called contract (the **Implementation**).
* **State (Storage):** It maintains the context of the calling contract (the **Proxy**).

In essence, the Proxy contract holds the data (State), while borrowing the business logic from an external logic contract for execution. By simply swapping the address of the logic contract, developers can "upgrade" the service.

---

### 2. Comparison of Major Proxy Protocols

Here is a comparison of the two core patterns frequently discussed in technical interviews: **Transparent** and **UUPS**.

| Category | Transparent Proxy (TPP) | UUPS (Universal Upgradeable) |
| --- | --- | --- |
| **Upgrade Logic Location** | Located in the Proxy contract | Located in the Implementation contract |
| **Gas Efficiency** | Relatively lower (checks admin status every call) | High (handled within the logic) |
| **Complexity** | Structure is somewhat complex | Simple structure but carries more risk |
| **Security Strength** | Calls for Admin and User are strictly separated | Code is lightweight and easier to manage (EIP-1822) |

> **Pro Tip:** Recently, the **UUPS pattern** has been more favored due to its gas efficiency and flexibility. However, engineers must be cautious of the "Bricking" risk: if the upgrade function is omitted in a new logic contract deployment, the contract can never be updated again.

---

### 3. Proxy Vulnerabilities for Security Engineers

Penetration testers must understand the specific vulnerabilities that can arise within a proxy architecture.

#### **① Storage Collision**

If the order of variable declarations in the Proxy and Implementation contracts does not match, data will be overwritten in unintended slots.

* **Solution:** Use **EIP-1967** standard slots (randomized slots located far at the end of storage) or strictly manage inheritance structures.

#### **② Uninitialized Proxy**

Proxies cannot use a `constructor` because the state must be stored in the Proxy, not the Implementation. Instead, an `initialize` function is used. If this function is not called immediately upon deployment, an attacker can hijack it to seize administrative control.

#### **③ Function Selector Clash**

This occurs when a management function in the Proxy (e.g., `upgradeTo`) and a function in the Implementation share the same 4-byte ID (Function Selector). This is primarily mitigated in the Transparent pattern through strict administrative access control.

---

### 4. Balancing Security and Flexibility

Proxy protocols breathe life into smart contracts, but they significantly increase security complexity. For a successful Web3 project, deploying code is not enough; a rigorous **Audit** of **Storage Layout Validation** and **Permission Management** must be conducted beforehand.

---

## 스마트 컨트랙트의 한계를 넘는 '프록시(Proxy) 프로토콜' 이해하기

블록체인의 가장 큰 특징 중 하나는 **'수정 불가능성(Immutability)'**입니다. 하지만 서비스 운영 중 치명적인 버그가 발견되거나 기능을 개선해야 할 때, 이 특징은 오히려 독이 되기도 합니다. 이를 해결하기 위해 등장한 것이 바로 **프록시(Proxy) 프로토콜**입니다.

### 1. 프록시 패턴의 핵심: `delegatecall`

프록시 구조를 이해하기 위한 핵심 키워드는 **`delegatecall`**입니다. 일반적인 호출과 달리, `delegatecall`은 다음과 같은 특징을 가집니다.

* **코드(Code):** 호출된 컨트랙트(Implementation)의 것을 실행합니다.
* **상태(Storage/State):** 호출한 컨트랙트(Proxy)의 컨텍스트를 유지합니다.

즉, 프록시 컨트랙트는 데이터(State)만 가지고 있고, 실제 비즈니스 로직은 외부의 로직 컨트랙트에서 빌려와 실행하는 구조입니다. 이를 통해 로직 컨트랙트 주소만 교체하면 서비스의 '업그레이드'가 가능해집니다.

---

### 2. 주요 프록시 프로토콜 비교

인터뷰에서도 자주 묻는 두 가지 핵심 패턴, **Transparent**와 **UUPS**를 비교해 보겠습니다.

| 구분 | Transparent Proxy (TPP) | UUPS (Universal Upgradeable) |
| --- | --- | --- |
| **업그레이드 로직 위치** | Proxy 컨트랙트 | Implementation 컨트랙트 |
| **가스 효율성** | 상대적으로 낮음 (매번 관리자 확인) | 높음 (로직 내에서 처리) |
| **복잡도** | 구조가 다소 복잡함 | 구조가 단순하지만 위험 부담이 있음 |
| **보안 강점** | Admin과 User의 호출 경로가 완벽히 분리됨 | 코드가 가볍고 관리가 용이함 (EIP-1822) |

> **Pro Tip:** 최근에는 가스비 절감과 유연성 때문에 **UUPS 패턴**이 더 선호되는 추세입니다. 하지만 로직 컨트랙트 배포 시 업그레이드 함수를 누락하면 다시는 업데이트를 할 수 없게 되는 '벽돌(Brick)' 현상을 주의해야 합니다.

---

### 3. 보안 엔지니어가 체크해야 할 프록시 취약점

펜테스터라면 프록시 구조에서 발생할 수 있는 특유의 취약점을 반드시 이해해야 합니다.

#### **① 스토리지 충돌 (Storage Collision)**

프록시와 로직 컨트랙트의 변수 선언 순서가 일치하지 않으면 데이터가 엉뚱한 곳에 덮어씌워집니다.

* **해결책:** `EIP-1967` 표준에 따라 매우 먼 스토리지 슬롯(Randomized Slot)을 사용하거나, 상속 구조를 엄격히 관리해야 합니다.

#### **② 초기화 문제 (Uninitialized Proxy)**

프록시는 `constructor`를 사용할 수 없습니다(상태값이 프록시에 저장되어야 하기 때문). 대신 `initialize`라는 일반 함수를 사용하는데, 이 함수를 배포 즉시 호출하지 않으면 공격자가 가로채어 컨트랙트의 권한을 탈취할 수 있습니다.

#### **③ 함수 선택자 충돌 (Function Selector Clash)**

프록시 자체의 관리 함수(예: `upgradeTo`)와 로직 컨트랙트의 일반 함수가 동일한 ID를 가질 때 발생하는 문제입니다. 이는 주로 Transparent 패턴에서 관리자 권한 분리로 해결합니다.

---

### 4. 보안과 유연성 사이의 균형

프록시 프로토콜은 스마트 컨트랙트에 생명력을 불어넣어 주지만, 그만큼 보안적인 복잡도를 높입니다. 성공적인 Web3 프로젝트를 위해서는 단순히 코드를 배포하는 것을 넘어, **스토리지 레이아웃 검증**과 **권한 관리**에 대한 철저한 오딧(Audit)이 선행되어야 합니다.