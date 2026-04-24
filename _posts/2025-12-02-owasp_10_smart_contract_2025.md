---
title: OWASP Smart Contract Top 10 - 2025
key: page-owasp_10_smart_contract_2025
categories:
- Security
- Blockchain
author: hyoeun
math: true
mathjax_autoNumber: true
bilingual: true
image: "/assets/thumbnails/2022-12-02-owasp_10_smart_contract_2025.png"
date: 2022-12-02 09:57:36
---

## OWASP Smart Contract Top 10 - 2025

Smart contracts are immutable by design — once deployed to a blockchain, their logic cannot be patched. A single vulnerability can result in millions of dollars drained within a single transaction, with no recourse. The OWASP Smart Contract Top 10 for 2025 documents the ten most critical vulnerability classes affecting smart contracts today.

## SC01: Reentrancy Attacks

Reentrancy is the classic DeFi exploit. It occurs when a vulnerable contract makes an external call to another contract before updating its own state, allowing the callee to call back into the vulnerable function before the state has been updated.

The canonical example is the 2016 DAO hack: the `withdraw()` function sent ETH before reducing the balance, allowing the attacker's fallback function to recursively call `withdraw()` again, draining the contract.

**Mitigations:**
* Use the Checks-Effects-Interactions (CEI) pattern — update state before making external calls.
* Apply `ReentrancyGuard` mutex locks (e.g., OpenZeppelin's implementation).
* Avoid using `call()` for ETH transfers when possible; use `transfer()` or `send()` which limit gas to 2300.

## SC02: Integer Overflow and Underflow

Before Solidity 0.8.0, arithmetic operations could silently overflow or underflow. A `uint256` at its maximum value incremented by 1 wraps to 0. Attackers exploited this to bypass balance checks or manipulate token amounts.

**Mitigations:**
* Solidity 0.8.0+ reverts on overflow/underflow by default.
* For older contracts, use SafeMath libraries.
* Explicitly handle edge cases in arithmetic logic.

## SC03: Access Control Vulnerabilities

Functions that should be restricted to owners or authorized roles are exposed without proper access control. This includes missing `onlyOwner` modifiers, incorrect role assignments, and flawed ownership transfer logic.

**Mitigations:**
* Use role-based access control (RBAC) patterns (e.g., OpenZeppelin's `AccessControl`).
* Apply function visibility modifiers (`private`, `internal`, `external`) correctly.
* Audit all administrative functions for proper authorization checks.

## SC04: Unprotected Self-Destruct

If `selfdestruct()` is callable by unauthorized parties, an attacker can destroy the contract and drain its ETH balance to an arbitrary address. Some proxy patterns are especially vulnerable.

**Mitigations:**
* Restrict `selfdestruct()` with strict access controls.
* Consider removing `selfdestruct()` entirely if not functionally required.
* Audit proxy contracts for uninitialized implementation slots.

## SC05: Arithmetic Issues (Price Oracle Manipulation)

DeFi protocols that rely on on-chain price oracles (e.g., AMM spot prices) are vulnerable to flash loan manipulation. An attacker borrows a large amount, manipulates the pool price, exploits the victim protocol, and repays the loan — all in one transaction.

**Mitigations:**
* Use time-weighted average prices (TWAP) instead of spot prices.
* Use decentralized oracle networks (e.g., Chainlink).
* Apply sanity checks on price deviations.

## SC06: Unchecked External Calls

In Solidity, low-level calls (`call()`, `delegatecall()`, `send()`) return a boolean indicating success or failure. If the return value is not checked, failed calls silently continue execution, potentially leading to inconsistent state.

**Mitigations:**
* Always check the return value of low-level calls.
* Prefer `transfer()` which automatically reverts on failure.
* Use the CEI pattern and fail-safe defaults.

## SC07: Denial of Service (DoS)

DoS attacks make a contract permanently or temporarily unusable. Common patterns include:
* **Gas limit DoS** — iterating over an unbounded array that grows over time, eventually exceeding the block gas limit.
* **External call DoS** — a contract that calls an external address where the callee reverts, blocking critical functionality.
* **Push payment DoS** — sending ETH to addresses that always revert blocks withdrawal patterns.

**Mitigations:**
* Use pull payment patterns instead of push.
* Set explicit iteration limits.
* Design contracts to handle individual external call failures gracefully.

## SC08: Logic Bugs and Business Logic Flaws

Vulnerabilities that don't fit classic categories but arise from incorrect implementation of intended business logic — such as wrong calculation order, flawed reward distribution, or incorrect state machine transitions.

**Mitigations:**
* Formal specification and verification of contract logic.
* Comprehensive unit and integration testing.
* Professional security audits with business logic review.

## SC09: Insecure Randomness

Smart contracts run deterministically on all nodes. `block.timestamp`, `block.number`, and `blockhash` are manipulable by miners to a degree, making them unsuitable as randomness sources in security-sensitive contexts like lotteries or NFT minting.

**Mitigations:**
* Use Chainlink VRF (Verifiable Random Function) for provably fair randomness.
* Use commit-reveal schemes for interactive randomness.
* Avoid on-chain randomness for high-value outcomes.

## SC10: Front-Running

Transactions on public blockchains are visible in the mempool before being mined. Attackers (or MEV bots) monitor pending transactions and insert their own transactions with higher gas fees to execute before the victim's transaction, exploiting price movements or sniping NFT mints.

**Mitigations:**
* Commit-reveal patterns for sensitive operations.
* Slippage limits in DEX trades.
* Batch auctions to prevent front-running.
* MEV protection services (e.g., Flashbots Protect).

---

## OWASP 스마트 컨트랙트 Top 10 - 2025

스마트 컨트랙트는 설계상 불변(immutable)이다. 블록체인에 배포된 후에는 로직을 패치할 수 없다. 취약점 하나로 단 하나의 트랜잭션 안에서 수백만 달러가 유출될 수 있으며, 복구 수단도 없다. OWASP 스마트 컨트랙트 Top 10 2025는 오늘날 스마트 컨트랙트에 영향을 미치는 10가지 핵심 취약점 유형을 정리한 것이다.

## SC01: 재진입 공격 (Reentrancy Attacks)

재진입(Reentrancy)은 대표적인 DeFi 익스플로잇이다. 취약한 컨트랙트가 자신의 상태를 업데이트하기 전에 외부 컨트랙트를 호출할 때 발생한다. 피호출 컨트랙트가 상태 업데이트 전에 다시 취약한 함수를 재귀 호출할 수 있게 된다.

2016년 DAO 해킹이 대표적 사례다. `withdraw()` 함수가 잔액을 줄이기 전에 ETH를 보내면서, 공격자의 fallback 함수가 재귀적으로 `withdraw()`를 다시 호출해 컨트랙트를 고갈시켰다.

**대응 방안:**
* Checks-Effects-Interactions(CEI) 패턴 — 외부 호출 전에 상태를 먼저 업데이트.
* ReentrancyGuard 뮤텍스 잠금 적용(예: OpenZeppelin 구현체).
* 가능하면 ETH 전송에 `call()` 대신 가스를 2300으로 제한하는 `transfer()` 또는 `send()` 사용.

## SC02: 정수 오버플로우 및 언더플로우 (Integer Overflow and Underflow)

Solidity 0.8.0 이전에는 산술 연산이 조용히 오버플로우/언더플로우될 수 있었다. 최댓값의 `uint256`에 1을 더하면 0으로 래핑된다. 공격자는 이를 이용해 잔액 검사를 우회하거나 토큰 양을 조작했다.

**대응 방안:**
* Solidity 0.8.0+는 오버플로우/언더플로우 시 기본적으로 revert한다.
* 구버전 컨트랙트는 SafeMath 라이브러리 사용.
* 산술 로직의 경계 케이스 명시적 처리.

## SC03: 접근 제어 취약점 (Access Control Vulnerabilities)

소유자나 권한 있는 역할에만 제한되어야 할 함수가 적절한 접근 제어 없이 노출된다. `onlyOwner` 수정자 누락, 잘못된 역할 할당, 소유권 이전 로직 결함 등이 포함된다.

**대응 방안:**
* 역할 기반 접근 제어(RBAC) 패턴 사용(예: OpenZeppelin의 `AccessControl`).
* 함수 가시성 수정자(`private`, `internal`, `external`)를 올바르게 적용.
* 모든 관리 함수에 대한 적절한 인가 검사 감사.

## SC04: 보호되지 않은 Self-Destruct (Unprotected Self-Destruct)

`selfdestruct()`가 권한 없는 주체에 의해 호출 가능하면, 공격자가 컨트랙트를 파괴하고 ETH 잔액을 임의의 주소로 유출할 수 있다. 일부 프록시 패턴이 특히 취약하다.

**대응 방안:**
* `selfdestruct()`에 엄격한 접근 제어 적용.
* 기능상 불필요하다면 `selfdestruct()` 자체를 제거 고려.
* 초기화되지 않은 구현 슬롯에 대한 프록시 컨트랙트 감사.

## SC05: 산술 이슈 - 가격 오라클 조작 (Price Oracle Manipulation)

온체인 가격 오라클(예: AMM 스팟 가격)에 의존하는 DeFi 프로토콜은 플래시 론 조작에 취약하다. 공격자가 대규모로 빌리고, 풀 가격을 조작하고, 피해 프로토콜을 악용하고, 대출을 상환하는 — 모든 과정이 단 하나의 트랜잭션 내에 이루어진다.

**대응 방안:**
* 스팟 가격 대신 시간 가중 평균 가격(TWAP) 사용.
* 탈중앙화 오라클 네트워크(예: Chainlink) 사용.
* 가격 편차에 대한 합리성 검사 적용.

## SC06: 확인되지 않은 외부 호출 (Unchecked External Calls)

Solidity에서 저수준 호출(`call()`, `delegatecall()`, `send()`)은 성공/실패를 나타내는 불리언을 반환한다. 반환값을 확인하지 않으면 실패한 호출이 조용히 계속 실행되어 불일치 상태를 초래할 수 있다.

**대응 방안:**
* 저수준 호출의 반환값 항상 확인.
* 실패 시 자동으로 revert하는 `transfer()` 선호.
* CEI 패턴 및 안전 기본값 사용.

## SC07: 서비스 거부 (Denial of Service, DoS)

DoS 공격은 컨트랙트를 영구적 또는 일시적으로 사용 불가능하게 만든다. 일반적인 패턴:
* **가스 한도 DoS** — 시간이 지남에 따라 무제한으로 성장하는 배열을 순회하여 결국 블록 가스 한도 초과.
* **외부 호출 DoS** — 피호출자가 revert하는 외부 주소를 호출하는 컨트랙트가 핵심 기능을 차단.
* **푸시 결제 DoS** — 항상 revert하는 주소로 ETH를 보내어 출금 패턴을 차단.

**대응 방안:**
* 푸시 대신 풀(pull) 결제 패턴 사용.
* 명시적 반복 한도 설정.
* 개별 외부 호출 실패를 우아하게 처리하도록 컨트랙트 설계.

## SC08: 로직 버그 및 비즈니스 로직 결함 (Logic Bugs)

고전적 카테고리에 속하지 않지만 의도한 비즈니스 로직의 잘못된 구현에서 발생하는 취약점 — 잘못된 계산 순서, 결함 있는 보상 분배, 잘못된 상태 기계 전환 등.

**대응 방안:**
* 컨트랙트 로직의 공식 명세 및 검증.
* 포괄적인 단위 및 통합 테스트.
* 비즈니스 로직 검토를 포함한 전문 보안 감사.

## SC09: 안전하지 않은 무작위성 (Insecure Randomness)

스마트 컨트랙트는 모든 노드에서 결정론적으로 실행된다. `block.timestamp`, `block.number`, `blockhash`는 어느 정도 채굴자가 조작할 수 있어, 복권이나 NFT 민팅 같은 보안 민감 컨텍스트에서의 무작위성 소스로는 부적합하다.

**대응 방안:**
* 검증 가능한 공정한 무작위성을 위해 Chainlink VRF 사용.
* 대화형 무작위성을 위한 커밋-공개(commit-reveal) 체계 사용.
* 고가치 결과에 온체인 무작위성 회피.

## SC10: 프런트러닝 (Front-Running)

퍼블릭 블록체인의 트랜잭션은 채굴 전에 멤풀에서 볼 수 있다. 공격자(또는 MEV 봇)가 대기 중인 트랜잭션을 모니터링하고, 더 높은 가스 수수료로 자신의 트랜잭션을 삽입하여 피해자의 트랜잭션보다 먼저 실행해, 가격 변동을 악용하거나 NFT 민팅을 가로챈다.

**대응 방안:**
* 민감한 작업에 커밋-공개 패턴 적용.
* DEX 거래에서 슬리피지 한도 설정.
* 프런트러닝 방지를 위한 배치 경매.
* MEV 보호 서비스 활용(예: Flashbots Protect).
