---
title: Smart Contract
tags:  Blockchain
key: page-smart_contract
categories: [Cybersecurity, Blockchain]
author: hyoeun
math: true
mathjax_autoNumber: true
---

## Basic Concepts of Smart Contracts

Unlike traditional contracts executed in writing, a **smart contract** is a digital protocol that automatically executes when predefined conditions, written in code, are met. First proposed by Nick Szabo in 1994, it is most easily understood through the mechanism of a **vending machine**. Just as a vending machine dispenses a product immediately without third-party intervention when a user inserts the correct amount and selects an item, a smart contract processes transactions according to predefined logic.

## Working Principles and Blockchain Interaction

Smart contracts are deployed on a **blockchain**—a distributed ledger—rather than a central server. Once the code is recorded on the blockchain, it gains **immutability**, meaning it cannot be arbitrarily modified. Furthermore, because every node in the network verifies the execution results, transparency and reliability are guaranteed.

The operational process is as follows:

1. **Logic Implementation:** A developer writes business logic in code based on specific conditions (**If-Then**).
2. **Compilation & Deployment:** The code is compiled into bytecode and sent to a specific address on the blockchain network.
3. **Triggering:** An external user or another contract calls a function by sending a transaction to that address.
4. **State Transition:** If the conditions are met, the code executes and updates the **state** of the blockchain.

## Engineering Perspectives: EVM and the Gas System

On platforms like Ethereum, smart contracts run in a runtime environment called the **Ethereum Virtual Machine (EVM)**. Software engineers must recognize that this is an environment with limited resources. While it offers **Turing Completeness**, it introduces the concept of **Gas** to prevent the entire network from being paralyzed by infinite loops or excessive computations.

Every instruction (**Opcode**) consumes gas during execution, which the transaction requester must pay for. Writing efficient code is not just a matter of readability; it directly impacts service operating costs and user experience. For example, designs that frequently modify state variables within loops should be avoided.

## Data Storage Contract Example using Solidity

A simple storage contract can be implemented using **Solidity**, the most widely used smart contract language.

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract BasicStorage {
    uint256 private storedData;

    // Function to store data. Consumes gas as it changes the state.
    function set(uint256 x) public {
        storedData = x;
    }

    // Function to retrieve data. The 'view' keyword indicates it does not change the state.
    function get() public view returns (uint256) {
        return storedData;
    }
}

```

## Checklist for Security Engineers

From a cybersecurity professional's perspective, smart contracts present a unique attack surface. Logical errors in the code can lead to immediate asset theft, and deploying patches is extremely difficult.

* **Reentrancy Attack:** This is one of the most prominent threats. It occurs when an external contract's fallback function is triggered during a fund transfer, allowing it to call the original function again before the first execution finishes. To prevent this, developers must strictly adhere to the **Checks-Effects-Interactions** pattern, ensuring all state changes occur before any external interactions.
* **Denial of Service (DoS) via Gas Limit:** Engineers must consider the possibility of DoS attacks. If logic includes iterating over massive arrays, gas consumption may eventually exceed the block limit, causing the function to become permanently unexecutable.

---

## 스마트 컨트랙트의 기본 개념

스마트 컨트랙트는 서면으로 체결되는 전통적인 계약과 달리, 코드로 작성된 조건이 충족되면 자동으로 실행되는 디지털 프로토콜이다. 1994년 닉 자보(Nick Szabo)에 의해 처음 제안되었으며, 자판기(Vending Machine) 메커니즘을 통해 가장 쉽게 이해할 수 있다. 사용자가 정확한 금액을 투입하고 원하는 상품 번호를 선택하면 제3자의 개입 없이 즉시 상품이 제공되는 것과 같이, 스마트 컨트랙트는 미리 정의된 로직에 따라 트랜잭션을 처리한다.

## 작동 원리와 블록체인 상호작용

스마트 컨트랙트는 중앙 서버가 아닌 블록체인이라는 분산 원장 위에 배포된다. 코드가 블록체인에 기록되는 순간부터는 임의로 수정할 수 없는 **불변성(Immutability)**을 가지며, 네트워크의 모든 노드가 실행 결과를 검증하므로 투명성과 신뢰성이 보장된다.

작동 프로세스는 다음과 같다.

1. 계약 로직 구현: 개발자가 특정 조건(If-Then)에 따른 비즈니스 로직을 코드로 작성한다.
2. 컴파일 및 배포: 작성된 코드는 바이트코드로 컴파일되어 블록체인 네트워크의 특정 주소로 전송된다.
3. 트리거 발생: 외부 사용자나 다른 계약이 해당 주소로 트랜잭션을 보내 함수를 호출한다.
4. 상태 전이: 조건이 맞으면 코드가 실행되어 블록체인의 상태(State)를 업데이트한다.

## 엔지니어링 측면에서의 EVM과 가스 시스템

이더리움과 같은 플랫폼에서 스마트 컨트랙트는 **이더리움 가상 머신(EVM)**이라는 런타임 환경에서 실행된다. 소프트웨어 엔지니어는 가용 리소스가 한정된 환경임을 인지해야 한다. 튜링 완전성(Turing Completeness)을 제공하지만, 무한 루프나 과도한 연산으로 인해 네트워크 전체가 마비되는 것을 방지하기 위해 **가스(Gas)**라는 비용 개념을 도입한다.

모든 명령어(Opcode)는 실행 시 가스를 소모하며, 트랜잭션 요청자는 이를 지불해야 한다. 효율적인 코드를 작성하는 것은 단순히 가독성의 문제를 넘어 실제 서비스 운영 비용 및 사용자 경험과 직결된다. 예를 들어, 반복문 내에서 상태 변수를 빈번하게 수정하는 설계는 지양해야 한다.

## Solidity를 이용한 데이터 저장 계약 예시

가장 널리 쓰이는 스마트 컨트랙트 언어인 Solidity를 사용하여 간단한 저장소 계약을 구현할 수 있다.

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract BasicStorage {
    uint256 private storedData;

    // 데이터를 저장하는 함수. 상태를 변경하므로 가스가 소모됨.
    function set(uint256 x) public {
        storedData = x;
    }

    // 데이터를 조회하는 함수. view 키워드는 상태를 변경하지 않음을 명시함.
    function get() public view returns (uint256) {
        return storedData;
    }
}

```

## 보안 엔지니어를 위한 체크리스트

사이버 보안 전문가의 시각에서 스마트 컨트랙트는 공격 표면이 매우 독특한 영역이다. 코드의 논리적 오류가 즉각적인 자산 탈취로 이어질 수 있으며, 패치 배포가 매우 까다롭기 때문이다.

**재진입 공격(Reentrancy Attack)**은 가장 대표적인 위협이다. 외부 계약으로 자금을 전송할 때, 상대방 계약의 폴백(Fallback) 함수가 실행되면서 원래의 함수가 종료되기 전에 다시 호출되는 취약점이다. 이를 방지하기 위해서는 모든 상태 변경을 외부 상호작용 이전에 수행하는 **Checks-Effects-Interactions** 패턴을 엄격히 준수해야 한다.

또한 가스 한도(Gas Limit)를 이용한 서비스 거부 공격(DoS) 가능성도 고려해야 한다. 거대한 배열을 순회하는 로직이 포함된 경우, 특정 시점에 가스 소모량이 블록 한도를 초과하여 해당 함수가 영원히 실행되지 못하는 상황이 발생할 수 있다.