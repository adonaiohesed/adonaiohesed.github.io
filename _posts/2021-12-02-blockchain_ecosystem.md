---
title: What is Blockchain?
tags:  Blockchain
key: page-blockchain_ecosystem
categories: [Cybersecurity, Blockchain]
author: hyoeun
math: true
mathjax_autoNumber: true
---

## What is Blockchain Technology?

Blockchain technology is an advanced database mechanism that allows for transparent information sharing within a business network. A blockchain database stores data in blocks that are linked together in a chain. Since the chain cannot be deleted or modified without network consensus, this data remains chronologically consistent. As a result, blockchain technology can be used to create an **immutable** or unchangeable ledger for tracking orders, payments, accounts, and other transactions. The system includes built-in mechanisms to prevent unauthorized transaction entries and ensure consistency across a shared view of these transactions.

## Why is Blockchain Important?

Traditional database technologies face several challenges when recording financial transactions. For example, consider a real estate sale. When money is exchanged, property ownership is transferred to the buyer. While both the buyer and seller can record the financial transaction individually, neither source can be implicitly trusted. A seller could easily claim they did not receive the money even if they did, and a buyer could equally claim they paid the money even if they did not.

To prevent potential legal issues, a trusted third party must oversee and verify the transaction. The presence of this central authority not only complicates the transaction but also creates a **single point of failure**. If the central database is compromised, both parties could suffer.

Blockchain mitigates these issues by creating a decentralized, tamper-proof system for recording transactions. In a real estate scenario, blockchain creates a single ledger for both the buyer and the seller. Every transaction must be approved by both parties and is automatically updated in both ledgers in real-time. Any corruption in past transactions would invalidate the entire ledger. These properties of blockchain technology have led to its use in various fields, including the creation of digital currencies like Bitcoin.

## How do Various Industries Use Blockchain?

Blockchain is an evolving technology being adopted in innovative ways across various industries. The following subsections describe several use cases:

### Energy

Energy companies use blockchain technology to create P2P energy trading platforms and streamline access to renewable energy. Examples include:

* **P2P Trading:** Blockchain-based energy companies have created trading platforms for electricity sales between individuals. Homeowners with solar panels use these platforms to sell excess solar energy to neighbors. The process is largely automated; smart meters generate transactions, and the blockchain records them.
* **Crowdfunding:** Initiatives allow users to sponsor and own solar panels in communities lacking energy access. Sponsors can receive rent from those communities once the solar panels are constructed.

### Finance

Traditional financial systems, such as banks and stock exchanges, use blockchain services to manage online payments, accounts, and market transactions. For example, **Singapore Exchange Limited**, an investment holding company providing financial transaction services across Asia, uses blockchain technology to build more efficient interbank settlement accounts. By introducing blockchain, they solved several challenges, including batch processing and manual reconciliation for thousands of financial transactions.

### Media and Entertainment

Companies use blockchain systems to manage copyright data. Copyright verification is critical for compensating artists fairly. Recording the sale or transfer of copyrighted content requires multiple transactions. **Sony Music Entertainment Japan** uses blockchain services to make digital rights management more efficient, successfully using blockchain strategies to improve productivity and reduce copyright processing costs.

### Retail

Retail companies use blockchain to track the movement of goods between suppliers and buyers. For instance, Amazon's retail arm filed a patent for a distributed ledger technology system to ensure all goods sold on the platform are authentic. Amazon sellers can map global supply chains by allowing participants like manufacturers, shippers, distributors, end-users, and secondary users to add events to the ledger after registering with a certificate authority.

---

## What are the Characteristics of Blockchain Technology?

Blockchain technology has the following key characteristics:

* **Decentralization:** This refers to the transfer of control and decision-making from a centralized entity (individual, organization, or group) to a distributed network. Decentralized networks use transparency to reduce the need for trust among participants.
* **Immutability:** This means something cannot be changed or modified. Once a transaction is recorded in the shared ledger, no participant can tamper with it. If a record contains an error, a new transaction must be added to reverse the mistake, and both transactions will be visible to the network.
* **Consensus:** Blockchain systems establish rules regarding participant agreement for recording transactions. A new transaction can be recorded only when the majority of network participants agree.

---

## What are the Core Components of Blockchain Technology?

### Distributed Ledger

The distributed ledger is the shared database of the blockchain network that stores transactions, similar to a shared file that everyone on a team can edit. However, in distributed ledger technology, there are strict rules about who can edit and how. Once an entry is recorded, it cannot be deleted.

### Smart Contracts

Businesses use smart contracts to self-manage business agreements without the need for third-party support. Smart contracts are programs stored on the blockchain system that execute automatically when predetermined conditions are met. They run "if-then" checks so that transactions can be completed with confidence. For example, a logistics company can have a smart contract that automatically triggers payment when goods arrive at a port.

### Public Key Cryptography

Public key cryptography is a security feature that uniquely identifies participants in a blockchain network. This mechanism generates two sets of keys for network members: a **Public Key** (common to everyone in the network) and a **Private Key** (unique to each member). Together, they unlock the data in the ledger.

---

## How Does Blockchain Work?

While the underlying mechanism is complex, here is a simplified overview of the steps involved:

1. **Step 1 – Recording the Transaction:** A transaction shows the movement of a physical or digital asset from one party to another in the network. It is recorded as a data block and includes details like who, what, when, where, why, and how much.
2. **Step 2 – Reaching Consensus:** The majority of participants in the decentralized network must agree that the recorded transaction is valid.
3. **Step 3 – Linking Blocks:** Once consensus is reached, the transaction is recorded in a block. A **cryptographic hash** is added to the new block, acting as a chain that links the blocks together. If the content of a block is modified, the hash value changes, providing a way to detect data tampering.
4. **Step 4 – Sharing the Ledger:** The system distributes the latest copy of the central ledger to all participants.

### The Blockchain Trilemma and Consensus Algorithms

Blockchain faces a "Trilemma" where it is difficult to achieve **Decentralization, Security, and Scalability (Speed)** simultaneously. This has led to various consensus mechanisms:

| **Consensus Algorithm** | **Features** | **Examples** |
| --- | --- | --- |
| **PoW** (Proof of Work) | Verified through computing power (mining). High security but slow. | Bitcoin, early Ethereum |
| **PoS** (Proof of Stake) | Verified by those who stake assets. Fast and eco-friendly. | **Ethereum 2.0**, Solana, Cardano |
| **PoA** (Proof of Authority) | Verified by specific trusted entities. Extremely fast. | Enterprise blockchains, Testnets |

---

## Types of Blockchain Networks

* **Public Blockchain:** Permissionless; anyone can join and has equal rights to read, edit, and verify. (e.g., Bitcoin, Ethereum).
* **Private Blockchain:** Controlled by a single organization (Managed Blockchain). They decide who can join and what permissions they have. (e.g., Ripple).
* **Hybrid Blockchain:** Combines elements of both. Companies can control access to specific data while keeping the rest public.
* **Consortium Blockchain:** Managed by a group of organizations who share responsibility for maintaining the blockchain and determining data access.

---

## Understanding Blockchain Protocols

Blockchain protocols are sets of rules that define network operations, data structures, and consensus. They can be categorized into Layer 1 (L1), Layer 2 (L2), and Interoperability protocols.

### 1. Layer 1 (L1) Protocols: The Base Layer

* **Bitcoin:** Uses the UTXO (Unspent Transaction Output) model and PoW. Its programming is limited to 'Bitcoin Script' to minimize the attack surface.
* **Ethereum:** Uses an account-based model and the EVM (Ethereum Virtual Machine). It supports Turing-complete smart contracts.
* **Solana:** Uses **Proof of History (PoH)** and the Sealevel parallel processing engine for maximum speed.

### 2. Layer 2 (L2) Protocols: Scalability Solutions

L2s inherit L1 security while increasing speed and reducing costs.

* **Optimistic Rollups:** Assume transactions are valid by default and use **Fraud Proofs** if a challenge arises. (e.g., Optimism, Arbitrum).
* **ZK Rollups (Zero-Knowledge):** Use **Validity Proofs** based on zero-knowledge proofs to mathematically prove transaction validity. (e.g., zkSync, Starknet).

### 3. Interoperability and Bridge Protocols

* **IBC (Inter-Blockchain Communication):** Used in the Cosmos ecosystem for direct communication between chains via light clients.
* **Cross-chain Bridges:** Use a "Lock and Mint" mechanism. **Security Note:** Bridges are high-value targets for hackers (e.g., multisig signature theft, relayer manipulation).

---

## Integrated Understanding of Blockchain Architecture and Security

For a security engineer, it is crucial to understand the different threat models at each layer of the architecture.

### 1. Network Layer (P2P Layer)

Nodes propagate transactions and blocks via the **Gossip Protocol**.

* **Security Concerns:** **Eclipse Attacks** (isolating a node) and **Sybil Attacks** (creating fake identities).

### 2. Consensus Layer

The engine that maintains integrity and solves the Byzantine Fault Tolerance (BFT) problem.

* **Security Concerns:** **51% Attacks** and understanding **Finality** (the point at which a transaction cannot be reversed).

### 3. Execution Layer (Virtual Machine Layer)

Where the code is executed and the **Global State** is updated.

* **Security Concerns:** Ensuring **Deterministic Execution** and analyzing the **Gas System** to prevent DoS attacks via resource exhaustion.

### 4. Application Layer (Smart Contract Layer)

Where the business logic resides. Most security incidents occur here.

* **Security Concerns:** Reentrancy, access control flaws, and the **Oracle Problem** (manipulation of external data sources).

### Cryptographic Tools for Integrity

* **Merkle Trees:** Used to verify data validity quickly using a 'Root Hash'.
* **Digital Signatures (ECDSA):** Used to verify ownership of assets through elliptic curve cryptography.

---

**Summary for Security Engineers:**
Blockchain security is a combination of infrastructure security (P2P, Consensus) and application security (VM, Contracts). The flow is:

1. User signs a transaction (**Application Layer**).
2. Transaction propagates via P2P (**Network Layer**).
3. Consensus decides block inclusion (**Consensus Layer**).
4. VM executes code and updates state (**Execution Layer**).

**Reference:** [AWS - What is Blockchain?](https://aws.amazon.com/ko/what-is/blockchain/)

---

## 블록체인 기술이란 무엇인가요?

블록체인 기술은 비즈니스 네트워크 내에서 정보를 투명하게 공유할 수 있도록 하는 고급 데이터베이스 메커니즘입니다. 블록체인 데이터베이스는 연쇄적으로 연결된 블록에 데이터를 저장합니다. 네트워크의 합의 없이 체인을 삭제하거나 수정할 수 없으므로 이 데이터는 시간 순서대로 일관성이 있습니다. 그 결과 블록체인 기술을 사용하여 주문, 결제, 계정, 기타 트랜잭션을 추적하기 위해 불변하거나 변경 불가능한 원장을 생성할 수 있습니다. 이 시스템에는 무단 트랜잭션 항목을 방지하고 이러한 트랜잭션의 공유 보기에서 일관되게 생성하는 기본 제공 메커니즘이 있습니다.

## 블록체인이 왜 중요한가요?

기존 데이터베이스 기술은 금융 거래를 기록하는 데 몇 가지 문제를 보입니다. 예를 들어 부동산 매각을 생각해 보겠습니다. 돈이 교환되면 부동산 소유권이 구매자에게 이전됩니다. 구매자와 판매자 모두 개별적으로 금전 거래를 기록할 수 있지만, 어느 출처도 신뢰할 수 없습니다. 판매자는 돈을 받았는데도 받지 못했다고 쉽게 주장할 수 있고, 구매자는 돈을 지불하지 않았는데도 돈을 지불했다고 똑같이 주장할 수 있습니다.

잠재적으로 일어날 수 있는 법적 문제를 방지하려면 신뢰할 수 있는 제3자가 거래를 감독하고 검증해야 합니다. 이 중앙 기관의 존재는 거래를 복잡하게 할 뿐만 아니라 단일 취약점을 만듭니다. 중앙 데이터베이스가 손상되면 양쪽 모두가 피해를 입을 수 있습니다.

블록체인은 거래를 기록하는 탈중앙화 변조 방지 시스템을 만들어 이러한 문제를 완화합니다. 부동산 거래 시나리오에서 블록체인은 구매자와 판매자 각각에 대해 하나의 원장을 생성합니다. 모든 거래는 양 당사자의 승인을 받아야 하며 두 원장에서 실시간으로 자동 업데이트됩니다. 과거 거래에서 일어난 모든 손상은 전체 원장을 손상시킵니다. 블록체인 기술의 이러한 속성은 Bitcoin과 같은 디지털 통화의 생성 등 다양한 분야의 사용으로 이어졌습니다.

## 다양한 산업에서 어떻게 블록체인을 사용하나요?

블록체인은 다양한 산업 분야에서 혁신적인 방식으로 채택되고 있는 발전 중인 기술입니다. 다음 하위 섹션에서는 다양한 산업 분야에서의 몇 가지 사용 사례를 설명합니다.

### 에너지

에너지 회사는 블록체인 기술을 사용하여 P2P 에너지 거래 플랫폼을 만들고 재생 에너지에 대한 액세스를 간소화합니다. 예를 들어 이렇게 사용될 수 있습니다.

- 블록체인 기반 에너지 회사는 개인 간의 전기 판매를 위한 거래 플랫폼을 만들었습니다. 태양광 패널을 보유한 주택 소유자는 이 플랫폼을 사용하여 초과 태양 에너지를 이웃에게 판매합니다. 프로세스는 대부분 자동화되어 있습니다. 스마트 미터는 거래를 생성하고 블록체인은 이를 기록합니다.
- 블록체인 기반 크라우드 펀딩 이니셔티브를 통해 사용자는 에너지 접근성이 부족한 커뮤니티에 태양광 패널을 후원하고 소유할 수 있습니다. 후원자는 태양광 패널이 건설되면 해당 커뮤니티에서 임대료를 받을 수도 있습니다.

### 금융

은행 및 증권 거래소와 같은 전통적인 금융 시스템은 블록체인 서비스를 사용하여 온라인 지불, 계정 및 시장 거래를 관리합니다. 예를 들어, 아시아 전역에 금융 거래 서비스를 제공하는 투자 지주 회사인 [Singapore Exchange Limited는](https://aws.amazon.com/solutions/case-studies/singapore-exchange-case-study/) 블록체인 기술을 사용하여 보다 효율적인 은행 간 결제 계좌를 구축합니다. 블록체인을 도입하여 수천 개의 금융 거래에 대한 일괄 처리 및 수동 조정을 비롯한 여러 문제를 해결했습니다.

### 미디어 및 엔터테인먼트

미디어 및 엔터테인먼트 회사는 블록체인 시스템을 사용하여 저작권 데이터를 관리합니다. 아티스트에게 공정하게 보상하기 위해서는 저작권 확인이 중요합니다. 저작권 콘텐츠의 판매 또는 양도를 기록하려면 여러 거래가 필요합니다. [소니 뮤직 엔터테인먼트 재팬은](https://www.forbes.com/sites/amazonwebservices/2019/11/19/how-sony-is-protecting-rights-of-digital-creators-using-blockchain-on-aws/) 블록체인 서비스를 사용하여 디지털 저작권 관리를 보다 효율적으로 만듭니다. 생산성을 향상시키고 저작권 처리 비용을 줄이기 위해 블록체인 전략을 성공적으로 사용했습니다.

### 소매

소매 회사는 블록체인을 사용하여 공급업체와 구매자 간의 상품 이동을 추적합니다. 예를 들어, Amazon의 소매 부분은 블록체인 기술을 사용하여 플랫폼에서 판매되는 모든 상품이 진품인지 확인하는 분산 원장 기술 시스템에 대한 특허를 출원했습니다. Amazon 판매자는 제조업체, 배송업체, 유통업체, 최종 사용자 및 2차 사용자와 같은 참여자가 인증 기관에 등록한 후 원장에 이벤트를 추가할 수 있도록 하여 글로벌 공급망을 매핑할 수 있습니다. 

## 블록체인 기술의 특징은 무엇인가요?

블록체인 기술에는 다음과 같은 주요 특징이 있습니다.

### 탈중앙화

블록체인의 탈중앙화는 중앙 집중식 엔터티(개인, 조직 또는 그룹)에서 분산 네트워크로 제어 및 의사 결정을 이전하는 것을 의미합니다. 분산형 블록체인 네트워크는 투명성을 사용하여 참여자 간의 신뢰에 대한 필요성을 줄입니다. 또한 해당 네트워크는 참여자가 네트워크의 기능을 저하시키는 방식으로 서로에 대한 권한이나 통제를 행사하는 것을 막습니다.

### 불변성

불변성은 무언가를 변경하거나 수정할 수 없음을 의미합니다. 누군가가 공유 원장에 거래를 기록하면 참여자는 거래를 조작할 수 없습니다. 거래 레코드에 오류가 포함된 경우, 실수를 되돌리기 위해 새 거래를 추가해야 하며 두 거래 모두 네트워크에 표시됩니다.

### 합의

블록체인 시스템은 거래 기록을 위한 참여자 동의에 관한 규칙을 설정합니다. 네트워크 참여자의 과반수가 동의한 경우에만 새로운 거래를 기록할 수 있습니다.

## 블록체인 기술의 핵심 구성 요소는 무엇인가요?

블록체인 아키텍처에는 다음과 같은 주요 구성 요소가 있습니다.

분산 원장

분산 원장은 팀의 모든 사람이 편집할 수 있는 공유 파일 등의 거래를 저장하는 블록체인 네트워크의 공유 데이터베이스입니다. 대부분의 공유 텍스트 편집기에서 편집 권한이 있는 모든 사용자는 전체 파일을 삭제할 수 있습니다. 그러나 분산 원장 기술에서는 누가 편집할 수 있고 어떻게 편집할 수 있는지에 대한 엄격한 규칙이 있습니다. 기록된 항목은 삭제할 수 없습니다.

### 스마트 계약

기업은 스마트 계약을 사용하여 서드 파티를 지원할 필요 없이 비즈니스 계약을 자체 관리합니다. 스마트 계약은 미리 정해진 조건이 충족되면 자동으로 실행되는 블록체인 시스템에 저장된 프로그램입니다. 거래에 확신을 가지고 완료할 수 있도록 if-then 검사를 실행합니다. 예를 들어, 물류 회사는 상품이 항구에 도착하면 자동으로 결제하는 스마트 계약을 할 수 있습니다.

### 퍼블릭 키 암호화

퍼블릭 키 암호화는 블록체인 네트워크 참여자를 고유하게 식별하는 보안 기능입니다. 이 메커니즘은 네트워크 구성원에 대해 두 세트의 키를 생성합니다. 하나는 네트워크의 모든 사람에게 공통적인 퍼블릭 키입니다. 다른 하나는 모든 구성원에게 고유한 프라이빗 키입니다. 프라이빗 키와 퍼블릭 키가 함께 작동하여 원장의 데이터 잠금을 해제합니다. 

예를 들어, John과 Jill은 네트워크의 두 구성원입니다. John은 프라이빗 키로 암호화된 거래를 기록합니다. Jill은 퍼블릭 키로 암호를 해독할 수 있습니다. 이런 식으로 Jill은 John이 거래를 했다고 확신합니다. John의 프라이빗 키가 변조된 경우 Jill의 퍼블릭 키는 작동하지 않았을 것입니다.

## 블록체인은 어떻게 작동하나요?

기본 블록체인 메커니즘은 복잡하지만, 다음 단계로 이루어진 간략한 개요를 보여드리겠습니다. 블록체인 소프트웨어는 다음 단계의 대부분을 자동화할 수 있습니다.

### 1단계 – 거래 기록

블록체인 거래는 블록체인 네트워크의 한 쪽에서 다른 쪽으로 물리적 또는 디지털 자산의 이동을 보여줍니다. 이는 데이터 블록으로 기록되며 다음과 같은 세부 정보를 포함할 수 있습니다.

- 거래에 참여한 사람은 누구인가요?
- 거래 중에 무슨 일이 일어났나요?
- 거래가 언제 발생했나요?
- 거래가 어디에서 발생했나요?
- 거래가 발생한 이유는 무엇인가요?
- 얼마나 많은 자산이 교환 되었나요?
- 거래 기간에 얼마나 많은 전제 조건이 충족되었나요?

### 2단계 – 합의 도출

분산 블록체인 네트워크의 참여자 대부분이 기록된 거래가 유효하다는 데 동의해야 합니다. 네트워크 유형에 따라 합의 규칙이 다를 수 있지만, 일반적으로 네트워크 시작 시 설정됩니다.

합의 알고리즘에는 다음과 같은 것들이 대표적으로 있습니다. 블록체인에는 **탈중앙화, 보안성, 확장성(속도)** 세 가지를 동시에 잡기 어렵다는 '트릴레마'가 있습니다. 그렇기에 다양한 방식이 나오게 된 것입니다.

| **합의 알고리즘**                  | **특징**                           | **대표 사례**              |
| ---------------------------- | -------------------------------- | ---------------------- |
| **PoW** (Proof of Work)      | 채굴기(연산력)를 통해 검증. 보안성이 높지만 느림.    | 비트코인, 초기 이더리움          |
| **PoS** (Proof of Stake)     | 자산(지분)을 많이 예치한 사람이 검증. 빠르고 친환경적. | **이더리움 2.0**, 솔라나, 에이다 |
| **PoA** (Proof of Authority) | 신뢰할 수 있는 특정 기관들이 검증. 매우 빠름.      | 기업용 블록체인, 테스트넷         |

### 3단계 – 블록 연결

참여자가 합의에 도달하면 블록체인 거래가 원장 페이지와 동일한 블록에 기록됩니다. 거래와 함께 암호화 해시도 새 블록에 추가됩니다. 해시는 블록을 함께 연결하는 체인 역할을 합니다. 블록의 내용이 의도적 또는 비의도적으로 수정되면 해시 값이 변경되어 데이터 변조를 감지하는 방식을 제공합니다. 

따라서 블록과 체인은 안전하게 연결되며 수정될 수 없습니다. 각 추가 블록은 이전 블록 및 전체 블록체인의 검증을 강화합니다. 이는 나무 블록을 쌓아 탑을 만드는 것과 같습니다. 블록은 맨 위에만 쌓을 수 있으며, 탑 중앙에서 블록을 제거하면 탑 전체가 무너집니다.

### 4단계 – 원장 공유

시스템은 중앙 원장의 최신 사본을 모든 참가자에게 배포합니다.

## 블록체인 네트워크의 유형에는 무엇이 있나요?

블록체인에는 네 가지의 주요 탈중앙화 또는 분산 네트워크 유형이 있습니다.

### 퍼블릭 블록체인 네트워크

퍼블릭 블록체인은 권한이 없으며 모든 사람이 블록체인에 참여할 수 있습니다. 블록체인의 모든 구성원은 블록체인을 읽고, 편집하고, 검증할 동등한 권리를 갖습니다. 사람들은 주로 퍼블릭 블록체인을 사용하여 Bitcoin, Ethereum 및 Litecoin과 같은 암호화폐를 교환하고 채굴합니다. 

### 프라이빗 블록체인 네트워크

단일 조직이 관리형 블록체인이라고도 하는 프라이빗 블록체인을 제어합니다. 해당 조직에서 누가 구성원이 될 수 있고 네트워크에서 어떤 권한을 가질 수 있는지 결정합니다. 프라이빗 블록체인은 접근 제한이 있기 때문에 부분적으로만 분산되어 있습니다. 기업용 디지털 화폐 교환 네트워크인 Ripple은 프라이빗 블록체인의 한 예입니다.

### 하이브리드 블록체인 네트워크

하이브리드 블록체인은 프라이빗 및 퍼블릭 네트워크의 요소를 결합합니다. 회사는 퍼블릭 시스템과 함께 권한 기반 프라이빗 시스템을 설정할 수 있습니다. 이러한 방식으로 블록체인에 저장된 특정 데이터에 대한 액세스를 제어하면서 나머지 데이터는 공개적으로 유지합니다. 회사에서 스마트 계약을 사용함으로써 퍼블릭 회원은 프라이빗 거래가 완료되었는지 확인할 수 있습니다. 예를 들어, 하이브리드 블록체인은 은행 소유 통화를 프라이빗으로 유지하면서 디지털 통화에 대한 퍼블릭 액세스 권한을 부여할 수 있습니다.

### 컨소시엄 블록체인 네트워크

조직의 그룹은 컨소시엄 블록체인 네트워크를 관리합니다. 사전 선택된 조직은 블록체인을 유지 관리하고 데이터 액세스 권한을 결정하는 책임을 공유합니다. 많은 조직이 공통의 목표를 갖고 공동 책임의 혜택을 받는 산업은 종종 컨소시엄 블록체인 네트워크를 선호합니다. 예를 들어, 글로벌 해운 비즈니스 네트워크 컨소시엄은 해운 산업을 디지털화하고 해양 산업 운영자 간의 협업을 증대하는 것을 목표로 하는 비영리 블록체인 컨소시엄입니다.

## 블록체인 프로토콜이란 무엇인가요?

블록체인 프로토콜이라는 용어는 애플리케이션 개발에 사용할 수 있는 다양한 유형의 블록체인 플랫폼을 나타냅니다. 각 블록체인 프로토콜은 기본 블록체인 원칙을 특정 산업 또는 애플리케이션에 맞게 조정합니다.  블록체인 프로토콜은 네트워크의 운영 규칙, 데이터 구조, 합의 방식 및 자산 이동 방식을 정의하는 규약의 집합입니다. 프로토콜은 크게 레이어 1(L1), 레이어 2(L2), 그리고 상호운용성 프로토콜로 구분할 수 있습니다.

### 1. 레이어 1 (Layer 1) 프로토콜: 베이스 레이어

레이어 1은 자체적인 합의 알고리즘과 보안 모델을 가진 독립적인 블록체인 네트워크입니다.

**비트코인 (Bitcoin)**

- **기술적 핵심**: UTXO(Unspent Transaction Output) 모델과 PoW 합의를 사용합니다. 프로그래밍 기능은 'Bitcoin Script'라는 비튜링 완전 언어로 제한되어 있어 공격 표면이 좁지만 복잡한 로직 구현이 어렵습니다.
    
- **보안 이슈**: 해시 파워 집중화로 인한 51% 공격 위험과 스크립트의 논리적 한계 내에서의 트랜잭션 변조 가능성을 점검해야 합니다.
    

**이더리움 (Ethereum)**

- **기술적 핵심**: 계정 기반 모델(Account-based)과 EVM을 사용하며 PoS 합의를 채택하고 있습니다. 튜링 완전한 스마트 컨트랙트를 지원하여 복잡한 DApp 생태계를 구성합니다.
    
- **보안 이슈**: 스마트 컨트랙트의 논리적 결함(재진입, 권한 오용 등)과 스테이킹 노드의 슬래싱 위험, 그리고 검증자 노드의 MEV(Maximal Extractable Value) 추출 전략을 분석해야 합니다.
    

**솔라나 (Solana)**

- **기술적 핵심**: 역사 증명(PoH, Proof of History)과 병렬 처리 엔진인 Sealevel을 사용합니다. 트랜잭션의 순서를 타임스탬프화하여 합의 속도를 극대화합니다.
    
- **보안 이슈**: 높은 하드웨어 성능 요구로 인한 중앙화 위험과 Sealevel 엔진의 메모리 관리 및 런타임 취약점을 점검해야 합니다.
    

### 2. 레이어 2 (Layer 2) 프로토콜: 확장성 솔루션

L1의 보안을 상속받으면서 트랜잭션 처리 속도를 높이고 비용을 절감하기 위해 구축된 상위 프로토콜입니다. 주로 롤업(Rollup) 기술이 핵심입니다.

**옵티미스틱 롤업 (Optimistic Rollups)**

- **기술적 핵심**: 모든 트랜잭션이 기본적으로 유효하다고 가정(Optimistic)하고 처리합니다. 만약 부정한 트랜잭션이 발견되면 **사기 증명(Fraud Proof)**을 통해 이를 취소합니다. 대표적으로 Optimism과 Arbitrum이 있습니다.
    
- **보안 이슈**: L1으로 최종 확정되기까지의 분쟁 기간(Dispute Period, 보통 7일) 동안 발생할 수 있는 데이터 가용성(Data Availability) 문제와 시퀀서(Sequencer)의 중앙화 공격 가능성을 분석해야 합니다.
    

**ZK 롤업 (Zero-Knowledge Rollups)**

- **기술적 핵심**: 영지식 증명을 기반으로 한 **유효성 증명(Validity Proof)**을 사용합니다. 트랜잭션 묶음이 올바르다는 것을 수학적으로 증명하여 L1에 제출하므로 즉각적인 확정성을 가집니다. 대표적으로 zkSync, Starknet이 있습니다.
    
- **보안 이슈**: 영지식 증명 회로(Circuit) 설계 시의 수학적 오류나 증명 생성기(Prover)의 가용성 문제를 핵심적으로 다뤄야 합니다.
    

### 3. 상호운용성 및 브릿지 프로토콜 (Interoperability Protocols)

서로 다른 블록체인 네트워크 간에 자산과 정보를 이동시키기 위한 통신 규약입니다.

**IBC (Inter-Blockchain Communication)**

- **기술적 핵심**: 코스모스(Cosmos) 생태계에서 사용되는 프로토콜로, 신뢰 기반의 중계자 없이 체인 간에 직접 패킷을 주고받습니다. 라이트 클라이언트를 통해 상대 체인의 헤더를 검증합니다.
    
- **보안 이슈**: 상대 체인의 합의 붕괴가 연결된 전체 생태계로 전이될 수 있는 위험(Chain Contagion)을 고려해야 합니다.
    

**크로스체인 브릿지 (Cross-chain Bridges)**

- **기술적 핵심**: 한 체인에서 자산을 잠그고(Lock), 다른 체인에서 동일한 가치의 자산을 발행(Mint)하는 방식을 주로 사용합니다.
    
- **보안 이슈**: 브릿지는 블록체인 보안 사고의 가장 큰 비중을 차지합니다. 잠금된 자산을 보관하는 멀티시그(Multisig) 지갑의 서명 탈취, 메시지 릴레이어(Relayer) 조작, 그리고 민팅 로직의 검증 미흡 등이 주요 공격 대상입니다.
## 블록체인 기술은 어떻게 발전했나요?

블록체인 기술은 1970년대 후반 Ralph Merkle이라는 컴퓨터 과학자가 해시 트리 또는 Merkle 트리에 대한 특허를 낸 데 뿌리를 두고 있습니다. 이 트리는 암호화된 블록을 연결하여 데이터를 저장하는 컴퓨터 과학 구조입니다. 1990년대 후반, Stuart Haber와 W. Scott Stornetta는 Merkle 트리를 사용하여 문서 타임스탬프를 변경할 수 없는 시스템을 구현했습니다. 이것이 블록체인 역사상 최초의 사례였습니다.

이 기술은 다음 3세대에 걸쳐 계속 발전해 왔습니다.

### 1세대 – Bitcoin ​​및 기타 가상 화폐

2008년에 Satoshi Nakamoto라는 이름으로만 알려진 익명의 개인 또는 그룹이 블록체인 기술을 현대적인 형태로 설명했습니다. Bitcoin 블록체인에 대한 Satoshi의 아이디어에서 Bitcoin ​​거래는 1MB의 정보 블록을 사용했습니다. Bitcoin 블록체인 시스템의 많은 기능은 오늘날에도 블록체인 기술의 핵심으로 남아 있습니다.

### 2세대 – 스마트 계약

1세대 화폐가 등장하고 몇 년 후, 개발자들은 암호화폐를 넘어 블록체인 애플리케이션을 검토하기 시작했습니다. 예를 들어, Ethereum 개발자들은 자산 전송 거래에 블록체인 기술을 사용하기로 결정했습니다. 그들의 스마트 계약 기능이라는 중요한 공헌을 했습니다.

### 3세대 – 미래

기업이 새로운 애플리케이션에 관심을 갖고 구현함에 따라 블록체인 기술은 계속 진화하고 성장하고 있습니다. 기업은 규모와 연산의 한계를 해결하고 있으며, 진행 중인 블록체인 혁명에 잠재되어 있는 기회는 무한합니다.

## 블록체인 기술의 이점은 무엇인가요?

블록체인 기술은 자산 거래 관리에 많은 이점을 제공합니다. 다음 하위 섹션에서 몇 가지를 나열했습니다.

### 고급 보안

블록체인 시스템은 현대 디지털 거래에 필요한 높은 수준의 보안과 신뢰를 제공합니다. 누군가가 가짜 돈을 생성하기 위해 기본 소프트웨어를 조작할 것이라는 두려움은 언제나 존재합니다. 하지만 블록체인은 암호화, 탈중앙화 및 합의의 세 가지 원칙을 사용하여 변조가 거의 불가능하며 고도로 안전한 기본 소프트웨어 시스템을 생성합니다. 단일 실패 지점이 없으며 단일 사용자가 거래 기록을 변경할 수 없습니다.

### 효율성 향상

B2B 거래는 특히 규정 준수 및 서드 파티 규제 기관이 관련된 경우 시간이 많이 걸리고 운영상의 병목 ​​현상을 일으킬 수 있습니다. 블록체인의 투명성과 스마트 계약은 이러한 비즈니스 거래를 더 빠르고 효율적으로 만듭니다.

### 빠른 감사

기업은 감사 가능한 방식으로 전자 거래를 안전하게 생성, 교환, 아카이브 및 재구성할 수 있어야 합니다. 블록체인 기록의 시간 순서는 변경이 불가능하므로 모든 기록은 항상 시간순으로 정렬됩니다. 이러한 데이터 투명성으로 인해 감사 처리가 훨씬 빨라집니다.

## Bitcoin과 블록체인의 차이점은 무엇인가요?

Bitcoin과 블록체인은 같은 의미로 사용될 수 있지만, 둘은 다릅니다. Bitcoin은 블록체인 기술이 처음 적용된 사례이기 때문에 사람들은 무심코 Bitcoin을 블록체인과 동일시하기 시작했습니다. 그러나 블록체인 기술이 적용된 사례는 Bitcoin ​​외에도 많이 있습니다.

Bitcoin은 중앙 집중식 통제 없이 작동하는 디지털 통화입니다. Bitcoin은 원래 온라인으로 금융 거래를 하기 위해 만들어졌지만, 현재는 USD나 유로 등의 다른 글로벌 통화로 환전할 수 있는 디지털 자산으로 여겨집니다. 퍼블릭 Bitcoin ​​블록체인 네트워크는 중앙 원장을 생성하고 관리합니다. 

### Bitcoin 네트워크

퍼블릭 원장은 모든 Bitcoin ​​거래를 기록하고, 전 세계 서버들은 이 원장의 사본을 보유합니다. 서버는 은행과 같습니다. 은행은 각 은행에서 고객이 교환하는 돈에 대해서만 알고 있지만, Bitcoin 서버는 전 세계의 모든 단일 Bitcoin 거래에 대해 알고 있습니다.

여분의 컴퓨터가 있는 사람은 이러한 서버 중 하나(노드)를 설정할 수 있습니다. 이는 은행 계정 대신 자신의 Bitcoin ​​은행을 여는 것과 같습니다.

### Bitcoin 채굴

퍼블릭 Bitcoin ​​네트워크에서 회원들은 암호화 방정식을 풀어 새로운 블록을 생성함으로써 암호화폐를 채굴합니다. 시스템은 각각의 새로운 거래를 네트워크에 공개적으로 브로드캐스트하고 노드에서 노드로 공유합니다. 약 10분마다 채굴자는 이러한 거래를 새로운 블록으로 수집해서 Bitcoin의 최종 거래 장부 역할을 하는 블록체인에 영구적으로 추가합니다.

채굴은 상당한 컴퓨팅 리소스를 필요로 하고 소프트웨어 프로세스의 복잡성으로 인해 시간이 오래 걸립니다. 그 대가로 채굴자는 소량의 암호화폐를 얻습니다. 채굴자는 거래를 기록하고 거래 수수료를 징수하는 현대적인 사무원의 역할을 합니다.

네트워크의 모든 참여자는 블록체인 암호화 기술을 사용하여 누가 어떤 코인을 소유하고 있는지에 대한 합의에 도달합니다.

## 데이터베이스와 블록체인의 차이점은 무엇인가요?

블록체인은 일반 데이터베이스보다 많은 기능을 가진 특별한 유형의 데이터베이스 관리 시스템입니다. 다음 목록에서 기존 데이터베이스와 블록체인 간의 몇 가지 중요한 차이점을 설명합니다.

- 블록체인은 기존 데이터에 대한 신뢰를 손상시키지 않으면서 제어를 분산시킵니다. 이는 다른 데이터베이스 시스템에서 불가능합니다.
- 거래에 관련된 회사는 전체 데이터베이스를 공유할 수 없습니다. 하지만 블록체인 네트워크에서는 각 회사에 원장 사본이 있으며, 시스템은 자동으로 두 원장의 일관성을 유지합니다.
- 대부분의 데이터베이스 시스템에서는 데이터를 편집하거나 삭제할 수 있지만, 블록체인에서는 데이터를 삽입만 할 수 있습니다.

## 블록체인은 클라우드와 어떻게 다른가요?

클라우드라는 용어는 온라인으로 액세스할 수 있는 컴퓨팅 서비스를 의미합니다. 클라우드에서 서비스형 소프트웨어(SaaS), 서비스형 제품(PaaS) 및 서비스형 인프라(IaaS)에 액세스할 수 있습니다. 클라우드 공급자는 하드웨어 및 인프라를 관리하고, 인터넷을 통해 이러한 컴퓨팅 리소스에 대한 액세스를 제공합니다. 또한, 데이터베이스 관리 외에 많은 추가 리소스를 제공합니다. 퍼블릭 블록체인 네트워크에 가입하려면 원장 사본을 저장할 하드웨어 리소스를 제공해야 합니다. 이 목적을 위해 클라우드의 서버를 사용할 수도 있습니다. 일부 클라우드 공급자는 클라우드에서 완전한 서비스형 블록체인(BaaS)을 제공하기도 합니다.

## 서비스형 블록체인이란 무엇인가요?

서비스형 블록체인(BaaS)은 서드 파티가 클라우드에서 제공하는 관리형 블록체인 서비스입니다. 클라우드 공급자가 인프라 및 블록체인 구축 도구를 제공하는 동안 귀하는 블록체인 애플리케이션 및 디지털 서비스를 개발할 수 있습니다. 기존 블록체인 기술을 사용자 지정하기만 하면 블록체인을 더 빠르고 효율적으로 도입할 수 있습니다.

## 블록체인 계층 구조와 보안의 통합적 이해

블록체인 에코시스템을 체계적으로 이해하려면 이를 하나의 거대한 분산 시스템 아키텍처로 분해해야 합니다. 보안 엔지니어는 각 계층에서 발생하는 위협 모델이 다르다는 점에 주목해야 합니다. 블록체인은 크게 네트워크, 합의, 실행, 애플리케이션 계층으로 나뉩니다.

### 1. 네트워크 계층 (P2P Network Layer)

블록체인의 최하단에는 전 세계에 흩어진 노드들이 서로 데이터를 주고받는 P2P 네트워크가 존재합니다. 중앙 서버 없이 모든 노드가 클라이언트이자 서버 역할을 수행합니다.

**기술적 핵심**
노드들은 가십 프로토콜(Gossip Protocol)을 통해 트랜잭션과 블록 정보를 전파합니다. 새로운 트랜잭션이 발생하면 인접한 노드에게 전달되고, 이는 다시 전체 네트워크로 퍼져나갑니다.

**보안 고려 사항**

* **이클립스 공격(Eclipse Attack)**: 공격자가 특정 노드의 모든 유입/유출 연결을 장악하여 격리시킨 뒤, 조작된 블록 정보를 제공하는 공격입니다.
* **Sybil 공격**: 한 명의 공격자가 수많은 가짜 노드를 생성하여 네트워크의 의사결정이나 데이터 전파를 왜곡합니다.

### 2. 합의 계층 (Consensus Layer)

분산된 환경에서 "어떤 블록이 정당한가"를 결정하는 규칙입니다. 블록체인의 무결성을 유지하는 가장 중요한 엔진입니다.

**기술적 핵심**
합의 알고리즘은 비잔틴 장애 허용(BFT) 문제를 해결하기 위해 설계되었습니다.

* **PoW (Proof of Work)**: 복잡한 수학 문제를 풀어 연산력을 증명한 노드에게 블록 생성권을 부여합니다.
* **PoS (Proof of Stake)**: 자산(지분)을 스테이킹한 양에 비례하여 검증자로 선정될 확률을 높입니다.

**보안 고려 사항**

* **51% 공격**: 특정 집단이 전체 연산력이나 지분의 과반수를 차지하여 트랜잭션을 되돌리거나(Reorg) 이중 지불을 수행하는 위협입니다.
* **파이널리티(Finality)**: 트랜잭션이 절대로 번복될 수 없는 상태가 되는 시점을 이해해야 하며, 보안 사고 발생 시 이 시점이 분석의 기준이 됩니다.

### 3. 실행 계층 (Virtual Machine Layer)

블록체인이 단순한 데이터 저장소를 넘어 '컴퓨터'처럼 동작하게 만드는 계층입니다. 이더리움의 EVM(Ethereum Virtual Machine)이 대표적입니다.

**기술적 핵심**
트랜잭션에 포함된 코드를 실행하고, 블록체인의 전역 상태(Global State)를 업데이트합니다. 이 과정에서 **계정 기반 모델(Account-based Model)**과 **UTXO 모델**의 차이를 이해하는 것이 중요합니다. 계정 기반 모델은 은행 잔고와 유사하며, UTXO(비트코인 방식)는 미사용 수표를 주고받는 것과 유사합니다.

**보안 고려 사항**

* **결정론적 실행(Deterministic Execution)**: 모든 노드에서 동일한 코드를 실행했을 때 결과가 반드시 같아야 합니다. 보안 전문가는 가상 머신의 연산 오류나 비결정론적 요소가 침투할 수 있는지 분석해야 합니다.
* **가스(Gas) 시스템**: 무한 루프와 같은 자원 낭비 공격을 막기 위한 비용 모델입니다. 가스 소모량 최적화 실패는 DoS 취약점으로 이어집니다.

### 4. 애플리케이션 계층 (Smart Contract Layer)

사용자가 직접 상호작용하는 스마트 컨트랙트와 DApp(Decentralized Application)이 위치하는 곳입니다. 대부분의 보안 사고가 이 계층의 논리적 결함에서 발생합니다.

**기술적 핵심**
Solidity나 Rust와 같은 언어로 작성된 비즈니스 로직입니다. 이 코드는 바이트코드로 컴파일되어 실행 계층(VM)에서 돌아갑니다.

**보안 고려 사항**

* **비즈니스 로직 취약점**: 재진입성, 권한 제어 미흡, 반올림 오류 등 코드 레벨의 버그입니다.
* **오라클 문제(Oracle Problem)**: 블록체인 외부 데이터(예: 현재 달러 환율)를 가져올 때, 그 데이터 소스가 조작될 경우 컨트랙트 전체가 붕괴됩니다.

### 계층별 데이터 무결성을 위한 암호학 도구

위의 계층들이 유기적으로 연결되기 위해 두 가지 핵심 암호 기술이 사용됩니다.

**머클 트리 (Merkle Tree)**
네트워크와 실행 계층에서 데이터의 유효성을 검증할 때 사용됩니다. 수천 개의 트랜잭션을 단 하나의 '루트 해시'로 요약할 수 있어, 특정 데이터가 위변조되지 않았음을 매우 빠르게 증명할 수 있습니다.

**디지털 서명 (ECDSA)**
애플리케이션 계층에서 사용자가 트랜잭션을 생성할 때 사용됩니다. "이 돈을 보내는 사람이 실제 소유주가 맞는지"를 타원곡선 암호학을 통해 검증합니다. 보안 엔지니어는 서명 검증 로직이 생략되거나, 서명 재사용(Replay Attack)이 가능한지 확인해야 합니다.

### 보안 엔지니어를 위한 기술적 요약

블록체인 보안은 하위 계층(P2P, 합의)에서의 인프라 보안과 상위 계층(VM, 컨트랙트)에서의 애플리케이션 보안이 결합된 형태입니다. 입문 단계에서는 다음의 흐름을 기억하십시오.

1. 사용자가 디지털 서명으로 트랜잭션을 생성한다. (애플리케이션 계층)
2. P2P 네트워크를 통해 노드들에게 전파된다. (네트워크 계층)
3. 합의 알고리즘에 의해 블록에 포함될지 결정된다. (합의 계층)
4. 가상 머신이 코드를 실행하여 상태를 변경한다. (실행 계층)

이 흐름 중 어느 한 곳이라도 신뢰가 깨지면 블록체인 전체의 보안성이 상실됩니다.

Reference
https://aws.amazon.com/ko/what-is/blockchain/