---
title: Lightning Network
tags: Lightning-Network Blockchain
key: page-lightning_network
categories: [Cybersecurity, Blockchain]
author: hyoeun
mathjax: true
mathjax_autoNumber: true
---

## Bitcoin
* Bitcoin is based on the premise that you don't need to trust anyone, recording all transaction details in blocks and distributing them equally to all network participants. You can verify manipulation by comparing distributed blocks, and the process of transmitting this information across the network is called broadcasting.
* Bitcoin transaction records are created when miners generate new blocks through proof of work and broadcast these blocks to nodes worldwide.
* Because the network is decentralized, transactions take longer and fees are more expensive.
* These aspects create an environment where Bitcoin cannot be used for everyday payments, leading to new designs like Bitcoin Cash, but even these cannot solve Bitcoin's fundamental problems, which is why the Lightning Network emerged as a solution.

## Background of the Lightning Network
* Bitcoin blocks are set to be generated once every 10 minutes, and each block can only process about 7 transactions per second. Compared to Visa card's millions of transactions per second, this transaction volume is too low for real-world usage levels. Therefore, to handle current transaction demands, we need scalability that can meet the same transaction volume.
* While increasing the block size itself could increase the number of transactions, this would mean only computers capable of performing the related calculations could effectively participate. Since very few computers can handle this level, it's practically impossible. The Lightning Network was developed to solve this problem.
* Lightning is a payment channel. By creating payment channels outside the blockchain, when transaction parties have their public keys, they can record their transactions.
* When we say Bitcoin generates one block every 10 minutes, it means it takes 10 minutes to confirm a Bitcoin transaction. Transaction fees ranged from 5 to 10 cents per transaction, making micropayments impossible. The Lightning Network enables immediate transactions at speeds of thousands to millions per second with fees of 1 cent or free.

## Payment Routing
* Once users create payment channels with each other, each person in the network will have channels with different people, and if these connections are linked, transactions can be sent between two different people via the shortest route through routing, even without direct channel connections.
* However, this network won't work unless each independent person has enough money to cover the amount being sent.
* It feels like it happens simultaneously rather than sequentially. Therefore, you need to find the shortest network route that satisfies the amount of money each person has.
* The goals are availability (user funds must always be available) and connectivity (network participants must be able to send funds to other participants).

## Lightning Channel
* In the payment channel network, transactions are conducted in mili-satoshi units (1/1000 of a satoshi).
* To create a channel between two users, a funding transaction (funding tx) must be sent to the Bitcoin network. The funding tx is similar to a regular Bitcoin transaction, with transaction records of both users held as collateral, and the transaction can only be released with the private keys of both people through a locking script.
* The channel creation is considered complete when the funding tx is sent to the Bitcoin network and included in the blockchain.
* A commitment tx in the Lightning Network takes the channel created by the funding tx as input, locks balance information for each user with their public key, and allows each party to take their output so they can retrieve their balance at any time.
* The commitment tx can be seen as Layer 2 of the Lightning Network, where balances exchanged between parties are continuously updated through the process above.
* Finally, the channel is closed through agreement between the two users.

## Funding Transaction
* Open a channel.
* There is a multi-signature address (walnut). When you put Bitcoin in the wallet and open a channel, private keys are given to two people, and you only pay the Bitcoin fee once, allowing transactions on the Lightning channel.

---

## 비트코인
* 비트코인에서는 그 누구도 믿지 않아도 되는 것을 가정하고 모든 거래 내용을 블록에 기록하고 블록을 네트워크에 참여한 사람에게 똑같이 뿌린다. 분산된 블록과 대조를 해서 조작 여부를 확인 할 수 있고 네트워크로 알 수 있도록 전송하는 과정을 브로드 캐스팅이다.
* 비트코인의 거래 기록은 채굴자가 작업 증명으로 새로운 블록을 생성하고 그 블록을 전 세계 노드에 브로드 캐스팅 한다.
* 네트워크가 분산되어 있기 때문에 시간도 오래 걸리고 수수료도 비싼 것이다.
* 이러한 점들은 일상생활에서 비트코인을 사용하여 결제할 수 없는 환경을 만들고 비트코인 캐시와 같은 새로운 디자인이 나오지만 여전히 비트코인 본질의 문제를 해결 할 수 없어 그 해결책으로 lightning network가 나왔다.

## Lightning Network가 나오게 된 배경
* 비트코인의 블록은 10분에 1개가 생성되도록 설정되어 있고 그 블록 안에서 거래 할 수 있는 양은 초당 7개의 거래밖에 할 수 없다. Visa 카드의 거래량이 1초에 수백만건에 비해 거래량이 너무 현저히 낮아서 실제와 동일한 수준의 거래는 불가능하다. 따라서 현재와 같은 거래를 위해서는 같은 거래량을 충족시킬 수 있는 확장성이 되어야 한다.
* 10분에 1개가 생성되는 블록 자체의 크기를 키워서 트랙젝션을 늘릴 수 있겠지만 그렇게 되면 그것에 관한 연산을 할 수 있는 컴퓨터만 실질적으로 이용될 수 있다. 이 정도의 컴퓨터는 거의 없는 수준이라서 현실적으로 불가능하다. 이러한 문제를 해결하기 위한 것이 lightning network이다.
* Lightning이란 payment channel이다. 블록체인 바깥에 결제 채널을 만들어서 거래 당사자들의 공개키가 있을때 그들의 거래 기록을 남길 수 있게 된다.
* 비트코인이 10분에 1개가 생성된다는 말은 비트코인 거래가 확인되는데 10분이 걸린다는 말이다. 그리고 거래 수수료는 거래당 5센트에서 10센트 사이로 실행되어 소액 결제가 불가능했다. 그렇기에 라이트닝 네트워크를 통해 1센트 또는 무료의 수수료로 초당 수천에서 수백만의 속도로 즉각 거래를 가능하게 했다.

## Payment Routing
* 각 유저들이 서로의 payment channel을 만들고 나면 네트워크 안에 각 사람마다 서로 다른 사람과의 채널이 형성 될 것이고 그 형성이 이어져 있다면 직접 채널 연결을 하지 않아도 routing을 통해 서로 다른 두 사람에게 최단거리로 트랜젝션을 보낼 수 있게 된다.
* 하지만 보내려는 돈에 관해 모든 각자의 독립적인 사람이 그만큼의 돈을 가지고 있지 않으면 이 네트워크는 작동하지 않는다.
* 순차적으로 일어나는 것이 아니라 동시에 일어나는 느낌이다. 따라서 최단의 거리를 구하되 각자가 가지고 있는 돈의 양에 대해 만족하는 네트워크의 루트를 찾아야한다.
* 목표는 가용성(사용자 자금이 항상 사용 가능해야 함)과 연결성(네트워크 참여자가 다른 참여자에게 자금을 보낼 수 있어야 함)이다.

## Lightning Channel
* 페이먼트 채널 네트워크에서는 mili-satoshi(1 사토시의 1/1000) 단위로 거래가 이루어진다.
* 두 유저간에 채널을 생성하기 위해서는 비트코인 네트워크에 fundng transaction(funding tx)를 전송해야 한다. funding tx는 일반적인 비트코인 트랜잭션과 같은 형태이며 여기 안에 있는 두 유저의 거래 내역이 담보로 붙잡혀 있으며 그 거래는 두 사람 모두의 private key로만 해제할 수 있는 locking script이다.
* 위에서 만들어진 Funding tx가 비트코인 네트워크에 전송이 되고 블록체인에 포함되는 것 까지의 과정을 채널 생성이 완료되었다고 표현한다.
* Commitment tx는 라이트닝 네트워크에서 funding tx가 생선한 채널을 input으로 받아 각 유저의 public key로 각자에 관한 잔액 정보를 잠구고 서로 그 아웃풋을 가져가면 자기 자신은 그 잔액을 언제든 가져 갈 수 있게 된다.
* Commiment tx가 라이트닝 네트워크의 Layer 2라고 보면 되고 거기서 잔액에 대해 서로 주고 받은 값들을 계속 새로이 위의 과정을 통해 업데이트 시킨다.
* 마지막으로 두 유저간의 합의를 통해 closing the channel 과정을 지난다.

## Funding transaction
* Open a channel.
* Multi siginiture address(walnut)가 있다. 월넷에 비트코인을 넣고 채널을 개설하면 두명에게 비밀키가 주어지고 비트코인 수수료는 한 번만 내고 라이트닝 채널에서 거래가 가능하다.