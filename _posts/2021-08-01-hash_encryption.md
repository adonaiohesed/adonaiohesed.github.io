---
title: Hash & Encryption
tags: Hashing Encryption Cryptography
key: page-hash_encryption
categories: [Cybersecurity, Cryptography]
author: hyoeun
mathjax: true
mathjax_autoNumber: true
---

## Hash and encryption
* 해시 알고리즘을 거쳐 생성된 결과물을 digest라고 부른다.
* Hash는 단방향이고 encryption은 양방향이다.
* Hash의 종류에는 MD5, SHA-1, SHA-256, SHA-512, WHIRLPOOL등이 있으나 PBKDF2(Password-Based Key Derivation Function), bcrypt, and scrypt algorithms을 쓰는게 좋다.
* 좋은 Hash 함수란 simple uniform hasihng을 만족하는 함수인데 중복이 없이 확률적으로 슬롯에 골고루 나눠지는 것이다.
* Hash는 encryption에 비해 연산이 빠르다.

## Encryption
### Symmetric
* DES, 3DES, AES

### Asymmetric
* RSA, ElGamal, DSS

## HMAC
* 인증에 관해 key가 필요한 keyed-hashing이라고 할 수 있다.
* MD5, SHA-1과 같은 해시기반 함수를 이용해서 만든다.
* 서로 공유하고 있는 shared key로 message를(key + message) HMAC 알고리즘으로 해시값을 생성하고 digest를 메시지와 같이 보낸다. 받는 측에서는 받은 messsaged와 본인이 가지고 있는 key로 다시 해시값을 생성하여 받은 digest와 비교한다.
* <img src="/assets/images/hmac.png" width="600px">
* key 없이 메시지의 위변조가 불가능하지만 원문 message를 보호하기 위해서 HTTPS와 같은 안전한 전송채널을 사용하는 것이 좋다.
* 취약점으로는 메시지를 가로채서 목적지로 다시 보내는 reply 공격에 취약하다. 이런 공격은 차량에서 unlock신호를 캡쳐했다가 나중에 다시 보내서 unlock을 시켜버릴 수도 있는 공격이다.
* 취약점을 보안하기 위해 timestamp를 메시지 안에 넣고 HMAC 알고리즘을 진행한뒤 마지막에 verficiation을 통과하면 시간이 지금 초과한건지 아닌지 체크해서 reply attack을 막는다.

## MAC(Message Authentication Code)
* MAC은 메시지가 외부에 노출되어도 상관없고 인증만 필요할 경우 암호화 알고리즘 보다 빠르기 때문에 사용한다.
* 송신자와 수신자 모두 같은 key를 가지고 있고 메시지에다가 MAC == Ck(M)을 붙여서 보낸다. Sender는 key를 가지고 메시지 M을 압축한 코드를 메시지와 보내고 receiver는 메시지를 가지고 같은 압축을 해보면서 붙여진 코드와 자기가 했는 것이 같은지 확인을 하여 메시지의 무결성을 확인한다.
* 여기서는 복화하라는 개념이 없다. 그냥 서로 같은 함수로 같은 키를 가지고 digest를 비교하는 것이다.
* 여기에서 속도도 빠르면서 암호화를 할 수 있고 MAC 기능을 할 수 있는 것이 HMAC이다. Encryption보다 빠른 이유는 해시 연산에서 저장했다가 다시 쓸 수 있는 연산들이 있어서 속도가 빨라질 수 있는 것이다.

## Encryption and compression
* 압축을 하고 암호화를 해버리면 side channel attack에 취약해진다. 이 공격은 JS 코드를 이용하여 victim's browser에 brute force공격을 하는 것인데 이것은 공격자가 암호화된 사이즈를 근간해서 transmitted data가 무엇인지 infer할 수 있게 해준다. compression oracle이라고도 알려져있고 CRIME과 BREACH와 같은 SSL/TLS 공격에도 취약해진다.
* 그런데 암호화를 하고 압축을 하면 더 많은 issues가 생긴다. 암호화를 해버리면 데이터의 패턴이 사라지고 이럴 경우 압축 자체가 힘들어 질 수 있다. 암호화는 패턴에 의존해서 사이즈를 줄여나가는 방식인데 암호화를 먼저 해버리면 압축을 제대로 할 수가 없게 되는 것이다.
* 사실 둘다 하지 않는게 좋다.

# Salted Password Hashing

## Creak Hash
* 이것은 결국 비밀번호를 어떻게 관리하냐에 관한 이야기이고 data breached를 막는것이 아닌 breach가 일어났을때 비밀번호만은 지킬 수 있는 방법들이다.
* 해시와 비밀번호의 관계는 단방향성과 빠름에 있다.
### Dictionary and Brute Force Attacks
* 가장 쉬운 방법은 비밀번호를 추측해서 그 해쉬값이 같은지 아닌지 확인하면 되는 방법이다. 여기에 2가지 대표적인 방법이 dictionary 공격과 brute force 공격이다.
* Dictionary attack은 이미 패스워드 해쉬로 사용하고 있는 데이터에서 가져오거나 그럴싸한 조합이 있는 파일을 가져와서 그것과 비교하는 공격이다.
* Brute Force attack은 주어진 legnth에 모든 경우의 수를 적용해서 매칭하는 공격이다. Cost가 제일 비싸지만 무조건 성공한다.
* Dictionary attack이나 brute force attack을 막을 방법은 없다. 다만 그 공격들을 덜 효과적으로 시행되도록 할 수 밖에 없다.

### Lookup Tables
* 매우 효과적인 공격 방법이다. 이 방법은 이전 공격방법과 다르게 pre-compute를해서 그것을 비교하는 방식이다.
* A good implementation of a lookup table은 초당 수백개의 hash lookups을 연산 할 수 있게 해주고 이미 인터넷에 sha256으로 hash된 값들이 존재해서 검색만 하면 된다.

### Reverse Lookup Tables
* 우선 다른 데이터베이스에서 계정 아이디와 해쉬된 비밀번호에 대한 룩업 테이블을 만듭니다. 이후 공격자가 비밀번호를 추측해서 그값을 해시한 digest를 미리 만든 룩업 테이블에서 사용하는지 골라내어 password - 사용하는 유저들 의 형태로 맵핑을 해서 테이블을 만듭니다.
* 보통 한 유저가 동일한 비밀번호를 사용하는 경우가 많기 때문에 이러한 테이블은 유용하게 쓰일 수 있습니다.

### Rainbow Tables
* time-space trade-off technique입니다. 룩업 테이블의 사이즈를 줄이는 대신 속도를 희생합니다. 룩업 테이블의 경우 시작시에 dictionary 파일(추측되는 암호들)을 해싱을 해서 램 위에 올립니다. 하지만 레인보우 테이블은 해싱 결과 자체를 파일로 만들어두어서 램 위에는 오직 해시값만 올리는 기법입니다. 램 위에서 해싱을 하지 않습니다.

## Adding Salt
* 단순한 해시만 해버리면 룩업 테이블 공격이나 레인보우 테이블 공격을 허용하게 된다. 하지만 해싱을 할 때 salt라 불리는 값을 넣어서 해시하면 그러한 공격이 힘들어진다.
* Salt는 암호화할 필요는 없다. Salt가 있는것만으로도 위에 말한 공격들을 무력화시킬 수 있기 때문이다.
* 비밀번호 앞에 붙이나 뒤에 붙이나 상관없다.
### Wrong way to use salt
* Salt Reuse: Salt는 하드 코드로 입력되거나 랜덤하게 생성될텐데 이것을 재사용해버리면 reverse lookup table attack을 허용하게 되어 salt를 사용한 의미가 사라지게 된다. 랜덤 salt는 반드시 유저가 계정을 만들거나 비밀번호를 바꿀때마다 갱신해줘야한다.
* Short Salt: Salt가 너무 짧으면 모든 경우에 관한 lookup table을 쉽게 만들어 버릴 수 있다. Salt가 암호화할 필요는 없지만 너무 짧거나 재사용을 해버리게되면 결국 해커는 그것에 관한 lookup table을 다 만들어버려서 공격을 허용하게 되어버린다. 따라서 가능하면 hash function의 output과 동일하거나 큰 size의 salt를 쓰는게 좋다.
* Double Hashing & Wacky Hash Functions: 서로 다른 hash 알고리즘을 섞어서 쓰면 보다 안전할 것 같지만 사실 약간의 이득만 취할뿐 가끔은 오히려 less secure하게 만들기도한다. Wacky hash function의 구조를 아는데 해커가 조금의 시간이 더 걸릴뿐, 결국은 알것이기에 그리 안전하지 않다. HMAC정도야 wacky하게 써도 괜찮을지 모르지만 결국 속도가 느릴 것이다. 결론은 잘 짜여진 hash 알고리즘을 사용법에 맞게 쓰는게 최고다.

### Right way to use salt
* Salt를 랜덤하게 생성하기위해 단순한 pseduo-random number generator를 쓰는게 아닌 CryptoGraphically Secure Pseduo-Random Number Generator(CSPRNG)를 써야한다.
* Salt는 per-user and per-password에서 unique해야한다. 유저 아이디를 생성하거나 비밀번호를 바꿀때 마다 새로운 랜덤 salt를 생성해야한다. 여기서 중요한 점은 최소한 digest보다는 커야 된다는 것이다.
* 만들어진 salt는 유저 DB에 어카운트와 비밀번호와 함께 저장해야 한다.
* 암호를 valid하기 위해서는 우선 DB에서 해쉬값과 salt를 가져오고 given password에 주어진 salt를 추가해서 해쉬한 후 비교한다.
* 웹의 경우 항상 해시는 서버에서 한다. 클라이언트 사이드에서 java script를 통해 비밀번호를 해시하고 그것을 보낸다고 할지라도 무조건 서버사이드에서 다시 hash를 해야한다. 왜냐하면 클라이언트에서 해시한 결과는 결국 해커가 뺏을 수 있고 그러면 password 자체는 몰라도 공격이 가능하기 때문이다. 따라서 클라이언트 사이드의 hash가 HTTPS를 대체한다고 생각해서는 안 된다. 또한 몇몇 browser는 JS를 support하지 않을 수 있기 때문에 그것도 고려해야하고 client-side hash salt가 필요한 경우 서버가 주는 것이 아닌 도메인 이름이나 유저 이름을 사용하는 등, 알아서 처리하게 해야한다.
* Key stretching을 사용하는데 이것은 동일한 해시 함수를 몇번이나 반복해서 digest를 만드는 것을 의미한다. 이 때 자신이 key stretching을 설계하지말고 잘 짜여진 라이브러리를 사용해야한다. 너무 많은 횟수를 해버리면 웹 서버의 경우 리소스를 다 잡아먹기 때문에 DoS가 발생할 수 있고 user experience에 영향을 미치지 않을 정도로(가령 0.2초) 사용하는것이 좋다. 이러한 방법을 통해 BF 공격을 예방 할 수 있다. 키 스트레칭을 서버에서 부담하기 싫다면 클라이언트쪽에서 돌리고 서버로 결과를 받아 처리하는 방법도 있다.
* YubiHSM과 같은 하드웨어 secret key를 쓰면 해시 크랙을 막을 수 있다. Hash를 막기 위해 key가 필요한 HMAC과 같은 알고리즘을 쓰면 좋겠지만 secret key 관리하는것도 쉽지 않다. 따라서 철저한 보안이 필요한 경우에는 physically 관리하는 것이 더 안전할 수 있다. HMAC을 쓴다고 salt와 key streatching이 필요 없는 것은 아니다. 왜냐하면 해커는 그 키 또한 얻을 수 있기 때문이다.
* Hash를 할 때 고정된 길이의 시간으로 계산을 해야한다. 왜냐하면 hash를 비교할때 byte by byte로 비교를 할텐데 그 함수가 구현된 방식이 하나의 byte씩 비교를해서 맞으면 계속 비교하고 중간에 틀리면 바로 negative 값으로 리턴을 해버리니깐 맞는 갯수만큼 return까지의 시간이 결정될 것이다. 하나의 해시값(비밀번호로 만든 해시)과 진짜 비밀번호로부터 만든 해시값을 해커가 맞춘다면 이후부터는 on-line 서버가 아니라 해커의 컴퓨터에서 그 다음 작업들을 계속 할 수 있을 것이다. 따라서 그러한 힌트를 얻을 수 없도록 시간을 정해서 결과값을 줄 수 있도록 해야한다.

## References
* https://crackstation.net/hashing-security.htm