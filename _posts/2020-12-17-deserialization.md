---
title: Deserialization Attacks
author: hyoeun
key: page-deserialization
categories:
- Security
- Vulnerabilities
image: "/assets/thumbnails/2020-12-17-deserialization.png"
date: 2020-12-17 00:00:00
bilingual: true
---

## What Is Deserialization?

**Serialization** is the process of converting an object (in memory) into a format that can be stored or transmitted—such as JSON, XML, or binary formats. **Deserialization** is the reverse: converting that stored/transmitted data back into a live object.

Insecure deserialization occurs when an application deserializes data from an untrusted source without proper validation, allowing attackers to manipulate the serialized data to achieve **Remote Code Execution (RCE)**, **authentication bypass**, **privilege escalation**, or **DoS**.

OWASP has listed insecure deserialization in its Top 10 since 2017 (A8:2017, A8:2021).

## Why Is Deserialization Dangerous?

When an application deserializes data, it often instantiates objects and executes methods automatically as part of the deserialization process. Attackers can craft malicious serialized payloads that, when deserialized, trigger unintended code execution through **gadget chains**—sequences of existing classes/methods that can be chained to achieve a malicious outcome.

## Java Deserialization

Java's `ObjectInputStream` is the classic example of insecure deserialization. The Apache Commons Collections vulnerability (2015) demonstrated how attackers could achieve RCE on any Java application using this library.

**Identifying Java Serialized Data:**
- Binary streams starting with `0xACED 0x0005` (hex) or `rO0AB` (base64)

```java
// Vulnerable code
ObjectInputStream ois = new ObjectInputStream(request.getInputStream());
Object obj = ois.readObject(); // DANGEROUS - no validation
```

**Tools:**
- **ysoserial**: Generates gadget chain payloads for various Java libraries.
- **Burp Suite**: Deserialization Scanner extension.

```bash
# Generate a payload using CommonsCollections1 gadget chain
java -jar ysoserial.jar CommonsCollections1 "calc.exe" | base64
```

## PHP Deserialization

PHP uses `serialize()` and `unserialize()`. PHP deserialization attacks exploit **magic methods** like `__wakeup()`, `__destruct()`, `__toString()` that execute automatically during object lifecycle events.

**Identifying PHP Serialized Data:**
```
O:4:"User":2:{s:4:"name";s:5:"Alice";s:4:"role";s:4:"user";}
```

**Attack Example:**
```php
// Attacker modifies serialized data to change role
O:4:"User":2:{s:4:"name";s:5:"Alice";s:4:"role";s:5:"admin";}
```

**POP (Property-Oriented Programming) Chains:** Attackers chain existing classes that have dangerous magic methods to achieve RCE, similar to Java gadget chains.

**Tools:**
- **PHPGGC**: PHP gadget chain generator (like ysoserial for PHP).

## Python Deserialization

Python's `pickle` module is notoriously dangerous:

```python
import pickle, os

class Exploit:
    def __reduce__(self):
        return (os.system, ('whoami',))

payload = pickle.dumps(Exploit())
# When deserialized: pickle.loads(payload) → executes whoami
```

Any application using `pickle.loads()` on untrusted data is vulnerable to RCE.

## Node.js / JavaScript Deserialization

Libraries like `node-serialize` are vulnerable when `unserialize()` is called on untrusted input. IIFE (Immediately Invoked Function Expression) patterns can be embedded in JSON to achieve RCE:

```json
{"rce":"_$$ND_FUNC$$_function(){require('child_process').exec('whoami')}()"}
```

## .NET Deserialization

`BinaryFormatter`, `NetDataContractSerializer`, and others in .NET are vulnerable. The **ActivitySurrogateSelector** and **ObjectDataProvider** gadget chains are commonly used.

**Tool:** **ysoserial.net** — equivalent of ysoserial for .NET.

## Detection and Testing

1. **Identify serialized data** in cookies, HTTP body, headers, or URL parameters.
2. **Intercept with Burp Suite** and modify serialized fields.
3. **Use automated scanners**: Burp's Deserialization Scanner, OWASP ZAP.
4. **Test for gadget chains** using ysoserial (Java/.NET) or PHPGGC (PHP).
5. **Monitor for DNS/HTTP callbacks** (out-of-band detection) using Burp Collaborator or interactsh.

## Mitigations

- **Avoid deserializing untrusted data** whenever possible.
- Use **data-only formats** (JSON, XML) instead of native serialization formats.
- Implement **allowlists** of classes that can be deserialized.
- Use `ObjectInputFilter` in Java 9+ to restrict deserialized classes.
- Sign and verify serialized data with HMAC before deserializing.
- Run deserialization in sandboxed environments.

---

## 역직렬화란?

**직렬화(Serialization)**는 메모리상의 객체를 저장하거나 전송할 수 있는 형식(JSON, XML, 바이너리 등)으로 변환하는 과정입니다. **역직렬화(Deserialization)**는 그 반대로, 저장/전송된 데이터를 다시 살아있는 객체로 변환하는 과정입니다.

안전하지 않은 역직렬화는 애플리케이션이 신뢰할 수 없는 소스의 데이터를 적절한 검증 없이 역직렬화할 때 발생하며, 공격자가 직렬화된 데이터를 조작하여 **원격 코드 실행(RCE)**, **인증 우회**, **권한 상승**, **DoS** 등을 달성할 수 있게 합니다.

OWASP는 2017년부터 안전하지 않은 역직렬화를 Top 10에 포함시켰습니다.

## 왜 역직렬화가 위험한가?

애플리케이션이 데이터를 역직렬화할 때, 역직렬화 과정의 일부로 자동으로 객체를 인스턴스화하고 메서드를 실행하는 경우가 많습니다. 공격자는 역직렬화 시 **가젯 체인(gadget chains)**—의도하지 않은 결과를 달성하기 위해 연결될 수 있는 기존 클래스/메서드의 시퀀스—을 통해 악성 코드 실행을 트리거하는 페이로드를 만들 수 있습니다.

## Java 역직렬화

Java의 `ObjectInputStream`은 안전하지 않은 역직렬화의 대표적인 예입니다. Apache Commons Collections 취약점(2015)은 공격자가 이 라이브러리를 사용하는 모든 Java 애플리케이션에서 RCE를 달성할 수 있음을 보여줬습니다.

**Java 직렬화 데이터 식별:**
- `0xACED 0x0005`(16진수) 또는 `rO0AB`(base64)로 시작하는 바이너리 스트림

**도구:**
- **ysoserial**: 다양한 Java 라이브러리의 가젯 체인 페이로드 생성
- **Burp Suite**: Deserialization Scanner 확장

## PHP 역직렬화

PHP는 `serialize()`와 `unserialize()`를 사용합니다. PHP 역직렬화 공격은 객체 생명주기 이벤트 중 자동으로 실행되는 `__wakeup()`, `__destruct()`, `__toString()` 같은 **매직 메서드**를 악용합니다.

**POP(Property-Oriented Programming) 체인:** 공격자는 위험한 매직 메서드를 가진 기존 클래스를 연결하여 RCE를 달성합니다.

**도구:** **PHPGGC** — PHP용 가젯 체인 생성기

## Python 역직렬화

Python의 `pickle` 모듈은 신뢰할 수 없는 데이터에 `pickle.loads()`를 사용하면 RCE에 취약합니다. `__reduce__` 메서드가 역직렬화 시 자동으로 호출되어 임의의 명령을 실행할 수 있습니다.

## 탐지 및 테스트

1. 쿠키, HTTP 본문, 헤더, URL 파라미터에서 **직렬화된 데이터 식별**
2. **Burp Suite로 인터셉트**하여 직렬화된 필드 수정
3. **자동화된 스캐너 사용**: Burp의 Deserialization Scanner, OWASP ZAP
4. ysoserial(Java/.NET) 또는 PHPGGC(PHP)를 사용하여 **가젯 체인 테스트**
5. Burp Collaborator 또는 interactsh를 사용하여 **DNS/HTTP 콜백 모니터링**(대역 외 탐지)

## 완화 방법

- 가능한 경우 **신뢰할 수 없는 데이터의 역직렬화 방지**
- 네이티브 직렬화 형식 대신 **JSON, XML 같은 데이터 전용 형식** 사용
- 역직렬화될 수 있는 클래스의 **화이트리스트 구현**
- Java 9+에서 `ObjectInputFilter`로 역직렬화 클래스 제한
- 역직렬화 전 HMAC으로 직렬화된 데이터 서명 및 검증
- 샌드박스 환경에서 역직렬화 실행
