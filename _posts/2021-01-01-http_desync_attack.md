---
title: HTTP Request Smuggling (Desync Attack)
author: hyoeun
key: page-http_desync_attack
categories:
- Security
- Web Security
image: "/assets/thumbnails/2021-01-01-http_desync_attack.png"
date: 2021-01-01 00:00:00
bilingual: true
---

## What Is HTTP Request Smuggling?

HTTP Request Smuggling (also called HTTP Desync Attack) is a technique that exploits discrepancies in how **front-end** (load balancer, CDN, reverse proxy) and **back-end** servers parse HTTP requests. By crafting an ambiguous request, an attacker can "smuggle" a secondary request that the front-end ignores but the back-end processes.

This vulnerability was popularized by James Kettle's research presented at Black Hat USA 2019 and is considered one of the most impactful web vulnerabilities of its era. It can lead to **request hijacking, cache poisoning, WAF bypass, XSS, and credential theft**.

## The Root Cause: Content-Length vs Transfer-Encoding

HTTP/1.1 provides two ways to specify request body length:
- **Content-Length (CL)**: Specifies the exact byte count of the body.
- **Transfer-Encoding: chunked (TE)**: Body is sent in chunks; a chunk of size `0` signals the end.

The HTTP/1.1 spec (RFC 7230) states: if both headers are present, `Transfer-Encoding` takes precedence and `Content-Length` must be ignored. However, different servers implement this differently—creating the desync opportunity.

## Types of Desync Attacks

### CL.TE (Front-end uses Content-Length, Back-end uses Transfer-Encoding)
The front-end forwards the request based on CL; the back-end processes it as chunked, leaving a portion of the "smuggled" request in its buffer.

```
POST / HTTP/1.1
Host: target.com
Content-Length: 13
Transfer-Encoding: chunked

0

SMUGGLED
```

### TE.CL (Front-end uses Transfer-Encoding, Back-end uses Content-Length)
The front-end processes the chunked body and forwards it; the back-end reads based on CL, leaving the excess in the buffer.

```
POST / HTTP/1.1
Host: target.com
Content-Length: 3
Transfer-Encoding: chunked

8
SMUGGLED
0
```

### TE.TE (Both use Transfer-Encoding, but one can be obfuscated)
When both front-end and back-end support TE, attackers can obfuscate the `Transfer-Encoding` header to make one server ignore it:

```
Transfer-Encoding: xchunked
Transfer-Encoding: chunked
Transfer-Encoding : chunked
X: X[\n]Transfer-Encoding: chunked
```

## Attack Scenarios

### 1. Bypassing Security Controls / WAF
By smuggling a request, an attacker can reach back-end endpoints that are blocked by the front-end security layer.

### 2. Capturing Other Users' Requests
By smuggling a partial request that causes the back-end to append another user's incoming request to the attacker's request body, the attacker can capture credentials, tokens, and session data.

### 3. Reflected XSS via Request Smuggling
If a reflected XSS payload exists somewhere in the application that would normally be blocked by WAF, smuggling can deliver it through the back-end directly.

### 4. Cache Poisoning
By smuggling a request that causes the cache to store a malicious response for a legitimate URL.

## Detection and Testing

**Using Burp Suite (recommended tool):**
1. Install the **HTTP Request Smuggler** extension by James Kettle.
2. Right-click → Extensions → HTTP Request Smuggler → "Launch Smuggle Probe."
3. Analyze timing differences (CL.TE) or response differences (TE.CL) for evidence of desync.

**Manual detection (CL.TE timing attack):**
```
POST / HTTP/1.1
Host: target.com
Transfer-Encoding: chunked
Content-Length: 4

1
A
X
```
If this request causes an unusual delay (because the back-end is waiting for the rest of the chunked body), CL.TE desync likely exists.

**Key tools:**
- Burp Suite Professional + HTTP Request Smuggler extension
- `smuggler.py` by defparam (open-source)

## Mitigations

- **Disable back-end connection reuse** (but this impacts performance significantly).
- Ensure **front-end and back-end normalize requests** before forwarding.
- Configure servers to **reject ambiguous requests** (both CL and TE present).
- Use **HTTP/2 end-to-end** — HTTP/2 doesn't have this ambiguity.
- Apply **strict parsing** on all intermediate proxies.
- Use **modern load balancers** that are aware of this class of attack.

---

## HTTP 요청 스머글링이란?

HTTP 요청 스머글링(HTTP Desync Attack이라고도 함)은 **프론트엔드**(로드 밸런서, CDN, 리버스 프록시)와 **백엔드** 서버가 HTTP 요청을 파싱하는 방식의 불일치를 이용하는 기법입니다. 모호한 요청을 만들어 프론트엔드는 무시하지만 백엔드가 처리하는 두 번째 요청을 "밀수"할 수 있습니다.

이 취약점은 James Kettle이 Black Hat USA 2019에서 발표한 연구로 널리 알려졌으며, **요청 하이재킹, 캐시 포이즈닝, WAF 우회, XSS, 자격 증명 탈취** 등으로 이어질 수 있어 그 시대의 가장 임팩트 있는 웹 취약점 중 하나로 꼽힙니다.

## 근본 원인: Content-Length vs Transfer-Encoding

HTTP/1.1은 요청 본문 길이를 지정하는 두 가지 방법을 제공합니다:
- **Content-Length (CL)**: 본문의 정확한 바이트 수를 지정합니다.
- **Transfer-Encoding: chunked (TE)**: 본문이 청크로 전송되며, 크기 `0`의 청크가 끝을 알립니다.

HTTP/1.1 스펙(RFC 7230)은 두 헤더가 모두 있을 경우 `Transfer-Encoding`이 우선하고 `Content-Length`는 무시해야 한다고 명시합니다. 그러나 다른 서버들이 이를 다르게 구현하면서 Desync 기회가 생깁니다.

## Desync 공격 유형

### CL.TE (프론트엔드는 CL 사용, 백엔드는 TE 사용)
프론트엔드가 CL 기반으로 요청을 전달하면, 백엔드는 청크로 처리하여 "밀수된" 요청의 일부를 버퍼에 남깁니다.

### TE.CL (프론트엔드는 TE 사용, 백엔드는 CL 사용)
프론트엔드가 청크 본문을 처리하고 전달하면, 백엔드는 CL 기반으로 읽어 초과분을 버퍼에 남깁니다.

### TE.TE (두 서버 모두 TE 사용, 하지만 난독화 가능)
두 서버가 모두 TE를 지원할 때, 공격자는 한 서버가 무시하도록 `Transfer-Encoding` 헤더를 난독화할 수 있습니다.

## 공격 시나리오

1. **보안 제어/WAF 우회**: 프론트엔드 보안 계층이 차단한 백엔드 엔드포인트에 도달
2. **다른 사용자의 요청 캡처**: 자격 증명, 토큰, 세션 데이터 탈취
3. **요청 스머글링을 통한 반사 XSS**: WAF가 차단하는 XSS 페이로드를 백엔드로 직접 전달
4. **캐시 포이즈닝**: 합법적인 URL에 악성 응답이 캐시되도록 유도

## 탐지 및 테스트

**Burp Suite 사용 (권장 도구):**
1. James Kettle의 **HTTP Request Smuggler** 확장 설치
2. 우클릭 → Extensions → HTTP Request Smuggler → "Launch Smuggle Probe"
3. 타이밍 차이(CL.TE) 또는 응답 차이(TE.CL)를 분석하여 Desync 증거 확인

**핵심 도구:**
- Burp Suite Professional + HTTP Request Smuggler 확장
- defparam의 `smuggler.py` (오픈 소스)

## 완화 방법

- **백엔드 연결 재사용 비활성화** (성능에 큰 영향)
- 프론트엔드와 백엔드가 전달 전 **요청을 정규화**하도록 구성
- CL과 TE 모두 있는 **모호한 요청 거부**하도록 서버 설정
- 이러한 모호성이 없는 **HTTP/2 종단 간 사용**
- 모든 중간 프록시에 **엄격한 파싱** 적용
