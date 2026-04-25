---
title: Certificate Pinning
key: page-certificate_pinning
categories:
- Security
- Mobile Security
author: hyoeun
math: true
mathjax_autoNumber: true
image: "/assets/thumbnails/2023-03-14-cert_pinning.png"
bilingual: true
date: 2023-03-14 15:36:00
---
## What is Certificate Pinning?

Certificate Pinning is a method where a client application "pins" specific server certificates (or related data) to trust only those certificates. This ensures stricter certificate validation during network communication and effectively defends against **MITM (Man-in-the-Middle)** attacks. Key characteristics include:

- Instead of hardcoding the certificate directly, it uses a **fingerprint**, the hash value of the certificate.
- Pinning can be based on **Certificate Authority (CA)**, public key, or end-entity certificate.
- While **HTTP Public Key Pinning (HPKP)** headers were introduced for web browsers, they are no longer widely used due to potential security vulnerabilities and misuse.

## Types of Pinning

Certificate Pinning can be categorized based on the type of certificate data being pinned:

### 1. Public Key Pinning
- The application continues to function as long as the **public key** remains the same, even if the server's certificate expires.
- Typically, the **public key fingerprint** is used for pinning.

**Pros**
- If the public key is maintained during certificate renewal, no app update is required, **reducing maintenance overhead.**
- Less sensitive to certificate rotation cycles compared to Leaf or Intermediate methods.
- A balanced approach between security and flexibility, **widely recommended in practice.**

**Cons**
- An app update is required if the public key itself is rotated (key rotation).
- Requires operational procedures to renew certificates while maintaining the same public key.

**When to use?**

Most suitable for **general production apps** where security and operational convenience must be balanced. Especially useful for services with high security requirements but slow DevOps cycles, such as finance or healthcare.

### 2. Leaf Certificate Pinning
- Pins the end-entity certificate directly.
- Provides the clearest guarantee of server certificate validation.
- However, frequent certificate renewals require application updates, which can be inconvenient.

**Pros**
- **Highest security strength.** Minimizes the attack surface as nothing is trusted except the pinned certificate.
- Clear binding to a specific certificate avoids the accidental acceptance of unintended certificates.

**Cons**
- **Highest operational overhead**, as the app must be updated for every certificate renewal (usually every 1-2 years).
- Risk of **service outage** if the app update is not successfully deployed before the certificate expires.
- Not a good fit for certificates with short renewal cycles, like Let’s Encrypt (90 days).

**When to use?**

Suitable for environments with long-lived certificates and full control over app deployment, such as **internal enterprise API servers** or **long-term offline/private network applications.**

### 3. Intermediate Certificate Pinning
- Pins an intermediate certificate between the root certificate and the end-entity certificate.
- Used as an alternative when the server's end-entity certificate changes frequently, reducing the update frequency.

**Pros**
- **Lower update frequency** compared to Leaf pinning, reducing app maintenance.
- **Much narrower blast radius** than trusting an entire Root CA.
- Allows flexibility in server certificate rotation as long as the same intermediate CA is used.

**Cons**
- App update is required if the intermediate CA is compromised or replaced.
- Wider attack surface than Leaf pinning, though stronger than Root pinning.
- If multiple domains share the same intermediate CA, a compromise of one could affect others.

**When to use?**

Used when you want to **avoid the operational burden of Leaf pinning** while maintaining higher security than Root pinning. Suitable for architectures like CDNs or load balancers where **multiple servers share the same intermediate CA.**

### 4. Root Certificate Pinning
- Trusts the root CA.
- Simple and universal but risks compromising the entire security chain if the root CA is compromised.
- The key difference from general certificate validation is that instead of trusting all Root CAs registered in the platform's trusted list, it only trusts a specific Root CA.

**Pros**
- **Simplest to implement and maintain.** Allows free rotation of any certificate issued by the same Root CA.
- **Minimal app update frequency** since Root CA certificates have very long lifespans (20+ years).
- Can cover multiple service domains with a single Root CA.

**Cons**
- **Lowest security strength.** Trusts every certificate issued by that Root CA, presenting the widest attack surface.
- **Total collapse of app security** if the Root CA is compromised or loses trust (e.g., the DigiNotar case).
- Management complexity can increase if the operator uses multiple CAs.

**When to use?**

Chosen for large-scale distributed systems with very frequent certificate rotations or **multiple subdomains and microservices** using various certificates. However, not recommended as a standalone method for anything other than internal systems or dev/staging environments.

### Comparison Summary

| Method | Security Strength | Maintenance Overhead | Flexibility | Primary Use Case |
|------|-----------|-----------|-----------|----------------|
| **Public Key** | ★★★★☆ | Low | High | Most production apps |
| **Leaf Certificate** | ★★★★★ | Very High | Low | Private networks, Internal APIs |
| **Intermediate** | ★★★☆☆ | Medium | Medium | CDN/LB environments, frequent Leaf rotation |
| **Root** | ★★☆☆☆ | Very Low | Very High | Dev/Test, large-scale MSA |


## Implementation

The implementation of Certificate Pinning varies by platform. Below are common methods for popular platforms:

### Android

1. **TrustManager**  
   - `TrustManager` is a class responsible for validating server certificates. You can customize it to implement pinning.  
   - However, implementation can be complex and misconfiguration may introduce vulnerabilities or bugs.

    ```java
    import java.io.InputStream;
    import java.security.KeyStore;
    import java.security.cert.Certificate;
    import java.security.cert.CertificateFactory;
    import java.security.cert.X509Certificate;
    import javax.net.ssl.SSLContext;
    import javax.net.ssl.TrustManager;
    import javax.net.ssl.X509TrustManager;
    import okhttp3.OkHttpClient;

    public class CustomTrustManager {

        public OkHttpClient getPinnedHttpClient() {
            try {
                // 1. Load certificate
                CertificateFactory cf = CertificateFactory.getInstance("X.509");
                InputStream certInputStream = getClass().getClassLoader().getResourceAsStream("your_cert.pem");
                Certificate caCert;
                try {
                    caCert = cf.generateCertificate(certInputStream);
                } finally {
                    if (certInputStream != null) certInputStream.close();
                }

                // 2. Create KeyStore and add certificate
                KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
                keyStore.load(null, null);
                keyStore.setCertificateEntry("ca", caCert);

                // 3. Create TrustManager
                final TrustManager[] trustManagers = new TrustManager[]{
                    new X509TrustManager() {
                        private final X509TrustManager defaultTrustManager;

                        {
                            TrustManagerFactory factory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
                            factory.init(keyStore);
                            defaultTrustManager = (X509TrustManager) factory.getTrustManagers()[0];
                        }

                        @Override
                        public void checkClientTrusted(X509Certificate[] chain, String authType) {
                            // Implement client certificate validation if needed
                        }

                        @Override
                        public void checkServerTrusted(X509Certificate[] chain, String authType) {
                            try {
                                defaultTrustManager.checkServerTrusted(chain, authType);
                            } catch (Exception e) {
                                throw new RuntimeException("Server certificate validation failed", e);
                            }
                        }

                        @Override
                        public X509Certificate[] getAcceptedIssuers() {
                            return defaultTrustManager.getAcceptedIssuers();
                        }
                    }
                };

                // 4. Set up SSLContext
                SSLContext sslContext = SSLContext.getInstance("TLS");
                sslContext.init(null, trustManagers, new java.security.SecureRandom());

                // 5. Add SSL configuration to OkHttpClient
                return new OkHttpClient.Builder()
                    .sslSocketFactory(sslContext.getSocketFactory(), (X509TrustManager) trustManagers[0])
                    .build();

            } catch (Exception e) {
                throw new RuntimeException("Failed to create custom TrustManager", e);
            }
        }
    }
    ```

2. **OkHttp with CertificatePinner**  
   - The OkHttp library provides a simpler way to implement Certificate Pinning.  
   - Embed the certificate's fingerprint during build time and add `CertificatePinner` to the HTTP client.

    ```java
    import okhttp3.CertificatePinner;
    import okhttp3.OkHttpClient;

    public class PinningExample {
        public OkHttpClient getPinnedHttpClient() {
            CertificatePinner certificatePinner = new CertificatePinner.Builder()
                .add("yourdomain.com", "sha256/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")
                .build();

            return new OkHttpClient.Builder()
                .certificatePinner(certificatePinner)
                .build();
        }
    }
    ```

3. **Network Security Configuration (NSC)**  
   - Android's **NSC** allows configuring certificate pinning via XML.  
   - This approach enables changes without modifying the app code.

    ```xml
    <network-security-config>
        <domain-config>
            <domain includeSubdomains="true">yourdomain.com</domain>
            <pin-set expiration="2024-12-31">
                <pin algorithm="sha256">AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=</pin>
            </pin-set>
        </domain-config>
    </network-security-config>
    ```

### iOS

1. **TrustKit**  
   - On iOS, **TrustKit**, an open-source SSL pinning library, is widely used.  
   - TrustKit provides an intuitive API for secure and straightforward pinning implementation.

    ```swift
    import TrustKit

    @UIApplicationMain
    class AppDelegate: UIResponder, UIApplicationDelegate {
        var window: UIWindow?

        func application(_ application: UIApplication, didFinishLaunchingWithOptions launchOptions: [UIApplication.LaunchOptionsKey: Any]?) -> Bool {
            let trustKitConfig: [String: Any] = [
                kTSKSwizzleNetworkDelegates: true,
                kTSKPinnedDomains: [
                    "yourdomain.com": [
                        kTSKIncludeSubdomains: true,
                        kTSKEnforcePinning: true,
                        kTSKPublicKeyHashes: [
                            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
                        ]
                    ]
                ]
            ]

            TrustKit.initSharedInstance(withConfiguration: trustKitConfig)
            return true
        }
    }
    ```

2. **Manual Implementation**  
   - If not using TrustKit, manual implementation of the pinning logic is possible but prone to design flaws or vulnerabilities.  
   - Not recommended unless you have expert knowledge.

    ```swift
    func urlSession(_ session: URLSession, didReceive challenge: URLAuthenticationChallenge,
                completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void) {
        guard let serverTrust = challenge.protectionSpace.serverTrust else {
            completionHandler(.cancelAuthenticationChallenge, nil)
            return
        }

        let policies = [SecPolicyCreateSSL(true, challenge.protectionSpace.host as CFString)]
        SecTrustSetPolicies(serverTrust, policies as CFTypeRef)

        var secresult = SecTrustResultType.invalid
        if SecTrustEvaluate(serverTrust, &secresult) == errSecSuccess {
            let serverCert = SecTrustGetCertificateAtIndex(serverTrust, 0)!
            let serverCertData = SecCertificateCopyData(serverCert) as Data
            let localCertData = NSData(contentsOfFile: Bundle.main.path(forResource: "your_cert", ofType: "cer")!)!

            if serverCertData == localCertData as Data {
                completionHandler(.useCredential, URLCredential(trust: serverTrust))
                return
            }
        }

        completionHandler(.cancelAuthenticationChallenge, nil)
    }
    ```

### .NET

- In .NET, you can implement pinning using **ServicePointManager**.  
- Similar to Android's `CertificatePinner`, you can hardcode the fingerprint in the source code or load it dynamically at build time.  
- Dynamic loading from external configuration files is preferred over hardcoding.

```csharp
using System;
using System.Net;
using System.Security.Cryptography.X509Certificates;

class Program
{
    static void Main()
    {
        ServicePointManager.ServerCertificateValidationCallback += (sender, cert, chain, errors) =>
        {
            var expectedFingerprint = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
            var actualFingerprint = Convert.ToBase64String(cert.GetCertHash());
            return actualFingerprint == expectedFingerprint;
        };

        // Example HTTP request
        var client = new WebClient();
        var response = client.DownloadString("https://yourdomain.com");
        Console.WriteLine(response);
    }
}
```

---

## Certificate Pinning이란?

Certificate Pinning은 클라이언트 애플리케이션에서 특정 서버 인증서(또는 관련 데이터를) "고정"하여 해당 인증서만 신뢰하는 방식입니다. 이를 통해 네트워크 통신 과정에서 인증서 검증을 보다 엄격히 수행하며, **MITM(Man-in-the-Middle)** 공격을 효과적으로 방어할 수 있습니다. 주요 특징은 다음과 같습니다:

- 인증서를 직접 하드코딩하기보다는, 인증서의 해시(hash) 값인 **fingerprint**를 사용하여 고정합니다.
- 인증서는 **Certificate Authority (CA)**, 공개 키(public key), 또는 최종 사용자 인증서(end-entity certificate)에 기반해 핀닝할 수 있습니다.
- 웹 브라우저에서는 한때 **HTTP Public Key Pinning (HPKP)** 헤더가 도입되었으나, 여러 보안 취약점 및 오용 가능성 때문에 현재는 사용되지 않는 추세입니다.

## Pinning 방식에 따른 차이

Certificate Pinning은 고정하는 인증서 데이터에 따라 다음과 같이 분류됩니다:

### 1. Public Key Pinning
- 서버의 인증서가 만료(expiration)되더라도 **Public Key**가 동일하다면 애플리케이션에서 인증서 변경 없이 계속 동작할 수 있어 유연합니다.
- 주로 **public key fingerprint**를 핀으로 사용합니다.

**장점**
- 인증서가 갱신되더라도 공개 키가 유지되면 앱 업데이트가 불필요해 **유지보수 부담이 적습니다.**
- Leaf나 Intermediate 방식에 비해 인증서 교체 주기에 덜 민감합니다.
- 보안성과 유연성의 균형이 잘 맞는 방식으로, **실무에서 가장 널리 권장**됩니다.

**단점**
- 공개 키 자체가 교체(key rotation)될 경우에는 앱 업데이트가 필요합니다.
- 동일한 공개 키를 유지하면서 인증서만 갱신하는 운영 절차를 이해하고 있어야 합니다.

**언제 사용하나요?**

인증서 갱신은 주기적으로 발생하지만 공개 키 교체는 드문 환경, 즉 **보안과 운영 편의성을 동시에 고려해야 하는 일반적인 프로덕션 앱**에 가장 적합합니다. 금융, 헬스케어 등 보안 요건이 높지만 DevOps 사이클이 느린 서비스에 특히 유용합니다.



### 2. Leaf Certificate Pinning
- 최종 사용자 인증서(end-entity certificate)를 고정하는 방식입니다.
- 가장 명확한 방식으로, 서버 인증서가 고정된 것을 확실히 보장할 수 있습니다.
- 단, 인증서가 자주 갱신되는 경우 애플리케이션 업데이트가 필요하여 번거로울 수 있습니다.

**장점**
- **보안 강도가 가장 높습니다.** 고정된 인증서 외에는 어떤 것도 신뢰하지 않으므로 공격 표면이 최소화됩니다.
- 특정 인증서에 대한 명확한 바인딩으로, 의도하지 않은 인증서 수락 가능성이 없습니다.

**단점**
- 인증서 유효기간(보통 1~2년)마다 앱을 업데이트해야하므로 **운영 부담이 가장 큽니다.**
- 인증서 갱신 전에 앱 업데이트가 정상 배포되지 않으면 **서비스 중단(outage)** 이 발생 할 수 있습니다.
- Let's Encrypt처럼 90일 주기로 갱신되는 인증서와는 궁합이 매우 좋지 않습니다.

**언제 사용하나요?**

인증서 수명이 길고 갱신 시 앱 배포를 완벽히 통제할 수 있는 환경, 예를 들어 **엔터프라이즈 내부 API 서버**나 **장기 운영 폐쇄망 애플리케이션**에 적합합니다. 단기 테스트 또는 PoC 환경에서 강력한 격리를 원할 때도 사용됩니다.



### 3. Intermediate Certificate Pinning
- 루트 인증서와 최종 인증서 사이에 위치한 중간 인증서를 고정합니다.
- 서버의 최종 인증서(leaf cert)가 자주 변경되는 경우 대안으로 사용되며, 업데이트 빈도를 줄일 수 있습니다.

**장점**
- Leaf Certificate에 비해 **인증서 갱신 빈도가 낮아** 앱 업데이트 부담이 줄어듭니다.
- Root CA 전체를 신뢰하는 것보다 **공격 범위(blast radius)가 훨씬 좁습니다.**
- 동일한 중간 CA를 사용하는 한, 서버 인증서를 자유롭게 교체할 수 있습니다.

**단점**
- 중간 CA가 손상되거나 교체되면 앱 업데이트가 필요합니다.
- Root Pinning보다는 보안이 강하지만, Leaf Pinning보다는 공격 표면이 넓습니다.
- 여러 도메인이 동일한 중간 CA를 공유하는 경우, 한 도메인의 타협이 다른 도메인에도 영향을 미칠 수 있습니다.

**언제 사용하나요?**

서버 인증서(Leaf)가 자주 갱신되는 환경에서 **Leaf Pinning의 운영 부담을 피하면서** 보안 수준은 Root Pinning보다 높게 유지하고 싶을 때 사용합니다. CDN이나 로드밸런서 환경처럼 **여러 서버가 동일한 중간 CA를 공유**하는 아키텍처에 적합합니다.



### 4. Root Certificate Pinning
- 루트 CA를 신뢰하는 방식입니다.
- 범용적이고 단순하지만, 루트 CA가 손상될 경우 전체 보안 체계가 무너질 수 있는 위험이 있습니다.
- 일반적인 certifcate validation과의 큰 차이점은 플랫폼에 신뢰 리스트로 등록된 모든 Root CA 인증서를 신뢰하는 것이 아닌 특정 루트 CA만 신뢰한다는 점입니다.

**장점**
- 구현이 가장 **단순하고 유지보수가 편합니다.** 동일한 Root CA에서 발급된 인증서라면 교체가 자유롭습니다.
- Root CA의 유효기간은 매우 길기 때문에(20년 이상) **앱 업데이트 빈도가 최소화**됩니다.
- 여러 서비스 도메인을 단일 Root CA로 커버할 수 있습니다.

**단점**
- **보안 강도가 가장 낮습니다.** 해당 Root CA가 발급한 모든 인증서가 신뢰되므로 공격 표면이 가장 넓습니다.
- Root CA가 침해되거나 신뢰를 잃을 경우(DigiNotar 사례처럼) **전체 앱 보안이 붕괴**됩니다.
- 운영자가 여러 CA를 사용하는 환경에서는 관리 복잡성이 높아질 수 있습니다.

**언제 사용하나요?**

서버 인증서 교체가 매우 빈번하거나, **여러 서브도메인과 마이크로서비스**가 다양한 인증서를 사용하는 대규모 분산 시스템에서 인증서 고정의 기본 틀을 유지하면서 운영 부담을 최소화할 때 선택합니다. 다만, 보안보다 운영 편의성이 더 중요한 내부 시스템이나 개발/스테이징 환경 외에는 단독 사용을 권장하지 않습니다.



### 방식별 비교 요약

| 방식 | 보안 강도 | 유지보수 부담 | 유연성 | 주요 사용 사례 |
|------|-----------|--------------|--------|----------------|
| **Public Key** | ★★★★☆ | 낮음 | 높음 | 대부분의 프로덕션 앱 |
| **Leaf Certificate** | ★★★★★ | 매우 높음 | 낮음 | 폐쇄망, 엔터프라이즈 내부 API |
| **Intermediate** | ★★★☆☆ | 중간 | 중간 | CDN/LB 환경, 잦은 Leaf 갱신 |
| **Root** | ★★☆☆☆ | 매우 낮음 | 매우 높음 | 개발/테스트, 대규모 MSA |

## Implementation

Certificate Pinning 구현 방식은 플랫폼마다 다르며, 아래는 각 플랫폼에서의 주요 구현 방법입니다:

### Android

1. **TrustManager**  
   - TrustManager는 서버의 인증서를 검증하는 클래스입니다. 이를 커스터마이징하여 핀닝을 구현할 수 있습니다.  
   - 하지만 구현 과정이 복잡하고 잘못된 설정으로 인해 취약점이나 버그가 발생할 가능성이 있습니다.

    ```java
    import java.io.InputStream;
    import java.security.KeyStore;
    import java.security.cert.Certificate;
    import java.security.cert.CertificateFactory;
    import java.security.cert.X509Certificate;
    import javax.net.ssl.SSLContext;
    import javax.net.ssl.TrustManager;
    import javax.net.ssl.X509TrustManager;
    import okhttp3.OkHttpClient;

    public class CustomTrustManager {

        public OkHttpClient getPinnedHttpClient() {
            try {
                // 1. 인증서 로드
                CertificateFactory cf = CertificateFactory.getInstance("X.509");
                InputStream certInputStream = getClass().getClassLoader().getResourceAsStream("your_cert.pem");
                Certificate caCert;
                try {
                    caCert = cf.generateCertificate(certInputStream);
                } finally {
                    if (certInputStream != null) certInputStream.close();
                }

                // 2. KeyStore 생성 및 인증서 추가
                KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
                keyStore.load(null, null);
                keyStore.setCertificateEntry("ca", caCert);

                // 3. TrustManager 생성
                final TrustManager[] trustManagers = new TrustManager[]{
                    new X509TrustManager() {
                        private final X509TrustManager defaultTrustManager;

                        {
                            TrustManagerFactory factory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
                            factory.init(keyStore);
                            defaultTrustManager = (X509TrustManager) factory.getTrustManagers()[0];
                        }

                        @Override
                        public void checkClientTrusted(X509Certificate[] chain, String authType) {
                            // 클라이언트 인증 필요 시 구현
                        }

                        @Override
                        public void checkServerTrusted(X509Certificate[] chain, String authType) {
                            try {
                                defaultTrustManager.checkServerTrusted(chain, authType);
                            } catch (Exception e) {
                                throw new RuntimeException("Server certificate validation failed", e);
                            }
                        }

                        @Override
                        public X509Certificate[] getAcceptedIssuers() {
                            return defaultTrustManager.getAcceptedIssuers();
                        }
                    }
                };

                // 4. SSLContext 설정
                SSLContext sslContext = SSLContext.getInstance("TLS");
                sslContext.init(null, trustManagers, new java.security.SecureRandom());

                // 5. OkHttpClient에 SSL 설정 추가
                return new OkHttpClient.Builder()
                    .sslSocketFactory(sslContext.getSocketFactory(), (X509TrustManager) trustManagers[0])
                    .build();

            } catch (Exception e) {
                throw new RuntimeException("Failed to create custom TrustManager", e);
            }
        }
    }
    ```

2. **OkHttp와 CertificatePinner**  
   - OkHttp 라이브러리를 사용하면 간단히 Certificate Pinning을 설정할 수 있습니다.  
   - 인증서의 fingerprint를 빌드 시점에 앱에 삽입한 뒤, `CertificatePinner`를 HTTP 클라이언트에 추가하여 구현합니다.
    
    ```java
    import okhttp3.CertificatePinner;
    import okhttp3.OkHttpClient;

    public class PinningExample {
        public OkHttpClient getPinnedHttpClient() {
            CertificatePinner certificatePinner = new CertificatePinner.Builder()
                .add("yourdomain.com", "sha256/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")
                .build();

            return new OkHttpClient.Builder()
                .certificatePinner(certificatePinner)
                .build();
        }
    }
    ```
3. **Network Security Configuration (NSC)**  
   - Android의 **NSC**는 XML 파일을 통해 인증서 핀닝을 구성합니다.  
   - fingerprint를 XML로 정의하며, 이 방식은 앱 코드 수정 없이 설정 변경이 가능하다는 장점이 있습니다.

    ```xml
    <network-security-config>
        <domain-config>
            <domain includeSubdomains="true">yourdomain.com</domain>
            <pin-set expiration="2024-12-31">
                <pin algorithm="sha256">AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=</pin>
            </pin-set>
        </domain-config>
    </network-security-config>
    ```

### iOS

1. **TrustKit**  
   - iOS에서는 **TrustKit**이라는 오픈 소스 SSL 핀닝 라이브러리를 사용하는 것이 가장 일반적입니다.  
   - TrustKit은 직관적인 API를 제공하며, 안전하고 간단하게 핀닝을 구현할 수 있습니다.

    ```swift
    import TrustKit

    @UIApplicationMain
    class AppDelegate: UIResponder, UIApplicationDelegate {
        var window: UIWindow?

        func application(_ application: UIApplication, didFinishLaunchingWithOptions launchOptions: [UIApplication.LaunchOptionsKey: Any]?) -> Bool {
            let trustKitConfig: [String: Any] = [
                kTSKSwizzleNetworkDelegates: true,
                kTSKPinnedDomains: [
                    "yourdomain.com": [
                        kTSKIncludeSubdomains: true,
                        kTSKEnforcePinning: true,
                        kTSKPublicKeyHashes: [
                            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
                        ]
                    ]
                ]
            ]

            TrustKit.initSharedInstance(withConfiguration: trustKitConfig)
            return true
        }
    }
    ```

2. **직접 구현**  
   - TrustKit을 사용하지 않을 경우 직접 핀ning 로직을 구현해야 할 수 있습니다.  
   - 하지만, 잘못된 설계나 구현으로 인해 보안 취약점이 발생할 위험이 있습니다. 전문가가 아닌 경우 권장되지 않습니다.

    ```swift
    func urlSession(_ session: URLSession, didReceive challenge: URLAuthenticationChallenge,
                completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void) {
        guard let serverTrust = challenge.protectionSpace.serverTrust else {
            completionHandler(.cancelAuthenticationChallenge, nil)
            return
        }

        let policies = [SecPolicyCreateSSL(true, challenge.protectionSpace.host as CFString)]
        SecTrustSetPolicies(serverTrust, policies as CFTypeRef)

        var secresult = SecTrustResultType.invalid
        if SecTrustEvaluate(serverTrust, &secresult) == errSecSuccess {
            let serverCert = SecTrustGetCertificateAtIndex(serverTrust, 0)!
            let serverCertData = SecCertificateCopyData(serverCert) as Data
            let localCertData = NSData(contentsOfFile: Bundle.main.path(forResource: "your_cert", ofType: "cer")!)!

            if serverCertData == localCertData as Data {
                completionHandler(.useCredential, URLCredential(trust: serverTrust))
                return
            }
        }

        completionHandler(.cancelAuthenticationChallenge, nil)
    }
    ```

### .NET

- .NET에서는 **ServicePointManager**를 통해 핀ning을 구현할 수 있습니다.  
- Android의 CertificatePinner처럼 fingerprint를 소스 코드에 직접 하드코딩하거나, 빌드 시점에 외부 설정에서 가져오는 방식을 사용할 수 있습니다.  
- 가능하면 하드코딩보다는 빌드 시점 설정 파일에서 값을 가져오는 방식이 선호됩니다.

```csharp
using System;
using System.Net;
using System.Security.Cryptography.X509Certificates;

class Program
{
    static void Main()
    {
        ServicePointManager.ServerCertificateValidationCallback += (sender, cert, chain, errors) =>
        {
            var expectedFingerprint = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
            var actualFingerprint = Convert.ToBase64String(cert.GetCertHash());
            return actualFingerprint == expectedFingerprint;
        };

        // Example HTTP request
        var client = new WebClient();
        var response = client.DownloadString("https://yourdomain.com");
        Console.WriteLine(response);
    }
}
```