---
title: Cyber Kill Chain
tags: Cyber-Kill-Chain
key: page-cyber_kill_chain
categories: [Cybersecurity, Threat Intelligence]
author: hyoeun
math: true
mathjax_autoNumber: true
---

## All About the Cyber Kill Chain and Attack Infrastructure

### Overview
The Cyber Kill Chain is an information security model developed by Lockheed Martin to defend its own internal network. The framework's purpose is to systematically analyze the series of steps an adversary performs to achieve their objective, thereby identifying opportunities to detect and block the attack at each stage. The Kill Chain serves as a highly useful conceptual tool for understanding the entire flow of an attack and for formulating defense strategies.

### The 7 Stages of the Cyber Kill Chain
The Cyber Kill Chain divides an attacker's activities into seven distinct stages. Each stage builds upon the success of the previous one, and defenders can neutralize an attack by breaking any link in this chain.

**1. Reconnaissance**

This is the first stage, where the attacker gathers information about the target organization. During this phase, the attacker leverages publicly available information (OSINT) to understand the target's network environment, technology stack, organizational structure, and employee details. The primary techniques used are:
* **Passive Reconnaissance**: Gathering information without leaving a trace through sources like social media, job-seeking sites, the company's public website, DNS records, and WHOIS information.
* **Active Reconnaissance**: Collecting system information through direct interaction, such as port scanning (Nmap), network topology mapping, and vulnerability scanning. This carries a risk of detection.

**2. Weaponization**

Based on the intelligence gathered during reconnaissance, the attacker creates a malicious payload. This payload is designed to exploit vulnerabilities in the target system and is often combined with an exploit that enables Remote Code Execution. For example, creating a malicious PDF document that targets a specific version of Adobe Flash Player or crafting a Microsoft Office document with malicious macros falls into this stage. This stage goes beyond using existing tools and is directly linked to the specialized field of **Malware Development**.

Malware development refers to the creation of custom malware designed to bypass modern security solutions like Antivirus (AV) and Endpoint Detection and Response (EDR). Developed malware may include advanced techniques such as running only in system memory to minimize its footprint (Fileless Malware), injecting code into legitimate processes (Process Injection), and obfuscating API calls.

The core objective of this stage is to ensure the created malware can pass through initial defense systems like email gateways, sandboxes, and AV scanners. To achieve this, attackers employ techniques like code obfuscation to evade signature-based detection and anti-sandbox methods that detect virtual environments and hide malicious behavior. In short, this stage focuses on disguising the weapon itself so it can pass through security checkpoints undetected.

**3. Delivery**

This is the stage where the weaponized payload is transmitted to the target system. The most common delivery vectors include:
* **Email Phishing**: Sending emails that impersonate a trusted sender and contain malicious attachments or links.
* **Watering Hole**: Compromising a website frequently visited by members of the target organization to automatically download malware onto their systems.
* **USB Drive**: If physical access is possible, leaving a malware-infected USB drive within the organization's premises to exploit user curiosity.

**4. Exploitation**

In this stage, the delivered payload is executed on the target system, triggering a vulnerability. A successful exploit provides a foothold for executing additional malicious code (the implant).

**5. Installation**

The attacker establishes persistence on the system to maintain the initial access they have gained. This is often achieved by installing malware such as a backdoor or a Remote Access Trojan (RAT).

**6. Command & Control (C2)**

The installed malware establishes a communication channel with an external C2 server. Through this channel, the attacker can remotely issue commands to the compromised system, download additional malicious scripts, or exfiltrate internal system information. To evade detection, C2 communication often uses common protocols like HTTP/HTTPS, DNS, or ICMP, and the traffic is frequently encrypted or disguised. Once the malware successfully bypasses initial defenses and is installed on a system, the focus of the attack shifts to concealing post-compromise activities. The key objective of the C2 phase is to evade behavior-based and network traffic monitoring solutions like EDR, network firewalls, and IDS/IPS to maintain persistent control. This process is analogous to a spy who has successfully infiltrated a target and is now secretly communicating with their headquarters.

#### Example C2 Infrastructure Setup (Using AWS)
Building a stable and hard-to-trace C2 infrastructure is a core component of modern attacks. Cloud services, particularly **AWS (Amazon Web Services)**, are widely used for this purpose.

1.  **C2 Server Hosting**: An attacker uses an AWS **EC2 (Elastic Compute Cloud)** instance to host their C2 server (team server). EC2 offers the flexibility to scale computing resources as needed and has the advantage of blending in with legitimate web traffic, making detection difficult.
2.  **Setting up Redirectors**: Direct communication between an infected system (implant) and the C2 server is risky. If the defense team detects this communication and blocks the C2 server's IP, the entire infrastructure is neutralized. To prevent this, attackers place **redirectors** in between.
    * **How it works**: A web server like Nginx or Apache is installed on a cheap VPS or another EC2 instance. It is configured to forward (proxy) only the traffic that meets specific criteria (e.g., a specific User-Agent, URI path) to the actual C2 server. All other traffic is redirected to a legitimate website (like Google). This makes it difficult for analysts to trace the infrastructure.
3.  **Domain Fronting**: This technique disguises C2 traffic by using a high-reputation domain. For instance, an attacker can use a CDN (Content Delivery Network) service like AWS **CloudFront**. The implant sends an HTTPS request to a legitimate CloudFront domain (`*.cloudfront.net`), but the HTTP Host header specifies the domain of the actual C2 server. Most network security appliances, unable to inspect the encrypted traffic, will see this as a legitimate connection to the CDN.
4.  **Domain Aging**: Attackers pre-register a large number of domains for phishing or malicious C2 servers and let them sit dormant for a period of time (from weeks to months). This "aging" process allows them to bypass **NRD (Newly Registered Domain)** detection policies, as security solutions are less likely to flag and block older, established domains.

#### Major C2 Frameworks
C2 frameworks are integrated toolkits for efficiently managing numerous compromised systems and executing attacks.
* **Cobalt Strike**: A commercial framework considered the industry standard for red teaming and adversary simulation. It uses a powerful payload called 'Beacon' and features Malleable C2 profiles that can meticulously disguise communication traffic to look like legitimate applications (e.g., Netflix, Gmail).
* **Metasploit Framework**: One of the most famous open-source frameworks, providing C2 capabilities through its powerful in-memory payload, 'Meterpreter.' It is integrated with a vast library of exploits, enabling everything from initial penetration to post-exploitation.
* **Sliver / Havoc / Mythic**: These are popular, modern open-source frameworks. Developed in languages like Go and C++, they support cross-platform operations, incorporate the latest EDR evasion techniques, and feature a modular architecture for easy extension.

**7. Actions on Objectives**

In the final stage of the attack, the adversary executes their original goals. This can manifest as **Data Exfiltration** (stealing confidential organizational data), **Sabotage** (destroying systems), or **Ransomware** (encrypting data and demanding payment).

### The Relationship Between a Full Chain Attack and the Kill Chain Model
It is important to distinguish between the **Cyber Kill Chain as a 'theoretical model'** and a **Full Chain Attack as a 'successful real-world execution'** of that model.

* **Cyber Kill Chain**: A **framework or blueprint** that describes the stages of an attack. It is an analytical tool for defenders to understand attacks on a stage-by-stage basis and identify points for interception.
* **Full Chain Attack**: A specific, concrete attack in which **all stages described in the Cyber Kill Chain model, from reconnaissance to actions on objectives, are successfully linked and completed.**

Advanced Persistent Threat (APT) attacks are prime examples of full chain attacks.
1.  **Reconnaissance**: The attacker identifies an engineer in a specific department of the target company via LinkedIn.
2.  **Weaponization**: They craft an exploit for a zero-day vulnerability in the web browser the engineer is likely to use and embed it on a malicious website.
3.  **Delivery**: Using social engineering, they send a spear-phishing email to the engineer with the subject line "Project-Related Documents," containing a link to the malicious website.
4.  **Exploitation**: When the engineer clicks the link, the browser's zero-day vulnerability is triggered, and the attacker's code is executed on the system.
5.  **Installation**: After gaining initial access, a PowerShell-based backdoor is loaded into memory to establish persistence.
6.  **C2**: The backdoor begins communicating with an external C2 server using DNS tunneling to evade detection.
7.  **Actions on Objectives**: Through the C2 channel, the attacker scans the internal network, exploits an Active Directory vulnerability to escalate privileges to Domain Admin, and finally exfiltrates the company's core design blueprints.

Because each stage of a full chain attack is intricately connected, it is difficult for defenders to stop the entire attack by blocking just a single piece of malware or one vulnerability. Therefore, a Defense in Depth strategy, based on the Cyber Kill Chain model, is essential to break the chain of the attack as early as possible.

### Modern Attack Trends: The Attack Surface is Shifting from the Perimeter to the Interior

The paradigm of cyber attack and defense is changing. In the past, **Perimeter Security**, which focused on protecting internal assets from external threats, was the most critical defense strategy. Today, however, the center of gravity for attacks is shifting beyond the perimeter and into the organization's **interior**.

#### Hardened Perimeters and New Attack Solutions
For decades, enterprises have invested heavily in hardening their external perimeters with Next-Generation Firewalls (NGFWs), email gateways, and advanced phishing awareness training. As a result, the difficulty of achieving initial access from a zero-base starting point has increased significantly compared to the past.

This strengthened defensive posture has presented a new challenge for attackers, who have naturally turned their attention to an easier and more effective path: **attack scenarios that begin from within**.

#### Attacks Starting from the Inside: Assumed Breach
The concept that best reflects this trend is **'Assumed Breach.'** This is an approach to building a defense strategy based on the assumption that "a breach is inevitable, and threats already exist inside." Red Team exercises have also evolved, with many now being conducted from the perspective of an attacker who has already established a foothold on the internal network, rather than just simulating an external intrusion.

The primary ways modern attackers compromise the interior are as follows:

* **Acquiring Valid Credentials**: On the dark web, access credentials for corporate internal systems are traded at surprisingly low prices. Attackers can purchase these or bribe an insider with financial incentives to easily gain an initial foothold.
* **Social Engineering**: This method exploits human trust instead of technical vulnerabilities. Help desks and IT support departments are prime targets for social engineering attacks, as they have high-level access to internal systems and are required to respond to support requests.
* **Supply Chain Attack**: This approach involves first compromising a third-party partner or software vendor with relatively weaker defenses and using that access as a bridgehead to pivot into the main target's internal network.

In conclusion, modern defense strategies must evolve beyond simply blocking external attacks and focus on **how quickly one can detect and respond to an attacker who is already inside the network**. This re-emphasizes the importance of a **Zero Trust** architecture, internal network segmentation, and the continuous monitoring and threat detection (NDR/EDR) of core infrastructure like Active Directory.

---

## 사이버 킬 체인(Cyber Kill Chain)과 공격 인프라의 모든 것

### 개요
사이버 킬 체인(Cyber Kill Chain)은 록히드 마틴(Lockheed Martin)이 자사의 내부 네트워크를 방어하기 위해 개발한 정보 보안 모델입니다. 이 프레임워크는 공격자가 목표를 달성하기 위해 수행하는 일련의 단계를 체계적으로 분석하여, 각 단계에서 공격을 탐지하고 차단할 기회를 식별하는 데 목적이 있습니다. 킬 체인은 공격의 전체 흐름을 이해하고, 방어 전략을 수립하는 데 매우 유용한 개념적 도구로 활용됩니다.

### 사이버 킬 체인의 7단계
사이버 킬 체인은 공격자의 활동을 7개의 주요 단계로 구분합니다. 각 단계는 이전 단계의 성공을 기반으로 진행되며, 방어자는 이 체인의 연결고리를 끊음으로써 공격을 무력화할 수 있습니다.

**1. 정찰 (Reconnaissance)**

공격자가 목표 조직에 대한 정보를 수집하는 첫 단계입니다. 이 단계에서 공격자는 공개적으로 접근 가능한 정보(OSINT)를 활용하여 목표의 네트워크 환경, 사용 기술 스택, 조직 구조, 임직원 정보 등을 파악합니다. 주로 사용되는 기술은 다음과 같습니다.
* **Passive Reconnaissance**: 소셜 미디어, 구직 사이트, 회사의 공개 웹사이트, DNS 레코드, WHOIS 정보 등을 통해 흔적을 남기지 않고 정보를 수집합니다.
* **Active Reconnaissance**: 포트 스캐닝(Nmap), 네트워크 토폴로지 매핑, 취약점 스캐닝 등을 통해 직접적인 상호작용으로 시스템 정보를 수집합니다. 이 과정에서 탐지될 위험이 존재합니다.

**2. 무기화 (Weaponization)**

정찰을 통해 얻은 정보를 바탕으로 공격자는 악성 페이로드를 제작합니다. 이 페이로드는 목표 시스템의 취약점을 악용하도록 설계되며, 주로 원격 코드 실행(Remote Code Execution)을 가능하게 하는 익스플로잇과 결합됩니다. 예를 들어, 특정 버전의 Adobe Flash Player 취약점을 타겟으로 하는 악성 PDF 문서를 생성하거나, 매크로를 포함한 Microsoft Office 문서를 만드는 과정이 이 단계에 해당합니다. 이 단계는 단순히 기존 도구를 사용하는 것을 넘어 **악성코드 개발(Malware Development)** 이라는 전문 분야와 직결됩니다.

악성코드 개발이란, AV(Antivirus)나 EDR(Endpoint Detection and Response) 같은 최신 보안 솔루션의 탐지를 우회할 목적으로 맞춤형 악성코드를 제작하는 행위를 의미합니다. 개발된 악성코드는 시스템 메모리상에서만 실행되어 흔적을 최소화하거나(Fileless Malware), 정상 프로세스에 코드를 주입(Process Injection)하고, API 호출을 난독화하는 등의 고도화된 기법을 포함합니다.

이 단계의 핵심 목표는 제작된 악성코드가 초기 방어 시스템, 즉 이메일 게이트웨이, 샌드박스, Anti-Virus(백신) 의 탐지를 통과하도록 만드는 것입니다. 이를 위해 시그니처 기반 탐지를 피하는 코드 난독화, 가상 환경을 탐지해 악성 행위를 숨기는 안티-샌드박스 기법 등이 적용됩니다. 한마디로, 만들어진 무기 자체가 검문소를 들키지 않고 통과하도록 위장하는 데 집중하는 단계입니다.

**3. 전달 (Delivery)**

제작된 악성 페이로드를 목표 시스템에 전달하는 단계입니다. 가장 일반적인 전달 경로는 다음과 같습니다.
* **이메일 피싱(Phishing)**: 신뢰할 수 있는 발신자로 위장하여 악성 첨부파일이나 링크를 포함한 이메일을 발송합니다.
* **워터링 홀(Watering Hole)**: 목표 조직의 구성원들이 자주 방문하는 웹사이트를 감염시켜, 방문 시 악성 코드가 자동으로 다운로드되도록 합니다.
* **USB 드라이브**: 물리적 접근이 가능한 경우, 악성 코드가 담긴 USB를 조직 내부에 두어 사용자의 호기심을 유발합니다.

**4. 공격 (Exploitation)**

전달된 악성 페이로드가 목표 시스템에서 실행되어 취약점을 공격하는 단계입니다. 성공적인 익스플로잇은 추가적인 악성 코드(임플란트)를 실행할 수 있는 발판을 마련합니다.

**5. 설치 (Installation)**

공격자는 획득한 초기 접근 권한을 유지하기 위해 시스템에 지속성(Persistence)을 확보합니다. 이를 위해 백도어(Backdoor)나 원격 관리 도구(RAT, Remote Access Trojan)와 같은 멀웨어를 설치합니다.

**6. 명령 및 제어 (Command & Control, C2)**

설치된 멀웨어는 외부의 C2 서버와 통신 채널을 구축합니다. 공격자는 이 채널을 통해 감염된 시스템에 원격으로 명령을 내리고, 추가적인 악성 스크립트를 다운로드하거나 내부 시스템 정보를 유출할 수 있습니다. C2 통신은 탐지를 피하기 위해 HTTP/HTTPS, DNS, ICMP 등 일반적인 프로토콜을 사용하거나 암호화하여 트래픽을 위장하는 경우가 많습니다. 악성코드가 초기 방어선을 뚫고 시스템에 성공적으로 설치되면, 공격의 초점은 침투 후 활동을 은닉하는 것으로 전환됩니다. 이 C2 단계의 핵심 목표는 EDR, 네트워크 방화벽, IDS/IPS 와 같은 행위 기반 및 네트워크 트래픽 감시 솔루션을 회피하여 지속적인 통제권을 유지하는 것입니다. 이는 잠입에 성공한 스파이가 본부와 몰래 연락을 주고받는 과정과 같습니다.

#### C2 인프라 구축 예시 (AWS 활용)
안정적이고 추적이 어려운 C2 인프라를 구축하는 것은 현대 공격의 핵심입니다. 클라우드 서비스, 특히 **AWS(Amazon Web Services)** 는 이러한 인프라 구축에 널리 사용됩니다.

1. **C2 서버 호스팅**: 공격자는 AWS의 **EC2(Elastic Compute Cloud)** 인스턴스를 사용하여 C2 서버(팀 서버)를 호스팅합니다. EC2는 필요에 따라 컴퓨팅 자원을 유연하게 조절할 수 있고, 정상적인 웹 트래픽과 섞여 탐지를 어렵게 만드는 장점이 있습니다.
2. **리디렉터(Redirector) 설정**: 감염된 시스템(임플란트)이 C2 서버와 직접 통신하는 것은 위험합니다. 방어팀이 통신을 탐지하여 C2 서버의 IP를 차단하면 전체 인프라가 무력화되기 때문입니다. 이를 방지하기 위해 중간에 **리디렉터**를 둡니다.
    * **작동 방식**: 저렴한 VPS나 또 다른 EC2 인스턴스에 Nginx나 Apache 같은 웹 서버를 설치합니다. 그리고 특정 조건(User-Agent, URI 경로 등)을 만족하는 트래픽만 실제 C2 서버로 전달(프록시)하고, 그 외의 모든 트래픽은 정상적인 웹사이트(예: 구글)로 보내버립니다. 이를 통해 분석가의 추적을 어렵게 만듭니다.
3. **도메인 프론팅(Domain Fronting)**: 신뢰도가 높은 도메인을 사용하여 C2 트래픽을 위장하는 기법입니다. 예를 들어, AWS의 **CloudFront**와 같은 CDN(Content Delivery Network) 서비스를 이용합니다. 임플란트는 CloudFront의 정상적인 도메인(`*.cloudfront.net`)으로 HTTPS 요청을 보내지만, HTTP Host 헤더에는 실제 C2 서버의 도메인을 지정합니다. 암호화된 트래픽 내부를 볼 수 없는 대부분의 네트워크 보안 장비는 이 트래픽을 정상적인 CDN 접속으로 판단하게 됩니다.
4. **도메인 에이징(Domain Aging)**: 공격자가 피싱이나 악성 C2 서버에 사용할 도메인을 미리 대량으로 등록해 놓고, 아무것도 하지 않은 채 일정 시간(수 주에서 수개월) 동안 방치하여 '숙성'시켜 보안 솔루션들이 의심하고 차단하지 않도록 **NRD(Newly Registered Domain, 신규 등록 도메인)** 탐지 정책을 우회합니다.

#### 주요 C2 프레임워크
C2 프레임워크는 감염된 다수의 시스템을 효율적으로 관리하고 공격을 수행하기 위한 통합 도구입니다.
* **Cobalt Strike**: 상용 프레임워크로, 레드팀 및 공격 시뮬레이션의 산업 표준으로 여겨집니다. 'Beacon'이라는 강력한 페이로드를 사용하며, Malleable C2 프로필을 통해 통신 트래픽을 정상적인 애플리케이션 트래픽(예: Netflix, Gmail)처럼 보이도록 정교하게 위장할 수 있습니다.
* **Metasploit Framework**: 가장 유명한 오픈소스 프레임워크 중 하나로, 'Meterpreter'라는 강력한 인메모리 페이로드를 통해 C2 기능을 제공합니다. 방대한 익스플로잇 라이브러리와 통합되어 초기 침투부터 후반 작업까지 모두 가능합니다.
* **Sliver / Havoc / Mythic**: 최근 각광받는 오픈소스 프레임워크들입니다. Go나 C++ 등 다양한 언어로 개발되어 크로스플랫폼을 지원하고, 최신 EDR 우회 기법들이 적용되어 있으며, 모듈식 구조로 확장이 용이하다는 장점이 있습니다.

**7. 목표 달성 (Actions on Objectives)**

공격의 최종 단계로, 공격자는 원래의 목표를 실행에 옮깁니다. 이는 조직의 기밀 데이터를 유출(Data Exfiltration)하거나, 시스템을 파괴(Sabotage)하거나, 데이터를 암호화하여 금전을 요구(Ransomware)하는 등의 형태로 나타날 수 있습니다.

### 풀 체인 공격(Full Chain Attack)과 킬 체인 모델의 관계
여기서 중요한 것은 **사이버 킬 체인은 '이론적인 모델'**이고, **풀 체인 공격은 그 모델이 '실제로 성공한 공격'**이라는 점을 구분하는 것입니다.

* **사이버 킬 체인**: 공격의 단계를 설명하는 **프레임워크 또는 청사진**입니다. 방어자가 공격을 단계별로 이해하고 차단 지점을 식별하기 위한 분석 도구입니다.
* **풀 체인 공격**: 사이버 킬 체인 모델에 설명된 **정찰부터 목표 달성까지 모든 단계가 성공적으로 연결되어 완결된 구체적인 공격** 자체를 의미합니다.

APT(Advanced Persistent Threat) 공격은 풀 체인 공격의 대표적인 예시입니다.
1.  **정찰**: 공격자는 LinkedIn을 통해 목표 기업의 특정 부서 엔지니어를 식별합니다.
2.  **무기화**: 해당 엔지니어가 사용할 가능성이 높은 웹 브라우저의 제로데이 취약점을 이용하는 익스플로잇을 제작하고, 이를 악성 웹사이트에 심습니다.
3.  **전달**: 사회 공학 기법을 이용해 "프로젝트 관련 자료"라는 제목의 스피어 피싱 이메일을 엔지니어에게 보내고, 이메일 본문에는 제작된 악성 웹사이트 링크를 포함시킵니다.
4.  **공격**: 엔지니어가 링크를 클릭하면 브라우저의 제로데이 취약점이 트리거되어 공격자의 코드가 시스템에서 실행됩니다.
5.  **설치**: 초기 접근 후, 파워셸 기반의 백도어를 메모리에 상주시켜 지속성을 확보합니다.
6.  **C2**: 백도어는 DNS 터널링을 이용해 외부 C2 서버와 통신을 시작하여 탐지를 우회합니다.
7.  **목표 달성**: 공격자는 C2 채널을 통해 내부 네트워크를 스캔하고, Active Directory의 취약점을 이용해 도메인 관리자 권한을 탈취한 후, 최종적으로 회사의 핵심 설계 도면을 외부로 유출합니다.

이처럼 풀 체인 공격은 각 단계가 정교하게 맞물려 돌아가기 때문에, 방어자는 단순히 특정 악성코드나 취약점 하나를 막는 것만으로는 전체 공격을 방어하기 어렵습니다. 따라서 사이버 킬 체인 모델에 기반하여 각 단계별로 방어 전략을 수립하고, 공격의 연결고리를 초기에 끊어내는 심층 방어(Defense in Depth) 전략이 필수적입니다.

물론입니다. 제공해주신 핵심 내용을 바탕으로 현대 공격 트렌드에 대한 글을 전문적이고 논리적인 흐름으로 완성해 드리겠습니다.

### 현대 공격 트렌드: 경계에서 내부로 이동하는 공격 표면

사이버 공격과 방어의 패러다임이 변화하고 있습니다. 과거에는 외부의 위협으로부터 내부 자산을 보호하는 **경계 보안(Perimeter Security)** 이 가장 중요한 방어 전략이었습니다. 그러나 오늘날, 공격의 무게 중심은 경계를 넘어 조직의 **내부**로 이동하고 있습니다.

#### 견고해진 경계와 공격의 새로운 해법
과거 수십 년간 기업들은 차세대 방화벽(NGFW), 이메일 게이트웨이, 고도화된 피싱 인식 교육 등을 통해 외부 경계를 견고하게 만드는 데 막대한 투자를 했습니다. 그 결과, 외부에서 제로베이스로 시작하는 초기 침투(Initial Access)의 난이도는 과거에 비해 크게 상승했습니다.

이처럼 강화된 방어 체계는 공격자들에게 새로운 숙제를 안겨주었고, 그들은 자연스럽게 더 쉽고 효과적인 경로, 즉 **내부에서 시작하는 공격 시나리오**로 눈을 돌리게 되었습니다.

#### 내부에서 시작되는 공격: Assumed Breach
이러한 트렌드를 가장 잘 반영하는 개념이 바로 **'Assumed Breach'** 입니다. 이는 "침해는 피할 수 없으며, 이미 내부에 위협이 존재한다"고 가정하고 방어 전략을 수립하는 접근 방식입니다. 레드팀 훈련 역시 외부 침투 시뮬레이션뿐만 아니라, 이미 내부망에 발판을 확보한 공격자 관점에서 진행되는 경우가 많아졌습니다.

현대의 공격자들이 내부를 공략하는 주요 방식은 다음과 같습니다.

* **유효한 자격 증명 획득 **: 다크웹에서는 생각보다 저렴한 가격에 기업 내부 시스템의 접근 권한(Credentials)이 거래되고 있습니다. 공격자는 이를 구매하거나, 금전적 보상을 미끼로 내부자를 매수하여 손쉽게 첫 발판을 마련합니다.
* **사회 공학 기법**: 기술적인 취약점 대신 사람의 신뢰를 이용하는 방식입니다. 특히 헬프 데스크나 IT 지원 부서는 내부 시스템에 대한 접근 권한이 높고 지원 요청에 응해야 하는 입장이므로 사회 공학 공격의 핵심 타겟이 됩니다.
* **공급망 공격 (Supply Chain Attack)**: 방어 체계가 상대적으로 허술한 서드파티 협력업체나 소프트웨어 공급망을 먼저 장악한 후, 이를 교두보 삼아 최종 목표인 기업의 내부망으로 접근하는 방식입니다.

결론적으로, 현대의 방어 전략은 단순히 외부 공격을 막는 것에서 더 나아가, **내부에 침입한 공격자를 얼마나 빨리 탐지하고 대응할 수 있는가**에 초점을 맞춰야 합니다. 이는 **제로 트러스트(Zero Trust)** 아키텍처, 내부망 세분화, 그리고 Active Directory와 같은 핵심 인프라에 대한 지속적인 모니터링 및 위협 탐지(NDR/EDR)의 중요성을 다시 한번 강조합니다.