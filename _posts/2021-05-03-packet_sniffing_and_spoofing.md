---
title: Packet Sniffing and Spoofing
tags: Packet-Sniffing Spoofing Cybersecurity
key: page-packet_sniffing_spoofing
categories: [Cybersecurity, Network Security]
author: hyoeun
math: true
mathjax_autoNumber: true
---

### **1. The Difference Between Sniffing and Spoofing**

* **Sniffing**: This is an attack where an attacker silently **eavesdrops** on network traffic to **capture** information. This is typically done by setting a Network Interface Card (NIC) to an abnormal mode to intercept all packets, including those not addressed to it.
* **Spoofing**: In this type of attack, a malicious actor sends packets with a **fake identity**. For example, they might forge a MAC address or an IP address to deceive network systems.

---

### **2. How Packets Are Received and Processed**

A network packet typically reaches a computer through the following process:

1.  **NIC Reception**: A **frame** transmitted over a network medium arrives at the computer's NIC.
2.  **NIC Memory Buffering**: The NIC temporarily stores the incoming frame in its internal memory.
3.  **MAC Address Check**: The NIC checks the **Destination MAC Address** in the frame's header. It proceeds to the next step only if this address matches its own MAC address or is a broadcast address.
4.  **Delivery to the Kernel**: If the MAC address matches, the frame is delivered to the kernel's memory buffer, known as the **Ring Buffer**, via **DMA (Direct Memory Access)**.
5.  **Frame Discard**: If the destination MAC address of the frame does not match the NIC's MAC address, the NIC immediately discards it without passing it to the OS. This is why, under normal circumstances, you cannot see network traffic not destined for your machine.

---

### **3. Special Modes That Enable Sniffing**

#### **3.1. Promiscuous Mode**

* **How it works**: This mode is used in a wired network (Ethernet) environment. Most NICs support **Promiscuous Mode**, and when it's enabled, the NIC sends **all frames** that arrive at the NIC to the kernel, regardless of whether the MAC address matches.
* **Relationship to sniffing**: All these frames are forwarded to a **sniffer program** registered with the kernel. This allows the sniffer program to capture and analyze all network traffic. Running such a program typically requires **elevated privileges**.

#### **3.2. Monitor Mode**

* **How it works**: This mode is used to enable sniffing in a wireless network (Wi-Fi) environment. A standard wireless NIC only sends and receives data on a specific channel to prevent performance degradation from interference. However, when **Monitor Mode** is activated, the NIC can capture packets on channels other than the one it is connected to.
* **Limitations**: Not all wireless NICs support Monitor Mode, and even if they do, their capabilities might be limited to specific channels.

---

### **4. Packet Filtering: BPF (BSD Packet Filter)**

Sniffer programs are usually interested in specific packets, not all of them. Filtering all packets after they are forwarded from the kernel to the user space is inefficient. To solve this, a low-level filtering mechanism like **BPF (BSD Packet Filter)** is used.

* **Role of BPF**: BPF is a kernel feature in **Unix-based** operating systems that helps sniffer programs efficiently filter for desired packets.
* **How it works**: A user program writes a human-readable filter rule (e.g., `port 80`, `src host 192.168.1.1`), which is then compiled by a BPF compiler and attached to a socket in the kernel. When a packet arrives at the kernel, the BPF filter is immediately invoked to decide whether to **accept** or **drop** the packet. This prevents unnecessary packets from being passed to the user space.
* **Windows Environment**: On Windows, separate mechanisms like WinPcap or Npcap are used to provide similar packet capture and filtering capabilities.

---

### **5. In-depth Analysis of Spoofing Attacks**

While sniffing is a passive act of "eavesdropping," spoofing is an active attack where an attacker "forges an identity" to interfere with network communication. By using a fake identity, an attacker can break the network's trust model and trick systems into performing unintended actions.

#### **5.1. ARP Spoofing**

**ARP (Address Resolution Protocol)** is used to translate an IP address into a physical MAC address on a local area network (LAN). Attackers exploit a vulnerability in this protocol by sending forged ARP response packets to the network.

* **How it works**: The attacker sends their own MAC address in response to an ARP query for a specific IP address (e.g., the gateway). This process, when repeated, can poison the victim's ARP cache table, causing all packets destined for the gateway to be routed through the attacker's machine.  This enables the attacker not only to perform sniffing but also to manipulate packets (man-in-the-middle) or block them entirely.
* **Defense strategies**: This can be mitigated by using static ARP entries or deploying switches with built-in ARP spoofing prevention features.

#### **5.2. IP Spoofing**

**IP Spoofing** is an attack where a sender uses a different IP address than their actual one to send packets. This is primarily used to bypass firewalls or launch DDoS (Distributed Denial of Service) attacks.

* **How it works**: An attacker manipulates the 'Source' IP address field in a packet's IP header to insert a forged IP address. The packet reaches its destination, but the response packet is sent to a different location—the forged address—not the attacker. This characteristic makes IP spoofing especially effective for UDP-based DDoS attacks that don't require a response.
* **Defense strategies**: **Ingress Filtering** is applied at the network perimeter to check if the source IP address of packets leaving the internal network falls within the internal IP address range. It's the responsibility of internal network administrators and ISPs to manage this. Managing this is critical because, even if your organization isn't the victim of a DDoS attack, being identified as the source can lead to legal and ethical issues, damaging your organization's reputation and trustworthiness.

### **Reference**

* [COMPUTER SECURITY: A Hands-on Approach by Wenliang Du](https://www.amazon.com/Computer-Security-Hands-Approach-Wenliang/dp/154836794X)

---

### **1. 스니핑(Sniffing)과 스푸핑(Spoofing)의 차이점**

* **스니핑(Sniffing)**: 네트워크 상에서 오가는 패킷을 몰래 **엿듣고(eavesdrop)** 정보를 **캡처(capture)**하는 공격입니다. 주로 네트워크 인터페이스 카드를 비정상적인 모드로 설정하여 자신에게 향하지 않는 패킷까지 모두 가로챕니다.
* **스푸핑(Spoofing)**: 실제로는 다른 사람 또는 장치인데, **가짜 신분(fake identity)**으로 패킷을 보내는 공격입니다. 예를 들어, MAC 주소나 IP 주소를 위조하여 네트워크 시스템을 속이는 행위가 여기에 해당합니다.

---

### **2. 패킷 수신 및 처리 과정**

일반적으로 네트워크 패킷이 컴퓨터에 도달하는 과정은 다음과 같습니다.

1. **NIC(Network Interface Card) 수신**: 네트워크를 통해 전송된 **프레임(frame)**이 매체(medium)를 타고 컴퓨터의 NIC에 도착합니다.
2. **NIC 메모리 버퍼링**: NIC는 도착한 프레임을 내부 메모리에 임시로 저장합니다.
3. **MAC 주소 확인**: NIC는 프레임의 헤더에 있는 **목적지 MAC 주소(Destination MAC Address)**를 확인합니다. 이 주소가 자신의 MAC 주소와 일치하거나, 브로드캐스트 주소(broadcast address)인 경우에만 다음 단계로 진행합니다.
4. **커널로 전달**: MAC 주소가 일치하면, **DMA(Direct Memory Access)**를 통해 프레임이 커널의 메모리 버퍼인 **링 버퍼(Ring Buffer)**로 전달됩니다.
5. **프레임 폐기**: 만약 프레임의 목적지 MAC 주소가 NIC의 MAC 주소와 일치하지 않으면, NIC는 해당 프레임을 즉시 폐기하고 OS 단으로 전달하지 않습니다. 이 때문에 일반적인 상황에서는 자신에게 오지 않는 네트워크 트래픽을 볼 수 없는 것입니다.

---

### **3. 스니핑을 가능하게 하는 특별한 모드**

#### **3.1. Promiscuous Mode (무차별 모드)**

* **작동 원리**: 유선 네트워크(이더넷) 환경에서 사용되는 모드입니다. 대부분의 NIC는 **무차별 모드(Promiscuous Mode)**를 지원하며, 이 모드가 활성화되면 MAC 주소 일치 여부와 관계없이 NIC에 도착하는 **모든 프레임**을 커널로 보냅니다.
* **스니핑과의 관계**: 이렇게 커널로 전달된 모든 프레임은 커널에 등록된 **스니퍼(sniffer) 프로그램**으로 전달됩니다. 스니퍼 프로그램은 네트워크의 모든 트래픽을 캡처하고 분석할 수 있게 되므로, 이러한 프로그램을 실행하려면 높은 권한(elevated privilege)이 요구됩니다.

#### **3.2. Monitor Mode (모니터 모드)**

* **작동 원리**: 무선 네트워크(Wi-Fi) 환경에서 스니핑을 위해 사용되는 모드입니다. 일반적인 무선 NIC는 성능 저하를 막기 위해 특정 채널로 오가는 데이터만 주고받습니다. 예를 들어, Wi-Fi의 경우 802.11 프레임만 캡처합니다. 하지만 **모니터 모드(Monitor Mode)**를 활성화하면 NIC는 자신이 연결된 채널 외에 주변의 모든 채널을 오가는 패킷을 캡처할 수 있습니다.
* **한계**: 모든 무선 NIC가 모니터 모드를 지원하는 것은 아니며, 지원하더라도 특정 채널에 한정될 수 있습니다.

---

### **4. 패킷 필터링: BPF(BSD Packet Filter)**

스니퍼 프로그램은 모든 패킷을 캡처하기보다는 특정 조건에 맞는 패킷에만 관심이 있습니다. 따라서 커널에서 사용자 영역으로 모든 패킷을 보낸 후 필터링하는 것은 비효율적입니다. 이러한 비효율성을 해결하기 위해 **BPF(BSD Packet Filter)**와 같은 로우레벨(low-level) 필터링 메커니즘이 사용됩니다.

* **BPF의 역할**: BPF는 **유닉스(Unix)** 계열 운영체제에서 스니퍼 프로그램이 원하는 패킷만 효율적으로 필터링할 수 있도록 돕는 커널의 기능입니다.
* **작동 방식**: 사용자 프로그램은 사람이 읽을 수 있는 형태로 필터 규칙(예: `port 80`, `src host 192.168.1.1`)을 작성한 후, 이를 BPF 컴파일러로 컴파일하여 커널에 있는 소켓에 붙입니다. 패킷이 커널에 도착하면 BPF 필터가 즉시 호출되어 패킷을 받아들일지(accept) 버릴지(drop) 결정합니다. 이를 통해 사용자 영역으로 불필요한 패킷이 전달되는 것을 원천적으로 방지할 수 있습니다.
* **윈도우즈(Windows) 환경**: 윈도우즈에서는 WinPcap 또는 Npcap과 같은 별도의 메커니즘을 사용하여 유사한 패킷 캡처 및 필터링 기능을 제공합니다.

### **5. 스푸핑(Spoofing) 공격의 심층 분석**

스니핑이 수동적으로 정보를 '엿듣는' 행위라면, 스푸핑은 공격자가 적극적으로 '신분을 위조'하여 네트워크 통신에 개입하는 행위입니다. 공격자는 가짜 신원을 사용하여 네트워크의 신뢰 체계를 무너뜨리고, 시스템을 속여 의도하지 않은 동작을 유발할 수 있습니다.

#### **5.1. ARP 스푸핑(ARP Spoofing)**

**ARP(Address Resolution Protocol)**는 로컬 네트워크(LAN)에서 IP 주소를 물리적 MAC 주소로 변환하는 데 사용되는 프로토콜입니다. 공격자는 이 프로토콜의 취약점을 이용해 네트워크에 위조된 ARP 응답 패킷을 지속적으로 보낼 수 있습니다.

* **작동 원리**: 공격자는 특정 IP 주소(예: 게이트웨이)에 대한 MAC 주소 질의에 자신의 MAC 주소를 응답으로 보냅니다. 이 과정이 반복되면, 피해자의 ARP 캐시 테이블이 오염되어 게이트웨이로 가는 모든 패킷이 공격자의 장치를 경유하게 됩니다. 이를 통해 공격자는 스니핑 공격을 수행할 수 있을 뿐만 아니라, 패킷을 조작(man-in-the-middle)하거나 차단할 수도 있습니다.
* **방어 전략**: 정적 ARP 항목을 사용하거나, ARP 스푸핑 방지 기능이 있는 스위치를 배치하여 방어할 수 있습니다.

#### **5.2. IP 스푸핑(IP Spoofing)**

**IP 스푸핑**은 송신자가 자신의 실제 IP 주소 대신 다른 IP 주소를 사용하여 패킷을 보내는 공격입니다. 주로 방화벽을 우회하거나, 서버를 마비시키는 DDoS(Distributed Denial of Service) 공격에 활용됩니다.

* **작동 원리**: 공격자는 패킷의 IP 헤더에 있는 '발신지(Source)' IP 주소 필드를 조작하여 위조된 IP 주소를 삽입합니다. 이 패킷은 목적지에 도달하지만, 위조된 주소 때문에 응답 패킷은 공격자가 아닌 다른 곳으로 전달됩니다. 이러한 특성 때문에 IP 스푸핑은 주로 응답을 필요로 하지 않는 UDP 기반의 DDoS 공격에 효과적으로 사용됩니다.
* **방어 전략**: 네트워크 경계에서 **필터링(Ingress Filtering)**을 적용하여 내부 네트워크에서 외부 네트워크로 나가는 패킷의 발신지 IP 주소가 내부 IP 주소 범위에 속하는지 검사합니다. 조직 내부 네트워크 관리자 혹은 ISP에서 담당을 해야하는데, DDoS 공격이 우리 내부 다른 시스템이 될 수도 있고, 우리 조직 내부 공격이 아니더라도 우리가 그 공격의 근원지라는 것이 알려진다면 법적, 윤리적 문제가 발생하고 신뢰성이 깨질수도 있기 때문에 관리해야합니다.

### **Reference**

* [COMPUTER SECURITY: A Hands-on Approach by Wenliang Du](https://www.amazon.com/Computer-Security-Hands-Approach-Wenliang/dp/154836794X)