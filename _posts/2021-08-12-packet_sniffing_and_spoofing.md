---
title: Packet Sniffing and Spoofing
tags: security
key: page-packet_sniffing_and_spoofing
cover: /assets/cover/cyber_security.png
mathjax: true
mathjax_autoNumber: true
---

## Introduction
* Sniffing attacks에서는 정보들을 capture하고 eavesdrop(엿듣는)다.
* Spoofing attack에서는 가짜 신분으로 패킷을 보내는 것이다.
<br><br>

## How Packets Are Received
* Network Interface Card(NIC)로 network들이 이어진다. 
* frame이 medium을 통해 machine에 도착하면 NIC안에 메모리에 그것을 저장한다.
* network 영역에서 frame의 header안에 있는 destination 주소가 NIC의 MAC address와 일치하면 그제서야 Direct Memory Access(DMA)를 통해 kernel로 frame을 buffer(Ring buffer라 부른다)에 태워서 보낸다.
* 여기서 중요한 것은 frame의 destination이 NIC가 아니라면 버리기 때문에 OS단에서 볼 수가 없어서 network traffic을 sniff할 수 없는 것이다.
<br><br>

### Promiscuous Mode
* Wired network인 ethernet과 같은 곳에서 작동하는 모드이다.
* 대다수의 NIC에는 promiscuous mode라는 것이 있는데 이것이 작동하며녀 MAC주소와 매치되지 않아도 NIC를 거치는 모든 frame을 kernel로 보낸다.
* 따라서 kernel에 sniffer program이 등록되어 있으면 kernel에서 forward되는 모든 frame들이 프로그램으로 가게 되고 그런 프로그램들은 elevated privilege가 요구되기 마련이다.
<br><br>

### Monitor Mode
* Wireless network card에서 sniffing을 제공해주는 모드이다.
* 무선 장치는 주변 다른 장치들로부터 많은 간섭에 영향을 받아서 performance가 떨어지는데 이런것을 막기 위해서 일정 channel들에 오는 데이터만 주고받는다. Wifi의 경우 802.11 frames만 capture한다.
* 이 말은 같은 네트워크라도 채널이 다르면 정보를 놓칠 수 있다는 소리이다.
* 대다수의 Wireless NIC는 monitor mode를 지원하지 않거나 그것을 disable할 수 있는 모드가 존재한다.
<br><br>

## BSD Packet Filter (BPF)
* Sniffer는 모든 패킷에 관심있기 보다는 특정 패킷에 관심있을텐데 kernel을 지나고 user에게 온 것들을 필요한것만 남기고 나머지를 버리기 보다는 애초에 가능한 적은 비용으로 filtering하는게 효과적인데 Unix OS에는 BPF라는 필터 lower level에서 동작해준다.
* BPF allows a user-space program to attach a filter to a socket.
* filter를 사람이 읽을 수 있는 형태로 쓴 다음 컴파일해서 socket에 붙이면 kernel에 packet이 들어올때 바로 invoke되어 the packet이 accept되어야 할지 말아야할지 결정한다.
* Windows에서는 다른 방식의 mechanism이 존재한다.
<br><br>

## Refrence
* [COMPUTER SECURITY: A Hands-on Approach by Wenliang Du](https://www.amazon.com/Computer-Security-Hands-Approach-Wenliang/dp/154836794X)