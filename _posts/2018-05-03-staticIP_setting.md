---
title: CentOS7 고정 ip 설정
tags: CentOS7 Static-IP
key: page-centos7_static_ip_configuration
categories: [Software Engineering, Linux]
author: hyoeun
---
## 네트워크 설정 파일 열기
1. ifconfig를 통해 연결된 이더넷의 이름이 뭔지 확인합니다.
2. vim /etc/sysconfig/network-scripts/ifcfg-[이더넷 이름]
3. 그러면 다음과 같은 설정값들이 보일 것입니다.
```conf
TYPE="Ethernet"
PROXY_METHOD="none"
BROWSER_ONLY="no"
BOOTPROTO="dhcp"
DEFROUTE="yes"
IPV4_FAILURE_FATAL="no"
IPV6INIT="yes"
IPV6_AUTOCONF="yes"
IPV6_DEFROUTE="yes"
IPV6_FAILURE_FATAL="no"
IPV6_ADDR_GEN_MODE="stable-privacy"
NAME="enp0s3"
UUID="91af51db-7cf0-4069-9433-77d356b31bca"
DEVICE="enp0s3"
ONBOOT="yes"
```

<br>

## 네트워크 설정 파일 수정하기
1. BOOTPROTO의 값을 static으로 변경시켜줍니다.
2. 이후 자신이 고정하고자 하는 IP, Gateway, DNS 서버 설정을 해줍니다.
   ```conf
   TYPE="Ethernet"
   PROXY_METHOD="none"
   BROWSER_ONLY="no"
   #BOOTPROTO="dhcp"
   DEFROUTE="yes"
   IPV4_FAILURE_FATAL="no"
   IPV6INIT="yes"
   IPV6_AUTOCONF="yes"
   IPV6_DEFROUTE="yes"
   IPV6_FAILURE_FATAL="no"
   IPV6_ADDR_GEN_MODE="stable-privacy"
   NAME="enp0s3"
   UUID="91af51db-7cf0-4069-9433-77d356b31bca"
   DEVICE="enp0s3"
   ONBOOT="yes"
   
   BOOTPROTO="static"
   IPADDR="192.168.0.123"
   GATEWAY="192.168.0.1"
   DNS1="168.126.63.1"
   DNS2="168.126.63.2"
   ```

<br>

## 네트워크 재시작하기

* 네트워크를 재시작하면 변경 사항이 적용됩니다.
```console
$ systemctl restart network
```

출처 : [https://www.manualfactory.net/10004](https://www.manualfactory.net/10004)