---
title: Syslog-Ng 설치 및 사용 방법
tags: Syslog-Ng Installation Tools
key: page-syslog_ng_installation_usage
categories: [Development, SysOps & Infrastructure]
author: hyoeun
---

## syslog-ng란?
* 로그를 다루는 프로그램이다.
* 기존의 리눅스에 포함되어 있는 syslog의 상위 버전이라 할 수 있다.
* CentOS7의 경우는 syslog보다 조금 더 상위버전인 rsyslog가 있지만 그것보다 더 상위버전인 것이 syslog-ng이다.

<br>

## RHEL or CentOS7 위에 설치
1. RHEL은 아래 과정을 하고 CentOS은 안 해도 된다. syslog-ng를 실행하기 위한 packages를 받을 수 있게 설정하는 작업.
```console
$ subscription-manager repos --enable rhel-7-server-optional-rpms
```
2. RPM package에다가 RHEL에 포함되어 있지 않은 Extra Packages for Enterprise Linux(EPEL)을 설치하는 작업
```console
$ wget https://dl.fedoraproject.org/pub/epel/epel-release-latest-7.noarch.rpm
$ rpm -Uvh epel-release-latest-7.noarch.rpm
```
3. 본격적인 syslog-ng 설치 작업.
```console
$ cd /etc/yum.repos.d/
$ wget https://copr.fedorainfracloud.org/coprs/czanik/syslog-ng319/repo/epel-7/czanik-syslog-ng319-epel-7.repo
$ yum install syslog-ng
$ systemctl enable syslog-ng
$ systemctl start syslog-ng
```
4. 위 설치가 끝나면 기존에 존재하는 rsyslog or syslog를 삭제시켜 충돌을 방지시킨다.<br>
```console
$ yum erase rsyslog
```
다른 리눅스 버전의 경우 아래 링크 참조<br>
[syslog-ng 공식 installation 사이트](https://www.syslog-ng.com/products/open-source-log-management/3rd-party-binaries.aspx)

<br>

## Syslog-ng를 데몬으로 돌리기

```console
$ systemctl enable syslog-ng
$ systemctl start syslog-ng
```
* 위의 과정에서 start(restart)에 에러가 나는 경우가 있을 수 있다. port에 관한 설정을 했을때 port 상태를 확인해야한다.
```console
$ semanage port -l | grep syslog
syslog_tls_port_t              tcp      6514, 10514
syslog_tls_port_t              udp      6514, 10514
syslogd_port_t                 tcp      601, 20514
syslogd_port_t                 udp      514, 601, 20514
```
* 여기에서 자신이 받고자 하는 port 정보가 없으면 아래의 명령어로 port를 추가시킨후 재실행 한다.
```console
$ semanage port -a -t syslogd_port_t -p udp 7071
$ systemctl reset-failed syslog-ng
$ systemctl restart syslog-ng
```
* syslog-ng는 syslog를 이용하기 때문에 기존 syslog의 port값 정보를 이용한다.

> semanage는 SELinux에 사용되는 명령어이다.
> SELinux는 RHEL 기반의 배포판 커널에 이식된 커널 레벨의 보안 모듈이다.

## 기본 개념
syslog-ng는 syslog-ng.conf 파일을 프로그래밍하면서 조작하는 프로그램이다.<br>
크게 3가지 부분으로 나뉜다.

source \<identifier> { params }
: 어디에서 로그를 수집할 것인지

filter \<identifier> { params } 
: 어떤 로그만 수집할 것인지

destination \<identifier> { params }
: 수집된 로그를 어디로 보낼 것인지

identifier는 모든 단어가 허용된다. (예약어와 충돌이 없다.)<br>
위의 3가지 요소를 배치하여 최종 실행 코드를 작성한다.
> log{ source(s1); source(s2); ... filter(f1); filter(f2); ... destination(d1); destination(d2); ... };

<br>

## 예시
```conf
@version:3.19
@include "scl.conf"

options {
     flush-timeout(300000);
     time_reopen (100);
     log_fifo_size (100000);
     chain_hostnames (off);
     use_dns (no);
     dns_cache (no);
     use_fqdn (no);
     create_dirs (no);
     keep_hostname (yes);
     flush-lines(5);
};

template template_date_format {
    template("${YEAR}-${MONTH}-${DAY} ${HOUR}:${MIN}:${SEC} ${HOST} ${MSGHDR}${MSG}\n");
    template_escape(no);
};

source s_sys {
    system();
    internal();
    udp(ip(0.0.0.0) port(514));
};
source udp {
    udp(ip("192.168.0.92") port(7071));
};

destination d_mlal { usertty("*"); };
destination hyoeun_info { file("/var/log/hyoeun_log/${YEAR}_${MONTH}_${DAY}_info"); };

filter f_kernel     { facility(kern); };
filter f_default    { level(info..emerg) and
                        not (facility(mail)
                        or facility(authpriv)
                        or facility(cron)); };
filter f_emergency  { level(emerg); };
filter f_news       { facility(uucp) or
                        (facility(news)
                        and level(crit..emerg)); };

log { source(s_sys); destination(d_mlal); };
log { source(udp); filter(f_default); filter(f_news); destination(hyoeun_info); };
log {
    source(udp);
    filter(f_default);
    filter {
        match("^((?!Hello).)*$",value("MSG"));
        match("Program\.exe",value("MSG"));
        match("Ann",value("MSGHDR"));
    };
    destination {
        file("/var/log/hyoeun/Program_${YEAR}_${MONTH}_${DAY}_${HOUR}_$(/ ${MIN} 10)0.log" template(template_date_format));
    };
};

@include "/etc/syslog-ng/conf.d/*.conf"

```
<br>

## 실행 확인
```
$ netstat -nltup
```
위의 명령어를 치면 현재 작동하고 있는 syslog-ng의 상황을 볼 수 있다.

## 더 자세히 알아보기

### [Source](https://www.syslog-ng.com/technical-documents/doc/syslog-ng-open-source-edition/3.16/administration-guide/16#TOPIC-956446)
* pipe: 지정된 파이프 이름을 오픈하여 로그 메시지를 읽음
* internal: syslog-ng 내부에서 생성되는 메시지를 수집
* system: 
* unix-stream: SOCK_STREAM 모드로 지정된 UNIX 소켓을 열고 로그 메시지를 수신(Linux의 경우)
```conf
source src {
    pipe ("/proc/kmsg" log_prefix("kernel:"));
    unix-stream ("<path-to-socket>"  max-connections(10) group(log));
    system();
    internal();
};
```
* unix-dgram: SOCK_DGRAM 모드로 지정된 UNIX 소켓을 열고 로그 메시지를 수신(BSD 계열 UNIX)
* file: 지정된 파일을 열고 메시지를 읽음
```conf
source s_file { 
    file("/var/log/messages_${HOST}"); #HOST라는 매크로를 사용 하고 싶을 때.
};
```
* udp: UDP 포트로 대기 로그 메시지를 수신
```conf
source s_file { 
    udp(ip("192.168.0.92") port(514));
};
```
* tcp: TCP 포트로 대기 로그 메시지를 수신
```conf
source tcpgateway {
    unix-stream("/dev/log");
    internal();
    tcp(ip(0.0.0.0) port(514) max_connections(1000));
};
```
* network: udp,tcp는 obsolete이기 때문에 안 쓰고 network로 대체하는 것이 좋다.
  * TLS를 쓰는 경우에는 transport에 "tls", TCP는 "tcp", UDP는 "udp"로 대체해서 쓴다.
  * IPv6의 경우에는 ip-protocol(6)를 추가한다.
```conf
source s_new_network_tcp {
    network(
        transport("tls")
        ip(127.0.0.1) port(1999)
        tls(
            peer-verify("required-trusted")
            key-file("/opt/syslog-ng/etc/syslog-ng/syslog-ng.key")
            cert-file('/opt/syslog-ng/etc/syslog-ng/syslog-ng.crt')
        )
    );
};
```
* sun-stream: 지정된 STREAM 장치를 열고 수신(Solaris)
* wildcard-file(): 여러파일에서 메시지를 수집
```conf
source s_file { 
    wildcard-file(
        base-dir("<pathname>")
       filename-pattern("<filename>")
    ); 
};
```
* syslog: syslog로부터 로그를 수집
```conf
source s_network {
    syslog(ip(10.1.2.3) transport("udp"));
};
 ```

<br>

### [Filter](https://www.syslog-ng.com/technical-documents/doc/syslog-ng-open-source-edition/3.16/administration-guide/51#TOPIC-956579)
* log 문에 여러 개의 filter 문이 포함되어있는 경우 syslog-ng는 모든 필터가 true 인 경우에만 로그를 저장합니다.
```conf
filter demo_filter1 { host("example1"); };
filter demo_filter2 { host("example2"); };
log {
    source(s1); source(s2);
    filter(demo_filter1); filter(demo_filter2);
    destination(d1); destination(d2); };
```
host는 동시에 2개 일 수 없기에 위와 같은 코드는 로그 수집이 불가하고 따라서 아래와 같이 수정해야합니다.
```conf
filter demo_filter { host("example1") or host("example2"); };
log {
    source(s1); source(s2);
    filter(demo_filter);
    destination(d1); destination(d2); };
```

* match: 정규식에 해당하는 메시지를 선택해서 필터링.
``` conf
filter match_filter {
   match("regex expre", value("MSGHDR")); #value는 ${MESSAGE} MACRO로 받아지는 부분으로 scope를 좁혀주는 역할을 한다.
   match("regex expre", value("MSG")); #value 옵션 안에 $ sign을 포함하지 말고 MACRO를 그냥 넣는다.
};
```

* message: match에서 메시지 부분만(헤더부분 제외) 필터링.
``` conf
filter message_filter {
   message("regexp");
};
```

* level: emerge, alert, crit, err, warning, notice, info, debug 구분으로 필터링.
``` conf
filter level_filter {
   level(warning);
   level(err..emerg); #..으로 범위 지정이 가능합니다.
};
```

* netmask: 특정 IP에서 온 host message만 필터링.
``` conf
filter ip_filter {
   netmask(192.168.0.151/255.255.255.0); #255.255.255.0 대신에 24로 입력할 수도 있다. IPv6인 경우 netmask6()를 사용하면 된다.
};
```

* facility: name, code와도 되는건데 아래의 코드를 사용한다.
 
    |Numberical Code|Facility Name|Facility|
    |:-----:|:-----:|:-----:|
    |0|kern|kernel messages|
    |1|user|user-level messages|
    |2|mail|mail system|
    |3|daemon|system daemons|
    |4|auth|security/authorization messages|
    |5|syslog|messages generated internally by syslogd|
    |6|lpr|line printer subsystem|
    |7|news|network news subsystem|
    |8|uucp|UUCP subsystem|
    |9|cron|clock daemon|
    |10|authpriv|security/authorization messages|
    |11|ftp|FTP daemon|
    |12|ntp|NTP subsystem|
    |13|security|log audit|
    |14|console|log alert|
    |15|solaris-cron|clock daemon|
    |16-23|local0..local7|locally used facilities (local0-local7)|

    ```conf
    filter f_local1 {
        facility(local1); 
    };
    ```

<br>

### [Destination](https://www.syslog-ng.com/technical-documents/doc/syslog-ng-open-source-edition/3.16/administration-guide/27#TOPIC-956486)

* file: macros를 이용해 파일 이름을 만들어 저장 할 수 있다. create-dirs() setting을 통해 폴더가 존재하지 않아도 만들 수 있다.
``` conf
destination d_file {
    file("/var/log/${YEAR}.${MONTH}.${DAY}/messages"
        template("${HOUR}:${MIN}:${SEC} ${TZ} ${HOST} [${LEVEL}] ${MESSAGE}\n")
        template-escape(no)
        owner("root")
        group("root")
        perm(0777)
        );
};
```

### [Options](https://www.syslog-ng.com/technical-documents/doc/syslog-ng-open-source-edition/3.16/administration-guide/54#TOPIC-956589)
* option 이름들, parameter들은 -이나 _를 동일하게 인식한다. ex) max-connections(10) == max_connections(10)
* create-dirs (no): yes, no(default)만 올 수 있고 destination files들을 위해 driectory를 만들수 있게 할 것인지 아닌지를 설정.
* dns-cache-expire(3600): 캐쉬를 언제까지 볼 수 있게 할 것인지 보는 시간 설정(초단위).
* dns-cache (yes): yes(default), no. Dns cache usage를 enable할건지 disable할건지 설정.
* flush-lines(100): destination에 얼마나 많은 lines을 flushed할 것인지 설정.

### elasticsearch
* Linux에만 사용이 되고 많은 memory를 사용한다.

### Macro
* HOUR12: 01, 02
* AMPM: AM, PM
* DATE: Apr 22 09:44:29
* ISODATE: 2006-06-13T15:58:00.123+01:00
* YEAR: 2019
* MONTH: 04
* WEEK_DAY: 3 (화요일 의미 1-7까지 있다.)
* WEEKDAY: Thu
* DAY: 23
* MIN: 1

### 나누기
* $(/ X Y)는 X를 Y로 나눈 값을 나타낸다.
* $(if ("${MIN}" < 5) "0" "$(if ("${MIN}" < 10) "1" "...")") 이런 식으로 5분 단위의 rotation을 만들 수 있다.

### 기타 정보
* option 혹은 parameter들 사이에서 ,는 무시될 수 있다.
```conf
source s_demo_stream {
    unix-stream("<path-to-socket>" max-connections(10) group(log));
};
source s_demo_stream {
    unix-stream("<path-to-socket>", max-connections(10), group(log));
};
```

* identifier에 ""로 선언하면 안에 스페이스도 허용 가능하다.
```conf
source "s demo stream" {
    unix-stream("<path-to-socket>" max-connections(10) group(log));
};
```