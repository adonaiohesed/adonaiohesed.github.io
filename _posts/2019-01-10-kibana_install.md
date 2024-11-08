---
title: Kibana 설치 및 실행(v 7.0.1)
tags: Kibana Installation Tools ELK
key: page-kibana_installation_usage
categories: [Tools, ELK]
author: hyoeun
---

## Windows 환경에서 설치

* [설치 파일](https://collabo.eloicube.com/redmine/projects/globalwiki/wiki/Elastic_Stack#Elastic-Stack-%EC%84%A4%EC%B9%98) 을 다운 받은 후 압축을 푼다.

## 실행

```console
$ ./bin/elasticsearch
```
* 실행 후 크롬 혹은 자신이 편한 브라우저(curl포함)에서 localhost:5601으로 접속. 아래와 같은 화면이 뜨면 성공.
<img src="/assets/images/kibana_install_success.png" width="600px">

<br>
## CentOS 7 환경에서 설치

* Elastic search를 설치했다고 가정한다.
* 기존에 있던 repo로 kibana를 설치한다.
```console
$ sudo yum install kibana -y
```

<br>
## 파일 구조
RPM 버전의 파일 구조는 아래와 같다. [공식홈페이지](https://www.elastic.co/guide/en/kibana/current/rpm.html#rpm-layout)

* /usr/share/kibana : 홈디렉토리
  * bin : 실행 파일 디렉토리
  * plugins : 플러그인
* /etc/kibana : 설정 파일 디렉토리
  * kibana.yml : 주 설정 파일
* /var/lib/kibana : 데이터 저장 디렉토리
* /usr/share/kibana/optimize : transpiled된 소스 파일 디렉토리

<br>
## 실행

* curl localhost:5601/status -I 로 작동 여부를 확인한다.
* 외부 컴퓨터에서 접속이 되는지 확인 하기 위해서는 2가지 작업을 해야 한다.
  1. kibana.yml 설정
``` bash
server.host: "자신의 ip" 혹은 "0.0.0.0"
elasticsearch.hosts: ["http://localhost:9200"] -> 여기서 elasticsearch에서 http.host 값을 준 걸로 넣으면 작동된다.
``` 
  2. 방화벽 설정
    * CentOS7부터는 iptables를 사용하지 않고 firewalld를 사용한다. 
    * 따라서 firewalld를 통해 방화벽을 열어줘야한다. [참고](https://conory.com/blog/42477)
    * ELK를 쓰기 위해서 /etc/firewalld/zones/public.xml 파일에 다음 코드를 추가한다.
    
      ```xml
      <service name="http"/>
      <port protocol="tcp" port="5601"/>
      <port protocol="tcp" port="9200"/>
      ```

      * 변경된 사항을 적용 시키기 위해 firewall-cmd -\-reload 를 실행시킨다.