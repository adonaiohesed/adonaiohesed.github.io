---
title: Elastic Search 설치 및 실행(v 6.6.1)
tags:  ELK Tools
key: page-elastic_search_installation_usage
categories: [Tools, ELK]
author: hyoeun
---

## Windows 환경에서 설치

* [설치 파일](https://collabo.eloicube.com/redmine/projects/globalwiki/wiki/Elastic_Stack#Elastic-Stack-%EC%84%A4%EC%B9%98) 을 다운 받은 후 압축을 푼다.

<br>
## 실행

```console
$ ./bin/elasticsearch
```
* 실행 후 크롬 혹은 자신이 편한 브라우저(curl포함)에서 localhost:9200으로 접속. 아래와 같은 화면이 뜨면 성공.
<img src="/assets/images/elasticsearch_install_success.png" width="600px">

<br>
## 실행 옵션

```console
$ ./bin/elasticsearch -E cluster.name=es-1 -E node.name=node-2
```

* es-1으로 지칭한 클러스터에 node-2라는 이름의 노드를 실행시키는 것을 의미합니다.
* 이때 동일한 클러스터를 지정하고 다른 이름의 노드로 실행하면 자동으로 기존 클러스터의 마스터 노드를 찾아 바인딩 됩니다.
* 그러면 하나의 클러스터에 여러개의 노드들이 붙어질 수 있는 것이고 각 노드별로 가지는 포트번호는 달라지지만 동일한 검색 결과를 가져와 줍니다.

<br>
## CentOS 7 환경에서 설치

* 8 version 이상의 java를 설치한다. [참고](https://blog.hanumoka.net/2018/04/30/centOs-20180430-centos-install-jdk/)
* elastic search설치를 위해 우선 repository를 만든다. [다른 버전일 경우 master 버전 docu 참고](https://www.elastic.co/guide/en/elasticsearch/reference/master/rpm.html##rpm-repo)
```console
$ sudo vi /etc/yum.repos.d/elastic.repo
```
```xml
[elasticsearch-6.x]
name=Elasticsearch repository for 6.x packages
baseurl=https://artifacts.elastic.co/packages/6.x/yum
gpgcheck=1
gpgkey=https://artifacts.elastic.co/GPG-KEY-elasticsearch
enabled=1
autorefresh=1
type=rpm-md
```

* elastic search를 설치한다.
```console
$ sudo yum install elasticsearch -y or sudo yum install elasticsearch-6.6.1 -y
```

* 혹시나 설치 과정 중 'No more mirrors to try' 에러가 뜨면 다음 명령어를 치고 다시 elastic search를 설치한다.<br>
인터넷 문제로 안 될때가 있으니 위의 설치를 다시 몇번하다보면 될때도 있었다.
```console
$ sudo yum clean all && yum clean metadata && yum clean dbcache && yum makecache
```

* 설치가 완료된 후 시스템 시작시 자동 실행 되도록 설정한다.
```console
$ sudo systemctl enable elasticsearch
$ sudo systemctl start elasticsearch
```

<br>
## 파일 구조
RPM 버전의 파일 구조는 아래와 같다. [공식홈페이지](https://www.elastic.co/guide/en/elasticsearch/reference/6.6/rpm.html#rpm-layout)

* /usr/share/elasticsearch : 홈디렉토리
  * bin : 실행 파일 디렉토리
  * plugins : 플러그인
* /etc/elasticsearch : 설정 파일 디렉토리
  * elasticsearch.yml : 주 설정 파일
  * jvm.options : java 설정 파일
  * log4j2.properties : 로그 설정 파일
* /var/lib/elasticsearch : 데이터 저장 디렉토리
* /var/log/elasticsearch : 로그 저장 디렉토리

<br>
## 실행(+방화벽 설정)

* curl로 작동 여부 확인 방법(local에서 확인)
```console
$ curl localhost:9200
```
* 외부 컴퓨터에서 현재 서버에 접속이 되는지 확인 하기 위해서는 2가지 작업을 미리 해야 한다.
  1. elasticsearch.yml 설정(/etc/elasticsearch/elasticsearch.yml)
  ```xml
  network.host: "자신의 ip" 혹은 "0.0.0.0"
  # 7.0 version 이후에는 http.host로 바꿔야지 적용된다.
  ```
-> 자신의 ip로 설정할 경우 kibana에서 접근하지 못하여 Kibana is not ready to server라고 뜰 수 있다. [참고](https://www.elastic.co/guide/en/elasticsearch/reference/6.1/modules-network.html#network-interface-values)
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