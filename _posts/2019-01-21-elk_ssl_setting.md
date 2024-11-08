---
title: ELK SSL 적용 (v 7.1.0)
tags: ELK SSL Tools
key: page-elk_ssl_setup
categories: [Tools, ELK]
author: hyoeun
---

## 기본 설치 및 실행 (CentOS 7 환경)

* 설치는 기존 설치 포스팅을 참고하여 7버전에 맞는 repo파일만 변경하여 그대로 따라하시면 됩니다.
* /etc/elasticsearch/elasticsearch.yml 파일에 아래 설정을 추가합니다.
```conf
http.host: 192.168.0.151[자신의 ip]
#network.host: 192.168.0.1
http.port: 9200
```
  * ver 7부터는 network.host가 아닌 http.host로 자신의 ip값을 주어야 binding이 됩니다. 
* /etc/kibana/kibana.yml 파일에 아래 설정을 추가합니다.  
```conf
server.port: 5601
server.host: "192.168.0.151" # kibana server ip를 입력하시면 됩니다.
elasticsearch.hosts: ["http://<elasticsearch http ip>:9200"]
```
* 위의 설정들을 모두 마치고 재실행을 해보시면 elastic search와 kibana가 정상적으로 작동함을 확인 할 수 있습니다.

<br>
## Elastic search node간의 TLS 통신 적용

<img src="/assets/images/es_transport_ssl_impostor.png" width="500px" style="display: block;margin-left: auto;margin-right: auto;">

* 만약, 동일한 클러스터에 속한 노드들 사이의 통신을 암호화 하지 않는다면 impostor가 다른 노드들을 속이고 정보를 빼내갈 수 있습니다. 따라서 노드들 간의 암호화를 해주어야 합니다.

<img src="/assets/images/es_transport_ssl.png" width="500px" style="display: block;margin-left: auto;margin-right: auto;">

* 암호화를 하기 위해 CA를 생성해야 되고 인증서를 발급 받아야 합니다. x-pack 유료 버전으로 이용가능 했던 것들이 7.1 버전 이후 무료로 사용이 가능하게 되었고 bin폴더 안에 관련 프로그램들이 있습니다.

<br>
### CA 생성

```console
$ /usr/share/elasticsearch/bin/elasticsearch-certutil ca
```
* 암호 입력에 관한 질문이 나오면 암호를 입력하지 않고 엔터로 넘어갑니다.
* 그러면 elastic-stack-ca.p12 파일이 생성 될 것입니다.

<br>
### 인증서 발급

```console
# /usr/share/elasticsearch/bin/elasticsearch-certutil cert --ca /path/to/your/ca
```

* CA를 생성할때 입력한 암호, 인증서에 들어갈 암호를 중간에 입력해야 하지만 엔터로 넘어갑니다.
* 그러면 elastic-certificates.p12라는 파일이 생성 될 것입니다.
* 만들어진 인증서를 /etc/elasticsearch/ 밑으로 복사를 하신 후 아래 명령어로 권한 설정을 바꿔줍니다.
```console
$ chmod 444 elastic-certificates.p12
```

* elasticsearch.yml 파일에 다음의 코드를 추가합니다.
```make
xpack.security.enabled: true
xpack.security.transport.ssl.enabled: true
xpack.security.transport.ssl.verification_mode: certificate 
xpack.security.transport.ssl.keystore.path: elastic-certificates.p12
xpack.security.transport.ssl.keystore.password: "인증서 생성시 암호가 있을 시에 추가합니다."
xpack.security.transport.ssl.truststore.path: elastic-certificates.p12
xpack.security.transport.ssl.truststore.password: "인증서 생성시 암호가 있을 시에 추가합니다."
```

* OpenSSL로 인증서를 사용할 시에는 다음 코드를 elasticsearch.yml 파일에 추가 후 그 다음 명령어를 실행합니다.
```make
xpack.security.enabled: true
xpack.security.transport.ssl.enabled: true
xpack.security.transport.ssl.verification_mode: certificate
xpack.security.transport.ssl.key: client.key
xpack.security.transport.ssl.certificate: client.crt
xpack.security.transport.ssl.certificate_authorities: "root.crt" 
```
```console
$ /usr/share/elastic/bin/elasticsearch-keystore add xpack.security.transport.ssl.secure_key_passphrase
```

* 코드 추가 후 elastic search를 재실행 시키시면 노드들 간의 TLS 적용이 완료 되었습니다.

<br>
## Role-Based Access Control 적용

<img src="/assets/images/es_block_unauthroized_access.png" width="500px">

* RBAC를 통해 클러스터 접근에 제한을 둘 수 있습니다.

<br>
<img src="/assets/images/es_roll_based.png" width="500px" style="display: block;margin-left: auto;margin-right: auto;">

* RBAC는 위와 같은 구조를 지녔습니다.
* 노드 간의 TLS 적용이 선행되어야 하고 TLS적용이 되었으면 아래 명령어를 실행시킵니다.
```console
$ /usr/share/elasticsearch/bin/elasticsearch-setup-passwords auto
```

* 실행 후 y를 누르면 다음과 같이 자동으로 계정 생성과 비밀번호를 console창에 보여줍니다.
  ```conf
  Changed password for user apm_system
  PASSWORD apm_system = H4jKTN0LMgvK9QYiOvk9

  Changed password for user kibana
  PASSWORD kibana = PhIrfPkcCxVdgj0EkcQY

  Changed password for user logstash_system
  PASSWORD logstash_system = rxHIJuxgmQjFhsGYBgfZ

  Changed password for user beats_system
  PASSWORD beats_system = i79rCxJ4MwdVIfnXygzo

  Changed password for user remote_monitoring_user
  PASSWORD remote_monitoring_user = b6d1Pap8i1BRWX5uW0co
  
  Changed password for user elastic
  PASSWORD elastic = WRrHZzliTHMxKrdQnRSN
  ```

* kibana.yml 파일에서 위의 비밀번호를 복사하여 추가해줍니다.
```make
elasticsearch.username: "kibana"
elasticsearch.password: "PhIrfPkcCxVdgj0EkcQY"
```

* elastic search와 kibana를 다시 실행시키고 위의 id에서 elastic으로 접속을 하시면 됩니다.

<br>
## HTTPS 적용

* elasticsearch.yml에 다음 코드를 추가합니다.
```make
xpack.security.http.ssl.enabled: true
xpack.security.http.ssl.keystore.path: elastic-certificates.p12
xpack.security.http.ssl.keystore.password: "인증서 생성시 암호가 있을 시에 추가합니다."
xpack.security.http.ssl.truststore.path: elastic-certificates.p12
xpack.security.http.ssl.truststore.password: "인증서 생성시 암호가 있을 시에 추가합니다."
```

* kibana는 .p12 포맷을 지원하지 않기에 http 인증서를 발급 받기 위해 pem형식을 추출해야 합니다.
```console
$ /usr/share/elasticsearch/bin/elasticsearch-certutil cert --ca /path/to/your/ca --pem
```

* 이후 생성된 key를 /etc/kibana로 옮긴 후 kibana.yml에 다음 코드를 추가합니다.

  ```make
  elasticsearch.hosts: ["https://<your_elasticsearch_host>:9200"]

  server.ssl.enabled: true
  server.ssl.key: /path/to/your/key
  server.ssl.certificate: /path/to/your/crt

  elasticsearch.ssl.verificationMode: none
  ```

* elastic search와 kibana를 재 실행 후 https로 접속하면 모두 적용 된 것을 확인 하실 수 있습니다.