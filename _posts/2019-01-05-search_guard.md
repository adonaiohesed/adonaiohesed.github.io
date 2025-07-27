---
title: Search Guard 설치 및 실행
tags: Search-Guard Installation Tools
key: page-search_guard_installation_usage
categories: [Tools, ELK]
author: hyoeun
---

## Windows 환경 (6.6.1 version 기준)

### Elastic Search에 설치

1. install 명령
```bash
$ [elastic search 설치 경로]/bin/elasticsearch-plugin install -b com.floragunn:search-guard-6:6.6.1-24.1 (6.6.1 version 기준)
```
  * 버전은 [version matrix](https://docs.search-guard.com/latest/search-guard-versions) 에서 확인 후 다운.
2. Demo Certificates 다운 후 압축 풀기
  * [Download Demo Certificates](https://docs.search-guard.com/latest/tls-download-certificates#download-and-install) 에서 다운을 받은 후 /plugins/search-guard-<version>/tools 에 파일들을 놓아둔다.
3. elasticsearch.yml 파일에 코드 추가
```conf
searchguard.ssl.transport.pemcert_filepath: esnode.pem
searchguard.ssl.transport.pemkey_filepath: esnode-key.pem
searchguard.ssl.transport.pemtrustedcas_filepath: root-ca.pem
searchguard.ssl.transport.enforce_hostname_verification: false
searchguard.ssl.http.enabled: true
searchguard.ssl.http.pemcert_filepath: esnode.pem
searchguard.ssl.http.pemkey_filepath: esnode-key.pem
searchguard.ssl.http.pemtrustedcas_filepath: root-ca.pem
searchguard.allow_unsafe_democertificates: true
searchguard.allow_default_init_sgindex: true
searchguard.authcz.admin_dn:
  - CN=kirk,OU=client,O=client,L=test,C=de
searchguard.enable_snapshot_restore_privilege: true
searchguard.check_snapshot_restore_write_privileges: true
searchguard.restapi.roles_enabled: ["sg_all_access"]
xpack.security.enabled: false
```
  * xpack.security.enabled: false를 안 해주면 에러가 났었다.
4. elastic 실행
  * elastic을 실행한 후 https://localhost:9200 으로 접속을 하면 search guard가 실행된 것을 확인 할 수 있다.

### Kibana에 설치

1. 공식 홈페이지의 [Search Guard Kibana plugin zip](https://search.maven.org/search?q=a:search-guard-kibana-plugin) 을 다운 받아 아래 명령어 실행
```bash
$ <Elasticsearch directory>/bin/kibna-plugin install file://C:\Users\최효은\Documents\kibana-6.6.1-windows-x86_64\search-guard-kibana-plugin-6.6.1-18.1.zip(다운 받은 zip파일 경로에 따라 달라질것이다.)
```

<br>
## CentOS 환경 (7.0.1 version 기준)

### Elastic Search에 설치. 

1. install 명령([버전 참고 공식 홈페이지](https://docs.search-guard.com/latest/demo-installer))
```bash
$ /usr/share/elasticsearch/bin/elasticsearch-plugin install -b com.floragunn:search-guard-7:7.0.1-35.0.0
```
2. 설치된 tool 사용
```bash
$ cd /usr/share/elasticsearch/plugins/search-guard-7/tools
$ chmod +x ./install_demo_configuration.sh
$ ./install_demo_configuration.sh
```
3. initailzed
```bash
Search Guard 7 Demo Installer
 ** Warning: Do not use on production or publicly reachable systems **
Install demo certificates? [y/N] y
Initialize Search Guard? [y/N] y
Enable cluster mode? [y/N] n
```
4. 변경 사항 적용
```bash
$ systemctl restart elasticsearch
```

### Kibana에 설치

1. kibana.yml 설정값 변경<br>(**매우 중요!** -> 이유는 모르겠으나 이거먼저 하지 않았을 경우 제대로 search guard가 실행되지 않았다.)
   ```conf
   # Use HTTPS instead of HTTP
   elasticsearch.url: "https://[elastic search ip]:9200"

   # Configure the Kibana internal server user
   elasticsearch.username: "kibanaserver"
   elasticsearch.password: "kibanaserver"

   # Disable SSL verification because we use self-signed demo certificates
   elasticsearch.ssl.verificationMode: none

   # 이 부분때문에 먼저 설정을 하고 SG를 설치해야한다.
   xpack.security.enabled: false
   ```
2. 공식 홈페이지의 [Search Guard Kibana plugin zip](https://search.maven.org/search?q=a:search-guard-kibana-plugin)에서 다운 받아도 되고 wget으로 다운 받아도 된다.
```bash
$ cd /usr/share/kibana
$ wget https://oss.sonatype.org/service/local/repositories/releases/content/com/floragunn/search-guard-kibana-plugin/7.0.1-35.0.0/search-guard-kibana-plugin-7.0.1-35.0.0.zip
$ /usr/share/kibana/bin/kibna-plugin install file:///usr/share/kibana/search-guard-kibana-plugin-7.0.1-35.0.0.zip
```
3. 변경 사항 적용
```bash
$ systemctl restart kibana
```

* **1번에서 xpack.security.enabled: false를 만지다가 혹여나 자꾸 Kibana server is not ready yet.로 접속이 안되면**<br>아래 명령어를 치면 해결 될 수도 있다.
```bash
$ sudo -i chown -R kibana:kibana /usr/share/kibana/optimize/bundles
```