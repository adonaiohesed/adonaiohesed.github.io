---
title: Cassandra 설치 및 사용 방법
tags: Cassandra Installation
key: page-cassandra_installation_usage
categories: [Development, Database Systems]
author: hyoeun
---

## Cassadnra에 대한 소개

* 잘 정리된 [블로그](https://meetup.toast.com/posts/58) 가 있으니 참고하시기 바랍니다.

## Docker에서 설치 후 실행

```console
$ sudo docker pull cassandra
```

* 설치 후 컨테이너 실행을 합니다.

```console
$ sudo docker run --name some-cassandra --network some-network -d cassandra:tag
```

* 컨테이너 실행 후 정상 작동 확인을 위해 다음 명령어를 실행합니다.
```console
$ sudo docker exec -it <container name> cqlsh
```

