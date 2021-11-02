---
title: 파이썬 설치 및 2.7 3.7 차이 설명
tags: python
key: page-python_install
cover: /assets/cover/python.png
---

```console
# yum install gcc openssl-devel bzip2-devel libffi-devel
# cd /usr/src
# wget https://www.python.org/ftp/python/3.7.3/Python-3.7.3.tgz
# tar xzf Python-3.7.3.tgz
# cd Python-3.7.3
# ./configure --enable-optimizations
# make altinstall
# rm /usr/src/Python-3.7.3.tgz
# python3.7 -V
```
[설치 참고 사이트](https://tecadmin.net/install-python-3-7-on-centos/)
<br>
<br>

* 2.7과 3.7 사이에는 상위호환이 가능하지 않은 것이 있는데 다음 사이트에 핵심 차이점들이 정리되어 있다.<br>
[key difference 참고 사이트](https://jaxenter.com/differences-python-2-3-148432.html)
* ```2to3``` 라는 tool을 이용하면 완벽하지는 않지만 version 2의 코드를 version 3의 코드로 어느정도 변환시켜준다.