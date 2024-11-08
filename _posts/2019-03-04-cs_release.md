---
title: c# 리눅스 배포 및 데몬 등록법
tags: C# Linux Deployment Daemon
key: page-csharp_linux_deployment_daemon
categories: [Software Engineering, Linux]
author: hyoeun
---

## CentOS7 배포 방법

1. Visual Studio를 통해서 디버그 모드로 아무 이상이 없는지 먼저 확인부터 하고 배포를 시작합니다.
2. 아무 이상이 없을경우 window power shell을 접속하여 본인이 배포하시기 원하는 폴더로 접근합니다.
3. 폴더에 접근 후 dotnet publish 라는 명령어를 실행시킵니다. 그러면 publish된 경로가 나옵니다.
4. 이후 배포 버전이 나온 경로에 들어가서 Winscp로 리눅스에서 실행시킬 파일들을 옮깁니다.
5. 옮긴 이후 다음 리눅스에서 dotnet <프로그램이름.dll>로 정상 작동하는지 확인합니다.

<br>

## 데몬 등록법

1. 다음 코드를 작성하여 저장합니다. 저는 dnsvc.service 라는 파일 이름으로 작성하였습니다.
  
   ```yml
   [Unit]
   Description=Logcenter SyslogPrep Service

   [Service]
   Type=simple
   ExecStart=/usr/bin/dotnet /root/play/NxP.Agent.SyslogPrep.dll
   Restart=always

   [Install]
   WantedBy=multi-user.target
   ```

  2. 이후 다음 명령어들을 실행시킵니다.
```console
$ cp dnsvc.service /lib/systemd/system
$ systemctl daemon-reload
$ systemctl enable dnsvc
$ systemctl start dnsvc
$ systemctl status dnsvc
```
  3. 마지막 명령어로 잘 실행되었는지 확인 하시고 정상작동이 되면 데몬으로 잘 돌아가는 것입니다.

* 참고 사이트
https://pmcgrath.net/running-a-simple-dotnet-core-linux-daemon