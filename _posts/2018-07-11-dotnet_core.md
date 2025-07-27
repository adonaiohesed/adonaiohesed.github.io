---
title: c# .net core 설치 및 실행
tags: C# .NET-Core
key: page-csharp_dotnetcore_installation_usage
categories: [Tools, .NET]
author: hyoeun
---

## CentOS / Oracle - x64기준 (.Net Core 2.1버전)
```console
$ sudo rpm -Uvh https://packages.microsoft.com/config/rhel/7/packages-microsoft-prod.rpm
$ sudo yum update
$ sudo yum install dotnet-sdk-2.1
```
* [참고 공식 사이트](https://dotnet.microsoft.com/download/linux-package-manager/centos/sdk-2.1.300)

## 실행 및 배포
```console
$ dotnet <program name>
$ dotnet publish <project name>
```
