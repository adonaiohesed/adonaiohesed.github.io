---
title: Shell script 기본 문법
tags: Shell-Script
key: page-shell_script_syntax
categories: [Development, SysOps & Infrastructure]
author: hyoeun
---

## 파일 생성 및 실행 권한 부여
```console
$ touch shell_script_practice.sh // 파일 생성
$ vim shell_script_practice.sh // 쉘 스크립트 파일 편집기로 열기
$ chmod +x shell_script_practice.sh // 실행 권한 부여
```

## 기본 문법

* 스크립트 상단에 ```#I/bin/bash```를 추가하고 스크립트 작성을 해야 합니다.

### 기본 출력

```console
echo "Echo Test" # 자동 개행
printf "printf Test" # 자동 개행X
printf "%s %s" print test # 뒤에 오는 문자열들이 전달되는 인자라고 생각하면 됩니다.
printf "Name of script : %s\n" $0
printf "%d arguments %s %s\n" $# $1 $2
```

* $# : 스크립트에 전달되는 인자들의 수(C언어에서 argc)
* $0 : 실행하는 스크립트의 파일명으로 실행했을 때 경로를 포함한다면 경로를 포함해서 나옵니다.
* $1, $2 ... : 스크립트로 전달된 인자들(C언어에서 argv[0], argv[1] 과 동일)