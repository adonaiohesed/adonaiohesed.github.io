---
title: 리눅스 알아두면 좋은 커맨드
tags: Linux
key: page-linux_useful_commands
categories: [Software Engineering, Linux]
author: hyoeun
---
## 정렬하지 않고 유니크한 부분만 출력하기
```console
$ awk '!x[$0]++ {print $0}' my_file.txt
$ cat my_file.txt | awk '!x[$0]++'
```

## 정렬하면서 유니크한 부분 출력하기
```console
$ cat my_file.txt | sort -u
```

## cat * | grep 의 환상 조합
```console
$ grep -r -H "찾고자 하는 string"
```
-i: 영문의 대소문자를 구별하지 않음
-v: pattern을 포함하지 않는 라인 출력
-n: 검색 결과에 번호 표시
-l: 파일명만 출력
-c: 패턴과 일치하는 라인의 개수만 출력
-r: 하위 디렉토리까지 검색
-E: 정규표현식 사용
-H: 파일 이름 출력 



출처: https://realforce111.tistory.com/11 [KIMS BLOG] 
