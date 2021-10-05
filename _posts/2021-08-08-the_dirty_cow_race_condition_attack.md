---
title: The Dirty COW Race Condition Attack
tags: security dirty_cow
key: page-the_dirty_cow_race_condition_attack
cover: /assets/cover/cyber_security.png
mathjax: true
mathjax_autoNumber: true
---

## Introduction
* Race condition vulnerability의 일종이며 Linux기반의 모든 OS에 영향을 주는 취약점이다.
* 공격자는 읽기 모드라도 모든 protected file을 수정할 수 있게 된다.
* /etc/password file을 수정하여 root 계정을 만들어 버리면 root 권한을 탈취하게 된다.

## Memory Mapping using mmap()
* 먼저 mmap() 함수를 살펴보고 시작한다. 여기서는 mmap()으로 mapping된 memory에 관한 이야기들을 할 것이다.
    * 첫 번째 인자는 starting address for the mapped memory를 의미하고 NULL값은 kernel이 주소를 선택하는 것을 의미한다.
    * 두 번째 인자는 mapped memory의 size.
    * 세 번째 인자는 memory가 readable(PROT_READ)인지 writable(PROT_WRITE)인지 나타내고 open()의 속성과 동일해야한다.
    * 네 번째 인자는 MAP_SHARED, MAP_PRIVATE같은 것을 넣는다.
    * 다섯 번째 인자는 mapped 될 file을 넣는다.
    * 여섯 번째 인자는 file의 mapping할 시작포인트에 관한 offset을 넣는데, 0이면 file 전체를 mapping하겠다는 의미이다. 
* 이를 이해하기 위해서는 가상메모리에 대해 잘 알고 있어야 한다.
* MAP_SHARED를 사용하면 physical memory의 내용을 다른 프로세스들에서 다 볼 수 있다.
* MAP_PRIVATE를 사용하면 한 프로세스에서 내용을 수정하면 기존에 모두가 접근 가능했떤 영역에서 새로운 영역으로 내용을 복사하기 때문에 수정한 프로세스만이 그 내용을 볼 수 있게 되는 것이다. 오리지널 영역에 영향을 주기 싫을때에도 사용한다. 단점은 복사하는 딜레이가 생기는 것이다.
* MAP_PRIVATE의 경우에서 보는 것과 같이 다른 프로세스들이 같은 물리적 메모리에 mapping이 되어 그것을 공유하고 있다가 쓰기를 시도할때 가상 메모리의 paging이 일어나면서(이것을 dirty page라고 부른다) 새로운 물리적 주소가 할당되는데 이런 과정들을 Copy On Write라고 부르는 것이다.

## Discard the Copied Memory
* Program이 private copy의 mapping이 끝나고 나면 madvise()로 memory를 관리한다.
* Mapping된 memory가 더 이상 필요없어서 버릴때 madvise()함수에서 MADV_DONTNEED 인자값을 사용한다.
* 이때 새로운 영역을 포인트 하던 것은 COW가 일어나기 전의 기존 영역으로 포인트하게 된다.

## Mapping Read-Only Files
* Dirty COW 공격은 read-only file을 대상으로 한다.
* 보통의 os에서는 read-only file의 memory에 normal user가 어떤 것도 못 쓰게 하지만 linux의 경우 MAP_PRIVATE로 mapping 되었을 경우에는 예외적으로 normal user가 write() system call을 통해 read-only file에 쓰기가 가능하게 만든다.
* 이런 방식은 private memory 영역에만 새로운 것을 write하기 때문에 안전하다고 할 수 있다. 다른 유저는 알 수 없고 다른 영역도 건드리지 않기 때문이다.
* 근데 /proc/self/mem을 통해서 간접적으로 private memory 영역에 새로운 것을 쓰게 할 수 있다.

## The Dirty COW Vulnerability
* write() system call을 통해 mapped memory에 무언가 쓰기 위해서는 다음 3가지 과정이 필요하다.
    1. make a copy of the mapped memory
    1. update the page table, so the virtual memory now points to the newly created physical memory
    1. write to the memory
* 위의 과정들은 atomic하지 않아서 다른 thread나 process에 의해 interrupted될 수 있다.
* 위에서 2, 3번째 과정 사이에서 만약 다른 thread나 process에 의해 madvise()가 MADV_DONTNEED와 함께 가상 메모리를 버리고 원래 메모리를 가리키게 된다면 원래 메모리이 위치에다가 write를 해버릴 수 있게 되는 것이다. 곧 race condition problem을 의미한다.
* 시스템 설계시 읽기 파일이라도 write system call이 가능하게 만든 이유는 2번 과정에서 이미 private memory에다가 쓴다는 가정이 있기 때문에 굳이 다른 check를 하지 않았기 때문이다.
* Dirty COW vulnerability를 위해서는 2개의 thread가 필요한데 1개는 write를 시도하는 것이고 나머지 하나는 discard the private copy of the mapped memory using madvise()이다.
* 이전 공격들과 조금 다른 점이라고 하면 다른 것들은 target programe이 있어서 그것을 공략하는데 이것은 system의 허점을 노려서 우리가 스스로 공격 프로그램을 짜고 우리 코드를 통해 protected file에 접근하여 정보를 수정하는 공격이다.

## Refrence
* [COMPUTER SECURITY: A Hands-on Approach by Wenliang Du](https://www.amazon.com/Computer-Security-Hands-Approach-Wenliang/dp/154836794X)