---
title: SET-UID Program
key: page-set_uid_program
categories:
- Security
- Vulnerabilities
author: hyoeun
math: true
mathjax_autoNumber: true
bilingual: true
image: "/assets/thumbnails/2021-03-29-set_uid_program.png"
date: 2021-03-29 00:07:12
---

## SET-UID Programs and Privilege Escalation

A **privileged program** is any program that has access controls applied to it — it operates with permissions beyond those of the invoking user. There are two primary mechanisms for delivering privileged functionality to normal users:

1. **Set-UID programs** — allow a process to temporarily adopt the file owner's privileges during execution.
2. **Daemons (Services on Windows)** — background processes that normal users can send requests to, with the daemon itself executing privileged operations on their behalf.

## Three User ID Types

Understanding the difference between these three UIDs is foundational to understanding SUID exploitation:

* **Real User ID (RUID):** The actual identity of the user who launched the process. Set at login and inherited across child processes.
* **Effective User ID (EUID):** The identity used for access control decisions. When a Set-UID root binary runs, the RUID might be 5000 (a normal user), but the EUID becomes 0 (root). This is what the kernel checks when evaluating file permissions.
* **Saved User ID (SUID):** Saves the previous EUID when privileges are dropped, allowing a process to restore them later via `seteuid()`.

## Attack Surfaces of Set-UID Programs

### User Inputs: Explicit Inputs

* **Buffer overflow vulnerability** — classic stack or heap overflow to hijack control flow.
* **Format string vulnerability** — when user input is passed directly as a format string argument to `printf()`-family functions.
* Older versions of `chsh` (change shell) allowed attackers to append arbitrary data to `/etc/passwd`, effectively creating new root accounts.

### System Inputs

If an attacker can modify what the program reads as system input — for example, by racing a symlink swap on a file being read — the program may act on attacker-controlled data despite believing it came from a trusted system source. This is the basis of the TOCTOU (Time-of-Check to Time-of-Use) race condition attack.

### Environment Variables: Hidden Inputs

Environment variables are not part of the explicit input the developer writes, but they influence program behavior at runtime. This makes them a covert and often overlooked attack surface. Classic examples include `LD_PRELOAD`, `IFS`, and `PATH` manipulation.

### Capability Leaking

This is a subtle class of privilege bugs that occurs when a privileged process transitions to an unprivileged state — similar to how `su` works — but forgets to close file descriptors or release other capabilities it acquired while elevated. If a Set-UID root program opens `/etc/shadow` and then fails to close that file descriptor before dropping privileges, the unprivileged child process can still read from it via the inherited open descriptor.

## Invoking Other Programs

Privilege escalation frequently happens when a Set-UID program invokes external commands:

* **`system()`** should be avoided. It invokes `/bin/sh -c <command>`, which means semicolons (`;`), pipes, and shell metacharacters in the argument string allow an attacker to chain arbitrary commands. The parameter is supposed to be data, but `system()` treats it as code — a direct violation of the principle of data/code separation.
* **`execve()`** is the safer choice. It passes the command and its arguments directly to the OS, bypassing shell interpretation entirely. Because the first argument is the exact binary to execute and the subsequent array is passed verbatim as `argv`, there is no metacharacter interpolation.
* As a rule, prefer the `exec()` family over `system()` whenever invoking external programs from a privileged context.

The **principle of data/code isolation** is fundamental to security. When input data can be interpreted as executable code, every class of injection attack becomes possible — XSS, SQL injection, buffer overflows, and command injection all follow from this same violation.

## Finding SUID Binaries

To enumerate Set-UID binaries on a system:

```bash
find / -perm -4000 -type f 2>/dev/null
```

Any binary in this list that is world-writable, calls `system()`, or trusts environment variables is a potential escalation vector.

## Reference

* [COMPUTER SECURITY: A Hands-on Approach by Wenliang Du](https://www.amazon.com/Computer-Security-Hands-Approach-Wenliang/dp/154836794X)

---

* privileged program: 접근 권한이 적용되어 있는 프로그램
* 이런 프로그램에 접근하기 위해서는 2가지 방법이 필요하다.
1. Set-UID program.
    * 사용자가 필요에 따라 privilege변환이 필요할때 이용하는 프로그램이다.
2. Daemons(Services in Windows)
    * 데몬으로 항상 띄워 놓으면 normal user가 daemon에 request를 날려서 그 프로그램을 통해 privileged program을 실행 시킬 수 있을 것이다.

## 3가지 유저의 형태

* real user ID: 실행되고 있는 프로세스의 진짜 주인.
* effective user ID: access control 안에서 사용되고 있는 ID. 즉 root권한으로 설정된 프로세스를 실행시키면 real user ID는 5000이지만 effective suer ID는 0이 된다.
* saved user ID

## Attack Surfaces of Set-UID Programs

### User Inputs: Explicit Inputs
* Buffer overflow vulnerability
* format string vulnerability
* earlier version of chsh - shell program의 기본값을 바꾸는 프로그램인데 공격자가 새로운 루트 어카운트를 만들수 있도록 허용해버린다.

### System Inputs
* 다른 사용자에 의해 시스템 input 자체가 변조되어버리면 system input은 system에서 왔다고 하더라도 믿을 수 없게 된다. 이런 취약점을 이용한 것이 race condition attack이다.

### Environment Variables: Hidden Inputs
* developer가 직접 만들지 않았지만 프로그램을 실행할때 들어가는 것으로써 여러가지 위험이 도사리고 있는 부분이다.

### Capability Leaking
* su의 작동원리와 마찬가지로 privileged process에서 non-privileged process과정으로 넘어갈때 흔히 발생하는 실수이다.
* 특정 파일을 열고 그것을 close하지 않는다면 열려 있는 정보를 사용할 수도 있게 된다.

## Invoking Other Programs

* 프로그램을 작동하다보면 외부 프로그램을 실행할 수 밖에 없는 경우가 생긴다. 하지만 이런 경우들로 인해 취약점이 발생한다.
* system()함수는 안 쓰는게 좋다. External commmand를 실행 시킬 수 있게 하고 ;을 통해 shell 같은 것을 실행 시킬 수 있게 하기 때문이다.
* execve()함수를 쓰는게 나은데 shell program이 아니라 os에게 바로 specifeid command를 실행시켜달라고 하니 ;를 통한 공격같은 것을 할 수 없게 된다. 왜냐하면 첫번째 인자를 실행시키고 두번째 argument에 관한 인자를 정확히 그 프로그램의 파라미터로 보내기 때문에 ;로 이어지는 실행이 되지 않는다.
* 따라서 exec() family of functions를 쓰는게 좋다.
* 보안에서 기본이 되는 원칙은 priciple of data/code isolation이다.
    * input data에서 code가 실행되면 안 된다. system()의 파라미터는 data로 써야되지만 ;로 또 다른 program을 시킬 수 있게 되면서 코드로 사용되어 보안의 기본 원칙에서 벗어난 잘못된 함수이다.
    * cross-site scripting attack, SQL-injection, buffer-overflow attack 모두 위의 원칙을 어김으로써 가능한 공격 방식들이다.

## Refrence

* [COMPUTER SECURITY: A Hands-on Approach by Wenliang Du](https://www.amazon.com/Computer-Security-Hands-Approach-Wenliang/dp/154836794X)
