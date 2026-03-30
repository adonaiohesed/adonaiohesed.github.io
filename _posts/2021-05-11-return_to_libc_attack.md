---
title: Return to libc Attack
key: page-return_to_libc_attack
categories:
- Security
- Vulnerabilities
author: hyoeun
math: true
mathjax_autoNumber: true
bilingual: true
image: "/assets/thumbnails/2021-05-11-return_to_libc_attack.png"
date: 2021-05-11 19:40:48
---

## Introduction

The **non-executable stack** (enforced via the NX bit in hardware or compiler flags like `-z noexecstack`) prevents the classic shellcode injection technique: even if you overflow a buffer and plant machine code on the stack, the CPU will refuse to execute it because the stack pages are marked non-executable.

The **Return-to-libc** attack sidesteps this entirely. Rather than injecting new code, the attacker reuses code that already exists in the process's address space — specifically, functions in the C standard library (`libc`). Every program that links against libc has `system()`, `exit()`, and many other functions already mapped into memory. The attack goal is to overwrite the return address so that instead of returning to the normal caller, the program "returns" into `system("/bin/sh")`.

The three steps:
1. Find the address of `system()` in memory.
2. Find the address of the string `"/bin/sh"` in memory.
3. Construct a fake stack frame that passes `"/bin/sh"` as the argument to `system()`.

## Finding the Address of system()

Since libc is loaded at program startup, its functions are at predictable addresses (with ASLR disabled). GDB makes this straightforward:

```shell
$ touch badfile
$ gdb stack
(gdb) run
(gdb) p system
$1 = {<text variable, no debug info>} 0xb7e42da0 <__libc_system>
(gdb) p exit
$2 = {<text variable, no debug info>} 0xb7e369d0 <__GI_exit>
(gdb) quit
```

The target program must be run first so libc is mapped into the process. We also capture `exit()`'s address to use as the return address after `system()` completes — this ensures a clean exit and avoids a segfault that might alert monitoring systems.

## Finding the Address of "/bin/sh"

Two approaches:

1. **Inject the string via a buffer overflow** — if overflow is achievable, you can place the string somewhere in memory with a known address.
2. **Use an environment variable** — export `"/bin/sh"` as an environment variable before running the target. Child processes inherit parent environment variables, so when the vulnerable program runs, it will load this value into its memory space.

**Critical detail:** Environment variable addresses are affected by the length of the program name passed to the kernel, because the program name is placed on the stack before environment variables. A helper program that calls `getenv()` must have the same name length as the target to produce an accurate address.

## Finding the Argument Address for system()

This is the subtlety of the return-to-libc technique. We are not calling `system()` through a normal `CALL` instruction — we are jumping directly into the middle of libc by placing its address as a return address. This means the stack frame for `system()` must be set up manually in the overflow payload.

Understanding **function prologue** and **epilogue** on IA-32 (x86 32-bit):

**Prologue** (at function entry):
1. The `CALL` instruction pushes the return address onto the stack and jumps to the function.
2. The function executes `push %ebp` — saves the caller's frame pointer.
3. `mov %esp, %ebp` — sets the new frame pointer to the current stack pointer.
4. `sub $N, %esp` — allocates space for local variables and compiler-reserved slots.

**Epilogue** (at function return):
1. `mov %ebp, %esp` — collapses local variable space, returning ESP to the frame base.
2. `pop %ebp` — restores the caller's frame pointer.
3. `ret` — pops the return address and jumps to it (advancing ESP in the process).

For `system()`, the argument `"/bin/sh"` must be at `[esp+4]` at the moment `system()` begins executing (after our crafted return jumps into it). Our overflow payload must therefore contain:

```
[overflow padding] [system() address] [exit() address] ["/bin/sh" address]
```

When the vulnerable function returns, it pops `system()` as the return address and jumps there. From `system()`'s perspective, its return address is `exit()` and its first argument (at `[esp+4]`) is the address of `"/bin/sh"`.

## Key Concepts

* **SP (Stack Pointer / ESP):** Moves with every push/pop, always pointing to the lowest currently-used stack address.
* **FP (Frame Pointer / EBP):** Stable reference for the current frame. The `push %ebp` instruction at function entry saves the previous frame's base pointer.
* **Return address:** Where code resumes after the current function finishes — this is what we overwrite.
* **Previous frame pointer:** Where ESP returns to — saved at `[ebp]` and restored by `pop %ebp` during epilogue.

The distinction matters: the return address governs where **code** jumps; the previous frame pointer governs where **SP** returns.

## Reference

* [COMPUTER SECURITY: A Hands-on Approach by Wenliang Du](https://www.amazon.com/Computer-Security-Hands-Approach-Wenliang/dp/154836794X)

---

## Introduction

* Stack은 주로 data가 담기는 곳이기 때문에 거기서 코드를 실행 시킬 필요는 없다. 그렇기 때문에 x86과 같은 컴퓨터 구조나 gcc에서 non-executable stack을 구현하여 stack에서 코드가 실행되지 않도록 해준다.
* 해커는 자신이 실행시키고 싶은 코드가 꼭 stack에 없어도 되고 이미 메모리상에서 돌아가고 있는 위치에다가 자신의 코드를 심으면 된다고 생각했다. 그래서 여러 곳 중에서 대다수 프로그램이 사용하고 있는 standard C library function을 위한 libc(In Linux)에 자신들의 코드를 심으면 되겠다 생각했다.
* 우리의 목적은 system() 함수로 jump해서 "/bin/sh"를 실행시키면 되는 것이다.
    1. 메모리 상에 올라와 있을 system() 주소를 찾는다.
    1. "/bin/sh" string 주소를 찾는다.
    1. 위의 string을 system()에 pass한다. argument의 정확한 자리를 찾으면 된다.

## 메모리 상의 system() 함수 주소 찾기

* libc는 프로그램 시작시 올라갈 것이기 때문에 gdb로 쉽게 알 수 있다.
```shell
$ touch badfile
$ gdb stack
(gdb) run
(gdb) p system
$1 = {<text variable, no debug info>} 0xb7e42da0 <__libc_system>
(gdb) p exit
$2 = {<text variable, no debug info>} 0xb7e369d0 <__GI_exit>
(gdb) quit
```
* 타겟 프로그램인 stack을 먼저 run 시켜야지 libc 함수 위치를 알 수 있다.
* exit 함수 주소는 나중을 위해서 찾아둔다.

## "/bin/sh" string 주소 찾기

* 2가지 접근법을 생각 할 수 있다.
    1. 버퍼 오버 플로우가 가능하면 직접 string을 만들어서 주소를 획득하기.
    1. environment variable을 이용해서 가져오기.

* shell process에서 export된 모든 환경 변수들은 자식 process들에게 그 값들을 전달하기 때문에 vulnerable program을 시키면 shell로 부터 환경 변수값을 메모리에 올리게 된다.
* 환경 변수값은 실행시키는 프로그램의 이름 길이에 영향을 받는다. 왜냐하면 프로그램의 이름이 먼저 스택에 쌓이고 이후에 환경 변수들이 쌓이기 때문이다.

## system() 함수에 argument 주소 찾기

* 우리가 system()을 쓰면 스택에 쌓이면서 $ebp로 접근을 할 수 있지만 libc에 있는 상황에서 그냥 그 함수를 쓰려고 하기 때문에 다른 방법을 찾아야한다.
* system()이 호출 되고 난 뒤에 $ebp가 어디로 가는지 파악하면 실마리를 찾을 수 있다.
* function prologue: the beginning of a function
    * 함수가 호출 되면 현재 esp위치에서 return address가 스텍에 쌓이고 esp는 다시 4만큼 늘어난다.
    * 이후 caller function's frame pointer, 즉 prev frame ptr($ebp)를 스텍에 쌓는다.
    * 지금까지 새로운 frame stack에 return address와 prev frame ptr이 쌓여있는 상황에서 $ebp의 값을 현재 $esp값으로 이동시킨다.(값 복사)
    * 마지막으로 $esp를 local variable에 관한 크기 + 컴파일러 시작에 관한 레지스터 값들을 위한 크기 N만큼 이동시킨다.
* function epilogue: the end of a function
    * %esp를 %ebp쪽으로 옮긴다. 즉, local variable을 위해 할당한 공간을 반납하는 것이다.
    * %ebp의 값을 이전 frame stack의 값으로 회복시킨다. 즉, base point를 이전 스택의 base point로 이동하여 이전 스택을 사용할 수 있게끔 하는 것이다.
    * 마지막으로 return address로 jump를 한다. 이때 $esp도 같이 움직인다.
* 지금 설명한 것들은 IA-32(32-bit x86) architecture에서 설명한 것이다.

* sp는 변수가 쌓일때마다 움직이면서 다음 변수가 할당될 메모리 위치를 가리킨다.
* fp는 sp가 돌아갈 위치를 가리킨다. 이전 스택의 $ebp이다.```<push %ebp>``` 명령어로 실행된다.
* return address는 code instruction이 돌아가야 할 위치를 의미하는 것이고 previous frame ptr은 sp가 옮겨가야 할 위치를 위미한다.

## Refrence

* [COMPUTER SECURITY: A Hands-on Approach by Wenliang Du](https://www.amazon.com/Computer-Security-Hands-Approach-Wenliang/dp/154836794X)
