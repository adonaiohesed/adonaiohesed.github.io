---
title: Buffer overflow attack
tags: security buffer_overflow
key: page-buffer_overflow_attack
cover: /assets/cover/cyber_security.png
mathjax: true
mathjax_autoNumber: true
---

## The five segments in a process's memory layout for a typical C program.

* **Text segment**: stores the executable code of the program. This block of memory is usually read-only. 코드 자체가 올라가는 영역으로 보면 된다.
* **Data segment**: stores static/global variables that are initialized by the programmer. For example, the variable ```a``` defined in ```static int a = 3``` will be stored in the Data segment.
* **BSS segment**: stores uninitialized static/global variables. This segment will be filled with zeros by the operating system, so all the uninitailized variables are initialized with zeros. For example, the variable ```b``` defined in ```static int b``` will be stored in the BSS segment, and it is initialized with zero.
* **Heap**: The heap is used to provide space for dynamic memory allocation. This area is managed by ```malloc, calloc, realloc, free```, etc.
* **Stack**: The stack is used for storing local variables defined inside functions, as well as storing data related to function calls, such as return address, arguments, etc.

지금까지 내가 몰랐던 것은 C에서 initialized를 하지 않으면 쓰레기 값이 들어간다고 생각했는데 그거는 stack에 쌓일때만 그렇고 BSS segment에서는 0으로 초기화 된다. 그말인 즉슨 static / global 변수는 0으로 초기화된다는 것을 의미한다.
<br><br>
일단 우리는 스택 버퍼 오버 플로우를 배우는 것이고 나중에 힙에 관한 버퍼 오버 플로우를 할 수 도 있는데 기법이 좀 다른가보다.
그리고 이거를 이해하기 위해서 먼저 스택의 작동방식과 저장 방식을 이해하는게 핵심이다.
<br><br>

## The layout of the stack frame

* **Arguments**: This region stores the values for the arguments that are passed to the function. When a function is called, , the values of the arguments(parameters) will be pushed into the stack, forming the beginning of the stack frame. It should be noted that the arguments are pushed in the reverse order.
* **Return Address**: When the function finishes and hits its ```return``` instruction, it needs to know where to return to(the previous code segment), i.e., the return address needs to be stored somewhere. Before jumping to the entrance of the function, the computer pushes the address of the next instruction-***the instruction placed right after the function invocation instruction***- into the top of the stack, which is the "return address" region in the stack frame.
* **Previous Frame Pointer**: The next item pushed into the stack frame by the program is the frame pointer for the previous frame.
* **Local Variables**: The next region is for stroing the function's local variables. The actual layout for this region, such as the order of the local variables, the actual size of the region, etc., is up to the compilers. Some compilers may randomize the order of the local variables, or give extra space for this region. Programmers should not assume any particular order or size for this region.

* Stack point(sp)는 Frame Pointer와 별개로 따로 존재한다.

* Frame Pointer가 작동할때에는 Previous Frame Pointer와 함께 동작한다.
우리가 배우는 곳에는 하나의 frame pointer register밖에 없다. 따라서 거기에는 항상 current function's stack frame을 가리키고 있고 Previous Frame Pointer에 이전에 호출한 함수의 frame위치를 저장시켜 하나의 레지스터로 이전의 위치들을 찾아가며 실행하는 원리이다.
strcpy()라는 함수는 끝에 ```\0``` 즉 0x00으로 끝나면 함수의 끝이라고 판단하고 string은 컴파일러에서 자동으로 붙여주어 끝을 알 수 있게 도와준다.

## Stack 작동 원리

* Stack이 자라는 방향은 downforward이고 스택이 쌓이기 전 가장 먼저 하는 것이 스택의 크기들이 정해지는 것이다.

* 따라서 변수들을 스택에 쌓기 전에 argument에 관한 크기, local variable에 관한 크기들이 이미 정해진다.

* 이후 argument는 ebp에서 +4씩(32bit 경우) 증가하는 방향으로 변수들이 차곡차곡 쌓이기 시작하고 local variable은 -4씩 감소하는 방향으로 변수들이 쌓이기 시작한다.

* 1byte, 2byte의 경우 4byte기준에서 남은 공간에 덤프 값(쓰레기 값)이 들어간다.

## 레지스터 정리 [참고 사이트](https://m.blog.naver.com/PostView.nhn?blogId=byunhy69&logNo=140112048445&proxyReferer=https%3A%2F%2Fwww.google.com%2F)

* ESP : 함수가 진행하고 있을 때 stack의 제일 아래 부분,현재 진행 stack 지점, Stack Pointer<br>stack 메모리는 아래로 성장하기 때문에 제일 아래가 제일 마지막이 된다.
* EBP : 스택의 가장 윗 부분(기준점), Base Pointer
* EIP : 실행할 명령의 주소, Instruction Pointer
* E가 붙는 것은 16비트에서 32비트 시스템으로 오면서 Extended 된 개념, 64비트에서는 R이 붙음
* 32bit 레지스터의 기본 설명은 [http://www.reversecore.com/tag/EIP](http://www.reversecore.com/tag/EIP) 참고

## Setup for Our Experiment

* Disable Address Randomization
```console
$ sudo sysctl -w kernel.randomize_va_space=0
```

* Vulnerable Program
```console
$ gcc -o stack -z execstack -fno-stack-protector stack.c
$ sudo chown root stack
$ sudo chmod 4755 stack
```

<img src="/assets/images/chmod_special.png" width="400px" style="display: block;margin-left: auto;margin-right: auto;">

* ```sudo chmod 4755 stack``` 을 할때에는 위와 같은 특수 권한이 부여되는 것이다. [참고사이트](https://eunguru.tistory.com/115)

## Conduct Buffer-Overflow Attack

### Finding the Address of the Injected Code

* First, we need to know the memory address of the malicious code. However, the target program in unlikely to print out the value of its frame pointer or the address of any variable inside the frame, leaving us no choice but to guess.
* 32bit 컴퓨터의 경우 한 번에 처리하는 데이터의 크기가 32bit이기 때문에 메모리 주소값을 가르키기 위해서 $$ 2^{32} = 4,294,967,296 $$밖에 표현 할 수 없다. 따라서 32bit 컴퓨터의 메모리의 한계는 4G정도 한다.
* 우리가 추측할 메모리의 크기는 사실 위의 범위보다 작게 되는데 왜냐하면 OS에서 보통 프로세스마다 하나의 stack을 고정된 시작 주소에서부터 할당하기 시작하기 때문이다. 또 다른 이유로 대다수의 프로그램은 deep stack을 쓰지 않기때문이다. Recursive 함수가 아닌 이상 shallow stack을 쓰기 때문에 어느정도 쉽게 우리가 원하는 target program에 관한 주소값을 추측 할 수 있게 된다. 단, kernel.randomize_va_space=0의 값을 설정했을 때만 그렇다.

### Improving Chances of Gussing

* 우리가 inject 시킬 코드의 위치도 정확히 계산을 해야 하는데 이때 우리가 1 byte라도 놓치게 된다면 실패할 것이다. 그래서 No-Op(NOP) instructions을 넣음으로써 entry point자체를 늘려준다.

<img src="/assets/images/nop.png" width="400px" style="display: block;margin-left: auto;margin-right: auto;">

[출처:https://csis.gmu.edu/ksun/AIT681-s19/notes/T07_Buffer_Overflow.pdf](https://csis.gmu.edu/ksun/AIT681-s19/notes/T07_Buffer_Overflow.pdf)

### Finding the Address Without Gussing

* 공격을 할 때 같은 머신에서 공격을 하면 victim program의 copy를 구할 수 있어서 주소 찾기가 쉽지만 remote attack일 경우는 copy를 구할 수 없고 target machine의 조사도 힘들다.
* debugger를 통해서 stack frame의 위치를 알 수 있다. 디버거(gdb)를 쓰기 위해 ```gcc -g``` 옵션을 붙여줘야 한다.
* 디버거를 할 수 있는 것을 만들었으면 gdb로 그 함수들의 $ebp, stack frame의 크기 같은 것을 계산한다.

### Constructing the Input File

* 위의 gdb 과정에서 단순 gussing이 아닌 어느 정도 그 구조의 위치들을 알아냈으면 우리가 원하는 코드를 집어넣기 위해서 어떻게 코드를 짜야될지 계산한다.

<img src="/assets/images/constructing_intput_file.png" width="600px" style="display: block;margin-left: auto;margin-right: auto;">

* 위의 프로그램은 'Computer Security A Hands-on Approach Chapter 4에서 나오는 예제로 구성한 그림이다.
* 먼저 우리 타겟 프로그램에 대한 분석을 끝내고 exploit.c프로그램을 통해서 badfile을 만들어 그 badfile을 타켓 프로그램에서 불러오도록 하여 타겟 스택에다가 심는다.
* 그때 계산해야 될 것이 우리가 타겟으로 삼은 foo 함수에서 return address를 main stack overwirte된 위치에 존재하는 shell code를 실행 시킬 수 있도록 주소값을 적절히 설정해야 되는 것이다.
* badfile에 있는 것을 main에도 심고 foo에도 심는 이유는 타겟 프로그램의 특성 자체가 저렇게 접근해야만 하도록 설정되어 있기 때문에 우리는 타겟 프로그램(우리가 바꿀 수 없다고 가정)에 맞도록 우리의 악성 코드를 실행 및 심을 수 있도록 생각해야 된다.
* 지금까지 가능한 것은 아래의 환경 때문이다.
    * Stack usually starts at the same address.
    * Stack is usually not very deep: most programs do not push more than a few hundred or a few thousand bytes into the stack at any one time.
    * Therefore the range of addresses that we need to guess is actually quite small.

## Countermeasures: Overview

### Developer approaches

* Use of Safer functions - strncpy(), strncat() 같은 것을 사용한다.
* Use of safer dynamic link libraries  - To check the length of the data before copying and when we only have binary, we can use it.
* Program Static Analyzer - editor속에 있거나 command-line tool로 사용되어져서 개발자가 조기에 위험한 요소를 발견할 수 있게 도와준다.
* Programming Language - Java나 파이썬 같은 것은 언어 자체내에서 boundary check를 해서 BOF를 막는다.

### Compiler approaches

* Stack-Guard, Stackshield - function이 끝나기전에 return address가 바뀌었는지 체크한다.
    * Stackshield - return address를 다른 location(a shadow stack)에 복사한 다음에 나중에 그 값과 return address를 실행할때 비교하는 방식이고 shadow stack은 overflown되지 않는 곳에 있다.
    * Stack-Guard - return address와 buffer 사이에 guard를 넣어서 guard의 변형 유무로 BOF를 막는다. guard(canary라고도 불린다)를 넣을때는 랜덤 값을 넣고 그 복사값을 스택 밖에다가 저장해둔다. 이 아이디어는 BOF가 진행되면 반드시 canary또한 overflow되어 바뀐다는 사실에 기반한다.

### OS approaches

* ASLR (Address Space Layout Randomization) - 메모리 위치를 추측 할 수 없도록 만들어서 BOF를 막는다.

### Hardware approaches

* Non-Executable Stack - 현대 CPU에는 NX bit가 있어서 code와 data를 분리시키는 기법이 있는데 이거는 return-to-libc attack으로 뚫릴 수 있다.

## Address Randomization

* Stack이 fixed memory location에서 시작되어야 될 필요는 없다. 왜냐하면 %ebp, %esp만 제대로 설정되어 있으면 그것으로 스택 접근이 가능하기 때문이다. 이런 기법은 heap, libraries등에서도 쓰일 수 있다.
* 프로그램이 돌때 OS에서 로더를 통해 프로그램을 로딩을 하는데 로더가 stack과 heap memory를 설정한다. 따라서 memory randomization은 주로 로더에서 implemented된다.
* 32bit Linux 컴퓨터의 경우 19bit은 stack entropy에 쓰이고 13bit가 heap에 쓰인다. 따라서 $$ 2^{19} = 524,288 $$ stack base possibilities가 형성되는데 너무 적은 숫자이다. 해커가 충분히 brute-force로 뚫을 수 있는 숫자이다.
* 안드로이드 Nexus 5의 경우 entropy가 8bit밖에 안 되어(32bit 체제) 경우의 수가 더 적어서 brute-force 공격이 더 쉬웠는데 이런 버그를 stagefright라고 불렀다.

## StackGuard

* stack안에 가드를 두고 그 값이 바뀌면 누군가 조작을 했다고 인식하는 것이다. 가드를 canary라고도 부른다.

## ETC

* foo같은 함수안에 buffer가 함수 인자로 들어오는 데이터 크기보다 작으면 버퍼 오버 플로우 공격을 당할 위험이 있다.
```c
int foo(char *str)
{
    char buffer[50];
    strcpy(buffer, str);
    return 1;
}
int main(int argc, char ** argv)
{
    char str[240];
    FILE *badfile;

    badfile = fopen("badfile", "r");
    fread(str, sizeof(char), 200, badfile);
    foo(str);

    return 1;    
}
```

## Refrence

* [COMPUTER SECURITY: A Hands-on Approach by Wenliang Du](https://www.amazon.com/Computer-Security-Hands-Approach-Wenliang/dp/154836794X)