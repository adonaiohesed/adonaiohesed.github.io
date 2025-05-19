---
title: EDR Bypass
tags: EDR
key: page-edr_bypass
categories: [Cybersecurity, Security Operations]
author: hyoeun
math: true
mathjax_autoNumber: true
---

# EDR Bypass Techniques: Understanding Attack Methods and Defense Strategies

## Overview

While Endpoint Detection and Response (EDR) solutions are core components of modern cybersecurity, continuously evolving attackers develop various techniques to bypass these protective mechanisms. This post explores the types of EDR bypass techniques, how they work, and defense strategies organizations can implement to protect against these threats.

## Basic Principles of EDR Bypass

EDR bypass is based on the following core principles:

1. **Monitoring evasion**: Avoiding or bypassing areas monitored by EDR
2. **Detection evasion**: Hiding or manipulating known malicious patterns
3. **Leveraging legitimate tools**: Using trusted tools already present in the system
4. **Memory-based attacks**: Conducting attacks that leave no traces on disk

## Major EDR Bypass Techniques

### 1. Memory Manipulation Techniques

Memory-based attacks are possible due to several combined factors:

1. **Visibility limitations**: Many EDR solutions tend to focus on files written to disk, registry changes, certain API calls, etc. Attacks that execute only in memory without leaving traces on disk can bypass these traditional detection methods.

2. **Resource constraints**: Continuously monitoring all areas of memory is highly resource-intensive. To prevent performance issues, EDR sometimes limits the depth and scope of memory monitoring.

3. **DLL-related issues**:
   - Not all DLLs are monitored equally: EDR often focuses on known dangerous DLLs or common attack paths.
   - Disguising as normal DLLs: Attackers can mimic normal system DLLs or exploit normal files through DLL hijacking.
   - Injection techniques: Various techniques for loading or injecting DLLs directly in memory (such as reflective loading) can bypass common DLL loading events.

4. **Complex detection environment**: 
   - While EDR can detect process execution, it's difficult to perfectly analyze all memory manipulations occurring within a process.
   - Obfuscation techniques: Attackers can dynamically decrypt or transform executable code in memory to evade detection.
   - Distinguishing from legitimate memory manipulation: Many normal programs also dynamically manipulate memory, making it difficult to distinguish from malicious activity.

5. **LOLBAS (Living Off The Land Binaries And Scripts) utilization**: Attackers can use built-in system tools like PowerShell, WMI, WinRM to perform in-memory attacks, and these are difficult to block because they are normal tools included in the system by default.

Memory manipulation techniques operate directly in system memory without writing files to disk, bypassing file-based detection in many EDR solutions.

#### DLL Injection

DLL injection is a technique that inserts malicious code into a legitimate process.

```c
// Basic DLL injection example code
HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, targetProcessId);
LPVOID remoteBuffer = VirtualAllocEx(hProcess, NULL, sizeof(dllPath), MEM_COMMIT, PAGE_READWRITE);
WriteProcessMemory(hProcess, remoteBuffer, dllPath, sizeof(dllPath), NULL);
HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)LoadLibraryA, remoteBuffer, 0, NULL);
```

#### Process Hollowing

Process hollowing is a technique that creates a legitimate process and then replaces its memory with malicious code.

1. Create a normal process in a suspended state
2. Unmap the content of the process memory
3. Map malicious code into memory
4. Resume process execution

#### Atom Bombing

Atom bombing uses the Windows atom table mechanism to inject code.

1. Store malicious code in the global atom table
2. Force a legitimate process to retrieve data from the atom table
3. Code is copied into the target process's address space
4. Execute code through an Asynchronous Procedure Call (APC)

### 2. Direct System Calls and API Hooking Bypass

#### Direct System Calls

Many EDR solutions monitor by hooking Windows API functions. Attackers can use direct system calls to bypass these hooks.

```c
// Direct syscall example
__asm {
    mov eax, 0x25 // Syscall number for NtCreateFile
    mov edx, esp
    sysenter
}
```

#### NTDLL Mapping Bypass

This technique loads a fresh copy of NTDLL.DLL from disk to bypass the hooked NTDLL.DLL.

1. Map a clean copy of NTDLL.DLL from disk
2. Extract necessary function addresses
3. Call functions directly from memory

#### Dynamic Function Resolution for Detection Evasion

Resolving function addresses dynamically instead of string references to evade static analysis detection.

```c
// Dynamic function resolution example
HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");
FARPROC pCreateProcessA = GetProcAddress(hKernel32, "CreateProcessA");
((CREATE_PROCESS_A)pCreateProcessA)(NULL, commandLine, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi);
```

### 3. Fileless Malware Techniques

#### Using PowerShell and WMI

Using PowerShell and Windows Management Instrumentation (WMI) to perform attacks without writing files to disk.

```powershell
# Execute PowerShell payload directly in memory
$code = [System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String('Base64 encoded payload'));
iex $code
```

#### Living-off-the-Land Techniques (LOLBins)

Exploiting legitimate binaries built into the system to conduct attacks.

```
# Example of code execution using regsvr32
regsvr32.exe /s /u /i:evil.sct scrobj.dll
```

Key LOLBins:
- regsvr32.exe
- mshta.exe
- certutil.exe
- bitsadmin.exe
- msiexec.exe

#### Registry-Based Payloads

Storing malicious code in the Windows registry and executing it from memory.

```powershell
# Example of storing payload in registry
$payload = "Base64 encoded payload"
Set-ItemProperty -Path "HKCU:\Software\Classes\CLSID\{00000000-0000-0000-0000-000000000000}" -Name "Payload" -Value $payload
```

### 4. Execution Flow Obfuscation

#### Control Flow Flattening

Making the logical flow of code complex to make analysis difficult.

1. Split code into small blocks
2. Control execution order of blocks through a central dispatcher
3. Hide the actual execution flow

#### String Obfuscation

Dynamically constructing strings at runtime to evade static analysis detection.

```c
// String obfuscation example
char str[] = {0x43, 0x72, 0x65, 0x61, 0x74, 0x65, 0x50, 0x72, 0x6f, 0x63, 0x65, 0x73, 0x73, 0x00};
for (int i = 0; i < sizeof(str) - 1; i++) {
    str[i] = str[i] ^ 0x11;  // Decrypt with XOR operation
}
```

### 5. Kernel-Level Attacks

#### Driver Exploitation

Using vulnerable legitimate drivers to escalate privileges and bypass EDR.

```c
// Driver loading example
SC_HANDLE hSCManager = OpenSCManager(NULL, NULL, SC_MANAGER_CREATE_SERVICE);
SC_HANDLE hService = CreateService(hSCManager, "VulnDriver", "Vulnerable Driver", SERVICE_ALL_ACCESS, SERVICE_KERNEL_DRIVER, SERVICE_DEMAND_START, SERVICE_ERROR_NORMAL, "C:\\Path\\To\\Driver.sys", NULL, NULL, NULL, NULL, NULL);
StartService(hService, 0, NULL);
```

#### Callback Invalidation

Invalidating kernel callbacks used by EDR solutions to block event notifications.

### 6. Environment Awareness and Evasion Techniques

#### Sandbox Detection

Detecting virtual environments or analysis tools to suppress malicious behavior.

```c
// Virtual environment detection example
bool IsVirtualMachine() {
    __try {
        __asm {
            rdtsc
            xchg ebx, ebx
            rdtsc
            sub eax, edx
            cmp eax, 0xFF
            jg vm_detected
        }
    }
    __except(EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
    return false;
vm_detected:
    return true;
}
```

#### Timing-Based Evasion

Using execution delays to bypass initial monitoring.

```c
// Timing-based evasion example
Sleep(300000);  // Wait 5 minutes
// Start malicious activity after delay
```

### 7. Abuse of Legitimate Tools

#### Leveraging Dual-Use Tools

Exploiting legitimate penetration testing tools like Cobalt Strike and Mimikatz.

#### Code Signing Bypass

Using digitally signed binaries to execute code or perform DLL sideloading.

## Defense Strategies Against EDR Bypass

### 1. Build Multi-Layered Defense

Implement multiple security layers instead of relying on a single security solution.

- EDR + Firewall + Network Monitoring + Email Security
- Implement Zero Trust Architecture
- Enhance anomaly behavior analysis

### 2. Optimize EDR Capabilities

Maintain the latest detection capabilities and optimize EDR configuration.

- Apply regular EDR updates
- Activate all monitoring channels
- Enable kernel-level monitoring
- Adjust behavior analysis engine sensitivity

### 3. Strengthen Privilege Management

Apply the principle of least privilege.

- Restrict administrator rights
- Apply application allowlisting
- Implement LAPS (Local Administrator Password Solution)
- Implement Just-In-Time administrator access

### 4. Network Segmentation

Limit lateral movement to minimize compromise scope.

- Implement internal firewalls
- Isolate critical systems
- Apply micro-segmentation

### 5. Integrate Threat Intelligence

Utilize information about the latest threat techniques.

- Subscribe to threat intelligence feeds
- Monitor IOCs (Indicators of Compromise)
- Map to MITRE ATT&CK framework
- Share information with security community

### 6. Security Awareness and Training

Train employees to recognize and report threats.

- Regular security awareness training
- Phishing simulations
- Penetration testing
- Incident response training

## Conclusion

EDR bypass techniques continue to evolve, and attackers will always try to find new methods to circumvent security mechanisms. It's important for security professionals to understand these techniques and implement appropriate defense strategies.

To build an effective security posture, organizations must continuously monitor the latest threat trends, integrate multiple security technologies, and adopt a defense-in-depth approach. Security is an ongoing process, not a single solution, and organizations should constantly evaluate and improve their security posture.

While EDR is an important component of endpoint security, no solution is perfect. Security teams must recognize the limitations of EDR and implement additional security controls to complement it. Organizations equipped with knowledge of threat actor techniques and response capabilities will be better protected in today's cyber threat landscape.

---

# EDR 우회 기법: 공격 기술 이해와 방어 전략

## 개요

엔드포인트 탐지 및 대응(EDR) 솔루션은 현대 사이버 보안의 핵심 구성 요소이지만, 지속적으로 진화하는 공격자들은 이러한 보호 메커니즘을 우회하기 위한 다양한 기술을 개발하고 있습니다. 이 포스팅에서는 EDR 우회 기법의 유형, 작동 방식, 그리고 조직이 이러한 위협으로부터 보호하기 위한 방어 전략에 대해 살펴보겠습니다.

## EDR 우회의 기본 원리

EDR 우회는 다음과 같은 핵심 원리에 기반합니다:

1. **모니터링 회피**: EDR이 모니터링하는 영역을 피하거나 우회
2. **감지 회피**: 알려진 악성 패턴을 숨기거나 변조
3. **합법적 도구 이용**: 시스템에 이미 존재하는 신뢰할 수 있는 도구 활용
4. **메모리 기반 공격**: 디스크에 흔적을 남기지 않는 공격 수행

## 주요 EDR 우회 기법

### 1. 메모리 조작 기법

메모리 기반 공격이 가능한 이유는 여러 요인이 복합적으로 작용하기 때문입니다:

1. **가시성의 한계**: 많은 EDR 솔루션은 디스크에 기록되는 파일, 레지스트리 변경, 특정 API 호출 등에 초점을 맞추는 경향이 있습니다. 메모리 내에서만 실행되고 디스크에 흔적을 남기지 않는 공격은 이러한 전통적인 탐지 방식을 우회할 수 있습니다.

2. **리소스 제약**: 메모리의 모든 영역을 지속적으로 모니터링하는 것은 매우 리소스 집약적입니다. 성능 문제를 방지하기 위해 EDR은
경우에 따라 메모리 모니터링의 깊이와 범위를 제한합니다.

3. **DLL 관련 문제**:
   - 모든 DLL을 동등하게 모니터링하지 않음: EDR은 알려진 위험한 DLL이나 일반적인 공격 경로에 집중하는 경우가 많습니다.
   - 정상적인 DLL 위장: 공격자는 정상적인 시스템 DLL을 모방하거나 정상 파일을 DLL 하이재킹으로 악용할 수 있습니다.
   - 인젝션 기법: 메모리에서 직접 DLL을 로드하거나 인젝션하는 다양한 기법(리플렉티브 로딩 등)을 사용하면 일반적인 DLL 로딩 이벤트를 우회할 수 있습니다.

4. **복잡한 탐지 환경**: 
   - EDR이 프로세스 실행은 탐지할 수 있지만, 프로세스 내부에서 일어나는 모든 메모리 조작을 완벽하게 분석하기는 어렵습니다.
   - 난독화 기법: 공격자는 메모리 내에서 실행 코드를 동적으로 복호화하거나 변형시켜 탐지를 회피할 수 있습니다.
   - 합법적인 메모리 조작과의 구분: 많은 정상적인 프로그램도 메모리를 동적으로 조작하므로, 악의적인 활동과 구분하기 어려울 수 있습니다.

5. **LOLBAS(Living Off The Land Binaries And Scripts) 활용**: 공격자는 PowerShell, WMI, WinRM과 같은 시스템 내장 도구를 사용하여 메모리 내 공격을 수행할 수 있으며, 이들은 시스템에 기본적으로 포함된 정상적인 도구이기 때문에 차단하기 어렵습니다.

메모리 조작 기법은 디스크에 파일을 쓰지 않고 시스템 메모리에서 직접 작동하여 많은 EDR 솔루션의 파일 기반 탐지를 우회합니다.

#### DLL 인젝션

DLL 인젝션은 합법적인 프로세스에 악성 코드를 삽입하는 기술입니다.

```c
// 기본적인 DLL 인젝션 예시 코드
HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, targetProcessId);
LPVOID remoteBuffer = VirtualAllocEx(hProcess, NULL, sizeof(dllPath), MEM_COMMIT, PAGE_READWRITE);
WriteProcessMemory(hProcess, remoteBuffer, dllPath, sizeof(dllPath), NULL);
HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)LoadLibraryA, remoteBuffer, 0, NULL);
```

#### 프로세스 할로잉(Process Hollowing)

프로세스 할로잉은 합법적인 프로세스를 생성한 후 해당 메모리를 악성 코드로 교체하는 기술입니다.

1. 정상 프로세스를 일시 중단된 상태로 생성
2. 프로세스 메모리의 내용을 언매핑
3. 악성 코드를 메모리에 매핑
4. 프로세스 실행 재개

#### 아톰 바밍(Atom Bombing)

아톰 바밍은 Windows 아톰 테이블 메커니즘을 사용하여 코드를 주입하는 기술입니다.

1. 전역 아톰 테이블에 악성 코드 저장
2. 합법적인 프로세스가 아톰 테이블에서 데이터를 검색하도록 강제
3. 코드가 대상 프로세스의 주소 공간에 복사됨
4. APC(Asynchronous Procedure Call)를 통해 코드 실행

### 2. 직접 시스템 호출 및 API 후킹 우회

#### 직접 시스템 호출

많은 EDR 솔루션은 Windows API 함수를 후킹하여 모니터링합니다. 공격자는 이러한 후킹을 우회하기 위해 직접 시스템 호출을 사용할 수 있습니다.

```c
// Direct syscall 예시
__asm {
    mov eax, 0x25 // NtCreateFile의 syscall 번호
    mov edx, esp
    sysenter
}
```

#### NTDLL 매핑 우회

이 기법은 후킹된 NTDLL.DLL을 우회하기 위해 디스크에서 새로운 NTDLL 복사본을 로드합니다.

1. 디스크에서 깨끗한 NTDLL.DLL 복사본 매핑
2. 필요한 함수 주소 추출
3. 메모리에서 직접 함수 호출

#### 탐지 회피를 위한 동적 함수 해석

문자열 참조 대신 동적으로 함수 주소를 해석하여 정적 분석 탐지를 회피합니다.

```c
// 동적 함수 해석 예시
HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");
FARPROC pCreateProcessA = GetProcAddress(hKernel32, "CreateProcessA");
((CREATE_PROCESS_A)pCreateProcessA)(NULL, commandLine, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi);
```

### 3. 파일리스 멀웨어 기법

#### PowerShell 및 WMI 사용

PowerShell 및 Windows Management Instrumentation(WMI)을 사용하여 디스크에 파일을 쓰지 않고 공격을 수행합니다.

```powershell
# 메모리에서 직접 PowerShell 페이로드 실행
$code = [System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String('Base64 인코딩된 페이로드'));
iex $code
```

#### Living-off-the-Land 기법(LOLBins)

시스템에 내장된 합법적인 바이너리를 악용하여 공격을 수행합니다.

```
# regsvr32를 사용한 코드 실행 예시
regsvr32.exe /s /u /i:evil.sct scrobj.dll
```

주요 LOLBins:
- regsvr32.exe
- mshta.exe
- certutil.exe
- bitsadmin.exe
- msiexec.exe

#### 레지스트리 기반 페이로드

악성 코드를 Windows 레지스트리에 저장하고 메모리에서 실행합니다.

```powershell
# 레지스트리에 페이로드 저장 예시
$payload = "Base64 인코딩된 페이로드"
Set-ItemProperty -Path "HKCU:\Software\Classes\CLSID\{00000000-0000-0000-0000-000000000000}" -Name "Payload" -Value $payload
```

### 4. 실행 흐름 난독화

#### 제어 흐름 평탄화(Control Flow Flattening)

코드의 논리적 흐름을 복잡하게 만들어 분석을 어렵게 합니다.

1. 코드를 작은 블록으로 분할
2. 중앙 디스패처를 통해 블록 실행 순서 제어
3. 실제 실행 흐름 숨기기

#### 문자열 난독화

문자열을 실행 시간에 동적으로 구성하여 정적 분석 탐지를 회피합니다.

```c
// 문자열 난독화 예시
char str[] = {0x43, 0x72, 0x65, 0x61, 0x74, 0x65, 0x50, 0x72, 0x6f, 0x63, 0x65, 0x73, 0x73, 0x00};
for (int i = 0; i < sizeof(str) - 1; i++) {
    str[i] = str[i] ^ 0x11;  // XOR 연산으로 복호화
}
```

### 5. 커널 레벨 공격

#### 드라이버 악용

취약한 합법적 드라이버를 사용하여 권한을 상승시키고 EDR을 우회합니다.

```c
// 드라이버 로드 예시
SC_HANDLE hSCManager = OpenSCManager(NULL, NULL, SC_MANAGER_CREATE_SERVICE);
SC_HANDLE hService = CreateService(hSCManager, "VulnDriver", "Vulnerable Driver", SERVICE_ALL_ACCESS, SERVICE_KERNEL_DRIVER, SERVICE_DEMAND_START, SERVICE_ERROR_NORMAL, "C:\\Path\\To\\Driver.sys", NULL, NULL, NULL, NULL, NULL);
StartService(hService, 0, NULL);
```

#### 콜백 무효화

EDR 솔루션이 사용하는 커널 콜백을 무효화하여 이벤트 알림을 차단합니다.

### 6. 환경 인식 및 회피 기법

#### 샌드박스 감지

가상 환경이나 분석 도구를 감지하여 악성 행동을 억제합니다.

```c
// 가상 환경 감지 예시
bool IsVirtualMachine() {
    __try {
        __asm {
            rdtsc
            xchg ebx, ebx
            rdtsc
            sub eax, edx
            cmp eax, 0xFF
            jg vm_detected
        }
    }
    __except(EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
    return false;
vm_detected:
    return true;
}
```

#### 타이밍 기반 회피

실행 지연을 사용하여 초기 모니터링을 우회합니다.

```c
// 타이밍 기반 회피 예시
Sleep(300000);  // 5분 대기
// 이후 악성 활동 시작
```

### 7. 합법적 도구 악용

#### 듀얼 유스 도구 활용

Cobalt Strike, Mimikatz 등 합법적 펜테스트 도구를 악용합니다.

#### 코드 서명 우회

디지털 서명된 바이너리를 사용하여 코드를 실행하거나 DLL 사이드로딩을 수행합니다.

## EDR 우회에 대한 방어 전략

### 1. 다층 방어 구축

단일 보안 솔루션에 의존하지 않고 여러 보안 계층을 구현합니다.

- EDR + 방화벽 + 네트워크 모니터링 + 이메일 보안
- 제로 트러스트 아키텍처 구현
- 이상 행동 분석 강화

### 2. EDR 기능 최적화

최신 탐지 기능을 유지하고 EDR 구성을 최적화합니다.

- 정기적인 EDR 업데이트 적용
- 모든 모니터링 채널 활성화
- 커널 레벨 모니터링 활성화
- 행동 분석 엔진 민감도 조정

### 3. 권한 관리 강화

최소 권한 원칙을 적용합니다.

- 관리자 권한 제한
- 애플리케이션 허용 목록 적용
- LAPS(Local Administrator Password Solution) 구현
- Just-In-Time 관리자 액세스 구현

### 4. 네트워크 세그먼테이션

측면 이동을 제한하여 침해 범위를 최소화합니다.

- 내부 방화벽 구현
- 중요 시스템 격리
- 마이크로 세그먼테이션 적용

### 5. 위협 인텔리전스 통합

최신 위협 기법에 대한 정보를 활용합니다.

- 위협 인텔리전스 피드 구독
- IOC(침해 지표) 모니터링
- MITRE ATT&CK 프레임워크와 매핑
- 보안 커뮤니티와 정보 공유

### 6. 보안 인식 및 훈련

직원들이 위협을 인식하고 보고할 수 있도록 훈련합니다.

- 정기적인 보안 인식 교육
- 피싱 시뮬레이션
- 모의 침투 테스트
- 인시던트 대응 훈련

## 결론

EDR 우회 기법은 계속해서 진화하고 있으며, 공격자들은 항상 새로운 방법을 찾아 보안 메커니즘을 우회하려고 시도할 것입니다. 보안 전문가들은 이러한 기법을 이해하고 적절한 방어 전략을 구현하는 것이 중요합니다.

효과적인 보안 태세를 구축하기 위해서는 최신 위협 동향을 지속적으로 모니터링하고, 여러 보안 기술을 통합하며, 심층 방어 접근 방식을 채택해야 합니다. 보안은 단일 솔루션이 아닌 지속적인 프로세스이며, 조직은 항상 보안 태세를 평가하고 개선해야 합니다.

EDR은 엔드포인트 보안의 중요한 구성 요소이지만, 완벽한 솔루션은 없습니다. 보안 팀은 EDR의 한계를 인식하고 이를 보완하기 위한 추가적인 보안 제어 장치를 구현해야 합니다. 위협 행위자의 기술에 대한 지식과 대응 능력을 갖춘 조직은 현대의 사이버 위협 환경에서 더 잘 보호될 수 있을 것입니다.