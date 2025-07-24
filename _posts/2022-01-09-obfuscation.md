---
title: Obfuscation
tags: Obfuscation
key: page-obfuscation
categories: [Cybersecurity, Mobile Security]
author: hyoeun
math: true
mathjax_autoNumber: true
---

## A Smokescreen in the Code: Obfuscation and the Art of Lifting the Veil

When developers release their code into the world, they want to protect the secrets within—core business logic, proprietary algorithms, and API keys. To do this, they create a clever **smokescreen** over their code. This is **obfuscation**. Obfuscation is a technique that keeps the code's functionality intact while making it nearly impossible for humans to read and understand.

However, for us—the hackers and reverse engineers who feel compelled to look inside the system—obfuscation isn't an insurmountable wall but an interesting **puzzle** waiting to be solved. In this article, I'll talk about why developers use this smokescreen, what kinds of smokescreens exist, and how we can lift that veil to see the code's true face.

-----

## Why Do Developers Hide Their Code? (The Purpose of Obfuscation)

Understanding our "enemy" is fundamental. The reasons developers apply obfuscation are clear.

  * **Intellectual Property (IP) Protection**: To prevent proprietary algorithms or core logic, developed through significant time and cost, from being easily copied by competitors or others.
  * **Hiding Security Logic**: To make it difficult to bypass security measures like root/jailbreak detection, SSL pinning, or encryption key handling by hiding where the relevant code is located.
  * **Preventing Tampering and Cracking**: To deter piracy and cracking attempts by making it harder to analyze the app's license verification or in-app purchase logic.

Ultimately, the essence of obfuscation is to **increase the cost of analysis**. The core goal isn't to make reverse engineering "impossible" but to make it so "time-consuming and labor-intensive" that it diminishes the cost-effectiveness of an attack.

-----

## Common Obfuscation Techniques (Types of Smokescreens)

An attacker must know the weapons their opponent uses. There are various obfuscation techniques, and they are often used in combination.

  * **Identifier Renaming**: This is the most basic and common technique. Meaningful function or variable names like `checkUserLicense()` are changed to meaningless characters like `a()`, `b`, or `c1`. The code still works, but you can't guess its role from the name alone.
  * **String Encryption**: Important strings directly exposed in the code (like API endpoints, error messages, or encryption keys) are replaced with encrypted byte arrays. The app decrypts these strings in memory at runtime. Static analysis alone won't reveal which strings are being used.
  * **Control Flow Flattening**: This is a very effective technique that turns code into spaghetti. Normal control flows like `if-else` or `for` loops are dismantled into a giant `while` loop and a `switch` statement. Code that originally executed sequentially is broken into multiple code blocks and called in a jumbled order within the massive `switch` statement. This makes it nearly impossible to visually follow the code's execution order.
  * **Instruction Substitution & Dead Code Insertion**: Simple operations like `a = b + c` are replaced with more complex but equivalent instructions, such as `a = (b*2 + c*2) / 2`. Alternatively, meaningless code that has no effect on the actual execution (dead code) is inserted intermittently to confuse the analyst.

-----

## Lifting the Veil: The De-obfuscation Process

Now, it's time to solve the puzzle. For obfuscated code, static analysis has clear limitations. Our key weapon is **dynamic analysis**.

### Step 1: Grasping the Structure with Static Analysis (Initial Analysis)

First, we open the code with tools like **Jadx** (Android), **IDA Pro**, or **Ghidra** (iOS/Native). If all the names are `a`, `b`, and `c`, there are no meaningful strings, and the function flows are abnormally complex, then obfuscation has been applied. At this stage, we scout for "targets" to attack. For example, we might find an unusually complex `switch` statement or a chunk of encrypted data.

### Step 2: Revealing the True Face with Dynamic Analysis (The Core)

The true nature of the code is revealed when it's actually **executed**. Dynamic analysis tools like **Frida** demonstrate absolute power here.

  * **Hooking the String Decryption Function**:
    The first thing to do is find the function that decrypts the encrypted strings. Usually, this function takes a byte array as an argument and returns a plaintext string. By finding and hooking this function, you can eavesdrop on all the secret strings the app uses in real time.

    **Conceptual Frida Script Example:**

    ```javascript
    Java.perform(function() {
        // Assume the 'a' method of the com.secret.CryptoUtil class is the decryption function
        const CryptoUtil = Java.use("com.secret.CryptoUtil");

        // Overwrite the method's implementation
        CryptoUtil.a.implementation = function(encrypted_bytes) {
            // Call the original method to get the decrypted result
            const decrypted_string = this.a(encrypted_bytes);

            // Log the result
            console.log("String Decrypted: " + decrypted_string);

            // Return the original result
            return decrypted_string;
        };
    });
    ```

    With just this one script, the app's hidden URLs, API keys, and more will be printed to the console.

  * **Tracing the Control Flow**:
    It doesn't matter if the code is tangled like spaghetti due to control flow flattening. You can use **frida-trace** or a debugger to trace which code blocks are called in what order when a specific feature is executed. The logical flow, which was invisible statically, becomes clear through dynamic tracing.

  * **Unpacking a Packer**:
    Often, the executable file itself is encrypted or compressed (packed). In this case, we wait for the moment the program executes. A packed program unpacks itself in memory at runtime to restore the original code. We target that very moment, dump the cleanly unpacked code from memory, and begin our analysis.

-----

## Conclusion: A Battle of Time and Effort

Obfuscation is not an absolute barrier that prevents reverse engineering. It is merely a device to **buy time**. Good obfuscation can make analysis take a few more hours or days, but it doesn't make it "impossible."

In the end, any client-side defense is bound to be breached by a persistent attacker. Developers may find temporary relief behind the smokescreen of obfuscation, but they should not forget that we are quietly and persistently finding our way through that smoke. The truth that real security begins not on the client but on the server remains unchanged.

-----

## 코드 속의 연막: 난독화(Obfuscation)와 그것을 걷어내는 기술

개발자들은 자신의 코드가 세상의 빛을 볼 때, 그 안에 담긴 비밀—핵심 비즈니스 로직, 독점적인 알고리즘, API 키—을 지키고 싶어 한다. 그래서 그들은 코드 위에 교묘한 '연막'을 피워 올린다. 이것이 바로 **난독화(Obfuscation)**다. 난독화는 코드의 기능을 그대로 유지하면서, 사람이 읽고 이해하기는 거의 불가능하게 만드는 기술을 말한다.

하지만 우리, 즉 시스템의 내부를 들여다봐야 직성이 풀리는 해커와 리버스 엔지니어에게 난독화는 넘을 수 없는 벽이 아니라, 풀기 위해 만들어진 흥미로운 '퍼즐'에 가깝다. 이 글에서는 개발자들이 왜 이 연막을 피우는지, 어떤 종류의 연막이 있는지, 그리고 우리는 어떻게 그 연막을 걷어내고 코드의 민낯을 마주하는지 이야기해 보겠다.

-----

### 개발자들은 왜 코드를 숨기려 하는가? (난독화의 목적)

우리가 상대하는 '적'을 이해하는 것은 기본이다. 개발자가 난독화를 적용하는 이유는 명확하다.

  * **지적 재산권(IP) 보호:** 수많은 시간과 비용을 들여 개발한 독점 알고리즘이나 핵심 로직이 경쟁사나 타인에게 쉽게 복제되는 것을 막기 위함이다.
  * **보안 로직 은닉:** 루팅/탈옥 탐지, SSL Pinning, 암호화 키 처리와 같은 보안 관련 코드가 어디에 있는지 숨겨서 우회를 어렵게 만든다.
  * **불법 변경 및 크랙 방지:** 앱의 라이선스 확인 로직이나 인앱 결제 로직을 분석하기 어렵게 만들어 불법 복제나 크랙 시도를 저지하려는 목적이다.

결국, 난독화의 본질은 **분석 비용의 증가**다. 리버스 엔지니어링을 '불가능'하게 만드는 것이 아니라, '시간과 노력이 많이 들게' 만들어 공격의 가성비를 떨어뜨리는 것이 핵심 목표다.

-----

### 흔한 난독화 기법들 (연막의 종류)

공격자는 상대가 사용하는 무기를 알아야 한다. 난독화에는 여러 가지 기법이 있으며, 보통 여러 기법이 복합적으로 사용된다.

1.  **이름 난독화 (Identifier Renaming):** 가장 기본적이고 흔한 기법이다. `checkUserLicense()` 같은 의미 있는 함수나 변수 이름을 `a()`, `b`, `c1`처럼 아무 의미 없는 문자로 바꿔버린다. 코드는 여전히 동작하지만, 이름만 보고는 그 역할을 전혀 짐작할 수 없다.

2.  **문자열 암호화 (String Encryption):** 코드에 직접 노출된 중요한 문자열(API 엔드포인트, 에러 메시지, 암호화 키 등)을 암호화된 바이트 배열로 바꿔놓는다. 앱이 실행될 때 메모리에서 이 문자열을 복호화하여 사용하는 방식이다. 정적 분석만으로는 어떤 문자열이 사용되는지 알 수 없다.

3.  **제어 흐름 평탄화 (Control Flow Flattening):** 코드를 스파게티처럼 꼬아놓는 매우 효과적인 기법이다. `if-else`나 `for`문 같은 정상적인 제어 흐름을 거대한 `while` 루프와 `switch`문으로 분해해 버린다. 원래는 순차적으로 실행되던 코드가 여러 코드 블록으로 쪼개져 거대한 `switch`문 안에서 뒤죽박죽 호출된다. 코드의 실행 순서를 시각적으로 따라가는 것을 거의 불가능하게 만든다.

4.  **명령어 치환 및 더미 코드 삽입 (Instruction Substitution & Dead Code Insertion):** `a = b + c` 같은 간단한 연산을 `a = (b*2 + c*2) / 2` 처럼 의미는 같지만 훨씬 복잡한 명령어로 대체한다. 또는, 실제 실행에는 아무런 영향을 주지 않는 의미 없는 코드(더미 코드)를 중간중간에 삽입하여 분석가를 혼란에 빠뜨린다.

-----

### 장막 걷어내기: 역난독화 (De-obfuscation) 프로세스

자, 이제 퍼즐을 풀 시간이다. 난독화된 코드는 정적 분석만으로는 한계가 명확하다. 우리의 핵심 무기는 **동적 분석**이다.

#### **1단계: 정적 분석으로 구조 파악 (초벌 분석)**

먼저 **Jadx(Android)**, **IDA Pro**나 **Ghidra(iOS/Native)** 같은 도구로 코드를 열어본다. 이름이 모두 `a, b, c`로 되어있고, 의미 있는 문자열은 보이지 않으며, 함수의 흐름이 비정상적으로 복잡하다면 난독화가 적용된 것이다. 이 단계에서 우리는 공격할 '타겟'을 물색한다. 예를 들어, 유난히 복잡한 `switch`문이나 암호화된 데이터 덩어리를 찾아낸다.

#### **2단계: 동적 분석으로 민낯 드러내기 (핵심)**

코드가 실제로 '실행'될 때 그 본질이 드러난다. **Frida**와 같은 동적 분석 도구는 여기서 절대적인 힘을 발휘한다.

  * **문자열 복호화 함수 후킹:**
    가장 먼저 할 일은 암호화된 문자열을 푸는 함수를 찾는 것이다. 보통 이 함수는 바이트 배열을 인자로 받아 평문 문자열을 반환한다. 이 함수를 찾아 후킹하면, 앱이 사용하는 모든 비밀 문자열을 실시간으로 엿볼 수 있다.

    **Frida 스크립트 컨셉 예시:**

    ```javascript
    Java.perform(function() {
        // com.secret.CryptoUtil 클래스의 a 메서드가 복호화 함수라고 가정
        const CryptoUtil = Java.use("com.secret.CryptoUtil");
        
        // 메서드의 구현을 덮어쓴다.
        CryptoUtil.a.implementation = function(encrypted_bytes) {
            // 원본 메서드를 호출하여 복호화된 결과를 얻는다.
            const decrypted_string = this.a(encrypted_bytes);
            
            // 결과를 로그로 출력한다.
            console.log("String Decrypted: " + decrypted_string);
            
            // 원본 결과를 그대로 반환한다.
            return decrypted_string;
        };
    });
    ```

    이 스크립트 하나만으로도 앱의 숨겨진 URL, API 키 등이 콘솔에 줄줄이 출력될 것이다.

  * **제어 흐름 추적:**
    제어 흐름 평탄화로 코드가  spaghetti처럼 꼬여있어도 상관없다. `frida-trace`나 디버거를 사용해 특정 기능이 실행될 때 어떤 코드 블록들이 어떤 순서로 호출되는지 추적하면 된다. 정적으로는 보이지 않던 논리적 흐름이 동적 추적을 통해 선명하게 드러난다.

  * **패커(Packer) 언패킹:**
    실행 파일 자체가 암호화/압축(패킹)된 경우도 많다. 이런 경우, 우리는 프로그램이 실행되는 순간을 기다린다. 패킹된 프로그램은 실행 시점에 메모리에서 스스로 압축을 풀고 원본 코드를 복원하기 때문이다. 우리는 바로 그 시점을 노려, 메모리에서 깨끗하게 언패킹된 코드를 덤프하여 분석을 시작한다.

### 결론: 시간과 노력의 싸움

난독화는 리버스 엔지니어링을 막는 절대적인 방벽이 아니다. 그것은 단지 **시간을 벌기 위한 장치**일 뿐이다. 잘 된 난독화는 분석에 몇 시간, 며칠이 더 걸리게 할 뿐, '불가능'하게 만들지는 못한다.

결국, 끈질긴 공격자에게 클라이언트 측의 모든 방어막은 언젠가 뚫리게 마련이다. 난독화라는 연막 뒤에서 개발자들은 잠시 안도할 수 있겠지만, 우리는 그 연막 속에서 조용히, 그리고 끈질기게 길을 찾고 있다는 사실을 잊어서는 안 된다. 진짜 보안은 클라이언트가 아닌 서버에서 시작된다는 진리는 변하지 않는다.