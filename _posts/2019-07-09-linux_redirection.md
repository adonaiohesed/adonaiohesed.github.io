---
title: Linux I/O Redirection and File Descriptors
key: page-linux_redirection
categories:
- Engineering
- SysOps & Infrastructure
author: hyoeun
math: false
mathjax_autoNumber: false
image: "/assets/thumbnails/2019-07-09-linux_redirection.png"
bilingual: true
date: 2019-07-09 09:00:00
---

## Understanding Linux I/O Redirection: Data Plumbing

If you've ever felt like Linux commands are "black boxes" throwing text onto your screen, you're not alone. The secret to mastering the terminal is understanding that this text isn't just "there"—it's flowing through specific pipes.

I/O Redirection is simply the art of pointing those pipes somewhere else.

### 1. The Three Outlets (Standard Streams)

Every time you run a command, Linux gives it three virtual "outlets" for data. Think of them as numbered doors:

| Door | Name | Description | 역할 |
|:---:|:---:|:---|:---|
| **0** | **stdin** | The **Input** door (usually your keyboard). | **입력**의 문 (보통 키보드) |
| **1** | **stdout** | The **Success** door (where normal results go). | **성공**의 문 (정상적인 결과물) |
| **2** | **stderr** | The **Error** door (where warning/error messages go). | **오류**의 문 (경고나 에러 메시지) |

By default, both door 1 and 2 lead straight to your screen. That's why you see both success messages and errors in the same window.

### 2. Redirecting Output: Arrows (`>` and `>>`)

The `>` symbol is like an arrow. It tells the command: "Don't send your output to the screen; send it here instead."

*   **`command > file`**: Overwrite. "Empty the bucket and put my data in."
*   **`command >> file`**: Append. "Add my data to the bottom of the bucket."

**Example:**
```bash
echo "Hello World" > greetings.txt  # Creates/Overwrites greetings.txt
echo "Hi again" >> greetings.txt    # Adds to the existing file
```

### 3. Handling Errors: The `2>` Trick

Standard redirection (`>`) only catches door 1 (Success). If a command fails, the error message from door 2 will still pop up on your screen.

To catch errors, you must use the door number:
```bash
ls /folder-that-doesnt-exist 2> errors.log
```

### 4. The "Magic" Formula: `> /dev/null 2>&1`

You will see this everywhere. It's the standard way to tell a command: "Shut up and don't show me anything."

Breaking it down:
1.  **`> /dev/null`**: Send all success messages (door 1) to a "black hole" (/dev/null).
2.  **`2>&1`**: Send door 2 (Errors) to wherever door 1 is currently going.

Since door 1 is already going to the black hole, everything disappears!

> **Bash Tip:** In modern Bash, you can just type `&> /dev/null` for the same result.

### 5. Connecting Tools: The Pipe

If `>` is an arrow pointing to a file, the pipe `|` is a connector between two commands. It takes the "Success" output of the first command and shoves it into the "Input" door of the next.

```bash
cat large_file.txt | grep "My Secret" | wc -l
# [Read File] -> [Find Text] -> [Count Lines]
```

### 6. Branching Out: `tee`

What if you want to save the output to a file AND see it on the screen at the same time? Use `tee` (named after a T-shaped pipe).

```bash
ls -la | tee list.txt
```

### Quick Reference

| Command | Meaning | 의미 |
|:---|:---|:---|
| `cmd > file` | Save success to file (clear first). | 파일에 저장 (기존 내용 삭제) |
| `cmd >> file` | Save success to file (append). | 파일 끝에 추가 (이어쓰기) |
| `cmd 2> file` | Save errors only to file. | 에러 메시지만 파일에 저장 |
| `cmd &> file` | Save everything to file. | 성공과 에러 모두 파일에 저장 |
| `cmd | other` | Pass result to the next tool. | 결과를 다음 도구로 넘기기 |
| `cmd | tee file` | Save to file AND show on screen. | 화면 출력 및 파일 저장 |

---

## 리눅스 I/O 리다이렉션: 데이터의 흐름 제어하기

리눅스 명령어가 화면에 쏟아내는 텍스트들이 어디서 오는지 궁금했던 적이 있나요? 터미널을 마스터하는 비결은 이 텍스트들이 단순한 글자가 아니라, 특정 **'통로'**를 통해 흐르는 데이터라는 점을 이해하는 것입니다.

I/O 리다이렉션(Redirection)은 쉽게 말해 "이 데이터 통로의 방향을 다른 곳으로 돌리는 기술"입니다.

### 1. 세 개의 문 (표준 스트림)

명령어가 실행될 때마다 리눅스는 데이터가 드나들 수 있는 3개의 가상 통로를 열어줍니다. 번호가 붙은 '문'이라고 생각하면 쉽습니다.

| Door | Name | Description | 역할 |
|:---:|:---:|:---|:---|
| **0** | **stdin** | The **Input** door (usually your keyboard). | **입력**의 문 (보통 키보드) |
| **1** | **stdout** | The **Success** door (where normal results go). | **성공**의 문 (정상적인 결과물) |
| **2** | **stderr** | The **Error** door (where warning/error messages go). | **오류**의 문 (경고나 에러 메시지) |

기본적으로 1번과 2번 문은 모두 '내 화면(터미널)'으로 연결되어 있습니다. 그래서 성공 메시지와 에러 메시지가 한 화면에 섞여서 보이는 것이죠.

### 2. 출력 방향 바꾸기: 화살표 (`>` 와 `>>`)

`>` 기호는 화살표와 같습니다. "출력을 화면으로 보내지 말고, 이 파일로 보내라"는 뜻입니다.

*   **`명령어 > 파일`**: 덮어쓰기. "기존 내용을 다 비우고 내 데이터를 넣어라."
*   **`명령어 >> 파일`**: 이어쓰기. "기존 내용 끝에 내 데이터를 덧붙여라."

**예시:**
```bash
echo "안녕하세요" > hello.txt  # hello.txt를 새로 만들거나 덮어씁니다.
echo "반가워요" >> hello.txt  # 기존 내용 아래에 추가합니다.
```

### 3. 에러만 골라내기: `2>`

일반적인 리다이렉션(`>`)은 1번(성공) 문만 잡아냅니다. 명령어가 실패해서 에러가 발생하면, 그 메시지는 여전히 화면에 나타납니다.

에러만 따로 저장하고 싶다면 문 번호 2를 명시해야 합니다.
```bash
ls /없는-폴더 2> error.log
```

### 4. 마법의 주문: `> /dev/null 2>&1`

리눅스에서 이 구문은 정말 자주 쓰입니다. 한마디로 "아무것도 보여주지 말고 조용히 처리해"라는 뜻입니다.

풀어보면 이렇습니다:
1.  **`> /dev/null`**: 1번(성공) 메시지를 '블랙홀(/dev/null)'로 보내서 버린다.
2.  **`2>&1`**: 2번(에러) 메시지를 1번 문이 가고 있는 곳(블랙홀)으로 같이 보낸다.

결국 성공도 에러도 모두 사라지게 됩니다.

### 5. 도구 연결하기: 파이프

`>`가 데이터를 파일로 보내는 화살표라면, 파이프 `|`는 명령어와 명령어를 연결하는 커넥터입니다. 앞 명령어의 '성공 결과'를 뒤 명령어의 '입력'으로 바로 꽂아줍니다.

```bash
cat 큰파일.txt | grep "비밀번호" | wc -l
# [파일 읽기] -> [텍스트 찾기] -> [줄 수 세기]
```

### 6. 화면도 보고 파일도 저장하고: `tee`

데이터를 파일에 저장하면서 동시에 화면으로도 확인하고 싶을 때가 있죠? 그럴 땐 T자형 파이프에서 이름을 딴 `tee`를 사용하세요.

```bash
ls -la | tee list.txt
```

### 요약표

| Command | Meaning | 의미 |
|:---|:---|:---|
| `cmd > 파일` | Save success to file (clear first). | 파일에 저장 (기존 내용 삭제) |
| `cmd >> 파일` | Save success to file (append). | 파일 끝에 추가 (이어쓰기) |
| `cmd 2> 파일` | Save errors only to file. | 에러 메시지만 파일에 저장 |
| `cmd &> 파일` | Save everything to file. | 성공과 에러 모두 파일에 저장 |
| `cmd | 다른명령어` | 결과를 다음 도구로 넘기기 |
| `cmd | tee 파일` | 화면에 보여주면서 파일로도 저장 |
