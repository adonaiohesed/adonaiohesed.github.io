---
title: Metasploit
key: page-metasploit
categories:
- Security
- Exploitation
author: hyoeun
math: true
mathjax_autoNumber: true
bilingual: true
image: "/assets/thumbnails/2021-07-23-metasploit.png"
date: 2021-07-23 20:16:48
---

## Metasploit Framework

Metasploit is the industry-standard open-source penetration testing framework. It provides a structured environment for developing, testing, and executing exploits against target systems. Understanding its architecture is as important as knowing individual commands.

## Usage

### Workflow

The standard msfconsole workflow follows this sequence:

**msfconsole → search → use → info → show options → set → exploit → meterpreter**

When selecting an exploit module, the selection process narrows from general to specific:
- **Platform** (e.g., Windows, Linux, Android)
- **Service** (e.g., SMB, HTTP, SSH)
- **Specific exploit code** (e.g., EternalBlue, ms17-010)

### Core Commands

* `use exploit/windows/...[module path]` — Load a module. After loading, `options` (or `show options`) displays all configurable parameters.
* `search type:<type> platform:<platform>` — Search the module database. Supports filters like `name:`, `cve:`, `rank:`.
* `info` — Display detailed module information: description, references, CVE numbers, reliability ranking, and required options.
* `back` — Return to the previous context (unload the current module).
* `show options` — Display all options for the currently loaded module, indicating which are required vs. optional.
* `set <OPTION> <value>` — Set an option value. Example: `set RHOSTS 192.168.1.100`.
* `exploit` (or `run`) — Execute the loaded module with the configured options. If successful, drops into a session (often a Meterpreter session).
* Modules are stored at `/usr/share/metasploit-framework/modules/`.

### Module Directory Structure

* **auxiliary** — Modules that do not require a payload. Used for scanning, enumeration, fuzzing, and information gathering. Subcategories `scanner/` and `gather/` are most frequently used.
* **encoder** — Payload encoding algorithms designed to evade signature-based detection by transforming the payload's byte representation while preserving functionality.
* **payload** — The code executed on the target after exploitation succeeds. Three subtypes:
    * **singles** — Self-contained payloads with a single function (e.g., `adduser`, `exec`). No staging required — the entire payload is delivered in one shot.
    * **stagers** — Small, lightweight payloads responsible for establishing the channel (bind or reverse connection) and then downloading the stage payload. The split between stager and stage reduces the initial payload size, helping evade size-limited delivery vectors.
    * **stages** — The second-stage payload loaded by the stager (e.g., Meterpreter, VNC injection). Contains the full feature set. Stager + stage together are less detectable than a monolithic single payload because only the small stager is transmitted during the initial exploitation.
* **post** — Post-exploitation modules executed after a session is established. Used for privilege escalation, credential dumping, lateral movement, persistence, and pivoting.

### Script Usage

```bash
msfconsole -r script.rc
```

Resource scripts (`.rc` files) automate sequences of msfconsole commands — useful for repeatable testing or automated reporting workflows.

## Reference

* 메타스플로잇 구조, 모듈 사용법 \[Rnfwoa\]신동환 PDF

---

## 사용법

### 사용 흐름
* msfconsole -> search -> use -> info -> show options -> set -> exploit -> meterpreter
* exploit을 할 때에는 플랫폼 -> 서비스 -> 코드를 선택하는 단계로 진행한다.

### 사용 명령어
* use exploit/windows/...[모듈 위치]
    * 모듈 사용
    * 이후 option을 치면 해당하는 option이 나온다.
    * exploit를 통해 원하는 모듈을 실행시킨다.
* search type: platform: 으로 모듈들을 조사해 나간다.
* info: 모듈 세부 정보 확인
* back: 이전 모드로 돌아간다.
* show options: 모듈에 관한 옵션을 확인
* set rhost(옵션) 1.2.3.4: 옵션 값을 설정
* exploit: 설정된 정보들로 exploit 시작
* 모듈들은 /usr/share/metasploit-framework/modules에 존재한다.

### modules 폴더 정보
* auxiliary: 페이로드를 필요로 하지 않는 공격 또는 정보 수집을 목적으로 하는 코드 모음. scanner와 gather를 많이 사용.
* encoder: 안걸리기 위해 페이로드의 형태를 변형 시키는 다양한 알고리즘의 코드 모음.
* payload: 쉘코드이자 최종 공격목적코드라고 생각하면된다.
    * singles: 단 하나의 기능을 가지거나 사전 단계 없이 직접 쉘 획득에 참여하는 페이로드.
    * stagers: 공격자와 대상 시스템을 연결 후 2단계 페이로드를 불러오는 역할을 하는 페이로드. bind, reverse를 나누는 기능이 있다.
    * stages: stage 페이로드가 로드해 주는 2단계 페이로드(ex 실제 공격 코드 삽입)
    * stagers, stages는 한 묶음이다. single을 사용하는 것보다 탐지가 덜 되기 때문에 2단계로 나눠서 사용한다.
* post: exploit 성공 후 대상 시스템에 대한 추가 공격을 위한 코듬 모음.

### Script 사용법
```bash
msfconsole -r script.rc
```

## Reference

* 1.메타스플로잇 구조, 모듈 사용법 \[Rnfwoa\]신동환 PDF
