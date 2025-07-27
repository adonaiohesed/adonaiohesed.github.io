---
title: Frida Install And Trouble Shooting
tags: Frida
key: page-frida_install
categories: [Tools, Penetration Testing]
author: hyoeun
math: true
mathjax_autoNumber: true
---

## 테스트 MacOS 환경에서 Frida 설치

Frida를 사용할 때는 **가상 환경에서 작업하는 것을 권장**합니다. 이렇게 하면 시스템 전체의 파이썬 환경과 충돌 없이 필요한 라이브러리들을 효율적으로 관리할 수 있습니다.

### 1\. Conda 초기화 설정 (Zsh 쉘)

`conda`를 zsh 쉘에서 사용하기 위해, `~/.zshrc` 파일에 다음 내용을 추가해야 합니다. 이 설정은 `conda` 명령어가 올바르게 작동하도록 돕습니다. `<YOUR_CONDA_PATH>`는 Anaconda 또는 Miniconda가 설치된 경로로 변경해야 합니다. 일반적으로 `/Users/YOUR_USERNAME/anaconda3/bin/conda`와 같을 수 있습니다.

```bash
# ~/.zshrc 파일에 추가:
# >>> conda initialize >>>
# !! Contents within this block are managed by 'conda init' !!
__conda_setup="$('/Users/YOUR_USERNAME/anaconda3/bin/conda' 'shell.zsh' 'hook' 2> /dev/null)"
if [ $? -eq 0 ]; then
    eval "$__conda_setup"
else
    if [ -f "/Users/YOUR_USERNAME/anaconda3/etc/profile.d/conda.sh" ]; then
        . "/Users/YOUR_USERNAME/anaconda3/etc/profile.d/conda.sh"
    else
        export PATH="/Users/YOUR_USERNAME/anaconda3/bin:$PATH"
    fi
fi
unset __conda_setup
# <<< conda initialize <<<
```

### 2\. 설정 적용

`~/.zshrc` 파일을 수정한 후에는 변경 사항을 적용하기 위해 터미널을 다시 시작하거나 다음 명령어를 실행합니다.

```bash
source ~/.zshrc
```

### 3\. Frida 가상 환경 생성 및 활성화

이제 `conda` 명령어를 사용하여 Frida를 위한 새로운 가상 환경을 생성하고 활성화할 수 있습니다. `frida_env`라는 이름으로 `python=3.12` 버전을 사용하는 환경을 만듭니다.

```bash
conda create -n frida_env python=3.12
conda activate frida_env
```

### 4\. Frida 설치

Frida 작업을 마쳤거나 다른 환경으로 전환하고 싶을 때는 다음 명령어로 현재 활성화된 가상 환경에서 벗어날 수 있습니다.

```bash
# 버전은 모바일에 돌아가는 frida와 같은 버전이어야합니다.
pip install frida==17.2.6
```

### 5\. 가상 환경 비활성화

Frida 작업을 마쳤거나 다른 환경으로 전환하고 싶을 때는 다음 명령어로 현재 활성화된 가상 환경에서 벗어날 수 있습니다.

```bash
conda deactivate
```

Frida Server를 설치할 때 휴대폰의 CPU 아키텍처(ARM, ARM64, x86 등)를 확인하는 것은 매우 중요합니다. Frida Server는 기기의 아키텍처에 맞는 바이너리를 사용해야 제대로 작동합니다.

-----

## 테스트 모바일 환경에 Frida Server 설치 (루팅된 장치용)

모바일 애플리케이션 침투 테스트(모의 해킹) 시, 특히 **디버깅이 허용되지 않은 상용 앱이나 시스템 수준의 취약점을 분석할 때는 루팅된 장치에서 Frida Server를 실행하는 것이 필수적입니다.** 이는 실제 공격자가 활용하는 접근 방식이며, 앱의 보안 취약점을 가장 심층적으로 파악할 수 있게 해줍니다.

### 1\. ADB Shell 명령어를 통해 모바일 아키텍처 확인

먼저 모바일 장치의 CPU 아키텍처를 정확히 파악해야 합니다. 이에 맞는 Frida Server 바이너리를 다운로드해야 하니까요.

  * **컴퓨터에 ADB가 설치되어 있는지 확인하세요.** 설치되어 있지 않다면 Android SDK Platform-Tools를 다운로드하여 설치해야 합니다.

  * **휴대폰에서 USB 디버깅을 활성화합니다.** 일반적으로 `설정 > 휴대전화 정보 > 빌드 번호`를 여러 번 탭하여 개발자 옵션을 활성화한 다음, 개발자 옵션에서 USB 디버깅을 켤 수 있습니다.

  * **USB 케이블을 사용하여 휴대폰을 컴퓨터에 연결하세요.**

  * **터미널(또는 명령 프롬프트)을 열고 다음 명령어 중 하나를 입력합니다.**

    ```bash
    adb shell getprop ro.product.cpu.abi
    ```

    또는

    ```bash
    adb shell getprop ro.product.cpu.abilist
    ```

    또는

    ```bash
    adb shell uname -m
    ```

  * **결과 해석:**

      * `arm64-v8a` 또는 `aarch64`가 나오면 **ARM64** 아키텍처입니다. (64비트 ARM)
      * `armeabi-v7a` 또는 `armv7l`이 나오면 **ARM** 아키텍처입니다. (32비트 ARM)
      * `x86_64`가 나오면 **x86\_64** 아키텍처입니다. (64비트 x86)
      * `x86` 또는 `i686`이 나오면 **x86** 아키텍처입니다. (32비트 x86)

### 2\. Frida Server 파일 다운로드

CPU 아키텍처를 확인했다면, 이제 Frida Server 바이너리를 다운로드할 차례입니다.

  * **[Frida GitHub Releases 페이지](https://github.com/frida/frida/releases)** 로 이동합니다.
  * 확인한 아키텍처에 맞는 `frida-server` 바이너리를 다운로드하세요. 예를 들어, 기기가 ARM64라면 `frida-server-*-android-arm64.xz` 파일을 다운로드해야 합니다.
  * **로컬에 설치된 Frida 버전과 서버 버전의 주요 버전 번호가 일치하는지 확인하는 것이 중요합니다.** 버전이 다르면 문제가 발생할 수 있습니다.

### 3\. 모바일에 다운로드한 Frida Server 파일 전송 및 실행

다운로드한 Frida Server 파일을 모바일 장치의 `/data/local/tmp` 디렉터리로 전송하고, **루트 권한으로 실행**합니다.

1.  **다운로드한 `frida-server-*.xz` 파일을 압축 해제합니다.** `.xz` 파일은 `tar -xvf` 명령어나 7-Zip 같은 압축 해제 도구를 사용하여 압축을 풀 수 있습니다. 압축을 풀면 `frida-server`라는 실행 파일이 나옵니다.

    ```bash
    # 터미널에서 다운로드한 파일이 있는 디렉터리로 이동 후
    tar -xvf frida-server-*-android-arm64.xz # 예시: frida-server-17.2.6-android-arm64.xz
    ```

2.  **압축 해제된 `frida-server` 파일을 모바일 장치로 푸시합니다.** `/data/local/tmp`는 일반 사용자도 쓰기 권한이 있는 임시 디렉토리이므로, `su` 없이도 푸시할 수 있습니다.

    ```bash
    adb push frida-server /data/local/tmp/
    ```

3.  **파일 실행 권한을 부여합니다.** 모바일 장치에 푸시된 `frida-server` 파일이 실행될 수 있도록 권한을 설정해야 합니다.

    ```bash
    adb shell "chmod +x /data/local/tmp/frida-server"
    ```

4.  **Frida Server를 루트 권한으로 실행합니다.** `su -c`를 사용하여 Frida Server를 루트 권한으로 실행합니다.

    ```bash
    adb shell "su -c 'cd /data/local/tmp && ./frida-server &'"
    ```


이제 Frida Server가 루팅된 모바일 장치에서 루트 권한으로 실행 중이며, 컴퓨터에서 Frida 툴을 사용하여 앱의 심층적인 분석 및 조작을 수행할 수 있습니다.