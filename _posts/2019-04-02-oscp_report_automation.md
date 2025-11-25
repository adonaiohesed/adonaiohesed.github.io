---
title: Automating OSCP Reports 
tags: Cybersecurity-Certificates OSCP
key: page-oscp_report_automation
categories: [Professional Toolkit, Certificates]
author: hyoeun
math: true
mathjax_autoNumber: true
---

# Automating OSCP and Penetration Testing Reports

In penetration testing, report writing is a process just as critical as technical discovery. Recently, writing reports in Markdown and converting them into high-quality PDFs using Pandoc and the LaTeX engine has become the standard among the Offensive Security community and practitioners.

This post covers how to build an efficient reporting environment on macOS using the [`noraj/OSCP-Exam-Report-Template-Markdown`](https://www.google.com/search?q=%5Bhttps://github.com/noraj/OSCP-Exam-Report-Template-Markdown%5D\(https://github.com/noraj/OSCP-Exam-Report-Template-Markdown\)) project. This tool is based on the Eisvogel Pandoc template and provides a professional layout applicable not only to OSCP exam requirements but also to general penetration testing reports.

## Prerequisites and Environment Setup (macOS)

This workflow relies on Pandoc and the LaTeX engine to convert Markdown source into PDF. Specifically, certain TeX packages are required to render the sophisticated design of the Eisvogel template.

### Step 1: Install Basic Conversion Tools

Install Pandoc (the document converter) and p7zip (for archive creation) via the Homebrew package manager.

```bash
brew install pandoc p7zip
```

### Step 2: Install TeX Distribution

Install MacTeX, the PDF engine used by Pandoc to generate PDFs. Since the file size is large, installation may take some time.

```bash
brew install --cask mactex
```

Once installation is complete, restart your terminal session or run the command below to load the `tlmgr` (TeX Live Manager) path into your system environment variables.

```bash
eval "$(/usr/libexec/path_helper)"
```

### Step 3: Resolve TeX Live Package Dependencies

The Eisvogel template uses specific packages that are not included in the standard LaTeX installation. If this step is skipped, font or style definition errors will occur during rendering. Install the required packages using the command below.

```bash
sudo tlmgr update --self
sudo tlmgr install collection-fontsrecommended collection-latexrecommended \
  adjustbox babel-german background bidi collectbox csquotes everypage \
  filehook footmisc footnotebackref framed fvextra letltxmacro ly1 \
  mdframed mweights needspace pagecolor sourcecodepro sourcesanspro \
  titling ucharcat uucharclasses xecjk xurl zref
```

### Step 4: Configure Eisvogel Template

Configure the design template that Pandoc will reference during the conversion process.

1.  **Create Directory**: Create the default template path for Pandoc.

    ```bash
    mkdir -p ~/.pandoc/templates
    ```

2.  **Install Template**: Download the latest version from the [Eisvogel Release Page](https://github.com/Wandmalfarbe/pandoc-latex-template/releases). Unzip it and move the `eisvogel.latex` file to the `~/.pandoc/templates` path created earlier. Additionally, saving files like `eisvogel.beamer` in the same location will prepare you for future presentation generation.

## Report Writing Workflow

Once the environment setup is complete, you can manage the report lifecycle using `noraj`'s Ruby script (`osert.rb`). This script abstracts complex Pandoc arguments to improve usability.

### Project Initialization

First, bring the template project into your local environment. Clone the repository using Git and move into the project directory.

```bash
# 1. Clone GitHub Repository
git clone https://github.com/noraj/OSCP-Exam-Report-Template-Markdown.git

# 2. Move to Project Directory
cd OSCP-Exam-Report-Template-Markdown
```

Next, create a workspace to manage your report. If you create a separate subdirectory (e.g., `report`) instead of using the project root, be aware that the relative path to the `osert.rb` script will change.

```bash
# Create and move to report directory
mkdir report

# Call osert.rb located in the current directory to initialize
ruby ./osert.rb init -o ./report
```

Running the command above creates a default Markdown template file containing OSCP-style tables of contents and sections in the current directory. Rename the generated file to fit your project context.

```bash
mv ./report/OSCP-exam-report-template_whoisflynn_v3.2.md ./report/hyoeun-report.md
```

### Content Writing

Open the Markdown file to document your penetration testing results. This template uses YAML Frontmatter to manage report metadata (Title, Author, Date, etc.).

#### Tips for Inserting Images

The most cumbersome part of report writing—inserting screenshots—is most efficiently handled by utilizing a tool called **Obsidian**. Using Obsidian allows you to automatically save images to a designated path simply by pasting (`Cmd+V`). Beyond just images, using Obsidian for overall document writing significantly boosts productivity.

If you are not using Obsidian and need to insert images manually, use standard Markdown syntax as shown below. Relative paths are recommended.

```markdown
![Admin Privilege Proof](../src/img/admin_proof.png)
```

#### Text Highlighting and Colors (LaTeX)

When you want to highlight important vulnerability ratings or keywords, standard Markdown syntax has limitations in color expression. In this case, using Pandoc's Raw Attribute feature to directly use LaTeX commands allows for clean color application upon PDF conversion. (Note: This does not apply in Obsidian preview but renders correctly in the PDF output.)

```markdown
# Usage Example
The risk level of the discovered vulnerability is `\textcolor{red}{\textbf{CRITICAL}}`{=latex}.
This service poses a `\textcolor{orange}{\textbf{HIGH}}`{=latex} level threat.
```

#### Code Blocks and Syntax Highlighting

When attaching exploit code or vulnerable source code, you must specify the language identifier (e.g., `python`, `bash`) after the triple backticks (\`\`\`). This ensures high-readability syntax highlighting in the generated PDF.

For example, using the `python` identifier as shown below will result in color-coded keywords in the report. (Please ignore the backslashes in the example below).

````
\```python
@app.route("/<test>")  # Vulnerability: Accepts any path input
def catch_all(test: str):
    """
    test code
    """
    return test(test)
\```
````

### Report Generation and Packaging

When writing is complete, perform PDF conversion and archive creation using the `generate` command. During this process, the script will prompt for options (such as password protection) via an interactive prompt.

```bash
ruby ./osert.rb generate -i ./report/hyoeun-report.md -o ./report
```

Upon successful execution, a professionally formatted PDF report and a 7z submission archive are created in the specified output directory (`./output`). This saves time spent on manual formatting, allowing you to focus more on technical analysis and vulnerability verification.

## Maximizing Productivity with Obsidian and noraj/OSCP-Exam-Report-Template-Markdown

Many successful candidates use **Obsidian** as their text editor to shorten report writing time. Obsidian facilitates easy screenshot capture, immediate documentation, and management. Follow the settings below to use `noraj\OSCP-Exam-Report-Template-Markdown` more comfortably.

### 1. Obsidian Vault Setup

Open the Noraj template folder (or project folder) itself as an Obsidian **Vault**. This allows image management via the file explorer and Markdown editing to happen within a single window.

### 2. Essential Compatibility Settings

Some of Obsidian's convenience features conflict with the Pandoc engine. You must change the following two settings in `Settings > Files & Links`.

1.  **Use WikiLinks: `OFF`**
      * Pandoc does not recognize Obsidian's default `[[image.png]]` format. Turning this off ensures images are inserted in the standard Markdown format `![](image.png)`.
2.  **Default location for new attachments: Specify `src/img` folder**
      * This prevents the report root path from becoming cluttered when pasting screenshots and automatically isolates images into `src/img` to match the Noraj template structure.
3.  **Utilize Table of Contents (TOC)**
      * Click the Outline icon in the right sidebar of Obsidian. You will see the `#`, `##` header structure of the document currently being written. This corresponds to the TOC in the final PDF. Clicking items allows you to jump directly to that location, making it easier to manage long reports.
      * ![Obsidian TOC](/assets/images/obsidian_toc.png)

### 3. Efficient Screenshot Workflow

In the Mac environment, you can reduce the 'Capture-Save-Insert' process to under a second using the following shortcut combination.

  * **Capture**: `Shift` + `Cmd` + `Ctrl` + `4` (Copies selected area to clipboard)
  * **Insert**: `Cmd` + `V` inside the Obsidian editor
  * **Result**: The image is automatically saved to the `src/img` folder, and a standard Markdown link is generated in the editor.

### 4. Obsidian Image Path Configuration and the Context of `osert.rb` Execution

The most frequent error encountered during the report generation process is "Image not found." This occurs because the image paths managed by Obsidian do not match the paths where Pandoc looks for files. To resolve this, you must modify Obsidian settings and clearly understand the script execution location relative to those settings.

#### Setting Absolute Paths in Obsidian

By default, Obsidian links images using relative paths based on the current document (e.g., `../img/image.png`). However, if your workflow involves running the `osert.rb` script from a parent directory of the project, you may need the full path relative to the Vault root.

1.  **Access Settings**: Go to `Settings > Files & Links`.
2.  **Change Link Format**: Find the `New link format` option and change the default "Relative path to file" to **"Absolute path in vault"**.

Applying this setting ensures that when you paste an image, a path starting from the top-level folder is automatically inserted (e.g., `project_name/img/screenshot.png`) instead of just `img/screenshot.png`.

#### The Core of Path Configuration: Script Execution Context

The "Absolute path" setting mentioned above is not a universal solution. The most important principle is that **"the image path string within the Markdown document must be valid from the perspective of the terminal's current working directory where the `osert.rb` command is executed."**

Pandoc resolves relative addresses based on the current terminal path when searching for images. Therefore, you must configure your settings flexibly according to your specific work style.

* **Case A: Running from the Project's Parent Directory (Recommended)**
    * **Terminal Location**: `/Start/` (containing the `Project_A/` folder)
    * **Execution Command**: `ruby osert.rb generate -i ./Project_A/report.md ...`
    * **Required MD Image Path**: `Project_A/img/screenshot.png`
    * **Conclusion**: In this case, Obsidian's **"Absolute path in vault"** setting is valid.

* **Case B: Running from Inside the Project Directory**
    * **Terminal Location**: `/Start/Project_A/`
    * **Execution Command**: `ruby ../osert.rb generate -i ./report.md ...`
    * **Required MD Image Path**: `img/screenshot.png`
    * **Conclusion**: In this case, Obsidian's **"Relative path to file"** or **"Shortest path possible"** setting is appropriate. If you use the absolute path (`Project_A/img/...`) here, Pandoc will attempt to locate `/Start/Project_A/Project_A/img/...`, resulting in an error.

In short, rather than blindly following a specific setting, you must establish a path strategy based on **where you invoke `osert.rb`**. Before you begin writing the full report, ensure you insert a test image and generate a PDF to verify that path recognition is functioning correctly.

---

# OSCP 및 모의해킹 리포트 자동화

모의해킹(Penetration Testing) 업무에서 리포트 작성은 기술적 발견만큼이나 중요한 과정입니다. 최근 Offensive Security 커뮤니티와 실무자들 사이에서는 Markdown으로 리포트를 작성하고, Pandoc과 LaTeX 엔진을 이용해 고품질의 PDF로 변환하는 방식이 표준으로 자리 잡고 있습니다.

이 글에서는 [`noraj/OSCP-Exam-Report-Template-Markdown`](https://github.com/noraj/OSCP-Exam-Report-Template-Markdown) 프로젝트를 활용하여 Mac OS 환경에서 효율적인 리포팅 환경을 구축하는 방법을 다룹니다. 이 도구는 Eisvogel Pandoc 템플릿을 기반으로 하며, OSCP 시험 요구사항뿐만 아니라 일반적인 모의해킹 리포트에도 적용 가능한 전문적인 레이아웃을 제공합니다.

## 전제 조건 및 환경 설정 (Mac OS)

이 워크플로우는 Markdown 소스를 PDF로 변환하기 위해 Pandoc과 LaTeX 엔진에 의존합니다. 특히 Eisvogel 템플릿의 세련된 디자인을 렌더링하기 위해서는 특정 TeX 패키지들이 필수적으로 요구됩니다.

### 1단계: 기본 변환 도구 설치

Homebrew 패키지 관리자를 통해 문서 변환 도구인 Pandoc과 아카이브 생성을 위한 p7zip을 설치합니다.

```bash
brew install pandoc p7zip
```

### 2단계: TeX 배포판 설치

Pandoc이 PDF를 생성할 때 사용하는 PDF 엔진인 MacTeX를 설치합니다. 용량이 크므로 설치에 시간이 소요될 수 있습니다.

```bash
brew install --cask mactex
```

설치가 완료되면 터미널 세션을 재시작하거나 아래 명령어를 실행하여 `tlmgr`(TeX Live Manager) 경로를 시스템 환경변수에 로드해야 합니다.

```bash
eval "$(/usr/libexec/path_helper)"
```

### 3단계: TeX Live 패키지 종속성 해결

Eisvogel 템플릿은 표준 LaTeX 설치에 포함되지 않은 특정 패키지들을 사용합니다. 이 단계가 누락될 경우 렌더링 과정에서 폰트 누락이나 스타일 정의 오류가 발생합니다. 아래 명령어를 통해 필수 패키지들을 설치합니다.

```bash
sudo tlmgr update --self
sudo tlmgr install collection-fontsrecommended collection-latexrecommended \
  adjustbox babel-german background bidi collectbox csquotes everypage \
  filehook footmisc footnotebackref framed fvextra letltxmacro ly1 \
  mdframed mweights needspace pagecolor sourcecodepro sourcesanspro \
  titling ucharcat uucharclasses xecjk xurl zref
```

### 4단계: Eisvogel 템플릿 구성

Pandoc이 변환 과정에서 참조할 디자인 템플릿을 설정합니다.

1.  **디렉토리 생성**: Pandoc의 기본 템플릿 경로를 생성합니다.

    ```bash
    mkdir -p ~/.pandoc/templates
    ```

2.  **템플릿 설치**: [Eisvogel 릴리스 페이지](https://github.com/Wandmalfarbe/pandoc-latex-template/releases)에서 최신 버전을 다운로드합니다. 압축을 해제한 후 `eisvogel.latex` 파일을 앞서 생성한 `~/.pandoc/templates` 경로로 이동시킵니다. 추가적으로 `eisvogel.beamer` 등의 파일도 동일한 위치에 저장하여 향후 프레젠테이션 생성에 대비할 수 있습니다.

## 리포트 작성 워크플로우

환경 설정이 완료되면 `noraj`의 Ruby 스크립트(`osert.rb`)를 사용하여 리포트의 생명주기를 관리할 수 있습니다. 이 스크립트는 복잡한 Pandoc 인자(arguments)를 추상화하여 사용 편의성을 높입니다.

### 프로젝트 초기화

먼저 템플릿 프로젝트를 로컬 환경으로 가져와야 합니다. Git을 이용해 저장소를 클론하고, 프로젝트 디렉토리로 이동합니다.

```bash
# 1. 깃허브 저장소 클론
git clone https://github.com/noraj/OSCP-Exam-Report-Template-Markdown.git

# 2. 프로젝트 디렉토리로 이동
cd OSCP-Exam-Report-Template-Markdown
```

그다음 리포트를 관리할 작업 공간을 생성합니다. 만약 프로젝트 루트가 아닌 별도의 하위 디렉토리(예: `report`)를 만들어 관리할 경우, `osert.rb` 스크립트의 상대 경로가 변경된다는 점에 주의해야 합니다.

```bash
# 리포트용 디렉토리 생성 및 이동
mkdir report

# 현재 디렉토리에 있는 osert.rb를 호출하여 초기화
ruby ./osert.rb init -o ./report
```

위 명령을 실행하면 현재 디렉토리에 OSCP 스타일의 목차와 섹션이 포함된 기본 Markdown 템플릿 파일이 생성됩니다. 생성된 파일명은 프로젝트 컨텍스트에 맞게 변경하여 사용합니다.

```bash
mv ./report/OSCP-exam-report-template_whoisflynn_v3.2.md ./report/hyoeun-report.md
```

### 콘텐츠 작성

Markdown 파일을 열어 모의해킹 결과를 작성합니다. 이 템플릿은 YAML Frontmatter를 사용하여 리포트의 메타데이터(제목, 작성자, 날짜 등)를 관리합니다.

#### 이미지 삽입 팁
리포트 작성 시 가장 번거로운 스크린샷 삽입 작업은 **Obsidian**이라는 다른 툴을 활용하는 것이 가장 효율적입니다. Obsidian을 사용하면 붙여넣기(`Cmd+V`)만으로 이미지가 지정된 경로에 자동 저장됩니다. 이미지 뿐만 아니라 전반적인 문서 작성 역시 Obsidian을 활용하는 것이 생산성에 도움이 됩니다.

만약 Obsidian을 사용하지 않고 수작업으로 이미지를 넣어야 한다면, 표준 Markdown 문법을 사용하여 아래와 같이 작성합니다. 경로는 상대 경로를 권장합니다.

```markdown
![관리자 권한 획득 증적](../src/img/admin_proof.png)
```

#### 텍스트 강조 및 색상 (LaTeX)
중요한 취약점 등급이나 키워드를 강조하고 싶을 때, Markdown 기본 문법으로는 색상 표현에 한계가 있습니다. 이 경우 Pandoc의 Raw Attribute 기능을 이용하여 LaTeX 명령어를 직접 사용하면 PDF 변환 시 깔끔한 색상을 입힐 수 있습니다. (Obsidian 미리보기에서는 적용되지 않으나 PDF 결과물에는 정상 반영됩니다.)

```markdown
# 사용 예시
발견된 취약점의 위험도는 `\textcolor{red}{\textbf{CRITICAL}}`{=latex} 입니다.
이 서비스는 `\textcolor{orange}{\textbf{HIGH}}`{=latex} 수준의 위협이 있습니다.
```

#### 코드 블록 및 구문 강조 (Syntax Highlighting)
익스플로잇 코드나 취약한 소스 코드를 첨부할 때는 백틱 3개(\`\`\`) 뒤에 언어 식별자(예: `python`, `bash`)를 반드시 명시해야 합니다. 이를 통해 PDF 생성 시 가독성 높은 구문 강조 효과를 얻을 수 있습니다.

예를 들어, `python` 식별자를 사용하여 아래와 같이 작성하면 리포트에서 키워드 색상이 구분되어 출력됩니다. 아래의 \는 무시하셔야합니다.

```
\```python
@app.route("/<test>")  # Vulnerability: Accepts any path input
def catch_all(test: str):
    """
    test code
    """
    return test(test)
\```
```

### 리포트 생성 및 패키징

작성이 완료되면 `generate` 명령을 통해 PDF 변환 및 아카이브 생성을 수행합니다. 이 과정에서 스크립트는 대화형 프롬프트를 통해 선택 옵션(비밀번호 보호 여부 등)을 확인합니다.

```bash
ruby ./osert.rb generate -i ./report/hyoeun-report.md -o ./report
```

이 명령이 성공적으로 실행되면 지정된 출력 디렉토리(`./output`)에 전문적인 서식이 적용된 PDF 리포트와 제출용 7z 아카이브가 생성됩니다. 이를 통해 수동 포매팅에 소요되는 시간을 절약하고, 기술적 분석과 취약점 검증에 더 집중할 수 있습니다.

## Obsidian을 활용한 noraj\OSCP-Exam-Report-Template-Markdown 생산성 극대화

리포트 작성 시간을 단축하기 위해 많은 합격자들이 텍스트 에디터로 **Obsidian**을 사용합니다. Obsidian을 기반으로 스크린샷을 쉽게 찍어 바로 문서화 작업을 하고 관리에 용이하게 합니다. 아래의 설정을 따르면 `noraj\OSCP-Exam-Report-Template-Markdown`를 더 편하게 사용할 수 있습니다.

### 1. Obsidian Vault 설정

Noraj 템플릿 폴더(혹은 프로젝트 폴더) 자체를 Obsidian의 **Vault(보관함)**로 지정하여 엽니다. 이렇게 하면 파일 탐색기에서 이미지를 관리하고 마크다운을 편집하는 과정이 하나의 창에서 이루어집니다.

### 2. 필수 호환성 설정

Obsidian의 편의 기능 중 일부는 Pandoc 엔진과 충돌을 일으킵니다. `설정(Settings) > 파일 및 링크(Files & Links)`에서 다음 두 가지를 반드시 변경해야 합니다.

1.  **위키 링크 사용 (Use WikiLinks) : `OFF`**
      * Obsidian 기본값인 `[[image.png]]` 형태는 Pandoc이 인식하지 못합니다. 이 옵션을 꺼야 표준 Markdown 형식인 `![](image.png)`로 이미지가 삽입됩니다.
2.  **새 첨부 파일 위치 (Default location for new attachments) : `src/img` 폴더로 지정**
      * 스크린샷을 붙여넣을 때 리포트 루트 경로가 지저분해지는 것을 막고, Noraj 템플릿 구조에 맞게 이미지를 `src/img` 하위로 자동 격리합니다.
3. **목차(TOC) 활용**
      * Obsidian 오른쪽 사이드바의 Outline(개요) 아이콘을 누르세요. 현재 작성 중인 문서의 #, ## 헤더 구조가 보입니다. 이것이 곧 나중에 PDF의 목차(TOC)가 됩니다. 클릭하면 해당 위치로 바로 점프할 수 있어 긴 리포트를 관리하기 쉽습니다.
      * ![Obsidian TOC](/assets/images/obsidian_toc.png)

### 3. 효율적인 스크린샷 워크플로우

Mac 환경에서는 다음 단축키 조합을 통해 '캡처-저장-삽입' 과정을 1초 내로 줄일 수 있습니다.

  * **캡처**: `Shift` + `Cmd` + `Ctrl` + `4` (지정 영역을 클립보드로 복사)
  * **삽입**: Obsidian 에디터 내에서 `Cmd` + `V`
  * **결과**: 이미지가 자동으로 `src/img` 폴더에 저장되며, 에디터에는 표준 마크다운 링크가 생성됩니다.

### 4. Obsidian 이미지 경로 설정과 `osert.rb` 실행 위치의 상관관계

리포트 생성 과정에서 가장 빈번하게 발생하는 오류는 "Image not found"입니다. 이는 Obsidian이 관리하는 이미지 경로와 Pandoc이 파일을 찾는 경로가 일치하지 않기 때문에 발생합니다. 이를 해결하기 위해 Obsidian 설정을 변경하고, 이에 따른 스크립트 실행 위치를 명확히 이해해야 합니다.

#### Obsidian 절대 경로 설정

기본적으로 Obsidian은 이미지를 현재 문서 기준의 상대 경로(`../img/image.png`)로 링크합니다. 하지만 `osert.rb` 스크립트를 프로젝트 상위 폴더에서 실행하는 구조라면, 볼트(Vault) 루트 기준의 전체 경로가 필요할 수 있습니다.

1.  **설정 메뉴 진입**: `설정(Settings) > 파일 및 링크(Files & Links)`로 이동합니다.
2.  **링크 형식 변경**: `새 링크 형식(New link format)` 옵션을 찾아 기본값인 '파일에 대한 상대 경로(Relative path to file)'를 **'볼트 내 절대 경로(Absolute path in vault)'**로 변경합니다.

이 설정을 적용하면 이미지를 붙여넣을 때 `img/screenshot.png`가 아닌, `project_name/img/screenshot.png`와 같이 최상위 폴더명부터 시작하는 경로가 자동으로 삽입됩니다.

#### 경로 설정의 핵심: 스크립트 실행 위치(Context)

위의 '절대 경로' 설정이 만능은 아닙니다. 가장 중요한 원칙은 **"Markdown 문서 내의 이미지 경로 문자열이, `osert.rb` 명령어를 실행하는 터미널의 현재 위치(Working Directory)에서 유효해야 한다"**는 점입니다.

Pandoc은 이미지를 찾을 때 현재 터미널의 경로를 기준으로 상대 주소를 탐색합니다. 따라서 본인의 작업 스타일에 맞춰 설정을 유동적으로 가져가야 합니다.

* **Case A: 프로젝트 상위 폴더에서 실행하는 경우 (권장)**
    * **터미널 위치**: `/Start/` (이 안에 `Project_A/` 폴더가 있음)
    * **실행 명령어**: `ruby osert.rb generate -i ./Project_A/report.md ...`
    * **필요한 MD 이미지 경로**: `Project_A/img/screenshot.png`
    * **결론**: 이 경우 Obsidian의 **'볼트 내 절대 경로'** 설정이 유효합니다.

* **Case B: 프로젝트 폴더 내부에서 실행하는 경우**
    * **터미널 위치**: `/Start/Project_A/`
    * **실행 명령어**: `ruby ../osert.rb generate -i ./report.md ...`
    * **필요한 MD 이미지 경로**: `img/screenshot.png`
    * **결론**: 이 경우 Obsidian의 **'파일에 대한 상대 경로'** 또는 **'가능한 가장 짧은 경로'** 설정이 적합합니다. 만약 여기서 절대 경로(`Project_A/img/...`)를 쓰면, Pandoc은 `/Start/Project_A/Project_A/img/...`를 찾게 되어 오류가 발생합니다.

즉, 무조건 특정 설정을 따르기보다 **자신이 `osert.rb`를 어디서 호출하는지**를 기준으로 경로 전략을 수립해야 합니다. 리포트 작성을 시작하기 전에 테스트용 이미지를 하나 넣고 PDF를 생성해 보며 경로 인식이 올바른지 확인하는 과정을 반드시 거치시기 바랍니다.
