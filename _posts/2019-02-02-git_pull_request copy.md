---
title: Git Pull Request
tags: Git Collaborate
key: page-git_pull_request
categories: [Development, DevOps & Automation]
author: hyoeun
---

# [GitHub] The Cheat Sheet for Better Collaboration: Understanding Pull Requests and Setting Up Templates

## 1\. What is a Pull Request (PR)?

A Pull Request is literally **"a request to pull my code."**

When using a Git hosting service like **GitHub** (or GitLab, Bitbucket), a PR is a formal feature request to merge the content of the **auxiliary branch** you worked on into the **main branch**.

### The Core Role of a PR

A PR is more than just a 'merge request'; it is the central discussion forum and safety net for team collaboration.

1.  **Starting Point for Code Review:** It is the space where team members inspect the code (Code Review) and exchange feedback before the merge.
2.  **Recording Change History:** It leaves a clear history of why this code was changed and the context in which the work began.
3.  **CI/CD Automation Trigger:** Automated tests are executed upon PR creation to prevent problematic code from being merged in advance.

## 2\. PR Creation Workflow (How-To)

Here is the process of creating a PR, using the `feature` branch work discussed in a previous article as an example.

1.  **Local Work and Push:** Complete your work on the `feature/new-api` branch (which was forked from `develop`) and push it to the remote repository.

    ```bash
    git push origin feature/new-api
    ```

2.  **Start PR Creation on GitHub:**

      * Navigate to your GitHub repository page.
      * Click the **"Compare & pull request"** button that appears (detecting your recent push) or go to the `Pull Requests` tab.

3.  **Set the Base Branch (Crucial):**

      * Define the merge target for the PR. (Specifying where the PR will be merged)
      * **Base (Target Branch):** `develop` (our development branch)
      * **Compare (Your Work Branch):** `feature/new-api`

4.  **Write the Title and Description:**

      * **Title:** Write according to the **Conventional Commit** rules defined earlier. (e.g., `feat: Implement user information lookup API`)
      * **Description:** This is where the **PR template** will be automatically populated.

5.  **Assign Reviewer and Create:**

      * Assign the reviewer(s) (your teammates) and create the PR.

## 3\. The Necessity of Adopting a PR Template

While the PR feature is excellent, it loses its value if the author doesn't put effort into the description. A PR template is the solution to this problem.

1.  **Provides Writing Guidelines:** It reduces the time a PR author spends pondering what to write.
2.  **Reduces Communication Costs:** It prevents repetitive questions like, "Did you test this?" or "What's the related ticket number?"
3.  **Improves Review Quality:** Including screenshots or testing methods allows reviewers to quickly understand the changes and focus on reviewing the core logic.
4.  **Enforces a Checklist:** It helps ensure essential pre-deployment checks (testing performed, linting checked, etc.) are not missed.

## 4\. How to Set Up a PR Template (Step-by-Step)

To set up a template, simply add a Markdown file to an agreed-upon path in the project's root directory.

### Basic Setup

1.  Create a folder named `.github` in the project's root (top-level) directory.
2.  Create a file named `pull_request_template.md` inside that folder.

**Path Example:**

```text
my-project/
├── .github/
│   └── pull_request_template.md  <-- Here!
├── src/
├── README.md
└── ...
```

### Best Practice Template Ready to Use

You can paste this content into your `pull_request_template.md` file.

```markdown
## 1. Overview
- **Related Issue:** (e.g., #123, [JIRA-456])
- **Changes:** (Summarize the core changes made in this PR.)

## 2. Detailed Work Description
- (Write concrete work details as a list.)
- (e.g., Improved the error handling logic for the login API.)
- (e.g., Removed unnecessary console logs.)

## 3. Screenshots (Mandatory for UI Changes)
| Before | After |
| :---: | :---: |
| <img src="" width="300" /> | <img src="" width="300" /> |

## 4. Checklist
- [ ] Does the build complete successfully without errors?
- [ ] Have test codes been written and passed?
- [ ] Have unnecessary comments or code been removed?
- [ ] Is the commit message written according to the convention (Conventional Commits)?

## 5. Review Requests
- (Please specify any particular logic or questions you'd like the reviewer to focus on.)
```

## 5\. Explanation of Key Template Components

Here's why the template above is structured this way.

### A. Related Issues

Link Jira tickets or GitHub Issue numbers here. This is the most important clue for tracking the history—"Why was this feature built?"—when looking at the code later.

### B. Screenshots

Unnecessary if only back-end logic was modified, but **mandatory** for front-end or mobile work. One screenshot (or GIF) is much faster for understanding changes than reading 100 lines of code.

### C. Checklist

Using the `[ ]` syntax renders as clickable checkboxes in the GitHub interface.

  * Whether local testing was performed
  * Whether Lint/Format checks were done
  * Whether Self-Review was performed

Having the author check these items directly assigns responsibility, ensuring the request for review is made only after "minimum quality assurance" has been met.

## 6\. Advanced: Using Multiple Templates

As projects grow, the required format for a bug fix might differ from that for a feature development. In this case, you can create a dedicated folder `.github/PULL_REQUEST_TEMPLATE/` and place multiple files inside it.

**Path Example:**

```text
.github/
└── PULL_REQUEST_TEMPLATE/
    ├── feature_request.md
    └── bug_fix.md
```

With this setup, you can select the template either via a URL query parameter (`?template=bug_fix.md`) when creating the PR or through an option that appears in the GitHub UI.

## 7\. Conclusion

A PR template is not just a document format; it is a mirror reflecting a team's **development culture**.

While it might seem bothersome at first, I encourage you to create your team's own template, remembering that "a good PR creates a good review, and a good review creates a good product."

-----

# [GitHub] 협업의 질을 높이는 치트키: Pull Request 이해와 템플릿 설정 가이드

## 1\. Pull Request (PR)란 무엇인가요?

Pull Request는 말 그대로 **"내 코드를 당겨달라(Pull)는 요청"**입니다.

GitHub(또는 GitLab, Bitbucket)와 같은 Git 호스팅 서비스를 사용할 때, 내가 작업한 **보조 브랜치**의 내용을 **메인 브랜치**로 병합(Merge)하기 위해 공식적으로 요청하는 기능입니다.

### PR의 핵심 역할

PR은 단순한 '병합 요청'을 넘어, 팀 협업의 핵심적인 토론장이자 안전장치입니다.

1.  **코드 리뷰의 시작점:** 병합 전, 팀원들이 코드를 검토(Code Review)하고 피드백을 주고받는 공간입니다.
2.  **변경 이력 기록:** 왜 이 코드가 변경되었는지, 어떤 배경에서 작업이 시작되었는지 명확한 히스토리를 남깁니다.
3.  **CI/CD 자동화 트리거:** PR 생성 시 자동화된 테스트가 실행되어, 문제가 있는 코드가 병합되는 것을 사전에 방지합니다.

## 2\. PR 생성 워크플로우 (How-To)

이전 글에서 다룬 `feature` 브랜치 작업을 예시로, PR을 생성하는 과정을 설명합니다.

1.  **로컬 작업 및 푸시:** `develop`에서 분기한 `feature/new-api` 브랜치에서 작업을 완료하고 원격 저장소에 푸시합니다.

    ```bash
    git push origin feature/new-api
    ```

2.  **GitHub에서 PR 생성 시작:**

      * GitHub 저장소 페이지로 이동합니다.
      * 최근 푸시한 브랜치가 감지되어 나타나는 **"Compare & pull request"** 버튼을 클릭하거나, `Pull Requests` 탭으로 이동합니다.

3.  **베이스 브랜치 설정 (중요):**

      * PR의 병합 기준을 설정합니다. (PR이 어디로 들어갈지 지정)
      * **Base (목표 브랜치):** `develop` (우리가 작업 중인 개발 브랜치)
      * **Compare (내 작업 브랜치):** `feature/new-api`

4.  **제목 및 내용 작성:**

      * **제목:** 이전 글에서 정한 **Conventional Commit** 규칙에 따라 작성합니다. (예: `feat: 사용자 정보 조회 API 구현`)
      * **내용:** 이곳에 **PR 템플릿**이 자동으로 채워집니다.

5.  **리뷰어 지정 및 생성:**

      * 리뷰어(팀 동료)를 지정하고 PR을 생성합니다.

## 3\. PR 템플릿 도입의 필요성

PR의 기능은 훌륭하지만, 작성자가 내용을 성의 없이 적으면 그 가치를 잃습니다. PR 템플릿은 이 문제에 대한 해결책입니다.

1.  **작성 가이드라인 제공:** PR 작성자가 무엇을 적어야 할지 고민하는 시간을 줄여줍니다.
2.  **커뮤니케이션 비용 절감:** "이거 테스트는 해보신 건가요?", "관련 티켓 번호가 뭐죠?" 같은 반복적인 질문을 사전에 방지합니다.
3.  **리뷰 품질 향상:** 스크린샷이나 테스트 방법이 포함되면 리뷰어가 변경 사항을 훨씬 빠르게 이해하고 본질적인 로직 검토에 집중할 수 있습니다.
4.  **체크리스트 강제:** 배포 전 필수 확인 사항(테스트 수행, 린트 체크 등)을 놓치지 않도록 돕습니다.

## 4\. PR 템플릿 설정 방법 (Step-by-Step)

설정 방법은 프로젝트의 루트 디렉터리에 약속된 경로로 마크다운 파일을 추가하기만 하면 됩니다.

### 기본 설정

1.  프로젝트 루트(최상위) 폴더에 `.github` 폴더를 생성합니다.
2.  그 안에 `pull_request_template.md` 파일을 생성합니다.

**경로 예시:**

```text
my-project/
├── .github/
│   └── pull_request_template.md  <-- 이곳!
├── src/
├── README.md
└── ...
```

### 바로 사용할 수 있는 모범 템플릿 (Best Practice)

이 내용을 `pull_request_template.md`에 붙여넣어 사용해 보세요.

```markdown
## 1. 개요
- **관련 이슈:** (예: #123, [JIRA-456])
- **변경 사항:** (이 PR에서 무엇을 변경했는지 핵심만 요약해서 적어주세요.)

## 2. 작업 상세 내용
- (구체적인 작업 내용을 리스트 형태로 작성합니다.)
- (예: 로그인 API의 에러 처리 로직을 개선했습니다.)
- (예: 불필요한 콘솔 로그를 제거했습니다.)

## 3. 스크린샷 (UI 변경 시 필수)
| Before | After |
| :---: | :---: |
| <img src="" width="300" /> | <img src="" width="300" /> |

## 4. 체크리스트
- [ ] 빌드가 에러 없이 정상적으로 수행되는가?
- [ ] 테스트 코드를 작성하고 통과했는가?
- [ ] 불필요한 주석이나 코드는 제거했는가?
- [ ] 컨벤션(Conventional Commits)에 맞게 커밋 메시지를 작성했는가?

## 5. 리뷰 시 요청 사항
- (리뷰어가 특별히 봐주었으면 하는 로직이나 궁금한 점이 있다면 적어주세요.)
```

## 5\. 템플릿의 핵심 구성 요소 설명

위 템플릿이 왜 이렇게 구성되었는지 설명합니다.

### A. 관련 이슈 (Related Issues)

Jira 티켓이나 GitHub Issue 번호를 링크합니다. 나중에 코드를 볼 때 "왜 이 기능을 만들었지?"에 대한 히스토리를 추적하는 가장 중요한 단서가 됩니다.

### B. 스크린샷 (Screenshots)

백엔드 로직만 수정했다면 필요 없지만, 프론트엔드나 모바일 작업 시에는 **필수**입니다. 코드 100줄을 읽는 것보다 스크린샷(혹은 GIF) 한 장이 변경 사항을 이해하는 데 훨씬 빠릅니다.

### C. 체크리스트 (Checklist)

`[ ]` 문법을 사용하면 GitHub 화면에서 클릭 가능한 체크박스로 렌더링됩니다.

  * 로컬 테스트 수행 여부
  * Lint/Format 체크 여부
  * Self-Review 수행 여부

이 항목들을 작성자가 직접 체크하게 함으로써, "최소한의 품질 보증"을 마친 상태로 리뷰를 요청한다는 책임감을 부여합니다.


## 6\. 심화: 여러 개의 템플릿 사용하기

프로젝트 규모가 커지면 버그 수정(Bug fix)과 기능 개발(Feature)의 양식이 달라야 할 때가 있습니다. 이때는 `.github/PULL_REQUEST_TEMPLATE/` 폴더를 만들고 그 안에 여러 파일을 넣으면 됩니다.

**경로 예시:**

```text
.github/
└── PULL_REQUEST_TEMPLATE/
    ├── feature_request.md
    └── bug_fix.md
```

이렇게 설정하면 PR 생성 시 URL 쿼리 파라미터(`?template=bug_fix.md`)를 통해 템플릿을 선택하거나, GitHub UI에서 템플릿을 선택할 수 있는 옵션이 나타납니다.


## 7\. 마치며

PR 템플릿은 단순한 문서 서식이 아니라 팀의 **개발 문화**를 보여주는 거울입니다.

처음에는 번거로울 수 있지만, "좋은 PR이 좋은 리뷰를 만들고, 좋은 리뷰가 좋은 제품을 만든다"는 사실을 기억하며 우리 팀만의 템플릿을 만들어 보시기를 권장합니다.