---
title: Git Action
tags: Git Collaborate
key: page-git_flow
categories: [Development, DevOps & Automation]
author: hyoeun
---

# [CI/CD] Collaboration Mastered: Automating Branch-Specific Builds and Deployments with GitHub Actions

In previous posts, we established a stable **Git Branching Strategy (Git Flow)** and an efficient **Pull Request (PR) Template**. The next step is to technically complete this strategy.

Manually building code and deploying it to servers wastes developer time and causes human errors. **CI/CD (Continuous Integration / Continuous Deployment)** is the solution that maximizes team productivity.

In this article, we will provide a step-by-step guide on how to build an automated pipeline tailored to our configured `develop` and `main` branches, leveraging **GitHub Actions**, which is built into GitHub.

## 1\. What is CI/CD, and Why Adopt It Now?

### CI (Continuous Integration)

  * **Goal:** Every developer regularly integrates their code into the main repository (e.g., the `develop` branch), and a build and test process is automatically run upon each integration.
  * **Effect:** Conflicts and bugs are discovered early, keeping issues small and reducing the cost of resolution.

### CD (Continuous Deployment)

  * **Goal:** Code that has passed testing is automatically deployed to staging or production servers.
  * **Effect:** Standardizes and automates the deployment process, shortening deployment time and reducing deployment errors.

## 2\. Understanding GitHub Actions: Workflow File Structure

GitHub Actions is used by creating a `.github/workflows` directory within your repository and defining YAML files inside it. This YAML file serves as the blueprint for your automation.

### Core Components of a Workflow File

| Element | Description |
| :--- | :--- |
| `name` | The name of the workflow (displayed in the GitHub UI) |
| `on` | The **event** that triggers the workflow (e.g., `push`, `pull_request`, etc.) |
| `jobs` | A set of tasks to be executed. Each Job runs in an independent environment. |
| `steps` | Units of commands executed sequentially within a Job (e.g., `npm install`, `npm test`) |
| `uses` | A command to invoke and use pre-built actions from others (Actions) |

### File Creation Path

Create the YAML file in the following path within the project root directory:

```text
.github/workflows/ci_pipeline.yml
```

## 3\. Hands-On: Building CI for Automatic Testing on PR (Build & Test)

This is the most fundamental and important CI pipeline. It sets up automatic testing to run before any PR is merged into the `develop` branch.

### ci\_pipeline.yml Example Code

```yaml
name: CI Build & Test

# 1. Trigger Condition: Push to main or develop, and any PR creation
on:
  push:
    branches:
      - main
      - develop
  pull_request:
    branches:
      - main
      - develop

# 2. Job Definition
jobs:
  build_and_test:
    name: Build & Run Tests
    # Execution Environment: Latest Ubuntu
    runs-on: ubuntu-latest
    
    # 3. Steps to be executed sequentially
    steps:
      - name: Checkout Code
        # Use standard action provided by GitHub Actions Marketplace
        uses: actions/checkout@v4

      - name: Setup Node.js
        # Configure Node.js environment
        uses: actions/setup-node@v4
        with:
          node-version: '20'

      - name: Install Dependencies
        run: npm install

      - name: Run Unit Tests
        run: npm test
```

**How it works:** When a PR is created from a `feature` branch into `develop`, this workflow automatically executes `npm test`. If the tests fail, the PR can be configured to be unmergeable.

## 4\. Building Separate CD for Different Environments (Deployment)

Now that we have confirmed the code is stable, we build a CD pipeline that automatically deploys to the corresponding server for each branch.

### Deployment Strategy: Develop vs. Main

We separate the CD strategy according to the Git Flow established in the previous post.

| Branch | Environment | Trigger Event |
| :--- | :--- | :--- |
| `develop` | Development Server (Dev Environment) | **Push or Merge** to the `develop` branch |
| `main` | Production Server (Prod Environment) | **Merge** to the `main` branch |

### deployment\_pipeline.yml (Example - Assuming AWS S3 Deployment)

```yaml
name: CD Deployment

on:
  push:
    branches:
      - develop
      - main

jobs:
  deploy:
    name: Deploy to Environment
    runs-on: ubuntu-latest
    # Environment Variable Configuration (using Secrets for security)
    environment: 
      name: ${{ github.ref == 'refs/heads/main' && 'production' || 'development' }}
      
    steps:
      - name: Checkout Code
        uses: actions/checkout@v4

      # ... (Node.js installation, dependency installation, and build process omitted)

      - name: Configure AWS Credentials
        uses: aws-actions/configure-aws-credentials@v4
        with:
          aws-access-key-id: ${{ secrets.AWS_ACCESS_KEY_ID }} # GitHub Secrets
          aws-secret-access-key: ${{ secrets.AWS_SECRET_ACCESS_KEY }}
          aws-region: ap-northeast-2

      - name: Deploy to S3 Bucket
        # Set different target S3 buckets based on the branch
        if: github.ref == 'refs/heads/develop' # If develop branch
        run: aws s3 sync ./dist s3://${{ secrets.DEV_S3_BUCKET }} --delete

      - name: Deploy to S3 Bucket (Production)
        if: github.ref == 'refs/heads/main' # If main branch
        run: aws s3 sync ./dist s3://${{ secrets.PROD_S3_BUCKET }} --delete
```

### Security Best Practice: Using GitHub Secrets

**Security** is paramount in CI/CD. Sensitive information like AWS keys or DB passwords must **never** be hardcoded in the YAML file.

  * **Configuration Method:** Register secret information in your GitHub repository under `Settings` \> `Secrets and variables` \> `Actions`, and safely retrieve and use it within the YAML file using the `${{ secrets.NAME }}` format.

-----

# [CI/CD] 협업 완성\! GitHub Actions로 브랜치별 빌드 및 배포 자동화하기

우리는 이전 포스팅에서 안정적인 **Git Branch 전략(Git Flow)**과 효율적인 **Pull Request(PR) 템플릿**을 구축했습니다. 이제 다음 단계는 이 전략을 기술적으로 완성하는 것입니다.

수동으로 코드를 빌드하고 서버에 배포하는 방식은 개발자의 시간을 낭비시키고 휴먼 에러를 유발합니다. 이 문제를 해결하고 팀의 생산성을 극대화하는 것이 바로 **CI/CD (Continuous Integration / Continuous Deployment)**입니다.

본 글에서는 GitHub에 내장된 **GitHub Actions**를 활용하여, 우리가 설정한 `develop`과 `main` 브랜치에 맞춘 자동화 파이프라인을 구축하는 방법을 단계별로 안내합니다.

## 1\. CI/CD란 무엇이며, 왜 지금 도입해야 하는가?

### CI (지속적 통합 - Continuous Integration)

  * **목표:** 모든 개발자가 자신의 코드를 주기적으로 메인 저장소(예: `develop` 브랜치)에 통합하고, 통합될 때마다 자동으로 빌드 및 테스트를 실행합니다.
  * **효과:** 충돌 및 버그를 조기에 발견하여, 문제를 작게 유지하고 해결 비용을 낮춥니다.

### CD (지속적 배포 - Continuous Deployment)

  * **목표:** 테스트를 통과한 코드를 자동으로 스테이징 서버나 운영 서버에 배포합니다.
  * **효과:** 배포 과정을 표준화하고 자동화하여, 배포 시간을 단축하고 배포 오류를 줄입니다.

## 2\. GitHub Actions 이해하기: Workflow 파일 구조

GitHub Actions는 저장소 내부에 `.github/workflows` 디렉터리를 만들고 그 안에 YAML 파일을 정의하여 사용합니다. 이 YAML 파일이 곧 자동화의 설계도입니다.

### Workflow 파일의 핵심 구성 요소

| 요소 | 설명 |
| :--- | :--- |
| `name` | 워크플로우의 이름 (GitHub UI에 표시) |
| `on` | 워크플로우를 트리거할 **이벤트** (예: `push`, `pull_request` 등) |
| `jobs` | 실행할 작업의 집합. 각 Job은 독립적인 환경에서 실행됨 |
| `steps` | Job 내에서 순차적으로 실행되는 명령어 단위 (예: `npm install`, `npm test`) |
| `uses` | 이미 만들어진 다른 액션(Action)을 불러와 사용하는 명령어 |

### 파일 생성 경로

프로젝트 루트 디렉터리에 다음 경로로 YAML 파일을 생성합니다.

```text
.github/workflows/ci_pipeline.yml 
```

## 3\. 실습: PR 시 자동 테스트를 위한 CI 구축 (Build & Test)

가장 기본적이면서 중요한 CI 파이프라인입니다. 모든 PR이 `develop` 브랜치로 병합되기 전에 자동으로 테스트를 수행하도록 설정합니다.

### ci\_pipeline.yml 예시 코드

```yaml
name: CI Build & Test

# 1. 트리거 조건: main 또는 develop으로의 push, 그리고 모든 PR 발생 시
on:
  push:
    branches:
      - main
      - develop
  pull_request:
    branches:
      - main
      - develop

# 2. 작업 정의
jobs:
  build_and_test:
    name: Build & Run Tests
    # 실행 환경: Ubuntu 최신 버전
    runs-on: ubuntu-latest
    
    # 3. 순차적으로 실행될 단계
    steps:
      - name: Checkout Code
        # GitHub Actions 마켓플레이스에서 제공하는 표준 액션 사용
        uses: actions/checkout@v4

      - name: Setup Node.js
        # Node.js 환경 설정
        uses: actions/setup-node@v4
        with:
          node-version: '20'

      - name: Install Dependencies
        run: npm install

      - name: Run Unit Tests
        run: npm test
```

**작동 방식:** `feature` 브랜치에서 `develop`으로 PR을 생성하면, 이 워크플로우가 자동으로 실행되어 `npm test`를 돌립니다. 테스트가 실패하면 PR은 병합될 수 없도록 설정할 수 있습니다.

## 4\. 환경별 분리된 CD 구축 (Deployment)

이제 코드가 안정적임을 확인했으니, 브랜치별로 대응하는 서버에 자동 배포하는 CD 파이프라인을 구축합니다.

### 배포 전략: Develop vs. Main

우리가 이전 포스팅에서 정립한 Git Flow에 따라 CD 전략을 분리합니다.

| 브랜치 | 환경 | 트리거 이벤트 |
| :--- | :--- | :--- |
| `develop` | 개발 서버 (Dev Environment) | `develop` 브랜치에 **Push 또는 Merge** 발생 시 |
| `main` | 운영 서버 (Prod Environment) | `main` 브랜치에 **Merge** 발생 시 |

### deployment\_pipeline.yml (예시 - AWS S3 배포 가정)

```yaml
name: CD Deployment

on:
  push:
    branches:
      - develop
      - main

jobs:
  deploy:
    name: Deploy to Environment
    runs-on: ubuntu-latest
    # 환경 변수 설정 (보안을 위해 Secrets 사용)
    environment: 
      name: ${{ github.ref == 'refs/heads/main' && 'production' || 'development' }}
      
    steps:
      - name: Checkout Code
        uses: actions/checkout@v4

      # ... (Node.js 설치, 의존성 설치, 빌드 과정 생략)

      - name: Configure AWS Credentials
        uses: aws-actions/configure-aws-credentials@v4
        with:
          aws-access-key-id: ${{ secrets.AWS_ACCESS_KEY_ID }} # GitHub Secrets
          aws-secret-access-key: ${{ secrets.AWS_SECRET_ACCESS_KEY }}
          aws-region: ap-northeast-2

      - name: Deploy to S3 Bucket
        # 브랜치에 따라 배포 대상 S3 버킷을 다르게 설정
        if: github.ref == 'refs/heads/develop' # develop 브랜치인 경우
        run: aws s3 sync ./dist s3://${{ secrets.DEV_S3_BUCKET }} --delete

      - name: Deploy to S3 Bucket (Production)
        if: github.ref == 'refs/heads/main' # main 브랜치인 경우
        run: aws s3 sync ./dist s3://${{ secrets.PROD_S3_BUCKET }} --delete
```

### 보안 Best Practice: GitHub Secrets 사용

CI/CD에서 가장 중요한 것은 **보안**입니다. AWS 키, DB 비밀번호 등 민감한 정보는 절대로 YAML 파일에 하드코딩해서는 안 됩니다.

  * **설정 방법:** GitHub 저장소의 `Settings` \> `Secrets and variables` \> `Actions`에서 비밀 정보를 등록하고, YAML 파일 내에서 `${{ secrets.NAME }}` 형태로 안전하게 불러와 사용해야 합니다.