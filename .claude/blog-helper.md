# Blog Writing Helper

사용자의 블로그 포스팅 작업을 보조하는 도우미입니다.

## 사용 가능한 명령어

### 1. 새 포스트 생성
```
/blog new --title "Post Title" --category "Category" --tags "tag1, tag2"
```

**옵션:**
- `--title`: 포스트 제목 (필수)
- `--category`: 주 카테고리 (선택, 기본: Personal)
- `--tags`: 태그 목록 (선택, 쉼표로 구분)
- `--bilingual`: 이중언어 포스트 (선택, 불린)
- `--toc`: 목차 포함 (선택, 기본: true)

### 2. 카테고리 확인
```
/blog categories
```
모든 사용 가능한 카테고리와 각 카테고리의 포스트 수를 표시합니다.

### 3. 포스트 템플릿
```
/blog template --category "Category"
```
지정된 카테고리의 포스트 템플릿을 생성합니다.

### 4. 날짜 자동 설정
```
/blog date --mode monthly
```
포스팅 날짜를 자동으로 설정합니다.
- `monthly`: 월별 1개씩 균등 분배
- `current`: 현재 시간 사용
- `yesterday`: 어제 날짜

### 5. 포스트 미리보기
```
/blog preview <filename>
```
마크다운 포스트의 미리보기를 생성합니다.

## 사용 가능한 카테고리

**Main Categories:**
- Security
- Engineering
- AI & ML
- Career
- Personal
- Tools

**Sub Categories (Tools):**
- Docker, ELK, Exploitation, Operating System, Reconnaissance, Jekyll, Kong, Forensics Tools, .NET

**Sub Categories (Personal):**
- Identity, Life Information, Philosophy

**Sub Categories (Security):**
- Blockchain, Cloud Security, Cryptography, Forensics, Network Security, Mobile Security, Web Security, Vulnerabilities 등

**Sub Categories (Career):**
- Certificates, Interview, Post-Interview

**Sub Categories (Engineering):**
- Algorithms & Data Structures, Database Systems, DevOps & Automation, Programming Fundamentals, System Design & Architecture

**Sub Categories (AI & ML):**
- GenAI, Machine Learning

## 포스트 Frontmatter 예시

```yaml
---
title: Post Title Here
tags: [tag1, tag2, tag3]
key: page-example
categories: [Main Category, Sub Category]
author: hyoeun
math: false
mathjax_autoNumber: false
image: "/assets/thumbnails/YYYY-MM-DD-slug.png"
bilingual: false
date: 2026-03-24 10:30:00
---
```

## 팁

1. **이미지**: `/assets/thumbnails/` 디렉토리에 `YYYY-MM-DD-슬러그.png` 형식으로 저장
2. **날짜 형식**: `YYYY-MM-DD HH:MM:SS` (예: 2026-03-24 10:30:00)
3. **카테고리**: 1개는 주 카테고리, 추가로 부분 카테고리 가능
4. **이중언어**: `bilingual: true`일 때 `---`로 EN/KR 섹션 분리
5. **수학**: `math: true`일 때 LaTeX 지원 활성화

## 빠른 시작

```bash
# 1. 새 포스트 생성
/blog new --title "My First Post" --category "Personal" --tags "reflection, learning"

# 2. 카테고리 확인
/blog categories

# 3. 포스트 작성 및 저장
# editor에서 작성

# 4. 미리보기
/blog preview 2026-03-24-my-first-post.md
```
