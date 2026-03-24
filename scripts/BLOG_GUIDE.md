# 📝 블로그 포스트 작성 가이드

학습 기반 블로그를 효율적으로 작성하기 위한 스크립트와 워크플로우입니다.

## 🚀 빠른 시작

### 1. 기본 템플릿으로 생성 (빠름)

```bash
python3 scripts/create_blog_post.py "주제"
python3 scripts/create_blog_post.py "Python 딕셔너리"
python3 scripts/create_blog_post.py "REST API" Engineering
```

**특징:**
- ⚡ 즉시 생성
- 📋 기본 구조 제공
- ✏️ 바로 편집 가능

### 2. AI로 자동 생성 (스마트)

```bash
python3 scripts/create_blog_post_ai.py "주제"
python3 scripts/create_blog_post_ai.py "Zero Trust Security" Security
python3 scripts/create_blog_post_ai.py "분산 시스템" Engineering
```

**특징:**
- 🤖 Claude AI가 기본 개요 작성
- 📚 학습자 관점의 구조화
- 💡 실제 예시와 팁 포함
- 🔧 커스터마이징 가능

## 📊 워크플로우

### Step 1: 포스트 생성
```bash
# AI 기반 추천 (더 나은 결과)
python3 scripts/create_blog_post_ai.py "React Hooks"

# 또는 기본 템플릿 (빠른 생성)
python3 scripts/create_blog_post.py "React Hooks"
```

### Step 2: 메타데이터 확인
생성 후 다음 정보가 자동으로 설정됩니다:
- ✅ 파일명: `YYYY-MM-DD-slug.md`
- ✅ 날짜: 자동 설정 (최신 포스트 기반)
- ✅ 썸네일 경로: 자동 설정
- ✅ Frontmatter: 완전 자동화

### Step 3: 콘텐츠 작성

VS Code에서 파일이 자동으로 열립니다.

**작성 팁:**
1. **개요 확인**: 생성된 구조가 적절한지 확인
2. **섹션 추가**: 필요시 섹션 추가/삭제
3. **코드 예시**: 해당하는 경우 코드 블록 추가
4. **실제 활용**: 실무에서 어떻게 사용하는지 작성
5. **요약**: 마지막에 주요 내용 요약

### Step 4: 대화형 확장 (선택사항)

작성 중간에 Claude Code와 대화하면서 추가 내용 작성:

```
"REST API 섹션을 더 자세하게 작성해줄 수 있을까?"
"실제 프로젝트 예시를 하나 추가해줘"
"이 개념의 장단점을 정리해줄래?"
```

### Step 5: 저장 및 완료

파일 저장 후 블로그 빌드:
```bash
bundle exec jekyll build
```

## 🎯 카테고리 선택 가이드

### Main Categories
- **Personal**: 개인 성찰, 일상 (기본값)
- **Tools**: 개발 도구, 프레임워크
- **Engineering**: 알고리즘, 데이터베이스, 아키텍처
- **Security**: 보안 관련 주제
- **AI & ML**: 인공지능, 머신러닝
- **Career**: 커리어, 면접, 인증

### 사용 예시

```bash
# Personal 카테고리
python3 scripts/create_blog_post_ai.py "나의 개발 여정"

# Tools 카테고리
python3 scripts/create_blog_post_ai.py "Docker 기본 개념" Tools

# Engineering 카테고리
python3 scripts/create_blog_post_ai.py "System Design Patterns" Engineering

# Security 카테고리
python3 scripts/create_blog_post_ai.py "OAuth 2.0 설명" Security
```

## 📝 Frontmatter 참고

자동으로 생성되는 메타데이터:

```yaml
---
title: 포스트 제목
tags: [tag1, tag2]
key: page-slug
categories: [Main Category]
author: hyoeun
math: false
mathjax_autoNumber: false
image: "/assets/thumbnails/YYYY-MM-DD-slug.png"
bilingual: false
date: YYYY-MM-DD HH:MM:SS
---
```

## 🔧 고급 옵션

### 이중언어 포스트 (EN/KR)

작성 후 frontmatter에서 수정:
```yaml
bilingual: true
```

그리고 본문에 `---` 구분선으로 영어/한국어 섹션 분리

### 수식 포함

```yaml
math: true
mathjax_autoNumber: true
```

## 💡 작성 팁

### 1. 구조화된 학습
```
개념 설명 → 핵심 포인트 → 실제 사례 → 주의사항 → 요약
```

### 2. 코드 예시
```python
# 나쁜 예
x = 1

# 좋은 예
def process_data(x: int) -> int:
    """데이터 처리 함수"""
    return x * 2
```

### 3. 시각화
- 리스트: `- 항목`
- 테이블: 마크다운 테이블 사용
- 코드: 언어 지정 (python, javascript, etc)

### 4. 내부 링크
```markdown
[이전 포스트](/posts/previous-post/)
```

## 🎨 썸네일 설정

생성된 포스트의 썸네일 경로:
```
/assets/thumbnails/YYYY-MM-DD-slug.png
```

**썸네일 추가:**
1. 이미지 생성/준비
2. 위의 경로에 저장
3. Frontmatter의 `image` 경로 확인

> 💡 미리보기: 썸네일이 없으면 기본 아이콘이 표시됩니다.

## 🔄 수정 및 업데이트

기존 포스트 수정:
1. 파일 직접 열기: `code _posts/YYYY-MM-DD-slug.md`
2. 내용 수정
3. 날짜는 변경하지 않기 (버전 관리상)

## ✨ 예시 워크플로우

```bash
# 1. 주제 결정 및 포스트 생성
python3 scripts/create_blog_post_ai.py "마이크로서비스 아키텍처" Engineering

# 2. VS Code에서 자동 열림
# (내용 검토 및 편집)

# 3. 대화로 섹션 추가
# "성능 최적화 섹션을 추가해줄 수 있을까?"
# "실제 구현 예시를 Java로 작성해줘"

# 4. 파일 저장

# 5. 빌드 확인
bundle exec jekyll build

# 6. 로컬 테스트
bundle exec jekyll serve
```

## 🐛 트러블슈팅

### 파일이 이미 존재합니다
- 다른 날짜로 포스트 생성 (스크립트가 자동 설정)
- 또는 기존 파일 덮어쓰기 (y 입력)

### ANTHROPIC_API_KEY 오류
```bash
export ANTHROPIC_API_KEY="your-key-here"
python3 scripts/create_blog_post_ai.py "주제"
```

### VS Code 자동 열기 실패
```bash
# 수동으로 열기
code _posts/YYYY-MM-DD-slug.md
```

## 📚 추가 리소스

- Markdown 가이드: https://guides.github.com/features/mastering-markdown/
- Jekyll 문서: https://jekyllrb.com/docs/
- 블로그 홈: https://adonaiohesed.github.io

---

**Happy Writing! 🚀**
