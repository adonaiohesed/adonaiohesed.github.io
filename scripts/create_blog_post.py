#!/usr/bin/env python3
"""
블로그 포스트 자동 생성 스크립트
주제를 입력하면 기본 구조의 포스트를 자동으로 생성합니다.
"""

import os
import sys
from datetime import datetime
from pathlib import Path
import subprocess
import json
import re

def slugify(text):
    """텍스트를 URL-safe한 slug로 변환"""
    text = text.lower()
    text = re.sub(r'[^\w\s-]', '', text)
    text = re.sub(r'[-\s]+', '-', text)
    return text.strip('-')

def get_next_date():
    """다음 포스팅 날짜를 계산 (기존 포스트 기반)"""
    posts_dir = Path(__file__).parent.parent / "_posts"

    # 기존 포스트 중 가장 최신 날짜 찾기
    latest_date = datetime(2018, 1, 1)
    for post_file in posts_dir.glob("*.md"):
        match = re.search(r'(\d{4})-(\d{2})-(\d{2})', post_file.name)
        if match:
            try:
                post_date = datetime(int(match.group(1)), int(match.group(2)), int(match.group(3)))
                if post_date > latest_date:
                    latest_date = post_date
            except ValueError:
                pass

    # 현재 날짜 또는 최신 포스트 이후로 설정
    now = datetime.now()
    if now > latest_date:
        return now
    else:
        return latest_date

def generate_post_structure(topic, category="Personal"):
    """주제를 기반으로 포스트 구조 생성"""

    template = f"""## Overview

{topic}에 대한 기본 개념과 원리를 설명합니다.

## Key Points

- 주요 포인트 1
- 주요 포인트 2
- 주요 포인트 3

## 개념 설명

### 1. 기초

{topic}의 기본 정의와 목적을 설명합니다.

### 2. 특징

이 주제의 핵심 특징들을 나열합니다.

### 3. 실제 활용

실제 사용 사례나 적용 방법을 설명합니다.

## 요약

{topic}은 ...

## 참고 자료

- 참고자료 1
- 참고자료 2

## 다음 단계

이 주제를 더 깊이 있게 학습하려면 ...
"""

    return template

def create_blog_post(topic, category="Personal", language="en"):
    """블로그 포스트 생성"""

    # 메타데이터 준비
    slug = slugify(topic)
    post_date = get_next_date()
    date_str = post_date.strftime("%Y-%m-%d")
    timestamp_str = post_date.strftime("%Y-%m-%d %H:%M:%S")
    filename = f"{date_str}-{slug}.md"

    posts_dir = Path(__file__).parent.parent / "_posts"
    post_path = posts_dir / filename

    # 이미 존재하는 파일 확인
    if post_path.exists():
        print(f"⚠️  파일이 이미 존재합니다: {filename}")
        response = input("덮어쓰시겠습니까? (y/n): ")
        if response.lower() != 'y':
            return None

    # 포스트 본문 생성
    content = generate_post_structure(topic, category)

    # 썸네일 경로
    thumbnail_path = f"/assets/thumbnails/{filename.replace('.md', '.png')}"

    # Frontmatter 생성
    frontmatter = f"""---
title: {topic}
tags: [{topic.lower()}]
key: page-{slug}
categories: [{category}]
author: hyoeun
math: false
mathjax_autoNumber: false
image: "{thumbnail_path}"
bilingual: false
date: {timestamp_str}
---

"""

    # 전체 포스트 작성
    full_content = frontmatter + content

    # 파일 저장
    post_path.write_text(full_content, encoding='utf-8')

    print(f"✅ 포스트 생성 완료!")
    print(f"   파일: {filename}")
    print(f"   경로: {post_path}")
    print(f"   제목: {topic}")
    print(f"   카테고리: {category}")
    print(f"   날짜: {timestamp_str}")

    # 메타데이터 출력
    metadata = {
        "filename": filename,
        "title": topic,
        "category": category,
        "date": timestamp_str,
        "slug": slug,
        "thumbnail": thumbnail_path,
        "full_path": str(post_path)
    }

    print(f"\n📋 메타데이터:")
    print(json.dumps(metadata, indent=2, ensure_ascii=False))

    # VS Code에서 파일 열기 (선택사항)
    try:
        subprocess.run(['code', str(post_path)], check=False)
        print(f"\n✨ VS Code에서 파일을 열었습니다.")
    except Exception as e:
        print(f"\n💡 수동으로 열기: code {post_path}")

    return str(post_path)

def main():
    if len(sys.argv) < 2:
        print("사용법: python3 create_blog_post.py '<주제>' [카테고리]")
        print("\n예시:")
        print("  python3 create_blog_post.py 'Python 딕셔너리'")
        print("  python3 create_blog_post.py 'REST API' Engineering")
        print("  python3 create_blog_post.py 'Zero Trust Security' Security")
        sys.exit(1)

    topic = sys.argv[1]
    category = sys.argv[2] if len(sys.argv) > 2 else "Personal"

    create_blog_post(topic, category)

if __name__ == "__main__":
    main()
