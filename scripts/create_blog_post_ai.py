#!/usr/bin/env python3
"""
Claude AI를 활용한 블로그 포스트 자동 생성 스크립트
주제를 입력하면 AI가 기본 글 구조를 생성합니다.
"""

import os
import sys
from datetime import datetime
from pathlib import Path
import subprocess
import json
import re

try:
    from anthropic import Anthropic
except ImportError:
    print("❌ anthropic 패키지가 필요합니다.")
    print("설치 명령어: pip install anthropic")
    sys.exit(1)

def slugify(text):
    """텍스트를 URL-safe한 slug로 변환"""
    text = text.lower()
    text = re.sub(r'[^\w\s-]', '', text)
    text = re.sub(r'[-\s]+', '-', text)
    return text.strip('-')

def get_next_date():
    """다음 포스팅 날짜를 계산"""
    posts_dir = Path(__file__).parent.parent / "_posts"

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

    now = datetime.now()
    return now if now > latest_date else latest_date

def generate_blog_outline_with_ai(topic, category):
    """Claude AI를 사용해 블로그 개요 생성"""

    client = Anthropic()

    system_prompt = """당신은 학습 목적의 기술 블로그 작성 전문가입니다.
사용자의 주제에 대해 마크다운 형식의 블로그 개요를 생성합니다.

요구사항:
1. 마크다운 형식 사용
2. H2(##)부터 시작 (H1은 제외)
3. 학습자 관점에서 작성
4. 실용적이고 이해하기 쉬운 내용
5. 코드 예시나 실제 사례 포함 (해당하는 경우)
6. 각 섹션은 200-300자 수준의 기본 개요만 작성 (사용자가 나중에 추가 작성)

구조:
- Overview (개념 설명)
- Key Points (핵심 포인트 3-5개)
- Core Concepts (세부 개념 2-3개)
- Practical Examples (실제 활용 예시)
- Common Pitfalls (주의사항)
- Summary (요약)

한국어/영어 모두 지원합니다. 사용자의 주제 언어로 작성하세요."""

    user_message = f"""주제: {topic}
카테고리: {category}

이 주제에 대한 블로그 포스트의 기본 구조를 마크다운으로 생성해주세요.
각 섹션은 간단한 개요만 포함하고, 사용자가 나중에 추가 작성할 수 있도록 해주세요.
"""

    print(f"\n🤖 Claude AI가 '{topic}' 포스트 개요를 생성 중...\n")

    # 스트리밍으로 응답 받기
    outline = ""
    with client.messages.stream(
        max_tokens=2048,
        system=system_prompt,
        messages=[{"role": "user", "content": user_message}],
        model="claude-opus-4-6",
    ) as stream:
        for text in stream.text_stream:
            print(text, end="", flush=True)
            outline += text

    print("\n")
    return outline

def create_blog_post_with_ai(topic, category="Personal"):
    """AI를 사용한 블로그 포스트 생성"""

    # API 키 확인
    if not os.environ.get("ANTHROPIC_API_KEY"):
        print("❌ ANTHROPIC_API_KEY 환경 변수가 설정되지 않았습니다.")
        print("설정 방법: export ANTHROPIC_API_KEY='your-api-key'")
        sys.exit(1)

    # 메타데이터 준비
    slug = slugify(topic)
    post_date = get_next_date()
    date_str = post_date.strftime("%Y-%m-%d")
    timestamp_str = post_date.strftime("%Y-%m-%d %H:%M:%S")
    filename = f"{date_str}-{slug}.md"

    posts_dir = Path(__file__).parent.parent / "_posts"
    post_path = posts_dir / filename

    # 파일 존재 확인
    if post_path.exists():
        print(f"⚠️  파일이 이미 존재합니다: {filename}")
        response = input("덮어쓰시겠습니까? (y/n): ")
        if response.lower() != 'y':
            return None

    # AI로 콘텐츠 생성
    content = generate_blog_outline_with_ai(topic, category)

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

    print(f"\n✅ AI 포스트 생성 완료!")
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

    # VS Code에서 파일 열기
    try:
        subprocess.run(['code', str(post_path)], check=False)
        print(f"\n✨ VS Code에서 파일을 열었습니다. 이제 내용을 추가/수정하세요!")
    except Exception as e:
        print(f"\n💡 수동으로 열기: code {post_path}")

    return str(post_path)

def main():
    if len(sys.argv) < 2:
        print("사용법: python3 create_blog_post_ai.py '<주제>' [카테고리]")
        print("\n예시:")
        print("  python3 create_blog_post_ai.py 'Python 딕셔너리'")
        print("  python3 create_blog_post_ai.py 'REST API Design' Engineering")
        print("  python3 create_blog_post_ai.py 'Zero Trust Architecture' Security")
        print("\n💡 팁: ANTHROPIC_API_KEY 환경 변수를 설정하고 사용하세요.")
        sys.exit(1)

    topic = sys.argv[1]
    category = sys.argv[2] if len(sys.argv) > 2 else "Personal"

    create_blog_post_with_ai(topic, category)

if __name__ == "__main__":
    main()
