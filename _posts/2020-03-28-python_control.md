---
title: "Python Control Flow and Iteration Patterns"
key: page-python_control_structures
categories:
- Engineering
- Programming Fundamentals
author: hyoeun
math: false
mathjax_autoNumber: false
image: "/assets/thumbnails/2020-03-28-python_control.png"
bilingual: true
date: 2020-03-28 21:07:12
---

## Why Control Flow Matters Beyond the Basics

If/else and for loops are table stakes. What separates experienced Python engineers is knowing the patterns that are actually idiomatic: `for`/`else`, generator expressions versus list comprehensions, the walrus operator for inline assignment, context managers for resource safety, and how Python's reference model interacts with control flow.

This post covers control flow with an emphasis on patterns you'll use daily and the subtleties that cause real bugs.

## Core Concepts: Variables and References First

Before control flow, the variable model matters. Python variables are references (names bound to objects), not boxes holding values.

```python
a = [1, 2]
b = a          # b refers to the SAME list object
b.append(3)
print(a)       # [1, 2, 3] — a sees the change

# Deep copy for independence
from copy import copy, deepcopy
b = a[:]       # shallow copy — new list, same element refs
b = deepcopy(a)  # full independent copy
```

### Checking Types and Identity

```python
x = 42
type(x)        # <class 'int'>
id(x)          # memory address of the object
isinstance(x, (int, float))  # True — preferred for type checking

a = [1, 2]
b = a
print(a is b)  # True — same object
print(a == b)  # True — same value

b = [1, 2]
print(a is b)  # False — different objects
print(a == b)  # True — same value
```

**Swap without a temporary variable:**
```python
a, b = b, a    # idiomatic Python swap
```

## How It Works: Control Flow Deep Dive

### if / elif / else

```python
x = 42

if x > 100:
    print("large")
elif x > 10:
    print("medium")
else:
    print("small")
```

Key Python-specific behaviors:
- **Indentation defines blocks** — tabs and spaces cannot be mixed. 4 spaces is the standard (PEP 8).
- **`in` operator** for membership: `if x in [1, 2, 3]:` (works on lists, tuples, sets, strings, dicts)
- **`pass`** as a no-op placeholder: valid inside if blocks, loops, function bodies
- **Ternary expression** (conditional expression):

```python
# One-liner when the logic is simple
label = "admin" if is_admin else "user"

# But don't nest — it gets unreadable
# BAD: result = a if a > b else c if c > b else b
```

**Truthiness as a shortcut:**
```python
# Instead of: if len(items) > 0:
if items:
    process(items)

# Instead of: if name is not None and name != "":
if name:
    greet(name)
```

### while

```python
count = 0
while count < 10:
    if count == 5:
        break       # exit loop
    if count % 2 == 0:
        count += 1
        continue    # skip rest of body, re-check condition
    print(count)
    count += 1
```

### for and the Underused for/else

```python
# Standard iteration
for item in iterable:
    process(item)

# range patterns
for i in range(10):          # 0..9
    pass
for i in range(1, 11):       # 1..10
    pass
for i in range(0, 10, 2):    # 0, 2, 4, 6, 8
    pass
for i in range(10, 0, -1):   # 10, 9, 8, ..., 1
    pass
```

**for/else** — the `else` block runs when the loop completes *without hitting a break*. Underused and genuinely useful:

```python
def find_prime(numbers):
    for n in numbers:
        if n % 2 == 0 and n > 2:
            break
    else:
        print("No composite even numbers found")

# Practical: search with fallback
for item in collection:
    if matches(item):
        result = item
        break
else:
    result = default_value  # only runs if loop didn't break
```

### Enumerate and zip

```python
# enumerate — index + value without a counter variable
fruits = ['apple', 'banana', 'cherry']
for i, fruit in enumerate(fruits):
    print(f"{i}: {fruit}")
# 0: apple
# 1: banana
# 2: cherry

# Start from a custom index
for i, fruit in enumerate(fruits, start=1):
    print(f"{i}. {fruit}")

# zip — iterate multiple iterables in parallel
names = ['Alice', 'Bob', 'Charlie']
scores = [95, 87, 92]
for name, score in zip(names, scores):
    print(f"{name}: {score}")

# zip stops at the shortest iterable
# Use itertools.zip_longest to pad with a fill value
from itertools import zip_longest
for a, b in zip_longest([1, 2, 3], [10, 20], fillvalue=0):
    print(a, b)  # (1,10), (2,20), (3,0)
```

### Comprehensions

```python
# List comprehension — preferred over map()/filter() for clarity
squares = [x**2 for x in range(10)]
evens = [x for x in range(20) if x % 2 == 0]

# Dict comprehension
squared_dict = {x: x**2 for x in range(5)}

# Set comprehension
unique_lengths = {len(word) for word in words}

# Generator expression — lazy, memory-efficient
# Use () instead of []
total = sum(x**2 for x in range(1000000))  # doesn't build the full list

# When to use which:
# List comprehension — when you need the full list multiple times
# Generator expression — when you're consuming once (sum, max, any, all)
```

### Walrus Operator := (Python 3.8+)

Assigns a value AND evaluates it in a single expression. Most useful in while loops and comprehensions:

```python
# Reading a file line by line — cleaner than a while True + break
with open('file.txt') as f:
    while line := f.readline():
        process(line.strip())

# Filter and transform in one comprehension
results = [y for x in data if (y := transform(x)) is not None]

# Avoid re-computing expensive calls
if (n := len(data)) > 100:
    print(f"Too much data: {n} items")  # n already computed
```

### Context Managers (with statement)

Context managers guarantee cleanup — file close, lock release, transaction rollback — even when exceptions occur.

```python
# File handling — the canonical example
with open('data.txt', 'r') as f:
    content = f.read()
# f is automatically closed here, even if an exception occurred

# Multiple context managers
with open('input.txt') as infile, open('output.txt', 'w') as outfile:
    outfile.write(infile.read())

# Custom context manager with contextlib
from contextlib import contextmanager

@contextmanager
def timer():
    import time
    start = time.time()
    try:
        yield
    finally:
        print(f"Elapsed: {time.time() - start:.3f}s")

with timer():
    expensive_operation()
```

### Exception Handling

```python
try:
    result = risky_operation()
except ValueError as e:
    print(f"Value error: {e}")
except (TypeError, KeyError) as e:  # catch multiple types
    print(f"Type or key error: {e}")
except Exception as e:              # catch-all (use sparingly)
    log.error(f"Unexpected: {e}")
    raise                           # re-raise — don't silently swallow
else:
    # Runs only if no exception occurred
    save_result(result)
finally:
    # Always runs — cleanup goes here
    cleanup()
```

**EAFP vs LBYL:**

```python
# LBYL (Look Before You Leap) — check before trying
if key in d:
    value = d[key]

# EAFP (Easier to Ask Forgiveness than Permission) — Python-preferred
try:
    value = d[key]
except KeyError:
    handle_missing()
```

## Practical Application: Real Patterns

### Iterating Over Data Files

```python
import csv

with open('data.csv') as f:
    reader = csv.DictReader(f)
    # Generator pipeline — memory efficient for large files
    processed = (
        transform(row)
        for row in reader
        if row['status'] == 'active'
    )
    for item in processed:
        save(item)
```

### Flattening Nested Data

```python
nested = [[1, 2, 3], [4, 5], [6, 7, 8, 9]]

# List comprehension
flat = [x for sublist in nested for x in sublist]

# Or itertools.chain
from itertools import chain
flat = list(chain.from_iterable(nested))
```

### Early Return Pattern (Guard Clauses)

```python
# BAD — deeply nested
def process_user(user):
    if user is not None:
        if user.is_active:
            if user.has_permission('edit'):
                do_work(user)

# GOOD — fail fast with guard clauses
def process_user(user):
    if user is None:
        return
    if not user.is_active:
        return
    if not user.has_permission('edit'):
        raise PermissionError("Edit access required")
    do_work(user)
```

## Gotchas: What Experts Know

### Modifying a List While Iterating

```python
# BAD — skips elements
items = [1, 2, 3, 4, 5]
for item in items:
    if item % 2 == 0:
        items.remove(item)  # mutates the list being iterated

# GOOD — iterate a copy, or build a new list
items = [x for x in items if x % 2 != 0]
```

### Variable Scope in Comprehensions

```python
# Python 3: comprehensions have their own scope
x = 10
result = [x for x in range(5)]  # this x is local to comprehension
print(x)  # 10 — outer x is unchanged
```

### Generator Exhaustion

```python
gen = (x**2 for x in range(5))
print(list(gen))   # [0, 1, 4, 9, 16]
print(list(gen))   # [] — generator is exhausted, can only iterate once

# If you need to iterate multiple times, use a list
squares = [x**2 for x in range(5)]  # use a list instead
```

### range() Returns an Iterator, Not a List

```python
r = range(10)
print(r)           # range(0, 10) — not a list
print(10 in r)     # True — O(1) membership test
print(list(r))     # [0, 1, 2, 3, 4, 5, 6, 7, 8, 9]
```

## Quick Reference

```python
# Conditional
x = val_if_true if condition else val_if_false

# Iteration patterns
for i, v in enumerate(lst):         # index + value
for a, b in zip(lst1, lst2):        # parallel iteration
for item in reversed(lst):          # reverse
for item in sorted(lst, key=fn):    # sorted

# Comprehensions
[expr for x in it if cond]          # list
{k: v for k, v in items}            # dict
{expr for x in it}                  # set
(expr for x in it)                  # generator (lazy)

# Context manager
with open(path) as f: ...           # auto-close

# Exception handling
try: ...
except SomeError as e: ...
else: ...      # no exception
finally: ...   # always

# Walrus
while chunk := f.read(8192): ...
[y for x in data if (y := fn(x))]
```

---

## 기초를 넘어서는 흐름 제어

if/else와 for 루프는 기본 중의 기본이다. 경험 있는 Python 엔지니어를 구분하는 건 진짜 Pythonic한 패턴들을 아는 것이다. `for`/`else`, 생성자 표현식 vs 리스트 컴프리헨션, 인라인 할당을 위한 walrus 연산자, 리소스 안전을 위한 컨텍스트 관리자, 그리고 Python의 참조 모델이 흐름 제어와 어떻게 상호작용하는지.

## 핵심 개념: 먼저 변수와 참조

Python 변수는 값을 담는 박스가 아니라 객체에 바인딩된 이름(참조)이다.

```python
a = [1, 2]
b = a          # b는 같은 리스트 객체를 가리킴
b.append(3)
print(a)       # [1, 2, 3] — a가 변화를 본다

# 독립성을 위한 깊은 복사
from copy import deepcopy
b = deepcopy(a)  # 완전 독립 복사
```

### 타입과 동일성 확인

```python
a = [1, 2]
b = a
print(a is b)  # True — 같은 객체
print(a == b)  # True — 같은 값

b = [1, 2]
print(a is b)  # False — 다른 객체
print(a == b)  # True — 같은 값
```

**변수 없이 swap:**
```python
a, b = b, a    # Pythonic한 swap
```

## 작동 원리: 제어 흐름 깊이 들어가기

### if / elif / else

```python
x = 42
if x > 100:
    print("large")
elif x > 10:
    print("medium")
else:
    print("small")
```

Python 특유의 동작:
- **들여쓰기가 블록을 정의한다** — 탭과 스페이스를 혼용하면 안 된다. 4 스페이스가 표준(PEP 8).
- **`in` 연산자**로 멤버십 확인: `if x in [1, 2, 3]:`
- **3항 표현식:**

```python
label = "admin" if is_admin else "user"
```

**참/거짓 단축:**
```python
# if len(items) > 0: 대신
if items:
    process(items)

# if name is not None and name != "": 대신
if name:
    greet(name)
```

### for와 잘 안 쓰이는 for/else

```python
for i in range(10):       # 0..9
    pass
for i in range(1, 11):    # 1..10
    pass
for i in range(0, 10, 2): # 0, 2, 4, 6, 8
    pass
```

**for/else** — `else` 블록은 루프가 `break` 없이 완료될 때 실행된다:

```python
# 검색 + 폴백
for item in collection:
    if matches(item):
        result = item
        break
else:
    result = default_value  # break가 없을 때만 실행
```

### enumerate와 zip

```python
# enumerate — 인덱스와 값
fruits = ['apple', 'banana', 'cherry']
for i, fruit in enumerate(fruits, start=1):
    print(f"{i}. {fruit}")

# zip — 병렬 반복
names = ['Alice', 'Bob']
scores = [95, 87]
for name, score in zip(names, scores):
    print(f"{name}: {score}")
```

### 컴프리헨션

```python
# 리스트 컴프리헨션
squares = [x**2 for x in range(10)]
evens = [x for x in range(20) if x % 2 == 0]

# 딕셔너리 컴프리헨션
squared_dict = {x: x**2 for x in range(5)}

# 생성자 표현식 — 지연 평가, 메모리 효율적
total = sum(x**2 for x in range(1000000))  # 전체 리스트를 만들지 않음
```

### Walrus 연산자 := (Python 3.8+)

단일 표현식에서 할당과 평가를 동시에:

```python
# while 루프에서 가장 유용
with open('file.txt') as f:
    while line := f.readline():
        process(line.strip())

# 비싼 계산을 한 번만
if (n := len(data)) > 100:
    print(f"데이터가 너무 많음: {n}개")
```

### 컨텍스트 관리자 (with 문)

예외가 발생해도 파일 닫기, 락 해제, 트랜잭션 롤백을 보장:

```python
# 파일 처리 — 정형화된 예시
with open('data.txt', 'r') as f:
    content = f.read()
# 예외가 있어도 f는 자동으로 닫힘

# 여러 컨텍스트 관리자
with open('input.txt') as infile, open('output.txt', 'w') as outfile:
    outfile.write(infile.read())
```

### 예외 처리

```python
try:
    result = risky_operation()
except ValueError as e:
    print(f"값 오류: {e}")
except (TypeError, KeyError) as e:
    print(f"타입 또는 키 오류: {e}")
except Exception as e:
    log.error(f"예상치 못한 오류: {e}")
    raise                   # 조용히 삼키지 말고 다시 발생
else:
    save_result(result)     # 예외가 없을 때만 실행
finally:
    cleanup()               # 항상 실행
```

## 실전 활용

### 데이터 파일 반복

```python
import csv

with open('data.csv') as f:
    reader = csv.DictReader(f)
    # 생성자 파이프라인 — 대용량 파일에 메모리 효율적
    processed = (
        transform(row)
        for row in reader
        if row['status'] == 'active'
    )
    for item in processed:
        save(item)
```

### 가드 절 패턴 (조기 반환)

```python
# 나쁨 — 깊은 중첩
def process_user(user):
    if user is not None:
        if user.is_active:
            if user.has_permission('edit'):
                do_work(user)

# 좋음 — 가드 절로 조기 실패
def process_user(user):
    if user is None:
        return
    if not user.is_active:
        return
    if not user.has_permission('edit'):
        raise PermissionError("편집 권한 필요")
    do_work(user)
```

## 전문가가 아는 함정들

### 반복 중 리스트 수정

```python
# 나쁨 — 요소를 건너뜀
for item in items:
    if item % 2 == 0:
        items.remove(item)  # 반복 중인 리스트를 변경

# 좋음 — 새 리스트 생성
items = [x for x in items if x % 2 != 0]
```

### 생성자 소진

```python
gen = (x**2 for x in range(5))
print(list(gen))   # [0, 1, 4, 9, 16]
print(list(gen))   # [] — 생성자는 한 번만 반복 가능

# 여러 번 반복이 필요하면 리스트 사용
squares = [x**2 for x in range(5)]
```

## 빠른 참조

```python
# 조건 표현식
x = val_if_true if condition else val_if_false

# 반복 패턴
for i, v in enumerate(lst):         # 인덱스 + 값
for a, b in zip(lst1, lst2):        # 병렬 반복
for item in reversed(lst):          # 역순
for item in sorted(lst, key=fn):    # 정렬

# 컴프리헨션
[expr for x in it if cond]          # 리스트
{k: v for k, v in items}            # 딕셔너리
{expr for x in it}                  # 집합
(expr for x in it)                  # 생성자 (지연 평가)

# 컨텍스트 관리자
with open(path) as f: ...           # 자동 닫기

# 예외 처리
try: ...
except SomeError as e: ...
else: ...      # 예외 없을 때
finally: ...   # 항상

# Walrus
while chunk := f.read(8192): ...
```
