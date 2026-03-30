---
title: "Python Data Types: What Every Engineer Should Know"
key: page-python_data_types
categories:
- Engineering
- Programming Fundamentals
author: hyoeun
math: false
mathjax_autoNumber: false
image: "/assets/thumbnails/2020-03-14-python_data_type.png"
bilingual: true
date: 2020-03-14 06:36:00
---

## Why Data Types Matter More in Python Than You Think

Python's dynamic typing is a double-edged sword. The flexibility speeds up prototyping, but a poor mental model of Python's type system causes bugs that are genuinely hard to find: mutable default arguments, surprising equality behavior, unexpected memory behavior under load, and performance characteristics that don't match expectations.

This post builds the correct mental model — not just "what are the types" but how they behave in memory, where they're fast, and where they silently do the wrong thing.

## Core Concepts: Python's Type System

### Interpreter vs Compiler

Python is an interpreted language — each line is parsed and executed at runtime. This means type information exists at runtime, not compile time. There's no static type checking unless you add it explicitly with mypy or Pyright.

```python
x = 42        # x is int
x = "hello"   # x is now str — Python allows this
x = [1, 2]    # x is now list — no error
```

### The Mutability Divide

This is the most important concept in Python's type system.

**Immutable types** — value cannot change after creation:
```
int, float, bool, complex, str, bytes, tuple, frozenset, range
```

**Mutable types** — value can be modified in-place:
```
list, dict, set, bytearray, user-defined classes (by default)
```

Immutability has a critical implication: immutable objects can be used as dictionary keys and set members. Mutable objects cannot.

### Scalar Types

- **int** — arbitrary precision. Python integers never overflow (unlike C/Java). `2**1000` works fine.
- **float** — IEEE 754 double precision. `0.1 + 0.2 != 0.3` is real.
- **bool** — subclass of int. `True == 1` and `False == 0`.
- **None** — singleton. There is only one `None` object; use `is None` not `== None`.
- **complex** — `3+4j`. Rarely needed outside scientific computing.

## How It Works: Deep Dive

### Integer: Arbitrary Precision and Interning

Python integers have no fixed size — they grow as needed. This is why `2**1000` doesn't overflow:

```python
print(2**1000)
# 10715086071862673209484250490600018105614048117055336074437503883703510511249361224931983788156958581275946729175531468251871452856923140435984577574698574803934567774824230985421074605062371141877954182153046474983581941267398767559165543946077062914571196477686542167660429831652624386837205668069376
```

CPython interns small integers (-5 to 256) — reuses the same object:

```python
a = 256
b = 256
print(a is b)  # True — same object

a = 257
b = 257
print(a is b)  # False — different objects (implementation detail, don't rely on this)
```

### Float: IEEE 754 and Precision Gotchas

```python
print(0.1 + 0.2)           # 0.30000000000000004
print(0.1 + 0.2 == 0.3)    # False

# Fix: use decimal for financial math
from decimal import Decimal
print(Decimal('0.1') + Decimal('0.2'))  # 0.3

# Or use round() for display
print(round(0.1 + 0.2, 10) == round(0.3, 10))  # True

# Integer division
print(3 / 4)    # 0.75  (true division in Python 3)
print(3 // 4)   # 0     (floor division)
print(3.1 // 2.7)  # 1.0  (floor division with floats)
```

### String: Immutable, Interned, Unicode

Strings in Python 3 are Unicode by default (UTF-8 internally stored as latin-1, UCS-2, or UCS-4 depending on content — CPython optimizes this).

```python
# Immutability — strings cannot be modified
s = "hello"
# s[0] = 'H'  → TypeError

# String formatting (modern f-strings are fastest)
name, count = "Alice", 42
old_way = "Hello %s, you have %d messages" % (name, count)
format_way = "Hello {}, you have {} messages".format(name, count)
f_string = f"Hello {name}, you have {count} messages"  # preferred

# Useful string methods
s = "  hello world  "
print(s.strip())           # "hello world"
print(s.upper())           # "  HELLO WORLD  "
print(s.split())           # ["hello", "world"]
print("tr".join(["s", "ing"]))  # "string"
print("hello".find("ll"))  # 2
print("hello".count("l"))  # 2
print("hello".replace("l", "L"))  # "heLLo"
```

### List: Dynamic Arrays

Lists are backed by dynamic arrays (C arrays that grow by ~1.125x when full). Random access is O(1), append is amortized O(1), but insert at index 0 is O(n).

```python
a = [1, 2, 3]

# Modification — lists are mutable
a.append(4)          # [1, 2, 3, 4]
a.insert(1, 10)      # [1, 10, 2, 3, 4]
a.remove(10)         # removes first occurrence of 10
popped = a.pop()     # removes and returns last element
a.sort()             # in-place sort (Timsort, stable)
a.reverse()          # in-place reverse

# Slicing — creates a new list
print(a[1:3])        # elements at index 1 and 2
print(a[::-1])       # reversed copy
print(a[::2])        # every other element

# Shallow copy pitfall
b = a          # b and a point to same list
b = a[:]       # shallow copy — new list, same element references
b = a.copy()   # same as a[:]
from copy import deepcopy
b = deepcopy(a)  # full independent copy (for nested structures)

# List comprehensions — Pythonic and fast
squares = [x**2 for x in range(10)]
evens = [x for x in range(20) if x % 2 == 0]
matrix_transpose = [[row[i] for row in matrix] for i in range(len(matrix[0]))]
```

### Tuple: Immutable Sequences

Tuples are faster than lists for iteration and use less memory. Use them for fixed-size records, return values, and dictionary keys.

```python
empty = ()
single = (5,)          # trailing comma required for single-element
point = (3, 4)
x, y = point           # unpacking

# Swap without temp variable
a, b = b, a

# Multiple return values (actually returns a tuple)
def min_max(lst):
    return min(lst), max(lst)

low, high = min_max([3, 1, 4, 1, 5, 9])

# Named tuples for readability
from collections import namedtuple
Point = namedtuple('Point', ['x', 'y'])
p = Point(3, 4)
print(p.x, p.y)    # 3 4
```

### Dictionary: Hash Maps with Insertion Order

Since CPython 3.7, dicts maintain insertion order. This is now guaranteed by the language spec (not just CPython).

```python
d = {'a': 1, 'b': 2, 'c': 3}

# Access and modification
print(d['a'])         # 1
d['d'] = 4            # add new key
del d['a']            # remove key

# Safe access
print(d.get('missing'))            # None (no KeyError)
print(d.get('missing', 'default')) # 'default'

# Iteration
for k, v in d.items():    # key-value pairs
    print(k, v)
for k in d.keys():         # keys
    pass
for v in d.values():       # values
    pass

# Dict comprehension
squared = {x: x**2 for x in range(5)}  # {0:0, 1:1, 2:4, 3:9, 4:16}

# Merge dicts (Python 3.9+)
merged = d1 | d2

# defaultdict for cleaner accumulation
from collections import defaultdict
word_count = defaultdict(int)
for word in text.split():
    word_count[word] += 1
```

### Set: Hash-Based Unordered Collections

Sets provide O(1) membership testing, unlike lists (O(n)). Use them for deduplication and membership checks.

```python
a = {1, 2, 3, 4, 5}
b = {3, 4, 5, 6, 7}

# Set operations
print(a | b)   # union: {1, 2, 3, 4, 5, 6, 7}
print(a & b)   # intersection: {3, 4, 5}
print(a - b)   # difference: {1, 2}
print(a ^ b)   # symmetric difference: {1, 2, 6, 7}

# Membership (O(1))
print(3 in a)  # True

# Modification
a.add(6)
a.remove(1)    # KeyError if not found
a.discard(99)  # safe — no error if not found

# Empty set — must use set(), not {} (that's a dict)
empty_set = set()
```

## Practical Application: Choosing the Right Type

### Performance-Conscious Type Selection

```python
import sys

# Memory comparison
lst = list(range(1000))
tup = tuple(range(1000))
print(sys.getsizeof(lst))  # larger (dynamic array overhead)
print(sys.getsizeof(tup))  # smaller (fixed size)

# Membership test performance
import timeit
lst = list(range(10000))
st = set(range(10000))

# List: O(n) — scans entire list
timeit.timeit(lambda: 9999 in lst, number=10000)  # ~slow

# Set: O(1) — hash lookup
timeit.timeit(lambda: 9999 in st, number=10000)   # ~fast

# Rule: if you do repeated membership checks, convert list to set
```

### Hashability: Why Some Types Can't Be Dict Keys

An object is **hashable** if it has a `__hash__()` method that returns a consistent value over its lifetime, and an `__eq__()` method.

Immutable types are hashable. Mutable types are not (by default).

```python
# Hashable — can be dict keys or set members
hash(42)
hash("string")
hash((1, 2, 3))        # tuple of hashables
hash(frozenset([1,2])) # frozenset

# Not hashable — will raise TypeError
hash([1, 2, 3])        # TypeError: unhashable type: 'list'
hash({1: 'a'})         # TypeError: unhashable type: 'dict'
hash({1, 2, 3})        # TypeError: unhashable type: 'set'

# Use frozenset as a hashable set
fs = frozenset([1, 2, 3])
d = {fs: "value"}  # works fine
```

## Gotchas: What Experts Know

### Mutable Default Argument (Classic Python Bug)

```python
# BAD — the default list is created ONCE at function definition
def append_to(element, lst=[]):
    lst.append(element)
    return lst

print(append_to(1))  # [1]
print(append_to(2))  # [1, 2]  ← bug! reuses same list

# GOOD — use None as sentinel
def append_to(element, lst=None):
    if lst is None:
        lst = []
    lst.append(element)
    return lst
```

### `is` vs `==`

```python
# == checks value equality
# is checks identity (same object in memory)

a = [1, 2, 3]
b = [1, 2, 3]
print(a == b)  # True — same value
print(a is b)  # False — different objects

# None comparison: always use 'is'
x = None
if x is None:   # correct
    pass
if x == None:   # works but misleading; custom __eq__ could interfere
    pass
```

### String Concatenation in Loops

```python
# BAD — creates a new string object each iteration, O(n²) total
result = ""
for word in words:
    result += word  # each += creates a new string

# GOOD — join is O(n)
result = "".join(words)
```

### Truthiness Rules

```python
# These are all falsy:
bool(0)       # False
bool(0.0)     # False
bool("")      # False
bool([])      # False
bool({})      # False
bool(set())   # False
bool(None)    # False

# Everything else is truthy
bool([0])     # True — list with one element
bool("False") # True — non-empty string
```

## Quick Reference

### Type Cheat Sheet

| Type | Mutable | Ordered | Duplicate OK | Key/Member |
|:--|:--:|:--:|:--:|:--:|
| `int` | ✗ | — | — | ✓ |
| `float` | ✗ | — | — | ✓ |
| `str` | ✗ | ✓ | ✓ | ✓ |
| `tuple` | ✗ | ✓ | ✓ | ✓ |
| `frozenset` | ✗ | ✗ | ✗ | ✓ |
| `list` | ✓ | ✓ | ✓ | ✗ |
| `dict` | ✓ | ✓ (insertion) | keys: ✗ | ✗ |
| `set` | ✓ | ✗ | ✗ | ✗ |

### Type Checking

```python
type(x)           # returns exact type
isinstance(x, int)             # True if x is int or subclass
isinstance(x, (int, float))    # True if x is int or float
```

---

## Python 데이터 타입이 생각보다 중요한 이유

Python의 동적 타이핑은 양날의 검이다. 유연성이 프로토타이핑을 빠르게 해주지만, 잘못된 타입 시스템 이해는 찾기 어려운 버그를 만든다. 뮤터블 기본 인수, 예상치 못한 동등성 동작, 부하 하에서의 메모리 동작, 기대와 다른 성능 특성 등.

이 포스팅은 단순히 "타입이 무엇인가"가 아니라, 메모리에서 어떻게 동작하는지, 언제 빠른지, 언제 조용히 잘못되는지를 다룬다.

## 핵심 개념: Python 타입 시스템

### 인터프리터 언어

Python은 인터프리터 언어다. 각 줄이 런타임에 파싱되고 실행된다. 타입 정보는 컴파일 타임이 아닌 런타임에 존재한다.

### 가변성의 구분

이것이 Python 타입 시스템에서 가장 중요한 개념이다.

**불변(Immutable) 타입** — 생성 후 값 변경 불가:
```
int, float, bool, complex, str, bytes, tuple, frozenset, range
```

**가변(Mutable) 타입** — 내부 값 변경 가능:
```
list, dict, set, bytearray, 사용자 정의 클래스 (기본적으로)
```

불변성의 핵심 의미: 불변 객체는 딕셔너리 키와 집합 멤버로 사용 가능하다. 가변 객체는 불가.

### 스칼라 타입

- **int** — 임의 정밀도. Python 정수는 절대 오버플로우하지 않는다.
- **float** — IEEE 754 배정밀도. `0.1 + 0.2 != 0.3`은 실제 문제다.
- **bool** — int의 서브클래스. `True == 1`, `False == 0`.
- **None** — 싱글톤. `is None`으로 비교하라, `== None`이 아니라.

## 작동 원리: 깊이 들어가기

### 정수: 임의 정밀도와 인터닝

Python 정수는 크기 제한이 없다. `2**1000`이 잘 동작한다. CPython은 작은 정수(-5~256)를 인터닝한다 — 같은 객체를 재사용:

```python
a = 256; b = 256
print(a is b)  # True — 같은 객체

a = 257; b = 257
print(a is b)  # False — 다른 객체 (구현 세부사항, 의존하지 말 것)
```

### 부동소수점: IEEE 754 함정

```python
print(0.1 + 0.2)           # 0.30000000000000004
print(0.1 + 0.2 == 0.3)    # False

# 금융 계산에는 Decimal 사용
from decimal import Decimal
print(Decimal('0.1') + Decimal('0.2'))  # 0.3

# 나눗셈
print(3 / 4)    # 0.75  (Python 3에서 진짜 나눗셈)
print(3 // 4)   # 0     (나머지 버림)
```

### 문자열: 불변, 인터닝, 유니코드

Python 3 문자열은 기본적으로 유니코드다.

```python
# f-string이 가장 빠름 (권장)
name, count = "Alice", 42
f_string = f"Hello {name}, you have {count} messages"

# 유용한 문자열 메서드
s = "  hello world  "
s.strip()            # "hello world"
s.upper()            # "  HELLO WORLD  "
s.split()            # ["hello", "world"]
"hello".find("ll")   # 2
"hello".replace("l", "L")  # "heLLo"
```

### 리스트: 동적 배열

리스트는 동적 배열로 구현된다. 랜덤 접근 O(1), append 분할상각 O(1), 인덱스 0 삽입은 O(n).

```python
a = [1, 2, 3]
a.append(4)          # [1, 2, 3, 4]
a.insert(1, 10)      # [1, 10, 2, 3, 4]
a.sort()             # 제자리 정렬 (Timsort, 안정적)

# 얕은 복사 함정
b = a          # 같은 리스트를 가리킴
b = a[:]       # 새 리스트 (얕은 복사)
from copy import deepcopy
b = deepcopy(a)  # 완전 독립 복사

# 리스트 컴프리헨션 — Pythonic하고 빠름
squares = [x**2 for x in range(10)]
evens = [x for x in range(20) if x % 2 == 0]
```

### 딕셔너리: CPython 3.7+에서 삽입 순서 보장

```python
d = {'a': 1, 'b': 2}

# 안전한 접근
d.get('missing', 'default')  # KeyError 없음

# 딕셔너리 컴프리헨션
squared = {x: x**2 for x in range(5)}

# 병합 (Python 3.9+)
merged = d1 | d2
```

### 집합: 해시 기반 순서 없는 컬렉션

O(1) 멤버십 테스트. 중복 제거와 멤버십 확인에 사용.

```python
a = {1, 2, 3, 4, 5}
b = {3, 4, 5, 6, 7}

print(a | b)   # 합집합
print(a & b)   # 교집합
print(a - b)   # 차집합
print(a ^ b)   # 대칭 차집합

# 빈 집합은 반드시 set()으로 — {}는 딕셔너리
empty_set = set()
```

## 실전 활용: 올바른 타입 선택

### 성능을 고려한 타입 선택

```python
import sys

# 멤버십 테스트 성능
lst = list(range(10000))
st = set(range(10000))

# 리스트: O(n) — 전체 스캔
# 집합: O(1) — 해시 조회
# 반복 멤버십 검사 → 리스트를 집합으로 변환하라
```

### 해시 가능성

```python
# 해시 가능 — 딕셔너리 키나 집합 멤버 가능
hash(42)
hash("string")
hash((1, 2, 3))
hash(frozenset([1,2]))

# 해시 불가능 — TypeError 발생
hash([1, 2, 3])    # TypeError: unhashable type: 'list'
hash({1: 'a'})     # TypeError: unhashable type: 'dict'
```

## 전문가가 아는 함정들

### 뮤터블 기본 인수 (클래식 Python 버그)

```python
# 나쁨 — 기본 리스트가 함수 정의 시 딱 한 번 생성됨
def append_to(element, lst=[]):
    lst.append(element)
    return lst

print(append_to(1))  # [1]
print(append_to(2))  # [1, 2] ← 버그! 같은 리스트를 재사용

# 좋음 — None을 센티넬로 사용
def append_to(element, lst=None):
    if lst is None:
        lst = []
    lst.append(element)
    return lst
```

### `is` vs `==`

```python
# ==는 값 동등성 확인
# is는 동일성 확인 (메모리의 같은 객체)

a = [1, 2, 3]; b = [1, 2, 3]
print(a == b)  # True — 같은 값
print(a is b)  # False — 다른 객체

# None은 항상 is로 비교
if x is None:   # 올바름
    pass
```

### 루프에서 문자열 연결

```python
# 나쁨 — 반복마다 새 문자열 객체 생성, O(n²)
result = ""
for word in words:
    result += word

# 좋음 — join은 O(n)
result = "".join(words)
```

### 참/거짓 규칙

```python
# 모두 False:
bool(0), bool(""), bool([]), bool({}), bool(set()), bool(None)

# True인 함정:
bool([0])     # True — 원소가 있는 리스트
bool("False") # True — 비어있지 않은 문자열
```

## 빠른 참조

### 타입 치트시트

| 타입 | 가변 | 순서 | 중복 | 키/멤버 가능 |
|:--|:--:|:--:|:--:|:--:|
| `int` | ✗ | — | — | ✓ |
| `float` | ✗ | — | — | ✓ |
| `str` | ✗ | ✓ | ✓ | ✓ |
| `tuple` | ✗ | ✓ | ✓ | ✓ |
| `frozenset` | ✗ | ✗ | ✗ | ✓ |
| `list` | ✓ | ✓ | ✓ | ✗ |
| `dict` | ✓ | ✓ (삽입순) | 키: ✗ | ✗ |
| `set` | ✓ | ✗ | ✗ | ✗ |

### 타입 확인

```python
type(x)                         # 정확한 타입 반환
isinstance(x, int)              # int 또는 서브클래스면 True
isinstance(x, (int, float))     # int 또는 float이면 True
```
