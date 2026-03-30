---
title: "Python Functions and Classes: The Complete Mental Model"
key: page-python_functions_classes
categories:
- Engineering
- Programming Fundamentals
author: hyoeun
math: false
mathjax_autoNumber: false
image: "/assets/thumbnails/2020-04-12-python_function_class.png"
bilingual: true
date: 2020-04-12 11:38:24
---

## Why the Mental Model Matters More Than Syntax

Python functions and classes look simple on the surface, but the underlying model is genuinely different from Java or C++. Functions are objects. Classes are objects. Everything is an object. This isn't marketing — it has real consequences for how closures work, why decorators are possible, what `self` actually means, and when to use `@classmethod` vs `@staticmethod`.

Engineers who understand this model write cleaner abstractions and fewer surprises. Those who don't create subtle bugs around closures, mutability, and inheritance.

## Core Concepts: Functions as First-Class Citizens

In Python, functions are objects of type `function`. You can pass them as arguments, return them from other functions, assign them to variables, and store them in data structures.

```python
def greet(name):
    return f"Hello, {name}"

# Assign to a variable
say_hello = greet
print(say_hello("Alice"))   # Hello, Alice

# Pass as an argument
def apply(func, value):
    return func(value)

print(apply(greet, "Bob"))  # Hello, Bob

# Store in a list
operations = [str.upper, str.lower, str.strip]
for op in operations:
    print(op("  Hello  "))
```

## How It Works: Deep Dive into Functions

### Parameters and Argument Patterns

```python
# Positional arguments
def add(a, b):
    return a + b

# Default arguments — evaluated ONCE at definition, not at call
def greet(name, greeting="Hello"):
    return f"{greeting}, {name}"

# *args — variable positional arguments (collected as tuple)
def sum_all(*args):
    return sum(args)

sum_all(1, 2, 3, 4)   # 10

# **kwargs — variable keyword arguments (collected as dict)
def configure(**kwargs):
    for key, value in kwargs.items():
        print(f"{key} = {value}")

configure(host="localhost", port=5432, debug=True)

# Keyword-only arguments (after *)
def connect(host, *, port=5432, timeout=30):
    pass

connect("db.example.com", port=5433)    # works
connect("db.example.com", 5433)         # TypeError — port is keyword-only

# Full signature pattern
def full_function(pos_only, /, normal, *, kw_only, **kwargs):
    pass
```

### Multiple Return Values

Functions can only return one object, but a tuple is one object:

```python
def stats(numbers):
    return min(numbers), max(numbers), sum(numbers) / len(numbers)

low, high, avg = stats([1, 2, 3, 4, 5])

# Ignore specific values with _
low, _, avg = stats([1, 2, 3, 4, 5])  # discard max
```

### Closures

A closure is a function that captures variables from its enclosing scope. The closure carries its own copy of those variables:

```python
def make_counter(start=0):
    count = start

    def counter():
        nonlocal count    # declare we're modifying the enclosing scope's variable
        count += 1
        return count

    return counter

c1 = make_counter()
c2 = make_counter(10)
print(c1())   # 1
print(c1())   # 2
print(c2())   # 11  — independent from c1
```

**Classic closure bug** — loop variable capture:

```python
# BAD — all functions capture the same variable i
funcs = [lambda: i for i in range(5)]
print([f() for f in funcs])   # [4, 4, 4, 4, 4] — all capture last i

# GOOD — capture the value at creation time with default argument
funcs = [lambda i=i: i for i in range(5)]
print([f() for f in funcs])   # [0, 1, 2, 3, 4]
```

### Decorators

A decorator is a function that takes a function and returns a (usually enhanced) function. The `@` syntax is syntactic sugar:

```python
@decorator
def func():
    pass

# Equivalent to:
func = decorator(func)
```

**Writing a proper decorator with `functools.wraps`:**

```python
from functools import wraps
import time

def timer(func):
    @wraps(func)  # preserves __name__, __doc__, etc.
    def wrapper(*args, **kwargs):
        start = time.time()
        result = func(*args, **kwargs)
        elapsed = time.time() - start
        print(f"{func.__name__} took {elapsed:.3f}s")
        return result
    return wrapper

@timer
def slow_function():
    time.sleep(1)

slow_function()  # "slow_function took 1.001s"
print(slow_function.__name__)  # "slow_function" — not "wrapper" (thanks to @wraps)
```

**Decorator with arguments:**

```python
def retry(times=3):
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            for attempt in range(times):
                try:
                    return func(*args, **kwargs)
                except Exception as e:
                    if attempt == times - 1:
                        raise
                    print(f"Attempt {attempt + 1} failed: {e}")
        return wrapper
    return decorator

@retry(times=5)
def unstable_network_call():
    pass
```

### functools.partial

Creates a new callable with some arguments pre-filled:

```python
from functools import partial

def power(base, exponent):
    return base ** exponent

square = partial(power, exponent=2)
cube = partial(power, exponent=3)

print(square(5))   # 25
print(cube(3))     # 27
```

## How Classes Work: The Object Model

### Class Definition and `self`

```python
class BankAccount:
    # Class variable — shared across ALL instances
    interest_rate = 0.05

    def __init__(self, owner: str, balance: float = 0.0):
        # Instance variables — unique to each instance
        self.owner = owner
        self.balance = balance

    def deposit(self, amount: float) -> float:
        self.balance += amount
        return self.balance

    def __repr__(self):
        return f"BankAccount(owner={self.owner!r}, balance={self.balance})"
```

`self` is a reference to the current instance. Python passes it automatically — it's not magic, it's just a convention for the first parameter.

```python
acc = BankAccount("Alice", 1000)
acc.deposit(500)   # Python translates this to BankAccount.deposit(acc, 500)
```

### Class vs Instance Variables

```python
class Counter:
    count = 0          # class variable

    def __init__(self):
        Counter.count += 1
        self.id = Counter.count   # instance variable

c1 = Counter()
c2 = Counter()
print(Counter.count)  # 2
print(c1.id)          # 1
print(c2.id)          # 2
```

### `@property` — Computed Attributes

```python
class Circle:
    def __init__(self, radius: float):
        self._radius = radius

    @property
    def radius(self) -> float:
        return self._radius

    @radius.setter
    def radius(self, value: float):
        if value < 0:
            raise ValueError("Radius cannot be negative")
        self._radius = value

    @property
    def area(self) -> float:
        import math
        return math.pi * self._radius ** 2

c = Circle(5)
print(c.area)     # 78.53...
c.radius = 10     # calls setter
c.radius = -1     # raises ValueError
```

### `@classmethod` and `@staticmethod`

```python
class Date:
    def __init__(self, year, month, day):
        self.year = year
        self.month = month
        self.day = day

    @classmethod
    def from_string(cls, date_string):
        """Alternative constructor — receives the class, not an instance"""
        year, month, day = map(int, date_string.split('-'))
        return cls(year, month, day)

    @staticmethod
    def is_valid_date(year, month, day):
        """Utility function — no access to class or instance"""
        return 1 <= month <= 12 and 1 <= day <= 31

d = Date.from_string("2024-01-15")
print(Date.is_valid_date(2024, 1, 15))  # True
```

**When to use each:**
- `def method(self)` — needs access to instance data
- `@classmethod` — alternative constructors, factory methods, accessing class variables
- `@staticmethod` — utility functions that logically belong to the class but don't need instance or class

### Inheritance and super()

```python
class Animal:
    def __init__(self, name: str):
        self.name = name

    def speak(self) -> str:
        raise NotImplementedError

    def __repr__(self):
        return f"{type(self).__name__}(name={self.name!r})"

class Dog(Animal):
    def __init__(self, name: str, breed: str):
        super().__init__(name)     # call parent __init__
        self.breed = breed

    def speak(self) -> str:
        return f"{self.name} says Woof!"

class Cat(Animal):
    def speak(self) -> str:
        return f"{self.name} says Meow!"

# Polymorphism
animals = [Dog("Rex", "Labrador"), Cat("Whiskers")]
for animal in animals:
    print(animal.speak())
```

### Dunder (Magic) Methods

```python
class Vector:
    def __init__(self, x, y):
        self.x = x
        self.y = y

    def __repr__(self):       # developer-facing string
        return f"Vector({self.x}, {self.y})"

    def __str__(self):        # user-facing string
        return f"({self.x}, {self.y})"

    def __add__(self, other):    # v1 + v2
        return Vector(self.x + other.x, self.y + other.y)

    def __len__(self):        # len(v)
        return 2

    def __eq__(self, other):  # v1 == v2
        return self.x == other.x and self.y == other.y

    def __iter__(self):       # for component in v:
        yield self.x
        yield self.y

v1 = Vector(1, 2)
v2 = Vector(3, 4)
print(v1 + v2)      # (4, 6)
print(v1 == v2)     # False
print(list(v1))     # [1, 2]
```

### dataclass — Boilerplate Elimination

```python
from dataclasses import dataclass, field

@dataclass
class Config:
    host: str
    port: int = 5432
    tags: list = field(default_factory=list)  # mutable default — use field()
    debug: bool = False

cfg = Config("localhost", port=5433)
print(cfg)  # Config(host='localhost', port=5433, tags=[], debug=False)
# __repr__, __eq__, __init__ are auto-generated
```

## Practical Application

### Entry Point Pattern

```python
def main():
    # All top-level logic here
    process()

if __name__ == "__main__":
    main()
```

`__name__` is `"__main__"` when the file is run directly, and the module name when imported. This pattern ensures `main()` is not called when the file is imported as a module.

### Abstract Base Classes

```python
from abc import ABC, abstractmethod

class Storage(ABC):
    @abstractmethod
    def read(self, key: str) -> bytes:
        ...

    @abstractmethod
    def write(self, key: str, data: bytes) -> None:
        ...

class S3Storage(Storage):
    def read(self, key: str) -> bytes:
        # real implementation
        ...

    def write(self, key: str, data: bytes) -> None:
        ...

# Cannot instantiate ABC directly
# storage = Storage()  → TypeError
storage = S3Storage()  # OK
```

## Gotchas: What Experts Know

### Mutable Default Arguments in Methods

```python
# BAD — the list is created once, shared across all calls
class Processor:
    def process(self, items=[]):
        items.append("processed")
        return items

# GOOD — use None sentinel
class Processor:
    def process(self, items=None):
        if items is None:
            items = []
        items.append("processed")
        return items
```

### Class Variable vs Instance Variable Shadowing

```python
class Dog:
    tricks = []  # class variable — SHARED

    def add_trick(self, trick):
        self.tricks.append(trick)  # modifies the shared class variable!

# CORRECT pattern
class Dog:
    def __init__(self):
        self.tricks = []  # each instance gets its own list
```

### `super()` in Multiple Inheritance (MRO)

Python uses C3 linearization for method resolution order. Always use `super()` instead of explicitly calling parent classes — it handles MRO correctly:

```python
class A:
    def method(self):
        print("A")
        super().method()  # will call B.method(), not object.method()

class B:
    def method(self):
        print("B")

class C(A, B):
    def method(self):
        print("C")
        super().method()  # calls A.method() per MRO

C().method()  # C → A → B
```

## Quick Reference

```python
# Function argument types
def f(pos_only, /, normal, *, kw_only, **kwargs): ...

# Decorator pattern
from functools import wraps
def my_decorator(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        return func(*args, **kwargs)
    return wrapper

# Class structure
class MyClass(Parent):
    class_var = value

    def __init__(self, arg):
        super().__init__()
        self.instance_var = arg

    @property
    def computed(self): ...

    @classmethod
    def from_something(cls, data): ...

    @staticmethod
    def utility(arg): ...

    def __repr__(self): ...

# Entry point
if __name__ == "__main__":
    main()
```

---

## 문법보다 멘탈 모델이 더 중요한 이유

Python의 함수와 클래스는 표면상 간단해 보이지만, 내부 모델은 Java나 C++와 진짜로 다르다. 함수는 객체이고, 클래스도 객체이고, 모든 것이 객체다. 이것은 마케팅이 아니라 실제 결과를 가져온다. 클로저의 작동 방식, 데코레이터가 왜 가능한지, `self`가 실제로 무엇을 의미하는지, `@classmethod`와 `@staticmethod`를 언제 사용하는지.

## 핵심 개념: 일급 시민으로서의 함수

Python에서 함수는 `function` 타입의 객체다. 인수로 전달하고, 다른 함수에서 반환하고, 변수에 할당하고, 데이터 구조에 저장할 수 있다.

```python
def greet(name):
    return f"Hello, {name}"

say_hello = greet
print(say_hello("Alice"))   # Hello, Alice

def apply(func, value):
    return func(value)

print(apply(greet, "Bob"))  # Hello, Bob
```

## 작동 원리: 함수 깊이 들어가기

### 매개변수와 인수 패턴

```python
# 기본 인수 — 정의 시 한 번만 평가됨
def greet(name, greeting="Hello"):
    return f"{greeting}, {name}"

# *args — 가변 위치 인수 (튜플로 수집)
def sum_all(*args):
    return sum(args)

# **kwargs — 가변 키워드 인수 (딕셔너리로 수집)
def configure(**kwargs):
    for key, value in kwargs.items():
        print(f"{key} = {value}")

# 키워드 전용 인수 (* 뒤)
def connect(host, *, port=5432, timeout=30):
    pass

connect("db.example.com", port=5433)    # 가능
connect("db.example.com", 5433)         # TypeError
```

### 클로저

클로저는 둘러싸는 범위의 변수를 캡처하는 함수다:

```python
def make_counter(start=0):
    count = start

    def counter():
        nonlocal count
        count += 1
        return count

    return counter

c1 = make_counter()
c2 = make_counter(10)
print(c1())   # 1
print(c2())   # 11 — c1과 독립
```

**클래식 클로저 버그** — 루프 변수 캡처:

```python
# 나쁨 — 모든 함수가 같은 변수 i를 캡처
funcs = [lambda: i for i in range(5)]
print([f() for f in funcs])   # [4, 4, 4, 4, 4]

# 좋음 — 기본 인수로 생성 시점의 값 캡처
funcs = [lambda i=i: i for i in range(5)]
print([f() for f in funcs])   # [0, 1, 2, 3, 4]
```

### 데코레이터

데코레이터는 함수를 받아 (보통 강화된) 함수를 반환하는 함수다:

```python
from functools import wraps
import time

def timer(func):
    @wraps(func)  # __name__, __doc__ 등을 보존
    def wrapper(*args, **kwargs):
        start = time.time()
        result = func(*args, **kwargs)
        elapsed = time.time() - start
        print(f"{func.__name__}에 {elapsed:.3f}초 소요")
        return result
    return wrapper

@timer
def slow_function():
    time.sleep(1)
```

## 클래스의 작동 원리: 객체 모델

### 클래스 정의와 `self`

```python
class BankAccount:
    interest_rate = 0.05   # 클래스 변수 — 모든 인스턴스가 공유

    def __init__(self, owner: str, balance: float = 0.0):
        self.owner = owner      # 인스턴스 변수 — 각 인스턴스마다 고유
        self.balance = balance

    def deposit(self, amount: float) -> float:
        self.balance += amount
        return self.balance
```

`self`는 현재 인스턴스에 대한 참조다. Python이 자동으로 전달한다.

### `@property`, `@classmethod`, `@staticmethod`

```python
class Date:
    def __init__(self, year, month, day):
        self.year = year
        self.month = month
        self.day = day

    @classmethod
    def from_string(cls, date_string):
        """대안 생성자 — 클래스를 받음, 인스턴스가 아님"""
        year, month, day = map(int, date_string.split('-'))
        return cls(year, month, day)

    @staticmethod
    def is_valid_date(year, month, day):
        """유틸리티 함수 — 클래스나 인스턴스 접근 불필요"""
        return 1 <= month <= 12 and 1 <= day <= 31
```

**언제 어떤 것을 사용하나:**
- `def method(self)` — 인스턴스 데이터 접근이 필요할 때
- `@classmethod` — 대안 생성자, 팩토리 메서드, 클래스 변수 접근
- `@staticmethod` — 클래스에 논리적으로 속하지만 인스턴스나 클래스가 필요 없는 유틸리티

### 상속과 super()

```python
class Animal:
    def __init__(self, name: str):
        self.name = name

    def speak(self) -> str:
        raise NotImplementedError

class Dog(Animal):
    def __init__(self, name: str, breed: str):
        super().__init__(name)    # 부모 __init__ 호출
        self.breed = breed

    def speak(self) -> str:
        return f"{self.name}이 왈왈!"

# 다형성
animals = [Dog("Rex", "Labrador"), Cat("나비")]
for animal in animals:
    print(animal.speak())
```

### 특수 메서드 (Dunder Methods)

```python
class Vector:
    def __init__(self, x, y):
        self.x = x
        self.y = y

    def __repr__(self):       # 개발자용 문자열
        return f"Vector({self.x}, {self.y})"

    def __add__(self, other):    # v1 + v2
        return Vector(self.x + other.x, self.y + other.y)

    def __eq__(self, other):  # v1 == v2
        return self.x == other.x and self.y == other.y
```

### dataclass — 보일러플레이트 제거

```python
from dataclasses import dataclass, field

@dataclass
class Config:
    host: str
    port: int = 5432
    tags: list = field(default_factory=list)  # 뮤터블 기본값
    debug: bool = False

# __repr__, __eq__, __init__ 자동 생성
```

## 전문가가 아는 함정들

### 클래스 변수 vs 인스턴스 변수 숨기기

```python
# 나쁨 — tricks이 모든 인스턴스가 공유하는 클래스 변수
class Dog:
    tricks = []
    def add_trick(self, trick):
        self.tricks.append(trick)  # 공유 클래스 변수를 수정!

# 좋음
class Dog:
    def __init__(self):
        self.tricks = []  # 각 인스턴스가 자체 리스트를 가짐
```

## 빠른 참조

```python
# 함수 인수 타입
def f(pos_only, /, normal, *, kw_only, **kwargs): ...

# 데코레이터 패턴
from functools import wraps
def my_decorator(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        return func(*args, **kwargs)
    return wrapper

# 클래스 구조
class MyClass(Parent):
    class_var = value
    def __init__(self, arg):
        super().__init__()
        self.instance_var = arg
    @property
    def computed(self): ...
    @classmethod
    def from_something(cls, data): ...
    @staticmethod
    def utility(arg): ...

# 진입점
if __name__ == "__main__":
    main()
```
