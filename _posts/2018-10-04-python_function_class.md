---
title: 파이썬 함수와 클래스
tags: Python
key: page-python_functions_classes
categories: [Development, Python]
author: hyoeun
---

## 함수

```python
def function_name(parameter):
  return something

def say_ho():
  print("ho~~")

say_ho() # ho~~
```
* return값이 void면 indentation으로 다른 실행문을 계속 쓰면 된다.
함수를 탈출하고 싶으면 return 만 써도 된다.(break같은 느낌으로)

```python
def name(choice, *args)
```
* choice변수 하나와 multiple 인자를 받을 수 있다는 뜻이다.
* name('mul', 1,2,3,4)로 받을 수 있다.
* args는 전체가 튜플() 로 변환되어 함수 내에서 사용가능하게 된다.
* return값이 ```return sum, mul``` 로 했을 경우 (sum, mul)의 튜플이 return된다.
  * 하지만 원칙상으로 항상 1개의 값만 return 되는 것이다.
  ``` python
  def calculator(a, b):
      return a+b, a*b
  a, b = calculator(1,2)
  c, _ = calculator(3,4)
  print(a,b)  # 3, 2
  print(c)    # 7
  ```

```python
def sum_to_ten(n):
  if n < 1:
    return 0
  return sum_to_ten(n-1) + n

print(sum_to_ten(10)) # 55
```
* recursive 가능

```python
def self(name, old, gender=True):
```
* parameter에 default값을 설정 할 수 있다.
  * gender를 parameter로 받지 않아도 기본적으로 True로 작동하게 할 수 있다.
* 따라서 default를 컴파일러가 파악하기 위해서는 가장 오른쪽에서부터 배치해야지 오류가 일어나지 않는다.(가운데나 처음에 오면 안됨)
* 함수 내에서 global 선언으로 외부 변수를 사용할 수 있는데 가급적 이건 사용하지 말자.

## 클래스
* class 내부에서 함수를 정의할 때 항상 맨 앞의 parameter로 self를 넣어줘야 한다.<br>이건 개발 원리와 관계가 있다.
```python
class 이름(<super class name>):
    foo = 0
    def __init__(self, name):
      self.name = name
      self.result = 0
    def skip(self, a,b):
      pass
    def add(self, num):
      self.result += num
      return self.result
```
* init는 constructor이다. self는 계속 붙이는거라 생각하면 된다.

```python
class Vehical(self, wheel):
  def __init__(self, wheel):
    self.wheel = wheel

  def show(self):
    print("This is vehical with " + self.wheel + "wheels")

class Car(Vehical):
  def __init__(self, wheel, capacity:
    super().__init__(self, wheel)
    self.capacity = capacity

  def show(self):
    super().show(self)
    print("This is a car")

class Ford(Car):
  def __init__(self, wheel, capacity, model_name):
    super().__init__(self, wheel, capacity)

x = Ford(4,6,'a1')
```

* class이름으로 상속을 받는다.
* 이름.skip(instance_name,a,b)와 같이 className을 이용해서도 쓸 수 있다.
* method overriding도 가능하다.
* 연산자 overloading
```python
def __add__(self, other):
    pass
def __sub__(self, other):
    pass
def __mul__(self, other):
    pass
def __truediv__(self, other):
    pass
```
* 위의 경우 각 연산자(+,-,*,/) 쓸 때마다 위에서 정의한 그대로 작동된다.

## Main 함수
* if __name__ == "__main__": 로 시작하면 메인함수처럼 쓸 수 있다.
```python
if __name__ == '__main__':
    print("This is main")
```