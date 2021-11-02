---
title: 파이썬 제어문
tags: python
key: page-python_control
cover: /assets/cover/python.png
---

## 변수

* 변수 선언법
```python
a, b = ('string','arr')
(a,b) = 'string, 'arr'
[a,b] = ['string', 'arr']
a = b = 'string'
```
```python
a = [1,2]
b = a # b는 a가 가리키고 있는 object의 주소값을 가리키고 deep copy가 일어나지는 않습니다.
```
* 기본적으로 변수들은 전부 reference type.
* deep copy 하는 방법

   ```python
   from copy import copy

   b = a[:]
   b = copy(a)
   print(a is b) # return값이 False이면 deep copy가 제대로 된 것입니다.
   ```

* sys.getrefcount(x)라고 하면 x object를 가리키는 reference 갯수를 retrun한다. (초기값이 항상 0은 아닐 수 있다.)
* swap은 a,b = b,a로 가능하다.
* 상수는 단순 상수가 아닌 object 입니다. ```type(3) => <class 'int'>```

#### Type 및 Reference Check 방법

* 다음 코드로 data type과 생성자 주소를 확인 할 수 있습니다.
```python
type(s)
id(t)
a is b # a와 b가 동일한 object를 가리키는지 판별.
```

<br>

## IF

```python
if condition:
   statement
elif condition:
   pass
else:
   statement
```
* indentation으로 block을 인지하기에 각별히 주의해야합니다.
* tab or space를 혼합해서 사용하면 안 되고 주로 4 space 사용을 권장합니다.
* 산술 비교 연산자는 c나 java와 동일하고 논리 연산자는 and, or, not이다.
* x in s, x not in s 이라는 조건을 쓸 수 있는데 s는 list, tuple, string에 해당하고 x는 확인하고 싶은 값을 의미합니다.
* pass는 continue와 비슷한 개념으로 if문을 탈출합니다.
* statement가 1줄로 이루어 졌을 때에는 다음과 같은 구문을 사용할 수 있습니다.
```python
if conditon: pass
else: stm
```

<br>
## WHILE

```python
while condition:
   stm
   if condition:
      break
   continue
```

<br>
## FOR
```python
for  변수 in list(or tuple, string):
    stm

for i in range(1,11)
   sum += 1
print(sum) # 55 출력.
```
* range(시작숫자, 끝숫자) or range(끝숫자)에서 끝 숫자는 포함되지 않습니다.
* range(start, stop, step) step씩 만큼 증가하면서 start부터 stop까지 반복합니다.
<br>

```python
def func(array):
  for num in array:
    if num % 2 == 0:
      print(num, "is even number")
      break
    else:
      print(num, "is odd number")
  else:
    print("Compelte for condition")

print("1st Case:")
a = [1]
func(a)

'''
1st Case:
1 is odd number
Compelte for condition
'''

print("2nd Case:")
a = [1,2,3]
func(a)

'''
2nd Case:
1 is odd number
2 is even number
'''
```
* for 구문과 함께 else를 사용하면 for가 종료 조건에 의해 끝났을 경우 else 구문이 실행됩니다.