---
title: 파이썬 Data type
tags: Python
key: page-python_data_types
categories: [Software Engineering, Python]
author: hyoeun
---

* Python은 interpreter이다. Interpreter란 한 줄 한 줄 바로바로 해석하고 결과를 보여주는 언어이다.
* Scalar type
  * int, float, bool, none, null
  * atomic data type
* Non-scalar type 
  * string, tuple, list, dictionary
  * data types with internal structures
* 파이썬은 index가 0부터 시작한다.
* slicing을 할 때 a[0:3]은 0<= index < 3 을 의미한다.<br>이것은 len(array)와 같이 sizeof array크기를 이용해서 slicing이 가능하게 설계한 것으로 보인다.
* 코드 안에 한글을 사용하기 위해서는 파일 맨 위에 다음 코드를 입력해야 합니다.
```python
#-*- coding: utf-8 -*- 
```
* ```print(i * j, end = " ")```는 i * j 계산값 이후에 \n이 아니라 " "를 출력한다는 의미.

### Integer
* ​파이썬 3 이전의 버전에서는 3/4의 계산을 0으로 표시했다.
int/int는 int형으로만 나타냈다. 하지만 3버전 이후에서는 실수형으로 자동 형변환 시켰다.
* 강제 형변환을 하기 위해서는 3/(4 * 0.1)의 형태를 취해주면 된다. 
* / 연산은 나눗셈의 결과를 나타내고 //은 몫을 의미한다
```python
print(3.1/2.7)  # 1.1481481481481481
print(3.1//2.7) # 1.0
```

### String
* "What's the matter?"<br>
'He said to her, "You are so great!"'<br>
"", ''는 동일한 기능을 하고 안에 escape 문자(\\)를 쓰지 않고 서로 구분 할 수 있도록 설계되었다.
* \000은 null을 의미한다.
* """ , """ 의 조합은 주석처리와 마찬가지로 거기 안에 들어있는 모든 문자열을 \n을 포함하면서 하나의 string으로 처리한다. 
``` python
multiline = """
Life is too short
You need python
"""
multiline = "Life is too short\n You need python"
```
* string에 관한 특수 formating (printf의 서식문자 관련 기능들과 유사)
```python
"I ate %d apples. so I was sick for %s days." % (2, "three") 
"I ate {0} apples. so I was sick for {1} days.".format (2, "three") 
"I ate {number} apples. so I was sick for {day} days.".format (number=2, day="three")
```
* interger type과 string을 더할때 str(int)로 바꿔야 된다.
* str * n : str연산자를 n 번 반복합니다.
* str[n]: 스트링 안에서 인덱스를 지정할 수 있습니다.
* str[n:m]: 스트링 안에서 인덱스 범위를 지정할 수 있습니다.
#### string 관련 함수.

  |함수|설명|
  |:--|:--|
  |a.count(x)| a 안에 x의 갯수 return
  |a.find(x) |a 문자열안에 x 문자열 처음 나오는 위치 return. 없으면 -1
  |a.index(x)| find와 동일한 기능이지만 x가 없으면 error 발생
  |a.join('!@#')| '' 안에 있는 문자 사이에 a가 들어간다. !a@a# <- a는 string
  |a.upper()| 모두 대문자로 변환
  |a.lower()| 모두 소문자로 변환
  |a.lstrip()| 왼쪽 공백 제거 
  |a.rstrip()| 오른쪽 공백 제거
  |a.strip()| 양쪽 공백 모두 제거
  |a.replace(x,y)| a안에 있는 x(string)를 y(string)로 치환
  |a.split(x)| x를 기준으로 x를 제외한 남은 요소를 list 형태로 return ex) "String".split("tr") -> ['S' , 'ing'] 


### List
* []를 사용하고 string을 다루는 것과 매우 유사하다.
* list는 array와 닮은 점이 많지만 다른 점은 list안에 서로 다른 data type이 존재할 수 있으며 크기가 또 다른 list가 담길 수 있다.
  ```python
  a = [1,2,3]
  a[1] = [1,2,3] => [1, [1,2,3], 3]
  a[1:2] = [1,2,3] => [1, 1, 2, 3, 1] # a[1:2]의 의미는 1과 2사이에 x를 넣겠다.
  ```
* ```del a[1]```을 하면 index 1의 요소가 삭제되고 list 크기도 준다.
#### List 관련 함수

  |함수|설명|
  |:--|:--|
  |a.append(x)| x를 list 끝에 추가
  |a.sort()| list를 오름차순으로 정렬
  |a.reverse()| list를 내림차순으로 정렬. 1,2,3 -> 3,2,1
  |a.index(x)| x에 해당하는 index를 return
  |a.insert(a,b)| index a(int) 위치에 b data를 삽입
  |a.remove(x)| 처음으로 나오는 x를 삭제
  |a.pop()| 마지막에 나오는 요소를 return하고 list 안에서는 삭제. ()안에는 index 넣어도 된다.
  |a.count(x)| list안에 있는 x 갯수 return
  |a.extend(x)| x라는 list를 a list 뒤에 추가 
  |len(a)| a리스트의 원소 갯수

#### List Comprehensions

```python
>>> squares = [x**2 for x in range(10)]
>>> squares
[0, 1, 4, 9, 16, 25, 36, 49, 64, 81]

>>> [(x, y) for x in [1,2,3] for y in [3,1,4] if x != y]
[(1, 3), (1, 4), (2, 3), (2, 1), (2, 4), (3, 1), (3, 4)]

>>> matrix = [
...     [1, 2, 3, 4],
...     [5, 6, 7, 8],
...     [9, 10, 11, 12],
... ]

>>> [[row[i] for row in matrix] for i in range(4)]
[[1, 5, 9], [2, 6, 10], [3, 7, 11], [4, 8, 12]]

>>> list(zip(*matrix))
[(1, 5, 9), (2, 6, 10), (3, 7, 11), (4, 8, 12)]
```

### Tuple 
* ()를 사용하고 tuple은 원소값을 직접 변경 불가. 시도시 error.
* list보다는 access가 빠른 편이다.
* ()과 ,로 구분되며 값이 1개인 튜플은(x,)와 같이 뒤에 ,를 붙인다. element가 없을 때는 ()
```python
empty = ()
one = 5,     # (5,)로 저장됩니다.
```
* 여러개의 요소가 있을 때에는 ()를 생략하고 ,로만 선언 가능.
```python
tp = 1,2,3                 # tp == (1, 2, 3)
print(tp[2])               # 3 출력
q = tp[:1] + (5,) + tp[2:] # q == (1, 5, 3)
```
* tp[2]와 같이 indexing은 가능하다. 그 index의 값 return.
* tp[:2]와 같이 slicing도 가능하다. 해당하는 값 return.
* tp1 + tp2 하면 더해진 새로운 tp을 return.
* tp * 3 은 tp를 3번 반복해서 만든 new 튜플을 return.
* 튜플 활용법

  ```python
  >>> c = 10
  >>> d = 20
  >>> c, d = d, c
  >>> print c,d
  20 10

  >>> def magu_print(x, y, *rest):
  ...   print x, y, rest
  ...
  >>> magu_print(1,2,3,5,6,7,9,10)
  1 2 (3, 5, 6, 7, 9, 10)

  >>> p = (1, 2, 3)
  >>> q = list(p)                  # 튜플 p로 리스트 q를 만듦
  >>> q
  [1, 2, 3]
  >>> r = tuple(q)                 # 리스트 q로 튜플 r을 만듦
  >>> r
  (1, 2, 3)
  ```
[참고 사이트](https://wikidocs.net/71)

### Dictionary
* {}를 사용하며 {key:value, ...} pair로 구성.
* java hash를 의미. 
* 추가 하는 방식은 dic[key] = value 이다.<br>
key에는 변하지 않는 값인 숫자, 문자, 튜플이 가능하다.<br>
value는 어떠한 타입이 와도 상관없다.
```python
dic = {}
dic['python'] = 'Easy'
```
* dictionary는 기본적으로 순서가 전혀 상관 없다.
* del dic[key]로 삭제.
* dic[key]는 value 값을 return 한다.<br>
따라서 key는 primary key이고 dic[중복된 key] = value하면 기존 key값의 value가 교체된다.<br>
초기화 당시에는 중복된 key 값들을 입력할 수 있지만 그렇게 사용하는 것은 피해야 한다.
#### Dictionary 관련 함수들

  |함수|설명|
  |:--|:--|
  |a.keys()| ([ ]) object 형태(ver3.0 이전은 list형태)로 key값들 return
  |a.values()| keys()와 마찬가지로 value 값들 return
  |a.items()| key, value pair를 튜플로 묶어서 return
  |a.clear()| 모두 지우기
  |a.get(key)| a[key]와 같은 기능이지만 key가 없을 경우 a[key]는 error를, a.get(key)는 None을 return
  |a.get(key, 'something')|key가 없을경우 None 대신에 'something'을 return
  
  * ```'key' in a```: a안에 key가 있으면 True, 없으면 False return<br>
  * 반환된 object로 ```for k in a.keys()``` 도 사용할 수도 있습니다.<br>
  * list(a.keys())로 하면 list로 변환 됩니다.

### Set
* 수학의 set 개념과 비슷합니다. unordered, not allowed redendent
* list(set), tuple(set) 하면 set이 각각에 해당하는 걸로 변환.
* 집합이기에 union(|), intersection(&), difference(-), symmetric_difference(^)<합집합 - 교집합> 연산자가 있습니다. ex) s1.difference(s2) == s1 - s2
```python
>>> a = {1, 2, 3, 4, 5}
>>> b = {3, 4, 5, 6, 7}
>>> c = a.symmetric_difference(b)
>>> a
{1, 2, 3, 4, 5}
>>> b
{3, 4, 5, 6, 7}
>>> c
{1, 2, 6, 7}
```
* 초기화
```python
s = set()
s1 = {1,3,5}
s2 = set([1,'a','ab']) # s2 == {'ab', 1, 'a'}
```
#### Set 관련 함수들

  |함수|설명|
  |:--|:--|
  |s.add(x)| x 추가
  |s.update([ , , ])| 여러개 추가
  |s.remove(x)| x 삭제, 없으면 Error 발생
  |s.discard(x)| x 삭제, 없어도 에러발생 x
  |s.copy()| s set 복사
  |s.issubset(a)| s가 a의 부분집합이면 True 아니면 False
  |s.issuperset(a)| s가 a의 superset이면 True 아니면 False
  |s.isdisjoint(a)| s와 a가 교집합이 없으면 True  아니면 False

### Ture and False / None
* 무슨 자료형이던지 있으면 True 없거나 0이면 False(==None)
* 다음과 같은 코드들을 쓸 수 있다.

  ```python
  bool_x = True
  print(bool_x)                # True
  print(not bool_x)            # False
  print(bool_x and not bool_x) # False
  print(bool_x or not bool_x)  # True

  var_none = None
  print(var_none)              # None
  ```

### Type 확인하기
```python
print(type(whatever))
```

## Mutable / Immutable
### List of mutable types:
* list, dict, set, bytearray, user-defined classes

### List of immutable types:
* int, float, decimal, complex, bool, string, tuple, range, frozenset, bytes

### Hashable
```python
x = hash(frozenset([1,2]))
x = hash((1,2,3))
```

### Unhashable(Not working)
```python
x = hash(set([1,2]))
x = hash(([1,2], [2,3]))
x = hash({1,2})
x = hash([1,2,3])
```