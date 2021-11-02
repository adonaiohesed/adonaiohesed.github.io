---
title: 파이썬 특징적인 문법
tags: python
key: page-python_key_characteristics
cover: /assets/cover/python.png
---

## 입출력

```python
a = input()
a = input("prompt")
print("a" "b" "c")         # abc
print("a" + "b" + "c")     # abc
print("a","b","c")         # ('a', 'b', 'c')

x = "Hello"
y = "World!"
print(x,y)                 # Hello World!
print(x+y)                 # HelloWorld!
```
* input으로 받은 것은 모두 문자열로 처리한다.
* print 안에 " " " " 로 이뤄지면 " " + " " 와 같은 결과이다.
* print 안에 ,가 들어가면 튜플로 보여진다.

<br>
## 파일 입출력

```python
f = open("file.txt",'w')   # w : 쓰기 r : 읽기 a : 이어쓰기
f.close()                  # 이거를 명시하지 않아도 자동으로 처리되기는 한다.
f.write('something')       # 파일에 'something'을 쓰기.
line = f.readline()        # 파일에서 한 줄씩 읽어오기.
if not line: break         # 이 형태로 EOF을 감지할 수 있다.
lines = f.readlines()      # 모든 line들을 가져와서 리스트 형태로 반환한다.
data = f.read()            # 모든 내용을 하나의 문자열로 return
```
```python
with open("file.txt", "w") as f:
  f.write('something')
```
* open block 안에서 나가는 즉시 자동으로 file close를 시켜준다.

```python
args = sys.argv[1:]
for i in args:
   print(i)
```
* argument로 들어오는 값들을 처리할 수 있다. int main(args[])와 같은 이치.

<br>
## Unpacking

```python
def point(x, y):
  print(x,y)

foo_list = [3,4]
foo_tuple = (5,6)
foo_dict = {'x':1, 'y':2}

point(*foo_list)            # 3 4
point(*foo_tuple)           # 5 6
point(**foo_dict)           # 1 2

print(*foo_dict)            # x y
```
* function의 argument로 사용하기 위해서 쓰는 문법입니다.
* list, tuple의 경우 *, dictionary의 경우 **을 붙여 사용합니다.

<br>
## Enumerate

```python
vowels = ['a','e','i','o','u']
for i, letter in enumerate(vowels):
  print(i, letter)

'''
0 a
1 e
2 i
3 o
4 u
'''

for i in enumerate(vowels):
  print(i)

'''
(0, 'a')
(1, 'e')
(2, 'i')
(3, 'o')
(4, 'u')
'''
```
* index와 item을 함께 쓰고 싶을 때 사용하는 방식이다.

<br>
## 비교 연산자 체인

```python
i = 3

ans = 1 < i < 10   # True
ans = 10 > i <= 9  # True
ans = 3 == i       # True
```
* 기존 c언어에서는 되지 않았던 직관적인 비교연산자 체인 사용 가능합니다.

<br>
## Infinites

```python
p_infinity = float('Inf')

if 999999999999999999999999999999999999999 > p_infinity:
  print("The number is greater than Infinity!")
else:
  print("Infinity is greatest")

n_infinity = float('-Inf')
if -9999999999999999999999999999999999999999999999999999999999999999999 < n_infinity:
  print("The number is lesser than Negative Infinity!")
else:
  print("Negative Inifinity is least")

'''
Infinity is greatest
Negative Inifinity is least
'''
```
* 특별한 라이브러리 사용 없이 무한대를 사용할 수 있습니다.

<br>
## List Comprehension

```python
a = []
for x in range(0,10):
  a.append(x)
print(a)                                   # [0, 1, 2, 3, 4, 5, 6, 7, 8, 9]
for ten for i in 
print([x * x + 1 for x in a if x%2 == 0])  # [1, 5, 17, 37, 65]
```
* 수학에서 쓰이는 조건문을 list, for, if를 결합하여 표현할 수 있습니다.

<br>
## Slicing

```python
a = [1, 2, 3, 4, 5]

print(a[1:2])                       # [2]
print(a[:-1])                       # [1, 2, 3, 4]
print(a[1:])                        # [2, 3, 4, 5]
print(a[:])                         # [1, 2, 3, 4, 5]
print(a[::-1])                      # [5, 4, 3, 2, 1]
print(a[::2])                       # [1, 3, 5]
print(a[::-2])                      # [5, 3, 1]
```
* \[start : end : step\] 으로 이루어져있고 string, tuple로도 slicing 가능하다.