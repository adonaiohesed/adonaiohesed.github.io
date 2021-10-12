---
title: 파이썬 알고리즘에 사용되는 함수
tags: python
key: page-python_algorithm
cover: /assets/cover/python.png
---

## All, Any
* 파라미터로 iterable를 받아서 각 item들이 모두가 참일때 true를 반환하는 것이 all, 하나라도 참일때 true를 반환하는 것이 any이다.
```python
return all(r ==0 or c == 0 or matrix[r-1][c-1] == val 
            for r, row in enumerate(matrix)
            for c, val in enumerated(row))
```

## Sorted set
* sorted() 함수는 list, tuple, string, sets, dictionary 모두 정렬을 해주는 것이다. 이것은 인풋으로 받은것을 바꾸지 않고 새로운 아웃풋을 내보낸다.
```python
s = {5,2,7,1,8}
new = sorted(s, reverse=True)
print(new) => [8, 7, 5, 2, 1]
```
* sort()는 list에 포함된 함수로 original list itself를 바꾸어버린다. 이것은 set에는 쓸 수 없지만 리스트로 enclose한 셋과 함께는 쓸 수 있다.
```python
s=[{5,2,7,1,8}]
s.sort()
print(s) => [{1, 2, 5, 7, 8}]
```