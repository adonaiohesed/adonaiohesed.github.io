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
