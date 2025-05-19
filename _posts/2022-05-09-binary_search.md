---
title: Binary Search
tags: Binary-Search Algorithms
key: page-binary_search
categories: [Software Engineering, Algorithms]
author: hyoeun
math: true
mathjax_autoNumber: true
---

## 바이너리 서치
```python
left = 1
right = n
while(left<right):
    mid = left + int((right-left) / 2)
    if isBadVersion(mid):
        right = mid
    else:
        left = mid + 1
return left
```