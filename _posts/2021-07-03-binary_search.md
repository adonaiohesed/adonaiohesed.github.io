---
title: Binary Search
tags: algorithm ds
key: page-binary_search
cover: /assets/cover/algorithm.png
mathjax: true
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