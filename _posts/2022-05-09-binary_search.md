---
title: Binary Search
tags: Binary-Search Algorithms
key: page-binary_search
categories:
- Engineering
- Algorithms & Data Structures
author: hyoeun
math: true
mathjax_autoNumber: true
image: "/assets/thumbnails/2022-05-09-binary_search.png"
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