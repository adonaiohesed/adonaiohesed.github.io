---
title: Binary Search
key: page-binary_search
categories:
- Engineering
- Algorithms & Data Structures
author: hyoeun
math: true
mathjax_autoNumber: true
image: "/assets/thumbnails/2023-10-19-binary_search.png"
date: 2023-10-19 17:24:00
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