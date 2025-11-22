---
title: 파이썬 알고리즘에 사용되는 함수
tags: Python
key: page-python_algorithms_functions
categories: [Development, Programming Fundamentals]
author: hyoeun
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

## For range 역순
* reversed()함수를 이용 할 수 있다.
```python
for i in reversed(range(5)):
  print(i)
=> 4,3,2,1,0 이 각각 엔터와 함께 출력
```

* range(start,stop,step) 이용하기
```python
for i in range(4,-1,-1):
  print(i)
=> 위와 같은 결과가 출력이 됨
```

## 나눗셈과 제곱
* // 은 몫을 의미한다. /는 나누기로 float형태로 반환값이 나오게 된다.
* **은 제곱을 의미한다.
```python
3//2 => 1
3/2 => 1.5
3**2 => 9
```

## 삼항연산자
* If 컨디션을 만족하면 true_value를 사용하고 아니면 false_value를 사용한다.
```python
[true_value] if [condition] else [false_value]
return True if a == 1 else False
```

## Is와 ==의 차이
* is는 변수가 같은 Object(객체)를 가리키면 True
* ==는 변수가 같은 Value(값)을 가지면 True

## Back Tracking
* 재귀적으로 문제를 풀어나가되 현재 상태가 조건에 위배되는지 판단하고 그런 경우 현재 상태를 제외하고 다음 단계로 나가는 방식.
* 보통 O(2^n)꼴이며 대부분 DP나 그리디로 풀 수 있지만 그것으로 해결 가능한 문제를 이 방식으로 푼다.

# Set vs List
* List는 삽입, 제거, 탐색, 포함여부 확인 모두 O(N)이 필요하다. 반면 set은 O(1)이 필요하다.
* 따라서 탐색과 확인이 주로 필요한 연산이라면 set이나 dictionary를 사용하는 것이 좋고 순서와 inde에 따른 접근이 필요하다면 list를 사용하는 것이 좋다.

## 알고리즘 문제 분석
* If input array is sorted then
  - Binary search
  - Two pointers
* If asked for all permutations/subsets then
  - Backtracking
* If given a tree then
  - DFS
  - BFS
  - Recursion
* If given a graph then
  - DFS
  - BFS
* If given a linked list & sub string problem then
  - Two pointers
* If recursion is banned then
  - Stack
* If must solve in-place then
  - Swap corresponding values
  - Sore one or more different values in the same pointer
* If asked for maximum/minumum subarray/subset/options + counter then
  - Dynamic programming
* If asked for top/least K items then
  - Heap
* If asked for common strings then
  - Map
  - Trie
* Else
  - Map/Set for O(1) time & O(n) space
  - Sort input for O(nlogn) time and O(1) space

## 인터뷰 tip
* 우선 디자인을 먼저하고 디자인에 대한 설명을 할 때에는 어느정도 주석과 함께 글을 쓰면서 설명을 해라. 말로만 하면 상대방이 무슨 말을 하는지 따라 잡을 수가 없다.
* 디자인 파트와 implementation 부분은 확실히 나눠야되고 섞으면 절대 안 된다. 힌트 받기가 어려워진다.
* 혼자 생각하는 시간은 가능하면 5분은 넘기지 마라. 5분 정도 생각해도 안 되면 일단 생각한 것을 설명하고 가이드를 받아라.
* 너무 verbose하게 말하지마라. 오히려 커뮤니케이션이 떨어지고 쓸데 없이 시간을 잡아먹을 뿐이다. 핵심 key만 전달하는것이 중요하다. 상대는 엔지니어고 일일이 설명할 필요가 없는 사람이다. 코드만 봐도 나머지가 다 설명이 된다.
* 간결한 것은 설명을 길게 하지 말고 skip해라. Can I do something이라 하지말고 혼자 생각할 시간이 필요할 때 말고 설명할 때에는 전부 Let's do 
xx라고 하고 혼자 진행해라. ex) Let's work through with my idea.
* 인터뷰어가 예제를 주면 거기서부터 시작해라. 이후에 또 다른 예제가 필요하면 요구를 하고 너가 만든 예제로 설명을 해도 된다.
* 크리티컬한 로직 버그는 절대 일어나서는 안 된다. 너무 쉬운 문제인데 그거에 대한 버그가 생겨버리면 그거 자체는 거의 큰일난다.
* 인터뷰어는 최대한 들으려고 한다. 그래서 너가 헛소리를 시작하면 들을 수 밖에 없고 정말 그게 길때만 제재를 가할 것이다.
* 인풋 자체에 대해서 제대로 잡아야한다.
* row col이 헷갈릴때에는 미리 디파인을 해놓고 꼽으면 된다.
* 아예 의미가 다른 변수가 있으면 그냥 하나 더 만드는게 낫지 뭔가 옵티마이즈 하지 마라.
* 뭔가가 코드가 조금이라도 헷갈리면 함수로 넘어가야된다.
* 기능이 2개가 있을 때에는 서로 다른 함수로 시작한다. 함수로 쳐낼 수 있는 것은 쳐내는게 좋다. 이중 for문이 있을때는 함수로 다시 쳐내는게 더 깔끔한 코드가 된다. 모듈화 시켜서 빼내는 걸 생각해서 보내는게 
좋다. 함수는 하나의 기능에 관한 논리적 단위라고 보면 되고 클린 코드의 기본이된다.
* 타임 스퀘어를 말 할때 답만 말하면 안 되고 로직을 먼저 얘기하면서 컴플렉시티를 얘기해야된다. 빅오를 꼭 붙여서 It is gonna be BigO n squar라고 해야한다.
* 타입은 아예 쓰지말고 consistant를 지키는 것이 중요하다.
* 버그가 많으면 더 헷갈리게 되고 사소한데에서 시간을 쓸데없이 쓰지 않도록 해라.
* 연습시 run을 거의 누르지 말고 한 번에 코드가 돌아갈 수 있도록 Run through를 많이해라.
* Sorry라는 말은 거의 쓰지 말고 thank you, you are right, that is a good point라는 표현을 해라.
* Can은 거의 쓰지 말고 let's run through, work through등의 표현을 써라. 예의 차리는 것은 시간을 낭비하게 만들고 불필요한 예의이다.
* 소개는 간단하게 나는 어느 학교에 다녔고 어느 정도의 프로젝트를 했었고 시큐어리티에 관심 있다. 혹시 다른 궁금한거 있으면 언제든지 질문해달라고 하면 된다.
* work through를 할 때 머릿속 시나리오로 가는게 아니라 한줄 한줄 진짜로 해야된다. 긴장해서 놓치면 안된다.
* 쉬운 알고리즘은 그냥 외워라. 템플릿을 들고 있느넥 확실히 좋다. 바이너리 서치같은거는 그냥 외워서 하는게 낫다. 바이너리 서치, BFS, DFS, 파이썬 템플릿을 만들어서 그냥 외워라 그거는 그냥 펑션으로 쳐내도 되고 그걸로 시간을 줄이는게 낫다.

## 참고하기 좋은 사이트
* [알고리즘 Big-O Cheat Sheet](https://www.bigocheatsheet.com/)
* [파이썬 자료형 및 연산자의 시간 복잡도](https://chancoding.tistory.com/43)