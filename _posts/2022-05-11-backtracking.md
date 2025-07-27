---
title: Backtracking
tags: Backtracking Algorithms
key: page-backtracking
categories: [Development, Algorithms]
author: hyoeun
math: true
mathjax_autoNumber: true
---

### 1\. What is Backtracking?

In a nutshell, **backtracking** is a strategy that involves **exploring all potential solutions, but immediately abandoning paths that are no longer likely to lead to a solution and returning to a previous state.**

The easiest analogy is a **maze search**.

> You're at the starting point of a maze. Every time you encounter a fork, you choose one path and proceed. You hit a dead end. What do you do? Naturally, you go back the way you came and choose a different path at the previous fork.

This process is the core of backtracking.

  * **Choose:** Select a path at a fork.
  * **Explore:** Follow the chosen path to its end.
  * **Un-choose/Backtrack:** If you reach a dead end or determine that this path cannot lead to a solution, you undo the choice you just made and return to the previous fork.

Due to these characteristics, backtracking is typically implemented using **recursion** and operates based on a **state-space tree** that explores all possible cases. **Pruning**, which avoids unnecessary exploration, is a critical element of backtracking.

#### Difference from DFS

"Isn't exploring all paths just Depth-First Search (DFS)?" That's a good question. Backtracking can be seen as a type of DFS, but there's a crucial difference:

  * **DFS:** Simply explores all possible paths to their end.
  * **Backtracking:** Explores a path, but if it fails to satisfy a certain **condition (constraint)**, it immediately backs up without going deeper (pruning).

In essence, backtracking is an **optimized DFS** for finding solutions that satisfy specific conditions.

-----

### 2\. The Universal Backtracking Recipe (Template)

Most backtracking problems can be solved using the following template. Understanding and memorizing this template will help you apply it confidently to any problem.

```python
def backtrack(candidate, ...):
    # 1. Base Case: Condition where the current state is a solution
    if is_solution(candidate):
        add_solution(candidate)
        return

    # 2. Recursive Step: Explore next choices
    for next_candidate in possible_moves(...):
        # 2-1. Pruning: Check if this path is promising
        if is_valid(next_candidate):
            # Choose
            add_to_candidate(next_candidate)

            # Explore
            backtrack(new_candidate, ...)

            # Un-choose - Most important!
            remove_from_candidate(next_candidate)
```

This **"Choose -\> Explore -\> Un-choose"** pattern is the heart of backtracking. The `Un-choose` process is vital as it must perfectly restore the previous state to allow correct exploration of other paths.

-----

### 3\. LeetCode Example: Subsets (LeetCode \#78)

Now, let's look at a real problem to see how the above template is applied. This problem asks us to find all subsets of a given array of numbers.

**Problem:** Given `nums = [1, 2, 3]`, return all its possible subsets: `[[], [1], [2], [1, 2], [3], [1, 3], [2, 3], [1, 2, 3]]`.

#### Solution Logic

For each number in `[1, 2, 3]`, we have two choices: **"include it in the subset"** or **"do not include it"**. If we visualize this decision process as a tree, it looks like this:

```
                      []
              /                \
           [1]                  []
         /     \              /      \
      [1, 2]    [1]         [2]        []
     /    \    /   \       /   \      /  \
[1,2,3] [1,2] [1,3] [1]  [2,3] [2]  [3]   []
```

Every node in this tree is a subset. We will use backtracking to traverse this tree and add all nodes to our result.

#### Python Code Implementation

```python
from typing import List

class Solution:
    def subsets(self, nums: List[int]) -> List[List[int]]:
        result = []
        path = [] # Current subset being explored

        def backtrack(start_index: int):
            # 1. Base Case: Every node is a subset, so add to result at the start of exploration
            result.append(path[:]) # Must append a copy of path, not path itself!

            # 2. Recursive Step: Explore next choices
            for i in range(start_index, len(nums)):
                # Choose
                path.append(nums[i])

                # Explore: Start exploration from the number after the current one
                backtrack(i + 1)

                # Un-choose
                path.pop()

        backtrack(0)
        return result

# Example execution
solver = Solution()
print(solver.subsets([1, 2, 3]))
# Output: [[], [1], [1, 2], [1, 2, 3], [1, 3], [2], [2, 3], [3]] (order may vary)
```

  * `result.append(path[:])`: `path` is like a mutable "workbench." When adding to the result, you must save a copy (`path[:]`) as if taking a snapshot.
  * `backtrack(i + 1)`: To avoid duplicate subsets, the next exploration starts from the index after the currently chosen number.
  * `path.pop()`: When the recursive call returns, remove the number just added from `path` to revert to the previous state. This is the crucial "un-choose" of backtracking.

#### Time and Space Complexity Analysis

  * **Time Complexity: $O(N \\times 2^N)$**

      * There are a total of $2^N$ subsets.
      * Adding each subset to the result list requires copying up to $N$ elements, taking $O(N)$ time.
      * Therefore, the total time complexity is $O(N \\times 2^N)$.

  * **Space Complexity: $O(N)$**

      * The maximum depth of the recursive calls does not exceed the length of `nums`, which is $N$. Since the `path` list also stores a maximum of $N$ elements, the space used by the recursion stack and `path` is $O(N)$. (The `result` list, which stores the output, is usually excluded from space complexity calculations.)

-----

### 4\. Coding Interview Tips

1.  **Pattern Recognition:** If a problem asks for "all possible combinations," "all permutations," or "all possible paths," think of backtracking.
2.  **Draw the State-Space Tree:** Before coding, drawing the decision tree for a small example directly helps clarify the logic and reduce errors.
3.  **"Choose, Explore, Un-choose" Mantra:** Always keep these three steps in mind when writing your code. Forgetting the `Un-choose` step is the most common mistake.
4.  **Passing Copies vs. Modifying State:** You can either modify a single `path` and use it as shown in the example above, or pass a copy of `path` with each recursive call. The latter can make the code more concise but might increase memory usage. It's important to understand this trade-off.

---

### 1. 백트래킹이란 무엇인가? (What is Backtracking?)

백트래킹을 한마디로 정의하면 **"가능성 있는 모든 해결책을 탐색하되, 더 이상 답이 될 가능성이 없는 경로는 즉시 포기하고 되돌아가는 전략"**입니다.

가장 쉬운 비유는 **미로 찾기**입니다.

> 당신은 미로의 출발점에 서 있습니다. 갈림길이 나올 때마다 하나의 길을 선택해서 들어갑니다. 가다 보니 막다른 길에 부딪혔습니다. 그럼 어떻게 할까요? 당연히 왔던 길을 되돌아가 다른 갈림길을 선택하겠죠.

이 과정이 바로 백트래킹의 핵심입니다.

* **선택 (Choose):** 갈림길에서 하나의 경로를 선택합니다.
* **탐색 (Explore):** 선택한 경로를 따라 끝까지 가봅니다.
* **되돌아가기 (Un-choose/Backtrack):** 막다른 길에 도달했거나, 이 경로가 정답이 될 수 없다고 판단되면, 방금 내린 선택을 취소하고 이전 갈림길로 돌아갑니다.

이러한 특성 때문에 백트래킹은 주로 **재귀(Recursion)**를 통해 구현되며, 모든 가능한 경우의 수를 탐색하는 **상태 공간 트리(State Space Tree)**를 기반으로 동작합니다. 백트래킹은 불필요한 탐색을 피하는 **가지치기(Pruning)**가 핵심적인 요소입니다.

#### DFS와의 차이점

"모든 경로를 탐색하는 건 깊이 우선 탐색(DFS) 아닌가요?" 좋은 질문입니다. 백트래킹은 DFS의 한 종류로 볼 수 있지만, 중요한 차이가 있습니다.

* **DFS:** 단순히 가능한 모든 경로를 끝까지 탐색합니다.
* **백트래킹:** 경로를 탐색하다가 특정 조건(constraint)을 만족하지 못하면 더 이상 깊이 들어가지 않고 즉시 되돌아옵니다. (가지치기)

즉, 백트래킹은 **'조건을 만족하는 해'**를 찾기 위해 최적화된 DFS라고 할 수 있습니다.

### 2. 백트래킹의 만능 레시피 (Template)

대부분의 백트래킹 문제는 아래와 같은 템플릿으로 해결할 수 있습니다. 이 템플릿을 이해하고 암기하면 어떤 문제가 나와도 당황하지 않고 적용할 수 있습니다.

```python
def backtrack(candidate, ...):
    # 1. Base Case: 현재 상태가 해(solution)가 되는 조건
    if is_solution(candidate):
        add_solution(candidate)
        return

    # 2. Recursive Step: 다음 선택지를 탐색
    for next_candidate in possible_moves(...):
        # 2-1. Pruning: 이 경로가 유망한지(promising) 검사
        if is_valid(next_candidate):
            # 선택 (Choose)
            add_to_candidate(next_candidate)

            # 탐색 (Explore)
            backtrack(new_candidate, ...)

            # 선택 취소 (Un-choose) - 가장 중요!
            remove_from_candidate(next_candidate)
```

이 **"Choose -> Explore -> Un-choose"** 패턴이 백트래킹의 심장입니다. `Un-choose` 과정을 통해 이전 상태로 완벽하게 복원되어야 다른 경로를 올바르게 탐색할 수 있습니다.

### 3. LeetCode 예제: Subsets (LeetCode #78)

이제 실제 문제를 통해 위 템플릿이 어떻게 적용되는지 살펴보겠습니다. 주어진 숫자 배열의 모든 부분 집합(subset)을 찾는 문제입니다.

**문제:** `nums = [1, 2, 3]` 가 주어졌을 때, 모든 부분 집합 `[[], [1], [2], [1, 2], [3], [1, 3], [2, 3], [1, 2, 3]]` 을 반환하라.

#### 풀이 로직

`[1, 2, 3]`의 각 숫자에 대해 우리는 두 가지 선택을 할 수 있습니다. **"부분 집합에 포함시킨다"** 또는 **"포함시키지 않는다"**. 이 결정 과정을 트리 형태로 그리면 다음과 같습니다.

```
                      []
              /                \
           [1]                  []
         /     \              /      \
      [1, 2]    [1]         [2]        []
     /    \    /   \       /   \      /  \
[1,2,3] [1,2] [1,3] [1]  [2,3] [2]  [3]   []
```

이 트리의 모든 노드가 바로 부분 집합입니다. 우리는 백트래킹을 이용해 이 트리를 순회하며 모든 노드를 결과에 추가할 것입니다.

#### Python 코드 구현

```python
from typing import List

class Solution:
    def subsets(self, nums: List[int]) -> List[List[int]]:
        result = []
        path = [] # 현재 탐색 중인 부분 집합

        def backtrack(start_index: int):
            # 1. Base Case: 모든 노드는 부분 집합이므로, 탐색 시작 시점에 결과에 추가
            result.append(path[:]) # path를 그대로 넣지 않고 복사해서 넣어야 함!

            # 2. Recursive Step: 다음 선택지를 탐색
            for i in range(start_index, len(nums)):
                # 선택 (Choose)
                path.append(nums[i])

                # 탐색 (Explore): 현재 숫자의 다음 숫자부터 탐색 시작
                backtrack(i + 1)

                # 선택 취소 (Un-choose)
                path.pop()

        backtrack(0)
        return result

# 예제 실행
solver = Solution()
print(solver.subsets([1, 2, 3]))
# 출력: [[], [1], [1, 2], [1, 2, 3], [1, 3], [2], [2, 3], [3]] (순서는 다를 수 있음)
```

* `result.append(path[:])`: `path`는 계속 변하는 '작업대' 같은 것입니다. 결과에 추가할 때는 반드시 스냅샷을 찍듯이 복사본(`path[:]`)을 저장해야 합니다.
* `backtrack(i + 1)`: 중복된 부분 집합을 피하기 위해 다음 탐색은 현재 선택한 숫자의 다음 인덱스부터 시작합니다.
* `path.pop()`: 재귀 호출이 끝나고 돌아오면, 방금 추가했던 숫자를 `path`에서 제거하여 이전 상태로 되돌립니다. 이것이 바로 백트래킹의 핵심인 '선택 취소'입니다.

#### 시간 및 공간 복잡도 분석

* **시간 복잡도: $O(N \times 2^N)$**
    * 총 $2^N$개의 부분 집합이 존재합니다.
    * 각 부분 집합을 결과 리스트에 추가할 때, 최대 $N$개의 원소를 복사해야 하므로 $O(N)$의 시간이 걸립니다.
    * 따라서 총 시간 복잡도는 $O(N \times 2^N)$가 됩니다.

* **공간 복잡도: $O(N)$**
    * 재귀 호출의 최대 깊이는 `nums`의 길이인 $N$을 넘지 않습니다. `path` 리스트도 최대 $N$개의 원소를 저장하므로, 재귀 스택과 `path`가 사용하는 공간은 $O(N)$입니다. (결과를 저장하는 `result`는 보통 공간 복잡도 계산에서 제외합니다.)

### 4. 코딩 인터뷰 팁

1.  **패턴 인식:** 문제에서 "모든 가능한 조합", "모든 순열", "가능한 모든 경로" 등을 요구하면 백트래킹을 떠올리세요.
2.  **상태 공간 트리 그리기:** 코딩 전에 작은 예시에 대한 결정 트리를 직접 그려보면 논리가 명확해지고 실수를 줄일 수 있습니다.
3.  **"Choose, Explore, Un-choose" Mantra:** 이 세 단계를 항상 머릿속에 새기고 코드를 작성하세요. 특히 `Un-choose`(선택 취소)를 잊는 실수가 가장 흔합니다.
4.  **복사본 전달 vs 상태 변경:** 위 예제처럼 하나의 `path`를 변경하며 사용하는 방법도 있고, 재귀 호출 시마다 `path`의 복사본을 넘겨주는 방법도 있습니다. 후자는 코드가 간결해지지만 메모리 사용량이 늘어날 수 있습니다. 트레이드오프를 이해하는 것이 중요합니다.