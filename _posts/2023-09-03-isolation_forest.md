---
title: Isolation Forest
tags: Isolation Forest Machine-Learning
key: page-isolation_forest
categories: [AI, Machine Learning]
author: hyoeun
---

# Isolation Forest: Detecting Anomalies Through Isolation

In vast datasets like security logs, system metrics, or financial transaction records, we often need to find the data that is 'different'. Detecting a few malicious attempts among millions of normal network requests is a classic anomaly detection problem. While many algorithms focus on learning the distribution of normal data, Isolation Forest starts from the opposite idea: **"Anomalies are few and different, and therefore they are easier to isolate."**

## The Core Idea: The Ease of Separating Normality and Anomaly

The fundamental principle of Isolation Forest is highly intuitive. When you randomly partition data points, an anomaly can be isolated in its own space with far fewer splits than a normal data point.

To isolate a single normal data point located within a dense cluster, numerous partitions are required. In contrast, an anomalous data point, lying far from the cluster, can be easily separated with just a few partitions. Isolation Forest measures this 'ease of isolation' to determine how anomalous a data point is.

## How the Algorithm Works

Isolation Forest is an ensemble model composed of multiple 'Isolation Trees'. Each tree is constructed through the following process:

1.  **Data Sampling**: A random subsample of data is taken from the original dataset.
2.  **Random Feature and Split Value Selection**:
      * A feature is randomly selected from the set of available features.
      * A random split value is chosen between the minimum and maximum values of the selected feature.
3.  **Data Partition**: The data is partitioned into two nodes: points with a value less than the split value go to the left node, and points with a greater value go to the right node.
4.  **Recursive Partitioning**: Steps 2 and 3 are repeated until every data point is isolated in its own terminal node or a predefined maximum tree depth is reached.

During this process, the number of splits required to isolate a data point—the **path length** from the root node to the point's terminal node—is calculated. The more anomalous the point, the shorter its path length tends to be, while normal data points will have longer path lengths.

## Calculating the Anomaly Score

Using just a single tree can lead to unreliable results due to its randomness. Therefore, Isolation Forest creates an ensemble of tens or hundreds of Isolation Trees and calculates the average path length for each data point across all trees.

This average path length is then normalized to produce an **Anomaly Score** between 0 and 1.

  * **A score close to 1**: Indicates a very high probability of being an anomaly.
  * **A score less than 0.5**: Indicates a high probability of being normal data.
  * **A score around 0.5**: Suggests that the entire dataset may not have distinct anomalies.

## Simple Implementation with Python

You can implement Isolation Forest very easily using the `scikit-learn` library.

```python
import numpy as np
from sklearn.ensemble import IsolationForest

# Generate normal and anomalous data
# Most data is clustered around 0, with two outliers far away
X_train = np.array([[0.1, 0.1], [0.2, 0.2], [-0.1, -0.1], 
                    [0.0, 0.1], [10, 10], [-8, 8]])

# Initialize and train the Isolation Forest model
# contamination: the expected proportion of outliers in the dataset
clf = IsolationForest(n_estimators=100, contamination=0.25, random_state=42)
clf.fit(X_train)

# Perform prediction (1: inlier, -1: outlier)
y_pred = clf.predict(X_train)
print("Prediction results (1: inlier, -1: outlier):")
print(y_pred)

# Check the anomaly score for each data point
anomaly_scores = clf.decision_function(X_train)
print("\nAnomaly scores (the lower, the more abnormal):")
print(anomaly_scores)
```

**Execution Results:**

```
Prediction results (1: inlier, -1: outlier):
[ 1  1  1  1 -1 -1]

Anomaly scores (the lower, the more abnormal):
[ 0.1341019   0.1251918   0.1341019   0.15511394 -0.21735442 -0.21175658]
```

As you can see from the prediction results, `[10, 10]` and `[-8, 8]` were accurately identified as outliers (-1). Their anomaly scores (from `decision_function`) are also significantly lower negative values compared to the other points.

## Applicability in Cybersecurity

Isolation Forest is particularly useful for security data analysis.

  * **Fast Processing Speed**: It does not need to calculate the distribution of the entire dataset and works by sampling and partitioning, making it suitable for large-scale log data.
  * **Handles High-Dimensional Data**: It functions effectively even with data that has numerous features (e.g., network packet data).
  * **No Prior Information Needed**: It can detect anomalous behavior in an unsupervised manner without needing to pre-define or label what 'normal' data looks like.

Thanks to these advantages, Isolation Forest can be an effective tool in various security scenarios, such as detecting abnormal login attempts, identifying unusual traffic on an internal network, or discovering malicious bot activity.

---

# Isolation Forest: '고립'을 통해 이상을 감지하는 알고리즘

보안 로그, 시스템 메트릭, 금융 거래 기록 등 방대한 데이터 속에서 우리는 종종 '다른' 데이터를 찾아내야 합니다. 수백만 개의 정상적인 네트워크 요청 중 단 몇 개의 악의적인 시도를 탐지하는 것은 전형적인 이상치 탐지(Anomaly Detection) 문제입니다. 많은 알고리즘이 정상 데이터의 분포를 학습하는 데 집중하는 반면, Isolation Forest는 정반대의 아이디어에서 출발합니다. 바로 \*\*"이상치는 소수이며 다르기 때문에 고립시키기 쉽다"\*\*는 것입니다.

## 핵심 아이디어: 정상과 이상의 분리 용이성

Isolation Forest의 기본 원리는 매우 직관적입니다. 데이터 포인트들을 무작위로 분할해 나갈 때, 이상치(Anomaly)는 정상(Normal) 데이터 포인트보다 훨씬 적은 횟수의 분할만으로 독립된 공간에 고립될 수 있다는 것입니다.

데이터가 밀집된 군집 내에 있는 정상적인 데이터 포인트를 하나만 남도록 분리하려면 수많은 분할이 필요합니다. 반면, 군집에서 멀리 떨어진 이상치 데이터 포인트는 단 몇 번의 분할만으로도 쉽게 분리할 수 있습니다. Isolation Forest는 이 '고립되기까지의 용이성'을 측정하여 데이터 포인트가 얼마나 비정상적인지를 판단합니다.

## 알고리즘 작동 방식

Isolation Forest는 여러 개의 'Isolation Tree'로 구성된 앙상블 모델입니다. 개별 트리는 다음과 같은 과정으로 생성됩니다.

1.  **데이터 샘플링**: 원본 데이터에서 무작위로 일부 데이터를 샘플링하여 가져옵니다.
2.  **무작위 특징(Feature) 및 분할 기준 선택**:
      * 데이터의 여러 특징 중 하나를 무작위로 선택합니다.
      * 선택된 특징의 최솟값과 최댓값 사이에서 임의의 분할 기준(Split Value)을 선택합니다.
3.  **데이터 분할 (Partition)**: 선택된 분할 기준보다 작은 값들은 왼쪽 노드로, 큰 값들은 오른쪽 노드로 데이터를 분할합니다.
4.  **재귀적 분할**: 모든 데이터 포인트가 하나의 노드에 고립되거나, 지정된 최대 깊이(Max Depth)에 도달할 때까지 2, 3번 과정을 반복합니다.

이 과정에서 특정 데이터 포인트가 고립될 때까지 거친 분할의 횟수, 즉 루트 노드에서 해당 데이터 포인트의 터미널 노드까지의 \*\*경로 길이(Path Length)\*\*가 계산됩니다. 이상치일수록 이 경로 길이는 짧아지고, 정상 데이터일수록 길어지는 경향을 보입니다.

## 이상 점수(Anomaly Score) 계산

단 하나의 트리만 사용하면 무작위성 때문에 결과의 신뢰도가 떨어질 수 있습니다. 따라서 Isolation Forest는 수십, 수백 개의 Isolation Tree를 생성하여 각 데이터 포인트의 평균 경로 길이를 계산합니다.

이 평균 경로 길이를 정규화하여 0과 1 사이의 \*\*이상 점수(Anomaly Score)\*\*를 도출합니다.

  * **점수가 1에 가까울수록**: 이상치일 가능성이 매우 높습니다.
  * **점수가 0.5보다 작을수록**: 정상 데이터일 가능성이 높습니다.
  * **점수가 0.5 근처일 경우**: 전체 데이터가 뚜렷한 이상치를 가지고 있지 않을 수 있습니다.

## Python을 이용한 간단한 구현

`scikit-learn` 라이브러리를 사용하면 Isolation Forest를 매우 간단하게 구현할 수 있습니다.

```python
import numpy as np
from sklearn.ensemble import IsolationForest

# 정상 데이터와 이상 데이터 생성
# 대부분의 데이터는 0 근처에, 두 개의 이상치는 멀리 떨어져 있음
X_train = np.array([[0.1, 0.1], [0.2, 0.2], [-0.1, -0.1], 
                    [0.0, 0.1], [10, 10], [-8, 8]])

# Isolation Forest 모델 초기화 및 학습
# contamination: 데이터셋에서 예상되는 이상치의 비율
clf = IsolationForest(n_estimators=100, contamination=0.25, random_state=42)
clf.fit(X_train)

# 예측 수행 (정상: 1, 이상치: -1)
y_pred = clf.predict(X_train)
print("Prediction results (1: inlier, -1: outlier):")
print(y_pred)

# 각 데이터 포인트의 이상 점수 확인
anomaly_scores = clf.decision_function(X_train)
print("\nAnomaly scores (the lower, the more abnormal):")
print(anomaly_scores)
```

**실행 결과:**

```
Prediction results (1: inlier, -1: outlier):
[ 1  1  1  1 -1 -1]

Anomaly scores (the lower, the more abnormal):
[ 0.1341019   0.1251918   0.1341019   0.15511394 -0.21735442 -0.21175658]
```

예측 결과에서 `[10, 10]`과 `[-8, 8]`이 이상치(-1)로 정확하게 판별된 것을 볼 수 있습니다. 이상 점수(decision\_function) 또한 이 두 포인트가 다른 포인트들보다 현저히 낮은 음수 값을 가집니다.

## 보안 분야에서의 활용성

Isolation Forest는 특히 보안 데이터 분석에 매우 유용합니다.

  * **빠른 처리 속도**: 전체 데이터의 분포를 계산할 필요 없이 샘플링과 분할만으로 작동하므로 대용량 로그 데이터에 적용하기에 적합합니다.
  * **높은 차원의 데이터 처리**: 수많은 특징을 가진 데이터(예: 네트워크 패킷 데이터)에서도 효과적으로 작동합니다.
  * **사전 정보 불필요**: '정상' 데이터가 무엇인지 미리 정의하거나 레이블링할 필요 없이 비지도 학습(Unsupervised Learning) 방식으로 이상 행위를 탐지할 수 있습니다.

이러한 장점 덕분에 Isolation Forest는 비정상적인 로그인 시도, 내부망에서의 이상 트래픽, 악성 봇 활동 탐지 등 다양한 보안 시나리오에서 효과적인 도구로 사용될 수 있습니다.