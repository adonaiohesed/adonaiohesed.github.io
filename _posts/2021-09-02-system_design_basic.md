---
title: System Design Basic
tags: privacy systemdesign
key: page-system_design_basic
cover: /assets/cover/cyber_security.png
mathjax: true
mathjax_autoNumber: true
---

## 시스템 디자인 인튜비 단계
1. Clarificiations을 제대로 해야한다. SDI(System Design Interview)는 정해진 답이 없기 때문에 주어진 시간안에 큰 설계를 끝내야 함으로 항상 명확한 범위를 설정해야 합니다. 트위터의 디자인을 설계할때 트윗에 사진과 비디오가 포함되는지, 핫 트렌드 주제를 표시할것인지, 푸시 알림이 있는지, 검색 기능이 있는지 등을 고려해야 합니다.
1. 시스템 설계시 규모도 생각해야 합니다. 나중에 확장, 로드 밸런싱 및 캐싱에 집중할 때에도 도움이 됩니다. 트윗의 수, 트윗 보기 수, 초당 타임라인 생성 수과 같은규모를 고려해야 하고 얼마나 많은 스토리지가 필요한지, 네트워크 대역폭 사용량은 어느정도인지 생각해야 합나디.
1. 시스템에 예상되는 API를 정의합니다.
1. 데이터의 모델을 정의해야 합니다. 어떤 데이터베이스 시스템을 사용할지(NoSQL, SQL을 쓸지)를 정해야 합니다. 읽기/쓰기 요청을 처리하기위해 읽기가 많다면 NoSQL이 유리할 것이고 쓰기 및 업데이트가 많을 경우 SQL이 적합할 것입니다. SQL은 데이터 무결성을 보장해주며 명확한 스키마가 사용자와 데이터에게 중요한 경우 좋고 NoSQL은 정확한 데이터 구조를 알 수 없거나 변경/확장 될 수 있는 경우, 막대한 양의 데이터를 다뤄야 하는 경우 수평으로 확장이 필요한 경우가 적합합니다.
1. 이후 세부 디자인적으로 논의를 할 것입니다. 이때 답은 없는 것을 기억하십시오. 서로 시스템 제약을 염두해 두면서 다른 옵션간의 절충안을 고려해야 합니다.
1. 병목현상에 대한 것을 논의하고 완화하기 위한 다양한 접근 방식을 논의해야 합니다.

## 시스템 디자인시 고려해야 할 점
1. What are the diffrent architectural pieces that can be used?
1. How do these pieces work with each other?
1. How can we best utilize these pieces: what are the right tradeoffs?

## Distributed Systems
* 다음과 같은 개념들이 핵심 개념입니다.
### Scalability
* 

### Reliability

### Availability

### Efficiency

### Manageability



## TinyURL과 같은 URL 단축 서비스 설계
* URL단축은 여러 장치에서 링크를 최적화하고 개별 링크를 추적하여 잠재고객 분석 및 광고 캠페인의 실적을 측정 할 수 있습니다. 혹은 연결된 원본 URL을 숨기는 역할로 사용될 수 있습니다.
* 이 시스템은 읽기가 많을 것입니다. 단축된 URL을 생성하는 횟수보다 리디렉션 요청이 더 많을 것입니다. 그 비율을 100:1이라고 가정을 해봅시다.
  * 트래픽 추정: 100:1의 읽기/쓰기 비율로 매월 500M 개의 새로운 URL 단축이 발생한다고 가정하면 같은 기간 동안 50B의 리다이렉션을 예상 할 수 있을 것입니다. 이때 QPS(Queries Per Second)는 500M / (30 days * 24 hours * 3600 sec) = ~200 URL/s이 되고 리다이렉션은 100 * 200 URL/s = 20,000 URL/s
  * Storage estimates: 모든 URL 단축 요청을 5년동안 저장한다고 가정해보겠습니다. 매월 500M개의 새 URL이 있을 것으로 예상하므로 저장될 총 갯수는 500M * 12 monthes * 5 years = 30B개가 저장되고 하나의 URLdl 500byte라고 한다면 30B * 500 bytes = 15TB가 필요합니다.
  * Bandwidth estimates: 쓰기 요청의 경우 초당 200개의 새 URL이 예상됨으로 총 수신 데이터는 200 * 500bytes = 100KB/s 이 될것입니다. 읽기 요청의 경우 초당 ~20K URL 리다이렉션이 예상됨으로 서비스의 총 나가는 데이터는 20K * 500bytes = 10MB/s가 될 것입니다.
  * Memory estimates: 자주 액세스하는 핫 URL 중 일부를 캐시하려면 이를 저장하는데 URL의 20%가 트래픽의 80%를 생성한다는 80-20 규칙을 따른다면 이 20%의 핫 URL을 메모리에 저장하기 위해서 초당 20,000개의 요청에 관해 하루에 20K * 3600s * 24h = ~1.7 B개의 요청을 받게 됩니다. 이것의 20%를 캐시하려면 0.2 * 1.7B * 500bytes = 170GB가 필요합니다.
* 