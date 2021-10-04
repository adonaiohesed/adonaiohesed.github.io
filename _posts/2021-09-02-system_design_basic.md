---
title: System Design Basic
tags: privacy system_design
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
* It is the capability of a system, process, or a network to manage increased demand. 증가하는 수요를 위해 evolve할 수 있는 시스템은 scalable하다고 말할 수 있습니다.
* 증가의 이유는 증가된 트랜젝션과 같은 이유로 확장을 할텐데 이때 성능 손실 없이 확장을 해야 합니다. 일반적으로 확장 가능한 시스템 디자인을 했어도 management or environment cost때문에 그런 시스템 확장에 제약이 있는데 예를들면 컴퓨터가 물리적으로 멀리 떨어져 있어서 네트워워크 속도가 느려질 수 있습니다.
* 일부 작업은 atomic한 특성이나 시스템 디자인의 flaw로 인해 분산처리를 할 수 없을텐데 scalable한 아키텍처는 가능한 이러한 상황을 피하고 참여하는 모든 노드의 부하를 균등하게 분산하려고 시도합니다.
* Horizontal scaling은 더 많은 서버를 붙여서 source를 늘리는 것이고 vertical scaling은 기존 서버에 더 많은 전력(CPU, RAM, storage, etc)를 늘리는 것입니다. 수평확장은 동적으로 확장하는 것이 더 쉬운반면 수직 확장은 단일 서버의 capacity에 제한이 되고 해당 용량을 초과할때에는 종종 가동 중지 시간이 포함됩니다. 수평 확장에 좋은 예는 MongoDB이고 수직 확장에 좋은 예는 MySQL입니다.ㅁㅁ

### Reliability
* Reliability is the probability a system will fail in a given period. 분산 시스템은 소프트웨어 또는 하드웨어 구성 요소 중 하나이상의 장애가 발생하더라도 서비스를 계속 제공하는 경우 안정적으로 간주됩니다. redundancy를 통해 하나의 서버에 장애가 생겼을때 바로 다른 정상적인 서버로 서비스를 재개할 수 있는데 이는 비용이 따릅니다.

### Availability
* Availability is the time a system remains operational to perform its required function in a specific period. 이 개념은 relability와 비교가 됩니다. 이것은 사용가능함에 대한 이야기입니다. Reliable하면 available합니다.  Available한다고 reliable한 것은 아닙니다. 사용 가능하다는 것이 안정적인 것을 보장하지는 않습니다.

### Efficiency
* 분산 시스템의 효율성을 측정하기 위해서는 메시지 크기에 관계 없이 시스템의 노드가 전역적으로 보낸 메시지 수와 데이터 교환시 메시지 크기를 단위로 한 응답 시간과 주어진 시간 단위에 보낸 메시지 수의 처리량으로 측정 할 수 있습니다.
* 분산 시스템의 효율성은 메시지 수로만 분석 할 수 없는데 이는 네트워크단의 여러가지 요소를 무시하고 측정하는 것이기 때문입니다. 따라서 우리는 대략적인 수치로만 이러한 효율성을 고려합니다.

### Manageability
* 이것은 시스템을 수리하거나 유지 관리할 수 있는 단순성과 속도입니다. 고장난 시스템을 수정하는 시간이 늘어나면 availability가 줄어듭니다.

## Load balancing
* LB는 분산 시스템의 또 다른 중요한 구성 요소입니다. Responsiveness and availability를 높이는데 도움이 됩니다. 리소스의 상태를 추적하고 오류율이 높은 경우 해당 서버의 트래픽 전송을 차단하고 서버 클러스트 전체에 트래픽을 골고루 분산하는 역할을 합니다.
* LB는 다음 3곳에 추가 할 수 있습니다.
  * Between client and web server
  * 웹 서버와 application server 또는 캐시 서버와 같은 내부 플랫폼 계층 사이
  * Between application server와 DB 사이

### Benefits
* 사용자는 더 빠르고 uniterrupted service를 경험합니다.
* Service providers는 downtime이 적고 더 높은 throughput을 경험합니다.
* 병목 현상이 발생하기 전에 예측 분석을 미리 할 수 있습니다.
* 시스템 관리자는 각 컴퍼넌트들이 덜 streesed받고 fewer failed하는 것을 경험 할 수 있습니다.

### 알고리즘
* Least Connection Method - the fewest active connection을 가진 서버로 트래픽을 보냅니다. 이 방식은 서버 간에 unevenly distributed되었고 persistent client가 많은 경우에 효과적입니다. 왜냐하면 연결은 persistant하게 되지만 서버간의 unevenly distributed되었기 때문에 가장 적은 활동을 하는 서버로 트래픽을 보내면 그 다른 서버의 부하를 줄일 수 있기 때문입니다.
* Least Response Time Method - 이 방식은 fewest active connections이면서 the lowest average response time을 지닌 서버에게 트래픽을 보냅니다.
* Least Bandwidth Method - 초당 메가비트로(Mbps)로 측정된 가장 적은 양의 트래픽을 처리하고 있는 서버를 선택합니다.
* Round Robin Method - 서버 목록을 순환하고 각각의 새 요청을 다음 서버로 보냅니다. 목록의 끝에 도달했을 경우에는 처음 순서의 서버로 다시 보냅니다. 서버의 사양이 동일하고 persistant connection이 많지 않을때 가장 유용합니다.
* Weighted Round Robin Method - 처리 용량이 서로 다른 서버를 더 잘 처리하도록 설계되었습니다. 서버에는 각 가중치가 적용되고 가중치가 높은 서버는 낮은 서버보다 먼저 새 연결을 수신하고 더 많은 연결을 받습니다.
* IP Hash - 클라이언트 IP 주소 해시가 계산되어 요청을 서버로 보냅니다.

### Redundant Load Balancers
* 로드 밸런서 하나만 있을때 장애가 발생하면 다른 밸런서가 그 역할을 대신할 수 있습니다. 동일한 기능을 하는 밸런서를 연결하여 클러스터를 구성할 수 있습니다.

## Caching
* LB는 계속해서 증가하는 서버에서 수평으로 확장할때 도움이 되지만 캐싱은 이미 가지고 있는 리소스를 훨씬 더 잘 사용할 수 있게 도와줍니다.
* 최근 요청한 데이터는 다시 요청될 가능성이 높습니다. 거의 모든 계층에서 가장 최근에 액세스한 항목을 포함하여 불러옵니다. 주로 다운스트림 수준에 부담을 주지 않으면서 빠르게 데이터를 반환하도록 구현되는 프론트 엔드에 가장 가까운 level에 캐시를 설치합니다.

### Application server cache
* 캐시를 요청 노드에 직접 배치하면 응답 데이터를 로컬에 저장 할 수 있습니다. 서비스 요청이 있을때마다 노드는 로컬에 캐시된 데이터가 있으면 바로 반환합니다. 없으면 노드가 디스크에서 데이터를 가져오고 캐시는 메모리와 디스크 어디에도 있을 수 있습니다.
* 노드가 확장될때 각 노드가 자체 캐시 호스트가 될 수도 있지만 LB가 노드 전체에 랜덤하게 요청을 분산하는 경우 동일한 request가 다른 노드로 이동하므로 캐시 miss가 발생하게 될 것입니다. 이를 해결하기 위해서는 global caches와 distributed cashes로 해결합니다.

### Content Delivery (or Distribution) Network(CDN)
* CDN은 large amounts of static media를 제공하는 사이트에서 사용되는 일종의 캐시입니다.
* CDN은 로컬에서 사용할 수 있는 경우 해당 콘텐츠를 제공하고 사용할 수 없는 경우는 백엔드 서버에 파일을 쿼리하고 로컬로 캐시한 다음 사용자에게 요청에 관한 서비스를 제공합니다.
* 우리가 building하려는 시스템이 자체 CDN을 가질만큼 크지 않을 경우에는 subdomain을 두어서 Nginx와 같은 lightweight HTTP 서버를 두어서 static media를 제공합니다.

### Cache Invalidation
* 데이터가 데이터베이스에서 수정이되면 캐시에서 invalidate가 되어야 할 것입니다. 이러한 문제를 해결하는 것을 cache invalidation이라고 합니다.
* 다음과 같은 3가지 main schemes가 있습니다.
  * Write-through cache: 데이터가 캐시와 해당 데이터베이스에 동시에 기록됩니다. 데이터 손실 위험을 최소화 할 수 있지만 모든 쓰기 작업이 두번 수행되어야 하므로 쓰기 작업 대기 시간이 길어지는 단점이 있습니다.
  * Write-around cache: write-through 방식과 유사하지만 데이터가 캐시를 우회하여 permanent storage에 직접 저장됩니다. 이 방식은 다시 읽지 않을 write operation을 줄여 줄 수 있지만 최근에 쓰여진 데이터가 cache miss를 읽으키고 back-end storage에서 읽어야하기 때문에 느릴것입니다.
  * Write-back cache: 이 방식은 일단 캐시에만 데이터를 쓰고 클라이언트에게 즉각적으로 completion을 confirm합니다. 지정된 간격이나 특정 조건하에서 permanent storage에 쓰기 작업이 일어납니다. 쓰기가 많은 어플리케이션에는 low-latency와 high-throughput을 제공하지만 캐시에만 데이터가 있기 때문에 손실 위험이 있습니다.

### Cache eviction policies
* 캐시의 용량이 다 찬 후 캐시 제거를 위한 정책은 다음과 같습니다.
1. First In First Out(FIFO): 캐시가 이전 빈도 또는 횟수에 관계없이 먼저 액세스한 첫 번째 블록을 evict합니다.
1. Last In First Out(LIFO): 빈도 및 횟수 관계없이 가장 최근에 액세스한 최근(마지막)에 access한 블록을 먼저 제거합니다.
1. Least Recently Used(LRU): 가장 적게 사용된 항목을 버립니다.
1. Most Recently Used(MRU): 가장 최근에 used한 item을 버립니다.
1. Least Frequently Used(LFU): item이 사용된 빈도수를 계산하고 가장 적게 사용된 것을 폐기합니다.
1. Random Replacement(RR): 무작위로 선택하고 공간을 만들기 위해 아이템을 버립니다.

## Data Partitioning
* 큰 DB를 여러개의 작은 부분으로 나누는 기술입니다.
* 애플리케이션의 관리를 용이하게 하기 위해서나 로드 밸런싱을 개선하기 위해 여러 시스템에 걸쳐 DB/table을 분할하는 프로세스 입니다.
* 이 방식은 강력한 서버를 두어 vertically grow하는 것이 아니라 horizontally add하는 것이 더 좋은 방법일때 data partitioning을 쓰는게 좋습니다.

### Partitioning Methods
* Horizontal Partitioning: Diffrent row를 다른 테이블에 넣습니다. 예를들어 우편번호의 정보를 넣을때 1-10000에 해당하는 정보들은 하나의 테이블에 넣고 그 이상의 우편번호들은 다른 테이블에 넣습니다. 이러한 특성 때문에 range-based Partitioning 혹은 Data Sharding이라고 불립니다. 이 방식은 range의 기준을 제대로 잡지 못한다면 unbalanced server가 되어버릴 것입니다.
* Vertical Partitioning: 이 방식은 a specific feature로 각자의 서버에 테이블을 저장하는 것입니다. 트위터의 경우 유저 정보, 유저가 올린 사진 자료, 팔로워들에 대한 데이터들을 각각 별개의 테이블로 각자 다른 DB에 저장하게 하는 것입니다. 이 방식은 구현이 직관적이고 어플리케이션에 영향을 덜 미칩니다. 하지만 이 방식의 문제점은 서버가 growth할때 기능별 DB를 추가로 partition해야 할것입니다. 왜냐하면 단일 서버에서 140 million user의 10 billion photos를 처리 할 수 없기 때문입니다. 
* Directory-Based Partitioning: 위 두가지의 문제를 어느정도 해결할 수 있는 방식은 lookup service table을 만들어서 우리가 이미 partitionoing한 정보를 알고 DB 액세스 코드를 가져오는 방식으로 partitioning을 하는 것입니다. 따라서 특정 data entity가 어디에 reside하는지 찾기 위해 directory server에 query를 날려서 결과를 얻습니다. 그 서버는 tuple key와 DB 서버간에 맵핑 정보를 지니고 있습니다. 이러한 방식은 애플리케이션에 영향을 주지 않고 DB pool에 서버를 추가하거나 partitioning scheme를 바꿀 수 있게 해줍니다. 하지만 찾는 cost가 조금 더 들것입니다.

### Partitioning Criteria
* Criteria는 method와는 다르게 각 테이블을 어떻게 split해서 다른 server에 분배하느냐이다. Method는 좀 더 큰 의미로 어떤 방식으로 partitioning을 할 것인지, organize the table을 할 것인지에 대한 개념이다. Vertical로 나눌때에도 hash-based partitioning기법으로 각 사진 특성에 대해 서로 다른 테이블로 data를 partitioing 할 수 있다. 
* Key or Hash-based Partitioning: 저장할 entity의 일부 특성을 가지고 hash function을 적용합니다. 그리고 그 digest를 partition number로 사용합니다. 100개의 DB서버가 있다고 할 때, 새로운 레코드가 삽입될때마다 해시 함수는 ID%100이 될것이며 서버간에 데이터를 균일하게 할당할 것입니다. 하지만 이 방식은 새로운 서버가 추가 되었을때 데이터를 redistribution해야 하며 그 동안 service에 downtime이 생길 것입니다. 
* List partitioning: 각 파티션에는 a list of values가 있으므로 우리가 새로운 레코드를 넣으려고 할때 어떤 partition이 키를 contain하고 있는지 확인 한 다음 저장할 것입니다. 예를들어 스웨덴, 필란드, 또는 덴마크에 관한 데이터는 Nordic countries에 관한 partition에 저장될 것입니다.
* Roudn-robin partitioning: 균일한 데이터 배포를 보장하는 간단한 전략입니다. n개의 partition으로 i개의 tuple을 파티션에 할당합니다. (i mod n)
* Composite Partitioing: 위 방식들 중 하나 이상을 혼합하여 새로운 방식을 만듭니다. List partitioning후 hash-based partitioning을 할 수 있을 것입니다. Consistent hashing은 hash로 key-space를 줄이고 list한 composition partitioing의 한 종류로 생각 할 수 있습니다.

### Common Problems of Data Partitioning
* 파티셔닝이 된 데이터베이스에는 join과 같은 여러가지 operation에 대한 constraints가 존재합니다. 왜냐하면 더 이상 동일한 서버에서 여러 작업이 실행되지 않기 때문입니다.
* Joins and Denormalization: 한 서버에서는 join을 실행하는 것이 간단하지만 데이터베이스가 분할되고 여러 시스템에 분산되면 join을 실행 할 수 없을 수도 있습니다. 이러한 join을 실행시키려면 여러 서버에서 데이터가 컴파일되어야 해서 성능이 효율적이지 않습니다. 이것을 해결하기 위해서는 DB의 denormalize인데 이러면 data inconsistency와 같은 denormalization's perils(위험)을 가지게 됩니다. 여기서 denormalization이란 읽는 시간을 최적화 하도록 설계된 데이터베이스이며 join 연산의 비용을 줄일 수 있습니다. 하나 이상의 테이블에 데이터를 중복해 배치합니다. 예를들어 courses와 teachers라는 두 테이블이 있을때 courses 테이블에 teacherID는 들어갈 수 있어도 teacherName은 안 들어갈 것이다. 왜냐하면 teachers 테이블에 이미 그 데이터가 있기에 중복할 필요가 없기 때문이다. 정규화 테이블에서는 course name과 teacher name을 얻기 위해서 두 테이블을 join할 것이다. 하지만 데이터가 많아지면 이러한 join이 힘들어진다. 이때 데이터를 중복하면서까지 비정규화 과정을 거치게 되는 것이다. 하지만 그만큼 중복된 데이터가 많기 때문에 저장공간이 더 필요로 하고 어느 데이터(teacherID, teacherName)이 올바른 것인지 검증하기 어려울 수 있다. 데이터를 고치려면 둘다 고쳐야 하기 때문이다. 데이터 update나 write비용이 더 들게 되고 코드 작성도 보다 어렵다.
* Referential integrity: 파티셔닝이 된 데이터베이스에서는 integrity constraints와 같은 integrity가 지켜지기 어려울 수 있습니다. 서로 다른 데이터베이스 서버에는 그런 constraint를 지원하지 않습니다(지원할 경우 외래키가 함부로 삭제 될 수 없게 함). 때문에 애플리케이션에서 이런 SQL 작업을 실행해야 합니다. 
* Rebalancing: 파티셔닝 scheme을 바꿔야 하는 경우는 데이터 distribution이 균일하지 않거나 특정 파티션에 load가 많은 경우가 그렇습니다. 이러한 경우 더 많은 DB 파티션을 creat하거나 기존 파티션을 rebalance해야 합니다. 즉 모든 기존 데이터가 새 위치로 이동하게 됩니다. 이때 downtime없이 이 작업ㅇ르 수행하는 것은 매우 어렵습니다. dicrectory-based partitioning을 하면 시스템의 복잡성이 증가되고 새로운 single point of failure가 생기지만 보다 나은 experience를 줄 수 있습니다.

## Indexes
* Indexes는 데이터베이스와 관련해서 잘 알려져 있습니다. 데이터 베이스의 성능이 만족스럽지 않을때 인덱싱을 먼저 확인해야 합니다. 인덱스는 테이블을 더 빠르게 검색하고 원하는 행을 찾게 도와줍니다. 빠른 랜덤 조회와 정렬된 레코드의 효율적인 액세스를 위한 기반을 제공합니다.
* 인덱스는 속도를 드라마틱하게 올릴 수 있지만 추가 키때문에 자체적으로 크기가 커질 수 있습니다.
* Active index가 있는 테이블에 대해 row를 추가하거나 기존 row를 업데이트할 때 인덱스도 같이 업데이트 됩니다. 이것이 write performance를 떨어뜨립니다. 이러한 이유로 테이블에 불필요한 인덱스를 추가하는 것은 피하고 더 이상 사용하지 않는 인덱스는 제거해야 합니다.
* 인덱스를 더하는 것은 search queri의 performance를 향상시키는 것이고 database의 goal은 거의 읽히지 않고 자주 사용되는 데이터를 저장하는 데이터 저장소의 역할을 제공한다고 할 수 있습니다. 이 경우 자주 사용하는 operation의 performance(write)의 performance가 떨어진다는 것은 reading을 위해 performance가 증가하는것 보다 가치가 있지 않습니다.
* 인덱스를 사용하지 않는 칼럼을 조회하는 경우 full scan을 할 것입니다. Indx가 적용된 컬럼에 insert, update, delete가 수행된다면 인덱스를 추가하거나, 기존 인덱스를 사용하지 않고 업데이트된 데이터에 인덱스를 추가하거나, 삭제하는 데이터의 인덱스를 사용하지 않는다는 작업들을 해야해서 오버헤드가 생깁니다.

## Proxies
* 프록시 서버는 클라이언트와 백엔드 서버 사이의 중간 서버입니다. 다른 서버의 리소스를 찾는 클라이언트의 요청에 대한 중개 역할을 하며 모든 프록시 서버는 캐싱이 가능합니다.
* 하드웨어, 또는 소프트웨어 형태로 있을 수 있습니다.
* 프록시는 요청을 필터링 하거나 헤더를 추가하거나 지우는 등의 작업, 암호화 작업등 transform request를 하고 많은 request에 관해 cache합니다.
* Proxy(대리) Server는 클라이언트가 서버의 정보를 요구할때 대신 서버에 요청을 보내기때문에 클라이언트의 ip를 숨기고 proxy 서버의 ip를 통해 대화하게 됩니다. 따라서 개인정보를 보호 할 수 있습니다.
* 다음은 프록시 서버의 types에 관한 설명이다.

### Open Proxy
* 모든 인터넷 사용자가 액세스 할 수 있는 프록시 서버입니다. 일반적으로 프록시 서버는 closed proxy로 특정 그룹의 사용자만을 위해 DNS or web pages와 같은 인터넷 서비스를 포워드 합니다. 다음과 같은 2가지 유형이 있습니다.
  * Anonymous Proxy: 서버로써 정보를 드러내지만 initial IP address는 숨깁니다. 그 정보가 밝혀질 수는 있을지라도 클라이언트가 IP를 숨기고자 하려고 할 때 사용 될 수 있습니다.
  * Transparent Proxy: 서버와 first IP address 모두를 볼 수 있는 HTTP headers를 지원합니다. 주로 웺사이트를 캐시하는데 사용 됩니다. 회사의 경우 프록시 서버를 통해 SNS 접속을 차단 할 수도 있고 조직의 트래픽을 모니터링 하는데 사용 될 수도 있습니다. 또한 캐싱을 통해 100대의 업데이트가 아닌 프록시 서버 1대의 업데이트로 대역폭을 줄여 줄 수 있습니다.
  
### Reverse Proxy
* 클라이언트가 특정 웹사이트 혹은 서버에 리퀘스트를 날릴때 서버에 직접 가지 않고 리버스 프록시가 대신 회사 내의 서버에 요청을 한 후 그 resource를 받아 다시 client에게 전달하게 도와주는 것입니다. 이렇게 하면 client는 마치 reverse proxy가 서버인 것으로 알게되고 회사 내의 네트워크 자체를 숨길 수 있습니다. 보안이 더 강해지며 우리가 WEB(Apache, nginx)를 DMZ에 두고 WAS(Tomcat)을 분리하여 내부망에 분리하는 형태를 reverse proxy라고 볼 수 있다. 이때, WEB이 reverse proxy이다.

