---
title: Tiny URL case
tags: TinyURL Web Case-Study
key: page-tiny_url_case
categories: [Software Engineering, Web]
author: hyoeun
math: true
mathjax_autoNumber: true
---

## URL Shortening Service Design Like TinyURL
* URL shortening can optimize links across multiple devices and track individual links to analyze potential customers and measure advertising campaign performance. Alternatively, it can be used to hide the original connected URL.
* This system will be read-heavy. There will be more redirection requests than URL shortening creation. Let's assume a ratio of 100:1.
  * Traffic Estimates: Assuming 500M new URL shortenings per month with a 100:1 read/write ratio, we can expect 50B redirections during the same period. The QPS (Queries Per Second) would be 500M / (30 days * 24 hours * 3600 sec) = ~200 URLs/s, and redirections would be 100 * 200 URLs/s = 20,000 URLs/s.
  * Storage Estimates: Assuming we store all URL shortening requests for 5 years. With 500M new URLs expected monthly, the total number of stored URLs would be 500M * 12 months * 5 years = 30B. If each URL is 500 bytes, we would need 30B * 500 bytes = 15TB of storage.
  * Bandwidth Estimates: For write requests, with 200 new URLs expected per second, the total incoming data would be 200 * 500 bytes = 100KB/s. For read requests, with ~20K URL redirections expected per second, the total outgoing data for the service would be 20K * 500 bytes = 10MB/s.
  * Memory Estimates: To cache some frequently accessed hot URLs, following the 80-20 rule where 20% of URLs generate 80% of traffic, for the 20% hot URLs to be stored in memory: With 20,000 requests per second, we'd receive ~1.7B requests per day (20K * 3600s * 24h). To cache 20% of this, we'd need 0.2 * 1.7B * 500 bytes = 170GB.

## System API Design
* Once requirements are finalized, it's always good to define the system APIs.
* The service functionality can be exposed through SOAP or REST APIs.

## TinyURL과 같은 URL 단축 서비스 설계
* URL단축은 여러 장치에서 링크를 최적화하고 개별 링크를 추적하여 잠재고객 분석 및 광고 캠페인의 실적을 측정 할 수 있습니다. 혹은 연결된 원본 URL을 숨기는 역할로 사용될 수 있습니다.
* 이 시스템은 읽기가 많을 것입니다. 단축된 URL을 생성하는 횟수보다 리디렉션 요청이 더 많을 것입니다. 그 비율을 100:1이라고 가정을 해봅시다.
  * 트래픽 추정: 100:1의 읽기/쓰기 비율로 매월 500M 개의 새로운 URL 단축이 발생한다고 가정하면 같은 기간 동안 50B의 리다이렉션을 예상 할 수 있을 것입니다. 이때 QPS(Queries Per Second)는 500M / (30 days * 24 hours * 3600 sec) = ~200 URL/s이 되고 리다이렉션은 100 * 200 URL/s = 20,000 URL/s
  * Storage estimates: 모든 URL 단축 요청을 5년동안 저장한다고 가정해보겠습니다. 매월 500M개의 새 URL이 있을 것으로 예상하므로 저장될 총 갯수는 500M * 12 monthes * 5 years = 30B개가 저장되고 하나의 URLdl 500byte라고 한다면 30B * 500 bytes = 15TB가 필요합니다.
  * Bandwidth estimates: 쓰기 요청의 경우 초당 200개의 새 URL이 예상됨으로 총 수신 데이터는 200 * 500bytes = 100KB/s 이 될것입니다. 읽기 요청의 경우 초당 ~20K URL 리다이렉션이 예상됨으로 서비스의 총 나가는 데이터는 20K * 500bytes = 10MB/s가 될 것입니다.
  * Memory estimates: 자주 액세스하는 핫 URL 중 일부를 캐시하려면 이를 저장하는데 URL의 20%가 트래픽의 80%를 생성한다는 80-20 규칙을 따른다면 이 20%의 핫 URL을 메모리에 저장하기 위해서 초당 20,000개의 요청에 관해 하루에 20K * 3600s * 24h = ~1.7 B개의 요청을 받게 됩니다. 이것의 20%를 캐시하려면 0.2 * 1.7B * 500bytes = 170GB가 필요합니다.

## 시스템 API 설계
* 요구 사항을 확정하고 나면 항상 시스템 API를 정의하는 것이 좋습니다.
* SOAP 또는 REST API를 통해 서비스의 기능을 노출 할 수 있습니다.