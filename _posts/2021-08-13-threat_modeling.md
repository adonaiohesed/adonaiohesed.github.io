---
title: Threat Modeling
tags: Threat-Modeling Cybersecurity Risk-Management
key: page-threat_modeling
categories: [Cybersecurity, Risk Management]
author: hyoeun
mathjax: true
mathjax_autoNumber: true
---

## Threat Modeling이란?
* 애플리케이션이나 컴퓨터 시스템에 해를 일으킬 수 있는 위협요소의 타입들을 identifying하는 작업이다.
* Threat modeling works by identifying the types of threat agents that cause harm to an application or computer system.
* 보통 4가지의 스텝이 있다.
  1. Diagram - 전체적인 구조를 표현한다.
  1. Identify threats - 위협 요소들을 점검한다.
  1. Mitigtate - 위협요소를 defend할 방법을 찾는다.
  1. Validate - 우리가 해왔던 것들을 점검한다.
* Threat modeling을 위해서 Architecture, secure status, identify valueable assests, identify possible threat type을 알고 있어야 된다.
* 한번 하고 끝나는 것이 아니라 지속적으로 관리해야하고 코드에 관한 것만이 아닌 모든 것에 관한 것이다.
* Data Flow Diagrame으로 시작을 할 수 있고 화이트 보드도 좋지만 지속적으로 관리해야 함을 잊어서는 안 된다.

## 주로 언급되는 4가지 방법론
### STRIDE(Based on type of threat)
* 다음 6가지 위협을 기반으로 threat modeling을 진행한다.
1. Spoofing - 다른 이용자의 권한을 이용해서 시스템의 접근 권한을 획득하는 위협. - Authentication로 대처, 전자 서명, 적절한 인증(패스워드, 홍채인식 등)
1. Tampering - 시스템에 있는 정보를 악의적으로 수정한다. - Integrity로 대처, 해쉬, 전자 서명
1. Repudiation - 공격을 했으나 그 공격을 부인하는 위협. - Non-repudiation으로 대처, 전자 서명, 감시 로그
1. Information Disclosure - 민감한 데이터를 유출시키는 위협 - Confidentiality로 대처, 암호화
1. Denial of Service - 시스템을 정상적으로 사용할 수 없도록 만드는 위협 - Availability로 대처, 필터링, 공격 모니터링, 
1. Elevation of Privilege - 권한이 없는 유저의 권한을 올려버리는 위협 - Authorization으로 대처

### DREAD(Based on level of dangerous threat)
* 각 항목들에 따라서 High, Medium, Low로 점수를 매겨 총점으로 공격의 위험도를 나타낸다. 이런 방법은 경력이 많은 보안 담당자가 해야 하고 이것의 신빙서은 그 작성자의 권위와 실력에서 나온다. 또는 fire eye와 같은 리포트에서 나온 점수를 기반으로 이러한 점수를 매길 수도 있다.
1. Damage Potential - 피해가 어느정도 시스템에 영향을 줄지
1. Reproducibility - 피해가 얼마나 쉽게 반복적으로 일어 날 수 있는지
1. Exploitability cost - 공격을 하기 위해 얼마나 비용이 드는지(비용이 적게 들수록 위험한거다)
1. Affected users - 몇명의 사용자가 피해를 입을지
1. Discoverability - 얼마나 찾기 쉬운 공격일지
* $$ Risk value = {(Damage + Affected users) * (Reproducibility + Exploitability + discoverability)} $$
