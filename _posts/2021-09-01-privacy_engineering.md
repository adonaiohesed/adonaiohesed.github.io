---
title: Privacy engineering
tags: Privacy Engineering Cybersecurity Interview
key: page-privacy_engineering
categories: [Carrer, Interview Tips]
author: hyoeun
mathjax: true
mathjax_autoNumber: true
---

## Basic of privacy engineering
* 데이터 보안과 데이터 프라이버시에 대해 차이를 둬야한다. 보안이란 내외부에서 발생하는 해킹으로부터 데이터를 보호하는 것을 뜻하고 프라이버시는 개인정보에 관한 데이터를 어떤 식으로 수집하고, 다루고, 활용하고 처리하는지에 관한 문제이다.
* Data Privacy is the fair and authorized processing of personal information or PII(Personally Identifiable Information).
* Privacy considerations to think about: differential privacy, user consent, user transparency, federated learning, data retention, minimization, end-to-end encryption, user data flow, anonymization, access control, data protection
* GDPR(General Data Protection Regulation) - 유렵연합의 법이며 유렵경제지역에 속해있는 모든 인구들의 사생활 보호와 개인정보들을 보호해주는 규제이다.
* CCPA(California Consumer Privacy Act) - 최근 켈리포니아에서 나온 법이며 정보를 알 권리, 지울 권리, 접근 할 수 있는 권리, 공유 선택에 관한 권리가 있다.

## Privacy Engineering lifecycle
1. Plan: 데이터의 scope를 설정하고 privacy policy를 리뷰하고 requirements를 identify한다. 그리고 유저 스토리를 작성한다.
1. Develop: Risk, threat, vulnerabilities를 identify한다.
1. Validate: 테스트를 통해 전반적인 controls를 validate하고 Privacy Data Sheet를 작성한다.
1. Launch: Privacy Data sheet을 publish하고 Privacy Policy를 업데이트한다.
1. Operate: Privacy regulation에 변화가 있는지 모니터링하고 privacy controls을 operate한다.
1. Monitor: Privacy policy, requirements, controls을 모니터링하고 required remediation과 함께 리뷰와 업데이트를 진행한다. 이후 전체 과정이 다시 반복.

### Plan
* 데이터의 scope를 잡아라. PII의 type에 따라서 나눠야 한다.
* 데이터의 inventory를 구성해라.
* Privacy Policy(법적으로 고객의 데이터들을 관리해야 하는 방식에 관한 문서)에서부터 Privacy Requirements를 발전시켜야 한다.
* 유저 스토리를 만들어라. 

### Develop
* 

## Different Flavors of Personal Information(PII)
* Direct PII(Linked Information): An individual을 identify할 수 있는데 직접적으로 사용될 수 있는 정보, 예를 들어 이름, DOB, address
* Indirect PII(Linkable Information): 간접적으로 그 사람에 대해 알 수 있는 것 하지만 다른 조합과 합쳐졌을때에만 비로서 제대로 알 수 있는 정보들, 예를 들어 gender, ethnicity, non-specific age
* Sensitive PII: 만약 정보를 잃었을 때, 개인에게 위해가 갈 수 있는 정보들. 예를 들어, SSN, credit score, sexual orientation

## 몇가지 고려해야 할 점
* 사용자의 정보를 persist 하지 마세요.

## 이메일로 로그인 하는 시스템
* 계정을 만들 때, 산입업에 리커버리 코드를 같이 생성하여 그것을 백업 카운트에 보내는 것으로 시스템을 디자인 했습니다.
* 유저는 가입 할 때, 백업 어카운트를 반드시 기입해야했고 거기로 이 플로우에서는 유저의 백업 메일에 대한 데이터를 persist합니다. 이런 경우에서 사용자가 리커버리 코드를 백업 이메일로 보내자마자 그 정보를 지웁니다. 이후에 다시 복구를 위해 백업 이메일을 다시 받습니다. 이런 방식은 프라이버시의 문제를 해결 할 수 있을 뿐더러 백업 업데이트의 정보가 바뀌었을때 데이터의 변화를 잘 적용 할 수 있다.

## Data anonymization
* 저장된 데이터 중, 개인 정보와 직접적으로 연관된 데이터에 식별자를 삭제하거나 인코딩하여 개인 정보를 preserving하는 방법.
* 데이터를 수집하거나 교환할때에도 기밀성이 보존됩니다.
* Data masking: 수정된 값을 공개하는 것이다. *, x와 같은 것으로 의미있는 값들을 수정하여 db에 저장하며 리버스 엔지니어가 힘들게 만든다.
* Pseudonymization: 이름을 완전 다른 사람의 이름으로 바꾸는 것으로 통계쩍 정확성, 데이터 기밀성을 유지하면서 변경된 데이터 프라이버시를 유지 할 수 있도록 하는 툴입니다.
* Generalization: 일부 정보를 일부러 빼서 덜 indentifiable하게 데이터를 만드는 방식. 집 주소의 경우 유닛 번호를 지우는 방식이다. 데이터의 정확성을 유지하면서 특정한 indentifiers를 지우는 작업이다.
* Data swapping: Permutation and shuffling을 통해 기본 데이터를 알 수 없도록 rearrange를 하는 것.
* Data perturbation: Random noise를 추가하고 반올림하는 등의 방식으로 초기 데이터를 변경합니다.
* Synthetic data: 실제 데이터와 관계 없이 알고리즘적으로 생성된 데이터를 의미합니다. 이 데이터는 가상의 데이터 베이스를 만들고 원본 데이터에 포함된 패턴을 가지고 수학적 모델로 만들어집니다.

## 면접 예상 질문
* How would you explain privacy to a normal developer?
* How did you get interested in the field of privacy?
* What would you look at from the privacy perspective when an app like FB dating is ready to go for production?
* If you were to design a consumer app, how would you approach the privacy for that app?
* What privacy concerns would you have for a fb dating app?
* pick a fb product and how would you improve the privacy for it?
* How would you protect this system?
* How would you attack this authentication mechanism?

