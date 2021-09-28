---
title: OWASP Top 10 Mobile- 2017
tags: hacking owasp
key: page-owasp_top_10_mobile
cover: /assets/cover/cyber_security.png
mathjax: true
mathjax_autoNumber: true
---

## Top 10 Mobile Risks
### M1: Improper Platform Usage
#### Threat Agents
* A misuse of a platform feature 혹은 failure to use platform security controls가 포함된다. 예를들어 Android intents, misuse of TouchID, platform permissions, the Keycahin등이 포함 될 수 있다.
* 이 경우는 주로 가이드라인을 제대로 따르지 않거나 의도적이지 않는 misuses로 인해서 발생한다.

#### Vulnerable and prevent
* 안드로이드 intents는 운영 체재내에서 다양한 activity간의 통신을 허용하는 메시징 객체입니다. 이러한 작업에는 백그라운드 서버스와 통신, 모바일 디바이스 또는 다른 앱의서버에 저장된 데이터 접근, 다른 앱 열기와 같은 activity의 시작과 종료가 포함됩니다. 메시지 교환중 데이터 유출 가능성이 생깁니다. 이러한 공격은 permission controle을 통해 다른 앱과 통신을 할 수 있는 앱을 제한하고 허용되지 않은 트래픽의 모든 시도를 차단하면 됩니다. intent내보내기 옵션을 허용하지 않음으로써 다른 앱과 통신할 이유가 없는 컴포넌트를 지킬 수 있습니다. 스니핑의 경우 인텐트 객체의 정의를 명확하기 하는 explicit intent를 통해 제어 할 수 있습니다. 그에 따라 모든 컴포넌트가 인텐트에 포함된 정보에 접근하는 것을 차단합니다.
* ios 키체인은 사용자가 3rd party 계정을 모바일에서 안전하게 사용할 수 있도록 합니다. ios 개발자는 자체 암호화 방법을 도입할 필요 없이 키체인 암호화를 사용 할 수 있습니다. 사용자가 키체인 옵션을 선택하지 않으면 쉬운 암호를 선택하는 경향이 있으며 해커에 의해 악용되기 쉽습니다. 키체인 암호화는 서버 경우를 통해 쓰지 말고 하나의 디바이스에만 보관하여 사용 할 수 있도록 합니다. access controle list를 가져야 하는 앱의 비밀 정보를 저장하기 위해 키체인을 사용하여 앱을 보호하는게 좋습니다.

### M2: Insecure Data Storage
#### Threat Agents
* 공격자가 휴대폰을 주웠거나 훔쳐서 물리적인 접근을 하거나 malware or another repackaged app을 사용하여 디바이스 내에 접근 할 수 있습니다. 물리적 접근의 경우 디바이스를 컴퓨터에 연결하여 파일 시스템에 access할 수 있고 무료로 제공되는 소프트웨어들을 통해 3rd party 애플리케이션 디렉토리 및 PII를 액세스 할 수 있습니다.

#### Vulnerable and prevent
* SQL DB, Log files, XML data stores, Cookies, SD card등에 insecure하게 저장된 데이터들, 혹은 의도치 않았지만 OS, frameworks, compiler environment등과 같은 곳에서도 data leakage가 일어 날 수 있습니다. 또한 개발자가 디바이스내에서 캐시 데이터, 이미지, 키 클릭 및 버퍼를 어떻게 저장하는지 등을 제대로 알지 못해 발생하는 문제이기도 합니다.
* 이러한 문제를 해결하기 위해서는 ios의 경우 iGoat와 같이 purposefully vulnerable mobile app을 사용하여 이러한 취약점에 관한 이해를 높이고 안드로이드 개발자는 ADB쉘을 사용하여 타겟 앱의 파일 권한을 확인하거나 logcat과 같은 명령을 제공하여 개발자가 안드로이드에 포함된 민감한 정보가 유출되는지 여부를 확인 할 수 있습니다. Threat modeling을 하는 것이 중요합니다.

### M3: Insecure Communication
#### Threat Agents
* 모바일 앱간의 데이터 전송은 일반적으로 carrier network를 통해 이루어집니다. Threat agents는 이러한 wire를 across하는 동안 민감한 데이터를 가로채는 공격을 할 것입니다. 사용자가 사용하는 Wi-fi를 통해 모니터링을 하는 공

#### Vulnerable and prevent

### M4: Insecure Data Storage
#### Threat Agents
* 공격자가 휴대폰을 주웠거나 훔쳤을때 혹은 공격자가 악성코드를 작동새킬때 일어날 수 있는 위험이다.

#### Vulnerable and prevent

### M2: Insecure Data Storage
#### Threat Agents
* 공격자가 휴대폰을 주웠거나 훔쳤을때 혹은 공격자가 악성코드를 작동새킬때 일어날 수 있는 위험이다.

#### Vulnerable and prevent

### M2: Insecure Data Storage
#### Threat Agents
* 공격자가 휴대폰을 주웠거나 훔쳤을때 혹은 공격자가 악성코드를 작동새킬때 일어날 수 있는 위험이다.

#### Vulnerable and prevent


### M2: Insecure Data Storage
#### Threat Agents
* 공격자가 휴대폰을 주웠거나 훔쳤을때 혹은 공격자가 악성코드를 작동새킬때 일어날 수 있는 위험이다.

#### Vulnerable and prevent

### M2: Insecure Data Storage
#### Threat Agents
* 공격자가 휴대폰을 주웠거나 훔쳤을때 혹은 공격자가 악성코드를 작동새킬때 일어날 수 있는 위험이다.

#### Vulnerable and prevent