---
title: Automating Mac Mini and MacBook Air Setup - AirPlay Connect and Audio Device Switching
tags: Automator
key: page-mac_mini_air_automator
categories: [Tools, MacOS]
author: hyoeun
mathjax: true
mathjax_autoNumber: true
---

# Setting Up Mac Mini and MacBook Air Environment with Automator

Recently, I decided to purchase a Mac Mini after experiencing performance issues with my MacBook Air. However, one major downside of the Mac Mini is its poor built-in speaker quality. While my MacBook Air wasn’t completely unusable, I wanted to find a way to use both devices effectively.

I ultimately set up my workspace by placing a monitor connected to the Mac Mini at the center of my desk, with the MacBook Air positioned underneath it. For better audio quality while watching videos, I used **AirPlay** to play sound through the MacBook Air speakers.

However, I discovered that **AirPlay and Universal Control** cannot be used simultaneously. To efficiently use both devices together, I decided to implement keyboard shortcuts for connecting and disconnecting AirPlay.

The two features I needed were:
1. A shortcut to **connect** AirPlay.
2. A shortcut to **disconnect** AirPlay  
   (achieved by switching to another audio device).

## Setting Up an AirPlay Connection Shortcut with Automator

Mac provides a built-in tool called **Automator**, which allows you to create scripts and assign them to keyboard shortcuts.

### Step-by-Step Guide

1. **Create a Quick Action Flow**  
   Open Automator and create a new **Quick Action**.  
   ![Automator Quick Action](/assets/images/automator_quick_action.png)

2. **Add AppleScript**  
   From the left-hand menu, select **Utilities > Run AppleScript**, then drag it into your flow.  
   ![Automator Run AppleScript](/assets/images/automator_script.png)

3. **Save and Assign a Shortcut**  
   Save the Quick Action, then go to **System Preferences > Keyboard > Shortcuts > Services** to assign a desired shortcut.  
   ![Automator Keyboard shortcut setting](/assets/images/automator_keyboard_shortcut.png)

	```shell
	on run {input, parameters}
		
		set devicesToSwitchBetween to {"Mac mini Speakers", "LG HDR 4k", "LG HDR WQHD", "Hyoeun’s MacBook Air"}
		
		set end of devicesToSwitchBetween to first item of devicesToSwitchBetween
		
		tell application "System Events" to tell process "Control Center"
			repeat with menuBarItem in every menu bar item of menu bar 1
				if description of menuBarItem as text is "Sound" then
					set soundMenuBarItem to menuBarItem
					exit repeat
				end if
			end repeat
			
			click soundMenuBarItem
			
			set currentDevice to (first checkbox of scroll area 1 of group 1 of window "Control Center" whose value is 1)
			set currentDeviceId to (value of attribute "AXIdentifier" of currentDevice)
			set currentDeviceName to text 14 thru -1 of currentDeviceId
			
			set existingDevices to {}
			repeat with currentCheckbox in every checkbox of scroll area 1 of group 1 of window "Control Center"
				set deviceId to value of attribute "AXIdentifier" of currentCheckbox
				set deviceName to text 14 thru -1 of deviceId
				set end of existingDevices to deviceName
			end repeat
			
			set nextDeviceName to "None"
			set shouldSetNext to false
			
			repeat with deviceName in devicesToSwitchBetween
				if shouldSetNext and deviceName is in existingDevices then
					set nextDeviceName to deviceName
					exit repeat
				end if
				if deviceName as string is equal to currentDeviceName as string then
					set shouldSetNext to true
				end if
			end repeat
			
			repeat with currentCheckbox in every checkbox of scroll area 1 of group 1 of window "Control Center"
				set deviceId to value of attribute "AXIdentifier" of currentCheckbox
				set deviceName to text 14 thru -1 of deviceId
				if deviceName as string is equal to nextDeviceName as string then
					click currentCheckbox
					click soundMenuBarItem
					exit repeat
				end if
			end repeat
			
		end tell
		return input
	end run
	```

## Setting Up an AirPlay Disconnect Shortcut (Switch to Another Audio Device) with Automator

To disconnect AirPlay and switch to another audio device, I used a program called **SwitchAudioSource**, which made the process simple.

### Steps to Set It Up

1. **Install SwitchAudioSource**  
	Install SwitchAudioSource using the following command:
	```bash
	brew install switchaudio-osx
	```

2. **List Available Audio Devices**  
	Check the names of all available audio devices to identify the one you want to use.
	```bash
	SwitchAudioSource -a
	```

3. **Create and Save an AppleScript**  
	Use the desired audio device name to create an AppleScript and save it as a Quick Action, similar to the AirPlay connection setup.
	```shell
	on run {input, parameters}
		
		do shell script "/opt/homebrew/bin/SwitchAudioSource -s 'Mac mini Speakers'"
		
		return input
	end run
	```

4. **Assign a Shortcut**  
	Go to **System Preferences > Keyboard > Shortcuts > Services**, find the saved script, and assign an appropriate shortcut.

---

# Mac Automator를 이용한 맥 미니와 맥북 에어 환경 설정
최근 맥북 에어를 사용하던 중 성능 저하를 느껴 맥 미니를 새로 구매했습니다. 하지만 맥 미니의 가장 큰 단점은 내장 스피커의 음질이 좋지 않다는 점이었습니다. 기존 맥북 에어는 성능 저하가 있었지만 여전히 사용 가능했기 때문에, 맥 미니와 함께 활용할 방법을 고민했습니다.
결론적으로, 책상 중앙에 맥 미니와 연결된 모니터를 배치하고 그 아래에 맥북 에어를 두는 방식으로 설정했습니다. 영상을 시청할 때는 **AirPlay**를 이용해 맥북 에어의 스피커를 사용하는 방법을 고안했습니다.
그러나 **AirPlay와 유니버설 컨트롤**을 동시에 사용할 수 없다는 점이 문제였습니다. 따라서 키보드 단축키를 통해 AirPlay를 연결하거나 해제하는 기능을 구현해 두 기기를 더 효율적으로 사용할 수 있도록 했습니다.

필요했던 두 가지 기능은 다음과 같습니다:
1. AirPlay를 **연결**하는 단축키
2. AirPlay를 **해제**하는 단축키  
   (이 작업은 다른 오디오 장치로 전환하는 방식으로 처리 가능합니다.)

## Automator를 이용한 AirPlay 연결 단축키 설정
Mac에는 기본적으로 제공되는 **Automator**라는 도구가 있습니다. 이를 활용해 스크립트를 작성하고, 키보드 단축키로 실행할 수 있습니다.

### 단계별 설정 방법

1. **Quick Action 플로우 생성**  
   Automator를 열고 **새로운 Quick Action**을 생성합니다.  
   ![Automator Quick Action](/assets/images/automator_quick_action.png)

2. **AppleScript 추가**  
   왼쪽 메뉴에서 **Utilities > Run AppleScript**를 선택해 플로우에 드래그합니다. 그런 다음 아래 코드를 복사해 붙여넣습니다.  
   ![Automator Run AppleScript](/assets/images/automator_script.png)

3. **저장 후 단축키 지정**  
   작업을 저장한 후, **시스템 환경설정 > 키보드 > 단축키 > 서비스**로 이동하여 저장한 스크립트를 찾아 원하는 단축키를 지정합니다.  
   ![Automator Keyboard shortcut setting](/assets/images/automator_keyboard_shortcut.png)

	```shell
	on run {input, parameters}
		
		set devicesToSwitchBetween to {"Mac mini Speakers", "LG HDR 4k", "LG HDR WQHD", "Hyoeun’s MacBook Air"}
		
		set end of devicesToSwitchBetween to first item of devicesToSwitchBetween
		
		tell application "System Events" to tell process "Control Center"
			repeat with menuBarItem in every menu bar item of menu bar 1
				if description of menuBarItem as text is "Sound" then
					set soundMenuBarItem to menuBarItem
					exit repeat
				end if
			end repeat
			
			click soundMenuBarItem
			
			set currentDevice to (first checkbox of scroll area 1 of group 1 of window "Control Center" whose value is 1)
			set currentDeviceId to (value of attribute "AXIdentifier" of currentDevice)
			set currentDeviceName to text 14 thru -1 of currentDeviceId
			
			set existingDevices to {}
			repeat with currentCheckbox in every checkbox of scroll area 1 of group 1 of window "Control Center"
				set deviceId to value of attribute "AXIdentifier" of currentCheckbox
				set deviceName to text 14 thru -1 of deviceId
				set end of existingDevices to deviceName
			end repeat
			
			set nextDeviceName to "None"
			set shouldSetNext to false
			
			repeat with deviceName in devicesToSwitchBetween
				if shouldSetNext and deviceName is in existingDevices then
					set nextDeviceName to deviceName
					exit repeat
				end if
				if deviceName as string is equal to currentDeviceName as string then
					set shouldSetNext to true
				end if
			end repeat
			
			repeat with currentCheckbox in every checkbox of scroll area 1 of group 1 of window "Control Center"
				set deviceId to value of attribute "AXIdentifier" of currentCheckbox
				set deviceName to text 14 thru -1 of deviceId
				if deviceName as string is equal to nextDeviceName as string then
					click currentCheckbox
					click soundMenuBarItem
					exit repeat
				end if
			end repeat
			
		end tell
		return input
	end run
	```

## Automator를 이용한 AirPlay 연결 해제(다른 오디오 장치로 전환) 단축키 설정

AirPlay 연결을 해제하고 다른 오디오 장치로 전환하는 단축키는 **SwitchAudioSource**라는 프로그램을 이용해 쉽게 구현할 수 있습니다.

### 설정 단계

1. **SwitchAudioSource 설치**  
   아래 명령어를 사용하여 SwitchAudioSource를 설치합니다.
   ```bash
   brew install switchaudio-osx
   ```

1. **변경 가능한 오디오 장치 확인**
	설치 후, 사용할 수 있는 오디오 장치의 이름을 확인합니다.
	```bash
	SwitchAudioSource -a
	```

1. **AppleScript 작성 및 저장**
	원하는 오디오 장치 이름을 사용하여 아래 AppleScript를 작성하고, 이전 AirPlay 연결 설정과 동일하게 Quick Action으로 저장합니다.
	```shell
	on run {input, parameters}
		
		do shell script "/opt/homebrew/bin/SwitchAudioSource -s 'Mac mini Speakers'"
		
		return input
	end run
	```

1. **단축키 지정**
	작성한 Quick Action을 시스템 환경설정 > 키보드 > 단축키 > 서비스에서 찾아 적절한 단축키로 지정합니다.