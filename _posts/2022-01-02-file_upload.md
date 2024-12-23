---
title: File upload feature test
tags: File-Upload
key: page-file_upload
categories: [Cybersecurity, Web Security]
author: hyoeun
mathjax: true
mathjax_autoNumber: true
---

파일 업로드 기능이 있을때에는 다음과 같은 것들을 확인해보면 됩니다. 기본적으로 개발자 입장에서는 white-list or allowlist approach가 이상적입니다.

## Check list
1. 파일 확장자 확인하기.
    - 압축파일일 경우 안의 내용도 확인해야합니다. target path, level of compression, estimated unzip size를 체크해야합니다.
    - .jpg.php 와 같이 double extensions 체크합니다.
    - Null bytes such as exploit.jpg%00.php or exploit.jpg\00.php 와 같이 .php가 실행되는지 체크합니다.
    - 비즈니스 로직에 알맞은 확장자만 허용을 하고 least harmful and lowest risk file type으로 정합니다.
    - svg 파일을 허용할 경우 SSRF, XXE, XXS 공격에 취약할 수 있다.
1. File size check - 한도보다 큰 사이즈의 파일을 올릴 수 있는건 아닌지 확인해야합니다.
    - [Large size file download site](https://testing.taxi/blog/325-giant-file-generator-tool/)
1. Eicar를 이용한 malicious content 기능이 있는지 확인합니다.
1. Upload된 파일 Path가 client에서 정해지는지 확인해야합니다. file path는 server단에서 랜던하게 정해져야합니다.
1. Content-type이 확장자와 제대로 매칭되어 있는지 확인합니다.
1. 허용하는 파일 확장자 중에서 Web executable script files인 aspx, asp, css, swf, xhtml, rhtml, shtml, jsp, js, pl, php, cgi가 있는지 확인합니다. 있으면 관련 공격을 시도해봅니다.
1. Image 업로드가 가능한 경우 악성 코드가 담긴 .php파일을 .jpg로 바꿔서 업로드 하거나 악성파일을 올린채 content-type을 image/jpeg로 바꿔서 공격해봅니다.
1. 파일 이름의 길이제한을 확인합니다. 10000이상의 파일 이름으로 공격을 시도해봅니다.
1. Authorized users만 file upload가 가능한지 체크합니다.
1. File을 다른 서버에 저장한지 안 한지 확인하기. 최소한 webroot 밖에 다른 곳에 저장하는 것이 안전합니다.
1. 파일 실행이 sanbox에서 이루어지는지 체크합니다.
1. 파일 이름을 "/><svg onload = alert(document.cookie)> 와 같이 바꾸어서 업로드해봅니다.

## Content Type
Content-Type 헤더는 HTTP 프로토콜에서 전송되는 데이터의 유형을 나타내며, MIME(Multipurpose Internet Mail Extensions) 타입을 기반으로 정의됩니다. Content-Type 값은 클라이언트와 서버가 데이터를 올바르게 처리하고 해석할 수 있도록 도움을 줍니다.

### 1. **텍스트 타입**
텍스트 데이터에 사용되며, 사람이 읽을 수 있는 콘텐츠를 나타냅니다.

- `text/plain`: 기본 텍스트 파일 (예: `.txt`)
- `text/html`: HTML 문서 (예: `.html`)
- `text/css`: CSS 스타일시트 (예: `.css`)
- `text/javascript` 또는 `application/javascript`: JavaScript 파일 (예: `.js`)
- `text/csv`: CSV 파일 (예: `.csv`)

### 2. **애플리케이션 타입**
주로 바이너리 데이터나 특수 데이터를 나타냅니다.

- `application/json`: JSON 데이터 (예: API 응답)
- `application/xml`: XML 데이터 (예: `.xml`)
- `application/x-www-form-urlencoded`: URL 인코딩된 폼 데이터
- `application/pdf`: PDF 문서 (예: `.pdf`)
- `application/zip`: ZIP 압축 파일 (예: `.zip`)
- `application/x-httpd-php`: PHP 파일 (예: `.php`)
- `application/octet-stream`: 임의의 바이너리 데이터 (예: 파일 다운로드)
- `application/vnd.ms-excel`: Microsoft Excel 파일 (예: `.xls`)
- `application/vnd.openxmlformats-officedocument.spreadsheetml.sheet`: Excel Open XML 형식 (예: `.xlsx`)

### 3. **이미지 타입**
이미지 데이터를 나타냅니다.

- `image/jpeg`: JPEG 이미지 (예: `.jpg`, `.jpeg`)
- `image/png`: PNG 이미지 (예: `.png`)
- `image/gif`: GIF 이미지 (예: `.gif`)
- `image/svg+xml`: SVG 이미지 (예: `.svg`)
- `image/webp`: WebP 이미지 (예: `.webp`)

### 4. **오디오 타입**
오디오 데이터를 나타냅니다.

- `audio/mpeg`: MP3 오디오 파일 (예: `.mp3`)
- `audio/ogg`: Ogg Vorbis 오디오 파일 (예: `.ogg`)
- `audio/wav`: WAV 오디오 파일 (예: `.wav`)
- `audio/flac`: FLAC 오디오 파일 (예: `.flac`)

### 5. **비디오 타입**
비디오 데이터를 나타냅니다.

- `video/mp4`: MP4 비디오 파일 (예: `.mp4`)
- `video/webm`: WebM 비디오 파일 (예: `.webm`)
- `video/ogg`: Ogg 비디오 파일 (예: `.ogv`)

### 6. **멀티파트 타입**
복합적인 데이터를 전송하는 데 사용됩니다.

- `multipart/form-data`: 파일 업로드를 포함한 폼 데이터
- `multipart/alternative`: 다양한 표현 형식을 포함한 데이터 (예: HTML 이메일)
- `multipart/mixed`: 텍스트와 바이너리 데이터 혼합

### 7. **폰트 타입**
웹에서 사용하는 폰트 파일에 대한 Content-Type입니다.

- `font/woff`: WOFF 폰트 파일 (예: `.woff`)
- `font/woff2`: WOFF2 폰트 파일 (예: `.woff2`)
- `font/ttf`: TrueType 폰트 파일 (예: `.ttf`)
- `font/otf`: OpenType 폰트 파일 (예: `.otf`)

### 8. **기타 타입**
특정 상황에서 사용되는 Content-Type입니다.

- `application/x-shockwave-flash`: Flash 파일 (예: `.swf`)
- `application/wasm`: WebAssembly 파일 (예: `.wasm`)
- `application/vnd.api+json`: JSON API 스펙 (예: REST API 응답)

## 파일의 실제 내용과 Content-Type 불일치로 인한 보안 취약점

### 1. **파일 실행 취약점**
Content-Type이 `image/png` 또는 `text/plain` 등으로 위장된 악성 파일이 서버에 업로드되면 다음과 같은 문제가 발생할 수 있습니다. 우리가 원하는 파일을 업로드 시키면서 Content-Type을 서버가 허용하는 것으로 변조하여 올리는 시도를 해보는 것이다.

#### 시나리오
- 공격자가 PHP 코드를 포함한 파일을 `image/jpeg`으로 위장하여 업로드.
- 서버가 Content-Type을 신뢰하여 파일을 저장한 후, 해당 파일을 실행 가능한 디렉토리에 배치.
- 결과적으로 공격자가 업로드한 PHP 코드가 실행되어 **원격 코드 실행(RCE)**으로 이어질 수 있음.

#### 방지 방법
- **파일의 실제 MIME 유형 검증**: `magic` 라이브러리 등을 사용하여 업로드된 파일의 실제 유형 확인.
- **업로드 디렉토리 설정**: 업로드 디렉토리를 웹 서버에서 실행 불가능하게 설정.

### 2. **MIME 스니핑(MIME Sniffing) 공격**
Content-Type 불일치를 악용하여 브라우저가 파일 내용을 잘못 해석하도록 유도하는 공격입니다.

#### 시나리오
- 공격자가 악성 JavaScript 코드가 포함된 `.html` 파일을 `text/plain`으로 위장하여 업로드.
- 브라우저가 파일을 열 때 MIME 스니핑으로 HTML로 인식.
- 브라우저에서 악성 JavaScript 코드 실행.

#### 방지 방법
- **응답 헤더 설정**: `X-Content-Type-Options: nosniff` 헤더를 사용하여 브라우저가 MIME 스니핑을 수행하지 않도록 설정.
- **Content-Disposition 설정**: 파일 다운로드로만 처리되도록 `Content-Disposition: attachment`를 설정.

### 3. **파일 탐지 회피**
악성 파일이 특정 보안 솔루션(예: 안티바이러스, WAF)에서 탐지되지 않도록 Content-Type을 위조하여 업로드될 수 있습니다.

#### 시나리오
- 공격자가 악성 스크립트를 포함한 `.exe` 파일을 `image/png`으로 위장하여 업로드.
- 보안 솔루션이 Content-Type만 확인하고 파일 내용을 분석하지 않으면, 해당 파일이 탐지를 우회.

#### 방지 방법
- **내용 기반 검증**: Content-Type뿐 아니라 파일의 실제 내용을 분석.
- **파일 서명 검증**: 파일 헤더를 분석하여 파일 유형을 확인.

### 4. **서비스 거부(DoS) 공격**
Content-Type 불일치로 인해 서버 리소스가 과도하게 사용되거나 비정상적인 처리가 발생할 수 있습니다.

#### 시나리오
- 공격자가 대용량 바이너리 데이터를 `application/json`으로 위장하여 업로드.
- 서버가 해당 데이터를 JSON으로 처리하려다 실패하면서 메모리 누수 또는 CPU 과부하가 발생.

#### 방지 방법
- **파일 크기 제한**: 업로드 가능한 파일 크기를 제한.
- **데이터 처리 로직 분리**: Content-Type과 파일 내용을 일치시키는 별도의 검증 단계 추가.

### 5. **클라이언트 공격 (Stored XSS)**
악성 파일이 잘못된 Content-Type으로 처리되어 클라이언트에 전달되면, 클라이언트 측 공격으로 이어질 수 있습니다.

#### 시나리오
- 공격자가 악성 JavaScript가 포함된 HTML 파일을 업로드하면서 Content-Type을 `image/png`으로 설정.
- 파일이 안전한 이미지 파일로 처리되어 클라이언트에 제공.
- 사용자가 파일을 열 때 악성 스크립트가 실행되어 **Stored XSS** 발생.

#### 방지 방법
- **파일 형식 화이트리스트**: 업로드를 허용하는 파일 형식을 명확히 제한.
- **출력 인코딩**: 파일 이름이나 내용이 사용자에게 노출될 경우 적절히 인코딩.

## SGV 파일의 취약점

### Case 1: SSRF

For this exploit, an attacker needs to create an SVG file with the below content and change the controlled server URL to its own server:
```html
<svg xmlns:svg=”http://www.w3.org/2000/svg" xmlns=”http://www.w3.org/2000/svg" xmlns:xlink=”http://www.w3.org/1999/xlink" width=”200" height=”200">

<image height=”30" width=”30"

xlink:href=”https://controlledserver.com/pic.svg" />

</svg>
```
If they upload this file to the application, there will be a callback if the application is vulnerable.

### Case 2: XXE

Here, attackers create an SVG file with the content shown below, and if the server is vulnerable the content of the local file is visible either in the response or in the image itself.
```html
<?xml version=”1.0" standalone=”yes”?><!DOCTYPE test [ <!ENTITY xxe SYSTEM “file:///etc/hostname” > ]><svg width=”128px” height=”128px” xmlns=”http://www.w3.org/2000/svg" xmlns:xlink=”http://www.w3.org/1999/xlink" version=”1.1"><text font-size=”16" x=”0" y=”16">&xxe;</text></svg>
```

### Case 3: Cross Site Scripting

In this case, attackers need to create an SVG file with the below content. If the server is vulnerable, they will see a pop-up showing that it is.
```html
<svg xmlns=”http://www.w3.org/2000/svg">

<script>alert(‘XSS’);</script>

<rect x=”0" height=”100" width=”100" style=”fill: #cccccc”/>

<line x1=”20" y1=”80" x2=”80" y2=”80" style=”stroke: #ff0000; stroke-width: 5;”/>

</svg>
```

## How to prevent and mitigate file upload vulnerabilities
- Your application should always check the content of the uploaded file. If it detects anything malicious, the file must be discarded.
- Maintain a whitelist of allowed extensions. Make sure that a file does not contain more than one extension.
- Make sure that the filename must not contain any special characters like “;”, “:”, “>”, “<”, “/”, “\”, “.”, “*”, “%” etc.
- Limit the size of the file name.
- Limit the size (minimum & maximum) of file upload to prevent DOS attacks.
- Make sure to disable execute permission on the directories where all the uploaded files are stored.
- Ensure the uploaded files do not replace the local files of the server.